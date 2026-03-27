#[cfg(not(test))]
use std::env;
use std::{
    collections::BTreeMap,
    convert::TryInto,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

#[allow(dead_code)]
#[path = "../barrier_shared.rs"]
mod barrier_shared;
#[allow(dead_code)]
#[path = "../message_crypto.rs"]
mod message_crypto;

use anchor_seed::{
    SeedCommitFields, build_anchor_seed_ctx, compute_seed_bundle_commit, compute_seed_commit,
    compute_seed_ctx_hash,
};
use anyhow::{Context, Result, anyhow};
use barrier_shared::{
    BARRIER_KEY_INFO, BARRIER_TREE_INFO, BarrierDeriveSaltPreimage, BarrierTreePathSaltPreimage,
    DEFAULT_BARRIER_N_MAX, TICKET_RETRY_MAX_ATTEMPTS, apply_join_set_to_snapshot,
    apply_revoked_set_to_snapshot, barrier_path_nodes, blank_leaf_and_path,
    collect_resolution_targets, compute_barrier_pkhash, compute_barrier_tree_hash,
    compute_revocation_roots_hash, encode_full_verification_receipt,
    encode_history_commitment_header, expected_barrier_tree_nodes, should_retry_ticket_http_error,
    sibling_node, ticket_retry_delay, validate_barrier_n_max,
};
#[cfg(test)]
use barrier_shared::{
    TICKET_RETRY_BASE_DELAY_MS, TICKET_RETRY_JITTER_MS, TICKET_RETRY_MAX_DELAY_MS,
    blank_internal_path_from_leaf, decode_history_commitment_header,
};
use ciborium::value::{Integer, Value};
#[cfg(test)]
use cityg_api_client::BarrierJoinRecord;
use cityg_api_client::{
    CitygApiClient, Error as ApiClientError, HistoryAuthorityExtension, HistoryCommitment,
    IdentityBinding,
};
#[cfg(test)]
use cityg_api_client::{RoomAdminOperation, build_room_admin_proof};
#[cfg(test)]
use cityg_client::demo;
use cityg_client::witness::SrxInputsOwned;
use cityg_client::{CityGClient, ClientEpochBundle};
use futures::StreamExt;
use hex::decode as hex_decode;
use message_crypto::{MessageCryptoContext, encrypt_message_v2};
#[cfg(test)]
use message_crypto::{
    MsgReplayState, decrypt_message_v2_with_index, derive_msg_replay_context_id,
    derive_msg_replay_tuple_tag,
};
use msphf_core::{ds, hash::h_l, hkdf::hkdf_blake3, serde_utils::to_cbor_vec};
use msphf_orchestrator::{
    AnchorInstanceParts, ForwardSecrecyState, FsJoinInputs, FsMergeInputs, LeafIdMode,
    OrchestrationParams, PivotParity, PopKeypair, SrxMode, compute_leaf_id, derive_we_epoch_id,
    hdr,
};
use pqcrypto_dilithium::dilithium5::{self, SecretKey as MlDsaSecretKey};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{PublicKey as KemPublicKeyTrait, SecretKey as KemSecretKeyTrait};
use pqcrypto_traits::sign::{
    DetachedSignature as DilithiumDetachedSignatureTrait, PublicKey as DilithiumPublicKeyTrait,
    SecretKey as DilithiumSecretKeyTrait,
};
use rand::{RngExt, rng};
use serde::Serialize;
use serde_bytes::ByteBuf;
use serde_json::Value as JsonValue;
use tokio::{
    sync::mpsc,
    time::{sleep, timeout},
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        client::IntoClientRequest,
        http::{HeaderValue, Request},
        protocol::Message as WsMessage,
    },
};
use tracing::warn;

fn random_room_id() -> String {
    let mut rng = rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    hex::encode(bytes)
}

const CLIENT_ADMIN_TOKEN_ENV: &str = "CITYG_CLIENT_ADMIN_TOKEN";
const CLIENT_MESSAGE_TOKEN_ENV: &str = "CITYG_CLIENT_MESSAGE_AUTH_TOKEN";
const MESSAGE_AUTH_HEADER: &str = "x-cityg-message-token";

fn read_nonempty_env(var: &str) -> Option<String> {
    std::env::var(var)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn configured_client_admin_token() -> Option<String> {
    read_nonempty_env(CLIENT_ADMIN_TOKEN_ENV)
        .or_else(|| read_nonempty_env("CITYG_SERVER_ROOMS_ADMIN_TOKEN"))
        .or_else(|| read_nonempty_env("CITYG_SERVER_WINDOW_ADMIN_TOKEN"))
}

fn configured_client_message_token() -> Option<String> {
    read_nonempty_env(CLIENT_MESSAGE_TOKEN_ENV)
        .or_else(|| read_nonempty_env("CITYG_SERVER_MESSAGE_AUTH_TOKEN"))
}

fn new_api_client(server_url: &str) -> CitygApiClient {
    let mut client = CitygApiClient::new(server_url);
    if let Some(token) = configured_client_admin_token() {
        client = client.with_admin_token(token);
    }
    if let Some(token) = configured_client_message_token() {
        client = client.with_message_auth_token(token);
    }
    client
}

fn ensure_supported_attested_current_state_extension(
    context: &str,
    extension: Option<HistoryAuthorityExtension>,
    current_global_history_attestation_bytes: &[u8],
) -> Result<()> {
    if current_global_history_attestation_bytes.is_empty() {
        if extension.is_some() {
            return Err(anyhow!(
                "{context} carries history authority extension without current global history attestation"
            ));
        }
        return Ok(());
    }
    if extension.is_none() {
        return Err(anyhow!(
            "{context} carries attested current state without negotiated history authority extension"
        ));
    }
    Ok(())
}

fn require_base_profile_global_history_authority_extension(
    extension: Option<HistoryAuthorityExtension>,
    context: &str,
) -> Result<HistoryAuthorityExtension> {
    match extension {
        Some(HistoryAuthorityExtension::GlobalHistoryAuthorityV1) => {
            Ok(HistoryAuthorityExtension::GlobalHistoryAuthorityV1)
        }
        Some(HistoryAuthorityExtension::LocalHistoryAuthorityV1) => Err(anyhow!(
            "{context} must carry global-history-authority-v1 in the base profile"
        )),
        None => Err(anyhow!(
            "{context} missing required global-history-authority-v1 in the base profile"
        )),
    }
}

fn parse_join_ticket_history_authority_extension(
    raw: &str,
) -> Result<Option<HistoryAuthorityExtension>> {
    if raw.is_empty() {
        return Ok(None);
    }
    if raw == HistoryAuthorityExtension::LocalHistoryAuthorityV1.as_str() {
        return Ok(Some(HistoryAuthorityExtension::LocalHistoryAuthorityV1));
    }
    if raw == HistoryAuthorityExtension::GlobalHistoryAuthorityV1.as_str() {
        return Ok(Some(HistoryAuthorityExtension::GlobalHistoryAuthorityV1));
    }
    Err(anyhow!(
        "join ticket carries unsupported history authority extension: {raw}"
    ))
}

fn generate_vrf_keys() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut params_seed = [0u8; 32];
    let mut key_seed = [0u8; 32];
    let mut rng = rng();
    rng.fill(&mut params_seed);
    rng.fill(&mut key_seed);
    let params = msphf_orchestrator::lb::generate_parameters(params_seed)
        .map_err(|err| anyhow!("generate VRF params: {err}"))?;
    msphf_orchestrator::lb::generate_keypair(&params, key_seed)
        .map_err(|err| anyhow!("generate VRF keypair: {err}"))
}

fn bytes32(name: &str, input: &[u8]) -> Result<[u8; 32]> {
    input
        .try_into()
        .map_err(|_| anyhow!("{name} must be 32 bytes, got {}", input.len()))
}

struct BarrierUpdateBuildResult {
    raw_update: Vec<u8>,
    k_barrier_new: [u8; 32],
}

fn build_barrier_update_bytes(
    gid: &[u8],
    n_max: u64,
    updater_leaf: u64,
    barrier_version: u64,
    prev_barrier_version: u64,
    revocation_roots_hash: [u8; 32],
    kem_tree_hash_before: [u8; 32],
    snapshot_pre: &[Vec<u8>],
) -> Result<BarrierUpdateBuildResult> {
    let n_max = validate_barrier_n_max(n_max)?;
    if updater_leaf >= n_max {
        return Err(anyhow!("invalid barrier update tree parameters"));
    }
    let expected_nodes = expected_barrier_tree_nodes(n_max)?;
    if snapshot_pre.len() != expected_nodes {
        return Err(anyhow!(
            "barrier snapshot size mismatch: expected {expected_nodes}, got {}",
            snapshot_pre.len()
        ));
    }

    #[derive(Serialize)]
    struct NewPublicKeyWire(u64, #[serde(with = "serde_bytes")] Vec<u8>);

    #[derive(Serialize)]
    struct KemTreeCoverPayloadWire(
        u64,
        Vec<u64>,
        Option<Vec<u64>>,
        Vec<NodeCiphertextWire>,
        Vec<NewPublicKeyWire>,
    );

    #[derive(Serialize)]
    struct NodeCiphertextWire(
        u64,
        u64,
        #[serde(with = "serde_bytes")] Vec<u8>,
        #[serde(with = "serde_bytes")] Vec<u8>,
        #[serde(with = "serde_bytes")] Vec<u8>,
    );

    #[derive(Serialize)]
    struct BarrierUpdateWire(
        String,
        u64,
        u64,
        u64,
        #[serde(with = "serde_bytes")] Vec<u8>,
        #[serde(with = "serde_bytes")] Vec<u8>,
        #[serde(with = "serde_bytes")] Vec<u8>,
        #[serde(with = "serde_bytes")] Vec<u8>,
    );

    let leaf_base = n_max.saturating_sub(1);
    let path_nodes = barrier_path_nodes(n_max, updater_leaf)?;

    let mut path_secrets = BTreeMap::new();
    let mut path_secret_leaf = [0u8; 32];
    rng().fill(&mut path_secret_leaf);
    path_secrets.insert(path_nodes[0], path_secret_leaf);
    for idx in 1..path_nodes.len() {
        let parent_node = path_nodes[idx];
        let child_node = path_nodes[idx - 1];
        let child_secret = path_secrets
            .get(&child_node)
            .ok_or_else(|| anyhow!("missing path secret for node {child_node}"))?;
        let salt = h_l(
            "barrier/tree/path",
            &BarrierTreePathSaltPreimage(gid, parent_node),
        )
        .map_err(|err| anyhow!("derive barrier tree/path salt: {err}"))?;
        let parent_secret = hkdf_blake3(&salt, child_secret, BARRIER_TREE_INFO);
        path_secrets.insert(parent_node, parent_secret);
    }
    let root_secret = path_secrets
        .get(&0)
        .ok_or_else(|| anyhow!("missing barrier root path secret"))?;
    let barrier_salt = h_l(
        "barrier/derive/salt",
        &BarrierDeriveSaltPreimage(gid, barrier_version, &revocation_roots_hash),
    )
    .map_err(|err| anyhow!("derive barrier/derive/salt: {err}"))?;
    let k_barrier_new = hkdf_blake3(&barrier_salt, root_secret, BARRIER_KEY_INFO);

    let mut expected_nodes: Vec<u64> = path_nodes.iter().copied().skip(1).collect();
    expected_nodes.sort_unstable();

    let new_public_keys = expected_nodes
        .into_iter()
        .map(|node| {
            let marker = (node as u8).wrapping_add(1);
            NewPublicKeyWire(node, vec![marker; kyber768::public_key_bytes()])
        })
        .collect::<Vec<_>>();

    let mut snapshot_post = snapshot_pre.to_vec();
    for NewPublicKeyWire(node, ek) in &new_public_keys {
        let idx = usize::try_from(*node).map_err(|_| anyhow!("barrier node index out of range"))?;
        let slot = snapshot_post
            .get_mut(idx)
            .ok_or_else(|| anyhow!("barrier node index out of range"))?;
        *slot = ek.clone();
    }
    let kem_tree_hash_after = compute_barrier_tree_hash(n_max, snapshot_post.as_slice())?;

    let mut node_ciphertexts = Vec::new();
    for step in 0..path_nodes.len().saturating_sub(1) {
        let child_node = path_nodes[step];
        let source_node = path_nodes[step + 1];
        let sibling =
            sibling_node(child_node).ok_or_else(|| anyhow!("barrier sibling missing for root"))?;
        let mut targets = Vec::new();
        collect_resolution_targets(snapshot_pre, sibling, leaf_base, &mut targets)?;
        targets.sort_unstable();
        for target_node in targets {
            let target_index = usize::try_from(target_node)
                .map_err(|_| anyhow!("barrier node index out of range"))?;
            let target_pk = snapshot_pre
                .get(target_index)
                .ok_or_else(|| anyhow!("barrier node index out of range"))?;
            let target_pkhash = compute_barrier_pkhash(target_pk.as_slice())?;
            let mut kem_ct = vec![0u8; kyber768::ciphertext_bytes()];
            let mut wrapped_ps = vec![0u8; 48];
            let mut rng = rng();
            rng.fill(kem_ct.as_mut_slice());
            rng.fill(wrapped_ps.as_mut_slice());
            node_ciphertexts.push(NodeCiphertextWire(
                source_node,
                target_node,
                target_pkhash[..16].to_vec(),
                kem_ct,
                wrapped_ps,
            ));
        }
    }
    node_ciphertexts.sort_by_key(|entry| (entry.0, entry.1));

    let cover_payload = KemTreeCoverPayloadWire(
        updater_leaf,
        path_nodes,
        None,
        node_ciphertexts,
        new_public_keys,
    );
    let cover_bytes = to_cbor_vec(&cover_payload).context("encode barrier cover payload")?;

    let update = BarrierUpdateWire(
        "barrier-v1".to_string(),
        barrier_version,
        prev_barrier_version,
        n_max,
        revocation_roots_hash.to_vec(),
        kem_tree_hash_before.to_vec(),
        kem_tree_hash_after.to_vec(),
        cover_bytes,
    );
    Ok(BarrierUpdateBuildResult {
        raw_update: to_cbor_vec(&update).context("encode barrier update")?,
        k_barrier_new,
    })
}

#[derive(Serialize)]
struct FsFingerprintInputs<'a> {
    fs_policy_version: &'a str,
    fs_ec: u64,
    #[serde(with = "serde_bytes")]
    fs_epoch_commit: &'a [u8],
    fs_epoch_base_ts: u64,
}

fn derive_fs_fingerprint_from_fields(
    fs_policy_version: &str,
    fs_ec: u64,
    fs_epoch_commit: &[u8; 32],
    fs_epoch_base_ts: u64,
) -> Option<[u8; 32]> {
    let inputs = FsFingerprintInputs {
        fs_policy_version,
        fs_ec,
        fs_epoch_commit,
        fs_epoch_base_ts,
    };
    h_l("fs/fingerprint", &inputs).ok()
}

fn compute_fs_fingerprint_from_header(header: &BTreeMap<u64, Value>) -> Option<[u8; 32]> {
    let policy = match header.get(&hdr::HDR_FS_POLICY_VERSION)? {
        Value::Text(text) => text.clone(),
        Value::Integer(value) => u64::try_from(*value).ok()?.to_string(),
        _ => return None,
    };
    let fs_ec = match header.get(&hdr::HDR_FS_EC)? {
        Value::Integer(int) => (*int).try_into().ok()?,
        _ => return None,
    };
    let fs_epoch_commit = match header.get(&hdr::HDR_FS_EPOCH_COMMIT)? {
        Value::Bytes(bytes) => bytes.as_slice().try_into().ok()?,
        _ => return None,
    };
    let fs_epoch_base_ts = match header.get(&hdr::HDR_FS_EPOCH_BASE_TS)? {
        Value::Integer(int) => (*int).try_into().ok()?,
        _ => return None,
    };
    derive_fs_fingerprint_from_fields(&policy, fs_ec, &fs_epoch_commit, fs_epoch_base_ts)
}

fn fingerprint_full_hex(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

fn fingerprint_preview_hex(bytes: &[u8; 32]) -> String {
    let hex = fingerprint_full_hex(bytes);
    let first = &hex[..8];
    let second = &hex[8..16];
    format!(
        "{}-{} {}-{} …",
        &first[..4],
        &first[4..],
        &second[..4],
        &second[4..]
    )
}

fn ensure_matching_history_dependencies(
    context: &str,
    expected_view_id: Option<&[u8; 32]>,
    expected_commitment: &HistoryCommitment,
    tree_history_view_id: &[u8; 32],
    tree_history_commitment: &HistoryCommitment,
    joins_history_view_id: &[u8; 32],
    joins_history_commitment: &HistoryCommitment,
    revoked_history_view_id: &[u8; 32],
    revoked_history_commitment: &HistoryCommitment,
) -> Result<()> {
    if *tree_history_view_id == [0u8; 32]
        || tree_history_view_id != joins_history_view_id
        || tree_history_view_id != revoked_history_view_id
    {
        return Err(anyhow!(
            "{context}: public tree / joins / revoked leaves do not share one authenticated history view (960.9)"
        ));
    }
    if tree_history_commitment.history_view_id == [0u8; 32]
        || *tree_history_commitment != *joins_history_commitment
        || *tree_history_commitment != *revoked_history_commitment
    {
        return Err(anyhow!(
            "{context}: public tree / joins / revoked leaves do not share one authenticated history commitment (960.9)"
        ));
    }
    if *tree_history_commitment != *expected_commitment {
        return Err(anyhow!(
            "{context}: authenticated history commitment does not match ticket/provisioning state (960.9)"
        ));
    }
    if let Some(expected_history_view_id) = expected_view_id
        && tree_history_view_id != expected_history_view_id
    {
        return Err(anyhow!(
            "{context}: authenticated history view does not match provisioning state (960.9)"
        ));
    }
    Ok(())
}

fn log_fingerprints(session: &Session) {
    let regular_preview = fingerprint_preview_hex(&session.seed_ctx_hash);
    let regular_full = fingerprint_full_hex(&session.seed_ctx_hash);
    let (fs_preview, fs_full) = match session.fs_fingerprint.as_ref() {
        Some(bytes) => (fingerprint_preview_hex(bytes), fingerprint_full_hex(bytes)),
        None => ("n/a".to_string(), "n/a".to_string()),
    };
    println!(
        "fingerprints: regular={} (full={}) fs={} (full={} fs_ec={})",
        regular_preview, regular_full, fs_preview, fs_full, session.fs_ec
    );
}

fn select_pivot_parity(parities: &[PivotParity]) -> Option<&PivotParity> {
    parities.iter().max_by(|a, b| {
        a.accept_seq
            .cmp(&b.accept_seq)
            .then_with(|| b.xk_hash.cmp(&a.xk_hash))
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliOptions {
    server_url: String,
    room_id: String,
    alias_base: String,
    count: usize,
    batch_mode: bool,
    watch_mode: bool,
    verbose: bool,
    leave_order: Option<Vec<usize>>,
    message_burst_count: usize,
    message_burst_interval_ms: u64,
    session_artifact_dir: Option<PathBuf>,
}

#[derive(Clone, Copy)]
struct MessageBurstOptions {
    count: usize,
    interval: Duration,
}

struct WatchModeParams<'a> {
    server_url: &'a str,
    room_id: &'a str,
    alias_base: &'a str,
    count: usize,
    leave_order: Option<Vec<usize>>,
    verbose: bool,
    message_burst: MessageBurstOptions,
    session_artifact_dir: Option<&'a Path>,
}

fn parse_cli_args(args: impl IntoIterator<Item = String>) -> Result<CliOptions> {
    let mut server_url = None;
    let mut room_id = None;
    let mut alias = None;
    let mut count = 1usize;
    let mut batch_mode = false;
    let mut leave_order_raw: Option<String> = None;
    let mut watch_mode = false;
    let mut verbose = false;
    let mut message_burst_count = 0usize;
    let mut message_burst_interval_ms = 0u64;
    let mut session_artifact_dir = None;

    for arg in args {
        if let Some(rest) = arg.strip_prefix("--count=") {
            count = rest
                .parse()
                .map_err(|_| anyhow!("invalid --count value: {rest}"))?;
            if count == 0 {
                return Err(anyhow!("--count must be at least 1"));
            }
            continue;
        }
        if arg == "--batch" {
            batch_mode = true;
            continue;
        }
        if arg == "--watch" {
            watch_mode = true;
            batch_mode = true;
            continue;
        }
        if arg == "--verbose" {
            verbose = true;
            continue;
        }
        if let Some(rest) = arg.strip_prefix("--leave-order=") {
            leave_order_raw = Some(rest.to_string());
            continue;
        }
        if let Some(rest) = arg.strip_prefix("--message-burst-count=") {
            message_burst_count = rest
                .parse()
                .map_err(|_| anyhow!("invalid --message-burst-count value: {rest}"))?;
            continue;
        }
        if let Some(rest) = arg.strip_prefix("--message-burst-interval-ms=") {
            message_burst_interval_ms = rest
                .parse()
                .map_err(|_| anyhow!("invalid --message-burst-interval-ms value: {rest}"))?;
            continue;
        }
        if let Some(rest) = arg.strip_prefix("--session-artifact-dir=") {
            if rest.trim().is_empty() {
                return Err(anyhow!("--session-artifact-dir requires a non-empty path"));
            }
            session_artifact_dir = Some(PathBuf::from(rest));
            continue;
        }
        match (&server_url, &room_id, &alias) {
            (None, _, _) => server_url = Some(arg),
            (Some(_), None, _) => room_id = Some(arg),
            (Some(_), Some(_), None) => alias = Some(arg),
            _ => {
                return Err(anyhow!(
                    "unexpected extra argument: {arg}. usage: [server] [room] [alias] [--count=N] [--batch|--watch] [--leave-order=...] [--message-burst-count=N] [--message-burst-interval-ms=MS] [--session-artifact-dir=PATH] [--verbose]"
                ));
            }
        }
    }

    let server_url = server_url.unwrap_or_else(|| "http://127.0.0.1:8080".to_string());
    let room_id = room_id.unwrap_or_else(random_room_id);
    let alias_base = alias.unwrap_or_else(|| "cli-joiner".to_string());

    if !batch_mode && !watch_mode && leave_order_raw.is_some() {
        return Err(anyhow!("--leave-order requires --batch"));
    }

    if watch_mode && count < 2 {
        return Err(anyhow!("--watch requires --count >= 2"));
    }

    let leave_order = if let Some(raw) = leave_order_raw {
        let mut order = Vec::new();
        for entry in raw.split(',') {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                continue;
            }
            let idx: usize = trimmed
                .parse()
                .map_err(|_| anyhow!("invalid leave order entry: {trimmed}"))?;
            if idx == 0 || idx > count {
                return Err(anyhow!(
                    "leave order index {idx} out of range (1..={count})"
                ));
            }
            order.push(idx);
        }
        if order.len() != count {
            warn!(
                "leave order length {} differs from count {}; missing entries will default",
                order.len(),
                count
            );
        }
        Some(order)
    } else {
        None
    };

    Ok(CliOptions {
        server_url,
        room_id,
        alias_base,
        count,
        batch_mode,
        watch_mode,
        verbose,
        leave_order,
        message_burst_count,
        message_burst_interval_ms,
        session_artifact_dir,
    })
}

#[cfg(not(test))]
#[tokio::main]
async fn main() -> Result<()> {
    let options = parse_cli_args(env::args().skip(1))?;
    run_with_options(options).await
}

async fn run_with_options(options: CliOptions) -> Result<()> {
    let CliOptions {
        server_url,
        room_id,
        alias_base,
        count,
        batch_mode,
        watch_mode,
        verbose,
        leave_order,
        message_burst_count,
        message_burst_interval_ms,
        session_artifact_dir,
    } = options;

    if watch_mode {
        let message_burst = MessageBurstOptions {
            count: message_burst_count,
            interval: Duration::from_millis(message_burst_interval_ms),
        };
        run_watch_mode(WatchModeParams {
            server_url: &server_url,
            room_id: &room_id,
            alias_base: &alias_base,
            count,
            leave_order: leave_order.clone(),
            verbose,
            message_burst,
            session_artifact_dir: session_artifact_dir.as_deref(),
        })
        .await?;
        return Ok(());
    }

    if batch_mode {
        let mut sessions = Vec::with_capacity(count);
        for i in 0..count {
            let alias = if count == 1 {
                alias_base.clone()
            } else {
                format!("{}-{}", alias_base, i + 1)
            };
            println!("server={server_url} room={room_id} alias={alias}");
            let session = perform_join(&server_url, &room_id, &alias).await?;
            println!("join ok: weid={}", hex::encode(session.we_epoch_id));
            log_fingerprints(&session);
            maybe_write_session_artifact(
                session_artifact_dir.as_deref(),
                "joined",
                &alias,
                &session,
            )?;
            sessions.push(session);
        }

        if message_burst_count > 0 {
            send_message_burst(
                &mut sessions,
                message_burst_count,
                Duration::from_millis(message_burst_interval_ms),
                None,
            )
            .await?;
        }

        let default_order: Vec<usize> = (1..=count).collect();
        let order = leave_order.as_ref().unwrap_or(&default_order);
        for idx in order {
            if *idx == 0 || *idx > sessions.len() {
                return Err(anyhow!("leave order index {idx} invalid"));
            }
            let session = &sessions[*idx - 1];
            maybe_write_session_artifact(
                session_artifact_dir.as_deref(),
                "pre-leave",
                &alias_for(&alias_base, count, *idx - 1),
                session,
            )?;
            println!(
                "leaving alias={} weid={}",
                alias_for(&alias_base, count, *idx - 1),
                hex::encode(session.we_epoch_id)
            );
            perform_leave(session, verbose).await?;
            println!("leave ok");
        }
    } else if count > 1 {
        let mut sessions = Vec::with_capacity(count);
        for i in 0..count {
            let alias = if count == 1 {
                alias_base.clone()
            } else {
                format!("{}-{}", alias_base, i + 1)
            };
            println!("server={server_url} room={room_id} alias={alias}");
            let session = perform_join(&server_url, &room_id, &alias).await?;
            println!("join ok: weid={}", hex::encode(session.we_epoch_id));
            log_fingerprints(&session);
            maybe_write_session_artifact(
                session_artifact_dir.as_deref(),
                "joined",
                &alias,
                &session,
            )?;
            sessions.push(session);
        }

        for (idx, session) in sessions.iter().enumerate() {
            maybe_write_session_artifact(
                session_artifact_dir.as_deref(),
                "pre-leave",
                &alias_for(&alias_base, count, idx),
                session,
            )?;
            println!(
                "leaving alias={} weid={}",
                alias_for(&alias_base, count, idx),
                hex::encode(session.we_epoch_id)
            );
            perform_leave(session, verbose).await?;
            println!("leave ok");
        }
    } else {
        println!("server={server_url} room={room_id} alias={alias_base}");
        let session = perform_join(&server_url, &room_id, &alias_base).await?;
        println!("join ok: weid={}", hex::encode(session.we_epoch_id));
        log_fingerprints(&session);
        maybe_write_session_artifact(
            session_artifact_dir.as_deref(),
            "joined",
            &alias_base,
            &session,
        )?;
        maybe_write_session_artifact(
            session_artifact_dir.as_deref(),
            "pre-leave",
            &alias_base,
            &session,
        )?;
        perform_leave(&session, verbose).await?;
        println!("leave ok");
    }

    Ok(())
}

fn alias_for(base: &str, count: usize, idx: usize) -> String {
    if count == 1 {
        base.to_string()
    } else {
        format!("{}-{}", base, idx + 1)
    }
}

#[derive(Serialize)]
struct SessionArtifact {
    alias: String,
    phase: String,
    room_id: String,
    barrier_version: u64,
    fs_ec: u64,
    gid_tag: String,
    leaf_tag: String,
    we_epoch_tag: String,
    xk_tag: String,
    epoch_key_tag: String,
    barrier_key_tag: String,
    seed_ctx_tag: String,
    fs_epoch_commit_tag: String,
    fs_dev_prev_commit_tag: String,
}

fn artifact_tag(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex()[..16].to_string()
}

fn artifact_file_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => ch,
            _ => '_',
        })
        .collect()
}

fn maybe_write_session_artifact(
    artifact_dir: Option<&Path>,
    phase: &str,
    alias: &str,
    session: &Session,
) -> Result<()> {
    let Some(artifact_dir) = artifact_dir else {
        return Ok(());
    };
    fs::create_dir_all(artifact_dir)
        .with_context(|| format!("create {}", artifact_dir.display()))?;
    let artifact = SessionArtifact {
        alias: alias.to_string(),
        phase: phase.to_string(),
        room_id: session.room_id.clone(),
        barrier_version: session.barrier_version,
        fs_ec: session.fs_ec,
        gid_tag: artifact_tag(&session.gid),
        leaf_tag: artifact_tag(&session.leaf_id),
        we_epoch_tag: artifact_tag(&session.we_epoch_id),
        xk_tag: artifact_tag(&session.xk_hash),
        epoch_key_tag: artifact_tag(&session.epoch_key),
        barrier_key_tag: artifact_tag(&session.k_barrier),
        seed_ctx_tag: artifact_tag(&session.seed_ctx_hash),
        fs_epoch_commit_tag: artifact_tag(&session.fs_epoch_commit),
        fs_dev_prev_commit_tag: artifact_tag(&session.fs_dev_prev_commit),
    };
    let path = artifact_dir.join(format!(
        "{}-{}.json",
        artifact_file_component(phase),
        artifact_file_component(alias)
    ));
    fs::write(&path, serde_json::to_vec_pretty(&artifact)?)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

struct Session {
    server_url: String,
    room_id: String,
    gid: [u8; 32],
    leaf_id: [u8; 32],
    xk_hash: [u8; 32],
    epoch_key: [u8; 32],
    barrier_version: u64,
    k_barrier: [u8; 32],
    pop_public_key: Vec<u8>,
    pop_secret: Box<MlDsaSecretKey>,
    vrf_secret_key: Vec<u8>,
    vrf_public_key: Vec<u8>,
    forward_state: ForwardSecrecyState,
    fs_ec: u64,
    fs_epoch_commit: [u8; 32],
    fs_dev_prev_commit: [u8; 32],
    we_epoch_id: [u8; 32],
    anchor_hdr_ctx: Vec<u8>,
    seed_ctx_hash: [u8; 32],
    seed_commit: [u8; 32],
    seed_bundle_commit: [u8; 32],
    fs_fingerprint: Option<[u8; 32]>,
    join_finalize_auth_token: [u8; 32],
    current_history_authority_extension: Option<HistoryAuthorityExtension>,
    current_global_history_attestation_bytes: Vec<u8>,
    stored_header_map: BTreeMap<u64, Value>,
    #[cfg(test)]
    msg_replay_state: MsgReplayState,
}

const EVENT_TIMEOUT: Duration = Duration::from_secs(10);
const MESSAGE_PREFIX: &[u8; 4] = b"CGM1";
const MESSAGE_SENDER_DEVICE_PK_ALG: &str = "ML-DSA-65";

#[cfg(test)]
#[derive(Debug)]
struct AuthenticatedMessage<'a> {
    timestamp_ms: u64,
    plaintext: &'a [u8],
    public_key: &'a [u8],
    signature: &'a [u8],
}

fn encode_authenticated_message(
    timestamp_ms: u64,
    plaintext: &[u8],
    public_key: &[u8],
    signature: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        MESSAGE_PREFIX.len() + 8 + 4 + plaintext.len() + 4 + public_key.len() + 4 + signature.len(),
    );
    out.extend_from_slice(MESSAGE_PREFIX);
    out.extend_from_slice(&timestamp_ms.to_le_bytes());
    out.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
    out.extend_from_slice(plaintext);
    out.extend_from_slice(&(public_key.len() as u32).to_le_bytes());
    out.extend_from_slice(public_key);
    out.extend_from_slice(&(signature.len() as u32).to_le_bytes());
    out.extend_from_slice(signature);
    out
}

fn sign_message(
    leaf_id: &[u8; 32],
    timestamp_ms: u64,
    plaintext: &[u8],
    secret_key: &[u8],
) -> Result<Vec<u8>> {
    let sk = dilithium5::SecretKey::from_bytes(secret_key)
        .map_err(|_| anyhow!("invalid ML-DSA-65 secret key"))?;
    let mut payload = Vec::with_capacity(32 + 8 + plaintext.len());
    payload.extend_from_slice(leaf_id);
    payload.extend_from_slice(&timestamp_ms.to_le_bytes());
    payload.extend_from_slice(plaintext);
    let signature = dilithium5::detached_sign(&payload, &sk);
    Ok(signature.as_bytes().to_vec())
}

#[cfg(test)]
fn decode_authenticated_message(data: &[u8]) -> Result<AuthenticatedMessage<'_>> {
    if data.len() < MESSAGE_PREFIX.len() + 8 + 4 + 4 + 4 {
        return Err(anyhow!("authenticated message too short"));
    }

    if &data[..MESSAGE_PREFIX.len()] != MESSAGE_PREFIX {
        return Err(anyhow!("invalid message prefix"));
    }

    let mut cursor = MESSAGE_PREFIX.len();

    let timestamp_ms = {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&data[cursor..cursor + 8]);
        cursor += 8;
        u64::from_le_bytes(buf)
    };

    let plaintext_len = {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&data[cursor..cursor + 4]);
        cursor += 4;
        u32::from_le_bytes(buf) as usize
    };
    if data.len() < cursor + plaintext_len {
        return Err(anyhow!("authenticated message truncated (plaintext)"));
    }
    let plaintext = &data[cursor..cursor + plaintext_len];
    cursor += plaintext_len;

    let public_key_len = {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&data[cursor..cursor + 4]);
        cursor += 4;
        u32::from_le_bytes(buf) as usize
    };
    if data.len() < cursor + public_key_len {
        return Err(anyhow!("authenticated message truncated (public key)"));
    }
    let public_key = &data[cursor..cursor + public_key_len];
    cursor += public_key_len;

    let signature_len = {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&data[cursor..cursor + 4]);
        cursor += 4;
        u32::from_le_bytes(buf) as usize
    };
    if data.len() != cursor + signature_len {
        return Err(anyhow!("authenticated message truncated (signature)"));
    }
    let signature = &data[cursor..];

    Ok(AuthenticatedMessage {
        timestamp_ms,
        plaintext,
        public_key,
        signature,
    })
}

#[cfg(test)]
fn verify_message_signature(
    leaf_id: &[u8; 32],
    timestamp_ms: u64,
    plaintext: &[u8],
    signature_bytes: &[u8],
    public_key_bytes: &[u8],
) -> Result<()> {
    let pk = dilithium5::PublicKey::from_bytes(public_key_bytes)
        .map_err(|_| anyhow!("invalid ML-DSA-65 public key"))?;
    let signature = dilithium5::DetachedSignature::from_bytes(signature_bytes)
        .map_err(|_| anyhow!("invalid ML-DSA-65 signature"))?;

    let mut payload = Vec::with_capacity(32 + 8 + plaintext.len());
    payload.extend_from_slice(leaf_id);
    payload.extend_from_slice(&timestamp_ms.to_le_bytes());
    payload.extend_from_slice(plaintext);

    dilithium5::verify_detached_signature(&signature, &payload, &pk)
        .map_err(|_| anyhow!("signature verification failed"))?;

    Ok(())
}

#[cfg(test)]
fn verify_sender_leaf_binding(
    gid: &[u8; 32],
    sender_leaf: &[u8; 32],
    public_key_bytes: &[u8],
) -> Result<()> {
    let derived_leaf = compute_leaf_id(
        LeafIdMode::PerGroup,
        gid,
        MESSAGE_SENDER_DEVICE_PK_ALG,
        public_key_bytes,
    )
    .map_err(|err| anyhow!("sender leaf derivation failed: {err}"))?;
    if &derived_leaf != sender_leaf {
        return Err(anyhow!(
            "sender leaf does not match authenticated sender public key"
        ));
    }
    Ok(())
}

async fn prepare_join_session_with_identity(
    server_url: &str,
    room_id: &str,
    alias: &str,
    pop_public_key: Vec<u8>,
    pop_secret_key: Vec<u8>,
) -> Result<Session> {
    let client = new_api_client(server_url);
    let pop_secret =
        Box::new(MlDsaSecretKey::from_bytes(&pop_secret_key).context("invalid POP key")?);

    let binding_message = (
        ByteBuf::from(alias.as_bytes().to_vec()),
        ByteBuf::from(pop_public_key.clone()),
    );
    let mut binding_message_bytes = Vec::new();
    ciborium::ser::into_writer(&binding_message, &mut binding_message_bytes)
        .context("encode identity binding message")?;
    let binding_signature = dilithium5::detached_sign(&binding_message_bytes, pop_secret.as_ref());
    let identity_binding = IdentityBinding {
        alias: alias.to_string(),
        pop_public_key: pop_public_key.clone(),
        signature: binding_signature.as_bytes().to_vec(),
    };

    let mut retry_attempt = 0u32;
    let ticket = loop {
        match client
            .join_ticket(room_id, alias, Some(identity_binding.clone()))
            .await
        {
            Ok(ticket) => break ticket,
            Err(ApiClientError::HttpStatus {
                status,
                message,
                freeze_code,
                freeze_reason,
                ..
            }) => {
                if should_retry_ticket_http_error(status.as_u16(), &message, freeze_code)
                    && retry_attempt < TICKET_RETRY_MAX_ATTEMPTS
                {
                    let delay = ticket_retry_delay(retry_attempt);
                    retry_attempt = retry_attempt.saturating_add(1);
                    warn!(
                        attempt = retry_attempt,
                        delay_ms = delay.as_millis() as u64,
                        status = status.as_u16(),
                        message = %message,
                        "join_ticket race/concurrency rejection; retrying"
                    );
                    sleep(delay).await;
                    continue;
                }

                let mut detail = describe_http_failure(
                    status.as_str(),
                    &message,
                    freeze_code,
                    freeze_reason.as_deref(),
                );
                if status.is_server_error() && message.contains("kbroad key missing") {
                    detail.push_str(
                        " (room is not KBROAD-provisioned; bootstrap it first with a room-specific public key)",
                    );
                }
                return Err(anyhow!(detail));
            }
            Err(err) => return Err(err.into()),
        }
    };

    let gid = bytes32("gid", &ticket.gid)?;
    let cat = bytes32("cat", &ticket.cat)?;
    let tswe_salt_hash = bytes32("tswe_salt_hash", &ticket.tswe_salt_hash)?;
    let parent_root = bytes32("parent_root", &ticket.parent_root)?;
    let join_delta_root = bytes32("join_delta_root", &ticket.join_delta_root)?;
    let revoked_since_root = bytes32("revoked_since_root", &ticket.revoked_since_root)?;
    let revoked_root = bytes32("revoked_root", &ticket.revoked_root)?;
    let leaf_id = bytes32("leaf_id", &ticket.leaf_id)?;
    let pox_r_commit = bytes32("pox_r_commit", &ticket.pox_r_commit)?;
    let join_finalize_auth_token =
        bytes32("join_finalize_auth_token", &ticket.join_finalize_auth_token)?;

    let kbroad_public = if ticket.kbroad_public.is_empty() {
        return Err(anyhow!("server returned empty KBROAD key"));
    } else {
        ticket.kbroad_public.clone()
    };

    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_KBROAD_ALG, Value::Text("ml-kem-768".to_string()));
    header.insert(hdr::HDR_KBROAD_PUB, Value::Bytes(kbroad_public.clone()));
    let (barrier_leaf_ek, barrier_leaf_dk) = kyber768::keypair();
    header.insert(
        hdr::HDR_BARRIER_LEAF_PK,
        Value::Bytes(KemPublicKeyTrait::as_bytes(&barrier_leaf_ek).to_vec()),
    );
    // Keep the private leaf key material local (future recover path).
    let _barrier_leaf_dk = KemSecretKeyTrait::as_bytes(&barrier_leaf_dk).to_vec();

    let mut fs_state = ForwardSecrecyState::new({
        let mut seed = [0u8; 32];
        rng().fill(&mut seed);
        seed
    });

    let (vrf_secret_key, vrf_public_key) =
        generate_vrf_keys().context("generate runtime VRF keypair")?;

    let params = OrchestrationParams {
        msphf_crs_id: ticket.msphf_crs_id.as_str(),
        params_id: ticket.msphf_params_id.as_str(),
        srx: Some(
            SrxInputsOwned::from_cbor(&ticket.srx_cbor)
                .context("decode SRX inputs")?
                .into_srx_inputs(),
        ),
        srx_mode: SrxMode::Complete,
        pop_keys: Some(PopKeypair {
            algorithm: "ML-DSA-65",
            public_key: pop_public_key.as_slice(),
            secret_key: pop_secret.as_ref(),
        }),
        leaf_id_mode: LeafIdMode::PerGroup,
        proof_mode: ticket.proof_mode.as_str(),
        vrf_id: ticket.vrf_id.as_str(),
        policy_version: ticket.policy_version.as_str(),
        vrf_secret_key: Some(vrf_secret_key.as_slice()),
        vrf_public_key: Some(vrf_public_key.as_slice()),
        fs_policy_version: ticket.fs_policy_version.as_str(),
        fs_epoch_base_ts: ticket.fs_epoch_base_ts,
        barrier_version: ticket.barrier_version,
        fs_join: FsJoinInputs::default(),
        fs_merge: FsMergeInputs::default(),
    };

    let parts = AnchorInstanceParts {
        gid: &gid,
        cat: &cat,
        tswe_salt_hash: tswe_salt_hash.as_slice(),
        parent_root: parent_root.as_slice(),
        join_delta_root: join_delta_root.as_slice(),
        revoked_since_prev_root: revoked_since_root.as_slice(),
        revoked_root: revoked_root.as_slice(),
        pox_r_commit: Some(pox_r_commit.as_slice()),
    };

    let witness_bytes = if ticket.witness_cbor.is_empty() {
        None
    } else {
        Some(ticket.witness_cbor.as_slice())
    };

    let build_join_bundle = |fs_state: &mut ForwardSecrecyState,
                             disable_autonomic_evolve: bool|
     -> Result<ClientEpochBundle> {
        if disable_autonomic_evolve {
            CityGClient::generate_epoch_without_evolve(
                header.clone(),
                parts.clone(),
                params.clone(),
                fs_state,
                witness_bytes,
            )
        } else {
            CityGClient::generate_epoch(
                header.clone(),
                parts.clone(),
                params.clone(),
                fs_state,
                witness_bytes,
            )
        }
        .context("generate join bundle")
    };

    let pristine_fs_state = fs_state.clone();
    let mut bundle = build_join_bundle(&mut fs_state, false)?;

    if parent_root == [0u8; 32] && !ticket.bootstrap_public.is_empty() {
        return Err(anyhow!(
            "server requires bootstrap signer for first join; join_leave bootstrap signer support is not configured"
        ));
    }

    match client.accept_epoch_bundle(&bundle).await {
        Ok(_) => {}
        Err(ApiClientError::HttpStatus {
            freeze_code,
            freeze_reason,
            ..
        }) if is_fs_forward_jump_group_http_error(freeze_code, freeze_reason.as_deref()) => {
            fs_state = pristine_fs_state;
            bundle = build_join_bundle(&mut fs_state, true)?;
            client
                .accept_epoch_bundle(&bundle)
                .await
                .context("server rejected join bundle after stale-group retry")?;
        }
        Err(err) => return Err(err).context("server rejected join bundle"),
    }

    let stored = client
        .get_bundle(&bundle.we_epoch_id)
        .await
        .context("fetch stored bundle")?;
    let stored =
        ClientEpochBundle::from_cbor(&stored.bundle_cbor).context("invalid stored bundle")?;

    let fs_epoch_commit = bytes32(
        "fs_epoch_commit",
        stored
            .header_map
            .get(&hdr::HDR_FS_EPOCH_COMMIT)
            .and_then(Value::as_bytes)
            .ok_or(anyhow!("stored bundle missing fs_epoch_commit"))?,
    )?;
    let fs_dev_prev_commit = bytes32(
        "fs_dev_prev_commit",
        stored
            .header_map
            .get(&hdr::HDR_FS_DEV_COMMIT)
            .or_else(|| stored.header_map.get(&hdr::HDR_FS_DEV_PREV_COMMIT))
            .and_then(Value::as_bytes)
            .ok_or(anyhow!("stored bundle missing fs_dev commit"))?,
    )?;

    let snapshot = fs_state.snapshot();
    let fs_ec = snapshot.fs_ec;
    let anchor_hdr_ctx = stored.anchor.anchor_hdr_ctx.clone();
    let seed_ctx_hash = stored.hp_binding.seed_ctx_hash;
    let seed_commit = stored.hp_binding.seed_commit;
    let seed_bundle_commit = stored.hp_binding.seed_bundle_commit;
    let fs_fingerprint = match compute_fs_fingerprint_from_header(&stored.header_map) {
        Some(fp) => Some(fp),
        None => derive_fs_fingerprint_from_fields(
            ticket.fs_policy_version.as_str(),
            fs_ec,
            &fs_epoch_commit,
            ticket.fs_epoch_base_ts,
        ),
    };
    let current_history_authority_extension =
        Some(require_base_profile_global_history_authority_extension(
            parse_join_ticket_history_authority_extension(&ticket.history_authority_extension)?,
            "join ticket",
        )?);
    ensure_supported_attested_current_state_extension(
        "join ticket",
        current_history_authority_extension,
        ticket.current_global_history_attestation.as_slice(),
    )?;
    let session = Session {
        server_url: server_url.to_string(),
        room_id: room_id.to_string(),
        gid,
        leaf_id,
        xk_hash: bundle.hp_binding.xk_hash,
        epoch_key: bundle.epoch_key,
        barrier_version: ticket.barrier_version,
        k_barrier: [0u8; 32],
        pop_public_key,
        pop_secret,
        vrf_secret_key,
        vrf_public_key,
        forward_state: fs_state,
        fs_ec,
        fs_epoch_commit,
        fs_dev_prev_commit,
        we_epoch_id: bundle.we_epoch_id,
        anchor_hdr_ctx,
        seed_ctx_hash,
        seed_commit,
        seed_bundle_commit,
        fs_fingerprint,
        join_finalize_auth_token,
        current_history_authority_extension,
        current_global_history_attestation_bytes: ticket.current_global_history_attestation.clone(),
        stored_header_map: stored.header_map.clone(),
        #[cfg(test)]
        msg_replay_state: MsgReplayState::default(),
    };
    Ok(session)
}

async fn prepare_join_session(server_url: &str, room_id: &str, alias: &str) -> Result<Session> {
    let (pop_pk, pop_sk) = dilithium5::keypair();
    prepare_join_session_with_identity(
        server_url,
        room_id,
        alias,
        DilithiumPublicKeyTrait::as_bytes(&pop_pk).to_vec(),
        DilithiumSecretKeyTrait::as_bytes(&pop_sk).to_vec(),
    )
    .await
}

async fn perform_join(server_url: &str, room_id: &str, alias: &str) -> Result<Session> {
    let session = prepare_join_session(server_url, room_id, alias).await?;
    perform_join_finalize(session).await
}

#[cfg(test)]
async fn perform_join_with_identity(
    server_url: &str,
    room_id: &str,
    alias: &str,
    pop_public_key: &[u8],
    pop_secret_key: &[u8],
) -> Result<Session> {
    let session = prepare_join_session_with_identity(
        server_url,
        room_id,
        alias,
        pop_public_key.to_vec(),
        pop_secret_key.to_vec(),
    )
    .await?;
    perform_join_finalize(session).await
}

async fn perform_join_finalize(mut session: Session) -> Result<Session> {
    let client = new_api_client(&session.server_url);
    let mut forward_state = session.forward_state.clone();
    let mut retry_attempt = 0u32;
    let ticket = loop {
        match client
            .merge_ticket_refresh(&session.room_id, &session.leaf_id)
            .await
        {
            Ok(ticket) => break ticket,
            Err(err) => {
                if let ApiClientError::HttpStatus {
                    status,
                    message,
                    freeze_code,
                    ..
                } = &err
                    && should_retry_ticket_http_error(status.as_u16(), message, *freeze_code)
                    && retry_attempt < TICKET_RETRY_MAX_ATTEMPTS
                {
                    let delay = ticket_retry_delay(retry_attempt);
                    retry_attempt = retry_attempt.saturating_add(1);
                    warn!(
                        attempt = retry_attempt,
                        delay_ms = delay.as_millis() as u64,
                        status = status.as_u16(),
                        message = %message,
                        "merge_ticket_refresh race/concurrency rejection during join finalize; retrying"
                    );
                    sleep(delay).await;
                    continue;
                }

                return Err(err).context("fetch merge ticket for join finalize");
            }
        }
    };

    if !ticket.srx_cbor.is_empty() {
        return Err(anyhow!(
            "join finalize merge ticket unexpectedly contained SRX payload"
        ));
    }
    ensure_supported_attested_current_state_extension(
        "join finalize merge ticket",
        ticket.history_authority_extension,
        ticket.current_global_history_attestation_bytes.as_slice(),
    )?;

    let parities = hydrate_parities(
        &ticket.parities,
        session.fs_ec,
        session.fs_epoch_commit,
        session.fs_dev_prev_commit,
    );
    let pivot = select_pivot_parity(&parities)
        .ok_or_else(|| anyhow!("merge ticket missing pivot parity entries for join finalize"))?;

    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_KBROAD_ALG, Value::Text("ml-kem-768".to_string()));
    header.insert(
        hdr::HDR_KBROAD_PUB,
        Value::Bytes(ticket.kbroad_public.clone()),
    );
    if session.join_finalize_auth_token == [0u8; 32] {
        return Err(anyhow!(
            "join finalize requires a non-zero server-issued join_finalize_auth_token"
        ));
    }
    header.insert(
        hdr::HDR_JOIN_FINALIZE_AUTH,
        Value::Bytes(session.join_finalize_auth_token.to_vec()),
    );

    let cat = bytes32("cat", &ticket.cat)?;
    let pox_r_commit = bytes32("pox_r_commit", &ticket.pox_r_commit)?;
    let parent_root_arr = bytes32("parent_root", &ticket.parent_root)?;
    let join_delta_root_arr = bytes32("join_delta_root", &ticket.join_delta_root)?;
    let revoked_since_root_arr = bytes32("revoked_since_root", &ticket.revoked_since_root)?;
    let revoked_root_arr = bytes32("revoked_root", &ticket.revoked_root)?;
    let tswe_salt_hash_arr = bytes32("tswe_salt_hash", &ticket.tswe_salt_hash)?;
    let snapshot_hash = bytes32("kem_tree_hash_after", &ticket.kem_tree_hash_after)?;
    let barrier_n_max = validate_barrier_n_max(if ticket.n_max == 0 {
        DEFAULT_BARRIER_N_MAX
    } else {
        ticket.n_max
    })?;
    if ticket.cover_leaf_index >= barrier_n_max {
        return Err(anyhow!(
            "cover_leaf_index out of range for barrier tree: {} >= {}",
            ticket.cover_leaf_index,
            barrier_n_max
        ));
    }
    let revocation_roots_hash =
        compute_revocation_roots_hash(&revoked_since_root_arr, &revoked_root_arr)?;
    let committed_revocation_roots_hash =
        compute_revocation_roots_hash(&pivot.revoked_since_root, &pivot.revoked_root)?;
    let barrier_tree_response = client
        .barrier_fetch_public_tree(&session.room_id, &snapshot_hash)
        .await
        .context("fetch barrier public tree snapshot for join finalize")?;
    let barrier_tree_snapshot = barrier_tree_response.tree;
    if barrier_tree_snapshot.n_max != barrier_n_max {
        return Err(anyhow!(
            "barrier tree snapshot n_max mismatch: expected {barrier_n_max}, got {}",
            barrier_tree_snapshot.n_max
        ));
    }
    let join_resolution = client
        .barrier_resolve_joins_since(&session.room_id, ticket.barrier_version)
        .await
        .context("resolve barrier joins since previous version for join finalize")?;
    let revoked_resolution = client
        .barrier_resolve_revoked_leaves(&session.room_id, &committed_revocation_roots_hash)
        .await
        .context("resolve committed barrier revoked leaves for join finalize")?;
    ensure_matching_history_dependencies(
        "join finalize",
        Some(&ticket.current_history_commitment.history_view_id),
        &ticket.current_history_commitment,
        &barrier_tree_response.history_view_id,
        &barrier_tree_response.history_commitment,
        &join_resolution.history_view_id,
        &join_resolution.history_commitment,
        &revoked_resolution.history_view_id,
        &revoked_resolution.history_commitment,
    )?;
    let history_commitment_header =
        encode_history_commitment_header(&barrier_tree_response.history_commitment)?;
    header.insert(
        hdr::HDR_BARRIER_HISTORY_COMMITMENT,
        Value::Bytes(history_commitment_header.clone()),
    );
    if !ticket.current_global_history_attestation_bytes.is_empty() {
        header.insert(
            hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION,
            Value::Bytes(ticket.current_global_history_attestation_bytes.clone()),
        );
    }
    let mut snapshot_pre = barrier_tree_snapshot.pk_entries.clone();
    apply_join_set_to_snapshot(
        snapshot_pre.as_mut_slice(),
        barrier_n_max,
        join_resolution.records.as_slice(),
    )?;
    apply_revoked_set_to_snapshot(
        snapshot_pre.as_mut_slice(),
        barrier_n_max,
        revoked_resolution.leaf_indices.as_slice(),
    )?;
    let kem_tree_hash_before = compute_barrier_tree_hash(barrier_n_max, snapshot_pre.as_slice())?;
    let next_barrier_version = ticket.barrier_version.saturating_add(1);
    let barrier_update = build_barrier_update_bytes(
        &session.gid,
        barrier_n_max,
        ticket.cover_leaf_index,
        next_barrier_version,
        ticket.barrier_version,
        revocation_roots_hash,
        kem_tree_hash_before,
        snapshot_pre.as_slice(),
    )?;
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(barrier_update.raw_update.clone()),
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(2u64)),
    );
    if !ticket.current_global_history_attestation_bytes.is_empty() {
        let receipt = encode_full_verification_receipt(
            &session.gid,
            &session.leaf_id,
            2,
            ticket.cover_leaf_index,
            history_commitment_header.as_slice(),
            ticket.current_global_history_attestation_bytes.as_slice(),
            barrier_update.raw_update.as_slice(),
            session.pop_secret.as_bytes(),
        )?;
        header.insert(
            hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT,
            Value::Bytes(receipt),
        );
    }

    let parts = AnchorInstanceParts {
        gid: &session.gid,
        cat: cat.as_slice(),
        tswe_salt_hash: tswe_salt_hash_arr.as_slice(),
        parent_root: parent_root_arr.as_slice(),
        join_delta_root: join_delta_root_arr.as_slice(),
        revoked_since_prev_root: revoked_since_root_arr.as_slice(),
        revoked_root: revoked_root_arr.as_slice(),
        pox_r_commit: Some(pox_r_commit.as_slice()),
    };

    let witness_bytes = if ticket.witness_cbor.is_empty() {
        None
    } else {
        Some(ticket.witness_cbor.as_slice())
    };

    let params = OrchestrationParams {
        msphf_crs_id: ticket.msphf_crs_id.as_str(),
        params_id: ticket.msphf_params_id.as_str(),
        srx: None,
        srx_mode: SrxMode::Complete,
        pop_keys: Some(PopKeypair {
            algorithm: "ML-DSA-65",
            public_key: session.pop_public_key.as_slice(),
            secret_key: session.pop_secret.as_ref(),
        }),
        leaf_id_mode: LeafIdMode::PerGroup,
        proof_mode: ticket.proof_mode.as_str(),
        vrf_id: ticket.vrf_id.as_str(),
        policy_version: ticket.policy_version.as_str(),
        vrf_secret_key: Some(session.vrf_secret_key.as_slice()),
        vrf_public_key: Some(session.vrf_public_key.as_slice()),
        fs_policy_version: ticket.fs_policy_version.as_str(),
        fs_epoch_base_ts: ticket.fs_epoch_base_ts,
        barrier_version: next_barrier_version,
        fs_join: FsJoinInputs {
            fs_ec: session.fs_ec,
            fs_epoch_commit: session.fs_epoch_commit,
            fs_dev_prev_commit: session.fs_dev_prev_commit,
        },
        fs_merge: FsMergeInputs::default(),
    };

    let build_join_finalize_bundle = |forward_state: &mut ForwardSecrecyState,
                                      disable_autonomic_evolve: bool|
     -> Result<(ClientEpochBundle, ClientEpochBundle)> {
        let mut bundle = if disable_autonomic_evolve {
            CityGClient::generate_merge_with_forward_state_without_evolve(
                header.clone(),
                parts.clone(),
                params.clone(),
                Some(forward_state),
                &parities,
                None,
                witness_bytes,
            )
        } else {
            CityGClient::generate_merge_with_forward_state(
                header.clone(),
                parts.clone(),
                params.clone(),
                Some(forward_state),
                &parities,
                None,
                witness_bytes,
            )
        }
        .context("generate join finalize bundle")?;
        let pristine_bundle = bundle.clone();
        strip_srx_and_rollup(&mut bundle.header_map);
        apply_pivot_alignment(&mut bundle.header_map, pivot);
        let computed_anchor_ctx =
            build_anchor_seed_ctx(&bundle.header_map).context("compute anchor seed ctx")?;
        let seed_ctx_hash =
            compute_seed_ctx_hash(&computed_anchor_ctx).context("compute_seed_ctx_hash")?;
        let seed_commit = compute_seed_commit(
            &computed_anchor_ctx,
            &SeedCommitFields {
                gid: &session.gid,
                cat: cat.as_slice(),
                we_epoch_id: bundle.we_epoch_id,
            },
        )
        .context("compute_seed_commit")?;
        let seed_bundle_commit = compute_seed_bundle_commit(
            &computed_anchor_ctx,
            &bundle.hp_binding.rho_commit,
            &session.gid,
            cat.as_slice(),
            &parent_root_arr,
        )
        .context("compute_seed_bundle_commit")?;
        let derived_we_epoch_id =
            derive_we_epoch_id(&session.gid, &parent_root_arr, &seed_ctx_hash)
                .context("derive we_epoch_id")?;

        bundle.anchor.anchor_hdr_ctx = computed_anchor_ctx;
        bundle.hp_binding.seed_ctx_hash = seed_ctx_hash;
        bundle.hp_binding.seed_commit = seed_commit;
        bundle.hp_binding.seed_bundle_commit = seed_bundle_commit;
        bundle.we_epoch_id = derived_we_epoch_id;
        bundle
            .seal_local_hp_header_with_barrier_key(&barrier_update.k_barrier_new)
            .context("seal merge HP envelope for join finalize")?;
        bundle
            .header_map
            .insert(hdr::HDR_SEED_CTX_HASH, Value::Bytes(seed_ctx_hash.to_vec()));
        bundle.header_map.insert(
            hdr::HDR_RHO_COMMIT,
            Value::Bytes(bundle.hp_binding.rho_commit.to_vec()),
        );
        bundle.header_map.insert(
            hdr::HDR_SEED_BUNDLE_COMMIT,
            Value::Bytes(seed_bundle_commit.to_vec()),
        );

        if let Some(commit) = recompute_srx_commit(&bundle.header_map)? {
            bundle
                .header_map
                .insert(hdr::HDR_SRX_COMMIT, Value::Bytes(commit.to_vec()));
        }
        let stored_commit = extract_bytes(&bundle.header_map, hdr::HDR_PROOFS_COMMIT)
            .context("join finalize bundle missing proofs_commit")?;
        let recomputed_commit =
            recompute_proofs_commit(&bundle.header_map).context("recompute proofs commit")?;
        if stored_commit.as_slice() != recomputed_commit {
            bundle.header_map.insert(
                hdr::HDR_PROOFS_COMMIT,
                Value::Bytes(recomputed_commit.to_vec()),
            );
        }

        Ok((bundle, pristine_bundle))
    };

    let pristine_forward_state = forward_state.clone();
    let (mut bundle, pristine_bundle) = build_join_finalize_bundle(&mut forward_state, false)?;

    match client.refresh_pivot(&bundle).await {
        Ok(_) => {}
        Err(ApiClientError::HttpStatus { message, .. })
            if message.contains("pivot head missing")
                || message.contains("refresh payload diverges from stored parity") => {}
        Err(err) => return Err(err).context("refresh pivot parity for join finalize"),
    }

    match client.accept_epoch_bundle(&bundle).await {
        Ok(_) => {}
        Err(ApiClientError::HttpStatus {
            freeze_code,
            freeze_reason,
            ..
        }) if is_fs_forward_jump_group_http_error(freeze_code, freeze_reason.as_deref()) => {
            forward_state = pristine_forward_state;
            let rebuilt = build_join_finalize_bundle(&mut forward_state, true)?;
            bundle = rebuilt.0;
            match client.refresh_pivot(&bundle).await {
                Ok(_) => {}
                Err(ApiClientError::HttpStatus { message, .. })
                    if message.contains("pivot head missing")
                        || message.contains("refresh payload diverges from stored parity") => {}
                Err(err) => {
                    return Err(err).context("refresh pivot parity for join finalize retry");
                }
            }
            client
                .accept_epoch_bundle(&bundle)
                .await
                .context("server rejected join finalize bundle after stale-group retry")?;
        }
        Err(ApiClientError::HttpStatus {
            message,
            freeze_reason,
            ..
        }) if message.contains("mh_heads_invalid")
            || freeze_reason.as_deref() == Some("mh_heads_invalid") =>
        {
            let _ = client.refresh_pivot(&pristine_bundle).await;
            client
                .accept_epoch_bundle(&pristine_bundle)
                .await
                .context("server rejected pristine join finalize bundle")?;
            bundle = pristine_bundle;
        }
        Err(ApiClientError::HttpStatus {
            status,
            message,
            freeze_code,
            freeze_reason,
            ..
        }) => {
            let detail = describe_http_failure(
                status.as_str(),
                &message,
                freeze_code,
                freeze_reason.as_deref(),
            );
            return Err(anyhow!(detail));
        }
        Err(err) => return Err(err.into()),
    }

    let fs_ec = match bundle.header_map.get(&hdr::HDR_FS_EC) {
        Some(Value::Integer(int)) => (*int)
            .try_into()
            .map_err(|_| anyhow!("join finalize bundle fs_ec out of range"))?,
        Some(_) => return Err(anyhow!("join finalize bundle fs_ec has invalid type")),
        None => session.fs_ec,
    };
    let fs_epoch_commit = bytes32(
        "fs_epoch_commit",
        bundle
            .header_map
            .get(&hdr::HDR_FS_EPOCH_COMMIT)
            .and_then(Value::as_bytes)
            .ok_or(anyhow!("join finalize bundle missing fs_epoch_commit"))?,
    )?;
    let fs_dev_prev_commit = bytes32(
        "fs_dev_prev_commit",
        bundle
            .header_map
            .get(&hdr::HDR_FS_DEV_COMMIT)
            .or_else(|| bundle.header_map.get(&hdr::HDR_FS_DEV_PREV_COMMIT))
            .and_then(Value::as_bytes)
            .ok_or(anyhow!("join finalize bundle missing fs_dev commit"))?,
    )?;

    forward_state.set_last_we_epoch_id(bundle.we_epoch_id);
    forward_state.set_epoch_base_ts(ticket.fs_epoch_base_ts);
    session.forward_state = forward_state;
    session.fs_ec = fs_ec;
    session.fs_epoch_commit = fs_epoch_commit;
    session.fs_dev_prev_commit = fs_dev_prev_commit;
    session.we_epoch_id = bundle.we_epoch_id;
    session.xk_hash = bundle.hp_binding.xk_hash;
    session.epoch_key = bundle.epoch_key;
    session.barrier_version = next_barrier_version;
    session
        .k_barrier
        .copy_from_slice(barrier_update.k_barrier_new.as_ref());
    session.anchor_hdr_ctx = bundle.anchor.anchor_hdr_ctx.clone();
    session.seed_ctx_hash = bundle.hp_binding.seed_ctx_hash;
    session.seed_commit = bundle.hp_binding.seed_commit;
    session.seed_bundle_commit = bundle.hp_binding.seed_bundle_commit;
    session.join_finalize_auth_token = [0u8; 32];
    session.current_history_authority_extension = None;
    session.current_global_history_attestation_bytes.clear();
    session.fs_fingerprint = compute_fs_fingerprint_from_header(&bundle.header_map).or_else(|| {
        derive_fs_fingerprint_from_fields(
            ticket.fs_policy_version.as_str(),
            session.fs_ec,
            &session.fs_epoch_commit,
            ticket.fs_epoch_base_ts,
        )
    });
    session.stored_header_map = bundle.header_map.clone();
    Ok(session)
}

async fn perform_leave(session: &Session, verbose: bool) -> Result<()> {
    let client = new_api_client(&session.server_url);
    let mut forward_state = session.forward_state.clone();
    let mut retry_attempt = 0u32;
    let ticket = loop {
        match client
            .merge_ticket(&session.room_id, &session.leaf_id)
            .await
        {
            Ok(ticket) => break ticket,
            Err(err) => {
                if let ApiClientError::HttpStatus {
                    status,
                    message,
                    freeze_code,
                    ..
                } = &err
                    && should_retry_ticket_http_error(status.as_u16(), message, *freeze_code)
                    && retry_attempt < TICKET_RETRY_MAX_ATTEMPTS
                {
                    let delay = ticket_retry_delay(retry_attempt);
                    retry_attempt = retry_attempt.saturating_add(1);
                    warn!(
                        attempt = retry_attempt,
                        delay_ms = delay.as_millis() as u64,
                        status = status.as_u16(),
                        message = %message,
                        "merge_ticket race/concurrency rejection; retrying"
                    );
                    sleep(delay).await;
                    continue;
                }

                return Err(err).context("fetch merge ticket");
            }
        }
    };
    ensure_supported_attested_current_state_extension(
        "leave merge ticket",
        ticket.history_authority_extension,
        ticket.current_global_history_attestation_bytes.as_slice(),
    )?;
    let current_fs_ec = session.fs_ec;
    let current_fs_epoch_commit = session.fs_epoch_commit;
    let current_fs_dev_prev_commit = session.fs_dev_prev_commit;
    let current_anchor_hdr_ctx = session.anchor_hdr_ctx.clone();
    let current_seed_ctx_hash = session.seed_ctx_hash;
    let current_seed_commit = session.seed_commit;
    let current_seed_bundle_commit = session.seed_bundle_commit;
    let current_stored_header_map = session.stored_header_map.clone();

    let parities = hydrate_parities(
        &ticket.parities,
        current_fs_ec,
        current_fs_epoch_commit,
        current_fs_dev_prev_commit,
    );

    if verbose {
        for (idx, parity) in parities.iter().enumerate() {
            println!(
                "parity[{idx}] accept_seq={} is_join={} fs_ec_present={} fs_dev_present={} fs_epoch_present={}",
                parity.accept_seq,
                parity.is_join,
                parity.fs_ec.is_some(),
                parity.fs_dev_commit.is_some(),
                parity.fs_epoch_commit.is_some()
            );
        }
    }

    let mut pivot: Option<&PivotParity> = None;
    for candidate in &parities {
        let better = match pivot {
            None => true,
            Some(current) => {
                candidate.accept_seq > current.accept_seq
                    || (candidate.accept_seq == current.accept_seq
                        && candidate.xk_hash < current.xk_hash)
            }
        };
        if better {
            pivot = Some(candidate);
        }
    }
    let pivot = pivot.ok_or(anyhow!("merge ticket missing pivot parity entries"))?;

    let srx_inputs = SrxInputsOwned::from_cbor(&ticket.srx_cbor)
        .context("decode SRX inputs")?
        .into_srx_inputs();

    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_KBROAD_ALG, Value::Text("ml-kem-768".to_string()));
    header.insert(
        hdr::HDR_KBROAD_PUB,
        Value::Bytes(ticket.kbroad_public.clone()),
    );

    let cat = bytes32("cat", &ticket.cat)?;
    let pox_r_commit = bytes32("pox_r_commit", &ticket.pox_r_commit)?;

    let parent_root_arr = bytes32("parent_root", &ticket.parent_root)?;
    let join_delta_root_arr = bytes32("join_delta_root", &ticket.join_delta_root)?;
    let revoked_since_root_arr = bytes32("revoked_since_root", &ticket.revoked_since_root)?;
    let revoked_root_arr = bytes32("revoked_root", &ticket.revoked_root)?;
    let tswe_salt_hash_arr = bytes32("tswe_salt_hash", &ticket.tswe_salt_hash)?;
    let snapshot_hash = bytes32("kem_tree_hash_after", &ticket.kem_tree_hash_after)?;
    let next_barrier_version = ticket.barrier_version.saturating_add(1);
    let revocation_roots_hash =
        compute_revocation_roots_hash(&revoked_since_root_arr, &revoked_root_arr)?;
    let committed_revocation_roots_hash =
        compute_revocation_roots_hash(&pivot.revoked_since_root, &pivot.revoked_root)?;
    let barrier_tree_response = client
        .barrier_fetch_public_tree(&session.room_id, &snapshot_hash)
        .await
        .context("fetch barrier public tree snapshot")?;
    let barrier_tree_snapshot = barrier_tree_response.tree;
    let barrier_n_max = validate_barrier_n_max(if ticket.n_max == 0 {
        DEFAULT_BARRIER_N_MAX
    } else {
        ticket.n_max
    })?;
    if ticket.cover_leaf_index >= barrier_n_max {
        return Err(anyhow!(
            "cover_leaf_index out of range for barrier tree: {} >= {}",
            ticket.cover_leaf_index,
            barrier_n_max
        ));
    }
    if barrier_tree_snapshot.n_max != barrier_n_max {
        return Err(anyhow!(
            "barrier tree snapshot n_max mismatch: expected {barrier_n_max}, got {}",
            barrier_tree_snapshot.n_max
        ));
    }
    let join_resolution = client
        .barrier_resolve_joins_since(&session.room_id, ticket.barrier_version)
        .await
        .context("resolve barrier joins since previous version")?;
    let revoked_resolution = client
        .barrier_resolve_revoked_leaves(&session.room_id, &committed_revocation_roots_hash)
        .await
        .context("resolve committed barrier revoked leaf indices")?;
    ensure_matching_history_dependencies(
        "leave",
        Some(&ticket.current_history_commitment.history_view_id),
        &ticket.current_history_commitment,
        &barrier_tree_response.history_view_id,
        &barrier_tree_response.history_commitment,
        &join_resolution.history_view_id,
        &join_resolution.history_commitment,
        &revoked_resolution.history_view_id,
        &revoked_resolution.history_commitment,
    )?;
    let history_commitment_header =
        encode_history_commitment_header(&barrier_tree_response.history_commitment)?;
    header.insert(
        hdr::HDR_BARRIER_HISTORY_COMMITMENT,
        Value::Bytes(history_commitment_header.clone()),
    );
    if !ticket.current_global_history_attestation_bytes.is_empty() {
        header.insert(
            hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION,
            Value::Bytes(ticket.current_global_history_attestation_bytes.clone()),
        );
    }
    let mut snapshot_pre = barrier_tree_snapshot.pk_entries.clone();
    apply_join_set_to_snapshot(
        snapshot_pre.as_mut_slice(),
        barrier_n_max,
        join_resolution.records.as_slice(),
    )?;
    apply_revoked_set_to_snapshot(
        snapshot_pre.as_mut_slice(),
        barrier_n_max,
        revoked_resolution.leaf_indices.as_slice(),
    )?;
    let leaf_base = barrier_n_max.saturating_sub(1);
    let revoked_leaf_node = leaf_base.saturating_add(ticket.cover_leaf_index);
    blank_leaf_and_path(snapshot_pre.as_mut_slice(), revoked_leaf_node)?;
    let kem_tree_hash_before = compute_barrier_tree_hash(barrier_n_max, snapshot_pre.as_slice())?;
    let barrier_update = build_barrier_update_bytes(
        &session.gid,
        barrier_n_max,
        ticket.cover_leaf_index,
        next_barrier_version,
        ticket.barrier_version,
        revocation_roots_hash,
        kem_tree_hash_before,
        snapshot_pre.as_slice(),
    )?;
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(barrier_update.raw_update.clone()),
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(0u64)),
    );
    if !ticket.current_global_history_attestation_bytes.is_empty() {
        let receipt = encode_full_verification_receipt(
            &session.gid,
            &session.leaf_id,
            0,
            ticket.cover_leaf_index,
            history_commitment_header.as_slice(),
            ticket.current_global_history_attestation_bytes.as_slice(),
            barrier_update.raw_update.as_slice(),
            session.pop_secret.as_bytes(),
        )?;
        header.insert(
            hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT,
            Value::Bytes(receipt),
        );
    }

    let parts = AnchorInstanceParts {
        gid: &session.gid,
        cat: cat.as_slice(),
        tswe_salt_hash: tswe_salt_hash_arr.as_slice(),
        parent_root: parent_root_arr.as_slice(),
        join_delta_root: join_delta_root_arr.as_slice(),
        revoked_since_prev_root: revoked_since_root_arr.as_slice(),
        revoked_root: revoked_root_arr.as_slice(),
        pox_r_commit: Some(pox_r_commit.as_slice()),
    };

    let pop_secret = session.pop_secret.as_ref();

    let params = OrchestrationParams {
        msphf_crs_id: ticket.msphf_crs_id.as_str(),
        params_id: ticket.msphf_params_id.as_str(),
        srx: Some(srx_inputs),
        srx_mode: SrxMode::Complete,
        pop_keys: Some(PopKeypair {
            algorithm: "ML-DSA-65",
            public_key: session.pop_public_key.as_slice(),
            secret_key: pop_secret,
        }),
        leaf_id_mode: LeafIdMode::PerGroup,
        proof_mode: ticket.proof_mode.as_str(),
        vrf_id: ticket.vrf_id.as_str(),
        policy_version: ticket.policy_version.as_str(),
        vrf_secret_key: Some(&session.vrf_secret_key[..]),
        vrf_public_key: Some(&session.vrf_public_key[..]),
        fs_policy_version: ticket.fs_policy_version.as_str(),
        fs_epoch_base_ts: ticket.fs_epoch_base_ts,
        barrier_version: next_barrier_version,
        fs_join: FsJoinInputs {
            fs_ec: current_fs_ec,
            fs_epoch_commit: current_fs_epoch_commit,
            fs_dev_prev_commit: current_fs_dev_prev_commit,
        },
        fs_merge: FsMergeInputs::default(),
    };

    let witness_bytes = if ticket.witness_cbor.is_empty() {
        None
    } else {
        Some(ticket.witness_cbor.as_slice())
    };

    let mut bundle = CityGClient::generate_merge_with_forward_state(
        header,
        parts,
        params,
        Some(&mut forward_state),
        &parities,
        None,
        witness_bytes,
    )
    .context("generate merge bundle")?;
    let pristine_bundle = bundle.clone();
    strip_srx_and_rollup(&mut bundle.header_map);
    apply_pivot_alignment(&mut bundle.header_map, pivot);
    if let Some(commit) = recompute_srx_commit(&bundle.header_map)? {
        bundle
            .header_map
            .insert(hdr::HDR_SRX_COMMIT, Value::Bytes(commit.to_vec()));
    }
    let computed_anchor_ctx =
        build_anchor_seed_ctx(&bundle.header_map).context("compute anchor seed ctx")?;
    let seed_ctx_hash =
        compute_seed_ctx_hash(&computed_anchor_ctx).context("compute_seed_ctx_hash")?;
    let seed_commit = compute_seed_commit(
        &computed_anchor_ctx,
        &SeedCommitFields {
            gid: &session.gid,
            cat: cat.as_slice(),
            we_epoch_id: bundle.we_epoch_id,
        },
    )
    .context("compute_seed_commit")?;
    let seed_bundle_commit = compute_seed_bundle_commit(
        &computed_anchor_ctx,
        &bundle.hp_binding.rho_commit,
        &session.gid,
        cat.as_slice(),
        &parent_root_arr,
    )
    .context("compute_seed_bundle_commit")?;
    let derived_we_epoch_id = derive_we_epoch_id(&session.gid, &parent_root_arr, &seed_ctx_hash)
        .context("derive we_epoch_id")?;

    if verbose {
        println!(
            "seed_ctx_hash_equal={} seed_commit_equal={} seed_bundle_equal={}",
            seed_ctx_hash == current_seed_ctx_hash,
            seed_commit == current_seed_commit,
            seed_bundle_commit == current_seed_bundle_commit
        );
        println!(
            "binding_match={} seed_commit_match={} seed_bundle_match={}",
            bundle.hp_binding.seed_ctx_hash == seed_ctx_hash,
            bundle.hp_binding.seed_commit == seed_commit,
            bundle.hp_binding.seed_bundle_commit == seed_bundle_commit
        );
    }

    bundle.anchor.anchor_hdr_ctx = computed_anchor_ctx.clone();
    bundle.hp_binding.seed_ctx_hash = seed_ctx_hash;
    bundle.hp_binding.seed_commit = seed_commit;
    bundle.hp_binding.seed_bundle_commit = seed_bundle_commit;
    bundle.we_epoch_id = derived_we_epoch_id;
    bundle
        .rebind_local_hp_envelope_with_barrier_key(&barrier_update.k_barrier_new)
        .context("rebind merge HP envelope for leave")?;
    bundle
        .header_map
        .insert(hdr::HDR_SEED_CTX_HASH, Value::Bytes(seed_ctx_hash.to_vec()));
    bundle.header_map.insert(
        hdr::HDR_RHO_COMMIT,
        Value::Bytes(bundle.hp_binding.rho_commit.to_vec()),
    );
    bundle.header_map.insert(
        hdr::HDR_SEED_BUNDLE_COMMIT,
        Value::Bytes(seed_bundle_commit.to_vec()),
    );

    if verbose {
        println!(
            "pre-submit roots: parent={} join_delta={} revoked_since={} revoked={}",
            describe_value(bundle.header_map.get(&110)),
            describe_value(bundle.header_map.get(&111)),
            describe_value(bundle.header_map.get(&112)),
            describe_value(bundle.header_map.get(&hdr::HDR_REVOKED_ROOT)),
        );
        if let Some(Value::Bytes(bytes)) = bundle.header_map.get(&110) {
            println!("pre-submit parent root hex={}", hex::encode(bytes));
        }
        if let Some(Value::Bytes(bytes)) = bundle.header_map.get(&111) {
            println!("pre-submit join root hex={}", hex::encode(bytes));
        }
        let stored_ctx_map: BTreeMap<u64, Value> =
            ciborium::de::from_reader(current_anchor_hdr_ctx.as_slice())
                .context("decode stored anchor ctx")?;
        println!(
            "stored ctx roots: parent={} join_delta={} revoked_since={} revoked={}",
            describe_value(stored_ctx_map.get(&110)),
            describe_value(stored_ctx_map.get(&111)),
            describe_value(stored_ctx_map.get(&112)),
            describe_value(stored_ctx_map.get(&113)),
        );
        if let Some(Value::Bytes(bytes)) = stored_ctx_map.get(&110) {
            println!("stored ctx parent root hex={}", hex::encode(bytes));
        }
        let adjusted: Vec<u64> = Vec::new();

        use std::collections::BTreeSet;
        let keys: BTreeSet<u64> = current_stored_header_map
            .keys()
            .chain(bundle.header_map.keys())
            .copied()
            .collect();
        let mut diff_report = Vec::new();
        for key in keys {
            let stored = current_stored_header_map.get(&key);
            let current = bundle.header_map.get(&key);
            if stored != current {
                diff_report.push((key, describe_value(stored), describe_value(current)));
            }
        }
        println!(
            "anchor_ctx_equal={} adjusted_keys={:?} diff_keys={:?}",
            computed_anchor_ctx == current_anchor_hdr_ctx,
            adjusted,
            diff_report
                .iter()
                .map(|(key, _, _)| *key)
                .collect::<Vec<_>>()
        );
        for (key, stored_desc, current_desc) in &diff_report {
            println!(
                " key {}: stored={} current={}",
                key, stored_desc, current_desc
            );
        }

        for key in [
            hdr::HDR_TSWE_ALG,
            hdr::HDR_MERKLE_SUITE,
            hdr::HDR_KBROAD_ALG,
            hdr::HDR_KBROAD_PUB,
            hdr::HDR_CRS_ID,
            hdr::HDR_PARAMS_ID,
        ] {
            println!(
                " hdr {} => {}",
                key,
                describe_value(bundle.header_map.get(&key))
            );
        }
    }
    for key in [
        hdr::HDR_POP_ALG,
        hdr::HDR_POP_SIG,
        hdr::HDR_BOOTSTRAP_ALG,
        hdr::HDR_BOOTSTRAP_PK,
        hdr::HDR_BOOTSTRAP_SIG,
    ] {
        bundle.header_map.remove(&key);
    }

    let pivot_fs_len = pivot.fs_capss.len();
    let bundle_fs = extract_bytes(&bundle.header_map, hdr::HDR_FS_CAPSS)
        .context("bundle missing fs_capss for comparison")?;
    let vrf_bytes = extract_bytes(&bundle.header_map, hdr::HDR_VRF_PROOF)
        .context("bundle missing vrf_proof for comparison")?;
    let has_srx_root = bundle.header_map.contains_key(&hdr::HDR_SRX_ROOT_SW);
    let has_srx_smallwood = bundle.header_map.contains_key(&hdr::HDR_SRX_SMALLWOOD);
    if verbose {
        let fs_match = pivot_fs_len == bundle_fs.len() && pivot.fs_capss == bundle_fs;
        let vrf_match = pivot.vrf_proof == vrf_bytes;
        println!(
            "fs_capss pivot_len={} bundle_len={} equal={} vrf_equal={}",
            pivot_fs_len,
            bundle_fs.len(),
            fs_match,
            vrf_match
        );
        println!(
            "srx_root_present={} srx_smallwood_present={}",
            has_srx_root, has_srx_smallwood
        );
        println!(
            "pivot_has_srx_commit={} pivot_accept_seq={}",
            pivot.srx_commit.is_some(),
            pivot.accept_seq
        );
        if let Some(Value::Array(items)) = bundle.header_map.get(&hdr::HDR_MH_HEADS) {
            println!("mh_heads len={}", items.len());
        }
    }

    let stored_commit = extract_bytes(&bundle.header_map, hdr::HDR_PROOFS_COMMIT)
        .context("bundle missing proofs_commit")?;
    let recomputed_commit =
        recompute_proofs_commit(&bundle.header_map).context("recompute proofs commit")?;
    if verbose {
        println!(
            "proofs_commit stored={} recomputed={}",
            hex::encode(&stored_commit),
            hex::encode(recomputed_commit)
        );
    }
    if stored_commit.as_slice() != recomputed_commit {
        if verbose {
            println!("warning: proofs_commit mismatch before submission");
        }
        bundle.header_map.insert(
            hdr::HDR_PROOFS_COMMIT,
            Value::Bytes(recomputed_commit.to_vec()),
        );
    }

    if verbose {
        log_fs_metadata(pivot, &bundle.header_map);
    }

    match client.refresh_pivot(&bundle).await {
        Ok(_) => {}
        Err(ApiClientError::HttpStatus {
            status, message, ..
        }) if message.contains("pivot head missing")
            || message.contains("refresh payload diverges from stored parity") =>
        {
            if verbose {
                println!(
                    "refresh pivot skipped (status={}): {message}",
                    status.as_u16()
                );
            }
        }
        Err(err) => return Err(err).context("refresh pivot parity"),
    }

    match client.accept_epoch_bundle(&bundle).await {
        Ok(_) => Ok(()),
        Err(ApiClientError::HttpStatus {
            message,
            freeze_reason,
            ..
        }) if message.contains("mh_heads_invalid")
            || freeze_reason.as_deref() == Some("mh_heads_invalid") =>
        {
            if verbose {
                println!("retrying leave with pristine merge bundle after mh_heads_invalid");
            }
            let _ = client.refresh_pivot(&pristine_bundle).await;
            client
                .accept_epoch_bundle(&pristine_bundle)
                .await
                .context("server rejected pristine merge bundle")?;
            Ok(())
        }
        Err(ApiClientError::HttpStatus {
            status,
            message,
            freeze_code,
            freeze_reason,
            ..
        }) => {
            let detail = describe_http_failure(
                status.as_str(),
                &message,
                freeze_code,
                freeze_reason.as_deref(),
            );
            Err(anyhow!(detail))
        }
        Err(err) => Err(err.into()),
    }
}

async fn run_watch_mode(params: WatchModeParams<'_>) -> Result<()> {
    let WatchModeParams {
        server_url,
        room_id,
        alias_base,
        count,
        leave_order,
        verbose,
        message_burst,
        session_artifact_dir,
    } = params;
    println!(
        "watch mode: server={server_url} room={room_id} alias_base={alias_base} count={count}"
    );
    let mut sessions = Vec::with_capacity(count);

    let first_alias = alias_for(alias_base, count, 0);
    println!("joining alias={first_alias}");
    let first_session = perform_join(server_url, room_id, &first_alias).await?;
    println!("join ok: weid={}", hex::encode(first_session.we_epoch_id));
    log_fingerprints(&first_session);
    maybe_write_session_artifact(session_artifact_dir, "joined", &first_alias, &first_session)?;
    let message_token = configured_client_message_token()
        .ok_or_else(|| anyhow!("message auth token is not configured"))?;
    let ws_url = websocket_url(server_url, &first_session.gid, &first_session.leaf_id);
    let (mut event_rx, ws_handle) =
        spawn_notification_listener(&ws_url, Some(&message_token)).await?;
    sessions.push(first_session);

    for i in 1..count {
        let alias = alias_for(alias_base, count, i);
        println!("joining alias={alias}");
        let session = perform_join(server_url, room_id, &alias).await?;
        println!("join ok: weid={}", hex::encode(session.we_epoch_id));
        log_fingerprints(&session);
        maybe_write_session_artifact(session_artifact_dir, "joined", &alias, &session)?;
        expect_membership_event(
            &mut event_rx,
            &session.gid,
            &session.leaf_id,
            "join",
            format!("alias {alias} join"),
        )
        .await?;
        sessions.push(session);
    }

    let effective_message_burst_count = message_burst.count.max(1);
    send_message_burst(
        &mut sessions,
        effective_message_burst_count,
        message_burst.interval,
        Some(&mut event_rx),
    )
    .await?;
    for (idx, session) in sessions.iter().enumerate() {
        maybe_write_session_artifact(
            session_artifact_dir,
            "post-burst",
            &alias_for(alias_base, sessions.len(), idx),
            session,
        )?;
    }

    let default_order: Vec<usize> = (1..=sessions.len()).collect();
    let order = leave_order.as_ref().unwrap_or(&default_order);
    for idx in order {
        if *idx == 0 || *idx > sessions.len() {
            return Err(anyhow!("leave order index {idx} invalid"));
        }
        let session = &sessions[*idx - 1];
        maybe_write_session_artifact(
            session_artifact_dir,
            "pre-leave",
            &alias_for(alias_base, sessions.len(), *idx - 1),
            session,
        )?;
        println!(
            "leaving alias={} weid={}",
            alias_for(alias_base, sessions.len(), *idx - 1),
            hex::encode(session.we_epoch_id)
        );
        perform_leave(session, verbose).await?;
        expect_membership_event(
            &mut event_rx,
            &session.gid,
            &session.leaf_id,
            "revoke",
            format!(
                "alias {} leave",
                alias_for(alias_base, sessions.len(), *idx - 1)
            ),
        )
        .await?;
    }

    println!("watch scenario completed successfully");
    ws_handle.abort();
    let _ = ws_handle.await;
    Ok(())
}

async fn send_text_message(session: &mut Session, plaintext: &str) -> Result<()> {
    let client = new_api_client(&session.server_url);
    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let signature = sign_message(
        &session.leaf_id,
        timestamp_ms,
        plaintext.as_bytes(),
        DilithiumSecretKeyTrait::as_bytes(session.pop_secret.as_ref()),
    )?;
    let authenticated = encode_authenticated_message(
        timestamp_ms,
        plaintext.as_bytes(),
        &session.pop_public_key,
        &signature,
    );
    let msg_index: u64 = rng().random();
    let ciphertext = encrypt_message_v2(
        &authenticated,
        &MessageCryptoContext {
            gid: &session.gid,
            we_epoch_id: &session.we_epoch_id,
            xk_hash: &session.xk_hash,
            fs_ec: session.fs_ec,
            barrier_version: session.barrier_version,
            sender_leaf: &session.leaf_id,
            epoch_key: &session.epoch_key,
            k_barrier: &session.k_barrier,
        },
        msg_index,
    )?;
    client
        .send_message(&session.we_epoch_id, &ciphertext, Some(&session.leaf_id))
        .await?;
    Ok(())
}

async fn send_dummy_message(session: &mut Session) -> Result<()> {
    let plaintext = format!("join_leave-message-{}", hex::encode(&session.leaf_id[..4]));
    send_text_message(session, plaintext.as_str()).await
}

#[cfg(test)]
async fn fetch_and_decrypt_messages(session: &mut Session) -> Result<Vec<String>> {
    let client = new_api_client(&session.server_url);
    let response = client
        .fetch_messages(&session.we_epoch_id, &session.leaf_id)
        .await?;

    let mut plaintexts = Vec::new();
    for message in response.messages {
        let sender_leaf: [u8; 32] = match message.sender.as_slice().try_into() {
            Ok(leaf) => leaf,
            Err(_) => continue,
        };
        let replay_context = MessageCryptoContext {
            gid: &session.gid,
            we_epoch_id: &session.we_epoch_id,
            xk_hash: &session.xk_hash,
            fs_ec: session.fs_ec,
            barrier_version: session.barrier_version,
            sender_leaf: &sender_leaf,
            epoch_key: &session.epoch_key,
            k_barrier: &session.k_barrier,
        };
        let replay_tuple_tag =
            derive_msg_replay_tuple_tag(&replay_context).context("derive fs/msg/replay/tuple")?;
        let replay_context_id = derive_msg_replay_context_id(&replay_context)
            .context("derive fs/msg/replay/context")?;
        session
            .msg_replay_state
            .ensure_tuple(replay_tuple_tag, replay_context_id);
        let (msg_index, authenticated) =
            match decrypt_message_v2_with_index(&message.ciphertext, &replay_context) {
                Ok(outcome) => outcome,
                Err(_) => continue,
            };
        if session
            .msg_replay_state
            .contains(replay_tuple_tag, msg_index)
        {
            continue;
        }
        let envelope = match decode_authenticated_message(&authenticated) {
            Ok(envelope) => envelope,
            Err(_) => continue,
        };
        if verify_sender_leaf_binding(&session.gid, &sender_leaf, envelope.public_key).is_err() {
            continue;
        }
        if verify_message_signature(
            &sender_leaf,
            envelope.timestamp_ms,
            envelope.plaintext,
            envelope.signature,
            envelope.public_key,
        )
        .is_err()
        {
            continue;
        }
        session
            .msg_replay_state
            .record(replay_tuple_tag, replay_context_id, msg_index);
        plaintexts.push(String::from_utf8_lossy(envelope.plaintext).into_owned());
    }
    Ok(plaintexts)
}

async fn send_message_burst(
    sessions: &mut [Session],
    message_burst_count: usize,
    message_burst_interval: Duration,
    mut event_rx: Option<&mut mpsc::Receiver<Notification>>,
) -> Result<()> {
    if sessions.is_empty() || message_burst_count == 0 {
        return Ok(());
    }

    for idx in 0..message_burst_count {
        let session = &mut sessions[idx % sessions.len()];
        println!(
            "sending dummy message {}/{} via {}",
            idx + 1,
            message_burst_count,
            hex::encode(session.we_epoch_id)
        );
        send_dummy_message(session).await?;
        if let Some(rx) = event_rx.as_deref_mut() {
            expect_message_event(
                rx,
                &session.we_epoch_id,
                format!("dummy message delivery {}", idx + 1),
            )
            .await?;
        }
        if message_burst_interval > Duration::ZERO && idx + 1 < message_burst_count {
            sleep(message_burst_interval).await;
        }
    }

    Ok(())
}

fn websocket_request(ws_url: &str, token: Option<&str>) -> Result<Request<()>> {
    let mut request = ws_url
        .into_client_request()
        .map_err(|err| anyhow!("failed to build websocket handshake request: {err}"))?;
    if let Some(token) = token {
        let token =
            HeaderValue::from_str(token).context("message auth token is not a valid header")?;
        request.headers_mut().insert(MESSAGE_AUTH_HEADER, token);
    }
    Ok(request)
}

async fn spawn_notification_listener(
    ws_url: &str,
    token: Option<&str>,
) -> Result<(mpsc::Receiver<Notification>, tokio::task::JoinHandle<()>)> {
    let request = websocket_request(ws_url, token)?;
    let (stream, _) = connect_async(request)
        .await
        .with_context(|| format!("failed to connect to websocket {ws_url}"))?;
    let (_write, mut read) = stream.split();
    let (tx, rx) = mpsc::channel(64);
    let handle = tokio::spawn(async move {
        let mut _writer_guard = _write;
        while let Some(msg) = read.next().await {
            match msg {
                Ok(WsMessage::Text(text)) => {
                    if let Ok(value) = serde_json::from_str::<JsonValue>(&text)
                        && let Some(notification) = Notification::from_json(&value)
                        && tx.send(notification).await.is_err()
                    {
                        break;
                    }
                }
                Ok(WsMessage::Close(_)) => break,
                Ok(_) => {}
                Err(err) => {
                    eprintln!("websocket read error: {err}");
                    break;
                }
            }
        }
        drop(_writer_guard);
    });
    Ok((rx, handle))
}

async fn expect_membership_event(
    rx: &mut mpsc::Receiver<Notification>,
    gid: &[u8; 32],
    leaf_id: &[u8; 32],
    expected_kind: &str,
    label: String,
) -> Result<()> {
    let expected_kind = expected_kind.to_string();
    timeout(EVENT_TIMEOUT, async {
        while let Some(event) = rx.recv().await {
            match event {
                Notification::Membership {
                    gid: event_gid,
                    leaf_id: event_leaf,
                    event,
                    timestamp_ms,
                } => {
                    println!(
                        "membership event type={event} gid={} leaf={} ts={}",
                        hex::encode(event_gid),
                        hex::encode(event_leaf),
                        timestamp_ms
                    );
                    if event == expected_kind && event_gid == *gid && event_leaf == *leaf_id {
                        return Ok(());
                    }
                }
                Notification::Lag { lagged_messages } => {
                    println!("websocket lag notice: dropped {lagged_messages} messages");
                }
                _ => {}
            }
        }
        Err(anyhow!(
            "websocket channel closed while waiting for {label}"
        ))
    })
    .await?
}

async fn expect_message_event(
    rx: &mut mpsc::Receiver<Notification>,
    we_epoch_id: &[u8; 32],
    label: String,
) -> Result<()> {
    timeout(EVENT_TIMEOUT, async {
        while let Some(event) = rx.recv().await {
            match event {
                Notification::Message {
                    we_epoch_id: event_weid,
                    timestamp_ms,
                } => {
                    println!(
                        "message event weid={} ts={}",
                        hex::encode(event_weid),
                        timestamp_ms
                    );
                    if event_weid == *we_epoch_id {
                        return Ok(());
                    }
                }
                Notification::Lag { lagged_messages } => {
                    println!("websocket lag notice: dropped {lagged_messages} messages");
                }
                _ => {}
            }
        }
        Err(anyhow!(
            "websocket channel closed while waiting for {label}"
        ))
    })
    .await?
}

fn websocket_url(server_url: &str, gid: &[u8; 32], leaf_id: &[u8; 32]) -> String {
    let base = if let Some(rest) = server_url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = server_url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        format!("ws://{server_url}")
    };
    format!(
        "{base}/v1/ws?gid={}&leaf_id={}",
        hex::encode(gid),
        hex::encode(leaf_id)
    )
}

#[derive(Debug)]
enum Notification {
    Message {
        we_epoch_id: [u8; 32],
        timestamp_ms: u64,
    },
    Membership {
        gid: [u8; 32],
        leaf_id: [u8; 32],
        event: String,
        timestamp_ms: u64,
    },
    Lag {
        lagged_messages: u64,
    },
    Other,
}

impl Notification {
    fn from_json(value: &JsonValue) -> Option<Self> {
        let event_type = value.get("type")?.as_str()?;
        match event_type {
            "message" => {
                let weid = parse_hex32_field(value, "we_epoch_id")?;
                let timestamp = value
                    .get("timestamp_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                Some(Notification::Message {
                    we_epoch_id: weid,
                    timestamp_ms: timestamp,
                })
            }
            "membership" => {
                let gid = parse_hex32_field(value, "gid")?;
                let leaf = parse_hex32_field(value, "leaf_id")?;
                let event = value.get("event")?.as_str()?.to_string();
                let timestamp = value
                    .get("timestamp_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                Some(Notification::Membership {
                    gid,
                    leaf_id: leaf,
                    event,
                    timestamp_ms: timestamp,
                })
            }
            "lag" => {
                let lagged = value
                    .get("lagged_messages")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                Some(Notification::Lag {
                    lagged_messages: lagged,
                })
            }
            _ => Some(Notification::Other),
        }
    }
}

fn parse_hex32_field(value: &JsonValue, key: &str) -> Option<[u8; 32]> {
    let hex_str = value.get(key)?.as_str()?;
    let bytes = hex_decode(hex_str).ok()?;
    bytes.as_slice().try_into().ok()
}

fn extract_bytes(header: &BTreeMap<u64, Value>, key: u64) -> Result<Vec<u8>> {
    match header.get(&key) {
        Some(Value::Bytes(bytes)) => Ok(bytes.clone()),
        Some(_) => Err(anyhow!("header key {key} is not raw bytes")),
        None => Err(anyhow!("header missing key {key}")),
    }
}

fn extract_bytes_opt(header: &BTreeMap<u64, Value>, key: u64) -> Result<Option<Vec<u8>>> {
    match header.get(&key) {
        Some(Value::Bytes(bytes)) => Ok(Some(bytes.clone())),
        Some(Value::Null) => Ok(None),
        Some(_) => Err(anyhow!("header key {key} is not raw bytes")),
        None => Ok(None),
    }
}

fn describe_http_failure(
    status_text: &str,
    message: &str,
    freeze_code: Option<u32>,
    freeze_reason: Option<&str>,
) -> String {
    let mut detail = format!("server error ({status_text}): {message}");
    if let Some(code) = freeze_code {
        match freeze_reason {
            Some(reason) => detail.push_str(&format!(" [freeze {code} {reason}]")),
            None => detail.push_str(&format!(" [freeze {code}]")),
        }
    }
    detail
}

fn is_fs_forward_jump_group_http_error(
    freeze_code: Option<u32>,
    freeze_reason: Option<&str>,
) -> bool {
    freeze_code == Some(9476) || freeze_reason == Some("fs_forward_jump_group")
}

fn recompute_proofs_commit(header: &BTreeMap<u64, Value>) -> Result<[u8; 32]> {
    #[derive(Serialize)]
    struct ProofVec(Vec<ByteBuf>);

    let mut components = Vec::new();
    components.push(ByteBuf::from(extract_bytes(header, hdr::HDR_VRF_PROOF)?));
    components.push(ByteBuf::from(extract_bytes(header, hdr::HDR_FS_CAPSS)?));
    if let Some(root) = extract_bytes_opt(header, hdr::HDR_SRX_ROOT_SW)? {
        components.push(ByteBuf::from(root));
    }
    if let Some(proof) = extract_bytes_opt(header, hdr::HDR_SRX_SMALLWOOD)? {
        components.push(ByteBuf::from(proof));
    }

    msphf_core::hash::h_l("msphf/proofs", &ProofVec(components)).map_err(Into::into)
}

fn describe_value(value: Option<&Value>) -> String {
    match value {
        None => "None".to_string(),
        Some(Value::Bytes(bytes)) => format!("Bytes({})", bytes.len()),
        Some(Value::Text(text)) => format!("Text({})", text),
        Some(Value::Integer(int)) => format!("Integer({:?})", int),
        Some(Value::Bool(flag)) => format!("Bool({flag})"),
        Some(Value::Array(items)) => format!("Array(len={})", items.len()),
        Some(Value::Map(entries)) => format!("Map(len={})", entries.len()),
        Some(Value::Float(f)) => format!("Float({f})"),
        Some(Value::Null) => "Null".to_string(),
        Some(Value::Tag(tag, _)) => format!("Tag({})", tag),
        Some(_) => "Other".to_string(),
    }
}

fn strip_srx_and_rollup(header: &mut BTreeMap<u64, Value>) {
    for key in [
        hdr::HDR_ROLLUP_PROVENANCE_COMMIT,
        hdr::HDR_ROLLUP_EPOCH_REPLAY,
        hdr::HDR_ROLLUP_VCK_COMMIT,
    ] {
        header.remove(&key);
    }
}

fn hydrate_parities(
    parities: &[PivotParity],
    fs_ec: u64,
    fs_epoch_commit: [u8; 32],
    fs_dev_commit: [u8; 32],
) -> Vec<PivotParity> {
    parities
        .iter()
        .cloned()
        .map(|mut parity| {
            if parity.fs_ec.is_none() {
                parity.fs_ec = Some(fs_ec);
            }
            if parity.fs_epoch_commit.is_none() {
                parity.fs_epoch_commit = Some(fs_epoch_commit);
            }
            if parity.fs_dev_commit.is_none() {
                parity.fs_dev_commit = Some(fs_dev_commit);
            }
            parity
        })
        .collect()
}

fn log_fs_metadata(pivot: &PivotParity, header: &BTreeMap<u64, Value>) {
    let pivot_ec = pivot
        .fs_ec
        .map(|value| value.to_string())
        .unwrap_or_else(|| "None".to_string());
    let pivot_epoch = pivot
        .fs_epoch_commit
        .map(hex::encode)
        .unwrap_or_else(|| "None".to_string());
    let pivot_dev = pivot
        .fs_dev_commit
        .map(hex::encode)
        .unwrap_or_else(|| "None".to_string());

    let bundle_ec = header
        .get(&hdr::HDR_FS_EC)
        .map(|value| match value {
            Value::Integer(int) => format!("{int:?}"),
            other => describe_value(Some(other)),
        })
        .unwrap_or_else(|| "None".to_string());
    let bundle_epoch = header
        .get(&hdr::HDR_FS_EPOCH_COMMIT)
        .and_then(Value::as_bytes)
        .map(hex::encode)
        .unwrap_or_else(|| "None".to_string());
    let bundle_dev = header
        .get(&hdr::HDR_FS_DEV_PREV_COMMIT)
        .and_then(Value::as_bytes)
        .map(hex::encode)
        .unwrap_or_else(|| "None".to_string());

    println!(
        "pivot fs: ec={pivot_ec} epoch={pivot_epoch} dev={pivot_dev}; bundle fs: ec={bundle_ec} epoch={bundle_epoch} dev={bundle_dev}"
    );
}

fn apply_pivot_alignment(header: &mut BTreeMap<u64, Value>, pivot: &PivotParity) {
    if let Ok(fs_policy_version) = pivot.policy_version.parse::<u64>() {
        header
            .entry(hdr::HDR_FS_POLICY_VERSION)
            .or_insert_with(|| Value::Integer(Integer::from(fs_policy_version)));
    }
    header
        .entry(hdr::HDR_PROOF_MODE)
        .or_insert_with(|| Value::Text(pivot.proof_mode.clone()));
    header
        .entry(hdr::HDR_VRF_ID)
        .or_insert_with(|| Value::Text(pivot.vrf_id.clone()));
    header
        .entry(hdr::HDR_VRF_PROOF)
        .or_insert_with(|| Value::Bytes(pivot.vrf_proof.clone()));
    header
        .entry(hdr::HDR_VRF_PUBLIC_KEY)
        .or_insert_with(|| Value::Bytes(pivot.vrf_public.clone()));
    header
        .entry(hdr::HDR_VRF_MASK_A)
        .or_insert_with(|| Value::Bytes(pivot.mask_a.to_vec()));
    header
        .entry(hdr::HDR_VRF_MASK_B)
        .or_insert_with(|| Value::Bytes(pivot.mask_b.to_vec()));
    header
        .entry(hdr::HDR_FS_CAPSS)
        .or_insert_with(|| Value::Bytes(pivot.fs_capss.clone()));
    header
        .entry(hdr::HDR_PROOFS_COMMIT)
        .or_insert_with(|| Value::Bytes(pivot.proofs_commit.to_vec()));

    if let Some(fs_ec) = pivot.fs_ec {
        header
            .entry(hdr::HDR_FS_EC)
            .or_insert_with(|| Value::Integer(Integer::from(fs_ec)));
        header
            .entry(hdr::HDR_FS_CHECKPOINT_EC)
            .or_insert_with(|| Value::Integer(Integer::from(fs_ec)));
    }
    if let Some(epoch_commit) = pivot.fs_epoch_commit
        && !header.contains_key(&hdr::HDR_FS_EPOCH_COMMIT)
    {
        header.insert(
            hdr::HDR_FS_EPOCH_COMMIT,
            Value::Bytes(epoch_commit.to_vec()),
        );
    }
    if let Some(dev_commit) = pivot.fs_dev_commit {
        header
            .entry(hdr::HDR_FS_DEV_PREV_COMMIT)
            .or_insert_with(|| Value::Bytes(dev_commit.to_vec()));
        header
            .entry(hdr::HDR_FS_DEV_COMMIT)
            .or_insert_with(|| Value::Bytes(dev_commit.to_vec()));
    }
}

fn recompute_srx_commit(header: &BTreeMap<u64, Value>) -> Result<Option<[u8; 32]>> {
    let payload = match header.get(&hdr::HDR_SRX_PAYLOAD) {
        Some(Value::Bytes(bytes)) => bytes.as_slice(),
        Some(Value::Null) | None => return Ok(None),
        Some(_) => return Err(anyhow!("srx_payload must be bytes")),
    };

    #[derive(Serialize)]
    struct SrxCommit<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

    let commit = h_l(ds::MSPHF_SRX_COMMIT, &SrxCommit(payload)).context("compute srx commit")?;
    Ok(Some(commit))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::{
        Router,
        extract::State,
        http::{StatusCode as HttpStatusCode, Uri, header},
        response::{IntoResponse, Response},
        routing::{get, post},
    };
    use cityg_config::CityGConfig;
    use futures::SinkExt;
    use prost::Message;
    use serde_json::json;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex, OnceLock},
        time::Duration,
    };
    use tokio::net::TcpListener;
    use tokio::time::sleep;

    static TEST_AUTH_ENV: OnceLock<()> = OnceLock::new();

    fn ensure_test_auth_env() {
        TEST_AUTH_ENV.get_or_init(|| unsafe {
            std::env::set_var("CITYG_SERVER_ROOMS_ADMIN_TOKEN", "join-leave-admin-token");
            std::env::set_var("CITYG_SERVER_WINDOW_ADMIN_TOKEN", "join-leave-admin-token");
            std::env::set_var(
                "CITYG_SERVER_MESSAGE_AUTH_TOKEN",
                "join-leave-message-token",
            );
            std::env::set_var("CITYG_CLIENT_ADMIN_TOKEN", "join-leave-admin-token");
            std::env::set_var(
                "CITYG_CLIENT_MESSAGE_AUTH_TOKEN",
                "join-leave-message-token",
            );
        });
    }

    fn next_free_local_port() -> u16 {
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("bind ephemeral test port")
            .local_addr()
            .expect("read ephemeral test port")
            .port()
    }

    fn sample_session(server_url: &str) -> Session {
        let (_pop_pk, pop_sk) = dilithium5::keypair();
        Session {
            server_url: server_url.to_string(),
            room_id: hex::encode([0xAA; 32]),
            gid: [0x11; 32],
            leaf_id: [0x22; 32],
            xk_hash: [0x23; 32],
            epoch_key: [0x24; 32],
            barrier_version: 1,
            k_barrier: [0x25; 32],
            pop_public_key: vec![0x33; 32],
            pop_secret: Box::new(pop_sk),
            vrf_secret_key: vec![0x44; 32],
            vrf_public_key: vec![0x55; 32],
            forward_state: ForwardSecrecyState::with_state([0x10; 32], 7, [0x77; 32], [0x88; 32]),
            fs_ec: 7,
            fs_epoch_commit: [0x66; 32],
            fs_dev_prev_commit: [0x77; 32],
            we_epoch_id: [0x88; 32],
            anchor_hdr_ctx: vec![0x99],
            seed_ctx_hash: [0xAB; 32],
            seed_commit: [0xBC; 32],
            seed_bundle_commit: [0xCD; 32],
            fs_fingerprint: None,
            join_finalize_auth_token: [0xCE; 32],
            current_history_authority_extension: None,
            current_global_history_attestation_bytes: Vec::new(),
            stored_header_map: BTreeMap::new(),
            #[cfg(test)]
            msg_replay_state: MsgReplayState::default(),
        }
    }

    async fn spawn_server_on_with_seed_demo(
        port: u16,
        seed_demo_room: bool,
    ) -> tokio::task::JoinHandle<()> {
        ensure_test_auth_env();
        tokio::spawn(async move {
            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            let mut config = CityGConfig::default();
            config.server.seed_demo_room = seed_demo_room;
            if let Err(err) = cityg_api::run_with_config(addr, config).await {
                eprintln!("join_leave test server exited with error: {err}");
            }
        })
    }

    async fn spawn_server_on(port: u16) -> tokio::task::JoinHandle<()> {
        spawn_server_on_with_seed_demo(port, false).await
    }

    async fn bootstrap_test_room(server_url: &str, room_id: &str) -> Result<()> {
        ensure_test_auth_env();
        let (pop_public_key, pop_secret_key) = cityg_api_client::generate_room_admin_keypair();
        let admin_proof = build_room_admin_proof(
            RoomAdminOperation::Bootstrap,
            room_id,
            demo::kbroad_public(),
            &pop_public_key,
            &pop_secret_key,
        )?;
        new_api_client(server_url)
            .bootstrap_room_as_admin(room_id, demo::kbroad_public(), admin_proof)
            .await
            .map_err(anyhow::Error::from)
    }

    fn sample_pivot_parity() -> PivotParity {
        PivotParity {
            gid: vec![0x01; 32],
            cat: vec![0x02; 32],
            parent_root: [0x03; 32],
            we_epoch_id: [0x04; 32],
            rho_commit: [0x05; 32],
            seed_ctx_hash: [0x06; 32],
            seed_commit: [0x07; 32],
            hp_commit: [0x08; 32],
            xk_hash: [0x09; 32],
            join_delta_root: [0x0A; 32],
            revoked_since_root: [0x0B; 32],
            revoked_root: [0x0C; 32],
            accept_seq: 1,
            crs_id: b"crs-v1".to_vec(),
            params_id: b"params-v1".to_vec(),
            policy_version: "7".to_string(),
            proof_mode: "lin+zkvrf".to_string(),
            vrf_id: "lb-vrf".to_string(),
            vrf_proof: vec![0xDD, 0xEE],
            vrf_public: vec![0x11, 0x22],
            mask_a: [0xAA; 32],
            mask_b: [0xBB; 32],
            fs_capss: vec![0xCC],
            proofs_commit: [0xDD; 32],
            srx_commit: Some([0xEE; 32]),
            srx_root_sw: Some([0xEF; 32]),
            is_join: true,
            hp_envelope: Arc::<[u8]>::from(vec![0x99, 0x88]),
            fs_epoch_commit: Some([0x44; 32]),
            fs_ec: Some(77),
            fs_dev_commit: Some([0x55; 32]),
        }
    }

    fn sample_history_commitment() -> HistoryCommitment {
        HistoryCommitment {
            history_view_id: [0x90; 32],
            history_commitment_id: [0x91; 32],
            prev_history_commitment_id: [0x92; 32],
            history_seq: 17,
        }
    }

    fn sample_merge_ticket() -> cityg_api_client::MergeTicket {
        cityg_api_client::MergeTicket {
            author_leaf_id: [0x55; 32],
            we_epoch_id: [0x04; 32],
            parities: vec![sample_pivot_parity()],
            witness_cbor: vec![0xA1, 0x01, 0x02],
            srx_cbor: vec![0xA1, 0x03, 0x04],
            proof_mode: "lin+zkvrf".to_string(),
            vrf_id: "lb-vrf".to_string(),
            policy_version: "7".to_string(),
            cat: [0x02; 32],
            parent_root: [0x03; 32],
            join_delta_root: [0x0A; 32],
            revoked_since_root: [0x0B; 32],
            revoked_root: [0x0C; 32],
            tswe_salt_hash: [0x0D; 32],
            pox_r_commit: [0x0E; 32],
            kbroad_public: vec![0x33; 32],
            msphf_crs_id: "crs-v1".to_string(),
            msphf_params_id: "params-v1".to_string(),
            fs_policy_version: "fs-v1".to_string(),
            fs_epoch_base_ts: 1_717_171_717,
            fs_forward_leap_policy: cityg_api_client::FsForwardLeapPolicy {
                h: 300,
                checkpoint_interval: 3600,
                slack_anchor: 0,
                slack_first_device: 0,
                slack_device: 4,
            },
            last_accepted_ec: 17,
            kbroad_generation: 3,
            barrier_version: 9,
            cover_leaf_index: 1,
            kem_tree_hash_after: [0x0F; 32],
            current_history_commitment: sample_history_commitment(),
            history_authority_extension: None,
            history_authority_descriptor_bytes: Vec::new(),
            history_authority: None,
            current_global_history_attestation_bytes: Vec::new(),
            current_global_history_attestation: None,
            merge_ticket_artifact_bytes: Vec::new(),
            n_max: 8,
            max_barrier_update_bytes: 64 * 1024,
        }
    }

    #[derive(Clone, PartialEq, Message)]
    struct MergeTicketResponsePb {
        #[prost(bytes = "vec", tag = "1")]
        we_epoch_id: Vec<u8>,
        #[prost(bytes = "vec", repeated, tag = "2")]
        pivot_parity_cbor: Vec<Vec<u8>>,
        #[prost(bytes = "vec", tag = "3")]
        witness_cbor: Vec<u8>,
        #[prost(string, tag = "4")]
        proof_mode: String,
        #[prost(string, tag = "5")]
        vrf_id: String,
        #[prost(string, tag = "6")]
        policy_version: String,
        #[prost(bytes = "vec", tag = "7")]
        kbroad_public: Vec<u8>,
        #[prost(bytes = "vec", tag = "8")]
        cat: Vec<u8>,
        #[prost(bytes = "vec", tag = "9")]
        parent_root: Vec<u8>,
        #[prost(bytes = "vec", tag = "10")]
        join_delta_root: Vec<u8>,
        #[prost(bytes = "vec", tag = "11")]
        revoked_since_root: Vec<u8>,
        #[prost(bytes = "vec", tag = "12")]
        revoked_root: Vec<u8>,
        #[prost(bytes = "vec", tag = "13")]
        tswe_salt_hash: Vec<u8>,
        #[prost(bytes = "vec", tag = "14")]
        pox_r_commit: Vec<u8>,
        #[prost(bytes = "vec", tag = "15")]
        srx_cbor: Vec<u8>,
        #[prost(string, tag = "16")]
        msphf_crs_id: String,
        #[prost(string, tag = "17")]
        msphf_params_id: String,
        #[prost(string, tag = "18")]
        fs_policy_version: String,
        #[prost(uint64, tag = "19")]
        fs_epoch_base_ts: u64,
        #[prost(uint64, tag = "20")]
        kbroad_generation: u64,
        #[prost(uint64, tag = "21")]
        barrier_version: u64,
        #[prost(string, tag = "22")]
        profile_version: String,
        #[prost(uint64, tag = "23")]
        cover_leaf_index: u64,
        #[prost(bytes = "vec", tag = "25")]
        kem_tree_hash_after: Vec<u8>,
        #[prost(uint64, tag = "26")]
        n_max: u64,
        #[prost(uint64, tag = "27")]
        max_barrier_update_bytes: u64,
        #[prost(bytes = "vec", tag = "28")]
        current_history_view_id: Vec<u8>,
        #[prost(message, optional, tag = "29")]
        current_history_commitment: Option<HistoryCommitmentPb>,
        #[prost(message, optional, tag = "30")]
        fs_forward_leap_policy: Option<FsForwardLeapPolicyPb>,
        #[prost(uint64, tag = "31")]
        last_accepted_ec: u64,
        #[prost(bytes = "vec", tag = "32")]
        history_authority_descriptor: Vec<u8>,
        #[prost(bytes = "vec", tag = "33")]
        current_global_history_attestation: Vec<u8>,
        #[prost(string, tag = "34")]
        history_authority_extension: String,
        #[prost(bytes = "vec", tag = "35")]
        merge_ticket_artifact: Vec<u8>,
    }

    #[derive(Clone, PartialEq, Message)]
    struct HistoryCommitmentPb {
        #[prost(bytes = "vec", tag = "1")]
        history_view_id: Vec<u8>,
        #[prost(bytes = "vec", tag = "2")]
        history_commitment_id: Vec<u8>,
        #[prost(bytes = "vec", tag = "3")]
        prev_history_commitment_id: Vec<u8>,
        #[prost(uint64, tag = "4")]
        history_seq: u64,
    }

    #[derive(Clone, PartialEq, Message)]
    struct FsForwardLeapPolicyPb {
        #[prost(uint64, tag = "1")]
        h: u64,
        #[prost(uint64, tag = "2")]
        checkpoint_interval: u64,
        #[prost(uint64, tag = "3")]
        slack_anchor: u64,
        #[prost(uint64, tag = "4")]
        slack_first_device: u64,
        #[prost(uint64, tag = "5")]
        slack_device: u64,
    }

    #[derive(Clone, PartialEq, Message)]
    struct BarrierJoinLeafRecordPb {
        #[prost(bytes = "vec", tag = "1")]
        device_pk: Vec<u8>,
        #[prost(uint32, tag = "2")]
        leaf_index: u32,
        #[prost(bytes = "vec", tag = "3")]
        ek_leaf: Vec<u8>,
    }

    #[derive(Clone, PartialEq, Message)]
    struct BarrierResolveJoinsSinceResponsePb {
        #[prost(message, repeated, tag = "1")]
        records: Vec<BarrierJoinLeafRecordPb>,
        #[prost(bytes = "vec", tag = "2")]
        history_view_id: Vec<u8>,
        #[prost(message, optional, tag = "3")]
        history_commitment: Option<HistoryCommitmentPb>,
        #[prost(uint32, tag = "4")]
        page_offset: u32,
        #[prost(uint32, optional, tag = "5")]
        next_page_offset: Option<u32>,
        #[prost(uint32, tag = "6")]
        total_entries: u32,
    }

    #[derive(Clone, PartialEq, Message)]
    struct BarrierResolveRevokedLeavesResponsePb {
        #[prost(uint32, repeated, tag = "1")]
        leaf_indices: Vec<u32>,
        #[prost(bytes = "vec", tag = "2")]
        history_view_id: Vec<u8>,
        #[prost(message, optional, tag = "3")]
        history_commitment: Option<HistoryCommitmentPb>,
        #[prost(uint32, tag = "4")]
        page_offset: u32,
        #[prost(uint32, optional, tag = "5")]
        next_page_offset: Option<u32>,
        #[prost(uint32, tag = "6")]
        total_entries: u32,
    }

    #[derive(Clone, PartialEq, Message)]
    struct BarrierFetchPublicTreeResponsePb {
        #[prost(uint64, tag = "1")]
        n_max: u64,
        #[prost(bytes = "vec", tag = "2")]
        kem_tree_hash_after: Vec<u8>,
        #[prost(bytes = "vec", repeated, tag = "3")]
        pk_entries: Vec<Vec<u8>>,
        #[prost(bytes = "vec", tag = "4")]
        history_view_id: Vec<u8>,
        #[prost(message, optional, tag = "5")]
        history_commitment: Option<HistoryCommitmentPb>,
        #[prost(uint32, tag = "6")]
        entry_offset: u32,
        #[prost(uint32, optional, tag = "7")]
        next_entry_offset: Option<u32>,
        #[prost(uint32, tag = "8")]
        total_entries: u32,
    }

    #[derive(Clone, PartialEq, Message)]
    struct EmptyProto {}

    #[derive(Clone)]
    struct MockResponse {
        status: HttpStatusCode,
        content_type: &'static str,
        body: Vec<u8>,
    }

    impl MockResponse {
        fn proto_bytes(body: Vec<u8>) -> Self {
            Self {
                status: HttpStatusCode::OK,
                content_type: "application/x-protobuf",
                body,
            }
        }

        fn empty_proto() -> Self {
            Self::proto_bytes(EmptyProto::default().encode_to_vec())
        }

        fn json(
            status: HttpStatusCode,
            message: &str,
            freeze_code: Option<u32>,
            freeze_reason: Option<&str>,
        ) -> Self {
            Self {
                status,
                content_type: "application/json",
                body: serde_json::to_vec(&json!({
                    "message": message,
                    "freeze_code": freeze_code,
                    "freeze_reason": freeze_reason,
                }))
                .expect("encode mock error envelope"),
            }
        }

        fn into_response(self) -> Response {
            (
                self.status,
                [(header::CONTENT_TYPE, self.content_type)],
                self.body,
            )
                .into_response()
        }
    }

    #[derive(Clone, Default)]
    struct LeaveMockState {
        responses: Arc<Mutex<BTreeMap<String, VecDeque<MockResponse>>>>,
        counts: Arc<Mutex<BTreeMap<String, usize>>>,
    }

    impl LeaveMockState {
        fn new(routes: impl IntoIterator<Item = (&'static str, Vec<MockResponse>)>) -> Self {
            let responses = routes
                .into_iter()
                .map(|(path, entries)| (path.to_string(), entries.into()))
                .collect();
            Self {
                responses: Arc::new(Mutex::new(responses)),
                counts: Arc::new(Mutex::new(BTreeMap::new())),
            }
        }

        fn response_for(&self, path: &str) -> MockResponse {
            {
                let mut counts = self.counts.lock().expect("lock call counts");
                *counts.entry(path.to_string()).or_insert(0) += 1;
            }
            let mut responses = self.responses.lock().expect("lock mock responses");
            let Some(queue) = responses.get_mut(path) else {
                return MockResponse::json(
                    HttpStatusCode::NOT_FOUND,
                    "resource not found",
                    Some(404),
                    None,
                );
            };
            if queue.len() > 1 {
                queue.pop_front().expect("non-empty response queue")
            } else {
                queue
                    .front()
                    .cloned()
                    .expect("response queue must contain at least one response")
            }
        }

        fn call_count(&self, path: &str) -> usize {
            self.counts
                .lock()
                .expect("lock call counts")
                .get(path)
                .copied()
                .unwrap_or(0)
        }
    }

    async fn mock_leave_health() -> &'static str {
        "ok"
    }

    async fn mock_leave_post(State(state): State<LeaveMockState>, uri: Uri) -> Response {
        state.response_for(uri.path()).into_response()
    }

    async fn start_leave_mock_server(
        state: LeaveMockState,
    ) -> Result<(String, tokio::task::JoinHandle<()>)> {
        let app = Router::new()
            .route("/health", get(mock_leave_health))
            .route("/{*path}", post(mock_leave_post))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let base = format!("http://{addr}");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok((base, handle))
    }

    struct LeaveFixture {
        session: Session,
        ticket: cityg_api_client::MergeTicket,
        barrier_tree_snapshot: cityg_api_client::BarrierPublicTree,
        join_records: Vec<BarrierJoinRecord>,
        revoked_leaf_indices: Vec<u32>,
    }

    struct JoinFinalizeFixture {
        session: Session,
        ticket: cityg_api_client::MergeTicket,
        barrier_tree_snapshot: cityg_api_client::BarrierPublicTree,
        join_records: Vec<BarrierJoinRecord>,
        revoked_leaf_indices: Vec<u32>,
    }

    #[derive(Serialize)]
    struct PivotParitySerializable {
        gid: ByteBuf,
        cat: ByteBuf,
        parent_root: ByteBuf,
        we_epoch_id: ByteBuf,
        rho_commit: ByteBuf,
        seed_ctx_hash: ByteBuf,
        seed_commit: ByteBuf,
        hp_commit: ByteBuf,
        xk_hash: ByteBuf,
        join_delta_root: ByteBuf,
        revoked_since_root: ByteBuf,
        revoked_root: ByteBuf,
        accept_seq: u64,
        crs_id: ByteBuf,
        params_id: ByteBuf,
        policy_version: String,
        proof_mode: String,
        vrf_id: String,
        vrf_proof: ByteBuf,
        vrf_public: ByteBuf,
        mask_a: ByteBuf,
        mask_b: ByteBuf,
        fs_capss: ByteBuf,
        proofs_commit: ByteBuf,
        srx_commit: Option<ByteBuf>,
        srx_root_sw: Option<ByteBuf>,
        is_join: bool,
        hp_envelope: ByteBuf,
        fs_epoch_commit: Option<ByteBuf>,
        fs_ec: Option<u64>,
        fs_dev_commit: Option<ByteBuf>,
    }

    fn select_ticket_pivot(parities: &[PivotParity]) -> Option<&PivotParity> {
        let mut pivot: Option<&PivotParity> = None;
        for candidate in parities {
            let better = match pivot {
                None => true,
                Some(current) => {
                    candidate.accept_seq > current.accept_seq
                        || (candidate.accept_seq == current.accept_seq
                            && candidate.xk_hash < current.xk_hash)
                }
            };
            if better {
                pivot = Some(candidate);
            }
        }
        pivot
    }

    async fn capture_leave_fixture() -> Result<LeaveFixture> {
        let port = next_free_local_port();
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = random_room_id();
        bootstrap_test_room(&server_url, &room_id).await?;
        let session = perform_join(&server_url, &room_id, "leave-mock-alice").await?;
        let _peer = perform_join(&server_url, &room_id, "leave-mock-bob").await?;

        let client = new_api_client(&server_url);
        let ticket = client.merge_ticket(&room_id, &session.leaf_id).await?;
        let pivot = select_ticket_pivot(&ticket.parities)
            .ok_or_else(|| anyhow!("merge ticket missing pivot parity entries"))?;
        let committed_revocation_roots_hash =
            compute_revocation_roots_hash(&pivot.revoked_since_root, &pivot.revoked_root)?;
        let barrier_tree_snapshot = client
            .barrier_fetch_public_tree(&room_id, &ticket.kem_tree_hash_after)
            .await?
            .tree;
        let join_records = client
            .barrier_resolve_joins_since(&room_id, ticket.barrier_version)
            .await?
            .records;
        let revoked_leaf_indices = client
            .barrier_resolve_revoked_leaves(&room_id, &committed_revocation_roots_hash)
            .await?
            .leaf_indices;

        handle.abort();
        let _ = handle.await;

        Ok(LeaveFixture {
            session,
            ticket,
            barrier_tree_snapshot,
            join_records,
            revoked_leaf_indices,
        })
    }

    async fn capture_join_finalize_fixture() -> Result<JoinFinalizeFixture> {
        let port = next_free_local_port();
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = random_room_id();
        bootstrap_test_room(&server_url, &room_id).await?;
        let session = prepare_join_session(&server_url, &room_id, "join-finalize-mock").await?;

        let client = new_api_client(&server_url);
        let ticket = client
            .merge_ticket_refresh(&room_id, &session.leaf_id)
            .await?;
        let pivot = select_ticket_pivot(&ticket.parities)
            .ok_or_else(|| anyhow!("merge ticket missing pivot parity entries"))?;
        let committed_revocation_roots_hash =
            compute_revocation_roots_hash(&pivot.revoked_since_root, &pivot.revoked_root)?;
        let barrier_tree_snapshot = client
            .barrier_fetch_public_tree(&room_id, &ticket.kem_tree_hash_after)
            .await?
            .tree;
        let join_records = client
            .barrier_resolve_joins_since(&room_id, ticket.barrier_version)
            .await?
            .records;
        let revoked_leaf_indices = client
            .barrier_resolve_revoked_leaves(&room_id, &committed_revocation_roots_hash)
            .await?
            .leaf_indices;

        handle.abort();
        let _ = handle.await;

        Ok(JoinFinalizeFixture {
            session,
            ticket,
            barrier_tree_snapshot,
            join_records,
            revoked_leaf_indices,
        })
    }

    fn encode_merge_ticket(ticket: &cityg_api_client::MergeTicket) -> Result<Vec<u8>> {
        let pivot_parity_cbor = ticket
            .parities
            .iter()
            .map(|parity| {
                to_cbor_vec(&PivotParitySerializable {
                    gid: ByteBuf::from(parity.gid.clone()),
                    cat: ByteBuf::from(parity.cat.clone()),
                    parent_root: ByteBuf::from(parity.parent_root.to_vec()),
                    we_epoch_id: ByteBuf::from(parity.we_epoch_id.to_vec()),
                    rho_commit: ByteBuf::from(parity.rho_commit.to_vec()),
                    seed_ctx_hash: ByteBuf::from(parity.seed_ctx_hash.to_vec()),
                    seed_commit: ByteBuf::from(parity.seed_commit.to_vec()),
                    hp_commit: ByteBuf::from(parity.hp_commit.to_vec()),
                    xk_hash: ByteBuf::from(parity.xk_hash.to_vec()),
                    join_delta_root: ByteBuf::from(parity.join_delta_root.to_vec()),
                    revoked_since_root: ByteBuf::from(parity.revoked_since_root.to_vec()),
                    revoked_root: ByteBuf::from(parity.revoked_root.to_vec()),
                    accept_seq: parity.accept_seq,
                    crs_id: ByteBuf::from(parity.crs_id.clone()),
                    params_id: ByteBuf::from(parity.params_id.clone()),
                    policy_version: parity.policy_version.clone(),
                    proof_mode: parity.proof_mode.clone(),
                    vrf_id: parity.vrf_id.clone(),
                    vrf_proof: ByteBuf::from(parity.vrf_proof.clone()),
                    vrf_public: ByteBuf::from(parity.vrf_public.clone()),
                    mask_a: ByteBuf::from(parity.mask_a.to_vec()),
                    mask_b: ByteBuf::from(parity.mask_b.to_vec()),
                    fs_capss: ByteBuf::from(parity.fs_capss.clone()),
                    proofs_commit: ByteBuf::from(parity.proofs_commit.to_vec()),
                    srx_commit: parity.srx_commit.map(|bytes| ByteBuf::from(bytes.to_vec())),
                    srx_root_sw: parity
                        .srx_root_sw
                        .map(|bytes| ByteBuf::from(bytes.to_vec())),
                    is_join: parity.is_join,
                    hp_envelope: ByteBuf::from(parity.hp_envelope.as_ref().to_vec()),
                    fs_epoch_commit: parity
                        .fs_epoch_commit
                        .map(|bytes| ByteBuf::from(bytes.to_vec())),
                    fs_ec: parity.fs_ec,
                    fs_dev_commit: parity
                        .fs_dev_commit
                        .map(|bytes| ByteBuf::from(bytes.to_vec())),
                })
            })
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|err| anyhow!("encode pivot parity: {err}"))?;
        Ok(MergeTicketResponsePb {
            we_epoch_id: ticket.we_epoch_id.to_vec(),
            pivot_parity_cbor,
            witness_cbor: ticket.witness_cbor.clone(),
            proof_mode: ticket.proof_mode.clone(),
            vrf_id: ticket.vrf_id.clone(),
            policy_version: ticket.policy_version.clone(),
            kbroad_public: ticket.kbroad_public.clone(),
            cat: ticket.cat.to_vec(),
            parent_root: ticket.parent_root.to_vec(),
            join_delta_root: ticket.join_delta_root.to_vec(),
            revoked_since_root: ticket.revoked_since_root.to_vec(),
            revoked_root: ticket.revoked_root.to_vec(),
            tswe_salt_hash: ticket.tswe_salt_hash.to_vec(),
            pox_r_commit: ticket.pox_r_commit.to_vec(),
            srx_cbor: ticket.srx_cbor.clone(),
            msphf_crs_id: ticket.msphf_crs_id.clone(),
            msphf_params_id: ticket.msphf_params_id.clone(),
            fs_policy_version: ticket.fs_policy_version.clone(),
            fs_epoch_base_ts: ticket.fs_epoch_base_ts,
            kbroad_generation: ticket.kbroad_generation,
            barrier_version: ticket.barrier_version,
            profile_version: "v0.1.4".to_string(),
            cover_leaf_index: ticket.cover_leaf_index,
            kem_tree_hash_after: ticket.kem_tree_hash_after.to_vec(),
            n_max: ticket.n_max,
            max_barrier_update_bytes: ticket.max_barrier_update_bytes,
            current_history_view_id: ticket.current_history_commitment.history_view_id.to_vec(),
            current_history_commitment: Some(encode_history_commitment(
                &ticket.current_history_commitment,
            )),
            fs_forward_leap_policy: Some(FsForwardLeapPolicyPb {
                h: ticket.fs_forward_leap_policy.h,
                checkpoint_interval: ticket.fs_forward_leap_policy.checkpoint_interval,
                slack_anchor: ticket.fs_forward_leap_policy.slack_anchor,
                slack_first_device: ticket.fs_forward_leap_policy.slack_first_device,
                slack_device: ticket.fs_forward_leap_policy.slack_device,
            }),
            last_accepted_ec: ticket.last_accepted_ec,
            history_authority_descriptor: ticket.history_authority_descriptor_bytes.clone(),
            current_global_history_attestation: ticket
                .current_global_history_attestation_bytes
                .clone(),
            history_authority_extension: ticket
                .history_authority_extension
                .map(|extension| extension.as_str().to_string())
                .unwrap_or_default(),
            merge_ticket_artifact: ticket.merge_ticket_artifact_bytes.clone(),
        }
        .encode_to_vec())
    }

    fn encode_history_commitment(commitment: &HistoryCommitment) -> HistoryCommitmentPb {
        HistoryCommitmentPb {
            history_view_id: commitment.history_view_id.to_vec(),
            history_commitment_id: commitment.history_commitment_id.to_vec(),
            prev_history_commitment_id: commitment.prev_history_commitment_id.to_vec(),
            history_seq: commitment.history_seq,
        }
    }

    fn encode_barrier_tree_snapshot(
        tree: &cityg_api_client::BarrierPublicTree,
        history_commitment: &HistoryCommitment,
        entry_offset: u32,
        next_entry_offset: Option<u32>,
        pk_entries: Vec<Vec<u8>>,
    ) -> Vec<u8> {
        let total_entries = u32::try_from(tree.pk_entries.len()).expect("tree entries fit in u32");
        BarrierFetchPublicTreeResponsePb {
            n_max: tree.n_max,
            kem_tree_hash_after: tree.kem_tree_hash_after.to_vec(),
            pk_entries,
            history_view_id: history_commitment.history_view_id.to_vec(),
            history_commitment: Some(encode_history_commitment(history_commitment)),
            entry_offset,
            next_entry_offset,
            total_entries,
        }
        .encode_to_vec()
    }

    fn encode_barrier_tree_snapshot_pages(
        tree: &cityg_api_client::BarrierPublicTree,
        history_commitment: &HistoryCommitment,
    ) -> Vec<MockResponse> {
        const MOCK_BARRIER_HELPER_PAGE_LIMIT: usize = 512;

        let total_entries = tree.pk_entries.len();
        if total_entries <= MOCK_BARRIER_HELPER_PAGE_LIMIT {
            return vec![MockResponse::proto_bytes(encode_barrier_tree_snapshot(
                tree,
                history_commitment,
                0,
                None,
                tree.pk_entries.clone(),
            ))];
        }

        let mut responses = Vec::new();
        let mut offset = 0usize;
        while offset < total_entries {
            let end = (offset + MOCK_BARRIER_HELPER_PAGE_LIMIT).min(total_entries);
            let next_entry_offset = (end < total_entries)
                .then(|| u32::try_from(end).expect("paginated tree entry offset fits in u32"));
            responses.push(MockResponse::proto_bytes(encode_barrier_tree_snapshot(
                tree,
                history_commitment,
                u32::try_from(offset).expect("paginated tree entry offset fits in u32"),
                next_entry_offset,
                tree.pk_entries[offset..end].to_vec(),
            )));
            offset = end;
        }
        responses
    }

    fn encode_join_records(
        records: &[BarrierJoinRecord],
        history_commitment: &HistoryCommitment,
    ) -> Vec<u8> {
        let total_entries = u32::try_from(records.len()).expect("join records fit in u32");
        BarrierResolveJoinsSinceResponsePb {
            records: records
                .iter()
                .map(|record| BarrierJoinLeafRecordPb {
                    device_pk: record.device_pk.clone(),
                    leaf_index: record.leaf_index,
                    ek_leaf: record.ek_leaf.clone(),
                })
                .collect(),
            history_view_id: history_commitment.history_view_id.to_vec(),
            history_commitment: Some(encode_history_commitment(history_commitment)),
            page_offset: 0,
            next_page_offset: None,
            total_entries,
        }
        .encode_to_vec()
    }

    fn encode_revoked_leaf_indices(
        indices: &[u32],
        history_commitment: &HistoryCommitment,
    ) -> Vec<u8> {
        let total_entries = u32::try_from(indices.len()).expect("revoked indices fit in u32");
        BarrierResolveRevokedLeavesResponsePb {
            leaf_indices: indices.to_vec(),
            history_view_id: history_commitment.history_view_id.to_vec(),
            history_commitment: Some(encode_history_commitment(history_commitment)),
            page_offset: 0,
            next_page_offset: None,
            total_entries,
        }
        .encode_to_vec()
    }

    #[test]
    fn random_room_id_and_bytes32_validation() -> Result<()> {
        let room_id = random_room_id();
        assert_eq!(room_id.len(), 64, "room id must be 32-byte hex");
        let decoded = hex::decode(&room_id)?;
        assert_eq!(decoded.len(), 32);

        let good = bytes32("room", &[0xAB; 32])?;
        assert_eq!(good, [0xAB; 32]);

        let err = bytes32("room", &[0xAB; 31]).expect_err("must reject non-32-byte input");
        assert!(err.to_string().contains("room must be 32 bytes"));
        Ok(())
    }

    #[test]
    fn ticket_retry_classifier_detects_concurrency_errors() {
        assert!(should_retry_ticket_http_error(
            500,
            "invalid input: barrier_version mismatch",
            None
        ));
        assert!(should_retry_ticket_http_error(
            500,
            "window full",
            Some(925)
        ));
        assert!(should_retry_ticket_http_error(
            503,
            "pivot head missing",
            None
        ));
        assert!(should_retry_ticket_http_error(
            409,
            "invalid input: refresh payload diverges from stored parity",
            None
        ));
        assert!(should_retry_ticket_http_error(
            429,
            "too many requests: unrelated text",
            Some(925)
        ));
        assert!(!should_retry_ticket_http_error(
            500,
            "kbroad key missing",
            None
        ));
        assert!(!should_retry_ticket_http_error(
            429,
            "too many requests: kbroad key missing",
            None
        ));
    }

    #[test]
    fn ticket_retry_delay_is_bounded() {
        for attempt in 0..=10 {
            let delay = ticket_retry_delay(attempt);
            assert!(delay >= Duration::from_millis(TICKET_RETRY_BASE_DELAY_MS));
            assert!(
                delay <= Duration::from_millis(TICKET_RETRY_MAX_DELAY_MS + TICKET_RETRY_JITTER_MS)
            );
        }
    }

    #[test]
    fn read_nonempty_env_trims_and_filters_values() {
        let missing = format!("CITYG_JOIN_LEAVE_TEST_MISSING_{}", std::process::id());
        assert!(read_nonempty_env(&missing).is_none());

        let blank = format!("CITYG_JOIN_LEAVE_TEST_BLANK_{}", std::process::id());
        unsafe {
            std::env::set_var(&blank, "   ");
        }
        assert!(read_nonempty_env(&blank).is_none());
        unsafe {
            std::env::remove_var(&blank);
        }

        let value = format!("CITYG_JOIN_LEAVE_TEST_VALUE_{}", std::process::id());
        unsafe {
            std::env::set_var(&value, "  token-value  ");
        }
        assert_eq!(read_nonempty_env(&value).as_deref(), Some("token-value"));
        unsafe {
            std::env::remove_var(&value);
        }
    }

    #[test]
    fn revocation_roots_hash_helper_is_deterministic() -> Result<()> {
        let since = [0x11; 32];
        let revoked = [0x22; 32];
        let first = compute_revocation_roots_hash(&since, &revoked)?;
        let second = compute_revocation_roots_hash(&since, &revoked)?;
        assert_eq!(first, second, "hash must be deterministic");
        let changed = compute_revocation_roots_hash(&since, &[0x23; 32])?;
        assert_ne!(first, changed, "hash must bind revocation roots");
        Ok(())
    }

    #[test]
    fn build_barrier_update_bytes_encodes_expected_shape() -> Result<()> {
        let snapshot_pre = vec![Vec::new(); 2 * 1_024 - 1];
        let update = build_barrier_update_bytes(
            &[0x44; 32],
            1_024,
            0,
            9,
            8,
            [0x33; 32],
            [0x22; 32],
            snapshot_pre.as_slice(),
        )?;
        let value: Value = ciborium::de::from_reader(update.raw_update.as_slice())?;
        let Value::Array(update) = value else {
            return Err(anyhow!("barrier update must decode as array"));
        };
        assert_eq!(update.len(), 8);
        assert!(matches!(update.first(), Some(Value::Text(mode)) if mode == "barrier-v1"));
        assert!(
            matches!(update.get(1), Some(Value::Integer(version)) if u64::try_from(*version).ok() == Some(9))
        );
        assert!(
            matches!(update.get(2), Some(Value::Integer(version)) if u64::try_from(*version).ok() == Some(8))
        );
        assert!(
            matches!(update.get(3), Some(Value::Integer(tree_size)) if u64::try_from(*tree_size).ok() == Some(1_024))
        );

        let cover_bytes = match update.get(7) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err(anyhow!("cover payload must be encoded as bytes")),
        };
        let cover_value: Value = ciborium::de::from_reader(cover_bytes.as_slice())?;
        assert!(matches!(cover_value, Value::Array(fields) if fields.len() == 5));
        Ok(())
    }

    #[test]
    fn build_barrier_update_bytes_sets_hash_after_from_snapshot_and_new_public_keys() -> Result<()>
    {
        let n_max = 8u64;
        let snapshot_pre = vec![Vec::new(); (n_max as usize) * 2 - 1];
        let update = build_barrier_update_bytes(
            &[0x11; 32],
            n_max,
            0,
            2,
            1,
            [0x11; 32],
            [0x22; 32],
            snapshot_pre.as_slice(),
        )?;
        let update_value: Value = ciborium::de::from_reader(update.raw_update.as_slice())?;
        let Value::Array(update_fields) = update_value else {
            return Err(anyhow!("barrier update must decode as array"));
        };
        let kem_tree_hash_after = match update_fields.get(6) {
            Some(Value::Bytes(bytes)) if bytes.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(bytes.as_slice());
                out
            }
            _ => return Err(anyhow!("barrier update missing kem_tree_hash_after")),
        };
        let cover_bytes = match update_fields.get(7) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err(anyhow!("cover payload must be bytes")),
        };
        let cover_value: Value = ciborium::de::from_reader(cover_bytes.as_slice())?;
        let Value::Array(cover_fields) = cover_value else {
            return Err(anyhow!("cover payload must decode as array"));
        };
        let Some(Value::Array(new_public_keys_values)) = cover_fields.get(4) else {
            return Err(anyhow!("cover payload missing new_public_keys"));
        };

        let mut snapshot_post = snapshot_pre.clone();
        for entry in new_public_keys_values {
            let Value::Array(pair) = entry else {
                return Err(anyhow!("new_public_keys entry must be [node, ek]"));
            };
            if pair.len() != 2 {
                return Err(anyhow!("new_public_keys entry must have two fields"));
            }
            let node = match pair.first() {
                Some(Value::Integer(value)) => u64::try_from(*value)
                    .map_err(|_| anyhow!("new_public_keys node index out of range"))?,
                _ => return Err(anyhow!("new_public_keys node index missing")),
            };
            let ek = match pair.get(1) {
                Some(Value::Bytes(bytes)) => bytes.clone(),
                _ => return Err(anyhow!("new_public_keys ek missing")),
            };
            let idx =
                usize::try_from(node).map_err(|_| anyhow!("new_public_keys node out of range"))?;
            let slot = snapshot_post
                .get_mut(idx)
                .ok_or_else(|| anyhow!("new_public_keys node out of range"))?;
            *slot = ek;
        }
        let recomputed = compute_barrier_tree_hash(n_max, snapshot_post.as_slice())?;
        assert_eq!(kem_tree_hash_after, recomputed);
        Ok(())
    }

    #[test]
    fn build_barrier_update_bytes_rejects_invalid_tree_parameters() {
        let snapshot_pre = vec![Vec::new(); 2 * 8 - 1];
        assert!(
            build_barrier_update_bytes(
                &[0u8; 32],
                0,
                0,
                1,
                0,
                [0u8; 32],
                [0u8; 32],
                snapshot_pre.as_slice(),
            )
            .is_err()
        );
        assert!(
            build_barrier_update_bytes(
                &[0u8; 32],
                3,
                0,
                1,
                0,
                [0u8; 32],
                [0u8; 32],
                snapshot_pre.as_slice(),
            )
            .is_err()
        );
        assert!(
            build_barrier_update_bytes(
                &[0u8; 32],
                8,
                8,
                1,
                0,
                [0u8; 32],
                [0u8; 32],
                snapshot_pre.as_slice(),
            )
            .is_err()
        );
        let wrong_snapshot = vec![Vec::new(); 3];
        assert!(
            build_barrier_update_bytes(
                &[0u8; 32],
                8,
                0,
                1,
                0,
                [0u8; 32],
                [0u8; 32],
                wrong_snapshot.as_slice(),
            )
            .is_err()
        );
    }

    #[test]
    fn generate_vrf_keys_are_not_deterministic() -> Result<()> {
        let (secret_a, public_a) = generate_vrf_keys()?;
        let (secret_b, public_b) = generate_vrf_keys()?;
        assert!(!secret_a.is_empty());
        assert!(!public_a.is_empty());
        assert_ne!(secret_a, secret_b);
        assert_ne!(public_a, public_b);
        Ok(())
    }

    #[test]
    fn fs_fingerprint_helpers_cover_valid_and_invalid_headers() {
        let fs_epoch_commit = [0x42; 32];
        let mut header = BTreeMap::new();
        header.insert(
            hdr::HDR_FS_POLICY_VERSION,
            Value::Integer(Integer::from(7u64)),
        );
        header.insert(hdr::HDR_FS_EC, Value::Integer(Integer::from(9u64)));
        header.insert(
            hdr::HDR_FS_EPOCH_COMMIT,
            Value::Bytes(fs_epoch_commit.to_vec()),
        );
        header.insert(
            hdr::HDR_FS_EPOCH_BASE_TS,
            Value::Integer(Integer::from(1234u64)),
        );

        let direct = derive_fs_fingerprint_from_fields("7", 9, &fs_epoch_commit, 1234);
        let from_header = compute_fs_fingerprint_from_header(&header);
        assert_eq!(from_header, direct);
        assert!(from_header.is_some());

        header.insert(hdr::HDR_FS_EC, Value::Text("bad".to_string()));
        assert!(compute_fs_fingerprint_from_header(&header).is_none());

        header.insert(hdr::HDR_FS_EC, Value::Integer(Integer::from(9u64)));
        header.insert(
            hdr::HDR_FS_POLICY_VERSION,
            Value::Bytes(b"not-text".to_vec()),
        );
        assert!(compute_fs_fingerprint_from_header(&header).is_none());
        header.insert(
            hdr::HDR_FS_POLICY_VERSION,
            Value::Integer(Integer::from(7u64)),
        );

        header.insert(hdr::HDR_FS_EPOCH_COMMIT, Value::Text("bad".to_string()));
        assert!(compute_fs_fingerprint_from_header(&header).is_none());
        header.insert(
            hdr::HDR_FS_EPOCH_COMMIT,
            Value::Bytes(fs_epoch_commit.to_vec()),
        );

        header.insert(hdr::HDR_FS_EPOCH_BASE_TS, Value::Text("bad".to_string()));
        assert!(compute_fs_fingerprint_from_header(&header).is_none());
    }

    #[test]
    fn fs_fingerprint_helpers_require_all_fields() {
        let mut header = BTreeMap::new();
        assert!(compute_fs_fingerprint_from_header(&header).is_none());

        header.insert(
            hdr::HDR_FS_POLICY_VERSION,
            Value::Integer(Integer::from(7u64)),
        );
        assert!(compute_fs_fingerprint_from_header(&header).is_none());

        header.insert(hdr::HDR_FS_EC, Value::Integer(Integer::from(1u64)));
        assert!(compute_fs_fingerprint_from_header(&header).is_none());

        header.insert(hdr::HDR_FS_EPOCH_COMMIT, Value::Bytes([0x11; 32].to_vec()));
        assert!(compute_fs_fingerprint_from_header(&header).is_none());

        header.insert(
            hdr::HDR_FS_EPOCH_BASE_TS,
            Value::Integer(Integer::from(42u64)),
        );
        assert!(compute_fs_fingerprint_from_header(&header).is_some());
    }

    #[test]
    fn fingerprint_formatting_helpers() {
        let bytes = [0xAB; 32];
        assert_eq!(
            fingerprint_full_hex(&bytes),
            "abababababababababababababababababababababababababababababababab"
        );
        assert_eq!(fingerprint_preview_hex(&bytes), "abab-abab abab-abab …");
    }

    #[test]
    fn websocket_url_converts_schemes() {
        let gid = [0x11u8; 32];
        let leaf_id = [0x22u8; 32];
        assert_eq!(
            websocket_url("http://127.0.0.1:18080", &gid, &leaf_id),
            format!(
                "ws://127.0.0.1:18080/v1/ws?gid={}&leaf_id={}",
                hex::encode(gid),
                hex::encode(leaf_id)
            )
        );
        assert_eq!(
            websocket_url("https://example.com", &gid, &leaf_id),
            format!(
                "wss://example.com/v1/ws?gid={}&leaf_id={}",
                hex::encode(gid),
                hex::encode(leaf_id)
            )
        );
        assert_eq!(
            websocket_url("localhost:9000", &gid, &leaf_id),
            format!(
                "ws://localhost:9000/v1/ws?gid={}&leaf_id={}",
                hex::encode(gid),
                hex::encode(leaf_id)
            )
        );
    }

    #[test]
    fn alias_for_formats_single_and_multi() {
        assert_eq!(alias_for("alice", 1, 0), "alice");
        assert_eq!(alias_for("alice", 3, 1), "alice-2");
    }

    #[test]
    fn barrier_tree_helpers_cover_size_mismatch_and_siblings() {
        let wrong_entries = (0..6).map(|_| vec![0x11; 1184]).collect::<Vec<_>>();
        let err =
            compute_barrier_tree_hash(4, &wrong_entries).expect_err("wrong tree size must fail");
        assert!(err.to_string().contains("barrier tree size mismatch"));

        assert_eq!(sibling_node(0), None);
        assert_eq!(sibling_node(1), Some(2));
        assert_eq!(sibling_node(2), Some(1));
    }

    #[test]
    fn barrier_tree_hash_and_pkhash_bind_inputs() -> Result<()> {
        let entries = (0..7).map(|idx| vec![idx as u8; 4]).collect::<Vec<_>>();
        let first = compute_barrier_tree_hash(4, &entries)?;
        let second = compute_barrier_tree_hash(4, &entries)?;
        assert_eq!(first, second, "tree hash must be deterministic");

        let mut changed = entries.clone();
        changed[6].push(0xFF);
        let changed_hash = compute_barrier_tree_hash(4, &changed)?;
        assert_ne!(first, changed_hash, "tree hash must bind pk entries");

        let pkhash_a = compute_barrier_pkhash(&vec![0xAA; kyber768::public_key_bytes()])?;
        let pkhash_b = compute_barrier_pkhash(&vec![0xAA; kyber768::public_key_bytes()])?;
        let pkhash_c = compute_barrier_pkhash(&vec![0xAB; kyber768::public_key_bytes()])?;
        assert_eq!(pkhash_a, pkhash_b, "pk hash must be deterministic");
        assert_ne!(pkhash_a, pkhash_c, "pk hash must bind pk bytes");
        Ok(())
    }

    #[test]
    fn barrier_snapshot_mutation_helpers_clear_expected_paths() -> Result<()> {
        let mut snapshot = (0..7).map(|idx| vec![idx as u8]).collect::<Vec<_>>();
        blank_internal_path_from_leaf(snapshot.as_mut_slice(), 5)?;
        assert_eq!(
            snapshot[5],
            vec![5],
            "leaf node itself must remain populated"
        );
        assert!(snapshot[2].is_empty(), "parent on path must be blanked");
        assert!(snapshot[0].is_empty(), "root on path must be blanked");
        assert_eq!(snapshot[1], vec![1], "unrelated branch must remain intact");

        let mut snapshot = (0..7).map(|idx| vec![idx as u8]).collect::<Vec<_>>();
        blank_leaf_and_path(snapshot.as_mut_slice(), 4)?;
        assert!(snapshot[4].is_empty(), "revoked leaf must be blanked");
        assert!(snapshot[1].is_empty(), "ancestor must be blanked");
        assert!(snapshot[0].is_empty(), "root must be blanked");
        assert_eq!(snapshot[2], vec![2], "disjoint branch must remain intact");

        let mut snapshot = vec![vec![0x11]; 7];
        assert!(blank_internal_path_from_leaf(snapshot.as_mut_slice(), 99).is_err());
        assert!(blank_leaf_and_path(snapshot.as_mut_slice(), 99).is_err());
        Ok(())
    }

    #[test]
    fn apply_join_and_revoke_mutate_snapshot_and_validate_bounds() -> Result<()> {
        let mut snapshot = (0..7).map(|idx| vec![idx as u8]).collect::<Vec<_>>();
        apply_join_set_to_snapshot(
            snapshot.as_mut_slice(),
            4,
            &[BarrierJoinRecord {
                device_pk: vec![0x01],
                leaf_index: 2,
                ek_leaf: vec![0xFE, 0xED],
            }],
        )?;
        assert_eq!(snapshot[5], vec![0xFE, 0xED]);
        assert!(snapshot[2].is_empty(), "join path parent must be blanked");
        assert!(snapshot[0].is_empty(), "join path root must be blanked");

        let mut snapshot = (0..7).map(|idx| vec![idx as u8]).collect::<Vec<_>>();
        apply_revoked_set_to_snapshot(snapshot.as_mut_slice(), 4, &[1])?;
        assert!(snapshot[4].is_empty(), "revoked leaf must be blanked");
        assert!(
            snapshot[1].is_empty(),
            "revoked path parent must be blanked"
        );
        assert!(snapshot[0].is_empty(), "revoked path root must be blanked");

        let mut snapshot = vec![vec![0x11]; 7];
        assert!(
            apply_join_set_to_snapshot(
                snapshot.as_mut_slice(),
                4,
                &[BarrierJoinRecord {
                    device_pk: vec![0x01],
                    leaf_index: 7,
                    ek_leaf: vec![0xFF],
                }],
            )
            .is_err()
        );
        assert!(apply_revoked_set_to_snapshot(snapshot.as_mut_slice(), 4, &[7]).is_err());
        Ok(())
    }

    #[test]
    fn collect_resolution_targets_descends_empty_internal_nodes() -> Result<()> {
        let snapshot = vec![
            Vec::new(),
            Vec::new(),
            vec![0xC2],
            vec![0xD3],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ];
        let mut targets = Vec::new();
        collect_resolution_targets(snapshot.as_slice(), 0, 3, &mut targets)?;
        assert_eq!(targets, vec![3, 2]);
        Ok(())
    }

    #[test]
    fn select_pivot_parity_prefers_highest_seq_then_lowest_hash() {
        assert!(select_pivot_parity(&[]).is_none());

        let mut older = sample_pivot_parity();
        older.accept_seq = 4;
        older.xk_hash = [0xBB; 32];

        let mut newer = sample_pivot_parity();
        newer.accept_seq = 5;
        newer.xk_hash = [0xCC; 32];
        let parities = [older.clone(), newer.clone()];
        let chosen = select_pivot_parity(&parities).expect("highest accept_seq must be selected");
        assert_eq!(chosen.accept_seq, newer.accept_seq);

        let mut tie_large = sample_pivot_parity();
        tie_large.accept_seq = 7;
        tie_large.xk_hash = [0x22; 32];
        let mut tie_small = sample_pivot_parity();
        tie_small.accept_seq = 7;
        tie_small.xk_hash = [0x11; 32];
        let parities = [tie_large, tie_small.clone()];
        let chosen = select_pivot_parity(&parities)
            .expect("tie must select lexicographically smaller xk_hash");
        assert_eq!(chosen.xk_hash, tie_small.xk_hash);
    }

    #[test]
    fn authenticated_message_helpers_cover_roundtrip_and_error_paths() -> Result<()> {
        let leaf_id = [0x44; 32];
        let timestamp_ms = 123_456u64;
        let plaintext = b"hello world";
        let (public_key, secret_key) = dilithium5::keypair();
        let signature = sign_message(
            &leaf_id,
            timestamp_ms,
            plaintext,
            DilithiumSecretKeyTrait::as_bytes(&secret_key),
        )?;
        let encoded = encode_authenticated_message(
            timestamp_ms,
            plaintext,
            DilithiumPublicKeyTrait::as_bytes(&public_key),
            signature.as_slice(),
        );
        let decoded = decode_authenticated_message(encoded.as_slice())?;
        assert_eq!(decoded.timestamp_ms, timestamp_ms);
        assert_eq!(decoded.plaintext, plaintext);
        assert_eq!(
            decoded.public_key,
            DilithiumPublicKeyTrait::as_bytes(&public_key)
        );
        assert_eq!(decoded.signature, signature.as_slice());
        verify_message_signature(
            &leaf_id,
            decoded.timestamp_ms,
            decoded.plaintext,
            decoded.signature,
            decoded.public_key,
        )?;

        assert!(sign_message(&leaf_id, timestamp_ms, plaintext, &[0xAA; 32]).is_err());
        assert!(decode_authenticated_message(&[]).is_err());

        let mut bad_prefix = encoded.clone();
        bad_prefix[0] ^= 0xFF;
        assert!(
            decode_authenticated_message(bad_prefix.as_slice())
                .expect_err("bad prefix must fail")
                .to_string()
                .contains("invalid message prefix")
        );

        let truncated_plaintext = &encoded[..MESSAGE_PREFIX.len() + 8 + 4 + plaintext.len() - 1];
        assert!(
            decode_authenticated_message(truncated_plaintext)
                .expect_err("truncated plaintext must fail")
                .to_string()
                .contains("truncated (plaintext)")
        );

        let plaintext_len = plaintext.len();
        let public_len_offset = MESSAGE_PREFIX.len() + 8 + 4 + plaintext_len;
        let public_key_len = DilithiumPublicKeyTrait::as_bytes(&public_key).len();
        let truncated_public = &encoded[..public_len_offset + 4 + public_key_len - 1];
        assert!(
            decode_authenticated_message(truncated_public)
                .expect_err("truncated public key must fail")
                .to_string()
                .contains("truncated (public key)")
        );

        let truncated_signature = &encoded[..encoded.len() - 1];
        assert!(
            decode_authenticated_message(truncated_signature)
                .expect_err("truncated signature must fail")
                .to_string()
                .contains("truncated (signature)")
        );

        let mut tampered_plaintext = plaintext.to_vec();
        tampered_plaintext[0] ^= 0x01;
        assert!(
            verify_message_signature(
                &leaf_id,
                timestamp_ms,
                tampered_plaintext.as_slice(),
                signature.as_slice(),
                DilithiumPublicKeyTrait::as_bytes(&public_key),
            )
            .is_err()
        );
        assert!(
            verify_message_signature(
                &leaf_id,
                timestamp_ms,
                plaintext,
                &signature[..signature.len() - 1],
                DilithiumPublicKeyTrait::as_bytes(&public_key),
            )
            .is_err()
        );
        assert!(
            verify_message_signature(
                &leaf_id,
                timestamp_ms,
                plaintext,
                signature.as_slice(),
                &DilithiumPublicKeyTrait::as_bytes(&public_key)[..8],
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn parse_cli_args_defaults_and_flags() -> Result<()> {
        let opts = parse_cli_args(vec!["--batch".to_string(), "--count=2".to_string()])?;
        assert_eq!(opts.server_url, "http://127.0.0.1:8080");
        assert_eq!(opts.count, 2);
        assert!(opts.batch_mode);
        assert!(!opts.watch_mode);
        assert!(!opts.verbose);
        assert!(opts.leave_order.is_none());
        assert_eq!(opts.message_burst_count, 0);
        assert_eq!(opts.message_burst_interval_ms, 0);
        assert!(opts.session_artifact_dir.is_none());
        assert_eq!(opts.alias_base, "cli-joiner");
        assert_eq!(opts.room_id.len(), 64);

        let opts = parse_cli_args(vec![
            "http://127.0.0.1:19090".to_string(),
            "abcd".repeat(16),
            "operator".to_string(),
            "--watch".to_string(),
            "--count=2".to_string(),
            "--message-burst-count=3".to_string(),
            "--message-burst-interval-ms=25".to_string(),
            "--session-artifact-dir=/tmp/cityg-client-state".to_string(),
            "--verbose".to_string(),
        ])?;
        assert_eq!(opts.server_url, "http://127.0.0.1:19090");
        assert_eq!(opts.alias_base, "operator");
        assert_eq!(opts.room_id, "abcd".repeat(16));
        assert!(opts.leave_order.is_none());
        assert!(opts.watch_mode);
        assert!(opts.batch_mode);
        assert!(opts.verbose);
        assert_eq!(opts.message_burst_count, 3);
        assert_eq!(opts.message_burst_interval_ms, 25);
        assert_eq!(
            opts.session_artifact_dir,
            Some(PathBuf::from("/tmp/cityg-client-state"))
        );
        Ok(())
    }

    #[test]
    fn parse_cli_args_sparse_leave_order_is_accepted_in_batch() -> Result<()> {
        let opts = parse_cli_args(vec![
            "--batch".to_string(),
            "--count=3".to_string(),
            "--leave-order=1,,3".to_string(),
        ])?;
        assert_eq!(opts.leave_order, Some(vec![1, 3]));
        Ok(())
    }

    #[test]
    fn parse_cli_args_rejects_invalid_combinations() {
        let err =
            parse_cli_args(vec!["--count=0".to_string()]).expect_err("count=0 should be rejected");
        assert!(err.to_string().contains("--count must be at least 1"));

        let err = parse_cli_args(vec!["--watch".to_string()])
            .expect_err("watch with default count should be rejected");
        assert!(err.to_string().contains("--watch requires --count >= 2"));

        let err = parse_cli_args(vec!["--leave-order=1".to_string()])
            .expect_err("leave-order without batch should fail");
        assert!(err.to_string().contains("--leave-order requires --batch"));

        let err = parse_cli_args(vec![
            "--batch".to_string(),
            "--count=2".to_string(),
            "--leave-order=1,3".to_string(),
        ])
        .expect_err("out-of-range leave order should fail");
        assert!(err.to_string().contains("out of range"));

        let opts = parse_cli_args(vec![
            "--watch".to_string(),
            "--count=2".to_string(),
            "--leave-order=2".to_string(),
        ])
        .expect("watch mode should accept sparse explicit leave-order");
        assert!(opts.watch_mode);
        assert_eq!(opts.leave_order, Some(vec![2]));

        let err = parse_cli_args(vec![
            "http://127.0.0.1:18080".to_string(),
            "room".to_string(),
            "alias".to_string(),
            "extra".to_string(),
        ])
        .expect_err("extra positional arg should fail");
        assert!(err.to_string().contains("unexpected extra argument"));

        let err = parse_cli_args(vec!["--session-artifact-dir=".to_string()])
            .expect_err("empty session artifact dir should fail");
        assert!(
            err.to_string()
                .contains("--session-artifact-dir requires a non-empty path")
        );
    }

    #[test]
    fn parse_cli_args_rejects_invalid_numeric_values() {
        let err = parse_cli_args(vec!["--count=abc".to_string()])
            .expect_err("non-numeric count should fail");
        assert!(err.to_string().contains("invalid --count value: abc"));

        let err = parse_cli_args(vec![
            "--batch".to_string(),
            "--count=2".to_string(),
            "--leave-order=1,a".to_string(),
        ])
        .expect_err("non-numeric leave order entry should fail");
        assert!(err.to_string().contains("invalid leave order entry: a"));

        let err = parse_cli_args(vec!["--message-burst-count=nope".to_string()])
            .expect_err("non-numeric message burst count should fail");
        assert!(
            err.to_string()
                .contains("invalid --message-burst-count value: nope")
        );

        let err = parse_cli_args(vec!["--message-burst-interval-ms=nope".to_string()])
            .expect_err("non-numeric message burst interval should fail");
        assert!(
            err.to_string()
                .contains("invalid --message-burst-interval-ms value: nope")
        );
    }

    #[test]
    fn parse_hex32_field_accepts_exact_hex32() {
        let expected = [0xABu8; 32];
        let value = serde_json::json!({
            "leaf_id": hex::encode(expected),
        });
        assert_eq!(parse_hex32_field(&value, "leaf_id"), Some(expected));
    }

    #[test]
    fn parse_hex32_field_rejects_invalid_inputs() {
        let short = serde_json::json!({ "leaf_id": "aa" });
        assert!(parse_hex32_field(&short, "leaf_id").is_none());

        let non_hex = serde_json::json!({ "leaf_id": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" });
        assert!(parse_hex32_field(&non_hex, "leaf_id").is_none());
    }

    #[test]
    fn notification_from_json_parses_message_and_membership() {
        let weid = [0x11u8; 32];
        let gid = [0x22u8; 32];
        let leaf_id = [0x33u8; 32];

        let message = serde_json::json!({
            "type": "message",
            "we_epoch_id": hex::encode(weid),
            "timestamp_ms": 42u64
        });
        let membership = serde_json::json!({
            "type": "membership",
            "gid": hex::encode(gid),
            "leaf_id": hex::encode(leaf_id),
            "event": "join",
            "timestamp_ms": 99u64
        });

        let parsed_message = Notification::from_json(&message);
        assert!(matches!(parsed_message, Some(Notification::Message { .. })));
        if let Some(Notification::Message {
            we_epoch_id,
            timestamp_ms,
        }) = parsed_message
        {
            assert_eq!(we_epoch_id, weid);
            assert_eq!(timestamp_ms, 42);
        }

        let parsed_membership = Notification::from_json(&membership);
        assert!(matches!(
            parsed_membership,
            Some(Notification::Membership { .. })
        ));
        if let Some(Notification::Membership {
            gid: parsed_gid,
            leaf_id: parsed_leaf,
            event,
            timestamp_ms,
        }) = parsed_membership
        {
            assert_eq!(parsed_gid, gid);
            assert_eq!(parsed_leaf, leaf_id);
            assert_eq!(event, "join");
            assert_eq!(timestamp_ms, 99);
        }
    }

    #[test]
    fn notification_from_json_rejects_invalid_membership_gid() {
        let membership = serde_json::json!({
            "type": "membership",
            "gid": "not-hex",
            "leaf_id": hex::encode([0x44u8; 32]),
            "event": "join"
        });
        assert!(Notification::from_json(&membership).is_none());
    }

    #[test]
    fn notification_from_json_parses_lag_and_other() {
        let lag = serde_json::json!({
            "type": "lag",
            "lagged_messages": 17u64
        });
        let unknown = serde_json::json!({
            "type": "custom",
            "foo": "bar"
        });

        let parsed_lag = Notification::from_json(&lag);
        assert!(matches!(parsed_lag, Some(Notification::Lag { .. })));
        if let Some(Notification::Lag { lagged_messages }) = parsed_lag {
            assert_eq!(lagged_messages, 17);
        }

        assert!(matches!(
            Notification::from_json(&unknown),
            Some(Notification::Other)
        ));
    }

    #[test]
    fn notification_from_json_rejects_missing_required_fields() {
        let missing_type = serde_json::json!({});
        assert!(Notification::from_json(&missing_type).is_none());

        let missing_message_weid = serde_json::json!({
            "type": "message",
            "timestamp_ms": 12u64
        });
        assert!(Notification::from_json(&missing_message_weid).is_none());

        let missing_membership_leaf = serde_json::json!({
            "type": "membership",
            "gid": hex::encode([0x11u8; 32]),
            "event": "join"
        });
        assert!(Notification::from_json(&missing_membership_leaf).is_none());
    }

    #[test]
    fn describe_http_failure_includes_freeze_metadata() {
        let detail =
            describe_http_failure("500", "acceptance error", Some(925), Some("mh_window_full"));
        assert!(detail.contains("server error (500): acceptance error"));
        assert!(detail.contains("[freeze 925 mh_window_full]"));

        let detail = describe_http_failure("500", "acceptance error", Some(925), None);
        assert!(detail.contains("[freeze 925]"));

        let detail = describe_http_failure("400", "bad request", None, None);
        assert_eq!(detail, "server error (400): bad request");
    }

    #[test]
    fn extract_bytes_opt_handles_missing_null_and_bytes() -> Result<()> {
        let mut header = BTreeMap::new();
        header.insert(1, Value::Null);
        header.insert(2, Value::Bytes(vec![1, 2, 3]));
        assert_eq!(extract_bytes_opt(&header, 0)?, None);
        assert_eq!(extract_bytes_opt(&header, 1)?, None);
        assert_eq!(extract_bytes_opt(&header, 2)?, Some(vec![1, 2, 3]));
        header.insert(3, Value::Text("oops".to_string()));
        assert!(extract_bytes_opt(&header, 3).is_err());
        Ok(())
    }

    #[test]
    fn extract_bytes_reports_missing_and_wrong_type() {
        let mut header = BTreeMap::new();
        header.insert(7, Value::Text("oops".to_string()));
        assert!(extract_bytes(&header, 8).is_err());
        assert!(extract_bytes(&header, 7).is_err());
    }

    #[test]
    fn recompute_proofs_commit_changes_with_optional_fields() -> Result<()> {
        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_VRF_PROOF, Value::Bytes(vec![0x01, 0x02]));
        header.insert(hdr::HDR_FS_CAPSS, Value::Bytes(vec![0x03, 0x04]));

        let base = recompute_proofs_commit(&header)?;

        header.insert(hdr::HDR_SRX_ROOT_SW, Value::Bytes([0x10; 32].to_vec()));
        header.insert(hdr::HDR_SRX_SMALLWOOD, Value::Bytes(vec![0x20, 0x21]));
        let with_optional = recompute_proofs_commit(&header)?;
        assert_ne!(base, with_optional);

        header.insert(hdr::HDR_VRF_PROOF, Value::Text("bad".to_string()));
        assert!(
            recompute_proofs_commit(&header).is_err(),
            "wrong type for mandatory proof must error"
        );
        Ok(())
    }

    #[test]
    fn describe_value_and_strip_rollup_metadata_behaviour() {
        assert_eq!(describe_value(None), "None");
        assert_eq!(describe_value(Some(&Value::Bool(true))), "Bool(true)");
        assert_eq!(describe_value(Some(&Value::Null)), "Null");
        assert_eq!(
            describe_value(Some(&Value::Bytes(vec![1, 2, 3]))),
            "Bytes(3)"
        );
        assert_eq!(
            describe_value(Some(&Value::Array(vec![Value::Null]))),
            "Array(len=1)"
        );
        assert_eq!(
            describe_value(Some(&Value::Map(vec![(Value::Null, Value::Null)]))),
            "Map(len=1)"
        );
        assert_eq!(describe_value(Some(&Value::Float(1.5))), "Float(1.5)");
        assert_eq!(
            describe_value(Some(&Value::Tag(7, Box::new(Value::Null)))),
            "Tag(7)"
        );

        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_ROLLUP_PROVENANCE_COMMIT, Value::Bytes(vec![1]));
        header.insert(hdr::HDR_ROLLUP_EPOCH_REPLAY, Value::Bytes(vec![2]));
        header.insert(hdr::HDR_ROLLUP_VCK_COMMIT, Value::Bytes(vec![3]));
        header.insert(9999, Value::Text("keep".to_string()));
        strip_srx_and_rollup(&mut header);
        assert!(!header.contains_key(&hdr::HDR_ROLLUP_PROVENANCE_COMMIT));
        assert!(!header.contains_key(&hdr::HDR_ROLLUP_EPOCH_REPLAY));
        assert!(!header.contains_key(&hdr::HDR_ROLLUP_VCK_COMMIT));
        assert!(header.contains_key(&9999), "unrelated keys must remain");
    }

    #[test]
    fn collect_resolution_targets_handles_missing_leaf_and_nonempty_branch() -> Result<()> {
        let mut targets = Vec::new();
        let snapshot = vec![Vec::new(), vec![0xAA], Vec::new()];

        collect_resolution_targets(snapshot.as_slice(), 99, 2, &mut targets)?;
        assert!(targets.is_empty());

        collect_resolution_targets(snapshot.as_slice(), 1, 2, &mut targets)?;
        assert_eq!(targets, vec![1]);

        targets.clear();
        collect_resolution_targets(snapshot.as_slice(), 2, 2, &mut targets)?;
        assert!(targets.is_empty());
        Ok(())
    }

    #[test]
    fn hydrate_parities_and_apply_pivot_alignment_cover_fs_rules() {
        let mut missing = sample_pivot_parity();
        missing.fs_ec = None;
        missing.fs_epoch_commit = None;
        missing.fs_dev_commit = None;

        let existing = sample_pivot_parity();
        let hydrated = hydrate_parities(&[missing, existing.clone()], 99, [0xAB; 32], [0xBC; 32]);
        assert_eq!(hydrated[0].fs_ec, Some(99));
        assert_eq!(hydrated[0].fs_epoch_commit, Some([0xAB; 32]));
        assert_eq!(hydrated[0].fs_dev_commit, Some([0xBC; 32]));
        assert_eq!(hydrated[1].fs_ec, existing.fs_ec);

        let pivot = sample_pivot_parity();
        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_FS_EC, Value::Integer(Integer::from(7u64)));
        header.insert(hdr::HDR_FS_EPOCH_COMMIT, Value::Bytes([0x11; 32].to_vec()));
        apply_pivot_alignment(&mut header, &pivot);

        assert_eq!(
            header.get(&hdr::HDR_FS_POLICY_VERSION),
            Some(&Value::Integer(Integer::from(7u64)))
        );
        assert_eq!(
            header.get(&hdr::HDR_PROOF_MODE),
            Some(&Value::Text("lin+zkvrf".to_string()))
        );
        assert_eq!(
            header.get(&hdr::HDR_VRF_ID),
            Some(&Value::Text("lb-vrf".to_string()))
        );
        assert_eq!(
            header.get(&hdr::HDR_FS_EC),
            Some(&Value::Integer(Integer::from(7u64)))
        );
        assert_eq!(
            header.get(&hdr::HDR_FS_CHECKPOINT_EC),
            Some(&Value::Integer(Integer::from(77u64)))
        );
        assert_eq!(
            header.get(&hdr::HDR_FS_EPOCH_COMMIT),
            Some(&Value::Bytes([0x11; 32].to_vec()))
        );
        assert_eq!(
            header.get(&hdr::HDR_FS_DEV_PREV_COMMIT),
            Some(&Value::Bytes([0x55; 32].to_vec()))
        );
        assert_eq!(
            header.get(&hdr::HDR_FS_DEV_COMMIT),
            Some(&Value::Bytes([0x55; 32].to_vec()))
        );
    }

    #[test]
    fn apply_pivot_alignment_inserts_missing_fs_fields() {
        let pivot = sample_pivot_parity();
        let mut header = BTreeMap::new();
        apply_pivot_alignment(&mut header, &pivot);
        assert_eq!(
            header.get(&hdr::HDR_FS_EC),
            Some(&Value::Integer(Integer::from(77u64)))
        );
        assert_eq!(
            header.get(&hdr::HDR_FS_CHECKPOINT_EC),
            Some(&Value::Integer(Integer::from(77u64)))
        );
        assert_eq!(
            header.get(&hdr::HDR_FS_EPOCH_COMMIT),
            Some(&Value::Bytes([0x44; 32].to_vec()))
        );
        assert_eq!(
            header.get(&hdr::HDR_FS_DEV_PREV_COMMIT),
            Some(&Value::Bytes([0x55; 32].to_vec()))
        );
        assert_eq!(
            header.get(&hdr::HDR_FS_DEV_COMMIT),
            Some(&Value::Bytes([0x55; 32].to_vec()))
        );
    }

    #[test]
    fn apply_pivot_alignment_preserves_existing_fields_and_skips_invalid_policy_version() {
        let mut pivot = sample_pivot_parity();
        pivot.policy_version = "not-a-u64".to_string();
        let mut header = BTreeMap::from([
            (
                hdr::HDR_PROOF_MODE,
                Value::Text("existing-proof-mode".to_string()),
            ),
            (hdr::HDR_VRF_ID, Value::Text("existing-vrf".to_string())),
            (hdr::HDR_VRF_PROOF, Value::Bytes(vec![0xAA])),
            (hdr::HDR_VRF_PUBLIC_KEY, Value::Bytes(vec![0xBB])),
            (hdr::HDR_VRF_MASK_A, Value::Bytes(vec![0xCC])),
            (hdr::HDR_VRF_MASK_B, Value::Bytes(vec![0xDD])),
            (hdr::HDR_FS_CAPSS, Value::Bytes(vec![0xEE])),
            (hdr::HDR_PROOFS_COMMIT, Value::Bytes(vec![0xFF])),
        ]);

        apply_pivot_alignment(&mut header, &pivot);

        assert!(!header.contains_key(&hdr::HDR_FS_POLICY_VERSION));
        assert_eq!(
            header.get(&hdr::HDR_PROOF_MODE),
            Some(&Value::Text("existing-proof-mode".to_string()))
        );
        assert_eq!(
            header.get(&hdr::HDR_VRF_ID),
            Some(&Value::Text("existing-vrf".to_string()))
        );
        assert_eq!(
            header.get(&hdr::HDR_VRF_PROOF),
            Some(&Value::Bytes(vec![0xAA]))
        );
        assert_eq!(
            header.get(&hdr::HDR_VRF_PUBLIC_KEY),
            Some(&Value::Bytes(vec![0xBB]))
        );
        assert_eq!(
            header.get(&hdr::HDR_VRF_MASK_A),
            Some(&Value::Bytes(vec![0xCC]))
        );
        assert_eq!(
            header.get(&hdr::HDR_VRF_MASK_B),
            Some(&Value::Bytes(vec![0xDD]))
        );
        assert_eq!(
            header.get(&hdr::HDR_FS_CAPSS),
            Some(&Value::Bytes(vec![0xEE]))
        );
        assert_eq!(
            header.get(&hdr::HDR_PROOFS_COMMIT),
            Some(&Value::Bytes(vec![0xFF]))
        );
    }

    #[test]
    fn log_helpers_cover_none_fingerprint_and_non_integer_fs_ec() {
        let (_pk, sk) = dilithium5::keypair();
        let session = Session {
            server_url: "http://127.0.0.1:18080".to_string(),
            room_id: hex::encode([0xAA; 32]),
            gid: [0x01; 32],
            leaf_id: [0x02; 32],
            xk_hash: [0x03; 32],
            epoch_key: [0x04; 32],
            barrier_version: 1,
            k_barrier: [0x05; 32],
            pop_public_key: vec![0x11],
            pop_secret: Box::new(sk),
            vrf_secret_key: vec![0x22],
            vrf_public_key: vec![0x33],
            forward_state: ForwardSecrecyState::with_state([0x12; 32], 5, [0x55; 32], [0x66; 32]),
            fs_ec: 5,
            fs_epoch_commit: [0x44; 32],
            fs_dev_prev_commit: [0x55; 32],
            we_epoch_id: [0x66; 32],
            anchor_hdr_ctx: vec![],
            seed_ctx_hash: [0x77; 32],
            seed_commit: [0x88; 32],
            seed_bundle_commit: [0x99; 32],
            fs_fingerprint: None,
            join_finalize_auth_token: [0xAA; 32],
            current_history_authority_extension: None,
            current_global_history_attestation_bytes: Vec::new(),
            stored_header_map: BTreeMap::new(),
            #[cfg(test)]
            msg_replay_state: MsgReplayState::default(),
        };
        log_fingerprints(&session);

        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_FS_EC, Value::Text("bad".to_string()));
        log_fs_metadata(&sample_pivot_parity(), &header);
    }

    #[test]
    fn log_helpers_cover_present_fs_metadata_fields() {
        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_FS_EC, Value::Integer(Integer::from(12u64)));
        header.insert(hdr::HDR_FS_EPOCH_COMMIT, Value::Bytes([0x42; 32].to_vec()));
        header.insert(
            hdr::HDR_FS_DEV_PREV_COMMIT,
            Value::Bytes([0x24; 32].to_vec()),
        );
        log_fs_metadata(&sample_pivot_parity(), &header);
    }

    #[test]
    fn recompute_srx_commit_returns_none_when_missing() -> Result<()> {
        let header = BTreeMap::new();
        assert!(recompute_srx_commit(&header)?.is_none());
        Ok(())
    }

    #[test]
    fn recompute_srx_commit_accepts_payload_and_rejects_wrong_type() -> Result<()> {
        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_SRX_PAYLOAD, Value::Bytes(vec![0xAA, 0xBB, 0xCC]));
        let commit = recompute_srx_commit(&header)?;
        assert!(commit.is_some());

        header.insert(hdr::HDR_SRX_PAYLOAD, Value::Text("bad".to_string()));
        assert!(recompute_srx_commit(&header).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn join_leave_roundtrip_and_message_send() -> Result<()> {
        let port = next_free_local_port();
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex::encode([0x91u8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;
        let alice = perform_join(&server_url, &room_id, "alice").await?;
        let mut bob = perform_join(&server_url, &room_id, "bob").await?;
        let client = new_api_client(&server_url);
        let before_leave = client.members(&alice.gid, None).await?;
        assert_eq!(before_leave.total_count, 2);
        assert!(
            before_leave
                .members
                .iter()
                .any(|member| member.leaf_id.as_slice() == alice.leaf_id.as_slice())
        );
        assert!(
            before_leave
                .members
                .iter()
                .any(|member| member.leaf_id.as_slice() == bob.leaf_id.as_slice())
        );

        send_dummy_message(&mut bob).await?;
        perform_leave(&alice, true).await?;
        let after_alice_leave = client.members(&alice.gid, None).await?;
        assert_eq!(after_alice_leave.total_count, 1);
        assert!(
            !after_alice_leave
                .members
                .iter()
                .any(|member| member.leaf_id.as_slice() == alice.leaf_id.as_slice())
        );
        assert!(
            after_alice_leave
                .members
                .iter()
                .any(|member| member.leaf_id.as_slice() == bob.leaf_id.as_slice())
        );
        perform_leave(&bob, true).await?;
        let after_bob_leave = client.members(&alice.gid, None).await?;
        assert_eq!(after_bob_leave.total_count, 0);
        assert!(after_bob_leave.members.is_empty());

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn rejoin_with_same_identity_succeeds_after_room_becomes_empty() -> Result<()> {
        let port = next_free_local_port();
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex::encode([0x93u8; 32]);
        ensure_test_auth_env();
        let (alice_pop_public_key, alice_pop_secret_key) =
            cityg_api_client::generate_room_admin_keypair();
        let admin_proof = build_room_admin_proof(
            RoomAdminOperation::Bootstrap,
            &room_id,
            demo::kbroad_public(),
            &alice_pop_public_key,
            &alice_pop_secret_key,
        )?;
        new_api_client(&server_url)
            .bootstrap_room_as_admin(&room_id, demo::kbroad_public(), admin_proof)
            .await?;

        let alice = perform_join_with_identity(
            &server_url,
            &room_id,
            "alice",
            &alice_pop_public_key,
            &alice_pop_secret_key,
        )
        .await?;
        let bob = perform_join(&server_url, &room_id, "bob").await?;
        let client = new_api_client(&server_url);

        perform_leave(&bob, true).await?;
        perform_leave(&alice, true).await?;

        let empty_members = client.members(&alice.gid, None).await?;
        assert_eq!(empty_members.total_count, 0);
        assert!(empty_members.members.is_empty());

        let rejoined = perform_join_with_identity(
            &server_url,
            &room_id,
            "alice",
            &alice_pop_public_key,
            &alice_pop_secret_key,
        )
        .await?;

        assert_eq!(
            rejoined.pop_public_key, alice.pop_public_key,
            "rejoin should reuse the same persistent room identity"
        );
        assert_eq!(
            rejoined.leaf_id, alice.leaf_id,
            "rejoining with the same room identity should reuse the same leaf id"
        );

        let after_rejoin = client.members(&alice.gid, None).await?;
        assert_eq!(after_rejoin.total_count, 1);
        assert!(
            after_rejoin
                .members
                .iter()
                .any(|member| member.leaf_id.as_slice() == rejoined.leaf_id.as_slice())
        );

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn repeated_sender_messages_roundtrip_with_randomized_msg_index() -> Result<()> {
        let port = next_free_local_port();
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex::encode([0xA1u8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;
        let mut alice = perform_join(&server_url, &room_id, "alice").await?;

        send_text_message(&mut alice, "one").await?;
        send_text_message(&mut alice, "two").await?;

        let fetched = fetch_and_decrypt_messages(&mut alice).await?;
        assert_eq!(fetched, vec!["one".to_string(), "two".to_string()]);

        let fetched_again = fetch_and_decrypt_messages(&mut alice).await?;
        assert!(
            fetched_again.is_empty(),
            "replay-tracked fetch should not re-emit already seen messages"
        );

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn perform_join_bootstrapped_room_returns_join_finalize_head() -> Result<()> {
        let port = next_free_local_port();
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex::encode([0x92u8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;

        let alice = perform_join(&server_url, &room_id, "alice").await?;
        let stored = new_api_client(&server_url)
            .get_bundle(&alice.we_epoch_id)
            .await
            .context("fetch stored join-finalize bundle")?;
        let stored =
            ClientEpochBundle::from_cbor(&stored.bundle_cbor).context("decode stored bundle")?;
        let reason: u64 = stored
            .header_map
            .get(&hdr::HDR_BARRIER_UPDATE_REASON)
            .and_then(|value| match value {
                Value::Integer(int) => (*int).try_into().ok(),
                _ => None,
            })
            .ok_or(anyhow!(
                "stored join-finalize bundle missing barrier_update_reason"
            ))?;
        assert_eq!(reason, 2);
        let join_finalize_auth = stored
            .header_map
            .get(&hdr::HDR_JOIN_FINALIZE_AUTH)
            .and_then(Value::as_bytes)
            .ok_or(anyhow!(
                "stored join-finalize bundle missing join_finalize_auth"
            ))?;
        assert_eq!(join_finalize_auth.len(), 32);
        let history_commitment = stored
            .header_map
            .get(&hdr::HDR_BARRIER_HISTORY_COMMITMENT)
            .and_then(Value::as_bytes)
            .ok_or(anyhow!(
                "stored join-finalize bundle missing barrier history commitment"
            ))?;
        let decoded_history = decode_history_commitment_header(history_commitment)?;
        assert_ne!(decoded_history.history_view_id, [0u8; 32]);
        assert_ne!(decoded_history.history_commitment_id, [0u8; 32]);

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn perform_join_second_member_returns_join_finalize_head() -> Result<()> {
        let port = next_free_local_port();
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex::encode([0x93u8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;

        let _alice = perform_join(&server_url, &room_id, "alice").await?;
        let bob = perform_join(&server_url, &room_id, "bob").await?;
        let stored = new_api_client(&server_url)
            .get_bundle(&bob.we_epoch_id)
            .await
            .context("fetch stored second join-finalize bundle")?;
        let stored =
            ClientEpochBundle::from_cbor(&stored.bundle_cbor).context("decode stored bundle")?;
        let reason: u64 = stored
            .header_map
            .get(&hdr::HDR_BARRIER_UPDATE_REASON)
            .and_then(|value| match value {
                Value::Integer(int) => (*int).try_into().ok(),
                _ => None,
            })
            .ok_or(anyhow!(
                "stored second join-finalize bundle missing barrier_update_reason"
            ))?;
        assert_eq!(reason, 2);
        let join_finalize_auth = stored
            .header_map
            .get(&hdr::HDR_JOIN_FINALIZE_AUTH)
            .and_then(Value::as_bytes)
            .ok_or(anyhow!(
                "stored second join-finalize bundle missing join_finalize_auth"
            ))?;
        assert_eq!(join_finalize_auth.len(), 32);
        let history_commitment = stored
            .header_map
            .get(&hdr::HDR_BARRIER_HISTORY_COMMITMENT)
            .and_then(Value::as_bytes)
            .ok_or(anyhow!(
                "stored second join-finalize bundle missing barrier history commitment"
            ))?;
        let decoded_history = decode_history_commitment_header(history_commitment)?;
        assert_ne!(decoded_history.history_view_id, [0u8; 32]);
        assert_ne!(decoded_history.history_commitment_id, [0u8; 32]);

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn perform_join_finalize_rejects_tickets_with_srx_payload() -> Result<()> {
        let fixture = capture_join_finalize_fixture().await?;
        let mut bad_ticket = fixture.ticket.clone();
        bad_ticket.srx_cbor = vec![0x01, 0x02, 0x03];

        let state = LeaveMockState::new([(
            "/v1/rooms/merge_ticket",
            vec![MockResponse::proto_bytes(encode_merge_ticket(&bad_ticket)?)],
        )]);
        let (server_url, handle) = start_leave_mock_server(state).await?;

        let mut session = fixture.session;
        session.server_url = server_url;
        let err = match perform_join_finalize(session).await {
            Ok(_) => {
                return Err(anyhow!(
                    "join finalize should reject unexpected SRX payloads"
                ));
            }
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("join finalize merge ticket unexpectedly contained SRX payload"),
            "unexpected error: {err}"
        );

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn perform_join_finalize_retries_ticket_conflict_and_falls_back_to_pristine_bundle()
    -> Result<()> {
        let fixture = capture_join_finalize_fixture().await?;
        let state = LeaveMockState::new([
            (
                "/v1/rooms/merge_ticket",
                vec![
                    MockResponse::json(
                        HttpStatusCode::CONFLICT,
                        "pivot head missing",
                        Some(925),
                        None,
                    ),
                    MockResponse::proto_bytes(encode_merge_ticket(&fixture.ticket)?),
                ],
            ),
            (
                "/v1/barrier/fetch_public_tree",
                encode_barrier_tree_snapshot_pages(
                    &fixture.barrier_tree_snapshot,
                    &fixture.ticket.current_history_commitment,
                ),
            ),
            (
                "/v1/barrier/resolve_joins_since",
                vec![MockResponse::proto_bytes(encode_join_records(
                    fixture.join_records.as_slice(),
                    &fixture.ticket.current_history_commitment,
                ))],
            ),
            (
                "/v1/barrier/resolve_revoked_leaves",
                vec![MockResponse::proto_bytes(encode_revoked_leaf_indices(
                    fixture.revoked_leaf_indices.as_slice(),
                    &fixture.ticket.current_history_commitment,
                ))],
            ),
            (
                "/v1/pivot/refresh",
                vec![MockResponse::empty_proto(), MockResponse::empty_proto()],
            ),
            (
                "/v1/accept_epoch",
                vec![
                    MockResponse::json(
                        HttpStatusCode::CONFLICT,
                        "mh_heads_invalid",
                        None,
                        Some("mh_heads_invalid"),
                    ),
                    MockResponse::empty_proto(),
                ],
            ),
        ]);
        let (server_url, handle) = start_leave_mock_server(state.clone()).await?;

        let mut session = fixture.session;
        session.server_url = server_url;
        let finalized = perform_join_finalize(session).await?;
        assert_eq!(
            finalized.barrier_version,
            fixture.ticket.barrier_version.saturating_add(1)
        );
        assert_ne!(finalized.k_barrier, [0u8; 32]);
        assert_eq!(state.call_count("/v1/rooms/merge_ticket"), 2);
        assert_eq!(state.call_count("/v1/pivot/refresh"), 2);
        assert_eq!(state.call_count("/v1/accept_epoch"), 2);

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn perform_join_finalize_defaults_zero_nmax_without_manual_kbroad_rotation() -> Result<()>
    {
        let fixture = capture_join_finalize_fixture().await?;
        let mut ticket = fixture.ticket.clone();
        ticket.n_max = 0;

        let state = LeaveMockState::new([
            (
                "/v1/rooms/merge_ticket",
                vec![MockResponse::proto_bytes(encode_merge_ticket(&ticket)?)],
            ),
            (
                "/v1/barrier/fetch_public_tree",
                encode_barrier_tree_snapshot_pages(
                    &fixture.barrier_tree_snapshot,
                    &ticket.current_history_commitment,
                ),
            ),
            (
                "/v1/barrier/resolve_joins_since",
                vec![MockResponse::proto_bytes(encode_join_records(
                    fixture.join_records.as_slice(),
                    &ticket.current_history_commitment,
                ))],
            ),
            (
                "/v1/barrier/resolve_revoked_leaves",
                vec![MockResponse::proto_bytes(encode_revoked_leaf_indices(
                    fixture.revoked_leaf_indices.as_slice(),
                    &ticket.current_history_commitment,
                ))],
            ),
            ("/v1/pivot/refresh", vec![MockResponse::empty_proto()]),
            ("/v1/accept_epoch", vec![MockResponse::empty_proto()]),
        ]);
        let (server_url, handle) = start_leave_mock_server(state.clone()).await?;

        let mut session = fixture.session;
        session.server_url = server_url;
        let finalized = perform_join_finalize(session).await?;
        assert_eq!(state.call_count("/v1/rooms/merge_ticket"), 1);
        assert_eq!(
            finalized.barrier_version,
            ticket.barrier_version.saturating_add(1)
        );
        assert_ne!(finalized.k_barrier, [0u8; 32]);

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn run_with_options_single_roundtrip() -> Result<()> {
        let port = next_free_local_port();
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex::encode([0x71u8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;

        run_with_options(CliOptions {
            server_url,
            room_id,
            alias_base: "single".to_string(),
            count: 1,
            batch_mode: false,
            watch_mode: false,
            verbose: true,
            leave_order: None,
            message_burst_count: 0,
            message_burst_interval_ms: 0,
            session_artifact_dir: None,
        })
        .await?;

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn run_with_options_batch_roundtrip() -> Result<()> {
        let port = next_free_local_port();
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex::encode([0x72u8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;

        run_with_options(CliOptions {
            server_url,
            room_id,
            alias_base: "batch".to_string(),
            count: 2,
            batch_mode: true,
            watch_mode: false,
            verbose: true,
            leave_order: None,
            message_burst_count: 2,
            message_burst_interval_ms: 0,
            session_artifact_dir: None,
        })
        .await?;

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn run_with_options_non_batch_multi_roundtrip() -> Result<()> {
        let port = next_free_local_port();
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex::encode([0x73u8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;

        run_with_options(CliOptions {
            server_url,
            room_id,
            alias_base: "multi".to_string(),
            count: 2,
            batch_mode: false,
            watch_mode: false,
            verbose: false,
            leave_order: None,
            message_burst_count: 0,
            message_burst_interval_ms: 0,
            session_artifact_dir: None,
        })
        .await?;

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn run_with_options_batch_single_alias_roundtrip() -> Result<()> {
        let port = next_free_local_port();
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex::encode([0x74u8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;

        run_with_options(CliOptions {
            server_url,
            room_id,
            alias_base: "single-batch".to_string(),
            count: 1,
            batch_mode: true,
            watch_mode: false,
            verbose: false,
            leave_order: None,
            message_burst_count: 1,
            message_burst_interval_ms: 0,
            session_artifact_dir: None,
        })
        .await?;

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn run_with_options_watch_mode_roundtrip() -> Result<()> {
        let port = next_free_local_port();
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex::encode([0x75u8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;

        run_with_options(CliOptions {
            server_url,
            room_id,
            alias_base: "watch-dispatch".to_string(),
            count: 2,
            batch_mode: true,
            watch_mode: true,
            verbose: false,
            leave_order: None,
            message_burst_count: 3,
            message_burst_interval_ms: 0,
            session_artifact_dir: None,
        })
        .await?;

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn run_watch_mode_accepts_zero_burst_count_and_interval() -> Result<()> {
        let port = next_free_local_port();
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex::encode([0x7Au8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;

        run_watch_mode(WatchModeParams {
            server_url: &server_url,
            room_id: &room_id,
            alias_base: "watch-zero-burst",
            count: 2,
            leave_order: Some(vec![2]),
            verbose: false,
            message_burst: MessageBurstOptions {
                count: 0,
                interval: Duration::from_millis(1),
            },
            session_artifact_dir: None,
        })
        .await?;

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn run_with_options_rejects_runtime_leave_order_index() -> Result<()> {
        let port = next_free_local_port();
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex::encode([0x76u8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;

        let err = run_with_options(CliOptions {
            server_url,
            room_id,
            alias_base: "runtime-order".to_string(),
            count: 1,
            batch_mode: true,
            watch_mode: false,
            verbose: false,
            leave_order: Some(vec![2]),
            message_burst_count: 0,
            message_burst_interval_ms: 0,
            session_artifact_dir: None,
        })
        .await
        .expect_err("invalid leave order should fail at runtime");
        assert!(err.to_string().contains("leave order index 2 invalid"));

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn run_watch_mode_rejects_invalid_leave_order_index() -> Result<()> {
        let port = next_free_local_port();
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex::encode([0x7Bu8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;

        let err = run_watch_mode(WatchModeParams {
            server_url: &server_url,
            room_id: &room_id,
            alias_base: "watch-invalid-order",
            count: 2,
            leave_order: Some(vec![3]),
            verbose: false,
            message_burst: MessageBurstOptions {
                count: 1,
                interval: Duration::ZERO,
            },
            session_artifact_dir: None,
        })
        .await
        .expect_err("invalid watch leave order should fail");
        assert!(err.to_string().contains("leave order index 3 invalid"));

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn watch_mode_roundtrip() -> Result<()> {
        let port = next_free_local_port();
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex::encode([0xA1u8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;

        // Keep a single explicit leave in this test to avoid stale-second-leave
        // checkpoint races under heavy instrumentation (llvm-cov).
        run_watch_mode(WatchModeParams {
            server_url: &server_url,
            room_id: &room_id,
            alias_base: "watcher",
            count: 2,
            leave_order: Some(vec![2]),
            verbose: true,
            message_burst: MessageBurstOptions {
                count: 3,
                interval: Duration::ZERO,
            },
            session_artifact_dir: None,
        })
        .await?;

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn perform_join_reports_kbroad_missing_on_unbootstrapped_room() -> Result<()> {
        let port = next_free_local_port();
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex::encode([0xD1u8; 32]);
        let result = perform_join(&server_url, &room_id, "missing-kbroad").await;
        assert!(result.is_err());
        let err = result.err().expect("expected error");
        let detail = err.to_string();
        assert!(detail.contains("kbroad key missing"));
        assert!(detail.contains("KBROAD-provisioned"));

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn perform_join_requires_bootstrap_signer_when_policy_enabled() -> Result<()> {
        let port = next_free_local_port();
        let handle = spawn_server_on_with_seed_demo(port, true).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex::encode([0xD2u8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;
        let result = perform_join(&server_url, &room_id, "bootstrap-required").await;
        assert!(result.is_err());
        let err = result.err().expect("expected error");
        assert!(
            err.to_string()
                .contains("bootstrap signer support is not configured")
        );

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn perform_join_reports_transport_error() -> Result<()> {
        let server_url = "http://127.0.0.1:9";
        let room_id = hex::encode([0xD3u8; 32]);
        let result = perform_join(server_url, &room_id, "transport-error").await;
        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn perform_leave_reports_transport_error() -> Result<()> {
        let session = sample_session("http://127.0.0.1:9");
        let result = perform_leave(&session, false).await;
        assert!(result.is_err());
        let err = match result {
            Ok(_) => return Err(anyhow!("expected transport failure")),
            Err(err) => err,
        };
        assert!(err.to_string().contains("fetch merge ticket"));
        Ok(())
    }

    #[tokio::test]
    async fn perform_leave_reports_cover_leaf_range_rejection_without_manual_kbroad_rotation()
    -> Result<()> {
        let fixture = capture_leave_fixture().await?;
        let barrier_n_max = if fixture.ticket.n_max == 0 {
            DEFAULT_BARRIER_N_MAX
        } else {
            fixture.ticket.n_max
        };
        let mut bad_ticket = fixture.ticket.clone();
        bad_ticket.cover_leaf_index = barrier_n_max;

        let state = LeaveMockState::new([
            (
                "/v1/rooms/merge_ticket",
                vec![MockResponse::proto_bytes(encode_merge_ticket(&bad_ticket)?)],
            ),
            (
                "/v1/barrier/fetch_public_tree",
                encode_barrier_tree_snapshot_pages(
                    &fixture.barrier_tree_snapshot,
                    &bad_ticket.current_history_commitment,
                ),
            ),
        ]);
        let (server_url, handle) = start_leave_mock_server(state.clone()).await?;

        let mut session = fixture.session;
        session.server_url = server_url;
        let err = perform_leave(&session, false)
            .await
            .expect_err("out-of-range cover leaf must fail");
        assert!(
            err.to_string()
                .contains("cover_leaf_index out of range for barrier tree"),
            "unexpected error: {err}"
        );
        assert_eq!(state.call_count("/v1/rooms/merge_ticket"), 1);

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn perform_leave_rejects_barrier_snapshot_nmax_mismatch() -> Result<()> {
        let fixture = capture_leave_fixture().await?;
        let mut bad_ticket = fixture.ticket.clone();
        bad_ticket.n_max = 0;
        let mut bad_snapshot = fixture.barrier_tree_snapshot.clone();
        bad_snapshot.n_max = DEFAULT_BARRIER_N_MAX + 1;

        let state = LeaveMockState::new([
            (
                "/v1/rooms/merge_ticket",
                vec![MockResponse::proto_bytes(encode_merge_ticket(&bad_ticket)?)],
            ),
            (
                "/v1/barrier/fetch_public_tree",
                encode_barrier_tree_snapshot_pages(
                    &bad_snapshot,
                    &bad_ticket.current_history_commitment,
                ),
            ),
        ]);
        let (server_url, handle) = start_leave_mock_server(state).await?;

        let mut session = fixture.session;
        session.server_url = server_url;
        let err = perform_leave(&session, false)
            .await
            .expect_err("n_max mismatch must fail");
        assert!(
            err.to_string()
                .contains("barrier tree snapshot n_max mismatch"),
            "unexpected error: {err}"
        );

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn perform_leave_skips_refresh_conflict_and_retries_pristine_bundle() -> Result<()> {
        let fixture = capture_leave_fixture().await?;
        let mut adjusted_ticket = fixture.ticket.clone();
        if let Some(first_parity) = adjusted_ticket.parities.first_mut() {
            first_parity.vrf_proof = vec![0xFA, 0xCE, 0x01];
            first_parity.fs_capss = vec![0xBE, 0xEF, 0x02];
            first_parity.proofs_commit = [0xAC; 32];
        }

        let state = LeaveMockState::new([
            (
                "/v1/rooms/merge_ticket",
                vec![MockResponse::proto_bytes(encode_merge_ticket(
                    &adjusted_ticket,
                )?)],
            ),
            (
                "/v1/barrier/fetch_public_tree",
                encode_barrier_tree_snapshot_pages(
                    &fixture.barrier_tree_snapshot,
                    &adjusted_ticket.current_history_commitment,
                ),
            ),
            (
                "/v1/barrier/resolve_joins_since",
                vec![MockResponse::proto_bytes(encode_join_records(
                    fixture.join_records.as_slice(),
                    &adjusted_ticket.current_history_commitment,
                ))],
            ),
            (
                "/v1/barrier/resolve_revoked_leaves",
                vec![MockResponse::proto_bytes(encode_revoked_leaf_indices(
                    fixture.revoked_leaf_indices.as_slice(),
                    &adjusted_ticket.current_history_commitment,
                ))],
            ),
            (
                "/v1/pivot/refresh",
                vec![
                    MockResponse::json(
                        HttpStatusCode::CONFLICT,
                        "invalid input: refresh payload diverges from stored parity",
                        None,
                        None,
                    ),
                    MockResponse::empty_proto(),
                ],
            ),
            (
                "/v1/accept_epoch",
                vec![
                    MockResponse::json(
                        HttpStatusCode::CONFLICT,
                        "mh_heads_invalid",
                        None,
                        Some("mh_heads_invalid"),
                    ),
                    MockResponse::empty_proto(),
                ],
            ),
        ]);
        let (server_url, handle) = start_leave_mock_server(state.clone()).await?;

        let mut session = fixture.session;
        session.server_url = server_url;
        perform_leave(&session, true).await?;
        assert_eq!(state.call_count("/v1/pivot/refresh"), 2);
        assert_eq!(state.call_count("/v1/accept_epoch"), 2);

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn mock_merge_ticket_roundtrips_current_history_commitment() -> Result<()> {
        let fixture = capture_leave_fixture().await?;
        let ticket = fixture.ticket;
        let state = LeaveMockState::new([(
            "/v1/rooms/merge_ticket",
            vec![MockResponse::proto_bytes(encode_merge_ticket(&ticket)?)],
        )]);
        let (server_url, handle) = start_leave_mock_server(state).await?;

        let client = new_api_client(&server_url);
        let decoded = client
            .merge_ticket(&hex::encode([0x44; 32]), &ticket.author_leaf_id)
            .await?;
        assert_eq!(
            decoded.current_history_commitment,
            ticket.current_history_commitment
        );
        assert_eq!(
            decoded.history_authority_extension,
            ticket.history_authority_extension
        );

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn perform_leave_surfaces_final_accept_epoch_failure_detail() -> Result<()> {
        let fixture = capture_leave_fixture().await?;
        let state = LeaveMockState::new([
            (
                "/v1/rooms/merge_ticket",
                vec![MockResponse::proto_bytes(encode_merge_ticket(
                    &fixture.ticket,
                )?)],
            ),
            (
                "/v1/barrier/fetch_public_tree",
                encode_barrier_tree_snapshot_pages(
                    &fixture.barrier_tree_snapshot,
                    &fixture.ticket.current_history_commitment,
                ),
            ),
            (
                "/v1/barrier/resolve_joins_since",
                vec![MockResponse::proto_bytes(encode_join_records(
                    fixture.join_records.as_slice(),
                    &fixture.ticket.current_history_commitment,
                ))],
            ),
            (
                "/v1/barrier/resolve_revoked_leaves",
                vec![MockResponse::proto_bytes(encode_revoked_leaf_indices(
                    fixture.revoked_leaf_indices.as_slice(),
                    &fixture.ticket.current_history_commitment,
                ))],
            ),
            ("/v1/pivot/refresh", vec![MockResponse::empty_proto()]),
            (
                "/v1/accept_epoch",
                vec![MockResponse::json(
                    HttpStatusCode::CONFLICT,
                    "merge rejected",
                    Some(944),
                    Some("barrier_version_mismatch"),
                )],
            ),
        ]);
        let (server_url, handle) = start_leave_mock_server(state).await?;

        let mut session = fixture.session;
        session.server_url = server_url;
        let err = perform_leave(&session, true)
            .await
            .expect_err("non-retryable accept_epoch failure must surface");
        let detail = err.to_string();
        assert!(
            detail.contains("merge rejected"),
            "unexpected detail: {detail}"
        );
        assert!(
            detail.contains("[freeze 944 barrier_version_mismatch]"),
            "unexpected detail: {detail}"
        );

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[test]
    fn ensure_matching_history_dependencies_rejects_commitment_mismatch() {
        let expected = HistoryCommitment {
            history_view_id: [0x11; 32],
            history_commitment_id: [0x22; 32],
            prev_history_commitment_id: [0x33; 32],
            history_seq: 7,
        };
        let mut mismatched = expected;
        mismatched.history_commitment_id[0] ^= 0x5A;

        let err = ensure_matching_history_dependencies(
            "leave",
            Some(&expected.history_view_id),
            &expected,
            &mismatched.history_view_id,
            &mismatched,
            &expected.history_view_id,
            &expected,
            &expected.history_view_id,
            &expected,
        )
        .expect_err("history commitment mismatch must fail");
        assert!(
            err.to_string()
                .contains("do not share one authenticated history commitment"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn expect_membership_event_matches_target() -> Result<()> {
        let (tx, mut rx) = mpsc::channel(8);
        let gid = [0x11; 32];
        let leaf = [0x22; 32];

        tx.send(Notification::Lag { lagged_messages: 3 }).await?;
        tx.send(Notification::Other).await?;
        tx.send(Notification::Membership {
            gid: [0xFF; 32],
            leaf_id: leaf,
            event: "join".to_string(),
            timestamp_ms: 1,
        })
        .await?;
        tx.send(Notification::Membership {
            gid,
            leaf_id: leaf,
            event: "join".to_string(),
            timestamp_ms: 2,
        })
        .await?;

        expect_membership_event(&mut rx, &gid, &leaf, "join", "membership".to_string()).await?;
        Ok(())
    }

    #[tokio::test]
    async fn expect_membership_event_errors_on_closed_channel() -> Result<()> {
        let (tx, mut rx) = mpsc::channel(1);
        drop(tx);
        let err = expect_membership_event(
            &mut rx,
            &[0u8; 32],
            &[0u8; 32],
            "join",
            "closed".to_string(),
        )
        .await
        .expect_err("closed channel should produce an error");
        assert!(err.to_string().contains("websocket channel closed"));
        Ok(())
    }

    #[tokio::test]
    async fn expect_message_event_matches_target() -> Result<()> {
        let (tx, mut rx) = mpsc::channel(8);
        let weid = [0x33; 32];
        tx.send(Notification::Lag { lagged_messages: 1 }).await?;
        tx.send(Notification::Other).await?;
        tx.send(Notification::Message {
            we_epoch_id: [0x44; 32],
            timestamp_ms: 7,
        })
        .await?;
        tx.send(Notification::Message {
            we_epoch_id: weid,
            timestamp_ms: 8,
        })
        .await?;

        expect_message_event(&mut rx, &weid, "message".to_string()).await?;
        Ok(())
    }

    #[tokio::test]
    async fn expect_message_event_errors_on_closed_channel() -> Result<()> {
        let (tx, mut rx) = mpsc::channel(1);
        drop(tx);
        let err = expect_message_event(&mut rx, &[0u8; 32], "closed".to_string())
            .await
            .expect_err("closed channel should produce an error");
        assert!(err.to_string().contains("websocket channel closed"));
        Ok(())
    }

    #[tokio::test]
    async fn send_message_burst_is_noop_for_empty_sessions() -> Result<()> {
        send_message_burst(&mut [], 3, Duration::ZERO, None).await?;
        send_message_burst(&mut [], 0, Duration::from_millis(1), None).await?;
        Ok(())
    }

    #[tokio::test]
    async fn spawn_notification_listener_rejects_unreachable_server() -> Result<()> {
        let err = spawn_notification_listener("ws://127.0.0.1:9/v1/ws", None)
            .await
            .expect_err("connecting to unreachable websocket endpoint should fail");
        assert!(err.to_string().contains("failed to connect to websocket"));
        Ok(())
    }

    #[tokio::test]
    async fn spawn_notification_listener_receives_message_notification() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let weid = [0xAB; 32];
        let weid_hex = hex::encode(weid);

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut ws = tokio_tungstenite::accept_async(stream).await?;
            ws.send(WsMessage::Text(
                format!(r#"{{"type":"message","we_epoch_id":"{weid_hex}","timestamp_ms":42}}"#)
                    .into(),
            ))
            .await?;
            ws.close(None).await?;
            Ok::<(), anyhow::Error>(())
        });

        let (mut rx, handle) =
            spawn_notification_listener(&format!("ws://{addr}/v1/ws"), None).await?;
        let event = timeout(Duration::from_secs(2), rx.recv())
            .await?
            .ok_or(anyhow!("notification channel closed unexpectedly"))?;
        let mut seen_message = false;
        if let Notification::Message {
            we_epoch_id,
            timestamp_ms,
        } = event
        {
            assert_eq!(we_epoch_id, weid);
            assert_eq!(timestamp_ms, 42);
            seen_message = true;
        }
        assert!(seen_message);

        drop(rx);
        handle.abort();
        let _ = handle.await;
        tokio::time::timeout(Duration::from_secs(1), server).await???;
        Ok(())
    }

    #[tokio::test]
    async fn spawn_notification_listener_ignores_binary_frames() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut ws = tokio_tungstenite::accept_async(stream).await?;
            ws.send(WsMessage::Binary(vec![1, 2, 3].into())).await?;
            ws.close(None).await?;
            Ok::<(), anyhow::Error>(())
        });

        let (mut rx, handle) =
            spawn_notification_listener(&format!("ws://{addr}/v1/ws"), None).await?;
        let event = timeout(Duration::from_secs(2), rx.recv()).await?;
        assert!(
            event.is_none(),
            "binary frames should not emit notifications"
        );

        handle.abort();
        let _ = handle.await;
        tokio::time::timeout(Duration::from_secs(1), server).await???;
        Ok(())
    }
}
