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
#[path = "join_leave/message_auth.rs"]
mod message_auth;
#[allow(dead_code)]
#[path = "../message_crypto.rs"]
mod message_crypto;
#[path = "join_leave/notifications.rs"]
mod notifications;
#[path = "join_leave/watch_mode.rs"]
mod watch_mode;
#[path = "../websocket_replay.rs"]
mod websocket_replay;

use anyhow::{Context, Result, anyhow};
use barrier_shared::ticket_retry_delay;
#[cfg(test)]
use barrier_shared::{
    DEFAULT_BARRIER_N_MAX, TICKET_RETRY_BASE_DELAY_MS, TICKET_RETRY_JITTER_MS,
    TICKET_RETRY_MAX_DELAY_MS, apply_join_set_to_snapshot, apply_revoked_set_to_snapshot,
    blank_internal_path_from_leaf, blank_leaf_and_path, collect_resolution_targets,
    compute_barrier_pkhash, compute_barrier_tree_hash, compute_revocation_roots_hash,
    decode_history_commitment_header, should_retry_ticket_http_error, sibling_node,
};
#[cfg(test)]
use ciborium::value::Integer;
use ciborium::value::Value;
#[cfg(test)]
use cityg_api_client::BarrierJoinRecord;
#[cfg(test)]
use cityg_api_client::RoomAdminOperation;
use cityg_api_client::{
    CitygApiClient, Error as ApiClientError, HistoryAuthorityExtension, HistoryCommitment,
    PrepareOriginMergeTicketInput, PrepareRevocationMergeTicketInput, PreparedBarrierSnapshot,
    ensure_supported_attested_current_state_extension, is_fs_forward_jump_group_http_error,
};
#[cfg(test)]
use cityg_client::demo;
use cityg_client::{
    ClientEpochBundle,
    barrier_merge_bundle::{
        BarrierMergeBundleInputs as CoreBarrierMergeBundleInputs,
        build_barrier_merge_bundle as build_barrier_merge_bundle_core,
    },
    bundle_headers::recompute_proofs_commit,
    join_bundle::{
        JoinEpochBundleInputs, build_join_epoch_bundle, parse_accepted_bundle_runtime_state,
    },
    join_runtime::generate_join_runtime_material,
};
#[cfg(test)]
use cityg_client::{
    binary::bytes32,
    bundle_headers::recompute_srx_commit,
    bundle_headers::{compute_fs_fingerprint_from_header, derive_fs_fingerprint_from_fields},
    pivot::{
        apply_pivot_alignment, hydrate_parities, select_pivot_parity,
        strip_rollup_metadata as strip_srx_and_rollup,
    },
};
use cityg_config::CityGConfig;
use futures::{SinkExt, StreamExt};
use hex::decode as hex_decode;
#[cfg(test)]
use message_auth::{
    MESSAGE_PREFIX, decode_authenticated_message, generate_message_signing_keypair,
    verify_message_signature, verify_sender_leaf_binding,
};
use message_auth::{encode_authenticated_message, sign_message};
use message_crypto::{MessageCryptoContext, encrypt_message_v2};
#[cfg(test)]
use message_crypto::{
    MsgReplayState, decrypt_message_v2_with_index, derive_msg_replay_context_id,
    derive_msg_replay_tuple_tag,
};
#[cfg(test)]
use msphf_core::serde_utils::to_cbor_vec;
use msphf_orchestrator::{ForwardSecrecyState, PivotParity, hdr};
#[cfg(test)]
use notifications::parse_hex32_field;
use notifications::{
    Notification, expect_membership_event, expect_message_event, spawn_notification_listener,
    websocket_url,
};
use pqcrypto_dilithium::dilithium5::SecretKey as MlDsaSecretKey;
#[cfg(test)]
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::sign::SecretKey as DilithiumSecretKeyTrait;
use rand::{RngExt, rng};
#[cfg(test)]
use reqwest::header::CONTENT_TYPE;
use serde::Serialize;
#[cfg(test)]
use serde_bytes::ByteBuf;
use serde_json::Value as JsonValue;
use tokio::{
    sync::mpsc,
    time::{sleep, timeout},
};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message as WsMessage};
use tracing::warn;
#[cfg(test)]
use watch_mode::fetch_and_decrypt_messages;
use watch_mode::{run_watch_mode, send_message_burst};
#[cfg(test)]
use watch_mode::{send_dummy_message, send_text_message};
use websocket_replay::{
    WebSocketReplayCursor, websocket_ack_message, websocket_lag_notice,
    websocket_notification_replayed, websocket_notification_sequence, websocket_request,
    websocket_resume_message, websocket_sync_required_notice,
};

fn random_room_id() -> String {
    let mut rng = rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    hex::encode(bytes)
}

const CLIENT_ADMIN_TOKEN_ENV: &str = "CITYG_CLIENT_ADMIN_TOKEN";
const CLIENT_MESSAGE_TOKEN_ENV: &str = "CITYG_CLIENT_MESSAGE_AUTH_TOKEN";
const MESSAGE_AUTH_HEADER: &str = "x-cityg-message-token";
const JOIN_IDENTITY_RETRY_MAX_ATTEMPTS: u32 = 8;
const LEAVE_ACCEPT_RETRY_MAX_ATTEMPTS: u32 = 2;

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

struct BarrierUpdateBuildResult {
    #[cfg(test)]
    raw_update: Vec<u8>,
    kem_tree_hash_after: [u8; 32],
    k_barrier_new: [u8; 32],
}

impl BarrierUpdateBuildResult {
    fn from_core(core: cityg_client::barrier_build::BarrierUpdateBuildResult) -> Self {
        #[cfg(test)]
        let raw_update = core.raw_update.clone();
        let cityg_client::barrier_build::BarrierUpdateBuildResult {
            kem_tree_hash_after,
            k_barrier_new,
            ..
        } = core;
        Self {
            #[cfg(test)]
            raw_update,
            kem_tree_hash_after,
            k_barrier_new: *k_barrier_new,
        }
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
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
    let gid = bytes32("gid", gid)?;
    let built = cityg_client::barrier_build::build_barrier_update_bytes(
        &gid,
        n_max,
        updater_leaf,
        barrier_version,
        prev_barrier_version,
        revocation_roots_hash,
        kem_tree_hash_before,
        snapshot_pre,
    )?;
    Ok(BarrierUpdateBuildResult::from_core(built))
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

const LEGACY_STANDALONE_DEFAULT_SERVER_URL: &str = "http://127.0.0.1:8080";

fn configured_cli_server_url() -> Option<String> {
    let config = CityGConfig::load().ok()?;
    let trimmed = config.client.default_server_url.trim();
    if trimmed.is_empty() || trimmed == LEGACY_STANDALONE_DEFAULT_SERVER_URL {
        return None;
    }
    Some(trimmed.to_string())
}

fn default_cli_server_url() -> String {
    configured_cli_server_url().unwrap_or_else(|| LEGACY_STANDALONE_DEFAULT_SERVER_URL.to_string())
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

    let server_url = server_url.unwrap_or_else(default_cli_server_url);
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
    current_history_commitment: Option<HistoryCommitment>,
    current_history_authority_extension: Option<HistoryAuthorityExtension>,
    current_global_history_attestation_bytes: Vec<u8>,
    kem_tree_hash_after: [u8; 32],
    stored_header_map: BTreeMap<u64, Value>,
    #[cfg(test)]
    msg_replay_state: MsgReplayState,
}

const EVENT_TIMEOUT: Duration = Duration::from_secs(10);
async fn prepare_join_session_with_identity(
    server_url: &str,
    room_id: &str,
    alias: &str,
    identity: cityg_api_client::RoomAdminIdentity,
) -> Result<Session> {
    let client = new_api_client(server_url);
    let pop_secret =
        Box::new(MlDsaSecretKey::from_bytes(&identity.pop_secret_key).context("invalid POP key")?);

    let identity_binding = identity
        .build_identity_binding(alias)
        .context("build identity binding")?;

    let ticket = match client
        .join_ticket_with_retry(room_id, alias, Some(identity_binding.clone()))
        .await
    {
        Ok(ticket) => ticket,
        Err(ApiClientError::HttpStatus {
            status,
            message,
            freeze_code,
            freeze_reason,
            ..
        }) => {
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
    };

    let prepared_runtime =
        cityg_api_client::prepare_runtime_join_ticket(&ticket).map_err(anyhow::Error::from)?;

    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_KBROAD_ALG, Value::Text("ml-kem-768".to_string()));
    header.insert(
        hdr::HDR_KBROAD_PUB,
        Value::Bytes(prepared_runtime.kbroad_public.clone()),
    );
    let join_runtime = generate_join_runtime_material()?;
    header.insert(
        hdr::HDR_BARRIER_LEAF_PK,
        Value::Bytes(join_runtime.barrier_leaf_public_key),
    );
    // Keep the private leaf key material local (future recover path).
    let _barrier_leaf_dk = join_runtime.barrier_leaf_secret_key;

    let mut fs_state = join_runtime.forward_state;
    let vrf_secret_key = join_runtime.vrf_secret_key;
    let vrf_public_key = join_runtime.vrf_public_key;

    let prepared_orchestration = prepared_runtime.prepare_barrier_orchestration(
        identity.pop_public_key.as_slice(),
        pop_secret.as_ref(),
        vrf_secret_key.as_slice(),
        vrf_public_key.as_slice(),
    );
    let witness_bytes = prepared_runtime.witness_bytes.as_deref();

    let build_join_bundle = |fs_state: &mut ForwardSecrecyState,
                             disable_autonomic_evolve: bool|
     -> Result<ClientEpochBundle> {
        build_join_epoch_bundle(JoinEpochBundleInputs {
            header: header.clone(),
            parts: prepared_orchestration.parts.clone(),
            params: prepared_orchestration.params.clone(),
            fs_state,
            witness_bytes,
            disable_autonomic_evolve,
        })
        .context("generate join bundle")
    };

    let pristine_fs_state = fs_state.clone();
    let mut bundle = build_join_bundle(&mut fs_state, false)?;

    if prepared_runtime.parent_root == [0u8; 32] && !prepared_runtime.bootstrap_public.is_empty() {
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

    let accepted_bundle = parse_accepted_bundle_runtime_state(
        &stored,
        prepared_runtime.fs_policy_version.as_str(),
        prepared_runtime.fs_epoch_base_ts,
    )?;
    let accepted_fs_dev_prev_commit = accepted_bundle
        .fs_dev_prev_commit
        .ok_or_else(|| anyhow!("accepted join bundle missing fs_dev commit"))?;
    ensure_supported_attested_current_state_extension(
        "join ticket",
        prepared_runtime.current_history_authority_extension,
        prepared_runtime
            .current_global_history_attestation_bytes
            .as_slice(),
    )?;
    let session = Session {
        server_url: server_url.to_string(),
        room_id: room_id.to_string(),
        gid: prepared_runtime.gid,
        leaf_id: prepared_runtime.leaf_id,
        xk_hash: bundle.hp_binding.xk_hash,
        epoch_key: bundle.epoch_key,
        barrier_version: prepared_runtime.barrier_version,
        k_barrier: [0u8; 32],
        pop_public_key: identity.pop_public_key,
        pop_secret,
        vrf_secret_key,
        vrf_public_key,
        forward_state: fs_state,
        fs_ec: accepted_bundle.fs_ec,
        fs_epoch_commit: accepted_bundle.fs_epoch_commit,
        fs_dev_prev_commit: accepted_fs_dev_prev_commit,
        we_epoch_id: bundle.we_epoch_id,
        anchor_hdr_ctx: accepted_bundle.anchor_hdr_ctx,
        seed_ctx_hash: accepted_bundle.seed_ctx_hash,
        seed_commit: accepted_bundle.seed_commit,
        seed_bundle_commit: accepted_bundle.seed_bundle_commit,
        fs_fingerprint: accepted_bundle.fs_fingerprint,
        join_finalize_auth_token: prepared_runtime.join_finalize_auth_token,
        current_history_commitment: prepared_runtime.current_history_commitment,
        current_history_authority_extension: prepared_runtime.current_history_authority_extension,
        current_global_history_attestation_bytes: prepared_runtime
            .current_global_history_attestation_bytes,
        kem_tree_hash_after: prepared_runtime.kem_tree_hash_after,
        stored_header_map: stored.header_map.clone(),
        #[cfg(test)]
        msg_replay_state: MsgReplayState::default(),
    };
    Ok(session)
}

async fn prepare_join_session(server_url: &str, room_id: &str, alias: &str) -> Result<Session> {
    let identity = cityg_api_client::generate_room_admin_identity();
    prepare_join_session_with_identity(server_url, room_id, alias, identity).await
}

fn is_cover_leaf_index_collision_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .to_string()
            .contains("cover leaf index already allocated")
    })
}

async fn perform_join(server_url: &str, room_id: &str, alias: &str) -> Result<Session> {
    let mut retry_attempt = 0u32;
    loop {
        let session = match prepare_join_session(server_url, room_id, alias).await {
            Ok(session) => session,
            Err(err)
                if is_cover_leaf_index_collision_error(&err)
                    && retry_attempt < JOIN_IDENTITY_RETRY_MAX_ATTEMPTS =>
            {
                retry_attempt = retry_attempt.saturating_add(1);
                warn!(
                    attempt = retry_attempt,
                    "join identity collided on cover leaf index; regenerating identity"
                );
                continue;
            }
            Err(err) => return Err(err),
        };
        match perform_join_finalize(session).await {
            Ok(session) => return Ok(session),
            Err(err)
                if is_cover_leaf_index_collision_error(&err)
                    && retry_attempt < JOIN_IDENTITY_RETRY_MAX_ATTEMPTS =>
            {
                retry_attempt = retry_attempt.saturating_add(1);
                warn!(
                    attempt = retry_attempt,
                    "join finalize collided on cover leaf index; regenerating identity"
                );
            }
            Err(err) => return Err(err),
        }
    }
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
        cityg_api_client::RoomAdminIdentity::from_slices(pop_public_key, pop_secret_key),
    )
    .await?;
    perform_join_finalize(session).await
}

async fn perform_join_finalize(mut session: Session) -> Result<Session> {
    let client = new_api_client(&session.server_url);
    let mut forward_state = session.forward_state.clone();
    let ticket = client
        .merge_ticket_refresh_with_retry(&session.room_id, &session.leaf_id)
        .await
        .context("fetch merge ticket for join finalize")?;
    let prepared_runtime = ticket
        .prepare_origin_runtime(PrepareOriginMergeTicketInput {
            operation_label: "join finalize",
            local_barrier_version: session.barrier_version,
            local_kem_tree_hash_after: session.kem_tree_hash_after,
            local_current_history_commitment: session.current_history_commitment.as_ref(),
            local_current_history_authority_extension: session.current_history_authority_extension,
            fs_ec: session.fs_ec,
            fs_epoch_commit: session.fs_epoch_commit,
            fs_dev_prev_commit: session.fs_dev_prev_commit,
            stored_max_barrier_update_bytes: 0,
            join_finalize_auth_token: Some(session.join_finalize_auth_token),
        })
        .map_err(anyhow::Error::from)?;
    if session.join_finalize_auth_token == [0u8; 32] {
        return Err(anyhow!(
            "join finalize requires a non-zero server-issued join_finalize_auth_token"
        ));
    }
    let snapshot_request = prepared_runtime.snapshot_preparation_request(
        &session.room_id,
        &session.gid,
        &session.leaf_id,
        session.pop_secret.as_bytes(),
        2,
        "join finalize",
    );

    let PreparedBarrierSnapshot {
        header,
        cat,
        parent_root: parent_root_arr,
        join_delta_root: _join_delta_root_arr,
        revoked_since_root: _revoked_since_root_arr,
        revoked_root: _revoked_root_arr,
        tswe_salt_hash: _tswe_salt_hash_arr,
        pox_r_commit: _pox_r_commit,
        pivot,
        snapshot_hash: _prepared_snapshot_hash,
        committed_revocation_roots_hash: _prepared_committed_revocation_roots_hash,
        revocation_roots_hash: _prepared_revocation_roots_hash,
        barrier_update,
    } = client
        .barrier_prepare_snapshot(snapshot_request)
        .await
        .context("prepare join finalize barrier snapshot")?;
    let next_barrier_version = prepared_runtime.barrier_version.saturating_add(1);
    let barrier_update = BarrierUpdateBuildResult::from_core(barrier_update);
    let prepared_orchestration = prepared_runtime.prepare_barrier_orchestration(
        &session.gid,
        session.pop_public_key.as_slice(),
        session.pop_secret.as_ref(),
        session.vrf_secret_key.as_slice(),
        session.vrf_public_key.as_slice(),
        session.fs_ec,
        session.fs_epoch_commit,
        session.fs_dev_prev_commit,
        next_barrier_version,
    );

    let build_join_finalize_bundle =
        |forward_state: ForwardSecrecyState,
         disable_autonomic_evolve: bool|
         -> Result<cityg_client::barrier_merge_bundle::PreparedBarrierMergeBundle> {
            build_barrier_merge_bundle_core(CoreBarrierMergeBundleInputs {
                header: header.clone(),
                parts: prepared_orchestration.parts.clone(),
                params: prepared_orchestration.params.clone(),
                forward_state,
                parities: &prepared_runtime.parities,
                witness_bytes: prepared_runtime.witness_bytes.as_deref(),
                pivot: &pivot,
                gid: &session.gid,
                cat: &cat,
                parent_root: &parent_root_arr,
                current_k_fs: None,
                next_barrier_version,
                barrier_key: &barrier_update.k_barrier_new,
                barrier_update_reason: 2,
                disable_autonomic_evolve,
            })
            .context("generate join finalize bundle")
        };

    let pristine_forward_state = forward_state.clone();
    let built = build_join_finalize_bundle(forward_state, false)?;
    let mut bundle = built.bundle;
    let pristine_bundle = built.pristine_bundle;
    forward_state = built.forward_state_after;

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
            let rebuilt = build_join_finalize_bundle(forward_state, true)?;
            bundle = rebuilt.bundle;
            forward_state = rebuilt.forward_state_after;
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

    let accepted_bundle = parse_accepted_bundle_runtime_state(
        &bundle,
        prepared_runtime.fs_policy_version.as_str(),
        prepared_runtime.fs_epoch_base_ts,
    )?;
    let accepted_fs_dev_prev_commit = accepted_bundle
        .fs_dev_prev_commit
        .ok_or_else(|| anyhow!("accepted bundle missing fs_dev commit"))?;

    forward_state.set_last_we_epoch_id(bundle.we_epoch_id);
    forward_state.set_epoch_base_ts(accepted_bundle.fs_epoch_base_ts);
    session.forward_state = forward_state;
    session.fs_ec = accepted_bundle.fs_ec;
    session.fs_epoch_commit = accepted_bundle.fs_epoch_commit;
    session.fs_dev_prev_commit = accepted_fs_dev_prev_commit;
    session.we_epoch_id = bundle.we_epoch_id;
    session.xk_hash = bundle.hp_binding.xk_hash;
    session.epoch_key = bundle.epoch_key;
    session.barrier_version = next_barrier_version;
    session
        .k_barrier
        .copy_from_slice(barrier_update.k_barrier_new.as_ref());
    session.kem_tree_hash_after = barrier_update.kem_tree_hash_after;
    session.anchor_hdr_ctx = accepted_bundle.anchor_hdr_ctx;
    session.seed_ctx_hash = accepted_bundle.seed_ctx_hash;
    session.seed_commit = accepted_bundle.seed_commit;
    session.seed_bundle_commit = accepted_bundle.seed_bundle_commit;
    session.join_finalize_auth_token = [0u8; 32];
    session.current_history_commitment = None;
    session.current_history_authority_extension = None;
    session.current_global_history_attestation_bytes.clear();
    session.fs_fingerprint = accepted_bundle.fs_fingerprint;
    session.stored_header_map = bundle.header_map.clone();
    Ok(session)
}

async fn perform_leave(session: &Session, verbose: bool) -> Result<()> {
    let client = new_api_client(&session.server_url);
    let mut accept_retry_attempt = 0u32;
    loop {
        let mut forward_state = session.forward_state.clone();
        let ticket = client
            .merge_ticket_with_retry(&session.room_id, &session.leaf_id)
            .await
            .context("fetch merge ticket")?;
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

        let prepared_runtime = ticket
            .prepare_revocation_runtime(PrepareRevocationMergeTicketInput {
                operation_label: "leave",
                local_barrier_version: session.barrier_version,
                local_kem_tree_hash_after: session.kem_tree_hash_after,
                local_current_history_commitment: session.current_history_commitment.as_ref(),
                local_current_history_authority_extension: session
                    .current_history_authority_extension,
                fs_ec: current_fs_ec,
                fs_epoch_commit: current_fs_epoch_commit,
                fs_dev_prev_commit: current_fs_dev_prev_commit,
                stored_max_barrier_update_bytes: 0,
            })
            .map_err(anyhow::Error::from)?;
        let snapshot_request = prepared_runtime.snapshot_preparation_request(
            &session.room_id,
            &session.gid,
            &session.leaf_id,
            session.pop_secret.as_bytes(),
            Some(session.leaf_id),
            0,
            "leave",
        );

        if verbose {
            for (idx, parity) in prepared_runtime.parities.iter().enumerate() {
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

        let PreparedBarrierSnapshot {
            header,
            cat,
            parent_root: parent_root_arr,
            join_delta_root: _join_delta_root_arr,
            revoked_since_root: _revoked_since_root_arr,
            revoked_root: _revoked_root_arr,
            tswe_salt_hash: _tswe_salt_hash_arr,
            pox_r_commit: _pox_r_commit,
            pivot,
            snapshot_hash: _prepared_snapshot_hash,
            committed_revocation_roots_hash: _prepared_committed_revocation_roots_hash,
            revocation_roots_hash: _prepared_revocation_roots_hash,
            barrier_update,
        } = client
            .barrier_prepare_snapshot(snapshot_request)
            .await
            .context("prepare leave barrier snapshot")?;
        let next_barrier_version = prepared_runtime.barrier_version.saturating_add(1);
        let barrier_update = BarrierUpdateBuildResult::from_core(barrier_update);

        let prepared_orchestration = prepared_runtime.prepare_barrier_orchestration(
            &session.gid,
            session.pop_public_key.as_slice(),
            session.pop_secret.as_ref(),
            session.vrf_secret_key.as_slice(),
            session.vrf_public_key.as_slice(),
            current_fs_ec,
            current_fs_epoch_commit,
            current_fs_dev_prev_commit,
            next_barrier_version,
        );

        let built = build_barrier_merge_bundle_core(CoreBarrierMergeBundleInputs {
            header,
            parts: prepared_orchestration.parts,
            params: prepared_orchestration.params,
            forward_state,
            parities: &prepared_runtime.parities,
            witness_bytes: prepared_runtime.witness_bytes.as_deref(),
            pivot: &pivot,
            gid: &session.gid,
            cat: &cat,
            parent_root: &parent_root_arr,
            current_k_fs: None,
            next_barrier_version,
            barrier_key: &barrier_update.k_barrier_new,
            barrier_update_reason: 0,
            disable_autonomic_evolve: false,
        })
        .context("generate merge bundle")?;
        let mut bundle = built.bundle;
        let pristine_bundle = built.pristine_bundle;
        forward_state = built.forward_state_after;
        let computed_anchor_ctx = bundle.anchor.anchor_hdr_ctx.clone();
        let seed_ctx_hash = bundle.hp_binding.seed_ctx_hash;
        let seed_commit = bundle.hp_binding.seed_commit;
        let seed_bundle_commit = bundle.hp_binding.seed_bundle_commit;

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
            log_fs_metadata(&pivot, &bundle.header_map);
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
            Ok(_) => return Ok(()),
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
                return Ok(());
            }
            Err(ApiClientError::HttpStatus {
                status,
                message,
                freeze_code,
                freeze_reason,
                ..
            }) if should_retry_leave_accept_http_error(
                status.as_u16(),
                &message,
                freeze_code,
                freeze_reason.as_deref(),
            ) && accept_retry_attempt < LEAVE_ACCEPT_RETRY_MAX_ATTEMPTS =>
            {
                let delay = ticket_retry_delay(accept_retry_attempt);
                accept_retry_attempt = accept_retry_attempt.saturating_add(1);
                warn!(
                    attempt = accept_retry_attempt,
                    delay_ms = delay.as_millis() as u64,
                    status = status.as_u16(),
                    message = %message,
                    freeze_code = ?freeze_code,
                    freeze_reason = freeze_reason.as_deref().unwrap_or(""),
                    "leave accept rejected by stale checkpoint guard; refetching merge ticket"
                );
                sleep(delay).await;
                continue;
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
    }
}

fn extract_bytes(header: &BTreeMap<u64, Value>, key: u64) -> Result<Vec<u8>> {
    match header.get(&key) {
        Some(Value::Bytes(bytes)) => Ok(bytes.clone()),
        Some(_) => Err(anyhow!("header key {key} is not raw bytes")),
        None => Err(anyhow!("header missing key {key}")),
    }
}

#[cfg(test)]
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

fn should_retry_leave_accept_http_error(
    status: u16,
    message: &str,
    freeze_code: Option<u32>,
    freeze_reason: Option<&str>,
) -> bool {
    let retryable_freeze = matches!(freeze_code, Some(9471 | 9473))
        || matches!(
            freeze_reason,
            Some("fs_checkpoint_backdate" | "fs_checkpoint_monotonicity")
        )
        || message.contains("fs_checkpoint_backdate")
        || message.contains("fs_checkpoint_monotonicity");
    retryable_freeze && (status == 409 || status >= 500)
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

#[cfg(test)]
#[allow(
    dead_code,
    clippy::clone_on_copy,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used
)]
mod tests {
    use super::*;
    use axum::{
        Router,
        extract::State,
        http::{StatusCode as HttpStatusCode, Uri, header},
        response::{IntoResponse, Response},
        routing::{get, post},
    };
    use cityg_client::vrf::generate_vrf_keys;
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

    struct EnvVarGuard {
        key: &'static str,
        original: Option<String>,
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match self.original.as_deref() {
                Some(value) => {
                    unsafe { std::env::set_var(self.key, value) };
                }
                None => {
                    unsafe { std::env::remove_var(self.key) };
                }
            }
        }
    }

    fn set_env_guard(key: &'static str, value: &str) -> EnvVarGuard {
        let original = std::env::var(key).ok();
        unsafe { std::env::set_var(key, value) };
        EnvVarGuard { key, original }
    }

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
        let identity = cityg_api_client::generate_room_admin_identity();
        let pop_sk = MlDsaSecretKey::from_bytes(&identity.pop_secret_key).expect("valid POP key");
        Session {
            server_url: server_url.to_string(),
            room_id: hex::encode([0xAA; 32]),
            gid: [0x11; 32],
            leaf_id: [0x22; 32],
            xk_hash: [0x23; 32],
            epoch_key: [0x24; 32],
            barrier_version: 1,
            k_barrier: [0x25; 32],
            pop_public_key: identity.pop_public_key,
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
            current_history_commitment: Some(sample_history_commitment()),
            current_history_authority_extension: None,
            current_global_history_attestation_bytes: Vec::new(),
            kem_tree_hash_after: [0xCF; 32],
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
        let identity = cityg_api_client::generate_room_admin_identity();
        let admin_proof = identity.build_kbroad_proof(
            RoomAdminOperation::Bootstrap,
            room_id,
            demo::kbroad_public(),
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
            deployment_profile_manifest_bytes: Vec::new(),
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
        #[prost(bytes = "vec", tag = "36")]
        deployment_profile_manifest: Vec<u8>,
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
    struct BarrierResolveJoinsSinceRequestPb {
        #[prost(string, tag = "1")]
        room_id: String,
        #[prost(uint64, tag = "2")]
        prev_barrier_version: u64,
        #[prost(uint32, tag = "3")]
        page_offset: u32,
        #[prost(uint32, tag = "4")]
        max_entries: u32,
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
        #[prost(bytes = "vec", tag = "7")]
        helper_completeness_attestation: Vec<u8>,
        #[prost(bytes = "vec", tag = "8")]
        history_authority_descriptor: Vec<u8>,
        #[prost(bytes = "vec", tag = "9")]
        global_history_attestation: Vec<u8>,
        #[prost(string, tag = "10")]
        history_authority_extension: String,
        #[prost(string, tag = "11")]
        profile_version: String,
        #[prost(uint64, tag = "12")]
        n_max: u64,
        #[prost(uint64, tag = "13")]
        max_barrier_update_bytes: u64,
        #[prost(message, optional, tag = "14")]
        fs_forward_leap_policy: Option<FsForwardLeapPolicyPb>,
        #[prost(bytes = "vec", tag = "15")]
        deployment_profile_manifest: Vec<u8>,
    }

    #[derive(Clone, PartialEq, Message)]
    struct BarrierResolveRevokedLeavesRequestPb {
        #[prost(string, tag = "1")]
        room_id: String,
        #[prost(bytes = "vec", tag = "2")]
        revocation_roots_hash: Vec<u8>,
        #[prost(uint32, tag = "3")]
        page_offset: u32,
        #[prost(uint32, tag = "4")]
        max_entries: u32,
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
        #[prost(bytes = "vec", tag = "9")]
        helper_completeness_attestation: Vec<u8>,
        #[prost(bytes = "vec", tag = "10")]
        history_authority_descriptor: Vec<u8>,
        #[prost(bytes = "vec", tag = "11")]
        global_history_attestation: Vec<u8>,
        #[prost(string, tag = "12")]
        history_authority_extension: String,
        #[prost(string, tag = "13")]
        profile_version: String,
        #[prost(uint64, tag = "14")]
        max_barrier_update_bytes: u64,
        #[prost(message, optional, tag = "15")]
        fs_forward_leap_policy: Option<FsForwardLeapPolicyPb>,
        #[prost(bytes = "vec", tag = "16")]
        deployment_profile_manifest: Vec<u8>,
    }

    #[derive(Clone, PartialEq, Message)]
    struct BarrierFetchPublicTreeRequestPb {
        #[prost(string, tag = "1")]
        room_id: String,
        #[prost(bytes = "vec", tag = "2")]
        kem_tree_hash_after: Vec<u8>,
        #[prost(uint32, tag = "3")]
        entry_offset: u32,
        #[prost(uint32, tag = "4")]
        max_entries: u32,
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

    fn proto_bytes_responses(raw_pages: &[Vec<u8>]) -> Vec<MockResponse> {
        raw_pages
            .iter()
            .cloned()
            .map(MockResponse::proto_bytes)
            .collect()
    }

    async fn post_proto_raw<T: Message>(
        server_url: &str,
        path: &str,
        request: &T,
    ) -> Result<Vec<u8>> {
        let mut req = reqwest::Client::new()
            .post(format!("{server_url}{path}"))
            .header(CONTENT_TYPE, "application/x-protobuf")
            .body(request.encode_to_vec());
        if let Some(token) = configured_client_message_token() {
            req = req.header(MESSAGE_AUTH_HEADER, token);
        }
        let response = req.send().await.context("send raw protobuf request")?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .context("read raw protobuf response")?;
        if !status.is_success() {
            return Err(anyhow!(
                "raw protobuf request failed ({status}): {}",
                String::from_utf8_lossy(body.as_ref())
            ));
        }
        Ok(body.to_vec())
    }

    async fn capture_fetch_public_tree_pages_raw(
        server_url: &str,
        room_id: &str,
        kem_tree_hash_after: &[u8; 32],
    ) -> Result<Vec<Vec<u8>>> {
        let mut entry_offset = 0u32;
        let mut pages = Vec::new();
        loop {
            let request = BarrierFetchPublicTreeRequestPb {
                room_id: room_id.to_string(),
                kem_tree_hash_after: kem_tree_hash_after.to_vec(),
                entry_offset,
                max_entries: 512,
            };
            let raw = post_proto_raw(server_url, "/v1/barrier/fetch_public_tree", &request).await?;
            let decoded = BarrierFetchPublicTreeResponsePb::decode(raw.as_slice())
                .context("decode fetch_public_tree mock page")?;
            let next = decoded.next_entry_offset;
            pages.push(raw);
            match next {
                Some(offset) => entry_offset = offset,
                None => break,
            }
        }
        Ok(pages)
    }

    async fn capture_resolve_joins_since_pages_raw(
        server_url: &str,
        room_id: &str,
        prev_barrier_version: u64,
    ) -> Result<Vec<Vec<u8>>> {
        let mut page_offset = 0u32;
        let mut pages = Vec::new();
        loop {
            let request = BarrierResolveJoinsSinceRequestPb {
                room_id: room_id.to_string(),
                prev_barrier_version,
                page_offset,
                max_entries: 512,
            };
            let raw =
                post_proto_raw(server_url, "/v1/barrier/resolve_joins_since", &request).await?;
            let decoded = BarrierResolveJoinsSinceResponsePb::decode(raw.as_slice())
                .context("decode resolve_joins_since mock page")?;
            let next = decoded.next_page_offset;
            pages.push(raw);
            match next {
                Some(offset) => page_offset = offset,
                None => break,
            }
        }
        Ok(pages)
    }

    async fn capture_resolve_revoked_pages_raw(
        server_url: &str,
        room_id: &str,
        revocation_roots_hash: &[u8; 32],
    ) -> Result<Vec<Vec<u8>>> {
        let mut page_offset = 0u32;
        let mut pages = Vec::new();
        loop {
            let request = BarrierResolveRevokedLeavesRequestPb {
                room_id: room_id.to_string(),
                revocation_roots_hash: revocation_roots_hash.to_vec(),
                page_offset,
                max_entries: 512,
            };
            let raw =
                post_proto_raw(server_url, "/v1/barrier/resolve_revoked_leaves", &request).await?;
            let decoded = BarrierResolveRevokedLeavesResponsePb::decode(raw.as_slice())
                .context("decode resolve_revoked_leaves mock page")?;
            let next = decoded.next_page_offset;
            pages.push(raw);
            match next {
                Some(offset) => page_offset = offset,
                None => break,
            }
        }
        Ok(pages)
    }

    #[derive(Clone, Default)]
    struct LeaveMockState {
        responses: Arc<Mutex<BTreeMap<String, VecDeque<MockResponse>>>>,
        counts: Arc<Mutex<BTreeMap<String, usize>>>,
        witness_proxy_base_url: Option<String>,
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
                witness_proxy_base_url: None,
            }
        }

        fn with_witness_proxy(mut self, base_url: String) -> Self {
            self.witness_proxy_base_url = Some(base_url);
            self
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

    async fn post_proto_bytes_raw(server_url: &str, path: &str, body: &[u8]) -> Result<Vec<u8>> {
        let mut req = reqwest::Client::new()
            .post(format!("{server_url}{path}"))
            .header(CONTENT_TYPE, "application/x-protobuf")
            .body(body.to_vec());
        if let Some(token) = configured_client_message_token() {
            req = req.header(MESSAGE_AUTH_HEADER, token);
        }
        let response = req
            .send()
            .await
            .context("send raw protobuf bytes request")?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .context("read raw protobuf bytes response")?;
        if !status.is_success() {
            return Err(anyhow!(
                "raw protobuf bytes request failed ({status}): {}",
                String::from_utf8_lossy(body.as_ref())
            ));
        }
        Ok(body.to_vec())
    }

    async fn mock_leave_post(
        State(state): State<LeaveMockState>,
        uri: Uri,
        body: axum::body::Bytes,
    ) -> Response {
        if uri.path() == "/v1/barrier/issue_full_verification_witness"
            && let Some(base_url) = state.witness_proxy_base_url.as_deref()
        {
            match post_proto_bytes_raw(base_url, uri.path(), body.as_ref()).await {
                Ok(raw) => return MockResponse::proto_bytes(raw).into_response(),
                Err(err) => {
                    warn!("witness proxy failed: {err}");
                    return MockResponse::json(
                        HttpStatusCode::INTERNAL_SERVER_ERROR,
                        "witness proxy failed",
                        None,
                        None,
                    )
                    .into_response();
                }
            }
        }
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
        barrier_tree_snapshot_pages_raw: Vec<Vec<u8>>,
        join_records_pages_raw: Vec<Vec<u8>>,
        revoked_leaf_indices_pages_raw: Vec<Vec<u8>>,
    }

    struct JoinFinalizeFixture {
        session: Session,
        ticket: cityg_api_client::MergeTicket,
        barrier_tree_snapshot: cityg_api_client::BarrierPublicTree,
        join_records: Vec<BarrierJoinRecord>,
        revoked_leaf_indices: Vec<u32>,
        barrier_tree_snapshot_pages_raw: Vec<Vec<u8>>,
        join_records_pages_raw: Vec<Vec<u8>>,
        revoked_leaf_indices_pages_raw: Vec<Vec<u8>>,
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

    async fn capture_leave_fixture_with_server()
    -> Result<(LeaveFixture, String, tokio::task::JoinHandle<()>)> {
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
        let barrier_tree_snapshot_pages_raw =
            capture_fetch_public_tree_pages_raw(&server_url, &room_id, &ticket.kem_tree_hash_after)
                .await?;
        let join_records = client
            .barrier_resolve_joins_since(&room_id, ticket.barrier_version)
            .await?
            .records;
        let join_records_pages_raw =
            capture_resolve_joins_since_pages_raw(&server_url, &room_id, ticket.barrier_version)
                .await?;
        let revoked_leaf_indices = client
            .barrier_resolve_revoked_leaves(&room_id, &committed_revocation_roots_hash)
            .await?
            .leaf_indices;
        let revoked_leaf_indices_pages_raw = capture_resolve_revoked_pages_raw(
            &server_url,
            &room_id,
            &committed_revocation_roots_hash,
        )
        .await?;
        Ok((
            LeaveFixture {
                session,
                ticket,
                barrier_tree_snapshot,
                join_records,
                revoked_leaf_indices,
                barrier_tree_snapshot_pages_raw,
                join_records_pages_raw,
                revoked_leaf_indices_pages_raw,
            },
            server_url,
            handle,
        ))
    }

    async fn capture_leave_fixture() -> Result<LeaveFixture> {
        let (fixture, _server_url, handle) = capture_leave_fixture_with_server().await?;
        handle.abort();
        let _ = handle.await;
        Ok(fixture)
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
        let barrier_tree_snapshot_pages_raw =
            capture_fetch_public_tree_pages_raw(&server_url, &room_id, &ticket.kem_tree_hash_after)
                .await?;
        let join_records = client
            .barrier_resolve_joins_since(&room_id, ticket.barrier_version)
            .await?
            .records;
        let join_records_pages_raw =
            capture_resolve_joins_since_pages_raw(&server_url, &room_id, ticket.barrier_version)
                .await?;
        let revoked_leaf_indices = client
            .barrier_resolve_revoked_leaves(&room_id, &committed_revocation_roots_hash)
            .await?
            .leaf_indices;
        let revoked_leaf_indices_pages_raw = capture_resolve_revoked_pages_raw(
            &server_url,
            &room_id,
            &committed_revocation_roots_hash,
        )
        .await?;

        handle.abort();
        let _ = handle.await;

        Ok(JoinFinalizeFixture {
            session,
            ticket,
            barrier_tree_snapshot,
            join_records,
            revoked_leaf_indices,
            barrier_tree_snapshot_pages_raw,
            join_records_pages_raw,
            revoked_leaf_indices_pages_raw,
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
            deployment_profile_manifest: ticket.deployment_profile_manifest_bytes.clone(),
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
        ticket: &cityg_api_client::MergeTicket,
        entry_offset: u32,
        next_entry_offset: Option<u32>,
        pk_entries: Vec<Vec<u8>>,
    ) -> Vec<u8> {
        let total_entries = u32::try_from(tree.pk_entries.len()).expect("tree entries fit in u32");
        BarrierFetchPublicTreeResponsePb {
            n_max: tree.n_max,
            kem_tree_hash_after: tree.kem_tree_hash_after.to_vec(),
            pk_entries,
            history_view_id: ticket.current_history_commitment.history_view_id.to_vec(),
            history_commitment: Some(encode_history_commitment(
                &ticket.current_history_commitment,
            )),
            entry_offset,
            next_entry_offset,
            total_entries,
            helper_completeness_attestation: Vec::new(),
            history_authority_descriptor: ticket.history_authority_descriptor_bytes.clone(),
            global_history_attestation: ticket.current_global_history_attestation_bytes.clone(),
            history_authority_extension: ticket
                .history_authority_extension
                .map(|extension| extension.as_str().to_string())
                .unwrap_or_default(),
            profile_version: "v0.1.4".to_string(),
            max_barrier_update_bytes: ticket.max_barrier_update_bytes,
            fs_forward_leap_policy: Some(FsForwardLeapPolicyPb {
                h: ticket.fs_forward_leap_policy.h,
                checkpoint_interval: ticket.fs_forward_leap_policy.checkpoint_interval,
                slack_anchor: ticket.fs_forward_leap_policy.slack_anchor,
                slack_first_device: ticket.fs_forward_leap_policy.slack_first_device,
                slack_device: ticket.fs_forward_leap_policy.slack_device,
            }),
            deployment_profile_manifest: ticket.deployment_profile_manifest_bytes.clone(),
        }
        .encode_to_vec()
    }

    fn encode_barrier_tree_snapshot_pages(
        tree: &cityg_api_client::BarrierPublicTree,
        ticket: &cityg_api_client::MergeTicket,
    ) -> Vec<MockResponse> {
        const MOCK_BARRIER_HELPER_PAGE_LIMIT: usize = 512;

        let total_entries = tree.pk_entries.len();
        if total_entries <= MOCK_BARRIER_HELPER_PAGE_LIMIT {
            return vec![MockResponse::proto_bytes(encode_barrier_tree_snapshot(
                tree,
                ticket,
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
                ticket,
                u32::try_from(offset).expect("paginated tree entry offset fits in u32"),
                next_entry_offset,
                tree.pk_entries[offset..end].to_vec(),
            )));
            offset = end;
        }
        responses
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
    fn join_collision_classifier_detects_nested_cover_leaf_errors() {
        let err = anyhow!("server error (500): invalid input: cover leaf index already allocated");
        assert!(is_cover_leaf_index_collision_error(&err));

        let wrapped = err.context("server rejected join bundle");
        assert!(is_cover_leaf_index_collision_error(&wrapped));

        let unrelated = anyhow!("server error (500): invalid input: kbroad key missing");
        assert!(!is_cover_leaf_index_collision_error(&unrelated));
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
        let (public_key, secret_key) = generate_message_signing_keypair();
        let signature = sign_message(&leaf_id, timestamp_ms, plaintext, &secret_key)?;
        let encoded = encode_authenticated_message(
            timestamp_ms,
            plaintext,
            &public_key,
            signature.as_slice(),
        );
        let decoded = decode_authenticated_message(encoded.as_slice())?;
        assert_eq!(decoded.timestamp_ms, timestamp_ms);
        assert_eq!(decoded.plaintext, plaintext);
        assert_eq!(decoded.public_key, public_key.as_slice());
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
        let public_key_len = public_key.len();
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
                &public_key,
            )
            .is_err()
        );
        assert!(
            verify_message_signature(
                &leaf_id,
                timestamp_ms,
                plaintext,
                &signature[..signature.len() - 1],
                &public_key,
            )
            .is_err()
        );
        assert!(
            verify_message_signature(
                &leaf_id,
                timestamp_ms,
                plaintext,
                signature.as_slice(),
                &public_key[..8],
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn parse_cli_args_defaults_and_flags() -> Result<()> {
        let opts = parse_cli_args(vec!["--batch".to_string(), "--count=2".to_string()])?;
        assert_eq!(opts.server_url, LEGACY_STANDALONE_DEFAULT_SERVER_URL);
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
    fn parse_cli_args_prefers_configured_worker_server_default() -> Result<()> {
        let _server_guard = set_env_guard(
            "CITYG_CLIENT_DEFAULT_SERVER_URL",
            "https://cityg.example.workers.dev",
        );
        let opts = parse_cli_args(Vec::<String>::new())?;
        assert_eq!(opts.server_url, "https://cityg.example.workers.dev");
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
            "sequence": 7u64,
            "replayed": true,
            "timestamp_ms": 42u64
        });
        let membership = serde_json::json!({
            "type": "membership",
            "gid": hex::encode(gid),
            "leaf_id": hex::encode(leaf_id),
            "event": "join",
            "sequence": 9u64,
            "replayed": true,
            "timestamp_ms": 99u64
        });

        let parsed_message = Notification::from_json(&message);
        assert!(matches!(parsed_message, Some(Notification::Message { .. })));
        if let Some(Notification::Message {
            we_epoch_id,
            sequence,
            replayed,
            timestamp_ms,
        }) = parsed_message
        {
            assert_eq!(we_epoch_id, weid);
            assert_eq!(sequence, Some(7));
            assert!(replayed);
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
            sequence,
            replayed,
            timestamp_ms,
        }) = parsed_membership
        {
            assert_eq!(parsed_gid, gid);
            assert_eq!(parsed_leaf, leaf_id);
            assert_eq!(event, "join");
            assert_eq!(sequence, Some(9));
            assert!(replayed);
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
    fn notification_from_json_parses_lag_sync_required_and_other() {
        let lag = serde_json::json!({
            "type": "lag",
            "lagged_messages": 17u64
        });
        let sync_required = serde_json::json!({
            "type": "sync_required",
            "lagged_messages": 23u64
            ,
            "reason": "replay_window_exhausted",
            "action": "refetch_and_reconnect",
            "reconcile_via": "http",
            "sequence": 44u64,
            "retained_from_sequence": 31u64,
            "server_time_ms": 99u64
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

        let parsed_disconnect = Notification::from_json(&sync_required);
        assert!(matches!(
            parsed_disconnect,
            Some(Notification::SyncRequired { .. })
        ));
        if let Some(Notification::SyncRequired {
            lagged_messages,
            sequence,
            timestamp_ms,
            retained_from_sequence,
            reason,
            action,
            reconcile_via,
        }) = parsed_disconnect
        {
            assert_eq!(lagged_messages, 23);
            assert_eq!(sequence, Some(44));
            assert_eq!(timestamp_ms, Some(99));
            assert_eq!(retained_from_sequence, Some(31));
            assert_eq!(reason.as_deref(), Some("replay_window_exhausted"));
            assert_eq!(action.as_deref(), Some("refetch_and_reconnect"));
            assert_eq!(reconcile_via.as_deref(), Some("http"));
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
        let identity = cityg_api_client::generate_room_admin_identity();
        let sk = MlDsaSecretKey::from_bytes(&identity.pop_secret_key).expect("valid POP key");
        let session = Session {
            server_url: "http://127.0.0.1:18080".to_string(),
            room_id: hex::encode([0xAA; 32]),
            gid: [0x01; 32],
            leaf_id: [0x02; 32],
            xk_hash: [0x03; 32],
            epoch_key: [0x04; 32],
            barrier_version: 1,
            k_barrier: [0x05; 32],
            pop_public_key: identity.pop_public_key,
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
            current_history_commitment: Some(sample_history_commitment()),
            current_history_authority_extension: None,
            current_global_history_attestation_bytes: Vec::new(),
            kem_tree_hash_after: [0xBB; 32],
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
        let alice_identity = cityg_api_client::generate_room_admin_identity();
        let admin_proof = alice_identity.build_kbroad_proof(
            RoomAdminOperation::Bootstrap,
            &room_id,
            demo::kbroad_public(),
        )?;
        new_api_client(&server_url)
            .bootstrap_room_as_admin(&room_id, demo::kbroad_public(), admin_proof)
            .await?;

        let alice = perform_join_with_identity(
            &server_url,
            &room_id,
            "alice",
            &alice_identity.pop_public_key,
            &alice_identity.pop_secret_key,
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
            &alice_identity.pop_public_key,
            &alice_identity.pop_secret_key,
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
        let detail = format!("{err:#}");
        assert!(
            detail.contains("merge ticket artifact response field mismatch"),
            "unexpected detail: {detail}"
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
                proto_bytes_responses(fixture.barrier_tree_snapshot_pages_raw.as_slice()),
            ),
            (
                "/v1/barrier/resolve_joins_since",
                proto_bytes_responses(fixture.join_records_pages_raw.as_slice()),
            ),
            (
                "/v1/barrier/resolve_revoked_leaves",
                proto_bytes_responses(fixture.revoked_leaf_indices_pages_raw.as_slice()),
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
                proto_bytes_responses(fixture.barrier_tree_snapshot_pages_raw.as_slice()),
            ),
            (
                "/v1/barrier/resolve_joins_since",
                proto_bytes_responses(fixture.join_records_pages_raw.as_slice()),
            ),
            (
                "/v1/barrier/resolve_revoked_leaves",
                proto_bytes_responses(fixture.revoked_leaf_indices_pages_raw.as_slice()),
            ),
            ("/v1/pivot/refresh", vec![MockResponse::empty_proto()]),
            ("/v1/accept_epoch", vec![MockResponse::empty_proto()]),
        ]);
        let (server_url, handle) = start_leave_mock_server(state.clone()).await?;

        let mut session = fixture.session;
        session.server_url = server_url;
        let err = match perform_join_finalize(session).await {
            Ok(_) => {
                return Err(anyhow!("tampered zero n_max ticket should fail closed"));
            }
            Err(err) => err,
        };
        assert_eq!(state.call_count("/v1/rooms/merge_ticket"), 1);
        let detail = format!("{err:#}");
        assert!(
            detail.contains("barrier n_max must be a non-zero power of two")
                || detail.contains("merge ticket artifact barrier state mismatch"),
            "unexpected detail: {detail}"
        );

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
    async fn watch_mode_reconnect_under_burst_resumes_live_notifications() -> Result<()> {
        let port = next_free_local_port();
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex::encode([0xA2u8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;

        let alice = perform_join(&server_url, &room_id, "watch-reconnect-alice").await?;

        let message_token = configured_client_message_token()
            .ok_or_else(|| anyhow!("message auth token is not configured"))?;
        let ws_url = websocket_url(&server_url, &alice.gid, &alice.leaf_id);
        let notification_cursor = WebSocketReplayCursor::default();
        let (mut first_rx, first_handle) =
            spawn_notification_listener(&ws_url, Some(&message_token), notification_cursor.clone())
                .await?;
        let mut bob = perform_join(&server_url, &room_id, "watch-reconnect-bob").await?;
        expect_membership_event(
            &mut first_rx,
            &bob.gid,
            &bob.leaf_id,
            "join",
            "bob join before reconnect".to_string(),
        )
        .await?;

        send_text_message(&mut bob, "bob-before-reconnect-1").await?;
        expect_message_event(
            &mut first_rx,
            &bob.we_epoch_id,
            false,
            "message before reconnect #1".to_string(),
        )
        .await?;
        send_text_message(&mut bob, "bob-before-reconnect-2").await?;
        expect_message_event(
            &mut first_rx,
            &bob.we_epoch_id,
            false,
            "message before reconnect #2".to_string(),
        )
        .await?;

        first_handle.abort();
        let _ = first_handle.await;

        send_text_message(&mut bob, "bob-while-disconnected").await?;

        let (mut second_rx, second_handle) =
            spawn_notification_listener(&ws_url, Some(&message_token), notification_cursor).await?;
        send_text_message(&mut bob, "bob-after-reconnect").await?;
        expect_message_event(
            &mut second_rx,
            &bob.we_epoch_id,
            true,
            "message after reconnect".to_string(),
        )
        .await?;
        send_text_message(&mut bob, "bob-after-reconnect-2").await?;
        expect_message_event(
            &mut second_rx,
            &bob.we_epoch_id,
            true,
            "second message after reconnect".to_string(),
        )
        .await?;

        second_handle.abort();
        let _ = second_handle.await;
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

        let state = LeaveMockState::new([(
            "/v1/rooms/merge_ticket",
            vec![MockResponse::proto_bytes(encode_merge_ticket(&bad_ticket)?)],
        )]);
        let (server_url, handle) = start_leave_mock_server(state.clone()).await?;

        let mut session = fixture.session;
        session.server_url = server_url;
        let err = perform_leave(&session, false)
            .await
            .expect_err("tampered out-of-range cover leaf must fail closed");
        let detail = format!("{err:#}");
        assert!(
            detail.contains("merge ticket cover_leaf_index out of range"),
            "unexpected detail: {detail}"
        );
        assert_eq!(state.call_count("/v1/rooms/merge_ticket"), 1);
        assert_eq!(state.call_count("/v1/barrier/fetch_public_tree"), 0);

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn perform_leave_rejects_barrier_snapshot_nmax_mismatch() -> Result<()> {
        let fixture = capture_leave_fixture().await?;
        let mut bad_snapshot = fixture.barrier_tree_snapshot.clone();
        bad_snapshot.n_max = if fixture.ticket.n_max <= 1 {
            2
        } else {
            fixture.ticket.n_max.saturating_mul(2)
        };

        let state = LeaveMockState::new([
            (
                "/v1/rooms/merge_ticket",
                vec![MockResponse::proto_bytes(encode_merge_ticket(
                    &fixture.ticket,
                )?)],
            ),
            (
                "/v1/barrier/fetch_public_tree",
                encode_barrier_tree_snapshot_pages(&bad_snapshot, &fixture.ticket),
            ),
        ]);
        let (server_url, handle) = start_leave_mock_server(state).await?;

        let mut session = fixture.session;
        session.server_url = server_url;
        let err = perform_leave(&session, false)
            .await
            .expect_err("n_max mismatch must fail");
        let detail = format!("{err:#}");
        assert!(
            detail.contains(
                "fetch public tree response deployment_profile_manifest barrier config mismatch"
            ),
            "unexpected detail: {detail}"
        );

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn perform_leave_skips_refresh_conflict_and_retries_pristine_bundle() -> Result<()> {
        let (fixture, witness_proxy_base_url, witness_handle) =
            capture_leave_fixture_with_server().await?;

        let state = LeaveMockState::new([
            (
                "/v1/rooms/merge_ticket",
                vec![MockResponse::proto_bytes(encode_merge_ticket(
                    &fixture.ticket,
                )?)],
            ),
            (
                "/v1/barrier/fetch_public_tree",
                proto_bytes_responses(fixture.barrier_tree_snapshot_pages_raw.as_slice()),
            ),
            (
                "/v1/barrier/resolve_joins_since",
                proto_bytes_responses(fixture.join_records_pages_raw.as_slice()),
            ),
            (
                "/v1/barrier/resolve_revoked_leaves",
                proto_bytes_responses(fixture.revoked_leaf_indices_pages_raw.as_slice()),
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
        ])
        .with_witness_proxy(witness_proxy_base_url);
        let (server_url, handle) = start_leave_mock_server(state.clone()).await?;

        let mut session = fixture.session;
        session.server_url = server_url;
        perform_leave(&session, true).await?;
        assert_eq!(state.call_count("/v1/pivot/refresh"), 2);
        assert_eq!(state.call_count("/v1/accept_epoch"), 2);

        handle.abort();
        let _ = handle.await;
        witness_handle.abort();
        let _ = witness_handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn perform_leave_retries_fresh_ticket_after_fs_checkpoint_monotonicity() -> Result<()> {
        let (fixture, witness_proxy_base_url, witness_handle) =
            capture_leave_fixture_with_server().await?;

        let mut fetch_public_tree =
            proto_bytes_responses(fixture.barrier_tree_snapshot_pages_raw.as_slice());
        fetch_public_tree.extend(proto_bytes_responses(
            fixture.barrier_tree_snapshot_pages_raw.as_slice(),
        ));
        let mut resolve_joins = proto_bytes_responses(fixture.join_records_pages_raw.as_slice());
        resolve_joins.extend(proto_bytes_responses(
            fixture.join_records_pages_raw.as_slice(),
        ));
        let mut resolve_revoked =
            proto_bytes_responses(fixture.revoked_leaf_indices_pages_raw.as_slice());
        resolve_revoked.extend(proto_bytes_responses(
            fixture.revoked_leaf_indices_pages_raw.as_slice(),
        ));

        let state = LeaveMockState::new([
            (
                "/v1/rooms/merge_ticket",
                vec![
                    MockResponse::proto_bytes(encode_merge_ticket(&fixture.ticket)?),
                    MockResponse::proto_bytes(encode_merge_ticket(&fixture.ticket)?),
                ],
            ),
            ("/v1/barrier/fetch_public_tree", fetch_public_tree),
            ("/v1/barrier/resolve_joins_since", resolve_joins),
            ("/v1/barrier/resolve_revoked_leaves", resolve_revoked),
            (
                "/v1/pivot/refresh",
                vec![MockResponse::empty_proto(), MockResponse::empty_proto()],
            ),
            (
                "/v1/accept_epoch",
                vec![
                    MockResponse::json(
                        HttpStatusCode::INTERNAL_SERVER_ERROR,
                        "acceptance error: fs_checkpoint_monotonicity",
                        Some(9473),
                        Some("fs_checkpoint_monotonicity"),
                    ),
                    MockResponse::empty_proto(),
                ],
            ),
        ])
        .with_witness_proxy(witness_proxy_base_url);
        let (server_url, handle) = start_leave_mock_server(state.clone()).await?;

        let mut session = fixture.session;
        session.server_url = server_url;
        perform_leave(&session, true).await?;
        assert_eq!(state.call_count("/v1/rooms/merge_ticket"), 2);
        assert_eq!(state.call_count("/v1/accept_epoch"), 2);

        handle.abort();
        let _ = handle.await;
        witness_handle.abort();
        let _ = witness_handle.await;
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
        let (fixture, witness_proxy_base_url, witness_handle) =
            capture_leave_fixture_with_server().await?;
        let state = LeaveMockState::new([
            (
                "/v1/rooms/merge_ticket",
                vec![MockResponse::proto_bytes(encode_merge_ticket(
                    &fixture.ticket,
                )?)],
            ),
            (
                "/v1/barrier/fetch_public_tree",
                proto_bytes_responses(fixture.barrier_tree_snapshot_pages_raw.as_slice()),
            ),
            (
                "/v1/barrier/resolve_joins_since",
                proto_bytes_responses(fixture.join_records_pages_raw.as_slice()),
            ),
            (
                "/v1/barrier/resolve_revoked_leaves",
                proto_bytes_responses(fixture.revoked_leaf_indices_pages_raw.as_slice()),
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
        ])
        .with_witness_proxy(witness_proxy_base_url);
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
        witness_handle.abort();
        let _ = witness_handle.await;
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

        let err = cityg_api_client::ensure_matching_barrier_history_dependencies(
            "leave",
            Some(&expected.history_view_id),
            &expected,
            &cityg_api_client::BarrierFetchedPublicTree {
                history_view_id: mismatched.history_view_id,
                history_commitment: mismatched,
                history_authority_extension: None,
                history_authority: None,
                global_history_attestation: None,
                tree: cityg_api_client::BarrierPublicTree {
                    n_max: 4,
                    kem_tree_hash_after: [0u8; 32],
                    pk_entries: Vec::new(),
                },
            },
            &cityg_api_client::BarrierResolvedJoins {
                history_view_id: expected.history_view_id,
                history_commitment: expected,
                history_authority_extension: None,
                history_authority: None,
                global_history_attestation: None,
                records: Vec::new(),
            },
            &cityg_api_client::BarrierResolvedRevokedLeaves {
                history_view_id: expected.history_view_id,
                history_commitment: expected,
                history_authority_extension: None,
                history_authority: None,
                global_history_attestation: None,
                leaf_indices: Vec::new(),
            },
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
            sequence: Some(1),
            replayed: true,
            timestamp_ms: 1,
        })
        .await?;
        tx.send(Notification::Membership {
            gid,
            leaf_id: leaf,
            event: "join".to_string(),
            sequence: Some(2),
            replayed: false,
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
            sequence: Some(1),
            replayed: true,
            timestamp_ms: 7,
        })
        .await?;
        tx.send(Notification::Message {
            we_epoch_id: weid,
            sequence: Some(2),
            replayed: false,
            timestamp_ms: 8,
        })
        .await?;

        expect_message_event(&mut rx, &weid, true, "message".to_string()).await?;
        Ok(())
    }

    #[tokio::test]
    async fn expect_message_event_errors_on_closed_channel() -> Result<()> {
        let (tx, mut rx) = mpsc::channel(1);
        drop(tx);
        let err = expect_message_event(&mut rx, &[0u8; 32], false, "closed".to_string())
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
        let err = spawn_notification_listener(
            "ws://127.0.0.1:9/v1/ws",
            None,
            WebSocketReplayCursor::default(),
        )
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

        let (mut rx, handle) = spawn_notification_listener(
            &format!("ws://{addr}/v1/ws"),
            None,
            WebSocketReplayCursor::default(),
        )
        .await?;
        let event = timeout(Duration::from_secs(2), rx.recv())
            .await?
            .ok_or(anyhow!("notification channel closed unexpectedly"))?;
        let mut seen_message = false;
        if let Notification::Message {
            we_epoch_id,
            sequence,
            replayed,
            timestamp_ms,
        } = event
        {
            assert_eq!(we_epoch_id, weid);
            assert_eq!(sequence, None);
            assert!(!replayed);
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
    async fn spawn_notification_listener_acks_sequences_and_resumes_on_reconnect() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let cursor = WebSocketReplayCursor::default();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut ws = tokio_tungstenite::accept_async(stream).await?;
            ws.send(WsMessage::Text(
                r#"{"type":"message","we_epoch_id":"abababababababababababababababababababababababababababababababab","sequence":12,"timestamp_ms":42}"#
                    .to_string()
                    .into(),
            ))
            .await?;
            let ack = ws.next().await.expect("ack frame").expect("ack frame ok");
            let ack_text = ack.into_text().expect("ack text frame");
            let ack_json: JsonValue = serde_json::from_str(&ack_text).expect("ack json");
            assert_eq!(ack_json["type"], "ack");
            assert_eq!(ack_json["last_sequence"], 12);
            ws.close(None).await?;

            let (stream, _) = listener.accept().await?;
            let mut ws = tokio_tungstenite::accept_async(stream).await?;
            let resume = ws
                .next()
                .await
                .expect("resume frame")
                .expect("resume frame ok");
            let resume_text = resume.into_text().expect("resume text frame");
            let resume_json: JsonValue = serde_json::from_str(&resume_text).expect("resume json");
            assert_eq!(resume_json["type"], "resume");
            assert_eq!(resume_json["last_sequence"], 12);
            ws.close(None).await?;

            Ok::<(), anyhow::Error>(())
        });

        let (mut first_rx, first_handle) =
            spawn_notification_listener(&format!("ws://{addr}/v1/ws"), None, cursor.clone())
                .await?;
        let event = timeout(Duration::from_secs(2), first_rx.recv())
            .await?
            .ok_or_else(|| anyhow!("notification channel closed unexpectedly"))?;
        assert!(matches!(
            event,
            Notification::Message {
                sequence: Some(12),
                replayed: false,
                ..
            }
        ));
        drop(first_rx);
        first_handle.abort();
        let _ = first_handle.await;

        let (second_rx, second_handle) =
            spawn_notification_listener(&format!("ws://{addr}/v1/ws"), None, cursor).await?;
        drop(second_rx);
        second_handle.abort();
        let _ = second_handle.await;

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

        let (mut rx, handle) = spawn_notification_listener(
            &format!("ws://{addr}/v1/ws"),
            None,
            WebSocketReplayCursor::default(),
        )
        .await?;
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
