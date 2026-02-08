#[cfg(not(test))]
use std::env;
use std::{collections::BTreeMap, convert::TryInto, time::Duration};

use anchor_seed::{
    SeedCommitFields, build_anchor_seed_ctx, compute_seed_bundle_commit, compute_seed_commit,
    compute_seed_ctx_hash,
};
use anyhow::{Context, Result, anyhow};
use ciborium::value::{Integer, Value};
use cityg_api_client::{CitygApiClient, Error as ApiClientError, IdentityBinding};
#[cfg(test)]
use cityg_client::demo;
use cityg_client::witness::SrxInputsOwned;
use cityg_client::{CityGClient, ClientEpochBundle};
use futures::StreamExt;
use hex::decode as hex_decode;
use msphf_core::{ds, hash::h_l};
use msphf_orchestrator::{
    AnchorInstanceParts, ForwardSecrecyState, FsJoinInputs, FsMergeInputs, LeafIdMode,
    OrchestrationParams, PivotParity, PopKeypair, SrxMode, derive_we_epoch_id,
    hdr,
};
use pqcrypto_dilithium::dilithium5::{self, SecretKey as MlDsaSecretKey};
use pqcrypto_traits::sign::{
    DetachedSignature as DilithiumDetachedSignatureTrait, PublicKey as DilithiumPublicKeyTrait,
};
use rand::{RngCore, thread_rng};
use serde::Serialize;
use serde_bytes::ByteBuf;
use serde_json::Value as JsonValue;
use tokio::{sync::mpsc, time::timeout};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message as WsMessage};
use tracing::warn;

fn demo_vrf_keys() -> (&'static [u8], &'static [u8]) {
    static VRF_KEYS: std::sync::OnceLock<(Vec<u8>, Vec<u8>)> = std::sync::OnceLock::new();
    let pair = VRF_KEYS.get_or_init(|| {
        let params = match msphf_orchestrator::lb::generate_parameters([0u8; 32]) {
            Ok(params) => params,
            Err(_) => unreachable!("deterministic join-leave VRF params must be derivable"),
        };
        match msphf_orchestrator::lb::generate_keypair(&params, [1u8; 32]) {
            Ok(pair) => pair,
            Err(_) => unreachable!("deterministic join-leave VRF keypair must be derivable"),
        }
    });
    (&pair.0, &pair.1)
}

fn random_room_id() -> String {
    let mut rng = thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn bytes32(name: &str, input: &[u8]) -> Result<[u8; 32]> {
    input
        .try_into()
        .map_err(|_| anyhow!("{name} must be 32 bytes, got {}", input.len()))
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
        match (&server_url, &room_id, &alias) {
            (None, _, _) => server_url = Some(arg),
            (Some(_), None, _) => room_id = Some(arg),
            (Some(_), Some(_), None) => alias = Some(arg),
            _ => {
                return Err(anyhow!(
                    "unexpected extra argument: {arg}. usage: [server] [room] [alias] [--count=N] [--batch|--watch] [--leave-order=...] [--verbose]"
                ));
            }
        }
    }

    let server_url = server_url.unwrap_or_else(|| "http://127.0.0.1:8080".to_string());
    let room_id = room_id.unwrap_or_else(random_room_id);
    let alias_base = alias.unwrap_or_else(|| "cli-joiner".to_string());

    if !batch_mode && leave_order_raw.is_some() {
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

    if watch_mode && leave_order.is_some() {
        return Err(anyhow!("--leave-order is not supported with --watch"));
    }

    Ok(CliOptions {
        server_url,
        room_id,
        alias_base,
        count,
        batch_mode,
        watch_mode,
        verbose,
        leave_order,
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
    } = options;

    if watch_mode {
        run_watch_mode(
            &server_url,
            &room_id,
            &alias_base,
            count,
            leave_order.clone(),
            verbose,
        )
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
            sessions.push(session);
        }

        let default_order: Vec<usize> = (1..=count).collect();
        let order = leave_order.as_ref().unwrap_or(&default_order);
        for idx in order {
            if *idx == 0 || *idx > sessions.len() {
                return Err(anyhow!("leave order index {idx} invalid"));
            }
            let session = &sessions[*idx - 1];
            println!(
                "leaving alias={} weid={}",
                alias_for(&alias_base, count, *idx - 1),
                hex::encode(session.we_epoch_id)
            );
            perform_leave(session, verbose).await?;
            println!("leave ok");
        }
    } else {
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
            perform_leave(&session, verbose).await?;
            println!("leave ok");
        }
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

struct Session {
    server_url: String,
    room_id: String,
    gid: [u8; 32],
    leaf_id: [u8; 32],
    pop_public_key: Vec<u8>,
    pop_secret: Box<MlDsaSecretKey>,
    vrf_secret_key: Vec<u8>,
    vrf_public_key: Vec<u8>,
    fs_ec: u64,
    fs_epoch_commit: [u8; 32],
    fs_dev_prev_commit: [u8; 32],
    we_epoch_id: [u8; 32],
    anchor_hdr_ctx: Vec<u8>,
    seed_ctx_hash: [u8; 32],
    seed_commit: [u8; 32],
    seed_bundle_commit: [u8; 32],
    fs_fingerprint: Option<[u8; 32]>,
    stored_header_map: BTreeMap<u64, Value>,
}

const EVENT_TIMEOUT: Duration = Duration::from_secs(10);

async fn perform_join(server_url: &str, room_id: &str, alias: &str) -> Result<Session> {
    let client = CitygApiClient::new(server_url);
    let (pop_pk, pop_sk) = dilithium5::keypair();
    let pop_public_key = DilithiumPublicKeyTrait::as_bytes(&pop_pk).to_vec();
    let pop_secret = Box::new(pop_sk);

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

    let ticket = match client
        .join_ticket(room_id, alias, Some(identity_binding))
        .await
    {
        Ok(t) => t,
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

    let gid = bytes32("gid", &ticket.gid)?;
    let cat = bytes32("cat", &ticket.cat)?;
    let tswe_salt_hash = bytes32("tswe_salt_hash", &ticket.tswe_salt_hash)?;
    let parent_root = bytes32("parent_root", &ticket.parent_root)?;
    let join_delta_root = bytes32("join_delta_root", &ticket.join_delta_root)?;
    let revoked_since_root = bytes32("revoked_since_root", &ticket.revoked_since_root)?;
    let revoked_root = bytes32("revoked_root", &ticket.revoked_root)?;
    let leaf_id = bytes32("leaf_id", &ticket.leaf_id)?;
    let pox_r_commit = bytes32("pox_r_commit", &ticket.pox_r_commit)?;

    let kbroad_public = if ticket.kbroad_public.is_empty() {
        return Err(anyhow!("server returned empty KBROAD key"));
    } else {
        ticket.kbroad_public.clone()
    };

    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_KBROAD_ALG, Value::Text("ml-kem-768".to_string()));
    header.insert(hdr::HDR_KBROAD_PUB, Value::Bytes(kbroad_public.clone()));

    let mut fs_state = ForwardSecrecyState::new({
        let mut seed = [0u8; 32];
        thread_rng().fill_bytes(&mut seed);
        seed
    });

    let (vrf_secret_key, vrf_public_key) = demo_vrf_keys();

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
        vrf_secret_key: Some(vrf_secret_key),
        vrf_public_key: Some(vrf_public_key),
        fs_policy_version: ticket.fs_policy_version.as_str(),
        fs_epoch_base_ts: ticket.fs_epoch_base_ts,
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

    let bundle = CityGClient::generate_epoch(header, parts, params, &mut fs_state, witness_bytes)
        .context("generate join bundle")?;

    if parent_root == [0u8; 32] && !ticket.bootstrap_public.is_empty() {
        return Err(anyhow!(
            "server requires bootstrap signer for first join; join_leave bootstrap signer support is not configured"
        ));
    }

    client
        .accept_epoch_bundle(&bundle)
        .await
        .context("server rejected join bundle")?;

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
            .get(&hdr::HDR_FS_DEV_PREV_COMMIT)
            .and_then(Value::as_bytes)
            .ok_or(anyhow!("stored bundle missing fs_dev_prev_commit"))?,
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
    Ok(Session {
        server_url: server_url.to_string(),
        room_id: room_id.to_string(),
        gid,
        leaf_id,
        pop_public_key,
        pop_secret,
        vrf_secret_key: vrf_secret_key.to_vec(),
        vrf_public_key: vrf_public_key.to_vec(),
        fs_ec,
        fs_epoch_commit,
        fs_dev_prev_commit,
        we_epoch_id: bundle.we_epoch_id,
        anchor_hdr_ctx,
        seed_ctx_hash,
        seed_commit,
        seed_bundle_commit,
        fs_fingerprint,
        stored_header_map: stored.header_map.clone(),
    })
}

async fn perform_leave(session: &Session, verbose: bool) -> Result<()> {
    let client = CitygApiClient::new(&session.server_url);
    let ticket = client
        .merge_ticket(&session.room_id, &session.leaf_id)
        .await
        .context("fetch merge ticket")?;

    let parities = hydrate_parities(
        &ticket.parities,
        session.fs_ec,
        session.fs_epoch_commit,
        session.fs_dev_prev_commit,
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
        fs_join: FsJoinInputs {
            fs_ec: session.fs_ec,
            fs_epoch_commit: session.fs_epoch_commit,
            fs_dev_prev_commit: session.fs_dev_prev_commit,
        },
        fs_merge: FsMergeInputs::default(),
    };

    let witness_bytes = if ticket.witness_cbor.is_empty() {
        None
    } else {
        Some(ticket.witness_cbor.as_slice())
    };

    let mut bundle =
        CityGClient::generate_merge(header, parts, params, &parities, None, witness_bytes)
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
            seed_ctx_hash == session.seed_ctx_hash,
            seed_commit == session.seed_commit,
            seed_bundle_commit == session.seed_bundle_commit
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
    bundle.we_epoch_id = derived_we_epoch_id;

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
            ciborium::de::from_reader(session.anchor_hdr_ctx.as_slice())
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
        let keys: BTreeSet<u64> = session
            .stored_header_map
            .keys()
            .chain(bundle.header_map.keys())
            .copied()
            .collect();
        let mut diff_report = Vec::new();
        for key in keys {
            let stored = session.stored_header_map.get(&key);
            let current = bundle.header_map.get(&key);
            if stored != current {
                diff_report.push((key, describe_value(stored), describe_value(current)));
            }
        }
        println!(
            "anchor_ctx_equal={} adjusted_keys={:?} diff_keys={:?}",
            computed_anchor_ctx == session.anchor_hdr_ctx,
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
        hdr::HDR_HP_BYTES,
        hdr::HDR_POP_ALG,
        hdr::HDR_POP_PK,
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
        }) if status.is_server_error() && message.contains("pivot head missing") => {
            if verbose {
                println!("refresh pivot skipped due to stale head set: {message}");
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

async fn run_watch_mode(
    server_url: &str,
    room_id: &str,
    alias_base: &str,
    count: usize,
    leave_order: Option<Vec<usize>>,
    verbose: bool,
) -> Result<()> {
    println!(
        "watch mode: server={server_url} room={room_id} alias_base={alias_base} count={count}"
    );
    let ws_url = websocket_url(server_url);
    let (mut event_rx, ws_handle) = spawn_notification_listener(&ws_url).await?;
    let mut sessions = Vec::with_capacity(count);

    for i in 0..count {
        let alias = alias_for(alias_base, count, i);
        println!("joining alias={alias}");
        let session = perform_join(server_url, room_id, &alias).await?;
        println!("join ok: weid={}", hex::encode(session.we_epoch_id));
        log_fingerprints(&session);
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

    if let Some(first) = sessions.first() {
        println!(
            "sending dummy message via {}",
            hex::encode(first.we_epoch_id)
        );
        send_dummy_message(first).await?;
        expect_message_event(
            &mut event_rx,
            &first.we_epoch_id,
            "dummy message delivery".to_string(),
        )
        .await?;
    }

    let default_order: Vec<usize> = (1..=sessions.len()).collect();
    let order = leave_order.as_ref().unwrap_or(&default_order);
    for idx in order {
        if *idx == 0 || *idx > sessions.len() {
            return Err(anyhow!("leave order index {idx} invalid"));
        }
        let session = &sessions[*idx - 1];
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

async fn send_dummy_message(session: &Session) -> Result<()> {
    let client = CitygApiClient::new(&session.server_url);
    let mut ciphertext = vec![0u8; 64];
    thread_rng().fill_bytes(&mut ciphertext);
    client
        .send_message(&session.we_epoch_id, &ciphertext, Some(&session.leaf_id))
        .await?;
    Ok(())
}

async fn spawn_notification_listener(
    ws_url: &str,
) -> Result<(mpsc::Receiver<Notification>, tokio::task::JoinHandle<()>)> {
    let (stream, _) = connect_async(ws_url)
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

fn websocket_url(server_url: &str) -> String {
    if let Some(rest) = server_url.strip_prefix("https://") {
        format!("wss://{rest}/v1/ws")
    } else if let Some(rest) = server_url.strip_prefix("http://") {
        format!("ws://{rest}/v1/ws")
    } else {
        format!("ws://{server_url}/v1/ws")
    }
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
    header.insert(
        hdr::HDR_POLICY_VERSION,
        Value::Text(pivot.policy_version.clone()),
    );
    header.insert(hdr::HDR_PROOF_MODE, Value::Text(pivot.proof_mode.clone()));
    header.insert(hdr::HDR_VRF_ID, Value::Text(pivot.vrf_id.clone()));
    header.insert(hdr::HDR_VRF_PROOF, Value::Bytes(pivot.vrf_proof.clone()));
    header.insert(
        hdr::HDR_VRF_PUBLIC_KEY,
        Value::Bytes(pivot.vrf_public.clone()),
    );
    header.insert(hdr::HDR_VRF_MASK_A, Value::Bytes(pivot.mask_a.to_vec()));
    header.insert(hdr::HDR_VRF_MASK_B, Value::Bytes(pivot.mask_b.to_vec()));
    header.insert(hdr::HDR_FS_CAPSS, Value::Bytes(pivot.fs_capss.clone()));
    header.insert(
        hdr::HDR_PROOFS_COMMIT,
        Value::Bytes(pivot.proofs_commit.to_vec()),
    );

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
mod tests {
    use super::*;
    use cityg_config::CityGConfig;
    use futures::SinkExt;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicU16, Ordering},
        },
        time::Duration,
    };
    use tokio::time::sleep;

    static NEXT_TEST_PORT: AtomicU16 = AtomicU16::new(18600);

    async fn spawn_server_on_with_seed_demo(
        port: u16,
        seed_demo_room: bool,
    ) -> tokio::task::JoinHandle<()> {
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
        CitygApiClient::new(server_url)
            .bootstrap_room(room_id, demo::kbroad_public())
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
            policy_version: "policy-v1".to_string(),
            proof_mode: "lin+zkvrf".to_string(),
            vrf_id: "lb-vrf".to_string(),
            vrf_proof: vec![0xDD, 0xEE],
            vrf_public: vec![0x11, 0x22],
            mask_a: [0xAA; 32],
            mask_b: [0xBB; 32],
            fs_capss: vec![0xCC],
            proofs_commit: [0xDD; 32],
            srx_commit: Some([0xEE; 32]),
            is_join: true,
            hp_envelope: Arc::<[u8]>::from(vec![0x99, 0x88]),
            fs_epoch_commit: Some([0x44; 32]),
            fs_ec: Some(77),
            fs_dev_commit: Some([0x55; 32]),
        }
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
    fn fs_fingerprint_helpers_cover_valid_and_invalid_headers() {
        let fs_epoch_commit = [0x42; 32];
        let mut header = BTreeMap::new();
        header.insert(
            hdr::HDR_FS_POLICY_VERSION,
            Value::Text("fs-policy-v1".to_string()),
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

        let direct = derive_fs_fingerprint_from_fields("fs-policy-v1", 9, &fs_epoch_commit, 1234);
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
            Value::Text("fs-policy-v1".to_string()),
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
            Value::Text("fs-policy-v1".to_string()),
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
        assert_eq!(
            websocket_url("http://127.0.0.1:18080"),
            "ws://127.0.0.1:18080/v1/ws"
        );
        assert_eq!(
            websocket_url("https://example.com"),
            "wss://example.com/v1/ws"
        );
        assert_eq!(websocket_url("localhost:9000"), "ws://localhost:9000/v1/ws");
    }

    #[test]
    fn alias_for_formats_single_and_multi() {
        assert_eq!(alias_for("alice", 1, 0), "alice");
        assert_eq!(alias_for("alice", 3, 1), "alice-2");
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
        assert_eq!(opts.alias_base, "cli-joiner");
        assert_eq!(opts.room_id.len(), 64);

        let opts = parse_cli_args(vec![
            "http://127.0.0.1:19090".to_string(),
            "abcd".repeat(16),
            "operator".to_string(),
            "--watch".to_string(),
            "--count=2".to_string(),
            "--verbose".to_string(),
        ])?;
        assert_eq!(opts.server_url, "http://127.0.0.1:19090");
        assert_eq!(opts.alias_base, "operator");
        assert_eq!(opts.room_id, "abcd".repeat(16));
        assert!(opts.leave_order.is_none());
        assert!(opts.watch_mode);
        assert!(opts.batch_mode);
        assert!(opts.verbose);
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

        let err = parse_cli_args(vec![
            "--watch".to_string(),
            "--count=2".to_string(),
            "--leave-order=2,1".to_string(),
        ])
        .expect_err("watch mode should reject explicit leave-order");
        assert!(
            err.to_string()
                .contains("--leave-order is not supported with --watch")
        );

        let err = parse_cli_args(vec![
            "http://127.0.0.1:18080".to_string(),
            "room".to_string(),
            "alias".to_string(),
            "extra".to_string(),
        ])
        .expect_err("extra positional arg should fail");
        assert!(err.to_string().contains("unexpected extra argument"));
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
            header.get(&hdr::HDR_POLICY_VERSION),
            Some(&Value::Text("policy-v1".to_string()))
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
    fn log_helpers_cover_none_fingerprint_and_non_integer_fs_ec() {
        let (_pk, sk) = dilithium5::keypair();
        let session = Session {
            server_url: "http://127.0.0.1:18080".to_string(),
            room_id: hex::encode([0xAA; 32]),
            gid: [0x01; 32],
            leaf_id: [0x02; 32],
            pop_public_key: vec![0x11],
            pop_secret: Box::new(sk),
            vrf_secret_key: vec![0x22],
            vrf_public_key: vec![0x33],
            fs_ec: 5,
            fs_epoch_commit: [0x44; 32],
            fs_dev_prev_commit: [0x55; 32],
            we_epoch_id: [0x66; 32],
            anchor_hdr_ctx: vec![],
            seed_ctx_hash: [0x77; 32],
            seed_commit: [0x88; 32],
            seed_bundle_commit: [0x99; 32],
            fs_fingerprint: None,
            stored_header_map: BTreeMap::new(),
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
        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex::encode([0x91u8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;
        let alice = perform_join(&server_url, &room_id, "alice").await?;
        let bob = perform_join(&server_url, &room_id, "bob").await?;

        send_dummy_message(&bob).await?;
        perform_leave(&alice, true).await?;
        perform_leave(&bob, true).await?;

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn run_with_options_single_roundtrip() -> Result<()> {
        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
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
        })
        .await?;

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn run_with_options_batch_roundtrip() -> Result<()> {
        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
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
        })
        .await?;

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn run_with_options_non_batch_multi_roundtrip() -> Result<()> {
        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
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
        })
        .await?;

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn run_with_options_batch_single_alias_roundtrip() -> Result<()> {
        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
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
        })
        .await?;

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn run_with_options_watch_mode_roundtrip() -> Result<()> {
        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
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
        })
        .await?;

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn run_with_options_rejects_runtime_leave_order_index() -> Result<()> {
        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
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
        })
        .await
        .expect_err("invalid leave order should fail at runtime");
        assert!(err.to_string().contains("leave order index 2 invalid"));

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn watch_mode_roundtrip() -> Result<()> {
        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex::encode([0xA1u8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;

        run_watch_mode(&server_url, &room_id, "watcher", 2, None, true).await?;

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn perform_join_reports_kbroad_missing_on_unbootstrapped_room() -> Result<()> {
        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
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
        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
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
    async fn spawn_notification_listener_rejects_unreachable_server() -> Result<()> {
        let err = spawn_notification_listener("ws://127.0.0.1:9/v1/ws")
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

        let (mut rx, handle) = spawn_notification_listener(&format!("ws://{addr}/v1/ws")).await?;
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
}
