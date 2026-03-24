#[cfg(test)]
use std::fs;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::barrier_shared::{
    BARRIER_KEY_INFO, BARRIER_TREE_INFO, BarrierDeriveSaltPreimage, BarrierTreePathSaltPreimage,
    DEFAULT_BARRIER_N_MAX, TICKET_RETRY_MAX_ATTEMPTS, apply_join_set_to_snapshot,
    apply_revoked_set_to_snapshot, barrier_path_nodes, blank_leaf_and_path,
    collect_resolution_targets, compute_barrier_pkhash, compute_barrier_tree_hash,
    compute_revocation_roots_hash, expected_barrier_tree_nodes, should_retry_ticket_http_error,
    sibling_node, ticket_retry_delay,
};
#[cfg(test)]
use crate::message_crypto::{MSG_INDEX_REPLAY_WINDOW, decrypt_message_v2};
use crate::message_crypto::{
    MessageCryptoContext, MsgReplayState, PersistedMsgReplayState, decrypt_message_v2_with_index,
    derive_msg_replay_tuple_tag, encrypt_message_v2,
};
use ahash::AHashMap;
use anchor_seed::{
    SeedCommitFields, build_anchor_seed_ctx, compute_seed_bundle_commit, compute_seed_commit,
    compute_seed_ctx_hash,
};
use anyhow::{Context as AnyhowContext, Result, anyhow};
use ciborium::value::{Integer, Value};
use cityg_api_client::{
    BarrierJoinRecord, BarrierPublicTree, CitygApiClient, Error as ApiClientError, MergeTicket,
    RoomAdminOperation, build_room_admin_listing_proof, build_room_admin_proof,
    build_room_admin_target_proof,
};
use cityg_client::witness::SrxInputsOwned;
use cityg_client::{CityGClient, ClientEpochBundle};
use cityg_config::CityGConfig;
use futures::{StreamExt, channel::mpsc as futures_mpsc};
use gpui::prelude::*;
#[cfg(not(test))]
use gpui::{
    App, Application, Bounds, TitlebarOptions, WindowBounds, WindowDecorations, WindowOptions, size,
};
use gpui::{
    ClipboardItem, Context as ViewContext, CursorStyle, Div, FontWeight, Keystroke, MouseButton,
    MouseDownEvent, Render, ScrollHandle, Task, Window, div, point, px, rgb,
};
use hex::{decode as hex_decode, encode as hex_encode};
use humantime::format_rfc3339_seconds;
use ml_kem::{
    ExpandedDecapsulationKey as MlKemExpandedDecapsulationKey, Seed as MlKemSeed,
    kem::{Decapsulate as MlKemDecapsulate, KeyExport as MlKemKeyExport},
    ml_kem_768,
    ml_kem_768::DecapsulationKey as MlKem768DecapsulationKey,
};
use msphf_core::{
    ds, hash::h_l, hkdf::hkdf_blake3, merkle::canonical_set_root, serde_utils::to_cbor_vec,
};
use msphf_orchestrator::CapssWitnessBundle;
use msphf_orchestrator::{
    AnchorInstanceParts, ForwardSecrecyState, FsJoinInputs, FsMergeInputs, LeafIdMode,
    OrchestrationParams, PivotParity, PopKeypair, SrxMode, compute_proofs_commit_bytes,
    derive_we_epoch_id, hdr,
};
use pqcrypto_dilithium::{
    dilithium3::{
        self, public_key_bytes as ml_dsa_public_key_bytes,
        signature_bytes as ml_dsa_signature_bytes,
    },
    dilithium5,
};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
};
use pqcrypto_traits::sign::{
    DetachedSignature, PublicKey as DilithiumPublicKey, SecretKey as DilithiumSecretKey,
};
use rand::{RngExt, rng};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::time::sleep;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        client::IntoClientRequest,
        http::{HeaderValue, Request},
        protocol::Message as WsMessage,
    },
};
use tracing::{debug, info, warn};
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
use cityg_client::demo;

#[path = "native/chat_ui.rs"]
mod chat_ui;
#[path = "native/errors.rs"]
mod errors;
#[path = "native/fault_injection.rs"]
mod fault_injection;
#[path = "native/interactions.rs"]
mod interactions;
#[path = "native/lifecycle.rs"]
mod lifecycle;
#[path = "native/members.rs"]
mod members;
#[path = "native/message_auth.rs"]
mod message_auth;
#[path = "native/params.rs"]
mod params;
#[path = "native/render_panels.rs"]
mod render_panels;
#[path = "native/render_session.rs"]
mod render_session;
#[path = "native/room_admin.rs"]
mod room_admin;
#[path = "native/session_runtime.rs"]
mod session_runtime;
#[path = "native/session_state.rs"]
mod session_state;
#[path = "native/storage.rs"]
mod storage;
#[path = "native/tokio_bridge.rs"]
mod tokio_bridge;

use errors::*;
#[cfg(test)]
use fault_injection::*;
use message_auth::*;
use params::*;
use storage::*;
use tokio_bridge::Tokio;

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

#[cfg(test)]
const DEFAULT_MAX_BARRIER_UPDATE_BYTES: u64 = 1_048_576;
const BARRIER_KEYGEN_D_INFO: &[u8] = b"city-g|barrier/keygen-d|v1";
const BARRIER_KEYGEN_Z_INFO: &[u8] = b"city-g|barrier/keygen-z|v1";
const FS_PCS_INFO: &[u8] = b"city-g|fs/pcs|v1";
const ML_KEM_SEED_BYTES: usize = 64;
const ML_KEM_EXPANDED_DK_BYTES: usize = 2400;
const BARRIER_CODE_RECOVER_NO_MATCH: u32 = 9606;
const BARRIER_CODE_SNAPSHOT_AUTH_FAILURE: u32 = 9609;
const JOIN_INVITE_PREFIX: &str = "cityg-invite:";

fn is_refresh_pivot_conflict(status_code: u16, message: &str) -> bool {
    matches!(status_code, 409 | 500)
        && (message.contains("pivot head missing")
            || message.contains("refresh payload diverges from stored parity"))
}

#[derive(Serialize)]
struct BarrierUpdateDigestPreimage<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

#[derive(Serialize)]
struct BarrierWrapNoncePreimage(u64, u64);

#[derive(Serialize)]
struct BarrierWrapAadPreimage<'a>(
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    u64,
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    u64,
    u64,
    u64,
    #[serde(with = "serde_bytes")] &'a [u8; 32],
);

#[derive(Serialize)]
struct FsPcsSaltPreimage<'a>(#[serde(with = "serde_bytes")] &'a [u8; 32], u64, u64);

#[derive(Serialize)]
struct BarrierKeygenSaltPreimage<'a>(u64, #[serde(with = "serde_bytes")] &'a [u8; 32], u64, u64);

#[derive(Clone, Serialize, Deserialize)]
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

#[derive(Clone, Serialize, Deserialize)]
struct KemTreeCoverPayloadWire(
    u64,
    Vec<u64>,
    Option<Vec<u64>>,
    Vec<NodeCiphertextWire>,
    Vec<NewPublicKeyWire>,
);

#[derive(Clone, Serialize, Deserialize)]
struct NodeCiphertextWire(
    u64,
    u64,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
);

#[derive(Clone, Serialize, Deserialize)]
struct NewPublicKeyWire(u64, #[serde(with = "serde_bytes")] Vec<u8>);

#[derive(Clone, Debug)]
struct ParsedNodeCiphertext {
    source_node: u64,
    target_node: u64,
    target_pk_hash: [u8; 16],
    kem_ct: Vec<u8>,
    wrapped_ps: Vec<u8>,
}

#[derive(Clone, Debug)]
struct ParsedBarrierUpdate {
    barrier_version: u64,
    prev_barrier_version: u64,
    tree_size: u64,
    revocation_roots_hash: [u8; 32],
    kem_tree_hash_before: [u8; 32],
    kem_tree_hash_after: [u8; 32],
    updater_leaf: u64,
    path_nodes: Vec<u64>,
    node_ciphertexts: Vec<ParsedNodeCiphertext>,
    new_public_keys: BTreeMap<u64, Vec<u8>>,
}

#[derive(Clone, Debug)]
struct BarrierRecoverResult {
    k_barrier_new: Zeroizing<[u8; 32]>,
    kem_tree_hash_after: [u8; 32],
    k_fs_after_pcs: Option<Zeroizing<[u8; 32]>>,
    derived_node_key_material: BTreeMap<u32, BarrierNodeKeyMaterial>,
}

#[derive(Clone, Debug)]
struct BarrierUpdateBuildResult {
    raw_update: Vec<u8>,
    barrier_update_digest: [u8; 32],
    kem_tree_hash_after: [u8; 32],
    k_barrier_new: Zeroizing<[u8; 32]>,
    on_path_key_material: BTreeMap<u32, BarrierNodeKeyMaterial>,
}

fn compute_barrier_update_digest(raw_update: &[u8]) -> Result<[u8; 32]> {
    h_l(
        "barrier/update/digest",
        &BarrierUpdateDigestPreimage(raw_update),
    )
    .map_err(|err| anyhow!("compute barrier_update_digest: {err}"))
}

fn validate_barrier_tree_snapshot_auth(
    expected_hash: &[u8; 32],
    expected_n_max: u64,
    snapshot: &BarrierPublicTree,
) -> Result<()> {
    if snapshot.kem_tree_hash_after != *expected_hash {
        return Err(anyhow!(
            "barrier tree snapshot auth failure (960.9): hash mismatch"
        ));
    }
    let computed_hash = compute_barrier_tree_hash(expected_n_max, snapshot.pk_entries.as_slice())?;
    if computed_hash != *expected_hash {
        return Err(anyhow!(
            "barrier tree snapshot auth failure (960.9): tree hash mismatch"
        ));
    }
    Ok(())
}

fn expected_same_rrh_barrier_reason(join_records: &[BarrierJoinRecord], updater_leaf: u64) -> u64 {
    if join_records
        .iter()
        .any(|record| u64::from(record.leaf_index) == updater_leaf)
    {
        2
    } else {
        1
    }
}

fn zeroize_path_secret_map(path_secrets: &mut BTreeMap<u64, [u8; 32]>) {
    for secret in path_secrets.values_mut() {
        secret.zeroize();
    }
}

fn parse_deterministic_cbor<T>(raw: &[u8], label: &str) -> Result<T>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let decoded: T =
        ciborium::de::from_reader(raw).map_err(|err| anyhow!("failed to parse {label}: {err}"))?;
    let canonical = to_cbor_vec(&decoded)
        .map_err(|err| anyhow!("failed to re-encode canonical {label}: {err}"))?;
    if canonical.as_slice() != raw {
        return Err(anyhow!("non-canonical {label} encoding"));
    }
    Ok(decoded)
}

fn to_array32(label: &str, bytes: Vec<u8>) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("{label} must be 32 bytes"))
}

fn to_array16(label: &str, bytes: Vec<u8>) -> Result<[u8; 16]> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("{label} must be 16 bytes"))
}

fn normalize_max_barrier_update_bytes(limit: u64) -> Result<usize> {
    if limit == 0 {
        return Err(anyhow!("max_barrier_update_bytes must be positive"));
    }
    usize::try_from(limit).map_err(|_| anyhow!("max_barrier_update_bytes is too large"))
}

fn parse_barrier_update_for_recover(
    raw_update: &[u8],
    expected_n_max: u64,
    max_barrier_update_bytes: usize,
) -> Result<ParsedBarrierUpdate> {
    if raw_update.len() > max_barrier_update_bytes {
        return Err(anyhow!(
            "barrier_update exceeds max_barrier_update_bytes: {} > {}",
            raw_update.len(),
            max_barrier_update_bytes
        ));
    }
    if expected_n_max == 0 || !expected_n_max.is_power_of_two() {
        return Err(anyhow!("barrier n_max must be a non-zero power of two"));
    }

    let BarrierUpdateWire(
        mode,
        barrier_version,
        prev_barrier_version,
        tree_size,
        revocation_roots_hash,
        kem_tree_hash_before,
        kem_tree_hash_after,
        cover_payload,
    ) = parse_deterministic_cbor(raw_update, "barrier_update")?;

    if mode != "barrier-v1" {
        return Err(anyhow!("unsupported barrier update mode: {mode}"));
    }
    if tree_size != expected_n_max {
        return Err(anyhow!(
            "barrier tree_size mismatch: expected {expected_n_max}, got {tree_size}"
        ));
    }

    let KemTreeCoverPayloadWire(
        updater_leaf,
        path_nodes,
        _revoked_leaf_indices_hint,
        node_ciphertexts_wire,
        new_public_keys,
    ) = parse_deterministic_cbor(cover_payload.as_slice(), "barrier cover payload")?;

    if updater_leaf >= expected_n_max {
        return Err(anyhow!("barrier updater_leaf out of range"));
    }

    let expected_nodes = expected_n_max
        .checked_mul(2)
        .and_then(|v| v.checked_sub(1))
        .ok_or_else(|| anyhow!("barrier tree size overflow"))?;
    let max_index = expected_nodes.saturating_sub(1);
    let leaf_base = expected_n_max.saturating_sub(1);
    let expected_leaf = leaf_base.saturating_add(updater_leaf);

    if path_nodes.is_empty() {
        return Err(anyhow!("barrier path_nodes must be non-empty"));
    }
    if path_nodes.first().copied() != Some(expected_leaf) {
        return Err(anyhow!(
            "barrier path_nodes must start at updater leaf node"
        ));
    }
    if path_nodes.last().copied() != Some(0) {
        return Err(anyhow!("barrier path_nodes must end at root node"));
    }
    let mut path_seen = HashSet::new();
    for &node in &path_nodes {
        if node > max_index {
            return Err(anyhow!("barrier path node out of range"));
        }
        if !path_seen.insert(node) {
            return Err(anyhow!("barrier path_nodes contains duplicate nodes"));
        }
    }
    for pair in path_nodes.windows(2) {
        let child = pair[0];
        let parent = pair[1];
        if child == 0 || (child - 1) / 2 != parent {
            return Err(anyhow!("barrier path_nodes parent chain is invalid"));
        }
    }

    let expected_public_nodes: HashSet<u64> = path_nodes.iter().copied().skip(1).collect();
    if new_public_keys.len() != expected_public_nodes.len() {
        return Err(anyhow!(
            "barrier new_public_keys length does not match ExpectedNodeSet"
        ));
    }
    let mut seen_public_nodes = HashSet::new();
    let mut prev_public_node: Option<u64> = None;
    let mut parsed_new_public_keys = BTreeMap::new();
    for NewPublicKeyWire(node_index, ek) in &new_public_keys {
        if *node_index > max_index {
            return Err(anyhow!("barrier new_public_keys node out of range"));
        }
        if *node_index >= leaf_base {
            return Err(anyhow!(
                "barrier new_public_keys may reference only internal nodes"
            ));
        }
        if ek.len() != kyber768::public_key_bytes() {
            return Err(anyhow!(
                "barrier new_public_keys ek must be ML-KEM-768 length"
            ));
        }
        if prev_public_node.is_some_and(|prev| prev >= *node_index) {
            return Err(anyhow!(
                "barrier new_public_keys must be sorted by node index"
            ));
        }
        prev_public_node = Some(*node_index);
        if !seen_public_nodes.insert(*node_index) {
            return Err(anyhow!(
                "barrier new_public_keys contains duplicate node index"
            ));
        }
        parsed_new_public_keys.insert(*node_index, ek.clone());
    }
    if seen_public_nodes != expected_public_nodes {
        return Err(anyhow!(
            "barrier new_public_keys must match ExpectedNodeSet exactly"
        ));
    }

    let mut node_ciphertexts = Vec::with_capacity(node_ciphertexts_wire.len());
    let mut prev_pair: Option<(u64, u64)> = None;
    for NodeCiphertextWire(source_node, target_node, target_pk_hash, kem_ct, wrapped_ps) in
        node_ciphertexts_wire
    {
        if source_node > max_index || target_node > max_index {
            return Err(anyhow!("barrier node_ciphertext index out of range"));
        }
        if target_pk_hash.len() != 16 {
            return Err(anyhow!("barrier target_pk_hash must be 16 bytes"));
        }
        if kem_ct.len() != kyber768::ciphertext_bytes() {
            return Err(anyhow!("barrier kem_ct length mismatch"));
        }
        if wrapped_ps.len() != 48 {
            return Err(anyhow!("barrier wrapped_ps must be 48 bytes"));
        }
        let pair = (source_node, target_node);
        if prev_pair.is_some_and(|prev| prev >= pair) {
            return Err(anyhow!(
                "barrier node_ciphertexts must be sorted and duplicate-free"
            ));
        }
        prev_pair = Some(pair);
        node_ciphertexts.push(ParsedNodeCiphertext {
            source_node,
            target_node,
            target_pk_hash: to_array16("target_pk_hash", target_pk_hash)?,
            kem_ct,
            wrapped_ps,
        });
    }

    Ok(ParsedBarrierUpdate {
        barrier_version,
        prev_barrier_version,
        tree_size,
        revocation_roots_hash: to_array32("revocation_roots_hash", revocation_roots_hash)?,
        kem_tree_hash_before: to_array32("kem_tree_hash_before", kem_tree_hash_before)?,
        kem_tree_hash_after: to_array32("kem_tree_hash_after", kem_tree_hash_after)?,
        updater_leaf,
        path_nodes,
        node_ciphertexts,
        new_public_keys: parsed_new_public_keys,
    })
}

async fn full_chain_check_barrier_update(
    client: &CitygApiClient,
    room_id: &str,
    session: &AppSession,
    header_map: &BTreeMap<u64, Value>,
    raw_update: &[u8],
    max_barrier_update_bytes: usize,
) -> Result<[u8; 32]> {
    let n_max = session.barrier_state.n_max.max(1);
    let parsed = parse_barrier_update_for_recover(raw_update, n_max, max_barrier_update_bytes)
        .map_err(|err| anyhow!("barrier full chain-check prevalidation failed (960.7): {err}"))?;
    let local_barrier_version = session.barrier_state.barrier_version;
    let local_barrier_initialized = session.barrier_state.barrier_initialized;
    let barrier_reason = header_u64(header_map, hdr::HDR_BARRIER_UPDATE_REASON).ok_or_else(|| {
        anyhow!("barrier full chain-check prevalidation failed (960.7): missing barrier_update_reason")
    })?;
    let genesis_local_case = !local_barrier_initialized
        && parsed.prev_barrier_version == 0
        && parsed.barrier_version == 0;
    let valid_local_progression = genesis_local_case
        || (local_barrier_initialized
            && parsed.prev_barrier_version == local_barrier_version
            && parsed.barrier_version == local_barrier_version.saturating_add(1));
    if !valid_local_progression {
        return Err(anyhow!(
            "barrier full chain-check prevalidation failed (960.7): local barrier version progression mismatch"
        ));
    }

    let h_prev = session.barrier_state.kem_tree_hash_after;
    let snapshot_prev = client
        .barrier_fetch_public_tree(room_id, &h_prev)
        .await
        .map_err(|err| anyhow!("barrier tree snapshot auth failure (960.9): {err}"))?;
    if snapshot_prev.n_max != n_max {
        return Err(anyhow!(
            "barrier tree snapshot auth failure (960.9): n_max mismatch (expected {n_max}, got {})",
            snapshot_prev.n_max
        ));
    }
    validate_barrier_tree_snapshot_auth(&h_prev, n_max, &snapshot_prev)?;

    let revoked_since_root =
        header_bytes32(header_map, hdr::HDR_REVOKED_SINCE_ROOT).ok_or_else(|| {
            anyhow!(
                "barrier full chain-check prevalidation failed (960.7): missing revoked_since_root"
            )
        })?;
    let revoked_root = header_bytes32(header_map, hdr::HDR_REVOKED_ROOT).ok_or_else(|| {
        anyhow!("barrier full chain-check prevalidation failed (960.7): missing revoked_root")
    })?;
    let revocation_roots_hash = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    if parsed.revocation_roots_hash != revocation_roots_hash {
        return Err(anyhow!(
            "barrier full chain-check prevalidation failed (960.7): revocation_roots_hash mismatch"
        ));
    }
    let join_records = client
        .barrier_resolve_joins_since(room_id, parsed.prev_barrier_version)
        .await
        .map_err(|err| anyhow!("barrier full chain-check dependency failure (960.8): {err}"))?;
    let revoked_indices = client
        .barrier_resolve_revoked_leaves(room_id, &revocation_roots_hash)
        .await
        .map_err(|err| anyhow!("barrier full chain-check dependency failure (960.8): {err}"))?;

    if !genesis_local_case {
        if session.barrier_state.barrier_roots_hash == parsed.revocation_roots_hash {
            let expected_reason =
                expected_same_rrh_barrier_reason(join_records.as_slice(), parsed.updater_leaf);
            if barrier_reason != expected_reason {
                return Err(anyhow!(
                    "barrier full chain-check prevalidation failed (960.7): local barrier_roots_hash unchanged but barrier_update_reason != {expected_reason}"
                ));
            }
        } else if barrier_reason != 0 {
            return Err(anyhow!(
                "barrier full chain-check prevalidation failed (960.7): local barrier_roots_hash changed but barrier_update_reason != 0"
            ));
        }
    }

    let parsed_for_hash = parsed.clone();
    let snapshot_prev_entries = snapshot_prev.pk_entries.clone();
    let (expected_before, expected_after) =
        tokio::task::spawn_blocking(move || -> Result<([u8; 32], [u8; 32])> {
            let mut snapshot_pre = snapshot_prev_entries;
            apply_join_set_to_snapshot(
                snapshot_pre.as_mut_slice(),
                n_max,
                join_records.as_slice(),
            )?;
            apply_revoked_set_to_snapshot(
                snapshot_pre.as_mut_slice(),
                n_max,
                revoked_indices.as_slice(),
            )?;
            let expected_before = compute_barrier_tree_hash(n_max, snapshot_pre.as_slice())?;

            let mut snapshot_post = snapshot_pre;
            for (node, ek) in &parsed_for_hash.new_public_keys {
                let index = usize::try_from(*node)
                    .map_err(|_| anyhow!("barrier node index out of range"))?;
                let slot = snapshot_post
                    .get_mut(index)
                    .ok_or_else(|| anyhow!("barrier node index out of range"))?;
                *slot = ek.clone();
            }
            let expected_after = compute_barrier_tree_hash(n_max, snapshot_post.as_slice())?;

            Ok((expected_before, expected_after))
        })
        .await
        .map_err(|err| anyhow!("barrier full chain-check worker join failure (960.8): {err}"))??;

    if expected_before != parsed.kem_tree_hash_before {
        return Err(anyhow!(
            "barrier tree hash-chain failure (960.8): kem_tree_hash_before mismatch"
        ));
    }
    if expected_after != parsed.kem_tree_hash_after {
        return Err(anyhow!(
            "barrier tree hash-chain failure (960.8): kem_tree_hash_after mismatch"
        ));
    }

    Ok(expected_before)
}

fn self_path_nodes(n_max: u64, cover_leaf_index: u64) -> Vec<u64> {
    let leaf_base = n_max.saturating_sub(1);
    let mut path = vec![leaf_base.saturating_add(cover_leaf_index)];
    while let Some(&node) = path.last() {
        if node == 0 {
            break;
        }
        path.push((node - 1) / 2);
    }
    path
}

fn derive_k_fs_after_pcs(
    k_fs_before: &[u8; 32],
    weid: &[u8; 32],
    fs_ec: u64,
    barrier_version: u64,
    k_barrier_new: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(k_fs_before);
    ikm[32..].copy_from_slice(k_barrier_new);
    let salt = h_l(
        "fs/pcs/salt",
        &FsPcsSaltPreimage(weid, fs_ec, barrier_version),
    )
    .map_err(|err| anyhow!("derive fs pcs salt: {err}"))?;
    Ok(hkdf_blake3(&salt, &ikm, FS_PCS_INFO))
}

fn derive_internal_node_key_material(
    path_secret: &[u8; 32],
    barrier_version: u64,
    revocation_roots_hash: &[u8; 32],
    n_max: u64,
    node: u64,
) -> Result<(Vec<u8>, [u8; 32], Vec<u8>)> {
    let d_salt = h_l(
        "barrier/keygen/d_salt",
        &BarrierKeygenSaltPreimage(barrier_version, revocation_roots_hash, n_max, node),
    )
    .map_err(|err| anyhow!("derive barrier keygen d_salt: {err}"))?;
    let z_salt = h_l(
        "barrier/keygen/z_salt",
        &BarrierKeygenSaltPreimage(barrier_version, revocation_roots_hash, n_max, node),
    )
    .map_err(|err| anyhow!("derive barrier keygen z_salt: {err}"))?;
    let d = hkdf_blake3(&d_salt, path_secret, BARRIER_KEYGEN_D_INFO);
    let z = hkdf_blake3(&z_salt, path_secret, BARRIER_KEYGEN_Z_INFO);
    let mut seed_bytes = [0u8; ML_KEM_SEED_BYTES];
    seed_bytes[..32].copy_from_slice(&d);
    seed_bytes[32..].copy_from_slice(&z);

    let dk = MlKem768DecapsulationKey::from_seed(MlKemSeed::from(seed_bytes));
    #[allow(deprecated)]
    let dk_expanded =
        <MlKem768DecapsulationKey as ml_kem::ExpandedKeyEncoding>::to_expanded_bytes(&dk);
    let ek_bytes = dk.encapsulation_key().to_bytes();
    let pkhash = compute_barrier_pkhash(ek_bytes.as_slice())?;
    Ok((
        dk_expanded.as_slice().to_vec(),
        pkhash,
        ek_bytes.as_slice().to_vec(),
    ))
}

fn decapsulate_internal_node_shared_secret(
    dk_expanded_bytes: &[u8],
    kem_ct: &[u8],
) -> Result<[u8; 32]> {
    let expanded: MlKemExpandedDecapsulationKey<ml_kem_768::MlKem768> = dk_expanded_bytes
        .try_into()
        .map_err(|_| anyhow!("internal dk_n must be 2400 bytes"))?;
    #[allow(deprecated)]
    let dk =
        <MlKem768DecapsulationKey as ml_kem::ExpandedKeyEncoding>::from_expanded_bytes(&expanded)
            .map_err(|_| anyhow!("invalid internal dk_n encoding"))?;
    let shared = dk
        .decapsulate_slice(kem_ct)
        .map_err(|_| anyhow!("invalid internal node ciphertext"))?;
    let mut ss = [0u8; 32];
    ss.copy_from_slice(shared.as_slice());
    Ok(ss)
}

fn try_recover_barrier_from_header_with_expected_before(
    session: &AppSession,
    header_map: &BTreeMap<u64, Value>,
    weid: &[u8; 32],
    fs_ec: u64,
    max_barrier_update_bytes: usize,
    expected_before_hash: Option<[u8; 32]>,
) -> Result<Option<BarrierRecoverResult>> {
    try_recover_barrier_inner(
        session,
        header_map,
        weid,
        fs_ec,
        max_barrier_update_bytes,
        expected_before_hash,
        false,
    )
}

/// Best-effort barrier recovery that skips local version progression and
/// hash-chain checks.  Used when the client is behind by multiple barrier
/// versions and cannot validate the chain, but can still attempt to decrypt
/// the barrier update using its leaf KEM key.
fn try_recover_barrier_best_effort(
    session: &AppSession,
    header_map: &BTreeMap<u64, Value>,
    weid: &[u8; 32],
    fs_ec: u64,
    max_barrier_update_bytes: usize,
) -> Result<Option<BarrierRecoverResult>> {
    try_recover_barrier_inner(
        session,
        header_map,
        weid,
        fs_ec,
        max_barrier_update_bytes,
        None,
        true,
    )
}

fn apply_recovered_barrier_state(
    session: &mut AppSession,
    recovered: BarrierRecoverResult,
) -> Result<()> {
    let BarrierRecoverResult {
        k_barrier_new,
        k_fs_after_pcs,
        derived_node_key_material,
        ..
    } = recovered;
    session.barrier_state.barrier_initialized = true;
    session.barrier_state.barrier_roots_hash =
        compute_revocation_roots_hash(&session.revoked_since_root, &session.revoked_root)?;
    session.barrier_state.k_barrier = k_barrier_new;
    for (node, material) in derived_node_key_material {
        session.barrier_state.dk_nodes.insert(node, material);
    }
    if let Some(k_fs_after_pcs) = k_fs_after_pcs {
        apply_forward_state_k_fs(session, *k_fs_after_pcs);
    }
    session.barrier_state.barrier_recovery_pending = false;
    Ok(())
}

fn enter_barrier_recovery_pending(session: &mut AppSession) -> Result<()> {
    session.barrier_state.barrier_initialized = true;
    session.barrier_state.barrier_roots_hash =
        compute_revocation_roots_hash(&session.revoked_since_root, &session.revoked_root)?;
    session.barrier_state.barrier_recovery_pending = true;
    Ok(())
}

fn try_recover_barrier_inner(
    session: &AppSession,
    header_map: &BTreeMap<u64, Value>,
    weid: &[u8; 32],
    fs_ec: u64,
    max_barrier_update_bytes: usize,
    expected_before_hash: Option<[u8; 32]>,
    skip_local_checks: bool,
) -> Result<Option<BarrierRecoverResult>> {
    if max_barrier_update_bytes == 0 {
        return Err(anyhow!("max_barrier_update_bytes must be positive"));
    }

    let raw_update = match header_map.get(&hdr::HDR_BARRIER_UPDATE) {
        Some(Value::Bytes(bytes)) => bytes.as_slice(),
        Some(_) => return Err(anyhow!("header barrier_update must be bytes")),
        None => return Ok(None),
    };

    let n_max = session.barrier_state.n_max.max(1);
    let parsed = parse_barrier_update_for_recover(raw_update, n_max, max_barrier_update_bytes)?;

    let valid_progression = (parsed.prev_barrier_version == 0 && parsed.barrier_version == 0)
        || parsed.prev_barrier_version.saturating_add(1) == parsed.barrier_version;
    if !valid_progression {
        return Err(anyhow!("barrier version progression is invalid"));
    }

    if !skip_local_checks {
        let local_barrier_version = session.barrier_state.barrier_version;
        let genesis_local_case = !session.barrier_state.barrier_initialized
            && parsed.prev_barrier_version == 0
            && parsed.barrier_version == 0;
        let valid_local_progression = genesis_local_case
            || (session.barrier_state.barrier_initialized
                && parsed.prev_barrier_version == local_barrier_version
                && parsed.barrier_version == local_barrier_version.saturating_add(1));
        if !valid_local_progression {
            return Err(anyhow!(
                "barrier version progression does not match local barrier state"
            ));
        }
    }

    if parsed.tree_size != n_max {
        return Err(anyhow!("barrier tree_size mismatch for local state"));
    }
    let reason = header_u64(header_map, hdr::HDR_BARRIER_UPDATE_REASON)
        .ok_or_else(|| anyhow!("barrier_update_reason is missing or malformed"))?;

    if !skip_local_checks {
        let required_before_hash =
            expected_before_hash.unwrap_or(session.barrier_state.kem_tree_hash_after);
        if reason != 2 && parsed.kem_tree_hash_before != required_before_hash {
            return Err(anyhow!("barrier hash-chain before-hash mismatch"));
        }
    }

    let revoked_since_root = header_bytes32(header_map, hdr::HDR_REVOKED_SINCE_ROOT)
        .ok_or_else(|| anyhow!("header revoked_since_prev_root is missing or malformed"))?;
    let revoked_root = header_bytes32(header_map, hdr::HDR_REVOKED_ROOT)
        .ok_or_else(|| anyhow!("header revoked_root is missing or malformed"))?;
    let expected_rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    if parsed.revocation_roots_hash != expected_rrh {
        return Err(anyhow!("barrier revocation_roots_hash mismatch"));
    }

    if !skip_local_checks {
        let genesis_local_case = !session.barrier_state.barrier_initialized
            && parsed.prev_barrier_version == 0
            && parsed.barrier_version == 0;
        if !genesis_local_case {
            if session.barrier_state.barrier_roots_hash == parsed.revocation_roots_hash {
                if !matches!(reason, 1 | 2) {
                    return Err(anyhow!(
                        "barrier_update_reason must be pcs_refresh (1) or join_finalize (2) when local barrier_roots_hash is unchanged"
                    ));
                }
            } else if reason != 0 {
                return Err(anyhow!(
                    "barrier_update_reason must be revocation_or_bootstrap (0) when local barrier_roots_hash changed"
                ));
            }
        }
    }

    let author_matches = header_map
        .get(&hdr::HDR_POP_PK)
        .and_then(Value::as_bytes)
        .map(|pk| pk == session.pop_public_key.as_slice())
        .unwrap_or(false);
    if author_matches && parsed.updater_leaf == session.barrier_state.cover_leaf_index {
        return Ok(None);
    }

    let self_path = self_path_nodes(n_max, session.barrier_state.cover_leaf_index);
    let self_path_set: HashSet<u64> = self_path.iter().copied().collect();
    let leaf_node = self_path
        .first()
        .copied()
        .ok_or_else(|| anyhow!("local self path is empty"))?;

    let mut matches: Vec<(u64, u64, [u8; 32])> = Vec::new();
    let mut candidate_decrypt_failure = false;
    for node in &parsed.node_ciphertexts {
        if !self_path_set.contains(&node.target_node) {
            continue;
        }

        let (dk_bytes, pkhash_t) = if node.target_node == leaf_node {
            (
                session.barrier_state.dk_leaf.as_slice(),
                session.barrier_state.pkhash_leaf,
            )
        } else if let Some(material) = session
            .barrier_state
            .dk_nodes
            .get(&(node.target_node as u32))
        {
            (material.dk.as_slice(), material.pkhash)
        } else {
            continue;
        };

        let mut target_prefix = [0u8; 16];
        target_prefix.copy_from_slice(&pkhash_t[..16]);
        if target_prefix != node.target_pk_hash {
            continue;
        }

        let mut ss = if node.target_node == leaf_node {
            if dk_bytes.len() != kyber768::secret_key_bytes() {
                continue;
            }
            let ct = match kyber768::Ciphertext::from_bytes(node.kem_ct.as_slice()) {
                Ok(ct) => ct,
                Err(_) => continue,
            };
            let dk = match kyber768::SecretKey::from_bytes(dk_bytes) {
                Ok(sk) => sk,
                Err(_) => continue,
            };
            let shared = kyber768::decapsulate(&ct, &dk);
            let mut ss = [0u8; 32];
            ss.copy_from_slice(shared.as_bytes());
            ss
        } else if dk_bytes.len() == ML_KEM_EXPANDED_DK_BYTES {
            match decapsulate_internal_node_shared_secret(dk_bytes, node.kem_ct.as_slice()) {
                Ok(ss) => ss,
                Err(_) => {
                    candidate_decrypt_failure = true;
                    continue;
                }
            }
        } else {
            candidate_decrypt_failure = true;
            continue;
        };

        let aad = to_cbor_vec(&BarrierWrapAadPreimage(
            &session.gid,
            parsed.barrier_version,
            &parsed.revocation_roots_hash,
            parsed.updater_leaf,
            node.source_node,
            node.target_node,
            &pkhash_t,
        ))
        .map_err(|err| anyhow!("encode barrier wrap aad: {err}"))?;
        let nonce_full = h_l(
            "barrier/wrap/nonce",
            &BarrierWrapNoncePreimage(node.source_node, node.target_node),
        )
        .map_err(|err| anyhow!("derive barrier wrap nonce: {err}"))?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_full[..12]);

        use chacha20poly1305::{
            ChaCha20Poly1305,
            aead::{Aead, KeyInit, Payload},
        };
        let cipher = ChaCha20Poly1305::new((&ss).into());
        let mut plaintext = match cipher.decrypt(
            (&nonce).into(),
            Payload {
                msg: node.wrapped_ps.as_slice(),
                aad: aad.as_slice(),
            },
        ) {
            Ok(plaintext) => plaintext,
            Err(_) => {
                ss.zeroize();
                candidate_decrypt_failure = true;
                continue;
            }
        };
        ss.zeroize();
        if plaintext.len() != 32 {
            plaintext.zeroize();
            candidate_decrypt_failure = true;
            continue;
        }
        let mut path_secret = [0u8; 32];
        path_secret.copy_from_slice(plaintext.as_slice());
        plaintext.zeroize();
        matches.push((node.source_node, node.target_node, path_secret));
    }

    if matches.is_empty() {
        if candidate_decrypt_failure {
            return Err(anyhow!(
                "barrier recover rejected: candidate unwrap/decrypt failure (960.7)"
            ));
        }
        warn!(
            code = BARRIER_CODE_RECOVER_NO_MATCH,
            "barrier recover produced no matching ciphertext"
        );
        return Ok(None);
    }
    if matches.len() > 1 {
        for (_, _, secret) in &mut matches {
            secret.zeroize();
        }
        return Err(anyhow!("barrier recover rejected: multi-match (960.2)"));
    }

    let (source_node, target_node, source_secret) = matches.remove(0);
    if !self_path_set.contains(&source_node) || !self_path_set.contains(&target_node) {
        return Err(anyhow!(
            "barrier recover rejected: off-path source/target (960.7)"
        ));
    }
    let source_index = parsed
        .path_nodes
        .iter()
        .position(|node| *node == source_node)
        .ok_or_else(|| {
            anyhow!("barrier recover rejected: source missing from path_nodes (960.7)")
        })?;

    let mut path_secrets = BTreeMap::new();
    path_secrets.insert(source_node, source_secret);
    for k in (source_index + 1)..parsed.path_nodes.len() {
        let parent_node = parsed.path_nodes[k];
        let child_node = parsed.path_nodes[k - 1];
        let child_secret = path_secrets
            .get(&child_node)
            .ok_or_else(|| anyhow!("barrier recover missing child path secret"))?;
        let salt = h_l(
            "barrier/tree/path",
            &BarrierTreePathSaltPreimage(parent_node),
        )
        .map_err(|err| anyhow!("derive barrier tree salt: {err}"))?;
        let parent_secret = hkdf_blake3(&salt, child_secret, BARRIER_TREE_INFO);
        path_secrets.insert(parent_node, parent_secret);
    }

    let root_secret = path_secrets
        .get(&0)
        .ok_or_else(|| anyhow!("barrier recover failed to derive root path secret"))?;
    let barrier_salt = h_l(
        "barrier/derive/salt",
        &BarrierDeriveSaltPreimage(parsed.barrier_version, &parsed.revocation_roots_hash),
    )
    .map_err(|err| anyhow!("derive barrier key salt: {err}"))?;
    let k_barrier_new = hkdf_blake3(&barrier_salt, root_secret, BARRIER_KEY_INFO);

    let expected_node_set: HashSet<u64> = parsed.path_nodes.iter().copied().skip(1).collect();
    let mut derived_node_key_material = BTreeMap::new();
    for node in parsed.path_nodes.iter().copied().skip(source_index) {
        if node == leaf_node || !self_path_set.contains(&node) {
            continue;
        }
        let path_secret = path_secrets
            .get(&node)
            .ok_or_else(|| anyhow!("barrier recover missing path secret for node {node}"))?;
        let (dk_bytes, pkhash, ek_bytes) = derive_internal_node_key_material(
            path_secret,
            parsed.barrier_version,
            &parsed.revocation_roots_hash,
            parsed.tree_size,
            node,
        )?;
        if expected_node_set.contains(&node) {
            let announced_ek = parsed.new_public_keys.get(&node).ok_or_else(|| {
                anyhow!("barrier recover rejected: missing new_public_keys for node {node} (960.7)")
            })?;
            if announced_ek.as_slice() != ek_bytes.as_slice() {
                return Err(anyhow!(
                    "barrier recover rejected: new_public_keys mismatch for node {node} (960.7)"
                ));
            }
        }
        let node_index = u32::try_from(node).map_err(|_| anyhow!("barrier node index overflow"))?;
        derived_node_key_material.insert(
            node_index,
            BarrierNodeKeyMaterial {
                dk: Zeroizing::new(dk_bytes),
                pkhash,
            },
        );
    }

    let reason = header_u64(header_map, hdr::HDR_BARRIER_UPDATE_REASON);
    let k_fs_after_pcs = if reason == Some(1) {
        let k_fs_before = session.forward_state.snapshot().k_fs;
        Some(derive_k_fs_after_pcs(
            &k_fs_before,
            weid,
            fs_ec,
            parsed.barrier_version,
            &k_barrier_new,
        )?)
    } else {
        None
    };

    zeroize_path_secret_map(&mut path_secrets);

    Ok(Some(BarrierRecoverResult {
        k_barrier_new: Zeroizing::new(k_barrier_new),
        kem_tree_hash_after: parsed.kem_tree_hash_after,
        k_fs_after_pcs: k_fs_after_pcs.map(Zeroizing::new),
        derived_node_key_material,
    }))
}

#[cfg(test)]
fn try_recover_barrier_from_header(
    session: &AppSession,
    header_map: &BTreeMap<u64, Value>,
    weid: &[u8; 32],
    fs_ec: u64,
    max_barrier_update_bytes: usize,
) -> Result<Option<BarrierRecoverResult>> {
    try_recover_barrier_from_header_with_expected_before(
        session,
        header_map,
        weid,
        fs_ec,
        max_barrier_update_bytes,
        None,
    )
}

fn extract_barrier_update_digest(header: &BTreeMap<u64, Value>) -> Result<Option<[u8; 32]>> {
    match header.get(&hdr::HDR_BARRIER_UPDATE) {
        Some(Value::Bytes(raw)) => Ok(Some(compute_barrier_update_digest(raw)?)),
        Some(_) => Err(anyhow!("header barrier_update must be bytes")),
        None => Ok(None),
    }
}

fn apply_forward_state_k_fs(session: &mut AppSession, k_fs: [u8; 32]) {
    let snapshot = session.forward_state.snapshot();
    let mut updated_state = ForwardSecrecyState::with_state(
        k_fs,
        snapshot.fs_ec,
        session.fs_dev_prev_commit,
        session.we_epoch_id,
    );
    updated_state.set_epoch_base_ts(session.fs_epoch_base_ts);
    session.forward_state = updated_state;
}

fn apply_forward_state_snapshot(
    session: &mut AppSession,
    k_fs: [u8; 32],
    fs_ec: u64,
    fs_dev_commit: [u8; 32],
    last_weid: [u8; 32],
) {
    let mut updated_state = ForwardSecrecyState::with_state(k_fs, fs_ec, fs_dev_commit, last_weid);
    updated_state.set_epoch_base_ts(session.fs_epoch_base_ts);
    session.forward_state = updated_state;
}

fn bundle_authored_by_local_device(session: &AppSession, header: &BTreeMap<u64, Value>) -> bool {
    matches!(
        header.get(&hdr::HDR_POP_PK),
        Some(Value::Bytes(pop_pk)) if pop_pk.as_slice() == session.pop_public_key.as_slice()
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingBarrierHistoryOutcome {
    Unchanged,
    Activated([u8; 32]),
    Discarded,
}

fn apply_pending_barrier_activation(
    session: &mut AppSession,
    observed_barrier_version: u64,
    observed_fs_ec: Option<u64>,
    observed_barrier_update_reason: Option<u64>,
    accepted_digest: Option<[u8; 32]>,
) -> Result<bool> {
    let Some(pending) = session.barrier_state.pending.clone() else {
        return Ok(false);
    };

    if observed_barrier_version < pending.barrier_version {
        return Ok(false);
    }

    if let Some(digest) = accepted_digest
        && digest == pending.barrier_update_digest
        && observed_barrier_version == pending.barrier_version
        && observed_fs_ec == Some(pending.fs_ec)
        && observed_barrier_update_reason == pending.barrier_update_reason
    {
        let BarrierPendingState {
            barrier_version,
            k_barrier_new,
            kem_tree_hash_after,
            k_fs_after_pcs,
            next_forward_fs_ec,
            next_forward_fs_dev_commit,
            next_forward_last_weid,
            revocation_roots_hash,
            on_path_key_material,
            ..
        } = pending;
        session.barrier_state.barrier_initialized = true;
        session.barrier_state.barrier_version = barrier_version;
        session.barrier_state.barrier_roots_hash = revocation_roots_hash;
        session.barrier_state.k_barrier = k_barrier_new;
        session.barrier_state.kem_tree_hash_after = kem_tree_hash_after;
        for (node, material) in on_path_key_material {
            session.barrier_state.dk_nodes.insert(node, material);
        }
        let reseeded_k_fs = k_fs_after_pcs.as_deref().copied();
        if next_forward_fs_ec != 0 {
            let k_fs = reseeded_k_fs.unwrap_or_else(|| session.forward_state.snapshot().k_fs);
            apply_forward_state_snapshot(
                session,
                k_fs,
                next_forward_fs_ec,
                next_forward_fs_dev_commit,
                next_forward_last_weid,
            );
        } else if let Some(k_fs_after_pcs) = reseeded_k_fs {
            apply_forward_state_k_fs(session, k_fs_after_pcs);
        }
        #[cfg(test)]
        fault_injection::trigger_fault(
            FaultInjectionCutPoint::AfterAuthenticatedAcceptBeforePersist,
            None,
        )?;
        session.barrier_state.pending = None;
        session.barrier_state.barrier_recovery_pending = false;
        return Ok(true);
    }

    Ok(false)
}

async fn apply_pending_barrier_activation_from_history(
    client: &CitygApiClient,
    session: &mut AppSession,
    current_barrier_version: u64,
) -> Result<PendingBarrierHistoryOutcome> {
    let Some(pending) = session.barrier_state.pending.clone() else {
        return Ok(PendingBarrierHistoryOutcome::Unchanged);
    };

    if pending.we_epoch_id == [0u8; 32] {
        if current_barrier_version > pending.barrier_version {
            warn!(
                code = BARRIER_CODE_SNAPSHOT_AUTH_FAILURE,
                pending_barrier_version = pending.barrier_version,
                current_barrier_version,
                "pending barrier state predates pending we_epoch_id persistence; discarding after newer barrier version observed"
            );
            session.barrier_state.pending = None;
            return Ok(PendingBarrierHistoryOutcome::Discarded);
        }
        return Ok(PendingBarrierHistoryOutcome::Unchanged);
    }

    match client.get_bundle(&pending.we_epoch_id).await {
        Ok(bundle_response) => {
            let bundle = ClientEpochBundle::from_cbor(&bundle_response.bundle_cbor).context(
                "decode accepted pending bundle for barrier activation correlation (960.9)",
            )?;
            let accepted_digest = extract_barrier_update_digest(&bundle.header_map)?.ok_or_else(|| {
                anyhow!(
                    "pending barrier activation history returned bundle without barrier_update (960.9)"
                )
            })?;
            let observed_barrier_version = header_u64(&bundle.header_map, hdr::HDR_BARRIER_VERSION)
                .ok_or_else(|| {
                    anyhow!("pending barrier activation history missing barrier_version (960.9)")
                })?;
            let observed_fs_ec = header_u64(&bundle.header_map, hdr::HDR_FS_EC);
            let observed_barrier_update_reason =
                header_u64(&bundle.header_map, hdr::HDR_BARRIER_UPDATE_REASON);
            if apply_pending_barrier_activation(
                session,
                observed_barrier_version,
                observed_fs_ec,
                observed_barrier_update_reason,
                Some(accepted_digest),
            )? {
                return Ok(PendingBarrierHistoryOutcome::Activated(bundle.we_epoch_id));
            }
            Err(anyhow!(
                "pending barrier activation history mismatch (960.9): accepted bundle did not match persisted pending state"
            ))
        }
        Err(ApiClientError::HttpStatus { status, .. }) if status.as_u16() == 404 => {
            if current_barrier_version > pending.barrier_version {
                session.barrier_state.pending = None;
                return Ok(PendingBarrierHistoryOutcome::Discarded);
            }
            Ok(PendingBarrierHistoryOutcome::Unchanged)
        }
        Err(err) => Err(anyhow!(
            "pending barrier activation history lookup failed (960.9): {err}"
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_barrier_update_bytes(
    gid: &[u8; 32],
    n_max: u64,
    updater_leaf: u64,
    barrier_version: u64,
    prev_barrier_version: u64,
    revocation_roots_hash: [u8; 32],
    kem_tree_hash_before: [u8; 32],
    snapshot_pre: &[Vec<u8>],
) -> Result<BarrierUpdateBuildResult> {
    if n_max == 0 || !n_max.is_power_of_two() || updater_leaf >= n_max {
        return Err(anyhow!("invalid barrier update tree parameters"));
    }
    let expected_nodes = expected_barrier_tree_nodes(n_max)?;
    if snapshot_pre.len() != expected_nodes {
        return Err(anyhow!(
            "barrier snapshot size mismatch: expected {expected_nodes}, got {}",
            snapshot_pre.len()
        ));
    }

    let leaf_base = n_max.saturating_sub(1);
    let path_nodes = barrier_path_nodes(n_max, updater_leaf)?;

    let mut path_secrets = BTreeMap::new();
    let mut ps_leaf = [0u8; 32];
    rng().fill(&mut ps_leaf);
    path_secrets.insert(path_nodes[0], ps_leaf);
    ps_leaf.zeroize();
    for k in 1..path_nodes.len() {
        let parent_node = path_nodes[k];
        let child_node = path_nodes[k - 1];
        let child_secret = path_secrets
            .get(&child_node)
            .ok_or_else(|| anyhow!("barrier path secret derivation missing child"))?;
        let salt = h_l(
            "barrier/tree/path",
            &BarrierTreePathSaltPreimage(parent_node),
        )
        .map_err(|err| anyhow!("derive barrier tree/path salt: {err}"))?;
        let parent_secret = hkdf_blake3(&salt, child_secret, BARRIER_TREE_INFO);
        path_secrets.insert(parent_node, parent_secret);
    }

    let root_secret = path_secrets
        .get(&0)
        .ok_or_else(|| anyhow!("barrier path secret derivation missing root"))?;
    let barrier_salt = h_l(
        "barrier/derive/salt",
        &BarrierDeriveSaltPreimage(barrier_version, &revocation_roots_hash),
    )
    .map_err(|err| anyhow!("derive barrier/derive/salt: {err}"))?;
    let k_barrier_new = hkdf_blake3(&barrier_salt, root_secret, BARRIER_KEY_INFO);

    let mut expected_nodes: Vec<u64> = path_nodes.iter().copied().skip(1).collect();
    expected_nodes.sort_unstable();
    let mut on_path_key_material = BTreeMap::new();
    let mut new_public_keys = Vec::with_capacity(expected_nodes.len());
    for node in expected_nodes {
        let path_secret = path_secrets
            .get(&node)
            .ok_or_else(|| anyhow!("missing path secret for node {node}"))?;
        let (dk_bytes, pkhash, ek_bytes) = derive_internal_node_key_material(
            path_secret,
            barrier_version,
            &revocation_roots_hash,
            n_max,
            node,
        )?;
        let node_index = u32::try_from(node).map_err(|_| anyhow!("barrier node index overflow"))?;
        on_path_key_material.insert(
            node_index,
            BarrierNodeKeyMaterial {
                dk: Zeroizing::new(dk_bytes),
                pkhash,
            },
        );
        new_public_keys.push(NewPublicKeyWire(node, ek_bytes));
    }

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
            if target_pk.is_empty() {
                return Err(anyhow!("barrier resolution produced blank target node"));
            }
            let target_pkhash = compute_barrier_pkhash(target_pk.as_slice())?;
            let target_ek = kyber768::PublicKey::from_bytes(target_pk.as_slice())
                .map_err(|_| anyhow!("invalid ML-KEM target public key in snapshot_pre"))?;
            let (ss, kem_ct) = kyber768::encapsulate(&target_ek);
            let mut ss_bytes = [0u8; 32];
            ss_bytes.copy_from_slice(ss.as_bytes());

            let aad = to_cbor_vec(&BarrierWrapAadPreimage(
                gid,
                barrier_version,
                &revocation_roots_hash,
                updater_leaf,
                source_node,
                target_node,
                &target_pkhash,
            ))
            .map_err(|err| anyhow!("encode barrier wrap aad: {err}"))?;
            let nonce_full = h_l(
                "barrier/wrap/nonce",
                &BarrierWrapNoncePreimage(source_node, target_node),
            )
            .map_err(|err| anyhow!("derive barrier wrap nonce: {err}"))?;
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&nonce_full[..12]);

            let source_secret = path_secrets
                .get(&source_node)
                .ok_or_else(|| anyhow!("missing path secret for source node {source_node}"))?;
            use chacha20poly1305::{
                ChaCha20Poly1305,
                aead::{Aead, KeyInit, Payload},
            };
            let cipher = ChaCha20Poly1305::new((&ss_bytes).into());
            let wrapped_ps = match cipher.encrypt(
                (&nonce).into(),
                Payload {
                    msg: source_secret.as_slice(),
                    aad: aad.as_slice(),
                },
            ) {
                Ok(wrapped_ps) => wrapped_ps,
                Err(_) => {
                    ss_bytes.zeroize();
                    return Err(anyhow!("barrier wrap encrypt failed"));
                }
            };
            ss_bytes.zeroize();
            node_ciphertexts.push(NodeCiphertextWire(
                source_node,
                target_node,
                target_pkhash[..16].to_vec(),
                KemCiphertext::as_bytes(&kem_ct).to_vec(),
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
    let raw_update = to_cbor_vec(&update).context("encode barrier update")?;
    let barrier_update_digest = compute_barrier_update_digest(raw_update.as_slice())?;
    zeroize_path_secret_map(&mut path_secrets);
    Ok(BarrierUpdateBuildResult {
        raw_update,
        barrier_update_digest,
        kem_tree_hash_after,
        k_barrier_new: Zeroizing::new(k_barrier_new),
        on_path_key_material,
    })
}

#[cfg(not(test))]
pub fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .without_time()
        .init();

    // Load configuration
    let config = match CityGConfig::load() {
        Ok(config) => {
            if let Err(e) = config.validate() {
                eprintln!("Configuration validation failed: {}", e);
                eprintln!("Please check your configuration and try again.");
                std::process::exit(1);
            }
            info!("Configuration loaded successfully");
            config
        }
        Err(e) => {
            warn!("Failed to load configuration: {}, using defaults", e);
            CityGConfig::default()
        }
    };

    Application::new().run(move |app: &mut App| {
        info!("Starting City-G GUI");
        tokio_bridge::init(app);

        let window_options = WindowOptions {
            titlebar: Some(TitlebarOptions {
                title: None,
                appears_transparent: true,
                traffic_light_position: Some(point(px(12.0), px(12.0))),
            }),
            window_decorations: Some(WindowDecorations::Client),
            window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
                None,
                size(
                    px(config.gui.default_window_width),
                    px(config.gui.default_window_height),
                ),
                app,
            ))),
            ..Default::default()
        };

        let config_clone = config.clone();
        let window_result = app.open_window(window_options, |_, cx| {
            let entity = cx.new(|_| AppModel::new(config_clone));
            let weak = entity.downgrade();

            cx.observe_keystrokes(move |event, _, cx| {
                if let Some(view) = weak.upgrade() {
                    view.update(cx, |model, cx| {
                        model.on_keystroke(&event.keystroke, cx);
                    });
                }
            })
            .detach();

            entity
        });

        if let Err(e) = window_result {
            eprintln!("Failed to open application window: {}", e);
            eprintln!("Please check your display settings and try again.");
            std::process::exit(1);
        }

        app.activate(true);
    });
}

struct AppModel {
    config: CityGConfig,
    join_form: JoinFormState,
    join_status: JoinStatus,
    leave_status: LeaveStatus,
    session: Option<AppSession>,
    last_error: Option<String>,
    categorized_error: Option<CategorizedError>,
    info_message: Option<String>,
    toasts: Vec<Toast>,
    messages: Vec<ChatMessageEntry>,
    message_keys: HashSet<MessageKey>,
    next_pending_message_id: u64,
    fetch_status: FetchStatus,
    send_status: SendStatus,
    composer: MessageComposer,
    fetch_task: Option<Task<()>>,
    fetch_in_flight: bool,
    fetch_after_epoch_sync: bool,
    show_ciphertext: bool,
    members: Vec<MemberEntry>,
    members_status: MembersStatus,
    members_total: u64,
    members_next_offset: Option<u64>,
    members_loading_append: bool,
    members_auto_page: bool,
    members_alias_dirty: bool,
    members_mode: MembersMode,
    members_search: MembersSearchState,
    members_refresh_task: Option<Task<()>>,
    alias_bindings: AHashMap<String, AliasBindingRecord>,
    leaf_alias_index: AHashMap<[u8; 32], String>,
    room_admins: Vec<Vec<u8>>,
    room_admins_loaded: bool,
    room_admin_status: RoomAdminStatus,
    room_admin_target: RoomAdminTargetState,
    room_admin_revoke_confirmation: Option<Vec<u8>>,
    epoch_sync_task: Option<Task<()>>, // Background task for membership-driven epoch sync
    ws_task: Option<Task<()>>,         // WebSocket connection task
    ws_connected: bool,                // WebSocket connection status
    ws_autostart_attempted: bool,
    restore_epoch_sync_pending: bool,
    last_retry_action: Option<RetryAction>, // Track what action to retry
    security_events: Vec<SecurityEvent>,
    security_unread: u32,
    security_panel_expanded: bool,
    activity_events: Vec<ActivityEvent>,
    chat_scroll_handle: ScrollHandle,
    right_sidebar_scroll_handle: ScrollHandle,
}

enum JoinStatus {
    Idle,
    Joining,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LeaveStatus {
    Idle,
    Leaving,
    Refreshing,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FetchStatus {
    Idle,
    Refreshing,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SendStatus {
    Idle,
    Sending,
}

#[derive(Clone, PartialEq, Eq)]
enum RoomAdminStatus {
    Idle,
    Loading(String),
    Error(String),
}

enum WebSocketEvent {
    Connected,
    Disconnected,
    Message,
    Membership(MembershipSignal),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MembershipSignalKind {
    Join,
    Revoke,
}

#[derive(Clone, Copy, Debug)]
struct MembershipSignal {
    gid: [u8; 32],
    leaf_id: Option<[u8; 32]>,
    kind: Option<MembershipSignalKind>,
    timestamp_ms: Option<u64>,
}

async fn run_websocket_worker(
    ws_url: String,
    message_token: Option<String>,
    reconnect_delay: Duration,
    tx: futures_mpsc::UnboundedSender<WebSocketEvent>,
) -> Result<()> {
    loop {
        debug!("Attempting WebSocket connection to {}", ws_url);

        let request = websocket_request(&ws_url, message_token.as_deref())?;
        match connect_async(request).await {
            Ok((ws_stream, _)) => {
                info!("WebSocket connected successfully");
                if tx.unbounded_send(WebSocketEvent::Connected).is_err() {
                    return Ok(());
                }

                let (_write, mut read) = ws_stream.split();
                while let Some(msg_result) = read.next().await {
                    match msg_result {
                        Ok(WsMessage::Text(text)) => {
                            debug!("WebSocket message received: {}", text);
                            if let Ok(notification) =
                                serde_json::from_str::<serde_json::Value>(&text)
                            {
                                match notification.get("type").and_then(|t| t.as_str()) {
                                    Some("message") => {
                                        if tx.unbounded_send(WebSocketEvent::Message).is_err() {
                                            return Ok(());
                                        }
                                    }
                                    Some("membership") => {
                                        if let Some(gid_hex) =
                                            notification.get("gid").and_then(|v| v.as_str())
                                            && let Some(gid) = decode_hex_32(gid_hex)
                                        {
                                            let signal = MembershipSignal {
                                                gid,
                                                leaf_id: notification
                                                    .get("leaf_id")
                                                    .and_then(|v| v.as_str())
                                                    .and_then(decode_hex_32),
                                                kind: match notification
                                                    .get("event")
                                                    .and_then(|v| v.as_str())
                                                {
                                                    Some("join") => {
                                                        Some(MembershipSignalKind::Join)
                                                    }
                                                    Some("revoke") => {
                                                        Some(MembershipSignalKind::Revoke)
                                                    }
                                                    _ => None,
                                                },
                                                timestamp_ms: notification
                                                    .get("timestamp_ms")
                                                    .and_then(|v| v.as_u64()),
                                            };
                                            if tx
                                                .unbounded_send(WebSocketEvent::Membership(signal))
                                                .is_err()
                                            {
                                                return Ok(());
                                            }
                                        }
                                    }
                                    Some("lag") => {
                                        warn!("WebSocket lag notification: {}", text);
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Ok(WsMessage::Close(_)) => {
                            info!("WebSocket closed by server");
                            break;
                        }
                        Ok(WsMessage::Ping(_)) | Ok(WsMessage::Pong(_)) => {
                            debug!("WebSocket ping/pong");
                        }
                        Err(e) => {
                            warn!("WebSocket error: {}", e);
                            break;
                        }
                        _ => {}
                    }
                }
                info!(
                    "WebSocket connection closed, will retry in {:?}",
                    reconnect_delay
                );
            }
            Err(e) => {
                warn!("WebSocket connection failed: {}", e);
            }
        }

        if tx.unbounded_send(WebSocketEvent::Disconnected).is_err() {
            return Ok(());
        }

        sleep(reconnect_delay).await;
    }
}

fn websocket_request(ws_url: &str, token: Option<&str>) -> Result<Request<()>> {
    let mut request = ws_url
        .into_client_request()
        .map_err(|err| anyhow!("failed to build websocket handshake request: {err}"))?;
    if let Some(token) = token {
        let token =
            HeaderValue::from_str(token).context("message auth token is not a valid header")?;
        request.headers_mut().insert("x-cityg-message-token", token);
    }
    Ok(request)
}

#[derive(Clone, PartialEq, Eq)]
enum MembersStatus {
    Idle,
    Loading(String),
    Error(String),
}

// Error categorization for user-friendly error handling
#[derive(Debug, Clone, PartialEq, Eq)]
enum ErrorCategory {
    Network,
    Crypto,
    Policy,
    Server,
    Validation,
}

#[derive(Debug, Clone)]
struct CategorizedError {
    category: ErrorCategory,
    user_message: String,
    technical_details: String,
    recovery_suggestion: String,
    can_retry: bool,
}

impl CategorizedError {
    fn new(
        category: ErrorCategory,
        user_message: impl Into<String>,
        technical_details: impl Into<String>,
        recovery_suggestion: impl Into<String>,
        can_retry: bool,
    ) -> Self {
        Self {
            category,
            user_message: user_message.into(),
            technical_details: technical_details.into(),
            recovery_suggestion: recovery_suggestion.into(),
            can_retry,
        }
    }
}

// Toast notification system
#[derive(Debug, Clone, PartialEq)]
enum ToastKind {
    Success,
    Error,
    Info,
}

#[derive(Debug, Clone)]
struct Toast {
    kind: ToastKind,
    message: String,
    created_at: SystemTime,
    duration_secs: u64,
}

impl Toast {
    fn success(message: impl Into<String>) -> Self {
        Self {
            kind: ToastKind::Success,
            message: message.into(),
            created_at: SystemTime::now(),
            duration_secs: 4,
        }
    }

    fn error(message: impl Into<String>) -> Self {
        Self {
            kind: ToastKind::Error,
            message: message.into(),
            created_at: SystemTime::now(),
            duration_secs: 6,
        }
    }

    fn info(message: impl Into<String>) -> Self {
        Self {
            kind: ToastKind::Info,
            message: message.into(),
            created_at: SystemTime::now(),
            duration_secs: 3,
        }
    }

    fn is_expired(&self) -> bool {
        SystemTime::now()
            .duration_since(self.created_at)
            .map(|d| d.as_secs() >= self.duration_secs)
            .unwrap_or(true)
    }
}

// Track which action can be retried
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryAction {
    Join,
    Send,
    Leave,
    Refresh,
}

#[derive(Clone, Default)]
struct MessageComposer {
    text: String,
    active: bool,
}

// Configuration constants have been moved to cityg_config
// These are kept as fallback if needed but should use config from AppModel

impl MessageComposer {
    fn clear(&mut self) {
        self.text.clear();
    }

    fn is_ready(&self) -> bool {
        !self.text.trim().is_empty()
    }

    fn focus(&mut self) {
        self.active = true;
    }

    fn blur(&mut self) {
        self.active = false;
    }

    fn set_text(&mut self, text: String) {
        self.text = text;
    }

    fn text(&self) -> &str {
        self.text.as_str()
    }

    fn handle_keystroke(&mut self, ks: &Keystroke) -> KeyOutcome {
        if !self.active {
            return KeyOutcome::None;
        }

        if ks.key == "escape" {
            self.blur();
            return KeyOutcome::Updated;
        }

        if ks.key == "return" || ks.key == "enter" {
            if self.is_ready() {
                return KeyOutcome::Submit;
            }
            return KeyOutcome::None;
        }

        if ks.key == "backspace" {
            if !self.text.is_empty() {
                self.text.pop();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "delete" {
            if !self.text.is_empty() {
                self.text.clear();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "space" {
            self.text.push(' ');
            return KeyOutcome::Updated;
        }

        if let Some(ch) = ks.key_char.as_ref() {
            if ks.modifiers.control
                || ks.modifiers.alt
                || ks.modifiers.platform
                || ks.modifiers.function
            {
                return KeyOutcome::None;
            }
            if ch.chars().any(|c| c == '\n' || c == '\r' || c == '\t') {
                return KeyOutcome::None;
            }
            self.text.push_str(ch);
            return KeyOutcome::Updated;
        }

        KeyOutcome::None
    }
}

#[derive(Clone, Default)]
struct MembersSearchState {
    query: String,
    active: bool,
}

impl MembersSearchState {
    fn focus(&mut self) {
        self.active = true;
    }

    fn blur(&mut self) {
        self.active = false;
    }

    fn clear(&mut self) {
        self.query.clear();
    }

    fn set_query(&mut self, query: String) {
        self.query = query;
    }

    fn query(&self) -> &str {
        self.query.as_str()
    }

    fn handle_keystroke(&mut self, ks: &Keystroke) -> KeyOutcome {
        if !self.active {
            return KeyOutcome::None;
        }

        if ks.key == "escape" {
            self.blur();
            return KeyOutcome::Updated;
        }

        if ks.key == "tab" {
            self.blur();
            return KeyOutcome::Updated;
        }

        if ks.key == "return" || ks.key == "enter" {
            return KeyOutcome::Submit;
        }

        if ks.key == "backspace" {
            if !self.query.is_empty() {
                self.query.pop();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "delete" {
            if !self.query.is_empty() {
                self.query.clear();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "space" {
            self.query.push(' ');
            return KeyOutcome::Updated;
        }

        if let Some(ch) = ks.key_char.as_ref() {
            if ks.modifiers.control
                || ks.modifiers.alt
                || ks.modifiers.platform
                || ks.modifiers.function
            {
                return KeyOutcome::None;
            }

            if ch.chars().any(|c| c == '\n' || c == '\r' || c == '\t') {
                return KeyOutcome::None;
            }

            self.query.push_str(ch);
            return KeyOutcome::Updated;
        }

        KeyOutcome::None
    }
}

#[derive(Clone, Default)]
struct RoomAdminTargetState {
    value: String,
    active: bool,
}

impl RoomAdminTargetState {
    fn focus(&mut self) {
        self.active = true;
    }

    fn blur(&mut self) {
        self.active = false;
    }

    fn clear(&mut self) {
        self.value.clear();
    }

    fn set_value(&mut self, value: String) {
        self.value = value;
    }

    fn value(&self) -> &str {
        self.value.as_str()
    }

    fn handle_keystroke(&mut self, ks: &Keystroke) -> KeyOutcome {
        if !self.active {
            return KeyOutcome::None;
        }

        if ks.key == "escape" {
            self.blur();
            return KeyOutcome::Updated;
        }

        if ks.key == "tab" {
            self.blur();
            return KeyOutcome::Updated;
        }

        if ks.key == "return" || ks.key == "enter" {
            return KeyOutcome::Submit;
        }

        if ks.key == "backspace" {
            if !self.value.is_empty() {
                self.value.pop();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "delete" {
            if !self.value.is_empty() {
                self.value.clear();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "space" {
            self.value.push(' ');
            return KeyOutcome::Updated;
        }

        if let Some(ch) = ks.key_char.as_ref() {
            if ks.modifiers.control
                || ks.modifiers.alt
                || ks.modifiers.platform
                || ks.modifiers.function
            {
                return KeyOutcome::None;
            }

            if ch.chars().any(|c| c == '\n' || c == '\r' || c == '\t') {
                return KeyOutcome::None;
            }

            self.value.push_str(ch);
            return KeyOutcome::Updated;
        }

        KeyOutcome::None
    }
}

#[derive(Clone, Default)]
enum MembersMode {
    #[default]
    Full,
    Search {
        query: String,
    },
}

#[derive(Clone)]
struct SecurityEvent {
    alias: String,
    description: String,
    timestamp_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActivityKind {
    Connection,
    Roster,
    Message,
    Sync,
    System,
}

#[derive(Clone, Debug)]
struct ActivityEvent {
    kind: ActivityKind,
    summary: String,
    detail: Option<String>,
    timestamp_ms: u64,
}

#[derive(Clone)]
struct ChatMessageEntry {
    sender_leaf: Option<[u8; 32]>,
    fallback_label: String,
    plaintext: String,
    ciphertext_hex: String,
    timestamp_ms: u64,
    delivery: MessageDelivery,
    pending_id: Option<u64>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MessageDelivery {
    Pending,
    Sent,
    Failed,
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct MessageKey {
    ciphertext_hex: String,
    sender_leaf: Option<[u8; 32]>,
}

#[derive(Clone)]
struct MemberEntry {
    leaf_id: [u8; 32],
    alias: Option<String>,
    pop_public_key: Option<Vec<u8>>,
    join_timestamp_ms: Option<u64>,
    last_seen_timestamp_ms: Option<u64>,
}

#[derive(Clone, PartialEq, Eq)]
struct AliasBindingRecord {
    pop_public_key: Vec<u8>,
    leaf_id: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RoomIdentity {
    pop_public_key: Vec<u8>,
    pop_secret_key: Vec<u8>,
}

#[derive(Clone)]
struct AppSession {
    server_url: String,
    room_id: String,
    alias: String,
    gid: [u8; 32],
    cat: [u8; 32],
    leaf_id: [u8; 32],
    parent_root: [u8; 32],
    join_delta_root: [u8; 32],
    revoked_since_root: [u8; 32],
    revoked_root: [u8; 32],
    regular_fingerprint: Option<[u8; 32]>,
    fs_fingerprint: Option<[u8; 32]>,
    tswe_salt_hash: [u8; 32],
    pox_r_commit: [u8; 32],
    we_epoch_id: [u8; 32],
    xk_hash: [u8; 32],
    epoch_key: [u8; 32],
    forward_state: ForwardSecrecyState,
    fs_ec: u64,
    fs_epoch_commit: [u8; 32],
    fs_dev_prev_commit: [u8; 32],
    fs_epoch_created_at: SystemTime, // Timestamp when current epoch was created
    fs_epoch_rotation_interval_secs: u64, // Epoch rotation interval (default: 300 = 5 min)
    pop_public_key: Vec<u8>,
    pop_secret_key: Vec<u8>,
    msg_sign_public_key: Vec<u8>, // ML-DSA-65 (Dilithium3) for message authentication
    msg_sign_secret_key: Vec<u8>, // ML-DSA-65 (Dilithium3) for message authentication
    vrf_secret_key: Vec<u8>,
    vrf_public_key: Vec<u8>,
    kbroad_public: Vec<u8>,
    bootstrap_public: Vec<u8>,
    proof_mode: String,
    vrf_id: String,
    policy_version: String,
    msphf_crs_id: String,
    msphf_params_id: String,
    fs_policy_version: String,
    fs_epoch_base_ts: u64,
    last_fetch_timestamp_ms: Option<u64>,
    msg_replay_state: MsgReplayState,
    capss_witness: Vec<u8>,
    barrier_state: BarrierSecretState,
}

#[derive(Clone)]
struct BarrierSecretState {
    barrier_initialized: bool,
    barrier_version: u64,
    barrier_roots_hash: [u8; 32],
    k_barrier: Zeroizing<[u8; 32]>,
    kem_tree_hash_after: [u8; 32],
    max_barrier_update_bytes: u64,
    n_max: u64,
    cover_leaf_index: u64,
    dk_leaf: Zeroizing<Vec<u8>>,
    pkhash_leaf: [u8; 32],
    dk_nodes: BTreeMap<u32, BarrierNodeKeyMaterial>,
    pending: Option<BarrierPendingState>,
    barrier_recovery_pending: bool,
}

impl Default for BarrierSecretState {
    fn default() -> Self {
        Self {
            barrier_initialized: false,
            barrier_version: 0,
            barrier_roots_hash: [0u8; 32],
            k_barrier: Zeroizing::new([0u8; 32]),
            kem_tree_hash_after: [0u8; 32],
            max_barrier_update_bytes: 0,
            n_max: DEFAULT_BARRIER_N_MAX,
            cover_leaf_index: 0,
            dk_leaf: Zeroizing::new(Vec::new()),
            pkhash_leaf: [0u8; 32],
            dk_nodes: BTreeMap::new(),
            pending: None,
            barrier_recovery_pending: false,
        }
    }
}

#[derive(Clone, Default, Debug)]
struct BarrierNodeKeyMaterial {
    dk: Zeroizing<Vec<u8>>,
    pkhash: [u8; 32],
}

impl Drop for BarrierNodeKeyMaterial {
    fn drop(&mut self) {
        self.dk.zeroize();
        self.pkhash.zeroize();
    }
}

#[derive(Clone, Default)]
struct BarrierPendingState {
    barrier_version: u64,
    we_epoch_id: [u8; 32],
    fs_ec: u64,
    next_forward_fs_ec: u64,
    next_forward_fs_dev_commit: [u8; 32],
    next_forward_last_weid: [u8; 32],
    revocation_roots_hash: [u8; 32],
    kem_tree_hash_after: [u8; 32],
    k_barrier_new: Zeroizing<[u8; 32]>,
    k_fs_after_pcs: Option<Zeroizing<[u8; 32]>>,
    barrier_update_reason: Option<u64>,
    barrier_update_digest: [u8; 32],
    on_path_key_material: BTreeMap<u32, BarrierNodeKeyMaterial>,
}

#[derive(Clone)]
struct PublishedBarrierMerge {
    bundle: ClientEpochBundle,
    pending_barrier_state: BarrierPendingState,
    forward_state_after: ForwardSecrecyState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BarrierMergeMode {
    PcsRefresh,
    JoinFinalize,
}

impl BarrierMergeMode {
    fn reason(self) -> u64 {
        match self {
            Self::PcsRefresh => 1,
            Self::JoinFinalize => 2,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::PcsRefresh => "refresh",
            Self::JoinFinalize => "join_finalize",
        }
    }

    fn publish_context(self) -> &'static str {
        match self {
            Self::PcsRefresh => "publish PCS refresh",
            Self::JoinFinalize => "publish join finalization barrier update",
        }
    }

    fn persist_context(self) -> &'static str {
        match self {
            Self::PcsRefresh => "persist refreshed room session",
            Self::JoinFinalize => "persist join-finalized room session",
        }
    }

    fn fallback_sync_context(self) -> &'static str {
        match self {
            Self::PcsRefresh => "recover initial barrier state after setup merge",
            Self::JoinFinalize => "recover barrier state after join finalization merge",
        }
    }

    fn still_pending_message(self) -> &'static str {
        match self {
            Self::PcsRefresh => {
                "initial room setup completed but barrier recovery is still pending"
            }
            Self::JoinFinalize => {
                "join finalization completed but barrier recovery is still pending"
            }
        }
    }

    fn build_bundle_context(self) -> &'static str {
        match self {
            Self::PcsRefresh => "failed to build refresh merge bundle",
            Self::JoinFinalize => "failed to build join finalize merge bundle",
        }
    }

    fn accept_bundle_context(self) -> &'static str {
        match self {
            Self::PcsRefresh => "server rejected refresh merge bundle",
            Self::JoinFinalize => "server rejected join finalize merge bundle",
        }
    }

    fn pending_guard_message(self) -> &'static str {
        match self {
            Self::PcsRefresh => {
                "cannot originate PCS refresh while barrier recovery is pending; complete FULL barrier recovery first"
            }
            Self::JoinFinalize => {
                "cannot originate join finalization while barrier recovery is pending without join-finalize eligibility"
            }
        }
    }

    fn reseeds_k_fs(self) -> bool {
        matches!(self, Self::PcsRefresh)
    }
}

impl AppModel {
    fn barrier_recovery_pending(&self) -> bool {
        self.session
            .as_ref()
            .map(|session| session.barrier_state.barrier_recovery_pending)
            .unwrap_or(false)
    }

    fn barrier_recovery_wait_message() -> &'static str {
        "Joined room. Waiting for barrier recovery before messaging."
    }

    fn new(config: CityGConfig) -> Self {
        let mut model = Self {
            config: config.clone(),
            join_form: JoinFormState {
                server: config.client.default_server_url.clone(),
                room_id: AppModel::random_room_id(),
                alias: String::new(),
                active: Some(ActiveField::Alias),
            },
            join_status: JoinStatus::Idle,
            leave_status: LeaveStatus::Idle,
            session: None,
            last_error: None,
            categorized_error: None,
            info_message: None,
            toasts: Vec::new(),
            messages: Vec::new(),
            message_keys: HashSet::new(),
            next_pending_message_id: 1,
            fetch_status: FetchStatus::Idle,
            send_status: SendStatus::Idle,
            composer: MessageComposer::default(),
            fetch_task: None,
            fetch_in_flight: false,
            fetch_after_epoch_sync: false,
            show_ciphertext: false,
            members: Vec::new(),
            members_status: MembersStatus::Idle,
            members_total: 0,
            members_next_offset: None,
            members_loading_append: false,
            members_auto_page: false,
            members_alias_dirty: false,
            members_mode: MembersMode::default(),
            members_search: MembersSearchState::default(),
            members_refresh_task: None,
            alias_bindings: AHashMap::new(),
            leaf_alias_index: AHashMap::new(),
            room_admins: Vec::new(),
            room_admins_loaded: false,
            room_admin_status: RoomAdminStatus::Idle,
            room_admin_target: RoomAdminTargetState::default(),
            room_admin_revoke_confirmation: None,
            epoch_sync_task: None,
            ws_task: None,
            ws_connected: false,
            ws_autostart_attempted: false,
            restore_epoch_sync_pending: false,
            last_retry_action: None,
            security_events: Vec::new(),
            security_unread: 0,
            security_panel_expanded: false,
            activity_events: Vec::new(),
            chat_scroll_handle: ScrollHandle::new(),
            right_sidebar_scroll_handle: ScrollHandle::new(),
        };

        match load_last_session() {
            Ok(Some(saved)) => {
                model.join_form.server = saved.server_url.clone();
                model.join_form.room_id = saved.room_id.clone();
                model.join_form.alias = saved.alias.clone();
                model.join_form.active = None;
                model.session = Some(saved);
                model.hydrate_alias_bindings_from_disk();
                model.load_security_events_from_disk();
                model.info_message = Some("Restored saved session.".to_string());
                model.fetch_status = FetchStatus::Idle;
                model.send_status = SendStatus::Idle;
                model.messages.clear();
                model.message_keys.clear();
                model.composer.clear();
                model.composer.blur();
                model.fetch_task = None;
                model.fetch_in_flight = false;
                model.fetch_after_epoch_sync = false;
                model.show_ciphertext = false;
                model.restore_epoch_sync_pending = true;
            }
            Ok(None) => {}
            Err(err) => {
                warn!("failed to load saved session: {err:?}");
            }
        }

        model
    }
}

#[derive(Clone)]
struct JoinFormState {
    server: String,
    room_id: String,
    alias: String,
    active: Option<ActiveField>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct JoinInvitePayload {
    version: u8,
    server_url: String,
    room_id: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ActiveField {
    Server,
    Room,
    Alias,
}

enum KeyOutcome {
    None,
    Updated,
    Submit,
}

fn is_primary_shortcut(keystroke: &Keystroke, key: &str) -> bool {
    if keystroke.modifiers.alt || keystroke.modifiers.function {
        return false;
    }
    if !(keystroke.modifiers.platform || keystroke.modifiers.control) {
        return false;
    }
    keystroke.key.eq_ignore_ascii_case(key)
}

fn sanitize_clipboard_text(raw: &str) -> String {
    raw.chars()
        .map(|c| match c {
            '\r' | '\n' | '\t' => ' ',
            _ => c,
        })
        .collect()
}

fn build_join_invite(session: &AppSession) -> Result<String> {
    let payload = JoinInvitePayload {
        version: 3,
        server_url: session.server_url.clone(),
        room_id: session.room_id.clone(),
    };
    let encoded = serde_json::to_string(&payload).context("failed to encode room invite")?;
    Ok(format!("{JOIN_INVITE_PREFIX}{encoded}"))
}

fn parse_join_invite(raw: &str) -> Result<Option<JoinInvitePayload>> {
    let trimmed = raw.trim();
    let Some(payload) = trimmed.strip_prefix(JOIN_INVITE_PREFIX) else {
        return Ok(None);
    };

    let invite: JoinInvitePayload =
        serde_json::from_str(payload).context("invalid City-G invite payload")?;
    if invite.version != 1 && invite.version != 2 && invite.version != 3 {
        return Err(anyhow!(
            "unsupported City-G invite version {}",
            invite.version
        ));
    }
    if invite.server_url.trim().is_empty() {
        return Err(anyhow!("invite server URL is missing"));
    }
    if !JoinFormState::is_valid_room_id(invite.room_id.trim()) {
        return Err(anyhow!("invite room ID is not valid"));
    }
    Ok(Some(invite))
}

fn apply_join_field_paste(field: ActiveField, existing: &str, pasted: &str) -> String {
    let sanitized = sanitize_clipboard_text(pasted);
    if field == ActiveField::Room {
        let trimmed = sanitized.trim();
        if JoinFormState::is_valid_room_id(trimmed) {
            return trimmed.to_string();
        }
    }

    let mut updated = existing.to_string();
    updated.push_str(&sanitized);
    updated
}

impl JoinFormState {
    fn apply_invite(&mut self, invite: JoinInvitePayload) -> Result<()> {
        self.server = invite.server_url;
        self.room_id = invite.room_id;
        Ok(())
    }

    fn clear_invite_material(&mut self) {}

    fn is_ready(&self) -> bool {
        let server = self.server.trim();
        let room = self.room_id.trim();
        let alias = self.alias.trim();

        !server.is_empty() && !alias.is_empty() && Self::is_valid_room_id(room)
    }

    fn is_valid_room_id(room: &str) -> bool {
        room.len() == 64 && room.chars().all(|c| c.is_ascii_hexdigit())
    }

    fn field_mut(&mut self, field: ActiveField) -> &mut String {
        match field {
            ActiveField::Server => &mut self.server,
            ActiveField::Room => &mut self.room_id,
            ActiveField::Alias => &mut self.alias,
        }
    }

    fn field(&self, field: ActiveField) -> &str {
        match field {
            ActiveField::Server => self.server.as_str(),
            ActiveField::Room => self.room_id.as_str(),
            ActiveField::Alias => self.alias.as_str(),
        }
    }

    fn next_field(field: ActiveField) -> ActiveField {
        match field {
            ActiveField::Server => ActiveField::Room,
            ActiveField::Room => ActiveField::Alias,
            ActiveField::Alias => ActiveField::Server,
        }
    }

    fn previous_field(field: ActiveField) -> ActiveField {
        match field {
            ActiveField::Server => ActiveField::Alias,
            ActiveField::Room => ActiveField::Server,
            ActiveField::Alias => ActiveField::Room,
        }
    }

    fn handle_keystroke(&mut self, ks: &Keystroke) -> KeyOutcome {
        let Some(active) = self.active else {
            return KeyOutcome::None;
        };

        if ks.key == "tab" {
            let new_field = if ks.modifiers.shift {
                Self::previous_field(active)
            } else {
                Self::next_field(active)
            };
            if self.active != Some(new_field) {
                self.active = Some(new_field);
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "escape" {
            self.active = None;
            return KeyOutcome::Updated;
        }

        if ks.key == "backspace" {
            let field = self.field_mut(active);
            if !field.is_empty() {
                field.pop();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "delete" {
            let field = self.field_mut(active);
            field.clear();
            return KeyOutcome::Updated;
        }

        if ks.key == "return" || ks.key == "enter" {
            if self.is_ready() {
                return KeyOutcome::Submit;
            }
            return KeyOutcome::None;
        }

        if ks.key == "space" {
            // Some layouts report space without key_char.
            let field = self.field_mut(active);
            field.push(' ');
            return KeyOutcome::Updated;
        }

        if let Some(ch) = ks.key_char.as_ref() {
            if ks.modifiers.control
                || ks.modifiers.alt
                || ks.modifiers.platform
                || ks.modifiers.function
            {
                return KeyOutcome::None;
            }

            if ch.chars().any(|c| c == '\n' || c == '\r' || c == '\t') {
                return KeyOutcome::None;
            }

            let field = self.field_mut(active);
            field.push_str(ch);
            return KeyOutcome::Updated;
        }

        KeyOutcome::None
    }

    fn join_params(&self) -> JoinParams {
        JoinParams {
            server_url: self.server.trim().to_string(),
            room_id: self.room_id.trim().to_string(),
            alias: self.alias.trim().to_string(),
        }
    }
}

impl Render for AppModel {
    fn render(&mut self, window: &mut Window, cx: &mut ViewContext<Self>) -> impl IntoElement {
        self.ensure_fetch_loop(cx);
        self.ensure_websocket_task(cx);
        self.ensure_epoch_sync_task(cx);
        self.ensure_members_refresh_task(cx);
        self.ensure_room_admins_loaded(cx);
        self.cleanup_expired_toasts();

        let background = rgb(0x0f1118);
        let has_session = self.session.is_some();
        let body: Div = if let Some(session) = &self.session {
            self.render_session(window, session, cx)
        } else {
            self.render_join(cx)
        };

        let mut root = div()
            .key_context("cityg-root")
            .flex()
            .flex_col()
            .w_full()
            .h_full()
            .bg(background);

        if has_session {
            root = root.child(body);
        } else {
            root = root.items_center().justify_center().child(body);
        }

        // Add toast notifications overlay
        if let Some(toasts) = self.render_toasts() {
            root = root.child(toasts);
        }

        root
    }
}

impl AppModel {
    fn random_room_id() -> String {
        let mut bytes = [0u8; 32];
        rng().fill(&mut bytes);
        hex_encode(bytes)
    }

    fn toast_cleanup_delay() -> Duration {
        #[cfg(test)]
        {
            Duration::from_millis(1)
        }
        #[cfg(not(test))]
        {
            Duration::from_secs(8)
        }
    }

    // Toast notification helpers
    fn show_toast(&mut self, toast: Toast, cx: &mut ViewContext<Self>) {
        self.toasts.push(toast);
        cx.notify();

        let cleanup_delay = Self::toast_cleanup_delay();
        let delay = Tokio::spawn_result(cx, async move {
            sleep(cleanup_delay).await;
            Ok(())
        });

        // Schedule cleanup of expired toasts
        cx.spawn(async move |this, cx| {
            if let Err(err) = delay.await {
                warn!("toast cleanup delay task failed: {err}");
                return;
            }
            let _ = this.update(cx, |model, cx| {
                model.cleanup_expired_toasts();
                cx.notify();
            });
        })
        .detach();
    }

    fn show_success(&mut self, message: impl Into<String>, cx: &mut ViewContext<Self>) {
        self.show_toast(Toast::success(message), cx);
    }

    fn show_error_toast(&mut self, message: impl Into<String>, cx: &mut ViewContext<Self>) {
        self.show_toast(Toast::error(message), cx);
    }

    fn show_info(&mut self, message: impl Into<String>, cx: &mut ViewContext<Self>) {
        self.show_toast(Toast::info(message), cx);
    }

    fn cleanup_expired_toasts(&mut self) {
        self.toasts.retain(|t| !t.is_expired());
    }

    // Set categorized error with automatic retry action tracking
    fn set_error(&mut self, err: &anyhow::Error, context: &str, retry_action: Option<RetryAction>) {
        let categorized = categorize_error(err, context);
        self.last_error = Some(categorized.user_message.clone());
        self.categorized_error = Some(categorized);
        self.last_retry_action = retry_action;
    }

    fn clear_error(&mut self) {
        self.last_error = None;
        self.categorized_error = None;
        self.last_retry_action = None;
    }

    // Render loading spinner with animated appearance
    fn render_spinner(&self) -> Div {
        div()
            .flex()
            .items_center()
            .gap(px(2.0))
            .child(
                div()
                    .text_size(px(16.0))
                    .text_color(rgb(0x72f88e))
                    .child("●"),
            )
            .child(
                div()
                    .text_size(px(16.0))
                    .text_color(rgb(0x5fd87f))
                    .child("●"),
            )
            .child(
                div()
                    .text_size(px(16.0))
                    .text_color(rgb(0x4cb86f))
                    .child("●"),
            )
    }

    // Render categorized error box with actions
    fn render_error_box(&self, cx: &mut ViewContext<Self>) -> Option<Div> {
        let error = self.categorized_error.as_ref()?;

        let (icon, color) = match error.category {
            ErrorCategory::Network => ("⚠", rgb(0xffa500)),
            ErrorCategory::Crypto => ("⚠", rgb(0xff6b6b)),
            ErrorCategory::Policy => ("⛔", rgb(0xff9f68)),
            ErrorCategory::Server => ("⚠", rgb(0xff6b6b)),
            ErrorCategory::Validation => ("ℹ", rgb(0x72a5f8)),
        };

        let mut error_box = div()
            .flex()
            .flex_col()
            .gap(px(12.0))
            .px(px(16.0))
            .py(px(14.0))
            .rounded(px(12.0))
            .bg(rgb(0x1f1f2e))
            .border_1()
            .border_color(color)
            .max_w(px(640.0))
            .child(
                div()
                    .flex()
                    .gap(px(8.0))
                    .items_center()
                    .child(div().text_size(px(18.0)).child(icon))
                    .child(
                        div()
                            .text_size(px(15.0))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(0xf2f4ff))
                            .child(error.user_message.clone()),
                    ),
            )
            .child(
                div()
                    .text_size(px(13.0))
                    .text_color(rgb(0x9aa5d3))
                    .child(error.recovery_suggestion.clone()),
            );

        // Add action buttons row
        let mut action_row = div().flex().flex_wrap().gap(px(8.0)).mt(px(4.0));

        // Primary action: Try Again (if retryable)
        if error.can_retry {
            action_row = action_row.child(
                div()
                    .px(px(14.0))
                    .py(px(8.0))
                    .rounded(px(10.0))
                    .bg(rgb(0x72f88e))
                    .text_color(rgb(0x0f1118))
                    .text_size(px(13.0))
                    .font_weight(FontWeight::MEDIUM)
                    .cursor(CursorStyle::PointingHand)
                    .child("Try Again")
                    .on_mouse_down(MouseButton::Left, cx.listener(Self::on_retry_clicked)),
            );
        }

        // Secondary actions
        action_row = action_row
            .child(
                div()
                    .px(px(14.0))
                    .py(px(8.0))
                    .rounded(px(10.0))
                    .bg(rgb(0x2a3148))
                    .text_color(rgb(0xc8d0e8))
                    .text_size(px(13.0))
                    .cursor(CursorStyle::PointingHand)
                    .child("Copy Details")
                    .on_mouse_down(MouseButton::Left, cx.listener(Self::on_copy_error_details)),
            )
            .child(
                div()
                    .px(px(14.0))
                    .py(px(8.0))
                    .rounded(px(10.0))
                    .bg(rgb(0x2a3148))
                    .text_color(rgb(0xc8d0e8))
                    .text_size(px(13.0))
                    .cursor(CursorStyle::PointingHand)
                    .child("Report Issue")
                    .on_mouse_down(MouseButton::Left, cx.listener(Self::on_report_issue)),
            )
            .child(
                div()
                    .px(px(14.0))
                    .py(px(8.0))
                    .rounded(px(10.0))
                    .bg(rgb(0x1f1f2e))
                    .text_color(rgb(0x9aa5d3))
                    .text_size(px(13.0))
                    .cursor(CursorStyle::PointingHand)
                    .child("Dismiss")
                    .on_mouse_down(MouseButton::Left, cx.listener(Self::on_dismiss_error)),
            );

        error_box = error_box.child(action_row);
        Some(error_box)
    }

    // Render toast notifications
    fn render_toasts(&self) -> Option<Div> {
        if self.toasts.is_empty() {
            return None;
        }

        let mut container = div()
            .absolute()
            .top(px(20.0))
            .right(px(20.0))
            .flex()
            .flex_col()
            .gap(px(8.0));

        for toast in &self.toasts {
            if !toast.is_expired() {
                let (icon, bg_color) = match toast.kind {
                    ToastKind::Success => ("✓", rgb(0x2d5f2d)),
                    ToastKind::Error => ("✗", rgb(0x5f2d2d)),
                    ToastKind::Info => ("ℹ", rgb(0x2d3d5f)),
                };

                container = container.child(
                    div()
                        .flex()
                        .gap(px(10.0))
                        .items_center()
                        .px(px(16.0))
                        .py(px(12.0))
                        .rounded(px(10.0))
                        .bg(bg_color)
                        .border_1()
                        .border_color(rgb(0x3a3a4f))
                        .child(
                            div()
                                .text_size(px(16.0))
                                .text_color(rgb(0xf2f4ff))
                                .child(icon),
                        )
                        .child(
                            div()
                                .text_size(px(14.0))
                                .text_color(rgb(0xf2f4ff))
                                .child(toast.message.clone()),
                        ),
                );
            }
        }

        Some(container)
    }

    fn render_join(&self, cx: &mut ViewContext<Self>) -> Div {
        let heading_color = rgb(0xf2f4ff);
        let subtext_color = rgb(0x9aa5d3);
        let error_color = rgb(0xff6b6b);
        let info_color = rgb(0x72f88e);
        let join_disabled =
            !self.join_form.is_ready() || matches!(self.join_status, JoinStatus::Joining);

        let form = div()
            .flex()
            .flex_col()
            .px(px(40.0))
            .py(px(36.0))
            .gap(px(16.0))
            .rounded(px(18.0))
            .bg(rgb(0x151929))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(4.0))
                    .child(
                        div()
                            .text_size(px(28.0))
                            .font_weight(FontWeight::BOLD)
                            .text_color(heading_color)
                            .child("Join a City-G Room"),
                    )
                    .child(div().text_size(px(14.0)).text_color(subtext_color).child(
                        "Connect to a City-G server, pick your alias, and request a join ticket.",
                    )),
            )
            .child(self.render_field(
                "Server URL",
                &self.join_form.server,
                "https://server.example",
                ActiveField::Server,
                cx,
            ))
            .child(self.render_field(
                "Room ID",
                &self.join_form.room_id,
                "64 hex characters",
                ActiveField::Room,
                cx,
            ))
            .child(
                div()
                    .flex()
                    .justify_between()
                    .items_center()
                    .text_size(px(12.0))
                    .text_color(subtext_color)
                    .child("Paste a City-G invite or enter a 64-character room ID.")
                    .child(
                        div()
                            .px(px(12.0))
                            .py(px(6.0))
                            .rounded(px(10.0))
                            .bg(rgb(0x2a3148))
                            .text_color(rgb(0xf2f4ff))
                            .cursor(CursorStyle::PointingHand)
                            .text_size(px(12.0))
                            .child("Generate new ID")
                            .on_mouse_down(
                                MouseButton::Left,
                                cx.listener(Self::on_generate_room_id),
                            ),
                    ),
            )
            .child(self.render_field(
                "Alias",
                &self.join_form.alias,
                "your name",
                ActiveField::Alias,
                cx,
            ))
            .child({
                let status_text = match self.join_status {
                    JoinStatus::Joining => Some("Requesting join ticket...".to_string()),
                    JoinStatus::Idle => None,
                };
                let mut status_div = div()
                    .flex()
                    .gap(px(6.0))
                    .items_center()
                    .text_size(px(13.0))
                    .text_color(subtext_color);
                if let Some(text) = status_text {
                    status_div = status_div.child(self.render_spinner()).child(text);
                }
                status_div
            })
            .child({
                let mut button = div()
                    .px(px(18.0))
                    .py(px(10.0))
                    .rounded(px(12.0))
                    .text_size(px(16.0))
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(rgb(0x0f1118))
                    .bg(if join_disabled {
                        rgb(0x3a3f57)
                    } else {
                        rgb(0x72f88e)
                    })
                    .cursor(if join_disabled {
                        CursorStyle::Arrow
                    } else {
                        CursorStyle::PointingHand
                    })
                    .child(if matches!(self.join_status, JoinStatus::Joining) {
                        "Joining..."
                    } else {
                        "Join room"
                    });

                if !join_disabled {
                    button =
                        button.on_mouse_down(MouseButton::Left, cx.listener(Self::on_join_clicked));
                }
                button
            });

        let mut root = div()
            .flex()
            .flex_col()
            .items_center()
            .gap(px(20.0))
            .child(form);

        // Show categorized error box if available
        if let Some(error_box) = self.render_error_box(cx) {
            root = root.child(error_box);
        } else if let Some(err) = &self.last_error {
            // Fallback to simple error message if no categorized error
            root = root.child(
                div()
                    .text_size(px(13.0))
                    .text_color(error_color)
                    .child(format!("Join failed: {err}")),
            );
        }

        if let Some(info) = &self.info_message {
            root = root.child(
                div()
                    .text_size(px(13.0))
                    .text_color(info_color)
                    .child(info.clone()),
            );
        }

        root
    }

    fn render_field(
        &self,
        label: &str,
        value: &str,
        placeholder: &str,
        field: ActiveField,
        cx: &mut ViewContext<Self>,
    ) -> Div {
        let is_active = self.join_form.active == Some(field);
        let border = if is_active {
            rgb(0x72f88e)
        } else {
            rgb(0x2a3148)
        };
        let background = if is_active {
            rgb(0x1b2135)
        } else {
            rgb(0x161b2a)
        };
        let text_color = if value.is_empty() {
            rgb(0x5b6584)
        } else {
            rgb(0xf5f7ff)
        };
        let display = if value.is_empty() {
            placeholder.to_string()
        } else {
            value.to_string()
        };

        div()
            .flex()
            .flex_col()
            .gap(px(6.0))
            .child(
                div()
                    .text_size(px(12.0))
                    .text_color(rgb(0x9aa5d3))
                    .child(label.to_string()),
            )
            .child({
                let handler_field = field;
                div()
                    .px(px(14.0))
                    .py(px(10.0))
                    .rounded(px(12.0))
                    .border(px(1.0))
                    .border_color(border)
                    .bg(background)
                    .cursor(CursorStyle::IBeam)
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _, _, cx| {
                            this.focus_field(handler_field, cx);
                        }),
                    )
                    .child(
                        div()
                            .text_size(px(16.0))
                            .text_color(text_color)
                            .child(display),
                    )
            })
    }
}

fn persist_pending_barrier_state_before_publish(
    request: &LeaveRequest,
    pending: BarrierPendingState,
) -> Result<()> {
    let Some(mut session) = load_session_at(&request.server_url, &request.room_id)? else {
        return Err(anyhow!(
            "session snapshot missing before barrier publish; refusing to publish barrier update"
        ));
    };
    if session.gid != request.gid || session.leaf_id != request.leaf_id {
        return Err(anyhow!(
            "session snapshot identity mismatch before barrier publish; refusing to publish barrier update"
        ));
    }
    session.barrier_state.pending = Some(pending);
    persist_session(&session).context("persist pending barrier state before publish")?;
    Ok(())
}

fn persist_activated_joined_session(session: &AppSession) -> Result<()> {
    persist_session(session)?;
    #[cfg(test)]
    fault_injection::trigger_fault(FaultInjectionCutPoint::AfterPersistBeforePendingClear, None)?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct PersistedSession {
    version: u32,
    server_url: String,
    room_id: String,
    alias: String,
    gid_hex: String,
    cat_hex: String,
    leaf_hex: String,
    parent_root_hex: String,
    join_delta_root_hex: String,
    revoked_since_root_hex: String,
    revoked_root_hex: String,
    tswe_salt_hash_hex: String,
    pox_r_commit_hex: String,
    we_epoch_id_hex: String,
    #[serde(default)]
    xk_hash_hex: String,
    epoch_key_hex: String,
    proof_mode: String,
    vrf_id: String,
    policy_version: String,
    msphf_crs_id: String,
    msphf_params_id: String,
    fs_policy_version: String,
    fs_epoch_base_ts: u64,
    kbroad_public_hex: String,
    bootstrap_public_hex: String,
    pop_public_hex: String,
    pop_secret_hex: String,
    msg_sign_public_hex: String,
    msg_sign_secret_hex: String,
    vrf_public_hex: String,
    vrf_secret_hex: String,
    fs_ec: u64,
    fs_epoch_commit_hex: String,
    fs_dev_prev_commit_hex: String,
    #[serde(default)]
    fs_epoch_created_at_unix_ms: u64, // Epoch creation timestamp (milliseconds since UNIX_EPOCH)
    #[serde(default = "default_epoch_rotation_interval")]
    fs_epoch_rotation_interval_secs: u64, // Epoch rotation interval in seconds (default: 300 = 5 min)
    forward_state: PersistedForwardState,
    #[serde(default)]
    last_fetch_timestamp_ms: Option<u64>,

    #[serde(default)]
    msg_replay_state: PersistedMsgReplayState,
    #[serde(default)]
    capss_witness_hex: String,
    #[serde(default)]
    regular_fingerprint_hex: String,
    #[serde(default)]
    barrier_state: PersistedBarrierState,
}

const ROOM_IDENTITY_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct PersistedRoomIdentity {
    version: u32,
    pop_public_hex: String,
    pop_secret_hex: String,
}

const ALIAS_STORE_VERSION: u32 = 2;
const SECURITY_LOG_VERSION: u32 = 1;
const MAX_SECURITY_EVENTS: usize = 128;
const MAX_ACTIVITY_EVENTS: usize = 256;
const UI_CANVAS_BG: u32 = 0x111522;
const UI_SIDEBAR_BG: u32 = 0x151c2f;
const UI_PANEL_BG: u32 = 0x171f33;
const UI_ROW_BG: u32 = 0x1e2940;
const UI_PANEL_BORDER: u32 = 0x2e3d5b;
const UI_BUTTON_BG: u32 = 0x2c3956;
const UI_PANEL_TEXT: u32 = 0xf2f5ff;
const UI_SUBTLE_TEXT: u32 = 0x9eabd2;
const UI_MUTED_TEXT: u32 = 0x7180a5;
const UI_ACCENT_TEXT: u32 = 0x67f3b8;
const UI_ACCENT_BUTTON_TEXT: u32 = 0x122015;
const UI_WARN_TEXT: u32 = 0xffb384;
const ENCRYPTED_SESSION_ENVELOPE_VERSION: u32 = 1;
const ENCRYPTED_SESSION_ALG: &str = "chacha20poly1305";
const SESSION_PASSPHRASE_ENV: &str = "CITYG_GUI_SESSION_PASSPHRASE";
const BARRIER_HP_MODE: &str = "barrier-sealed-v1";
const CLIENT_ADMIN_TOKEN_ENV: &str = "CITYG_CLIENT_ADMIN_TOKEN";
const CLIENT_MESSAGE_TOKEN_ENV: &str = "CITYG_CLIENT_MESSAGE_AUTH_TOKEN";
const SESSION_KEY_DERIVE_CONTEXT: &str = "cityg/gui/session-encryption/v1";
const SESSION_LOCAL_KEY_FILE: &str = "session-key-v1.bin";

#[derive(Serialize, Deserialize, Default)]
struct PersistedAliasStore {
    version: u32,
    bindings: AHashMap<String, PersistedAliasBinding>,
}

#[derive(Serialize, Deserialize, Default)]
struct PersistedAliasBinding {
    pop_public_key_hex: String,
    #[serde(default)]
    leaf_id_hex: String,
}

#[derive(Serialize, Deserialize, Default)]
struct PersistedSecurityLog {
    version: u32,
    events: Vec<PersistedSecurityEvent>,
}

#[derive(Serialize, Deserialize, Default)]
struct PersistedSecurityEvent {
    alias: String,
    description: String,
    timestamp_ms: u64,
}

fn default_epoch_rotation_interval() -> u64 {
    300 // 5 minutes in seconds
}

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

fn default_barrier_n_max() -> u64 {
    DEFAULT_BARRIER_N_MAX
}

fn default_max_barrier_update_bytes() -> u64 {
    0
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

#[derive(Serialize, Deserialize)]
struct PersistedForwardState {
    k_fs_hex: String,
    fs_ec: u64,
    fs_dev_commit_hex: String,
    #[serde(default)]
    fs_last_weid_hex: String,
}

#[derive(Serialize, Deserialize, Default)]
struct PersistedBarrierState {
    #[serde(default)]
    barrier_initialized: bool,
    #[serde(default)]
    barrier_version: u64,
    #[serde(default)]
    barrier_roots_hash_hex: String,
    #[serde(default)]
    k_barrier_hex: String,
    #[serde(default)]
    kem_tree_hash_after_hex: String,
    #[serde(default = "default_max_barrier_update_bytes")]
    max_barrier_update_bytes: u64,
    #[serde(default = "default_barrier_n_max")]
    n_max: u64,
    #[serde(default)]
    cover_leaf_index: u64,
    #[serde(default)]
    dk_leaf_hex: String,
    #[serde(default)]
    pkhash_leaf_hex: String,
    #[serde(default)]
    dk_nodes: BTreeMap<u32, PersistedBarrierNodeKeyMaterial>,
    #[serde(default)]
    pending: Option<PersistedBarrierPendingState>,
    #[serde(default = "default_barrier_recovery_pending")]
    barrier_recovery_pending: bool,
}

fn default_barrier_recovery_pending() -> bool {
    false
}

#[derive(Serialize, Deserialize, Default)]
struct PersistedBarrierNodeKeyMaterial {
    #[serde(default)]
    dk_hex: String,
    #[serde(default)]
    pkhash_hex: String,
}

#[derive(Serialize, Deserialize, Default)]
struct PersistedBarrierPendingState {
    #[serde(default)]
    barrier_version: u64,
    #[serde(default)]
    we_epoch_id_hex: String,
    #[serde(default)]
    fs_ec: u64,
    #[serde(default)]
    next_forward_fs_ec: u64,
    #[serde(default)]
    next_forward_fs_dev_commit_hex: String,
    #[serde(default)]
    next_forward_last_weid_hex: String,
    #[serde(default)]
    revocation_roots_hash_hex: String,
    #[serde(default)]
    kem_tree_hash_after_hex: String,
    #[serde(default)]
    k_barrier_new_hex: String,
    #[serde(default)]
    k_fs_after_pcs_hex: String,
    #[serde(default)]
    barrier_update_reason: Option<u64>,
    #[serde(default)]
    barrier_update_digest_hex: String,
    #[serde(default)]
    on_path_key_material: BTreeMap<u32, PersistedBarrierNodeKeyMaterial>,
}

#[derive(Serialize, Deserialize)]
struct EncryptedSessionEnvelope {
    version: u32,
    alg: String,
    key_source: String,
    nonce_hex: String,
    ciphertext_hex: String,
}

#[derive(Clone, Copy)]
enum SessionKeySource {
    EnvPassphrase,
    LocalKeyFile,
}

impl SessionKeySource {
    fn as_str(self) -> &'static str {
        match self {
            SessionKeySource::EnvPassphrase => "env-passphrase",
            SessionKeySource::LocalKeyFile => "local-key-file",
        }
    }
}

#[derive(Serialize, Deserialize)]
struct LastSessionPointer {
    server_url: String,
    room_id: String,
}

impl PersistedRoomIdentity {
    fn from_runtime(identity: &RoomIdentity) -> Self {
        Self {
            version: ROOM_IDENTITY_VERSION,
            pop_public_hex: hex_encode(&identity.pop_public_key),
            pop_secret_hex: hex_encode(&identity.pop_secret_key),
        }
    }

    fn into_runtime(self) -> Result<RoomIdentity> {
        if self.version != ROOM_IDENTITY_VERSION {
            return Err(anyhow!(
                "unsupported room identity file version {} (expected {})",
                self.version,
                ROOM_IDENTITY_VERSION
            ));
        }

        Ok(RoomIdentity {
            pop_public_key: decode_hex_vec("pop_public_hex", &self.pop_public_hex)?,
            pop_secret_key: decode_hex_vec("pop_secret_hex", &self.pop_secret_hex)?,
        })
    }
}

impl PersistedBarrierNodeKeyMaterial {
    fn from_runtime(material: &BarrierNodeKeyMaterial) -> Self {
        Self {
            dk_hex: hex_encode(material.dk.as_slice()),
            pkhash_hex: hex_encode(material.pkhash),
        }
    }

    fn into_runtime(self, field_prefix: &str) -> Result<BarrierNodeKeyMaterial> {
        let dk = decode_hex_vec(&format!("{field_prefix}.dk_hex"), &self.dk_hex)?;
        let pkhash = decode_hex32_or_zero(&format!("{field_prefix}.pkhash_hex"), &self.pkhash_hex)?;
        Ok(BarrierNodeKeyMaterial {
            dk: Zeroizing::new(dk),
            pkhash,
        })
    }
}

impl PersistedBarrierPendingState {
    fn from_runtime(pending: &BarrierPendingState) -> Self {
        let on_path_key_material = pending
            .on_path_key_material
            .iter()
            .map(|(node, material)| {
                (
                    *node,
                    PersistedBarrierNodeKeyMaterial::from_runtime(material),
                )
            })
            .collect();
        Self {
            barrier_version: pending.barrier_version,
            we_epoch_id_hex: hex_encode(pending.we_epoch_id),
            fs_ec: pending.fs_ec,
            next_forward_fs_ec: pending.next_forward_fs_ec,
            next_forward_fs_dev_commit_hex: hex_encode(pending.next_forward_fs_dev_commit),
            next_forward_last_weid_hex: hex_encode(pending.next_forward_last_weid),
            revocation_roots_hash_hex: hex_encode(pending.revocation_roots_hash),
            kem_tree_hash_after_hex: hex_encode(pending.kem_tree_hash_after),
            k_barrier_new_hex: hex_encode(*pending.k_barrier_new),
            k_fs_after_pcs_hex: pending
                .k_fs_after_pcs
                .as_ref()
                .map(|value| hex_encode(**value))
                .unwrap_or_default(),
            barrier_update_reason: pending.barrier_update_reason,
            barrier_update_digest_hex: hex_encode(pending.barrier_update_digest),
            on_path_key_material,
        }
    }

    fn into_runtime(self) -> Result<BarrierPendingState> {
        let mut on_path_key_material = BTreeMap::new();
        for (node, material) in self.on_path_key_material {
            on_path_key_material.insert(
                node,
                material.into_runtime(&format!(
                    "barrier_state.pending.on_path_key_material[{node}]"
                ))?,
            );
        }
        let k_fs_after_pcs = if self.k_fs_after_pcs_hex.is_empty() {
            None
        } else {
            Some(decode_hex32(
                "barrier_state.pending.k_fs_after_pcs_hex",
                &self.k_fs_after_pcs_hex,
            )?)
        };
        Ok(BarrierPendingState {
            barrier_version: self.barrier_version,
            we_epoch_id: decode_hex32_or_zero(
                "barrier_state.pending.we_epoch_id_hex",
                &self.we_epoch_id_hex,
            )?,
            fs_ec: self.fs_ec,
            next_forward_fs_ec: self.next_forward_fs_ec,
            next_forward_fs_dev_commit: decode_hex32_or_zero(
                "barrier_state.pending.next_forward_fs_dev_commit_hex",
                &self.next_forward_fs_dev_commit_hex,
            )?,
            next_forward_last_weid: decode_hex32_or_zero(
                "barrier_state.pending.next_forward_last_weid_hex",
                &self.next_forward_last_weid_hex,
            )?,
            revocation_roots_hash: decode_hex32_or_zero(
                "barrier_state.pending.revocation_roots_hash_hex",
                &self.revocation_roots_hash_hex,
            )?,
            kem_tree_hash_after: decode_hex32_or_zero(
                "barrier_state.pending.kem_tree_hash_after_hex",
                &self.kem_tree_hash_after_hex,
            )?,
            k_barrier_new: decode_hex32_or_zero(
                "barrier_state.pending.k_barrier_new_hex",
                &self.k_barrier_new_hex,
            )
            .map(Zeroizing::new)?,
            k_fs_after_pcs: k_fs_after_pcs.map(Zeroizing::new),
            barrier_update_reason: self.barrier_update_reason,
            barrier_update_digest: decode_hex32_or_zero(
                "barrier_state.pending.barrier_update_digest_hex",
                &self.barrier_update_digest_hex,
            )?,
            on_path_key_material,
        })
    }
}

impl PersistedBarrierState {
    fn from_runtime(state: &BarrierSecretState) -> Self {
        let dk_nodes = state
            .dk_nodes
            .iter()
            .map(|(node, material)| {
                (
                    *node,
                    PersistedBarrierNodeKeyMaterial::from_runtime(material),
                )
            })
            .collect();
        Self {
            barrier_initialized: state.barrier_initialized,
            barrier_version: state.barrier_version,
            barrier_roots_hash_hex: hex_encode(state.barrier_roots_hash),
            k_barrier_hex: hex_encode(*state.k_barrier),
            kem_tree_hash_after_hex: hex_encode(state.kem_tree_hash_after),
            max_barrier_update_bytes: state.max_barrier_update_bytes,
            n_max: state.n_max.max(1),
            cover_leaf_index: state.cover_leaf_index,
            dk_leaf_hex: hex_encode(state.dk_leaf.as_slice()),
            pkhash_leaf_hex: hex_encode(state.pkhash_leaf),
            dk_nodes,
            pending: state
                .pending
                .as_ref()
                .map(PersistedBarrierPendingState::from_runtime),
            barrier_recovery_pending: state.barrier_recovery_pending,
        }
    }

    fn into_runtime(self) -> Result<BarrierSecretState> {
        let mut dk_nodes = BTreeMap::new();
        for (node, material) in self.dk_nodes {
            dk_nodes.insert(
                node,
                material.into_runtime(&format!("barrier_state.dk_nodes[{node}]"))?,
            );
        }
        Ok(BarrierSecretState {
            barrier_initialized: self.barrier_initialized,
            barrier_version: self.barrier_version,
            barrier_roots_hash: decode_hex32_or_zero(
                "barrier_state.barrier_roots_hash_hex",
                &self.barrier_roots_hash_hex,
            )?,
            k_barrier: Zeroizing::new(decode_hex32_or_zero(
                "barrier_state.k_barrier_hex",
                &self.k_barrier_hex,
            )?),
            kem_tree_hash_after: decode_hex32_or_zero(
                "barrier_state.kem_tree_hash_after_hex",
                &self.kem_tree_hash_after_hex,
            )?,
            max_barrier_update_bytes: self.max_barrier_update_bytes,
            n_max: self.n_max.max(1),
            cover_leaf_index: self.cover_leaf_index,
            dk_leaf: Zeroizing::new(decode_hex_vec(
                "barrier_state.dk_leaf_hex",
                &self.dk_leaf_hex,
            )?),
            pkhash_leaf: decode_hex32_or_zero(
                "barrier_state.pkhash_leaf_hex",
                &self.pkhash_leaf_hex,
            )?,
            dk_nodes,
            pending: self
                .pending
                .map(PersistedBarrierPendingState::into_runtime)
                .transpose()?,
            barrier_recovery_pending: self.barrier_recovery_pending,
        })
    }
}

impl PersistedSession {
    fn from_session(session: &AppSession) -> Self {
        let snapshot = session.forward_state.snapshot();
        let fs_epoch_created_at_unix_ms = session
            .fs_epoch_created_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;

        Self {
            version: 12, // Version 12: Persist pending updater we_epoch_id for restart correlation.
            server_url: session.server_url.clone(),
            room_id: session.room_id.clone(),
            alias: session.alias.clone(),
            gid_hex: hex_encode(session.gid),
            cat_hex: hex_encode(session.cat),
            leaf_hex: hex_encode(session.leaf_id),
            parent_root_hex: hex_encode(session.parent_root),
            join_delta_root_hex: hex_encode(session.join_delta_root),
            revoked_since_root_hex: hex_encode(session.revoked_since_root),
            revoked_root_hex: hex_encode(session.revoked_root),
            tswe_salt_hash_hex: hex_encode(session.tswe_salt_hash),
            pox_r_commit_hex: hex_encode(session.pox_r_commit),
            we_epoch_id_hex: hex_encode(session.we_epoch_id),
            xk_hash_hex: hex_encode(session.xk_hash),
            epoch_key_hex: hex_encode(session.epoch_key),
            proof_mode: session.proof_mode.clone(),
            vrf_id: session.vrf_id.clone(),
            policy_version: session.policy_version.clone(),
            msphf_crs_id: session.msphf_crs_id.clone(),
            msphf_params_id: session.msphf_params_id.clone(),
            fs_policy_version: session.fs_policy_version.clone(),
            fs_epoch_base_ts: session.fs_epoch_base_ts,
            kbroad_public_hex: hex_encode(&session.kbroad_public),
            bootstrap_public_hex: hex_encode(&session.bootstrap_public),
            pop_public_hex: hex_encode(&session.pop_public_key),
            pop_secret_hex: hex_encode(&session.pop_secret_key),
            msg_sign_public_hex: hex_encode(&session.msg_sign_public_key),
            msg_sign_secret_hex: hex_encode(&session.msg_sign_secret_key),
            vrf_public_hex: hex_encode(&session.vrf_public_key),
            vrf_secret_hex: hex_encode(&session.vrf_secret_key),
            fs_ec: session.fs_ec,
            fs_epoch_commit_hex: hex_encode(session.fs_epoch_commit),
            fs_dev_prev_commit_hex: hex_encode(session.fs_dev_prev_commit),
            fs_epoch_created_at_unix_ms,
            fs_epoch_rotation_interval_secs: session.fs_epoch_rotation_interval_secs,
            forward_state: PersistedForwardState {
                k_fs_hex: hex_encode(snapshot.k_fs),
                fs_ec: snapshot.fs_ec,
                fs_dev_commit_hex: hex_encode(snapshot.fs_dev_commit),
                fs_last_weid_hex: hex_encode(snapshot.last_weid),
            },
            last_fetch_timestamp_ms: session.last_fetch_timestamp_ms,

            msg_replay_state: PersistedMsgReplayState::from_runtime(&session.msg_replay_state),
            capss_witness_hex: hex_encode(&session.capss_witness),
            regular_fingerprint_hex: session
                .regular_fingerprint
                .as_ref()
                .map(hex_encode)
                .unwrap_or_default(),
            barrier_state: PersistedBarrierState::from_runtime(&session.barrier_state),
        }
    }

    fn into_app_session(self) -> Result<AppSession> {
        let PersistedSession {
            version,
            server_url,
            room_id,
            alias,
            gid_hex,
            cat_hex,
            leaf_hex,
            parent_root_hex,
            join_delta_root_hex,
            revoked_since_root_hex,
            revoked_root_hex,
            tswe_salt_hash_hex,
            pox_r_commit_hex,
            we_epoch_id_hex,
            xk_hash_hex,
            epoch_key_hex,
            proof_mode,
            vrf_id,
            policy_version,
            msphf_crs_id,
            msphf_params_id,
            fs_policy_version,
            fs_epoch_base_ts,
            kbroad_public_hex,
            bootstrap_public_hex,
            pop_public_hex,
            pop_secret_hex,
            msg_sign_public_hex,
            msg_sign_secret_hex,
            vrf_public_hex,
            vrf_secret_hex,
            fs_ec: fs_join_ec,
            fs_epoch_commit_hex,
            fs_dev_prev_commit_hex,
            fs_epoch_created_at_unix_ms,
            fs_epoch_rotation_interval_secs,
            forward_state,
            last_fetch_timestamp_ms,
            msg_replay_state,
            capss_witness_hex,
            regular_fingerprint_hex,
            barrier_state,
        } = self;

        if !(version == 4
            || version == 5
            || version == 6
            || version == 7
            || version == 8
            || version == 9
            || version == 10
            || version == 11
            || version == 12)
        {
            return Err(anyhow!(
                "unsupported session file version {version} (expected 4, 5, 6, 7, 8, 9, 10, 11, or 12 with ML-DSA-65 authentication)"
            ));
        }

        let gid = decode_hex32("gid_hex", &gid_hex)?;
        let cat = decode_hex32("cat_hex", &cat_hex)?;
        let leaf_id = decode_hex32("leaf_hex", &leaf_hex)?;
        let parent_root = decode_hex32("parent_root_hex", &parent_root_hex)?;
        let join_delta_root = decode_hex32("join_delta_root_hex", &join_delta_root_hex)?;
        let revoked_since_root = decode_hex32("revoked_since_root_hex", &revoked_since_root_hex)?;
        let revoked_root = decode_hex32("revoked_root_hex", &revoked_root_hex)?;
        let tswe_salt_hash = decode_hex32("tswe_salt_hash_hex", &tswe_salt_hash_hex)?;
        let pox_r_commit = decode_hex32("pox_r_commit_hex", &pox_r_commit_hex)?;
        let we_epoch_id = decode_hex32("we_epoch_id_hex", &we_epoch_id_hex)?;
        let xk_hash = decode_hex32_or_zero("xk_hash_hex", &xk_hash_hex)?;
        let epoch_key = decode_hex32("epoch_key_hex", &epoch_key_hex)?;

        let kbroad_public = decode_hex_vec("kbroad_public_hex", &kbroad_public_hex)?;
        let bootstrap_public = decode_hex_vec("bootstrap_public_hex", &bootstrap_public_hex)?;
        let pop_public_key = decode_hex_vec("pop_public_hex", &pop_public_hex)?;
        let pop_secret_key = decode_hex_vec("pop_secret_hex", &pop_secret_hex)?;
        let msg_sign_public_key = decode_hex_vec("msg_sign_public_hex", &msg_sign_public_hex)?;
        let msg_sign_secret_key = decode_hex_vec("msg_sign_secret_hex", &msg_sign_secret_hex)?;
        let vrf_public_key = decode_hex_vec("vrf_public_hex", &vrf_public_hex)?;
        let vrf_secret_key = decode_hex_vec("vrf_secret_hex", &vrf_secret_hex)?;
        let fs_epoch_commit = decode_hex32("fs_epoch_commit_hex", &fs_epoch_commit_hex)?;
        let fs_dev_prev_commit = decode_hex32("fs_dev_prev_commit_hex", &fs_dev_prev_commit_hex)?;
        let capss_witness = decode_hex_vec("capss_witness_hex", &capss_witness_hex)?;
        let msg_replay_state = msg_replay_state.into_runtime()?;
        let barrier_state = barrier_state.into_runtime()?;
        let regular_fingerprint = if regular_fingerprint_hex.is_empty() {
            None
        } else {
            Some(decode_hex32(
                "regular_fingerprint_hex",
                &regular_fingerprint_hex,
            )?)
        };
        let PersistedForwardState {
            k_fs_hex,
            fs_ec,
            fs_dev_commit_hex,
            fs_last_weid_hex,
        } = forward_state;

        let k_fs = decode_hex32("forward_state.k_fs_hex", &k_fs_hex)?;
        let fs_dev_commit = decode_hex32("forward_state.fs_dev_commit_hex", &fs_dev_commit_hex)?;
        let fs_last_weid = if fs_last_weid_hex.is_empty() {
            we_epoch_id
        } else {
            decode_hex32("forward_state.fs_last_weid_hex", &fs_last_weid_hex)?
        };
        let forward_state =
            ForwardSecrecyState::with_state(k_fs, fs_ec, fs_dev_commit, fs_last_weid);

        // Restore epoch timestamp, default to now if not persisted or invalid
        let fs_epoch_created_at = if fs_epoch_created_at_unix_ms > 0 {
            UNIX_EPOCH + Duration::from_millis(fs_epoch_created_at_unix_ms)
        } else {
            SystemTime::now()
        };

        let mut session = AppSession {
            server_url,
            room_id,
            alias,
            gid,
            cat,
            leaf_id,
            parent_root,
            join_delta_root,
            revoked_since_root,
            revoked_root,
            regular_fingerprint,
            fs_fingerprint: None,
            tswe_salt_hash,
            pox_r_commit,
            we_epoch_id,
            xk_hash,
            epoch_key,
            forward_state,
            fs_ec: fs_join_ec,
            fs_epoch_commit,
            fs_dev_prev_commit,
            fs_epoch_created_at,
            fs_epoch_rotation_interval_secs,
            pop_public_key,
            pop_secret_key,
            msg_sign_public_key,
            msg_sign_secret_key,
            vrf_secret_key,
            vrf_public_key,
            kbroad_public,
            bootstrap_public,
            proof_mode,
            vrf_id,
            policy_version,
            msphf_crs_id,
            msphf_params_id,
            fs_policy_version,
            fs_epoch_base_ts,
            last_fetch_timestamp_ms,
            msg_replay_state,
            capss_witness,
            barrier_state,
        };

        session.fs_fingerprint = derive_fs_fingerprint_from_fields(
            session.fs_policy_version.as_str(),
            session.fs_ec,
            &session.fs_epoch_commit,
            session.fs_epoch_base_ts,
        );
        let legacy_barrier_state_present = session.barrier_state.barrier_recovery_pending
            || session.barrier_state.barrier_version > 0
            || session.barrier_state.kem_tree_hash_after != [0u8; 32]
            || *session.barrier_state.k_barrier != [0u8; 32]
            || !session.barrier_state.dk_leaf.is_empty()
            || !session.barrier_state.dk_nodes.is_empty();
        if !session.barrier_state.barrier_initialized && legacy_barrier_state_present {
            session.barrier_state.barrier_initialized = true;
        }
        if session.barrier_state.barrier_initialized
            && session.barrier_state.barrier_roots_hash == [0u8; 32]
        {
            session.barrier_state.barrier_roots_hash =
                compute_revocation_roots_hash(&session.revoked_since_root, &session.revoked_root)?;
        }

        Ok(session)
    }
}

async fn perform_join(params: JoinParams) -> Result<AppSession> {
    let JoinParams {
        server_url,
        room_id,
        alias,
    } = params;

    if server_url.is_empty() {
        return Err(anyhow!("server URL must not be empty"));
    }
    if room_id.is_empty() {
        return Err(anyhow!("room id must not be empty"));
    }
    if alias.is_empty() {
        return Err(anyhow!("alias must not be empty"));
    }

    let room_identity = load_or_create_room_identity(&server_url, &room_id)
        .context("load or create persistent room identity")?;
    let pop_public_key = room_identity.pop_public_key.clone();
    let pop_secret_key = room_identity.pop_secret_key.clone();
    let identity_binding = Some(build_identity_binding(
        &alias,
        &pop_public_key,
        &pop_secret_key,
    )?);

    let mut generated_kbroad_public: Option<Vec<u8>> = None;
    let mut bootstrap_attempted = false;
    let mut retry_attempt = 0u32;

    let client = new_api_client(&server_url);
    let ticket = loop {
        match client
            .join_ticket(&room_id, &alias, identity_binding.clone())
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
                if status.is_server_error()
                    && message.contains("kbroad key missing")
                    && !bootstrap_attempted
                {
                    bootstrap_attempted = true;
                    let provisioning_public = if let Some(public) = generated_kbroad_public.as_ref()
                    {
                        public.clone()
                    } else {
                        let public = generate_kbroad_keypair().0;
                        generated_kbroad_public = Some(public.clone());
                        public
                    };
                    let admin_proof = build_room_admin_proof(
                        RoomAdminOperation::Bootstrap,
                        &room_id,
                        &provisioning_public,
                        &pop_public_key,
                        &pop_secret_key,
                    )
                    .context("build room bootstrap admin proof")?;

                    match client
                        .bootstrap_room_as_admin(&room_id, &provisioning_public, admin_proof)
                        .await
                    {
                        Ok(_) => continue,
                        Err(ApiClientError::HttpStatus {
                            status: bootstrap_status,
                            message: bootstrap_message,
                            ..
                        }) if bootstrap_status.is_server_error()
                            && bootstrap_message.contains("kbroad key already registered") =>
                        {
                            continue;
                        }
                        Err(err) => {
                            return Err(anyhow!("failed to bootstrap room KBROAD key: {}", err));
                        }
                    }
                }

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
    };

    let gid = bytes32("gid", &ticket.gid)?;
    let cat = bytes32("cat", &ticket.cat)?;
    let parent_root = bytes32("parent_root", &ticket.parent_root)?;
    let revoked_root = bytes32("revoked_root", &ticket.revoked_root)?;
    let revoked_since_root = bytes32("revoked_since_root", &ticket.revoked_since_root)?;
    let tswe_salt_hash = bytes32("tswe_salt_hash", &ticket.tswe_salt_hash)?;
    let join_delta_root = bytes32("join_delta_root", &ticket.join_delta_root)?;
    let leaf_id = bytes32("leaf_id", &ticket.leaf_id)?;
    let pox_r_commit = bytes32("pox_r_commit", &ticket.pox_r_commit)?;
    let kbroad_public = if ticket.kbroad_public.is_empty() {
        return Err(anyhow!("server returned empty KBROAD public key"));
    } else {
        ticket.kbroad_public.clone()
    };
    let bootstrap_public = ticket.bootstrap_public.clone();

    let witness_bytes = if ticket.witness_cbor.is_empty() {
        return Err(anyhow!("server did not include canonical witness"));
    } else {
        ticket.witness_cbor
    };

    let srx_inputs = SrxInputsOwned::from_cbor(&ticket.srx_cbor)
        .context("unable to decode SRX bundle from server")?
        .into_srx_inputs();

    let mut header_map = BTreeMap::new();
    header_map.insert(hdr::HDR_KBROAD_ALG, Value::Text("ml-kem-768".to_string()));
    header_map.insert(hdr::HDR_KBROAD_PUB, Value::Bytes(kbroad_public.clone()));
    let (barrier_leaf_ek, barrier_leaf_dk) = kyber768::keypair();
    let barrier_leaf_ek_bytes = KemPublicKey::as_bytes(&barrier_leaf_ek).to_vec();
    let barrier_leaf_dk_bytes = KemSecretKey::as_bytes(&barrier_leaf_dk).to_vec();
    let barrier_pkhash_leaf = compute_barrier_pkhash(barrier_leaf_ek_bytes.as_slice())?;
    header_map.insert(
        hdr::HDR_BARRIER_LEAF_PK,
        Value::Bytes(barrier_leaf_ek_bytes.clone()),
    );

    let mut k_fs = [0u8; 32];
    rand::rng().fill(&mut k_fs);
    let mut fs_state = ForwardSecrecyState::new(k_fs);
    let pop_secret =
        Box::new(dilithium5::SecretKey::from_bytes(&pop_secret_key).context("invalid POP key")?);

    // Room-scoped PoP identity was loaded or created above.

    // Generate ML-DSA-65 (Dilithium3) keys for message authentication
    let (msg_sign_pk, msg_sign_sk) = dilithium3::keypair();
    let msg_sign_public_key = msg_sign_pk.as_bytes().to_vec();
    let msg_sign_secret_key = msg_sign_sk.as_bytes().to_vec();

    let (vrf_secret_key, vrf_public_key) =
        generate_vrf_keys().context("generate runtime VRF keypair")?;

    let msphf_crs_id = if ticket.msphf_crs_id.is_empty() {
        "rlwe-merkle/v1".to_string()
    } else {
        ticket.msphf_crs_id
    };
    let msphf_params_id = if ticket.msphf_params_id.is_empty() {
        "rlwe-params/mock".to_string()
    } else {
        ticket.msphf_params_id
    };
    let proof_mode = if ticket.proof_mode.is_empty() {
        "lin+zkvrf".to_string()
    } else {
        ticket.proof_mode
    };
    let vrf_id = if ticket.vrf_id.is_empty() {
        "lb-vrf/v1".to_string()
    } else {
        ticket.vrf_id
    };
    let policy_version = if ticket.policy_version.is_empty() {
        "0".to_string()
    } else {
        ticket.policy_version
    };
    let fs_policy_version = if ticket.fs_policy_version.is_empty() {
        "7".to_string()
    } else {
        ticket.fs_policy_version
    };
    let fs_epoch_base_ts = ticket.fs_epoch_base_ts;
    let kem_tree_hash_after = bytes32("kem_tree_hash_after", &ticket.kem_tree_hash_after)?;
    let barrier_n_max = if ticket.n_max == 0 {
        DEFAULT_BARRIER_N_MAX
    } else {
        ticket.n_max
    };
    if ticket.cover_leaf_index >= barrier_n_max {
        return Err(anyhow!(
            "cover_leaf_index out of range for barrier tree: {} >= {}",
            ticket.cover_leaf_index,
            barrier_n_max
        ));
    }

    let params = OrchestrationParams {
        msphf_crs_id: msphf_crs_id.as_str(),
        params_id: msphf_params_id.as_str(),
        srx: Some(srx_inputs),
        srx_mode: SrxMode::Complete,
        pop_keys: Some(PopKeypair {
            algorithm: "ML-DSA-65",
            public_key: pop_public_key.as_slice(),
            secret_key: pop_secret.as_ref(),
        }),
        leaf_id_mode: LeafIdMode::PerGroup,
        proof_mode: proof_mode.as_str(),
        vrf_id: vrf_id.as_str(),
        policy_version: policy_version.as_str(),
        vrf_secret_key: Some(vrf_secret_key.as_slice()),
        vrf_public_key: Some(vrf_public_key.as_slice()),
        fs_policy_version: fs_policy_version.as_str(),
        fs_epoch_base_ts,
        barrier_version: ticket.barrier_version,
        fs_join: FsJoinInputs::default(),
        fs_merge: FsMergeInputs::default(),
    };

    let parts = AnchorInstanceParts {
        gid: &gid,
        cat: &cat,
        tswe_salt_hash: &tswe_salt_hash,
        parent_root: &parent_root,
        join_delta_root: &join_delta_root,
        revoked_since_prev_root: &revoked_since_root,
        revoked_root: &revoked_root,
        pox_r_commit: Some(&pox_r_commit),
    };

    let bundle = CityGClient::generate_epoch(
        header_map,
        parts,
        params,
        &mut fs_state,
        Some(&witness_bytes),
    )
    .context("failed to build join anchor")?;

    let capss_witness_bytes = encode_capss_witness(&bundle.capss_witness)?;

    if parent_root == [0u8; 32] && !bootstrap_public.is_empty() {
        return Err(anyhow!(
            "server requires bootstrap signer for first join; GUI bootstrap signer support is not configured"
        ));
    }

    client
        .accept_epoch_bundle(&bundle)
        .await
        .context("server rejected join bundle")?;

    let forward_state = fs_state;
    let fs_ec: u64 = bundle
        .header_map
        .get(&hdr::HDR_FS_EC)
        .and_then(Value::as_integer)
        .ok_or_else(|| anyhow!("join bundle missing fs_ec"))?
        .try_into()
        .map_err(|_| anyhow!("fs_ec out of range"))?;
    let fs_epoch_commit: [u8; 32] = bundle
        .header_map
        .get(&hdr::HDR_FS_EPOCH_COMMIT)
        .and_then(Value::as_bytes)
        .map(|bytes| bytes.as_slice())
        .ok_or_else(|| anyhow!("join bundle missing fs_epoch_commit"))?
        .try_into()
        .map_err(|_| anyhow!("fs_epoch_commit length"))?;
    let fs_dev_prev_commit: [u8; 32] = bundle
        .header_map
        .get(&hdr::HDR_FS_DEV_COMMIT)
        .or_else(|| bundle.header_map.get(&hdr::HDR_FS_DEV_PREV_COMMIT))
        .and_then(Value::as_bytes)
        .map(|bytes| bytes.as_slice())
        .ok_or_else(|| anyhow!("join bundle missing fs_dev commit"))?
        .try_into()
        .map_err(|_| anyhow!("fs_dev commit length"))?;
    let regular_fingerprint = Some(bundle.hp_binding.seed_ctx_hash);
    let fs_fingerprint = compute_fs_fingerprint_from_header(&bundle.header_map).or_else(|| {
        derive_fs_fingerprint_from_fields(
            fs_policy_version.as_str(),
            fs_ec,
            &fs_epoch_commit,
            fs_epoch_base_ts,
        )
    });
    let mut session = AppSession {
        server_url,
        room_id,
        alias,
        gid,
        cat,
        leaf_id,
        parent_root,
        join_delta_root,
        revoked_since_root,
        revoked_root,
        regular_fingerprint,
        fs_fingerprint,
        tswe_salt_hash,
        pox_r_commit,
        we_epoch_id: bundle.we_epoch_id,
        xk_hash: bundle.hp_binding.xk_hash,
        epoch_key: bundle.epoch_key,
        forward_state,
        fs_ec,
        fs_epoch_commit,
        fs_dev_prev_commit,
        fs_epoch_created_at: SystemTime::now(), // Initialize epoch timestamp
        fs_epoch_rotation_interval_secs: 300,   // Default: 5 minutes
        pop_public_key,
        pop_secret_key,
        msg_sign_public_key,
        msg_sign_secret_key,
        vrf_secret_key,
        vrf_public_key,
        kbroad_public,
        bootstrap_public,
        proof_mode,
        vrf_id,
        policy_version,
        msphf_crs_id,
        msphf_params_id,
        fs_policy_version,
        fs_epoch_base_ts,
        last_fetch_timestamp_ms: None,
        msg_replay_state: MsgReplayState::default(),
        capss_witness: capss_witness_bytes,
        barrier_state: BarrierSecretState {
            barrier_initialized: true,
            barrier_version: ticket.barrier_version,
            barrier_roots_hash: compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?,
            k_barrier: Zeroizing::new([0u8; 32]),
            kem_tree_hash_after,
            max_barrier_update_bytes: ticket.max_barrier_update_bytes.max(1),
            n_max: barrier_n_max,
            cover_leaf_index: ticket.cover_leaf_index,
            dk_leaf: Zeroizing::new(barrier_leaf_dk_bytes),
            pkhash_leaf: barrier_pkhash_leaf,
            barrier_recovery_pending: true,
            ..BarrierSecretState::default()
        },
    };

    if ticket.barrier_version == 0 && parent_root == [0u8; 32] {
        session = match finalize_bootstrapped_room_join(session.clone()).await {
            Ok(finalized) => finalized,
            Err(err) => {
                warn!("initial room setup after bootstrap join failed: {err:#}");
                reload_join_finalization_session(&session, err, "complete initial room setup")?
            }
        };
    } else if session.barrier_state.barrier_recovery_pending {
        session = match finalize_pending_join(session.clone()).await {
            Ok(finalized) => finalized,
            Err(err) => {
                warn!("post-join barrier finalization failed: {err:#}");
                reload_join_finalization_session(
                    &session,
                    err,
                    "complete join barrier finalization",
                )?
            }
        };
    }

    Ok(session)
}

fn reload_join_finalization_session(
    session: &AppSession,
    err: anyhow::Error,
    context: &'static str,
) -> Result<AppSession> {
    match load_session_at(&session.server_url, &session.room_id) {
        Ok(Some(reloaded))
            if reloaded.gid == session.gid
                && reloaded.leaf_id == session.leaf_id
                && !reloaded.barrier_state.barrier_recovery_pending =>
        {
            Ok(reloaded)
        }
        Ok(Some(_)) => Err(err).context(context),
        Ok(None) => Err(err).context(context),
        Err(load_err) => Err(err).context(format!(
            "{context} (and reload persisted session failed: {load_err})"
        )),
    }
}

async fn finalize_bootstrapped_room_join(session: AppSession) -> Result<AppSession> {
    finalize_joined_room(session, BarrierMergeMode::JoinFinalize).await
}

async fn finalize_pending_join(session: AppSession) -> Result<AppSession> {
    finalize_joined_room(session, BarrierMergeMode::JoinFinalize).await
}

async fn finalize_joined_room(session: AppSession, mode: BarrierMergeMode) -> Result<AppSession> {
    persist_session(&session).context("persist joined session before initial room setup")?;

    let published = match mode {
        BarrierMergeMode::PcsRefresh => {
            perform_pcs_refresh_inner(LeaveRequest::from_session(&session), true).await
        }
        BarrierMergeMode::JoinFinalize => {
            perform_join_finalize_inner(LeaveRequest::from_session(&session)).await
        }
    }
    .context(mode.publish_context())?;

    #[cfg(test)]
    if mode == BarrierMergeMode::JoinFinalize {
        fault_injection::trigger_fault(FaultInjectionCutPoint::AfterPublishBeforeReload, None)?;
    }

    let mut updated = session.clone();
    match apply_local_published_barrier_merge(&mut updated, published) {
        Ok(()) => {
            persist_activated_joined_session(&updated).context(mode.persist_context())?;
            Ok(updated)
        }
        Err(local_err) => {
            warn!(
                "local activation of barrier merge failed; falling back to epoch sync: {local_err:#}"
            );
            let persisted =
                load_session_at(&session.server_url, &session.room_id)?.ok_or_else(|| {
                    anyhow!("persisted joined session missing after barrier merge publish")
                })?;
            let sync = perform_epoch_sync(persisted)
                .await
                .context(mode.fallback_sync_context())?;
            if sync.session.barrier_state.barrier_recovery_pending {
                return Err(anyhow!(mode.still_pending_message()));
            }
            persist_activated_joined_session(&sync.session).context(mode.persist_context())?;
            Ok(sync.session)
        }
    }
}

fn apply_local_published_barrier_merge(
    session: &mut AppSession,
    published: PublishedBarrierMerge,
) -> Result<()> {
    let PublishedBarrierMerge {
        bundle,
        pending_barrier_state,
        mut forward_state_after,
    } = published;
    session.barrier_state.pending = Some(pending_barrier_state.clone());
    session.we_epoch_id = bundle.we_epoch_id;
    session.xk_hash = bundle.hp_binding.xk_hash;
    session.epoch_key = bundle.epoch_key;
    session.parent_root = bundle.anchor.parent_root;
    session.join_delta_root = bundle.anchor.join_delta_root;
    session.revoked_since_root = bundle.anchor.revoked_since_prev_root;
    session.revoked_root = bundle.anchor.revoked_root;
    session.cat = bytes32("cat", &bundle.anchor.cat)?;
    session.tswe_salt_hash = bytes32("tswe_salt_hash", &bundle.anchor.tswe_salt_hash)?;
    if let Some(commit) = bundle.anchor.pox_r_commit {
        session.pox_r_commit = commit;
    }
    if let Some(fs_ec) = header_u64(&bundle.header_map, hdr::HDR_FS_EC) {
        session.fs_ec = fs_ec;
    }
    if let Some(commit) = header_bytes32(&bundle.header_map, hdr::HDR_FS_EPOCH_COMMIT) {
        session.fs_epoch_commit = commit;
    }
    if bundle_authored_by_local_device(session, &bundle.header_map)
        && let Some(commit) = header_bytes32(&bundle.header_map, hdr::HDR_FS_DEV_COMMIT)
            .or_else(|| header_bytes32(&bundle.header_map, hdr::HDR_FS_DEV_PREV_COMMIT))
    {
        session.fs_dev_prev_commit = commit;
    }
    if let Some(base_ts) = header_u64(&bundle.header_map, hdr::HDR_FS_EPOCH_BASE_TS) {
        session.fs_epoch_base_ts = base_ts;
    }
    if let Some(policy) = header_policy_version(&bundle.header_map, hdr::HDR_FS_POLICY_VERSION) {
        session.fs_policy_version = policy;
    }
    session.policy_version = session.fs_policy_version.clone();
    if let Some(vrf_id) = header_text(&bundle.header_map, hdr::HDR_VRF_ID) {
        session.vrf_id = vrf_id.to_string();
    }
    if let Some(proof_mode) = header_text(&bundle.header_map, hdr::HDR_PROOF_MODE) {
        session.proof_mode = proof_mode.to_string();
    }
    if let Some(Value::Bytes(kbroad_pub)) = bundle.header_map.get(&hdr::HDR_KBROAD_PUB) {
        session.kbroad_public = kbroad_pub.clone();
    }

    let observed_barrier_version = header_u64(&bundle.header_map, hdr::HDR_BARRIER_VERSION)
        .unwrap_or(pending_barrier_state.barrier_version);
    let observed_fs_ec = header_u64(&bundle.header_map, hdr::HDR_FS_EC);
    let observed_barrier_update_reason =
        header_u64(&bundle.header_map, hdr::HDR_BARRIER_UPDATE_REASON);
    if !apply_pending_barrier_activation(
        session,
        observed_barrier_version,
        observed_fs_ec,
        observed_barrier_update_reason,
        Some(pending_barrier_state.barrier_update_digest),
    )? {
        return Err(anyhow!(
            "accepted local refresh bundle did not match persisted pending barrier state"
        ));
    }

    session.regular_fingerprint = Some(bundle.hp_binding.seed_ctx_hash);
    session.fs_fingerprint = compute_fs_fingerprint_from_header(&bundle.header_map).or_else(|| {
        derive_fs_fingerprint_from_fields(
            session.fs_policy_version.as_str(),
            session.fs_ec,
            &session.fs_epoch_commit,
            session.fs_epoch_base_ts,
        )
    });
    session.fs_epoch_created_at = SystemTime::now();
    session.last_fetch_timestamp_ms = None;
    forward_state_after.set_last_we_epoch_id(session.we_epoch_id);
    forward_state_after.set_epoch_base_ts(session.fs_epoch_base_ts);
    session.forward_state = forward_state_after;
    Ok(())
}

async fn perform_leave(request: LeaveRequest) -> Result<()> {
    let persist_request = request.clone();
    let LeaveRequest {
        server_url,
        room_id,
        gid,
        leaf_id,
        mut forward_state,
        pop_public_key,
        pop_secret_key,
        vrf_secret_key,
        vrf_public_key,
        fs_ec,
        fs_epoch_commit,
        fs_dev_prev_commit,
        max_barrier_update_bytes: stored_max_barrier_update_bytes,
        barrier_recovery_pending,
        ..
    } = request;

    if barrier_recovery_pending {
        return Err(anyhow!(
            "cannot originate barrier updates while barrier recovery is pending; complete FULL barrier recovery first"
        ));
    }

    let client = new_api_client(&server_url);
    let mut retry_attempt = 0u32;
    let ticket = loop {
        match client.merge_ticket(&room_id, &leaf_id).await {
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

                return Err(err).context("failed to obtain merge ticket");
            }
        }
    };

    let MergeTicket {
        we_epoch_id: _,
        parities: raw_parities,
        witness_cbor,
        srx_cbor,
        proof_mode,
        vrf_id,
        policy_version,
        cat,
        parent_root,
        join_delta_root,
        revoked_since_root,
        revoked_root,
        tswe_salt_hash,
        pox_r_commit,
        kbroad_public,
        msphf_crs_id,
        msphf_params_id,
        fs_policy_version,
        fs_epoch_base_ts,
        kbroad_generation: _,
        barrier_version,
        cover_leaf_index,
        kem_tree_hash_after,
        n_max,
        max_barrier_update_bytes,
    } = ticket;

    let srx_inputs = SrxInputsOwned::from_cbor(&srx_cbor)
        .context("unable to parse SRX payload from merge ticket")?
        .into_srx_inputs();

    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_KBROAD_ALG, Value::Text("ml-kem-768".to_string()));
    header.insert(hdr::HDR_KBROAD_PUB, Value::Bytes(kbroad_public.clone()));

    let cat_arr = bytes32("cat", &cat)?;
    let pox_r_commit_arr = bytes32("pox_r_commit", &pox_r_commit)?;

    let pop_secret =
        Box::new(dilithium5::SecretKey::from_bytes(&pop_secret_key).context("invalid POP key")?);

    let witness_bytes = if witness_cbor.is_empty() {
        None
    } else {
        Some(witness_cbor.as_slice())
    };

    let parities = hydrate_parities(&raw_parities, fs_ec, fs_epoch_commit, fs_dev_prev_commit);

    let pivot = select_pivot_parity(&parities)
        .ok_or_else(|| anyhow!("merge ticket did not include any pivot parities"))?;
    let parent_root_arr = bytes32("parent_root", &parent_root)?;
    let join_delta_root_arr = bytes32("join_delta_root", &join_delta_root)?;
    let revoked_since_root_arr = bytes32("revoked_since_root", &revoked_since_root)?;
    let revoked_root_arr = bytes32("revoked_root", &revoked_root)?;
    let tswe_salt_hash_arr = bytes32("tswe_salt_hash", &tswe_salt_hash)?;
    let revocation_roots_hash =
        compute_revocation_roots_hash(&revoked_since_root_arr, &revoked_root_arr)?;
    let committed_revocation_roots_hash =
        compute_revocation_roots_hash(&pivot.revoked_since_root, &pivot.revoked_root)?;
    let snapshot_hash = bytes32("kem_tree_hash_after", &kem_tree_hash_after)?;
    let barrier_tree_snapshot = client
        .barrier_fetch_public_tree(&room_id, &snapshot_hash)
        .await
        .context("fetch barrier public tree snapshot")?;
    let barrier_n_max = if n_max == 0 {
        DEFAULT_BARRIER_N_MAX
    } else {
        n_max
    };
    if cover_leaf_index >= barrier_n_max {
        return Err(anyhow!(
            "cover_leaf_index out of range for barrier tree: {cover_leaf_index} >= {barrier_n_max}"
        ));
    }
    if barrier_tree_snapshot.n_max != barrier_n_max {
        return Err(anyhow!(
            "barrier tree snapshot n_max mismatch: expected {barrier_n_max}, got {}",
            barrier_tree_snapshot.n_max
        ));
    }
    validate_barrier_tree_snapshot_auth(&snapshot_hash, barrier_n_max, &barrier_tree_snapshot)?;
    let join_records = client
        .barrier_resolve_joins_since(&room_id, barrier_version)
        .await
        .context("resolve barrier joins since previous version")?;
    let committed_revoked_indices = client
        .barrier_resolve_revoked_leaves(&room_id, &committed_revocation_roots_hash)
        .await
        .context("resolve committed barrier revoked leaf indices")?;
    let mut snapshot_pre = barrier_tree_snapshot.pk_entries.clone();
    apply_join_set_to_snapshot(
        snapshot_pre.as_mut_slice(),
        barrier_n_max,
        join_records.as_slice(),
    )?;
    apply_revoked_set_to_snapshot(
        snapshot_pre.as_mut_slice(),
        barrier_n_max,
        committed_revoked_indices.as_slice(),
    )?;
    let leaf_base = barrier_n_max.saturating_sub(1);
    let revoked_leaf_node = leaf_base.saturating_add(cover_leaf_index);
    blank_leaf_and_path(snapshot_pre.as_mut_slice(), revoked_leaf_node)?;
    let kem_tree_hash_before = compute_barrier_tree_hash(barrier_n_max, snapshot_pre.as_slice())?;
    let next_barrier_version = barrier_version.saturating_add(1);
    let barrier_update = build_barrier_update_bytes(
        &gid,
        barrier_n_max,
        cover_leaf_index,
        next_barrier_version,
        barrier_version,
        revocation_roots_hash,
        kem_tree_hash_before,
        snapshot_pre.as_slice(),
    )?;
    let ticket_max_barrier_update_bytes = max_barrier_update_bytes.max(1);
    if stored_max_barrier_update_bytes != 0
        && stored_max_barrier_update_bytes != ticket_max_barrier_update_bytes
    {
        return Err(anyhow!(
            "max_barrier_update_bytes mismatch: local={} server={}",
            stored_max_barrier_update_bytes,
            ticket_max_barrier_update_bytes
        ));
    }
    let max_barrier_update_bytes =
        normalize_max_barrier_update_bytes(ticket_max_barrier_update_bytes)?;
    if barrier_update.raw_update.len() > max_barrier_update_bytes {
        return Err(anyhow!(
            "barrier_update exceeds max_barrier_update_bytes: {} > {}",
            barrier_update.raw_update.len(),
            max_barrier_update_bytes
        ));
    }
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(barrier_update.raw_update.clone()),
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(0u64)),
    );
    let mut pending_barrier_state = BarrierPendingState {
        barrier_version: next_barrier_version,
        we_epoch_id: [0u8; 32],
        fs_ec,
        next_forward_fs_ec: 0,
        next_forward_fs_dev_commit: [0u8; 32],
        next_forward_last_weid: [0u8; 32],
        revocation_roots_hash,
        kem_tree_hash_after: barrier_update.kem_tree_hash_after,
        k_barrier_new: barrier_update.k_barrier_new.clone(),
        k_fs_after_pcs: None,
        barrier_update_reason: Some(0),
        barrier_update_digest: barrier_update.barrier_update_digest,
        on_path_key_material: barrier_update.on_path_key_material.clone(),
    };

    let params = OrchestrationParams {
        msphf_crs_id: msphf_crs_id.as_str(),
        params_id: msphf_params_id.as_str(),
        srx: Some(srx_inputs),
        srx_mode: SrxMode::Complete,
        pop_keys: Some(PopKeypair {
            algorithm: "ML-DSA-65",
            public_key: pop_public_key.as_slice(),
            secret_key: pop_secret.as_ref(),
        }),
        leaf_id_mode: LeafIdMode::PerGroup,
        proof_mode: proof_mode.as_str(),
        vrf_id: vrf_id.as_str(),
        policy_version: policy_version.as_str(),
        vrf_secret_key: Some(vrf_secret_key.as_slice()),
        vrf_public_key: Some(vrf_public_key.as_slice()),
        fs_policy_version: fs_policy_version.as_str(),
        fs_epoch_base_ts,
        barrier_version: next_barrier_version,
        fs_join: FsJoinInputs {
            fs_ec,
            fs_epoch_commit,
            fs_dev_prev_commit,
        },
        fs_merge: FsMergeInputs::default(),
    };

    let parts = AnchorInstanceParts {
        gid: &gid,
        cat: cat_arr.as_slice(),
        tswe_salt_hash: tswe_salt_hash_arr.as_slice(),
        parent_root: parent_root_arr.as_slice(),
        join_delta_root: join_delta_root_arr.as_slice(),
        revoked_since_prev_root: revoked_since_root_arr.as_slice(),
        revoked_root: revoked_root_arr.as_slice(),
        pox_r_commit: Some(pox_r_commit_arr.as_slice()),
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
    .context("failed to build merge bundle")?;

    strip_rollup_metadata(&mut bundle.header_map);
    apply_pivot_alignment(&mut bundle.header_map, pivot);
    let anchor_ctx =
        build_anchor_seed_ctx(&bundle.header_map).context("compute anchor seed ctx")?;
    let seed_ctx_hash = compute_seed_ctx_hash(&anchor_ctx).context("compute seed_ctx_hash")?;
    let seed_commit = compute_seed_commit(
        &anchor_ctx,
        &SeedCommitFields {
            gid: &gid,
            cat: cat_arr.as_slice(),
            we_epoch_id: bundle.we_epoch_id,
        },
    )
    .context("compute seed_commit")?;
    let seed_bundle_commit = compute_seed_bundle_commit(
        &anchor_ctx,
        &bundle.hp_binding.rho_commit,
        &gid,
        cat_arr.as_slice(),
        &parent_root_arr,
    )
    .context("compute seed_bundle_commit")?;
    let derived_we_epoch_id =
        derive_we_epoch_id(&gid, &parent_root_arr, &seed_ctx_hash).context("derive we_epoch_id")?;

    bundle.anchor.anchor_hdr_ctx = anchor_ctx.clone();
    bundle.hp_binding.seed_ctx_hash = seed_ctx_hash;
    bundle.hp_binding.seed_commit = seed_commit;
    bundle.hp_binding.seed_bundle_commit = seed_bundle_commit;
    bundle.we_epoch_id = derived_we_epoch_id;
    bundle
        .rebind_local_hp_envelope_with_barrier_key(&barrier_update.k_barrier_new)
        .context("rebind merge HP envelope for leave")?;
    pending_barrier_state.we_epoch_id = bundle.we_epoch_id;
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

    if let Some(recomputed) = recompute_proofs_commit(&bundle.header_map)
        .ok()
        .map(|arr| arr.to_vec())
    {
        bundle
            .header_map
            .insert(hdr::HDR_PROOFS_COMMIT, Value::Bytes(recomputed));
    }

    persist_pending_barrier_state_before_publish(&persist_request, pending_barrier_state.clone())?;

    match client.refresh_pivot(&bundle).await {
        Ok(_) => {}
        Err(ApiClientError::HttpStatus {
            status, message, ..
        }) if is_refresh_pivot_conflict(status.as_u16(), &message) => {
            warn!("refresh pivot skipped: {message}");
        }
        Err(err) => return Err(err).context("refresh pivot parity"),
    }

    client
        .accept_epoch_bundle(&bundle)
        .await
        .context("server rejected merge bundle")?;

    Ok(())
}

async fn perform_pcs_refresh(request: LeaveRequest) -> Result<()> {
    perform_barrier_merge_inner(request, BarrierMergeMode::PcsRefresh, false)
        .await
        .map(|_| ())
}

async fn perform_pcs_refresh_inner(
    request: LeaveRequest,
    allow_pending_recovery: bool,
) -> Result<PublishedBarrierMerge> {
    perform_barrier_merge_inner(
        request,
        BarrierMergeMode::PcsRefresh,
        allow_pending_recovery,
    )
    .await
}

async fn perform_join_finalize_inner(request: LeaveRequest) -> Result<PublishedBarrierMerge> {
    perform_barrier_merge_inner(request, BarrierMergeMode::JoinFinalize, true).await
}

async fn perform_barrier_merge_inner(
    request: LeaveRequest,
    mode: BarrierMergeMode,
    allow_pending_recovery: bool,
) -> Result<PublishedBarrierMerge> {
    let persist_request = request.clone();
    let LeaveRequest {
        server_url,
        room_id,
        gid,
        leaf_id,
        mut forward_state,
        pop_public_key,
        pop_secret_key,
        vrf_secret_key,
        vrf_public_key,
        fs_ec,
        fs_epoch_commit,
        fs_dev_prev_commit,
        k_fs_current,
        max_barrier_update_bytes: stored_max_barrier_update_bytes,
        barrier_recovery_pending,
    } = request;

    if barrier_recovery_pending && !allow_pending_recovery {
        return Err(anyhow!(mode.pending_guard_message()));
    }

    let client = new_api_client(&server_url);
    let mut retry_attempt = 0u32;
    let ticket = loop {
        match client.merge_ticket_refresh(&room_id, &leaf_id).await {
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
                        "merge_ticket_refresh race/concurrency rejection; retrying"
                    );
                    sleep(delay).await;
                    continue;
                }

                return Err(err).context(format!("failed to obtain {} merge ticket", mode.label()));
            }
        }
    };

    let MergeTicket {
        we_epoch_id: _,
        parities: raw_parities,
        witness_cbor,
        srx_cbor,
        proof_mode,
        vrf_id,
        policy_version,
        cat,
        parent_root,
        join_delta_root,
        revoked_since_root,
        revoked_root,
        tswe_salt_hash,
        pox_r_commit,
        kbroad_public,
        msphf_crs_id,
        msphf_params_id,
        fs_policy_version,
        fs_epoch_base_ts,
        kbroad_generation: _,
        barrier_version,
        cover_leaf_index,
        kem_tree_hash_after,
        n_max,
        max_barrier_update_bytes,
    } = ticket;

    if !srx_cbor.is_empty() {
        return Err(anyhow!(
            "{} merge ticket unexpectedly contained SRX payload",
            mode.label()
        ));
    }

    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_KBROAD_ALG, Value::Text("ml-kem-768".to_string()));
    header.insert(hdr::HDR_KBROAD_PUB, Value::Bytes(kbroad_public.clone()));

    let cat_arr = bytes32("cat", &cat)?;
    let pox_r_commit_arr = bytes32("pox_r_commit", &pox_r_commit)?;

    let pop_secret =
        Box::new(dilithium5::SecretKey::from_bytes(&pop_secret_key).context("invalid POP key")?);

    let witness_bytes = if witness_cbor.is_empty() {
        None
    } else {
        Some(witness_cbor.as_slice())
    };

    let parities = hydrate_parities(&raw_parities, fs_ec, fs_epoch_commit, fs_dev_prev_commit);

    let pivot = select_pivot_parity(&parities)
        .ok_or_else(|| anyhow!("merge ticket did not include any pivot parities"))?;
    let parent_root_arr = bytes32("parent_root", &parent_root)?;
    let join_delta_root_arr = bytes32("join_delta_root", &join_delta_root)?;
    let revoked_since_root_arr = bytes32("revoked_since_root", &revoked_since_root)?;
    let revoked_root_arr = bytes32("revoked_root", &revoked_root)?;
    let tswe_salt_hash_arr = bytes32("tswe_salt_hash", &tswe_salt_hash)?;
    let revocation_roots_hash =
        compute_revocation_roots_hash(&revoked_since_root_arr, &revoked_root_arr)?;
    let committed_revocation_roots_hash =
        compute_revocation_roots_hash(&pivot.revoked_since_root, &pivot.revoked_root)?;
    let snapshot_hash = bytes32("kem_tree_hash_after", &kem_tree_hash_after)?;
    let barrier_tree_snapshot = client
        .barrier_fetch_public_tree(&room_id, &snapshot_hash)
        .await
        .context("fetch barrier public tree snapshot")?;
    let barrier_n_max = if n_max == 0 {
        DEFAULT_BARRIER_N_MAX
    } else {
        n_max
    };
    if cover_leaf_index >= barrier_n_max {
        return Err(anyhow!(
            "cover_leaf_index out of range for barrier tree: {cover_leaf_index} >= {barrier_n_max}"
        ));
    }
    if barrier_tree_snapshot.n_max != barrier_n_max {
        return Err(anyhow!(
            "barrier tree snapshot n_max mismatch: expected {barrier_n_max}, got {}",
            barrier_tree_snapshot.n_max
        ));
    }
    validate_barrier_tree_snapshot_auth(&snapshot_hash, barrier_n_max, &barrier_tree_snapshot)?;
    let join_records = client
        .barrier_resolve_joins_since(&room_id, barrier_version)
        .await
        .context("resolve barrier joins since previous version")?;
    let committed_revoked_indices = client
        .barrier_resolve_revoked_leaves(&room_id, &committed_revocation_roots_hash)
        .await
        .context("resolve committed barrier revoked leaf indices")?;
    let mut snapshot_pre = barrier_tree_snapshot.pk_entries.clone();
    apply_join_set_to_snapshot(
        snapshot_pre.as_mut_slice(),
        barrier_n_max,
        join_records.as_slice(),
    )?;
    apply_revoked_set_to_snapshot(
        snapshot_pre.as_mut_slice(),
        barrier_n_max,
        committed_revoked_indices.as_slice(),
    )?;
    let kem_tree_hash_before = compute_barrier_tree_hash(barrier_n_max, snapshot_pre.as_slice())?;
    let next_barrier_version = barrier_version.saturating_add(1);
    let barrier_update = build_barrier_update_bytes(
        &gid,
        barrier_n_max,
        cover_leaf_index,
        next_barrier_version,
        barrier_version,
        revocation_roots_hash,
        kem_tree_hash_before,
        snapshot_pre.as_slice(),
    )?;
    let ticket_max_barrier_update_bytes = max_barrier_update_bytes.max(1);
    if stored_max_barrier_update_bytes != 0
        && stored_max_barrier_update_bytes != ticket_max_barrier_update_bytes
    {
        return Err(anyhow!(
            "max_barrier_update_bytes mismatch: local={} server={}",
            stored_max_barrier_update_bytes,
            ticket_max_barrier_update_bytes
        ));
    }
    let max_barrier_update_bytes =
        normalize_max_barrier_update_bytes(ticket_max_barrier_update_bytes)?;
    if barrier_update.raw_update.len() > max_barrier_update_bytes {
        return Err(anyhow!(
            "barrier_update exceeds max_barrier_update_bytes: {} > {}",
            barrier_update.raw_update.len(),
            max_barrier_update_bytes
        ));
    }
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(barrier_update.raw_update.clone()),
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(mode.reason())),
    );
    let mut pending_barrier_state = BarrierPendingState {
        barrier_version: next_barrier_version,
        we_epoch_id: [0u8; 32],
        fs_ec,
        next_forward_fs_ec: 0,
        next_forward_fs_dev_commit: [0u8; 32],
        next_forward_last_weid: [0u8; 32],
        revocation_roots_hash,
        kem_tree_hash_after: barrier_update.kem_tree_hash_after,
        k_barrier_new: barrier_update.k_barrier_new.clone(),
        k_fs_after_pcs: None,
        barrier_update_reason: Some(mode.reason()),
        barrier_update_digest: barrier_update.barrier_update_digest,
        on_path_key_material: barrier_update.on_path_key_material.clone(),
    };

    let params = OrchestrationParams {
        msphf_crs_id: msphf_crs_id.as_str(),
        params_id: msphf_params_id.as_str(),
        srx: None,
        srx_mode: SrxMode::Complete,
        pop_keys: Some(PopKeypair {
            algorithm: "ML-DSA-65",
            public_key: pop_public_key.as_slice(),
            secret_key: pop_secret.as_ref(),
        }),
        leaf_id_mode: LeafIdMode::PerGroup,
        proof_mode: proof_mode.as_str(),
        vrf_id: vrf_id.as_str(),
        policy_version: policy_version.as_str(),
        vrf_secret_key: Some(vrf_secret_key.as_slice()),
        vrf_public_key: Some(vrf_public_key.as_slice()),
        fs_policy_version: fs_policy_version.as_str(),
        fs_epoch_base_ts,
        barrier_version: next_barrier_version,
        fs_join: FsJoinInputs {
            fs_ec,
            fs_epoch_commit,
            fs_dev_prev_commit,
        },
        fs_merge: FsMergeInputs::default(),
    };

    let parts = AnchorInstanceParts {
        gid: &gid,
        cat: cat_arr.as_slice(),
        tswe_salt_hash: tswe_salt_hash_arr.as_slice(),
        parent_root: parent_root_arr.as_slice(),
        join_delta_root: join_delta_root_arr.as_slice(),
        revoked_since_prev_root: revoked_since_root_arr.as_slice(),
        revoked_root: revoked_root_arr.as_slice(),
        pox_r_commit: Some(pox_r_commit_arr.as_slice()),
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
    .context(mode.build_bundle_context())?;

    strip_rollup_metadata(&mut bundle.header_map);
    apply_pivot_alignment(&mut bundle.header_map, pivot);
    let anchor_ctx =
        build_anchor_seed_ctx(&bundle.header_map).context("compute anchor seed ctx")?;
    let seed_ctx_hash = compute_seed_ctx_hash(&anchor_ctx).context("compute seed_ctx_hash")?;
    let seed_commit = compute_seed_commit(
        &anchor_ctx,
        &SeedCommitFields {
            gid: &gid,
            cat: cat_arr.as_slice(),
            we_epoch_id: bundle.we_epoch_id,
        },
    )
    .context("compute seed_commit")?;
    let seed_bundle_commit = compute_seed_bundle_commit(
        &anchor_ctx,
        &bundle.hp_binding.rho_commit,
        &gid,
        cat_arr.as_slice(),
        &parent_root_arr,
    )
    .context("compute seed_bundle_commit")?;
    let derived_we_epoch_id =
        derive_we_epoch_id(&gid, &parent_root_arr, &seed_ctx_hash).context("derive we_epoch_id")?;
    let observed_fs_ec = header_u64(&bundle.header_map, hdr::HDR_FS_EC)
        .ok_or_else(|| anyhow!("{} merge bundle missing fs_ec", mode.label()))?;
    let k_fs_after_pcs = if mode.reseeds_k_fs() {
        Some(derive_k_fs_after_pcs(
            &k_fs_current,
            &derived_we_epoch_id,
            observed_fs_ec,
            next_barrier_version,
            &barrier_update.k_barrier_new,
        )?)
    } else {
        None
    };

    bundle.anchor.anchor_hdr_ctx = anchor_ctx.clone();
    bundle.hp_binding.seed_ctx_hash = seed_ctx_hash;
    bundle.hp_binding.seed_commit = seed_commit;
    bundle.hp_binding.seed_bundle_commit = seed_bundle_commit;
    bundle.we_epoch_id = derived_we_epoch_id;
    let has_local_hp_material = !bundle.hp_ciphertext.is_empty() && bundle.hp_aead_key != [0u8; 32];
    if has_local_hp_material {
        if mode.reason() == 2 {
            bundle
                .seal_local_hp_header_with_barrier_key(&barrier_update.k_barrier_new)
                .context(format!("seal merge HP envelope for {}", mode.label()))?;
        } else {
            bundle
                .rebind_local_hp_envelope_with_barrier_key(&barrier_update.k_barrier_new)
                .context(format!("rebind merge HP envelope for {}", mode.label()))?;
        }
    } else {
        return Err(anyhow!(
            "{} merge bundle missing local HP material",
            mode.label()
        ));
    }
    pending_barrier_state.we_epoch_id = bundle.we_epoch_id;
    pending_barrier_state.fs_ec = observed_fs_ec;
    let next_forward = forward_state.snapshot();
    pending_barrier_state.next_forward_fs_ec = next_forward.fs_ec;
    pending_barrier_state.next_forward_fs_dev_commit = next_forward.fs_dev_commit;
    pending_barrier_state.next_forward_last_weid = next_forward.last_weid;
    if let Some(k_fs_after_pcs) = k_fs_after_pcs {
        pending_barrier_state.k_fs_after_pcs = Some(Zeroizing::new(k_fs_after_pcs));
    }
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

    if let Some(recomputed) = recompute_proofs_commit(&bundle.header_map)
        .ok()
        .map(|arr| arr.to_vec())
    {
        bundle
            .header_map
            .insert(hdr::HDR_PROOFS_COMMIT, Value::Bytes(recomputed));
    }

    persist_pending_barrier_state_before_publish(&persist_request, pending_barrier_state.clone())?;

    #[cfg(test)]
    if mode == BarrierMergeMode::JoinFinalize {
        fault_injection::trigger_fault(FaultInjectionCutPoint::BeforePublishJoinFinalize, None)?;
    }

    match client.refresh_pivot(&bundle).await {
        Ok(_) => {}
        Err(ApiClientError::HttpStatus {
            status, message, ..
        }) if is_refresh_pivot_conflict(status.as_u16(), &message) => {
            warn!("refresh pivot skipped: {message}");
        }
        Err(err) => return Err(err).context("refresh pivot parity"),
    }

    client
        .accept_epoch_bundle(&bundle)
        .await
        .context(mode.accept_bundle_context())?;

    Ok(PublishedBarrierMerge {
        bundle,
        pending_barrier_state,
        forward_state_after: forward_state,
    })
}

const MEMBERS_ROOT_VERIFY_PAGE_LIMIT: u32 = 2_000;

fn parse_member_leaf_id(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("member leaf id must be 32 bytes"))
}

fn validate_members_root_from_leaves(
    root: [u8; 32],
    mut leaves: Vec<[u8; 32]>,
    total_count: u64,
) -> Result<()> {
    if leaves.len() as u64 != total_count {
        return Err(anyhow!(
            "members root validation failed: expected {total_count} leaves, received {}",
            leaves.len()
        ));
    }
    leaves.sort_unstable();
    let computed = canonical_set_root(&leaves)
        .map_err(|err| anyhow!("members root validation failed: unable to compute root: {err}"))?;
    if computed != root {
        return Err(anyhow!(
            "members root validation failed: computed {} but server reported {}",
            hex_encode(computed),
            hex_encode(root)
        ));
    }
    Ok(())
}

async fn verify_members_root_consistency(
    client: &CitygApiClient,
    gid: &[u8; 32],
    root: &[u8; 32],
) -> Result<()> {
    let mut offset = 0u64;
    let mut expected_total: Option<u64> = None;
    let mut leaves: Vec<[u8; 32]> = Vec::new();

    loop {
        let response = client
            .members_with_range(
                gid,
                Some(root),
                Some(offset),
                Some(MEMBERS_ROOT_VERIFY_PAGE_LIMIT),
            )
            .await?;

        let response_root: [u8; 32] = response
            .root
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("members root must be 32 bytes"))?;
        if response_root != *root {
            return Err(anyhow!(
                "members root validation failed: page root {} did not match expected {}",
                hex_encode(response_root),
                hex_encode(*root)
            ));
        }

        match expected_total {
            Some(total) if total != response.total_count => {
                return Err(anyhow!(
                    "members root validation failed: inconsistent total_count ({total} vs {})",
                    response.total_count
                ));
            }
            None => expected_total = Some(response.total_count),
            _ => {}
        }

        for entry in response.members {
            leaves.push(parse_member_leaf_id(entry.leaf_id.as_slice())?);
        }

        if response.next_offset >= response.total_count {
            break;
        }
        if response.next_offset <= offset {
            return Err(anyhow!(
                "members root validation failed: non-increasing pagination offset {} -> {}",
                offset,
                response.next_offset
            ));
        }
        offset = response.next_offset;
    }

    validate_members_root_from_leaves(*root, leaves, expected_total.unwrap_or(0))
}

async fn perform_fetch_members(params: MembersParams) -> Result<MembersPage> {
    let client = new_api_client(&params.server_url);
    let (raw_members, root, total_count, next_offset) = match &params.mode {
        MembersMode::Full => {
            // Always resolve the first page against latest server root to avoid
            // sticking to an old-but-still-valid parent_root after missed events.
            let response = if params.offset == 0 {
                client
                    .members_with_range(&params.gid, None, Some(params.offset), Some(params.limit))
                    .await?
            } else {
                match client
                    .members_with_range(
                        &params.gid,
                        Some(&params.parent_root),
                        Some(params.offset),
                        Some(params.limit),
                    )
                    .await
                {
                    Ok(response) => response,
                    Err(ApiClientError::HttpStatus { status, .. }) if status.as_u16() == 404 => {
                        info!(
                            "members root {} not found for gid {}; retrying with latest root",
                            hex_encode(params.parent_root),
                            hex_encode(params.gid)
                        );
                        client
                            .members_with_range(
                                &params.gid,
                                None,
                                Some(params.offset),
                                Some(params.limit),
                            )
                            .await?
                    }
                    Err(err) => return Err(err.into()),
                }
            };
            (
                response.members,
                response.root,
                response.total_count,
                response.next_offset,
            )
        }
        MembersMode::Search { query } => {
            // Same latest-root bootstrap for search mode first page.
            let response = if params.offset == 0 {
                client
                    .search_members(
                        &params.gid,
                        query,
                        None,
                        Some(params.offset),
                        Some(params.limit),
                    )
                    .await?
            } else {
                match client
                    .search_members(
                        &params.gid,
                        query,
                        Some(&params.parent_root),
                        Some(params.offset),
                        Some(params.limit),
                    )
                    .await
                {
                    Ok(response) => response,
                    Err(ApiClientError::HttpStatus { status, .. }) if status.as_u16() == 404 => {
                        info!(
                            "search root {} not found for gid {}; retrying with latest root",
                            hex_encode(params.parent_root),
                            hex_encode(params.gid)
                        );
                        client
                            .search_members(
                                &params.gid,
                                query,
                                None,
                                Some(params.offset),
                                Some(params.limit),
                            )
                            .await?
                    }
                    Err(err) => return Err(err.into()),
                }
            };
            (
                response.members,
                response.root,
                response.total_count,
                response.next_offset,
            )
        }
    };
    let root: [u8; 32] = root
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("members root must be 32 bytes"))?;
    if params.offset == 0 {
        verify_members_root_consistency(&client, &params.gid, &root)
            .await
            .context("failed to verify member roster root")?;
    }
    let mut members = Vec::with_capacity(raw_members.len());
    for entry in raw_members {
        let leaf_id = parse_member_leaf_id(entry.leaf_id.as_slice())?;
        let alias = entry.alias.filter(|alias| !alias.trim().is_empty());
        let pop_public_key = entry.pop_public_key.filter(|pk| !pk.is_empty());
        members.push(MemberEntry {
            leaf_id,
            alias,
            pop_public_key,
            join_timestamp_ms: entry.join_date,
            last_seen_timestamp_ms: entry.last_seen,
        });
    }
    Ok(MembersPage {
        members,
        root,
        total_count,
        next_offset,
    })
}

async fn perform_fetch_room_admins(params: RoomAdminQueryParams) -> Result<Vec<Vec<u8>>> {
    let client = new_api_client(&params.server_url);
    let admin_proof = build_room_admin_listing_proof(
        &params.room_id,
        &params.pop_public_key,
        &params.pop_secret_key,
    )
    .context("build room admin listing proof")?;
    let response = client
        .list_room_admins(&params.room_id, admin_proof)
        .await
        .context("list room admins")?;
    Ok(response.admin_pop_public_keys)
}

async fn perform_room_admin_mutation(
    params: RoomAdminMutationParams,
) -> Result<RoomAdminMutationOutcome> {
    let client = new_api_client(&params.query.server_url);
    let admin_proof = build_room_admin_target_proof(
        params.kind.operation(),
        &params.query.room_id,
        &params.target_pop_public_key,
        &params.query.pop_public_key,
        &params.query.pop_secret_key,
    )
    .with_context(|| {
        format!(
            "build {} room admin proof",
            match params.kind {
                RoomAdminMutationKind::Grant => "grant",
                RoomAdminMutationKind::Revoke => "revoke",
            }
        )
    })?;
    let response = match params.kind {
        RoomAdminMutationKind::Grant => client
            .grant_room_admin(
                &params.query.room_id,
                &params.target_pop_public_key,
                admin_proof,
            )
            .await
            .context("grant room admin")?,
        RoomAdminMutationKind::Revoke => client
            .revoke_room_admin(
                &params.query.room_id,
                &params.target_pop_public_key,
                admin_proof,
            )
            .await
            .context("revoke room admin")?,
    };
    Ok(RoomAdminMutationOutcome {
        status: response.status,
        admin_count: response.admin_count,
    })
}

async fn perform_send(params: SendParams) -> Result<ChatMessageEntry> {
    let SendParams {
        server_url,
        gid,
        we_epoch_id,
        xk_hash,
        epoch_key,
        fs_ec,
        barrier_version,
        k_barrier,
        msg_index,
        leaf_id,
        alias,
        plaintext,
        msg_sign_secret_key,
        msg_sign_public_key,
    } = params;

    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Sign the message with ML-DSA-65
    let signature = sign_message(
        &leaf_id,
        timestamp_ms,
        plaintext.as_bytes(),
        &msg_sign_secret_key,
    )
    .context("failed to sign message")?;

    let authenticated_msg = encode_authenticated_message(
        timestamp_ms,
        plaintext.as_bytes(),
        &msg_sign_public_key,
        &signature,
    );

    // Encrypt the authenticated message
    let ciphertext = encrypt_message_v2(
        &authenticated_msg,
        &MessageCryptoContext {
            gid: &gid,
            we_epoch_id: &we_epoch_id,
            xk_hash: &xk_hash,
            fs_ec,
            barrier_version,
            sender_leaf: &leaf_id,
            epoch_key: &epoch_key,
            k_barrier: &k_barrier,
        },
        msg_index,
    )
    .context("failed to encrypt message")?;

    // Send with leaf_id as sender identifier
    let client = new_api_client(&server_url);
    client
        .send_message(&we_epoch_id, &ciphertext, Some(&leaf_id))
        .await
        .context("failed to send message")?;

    Ok(ChatMessageEntry {
        sender_leaf: Some(leaf_id),
        fallback_label: alias,
        plaintext,
        ciphertext_hex: hex_encode(&ciphertext),
        timestamp_ms,
        delivery: MessageDelivery::Sent,
        pending_id: None,
    })
}

async fn perform_fetch(params: FetchParams) -> Result<FetchOutcome> {
    let FetchParams {
        server_url,
        gid,
        we_epoch_id,
        xk_hash,
        epoch_key,
        fs_ec,
        barrier_version,
        k_barrier,
        mut msg_replay_state,
        leaf_id,
        since,
    } = params;

    let client = new_api_client(&server_url);
    let response = client
        .fetch_messages(&we_epoch_id, &leaf_id)
        .await
        .context("failed to fetch messages")?;

    let mut messages = Vec::new();
    let mut max_timestamp = since.unwrap_or(0);
    for message in response.messages {
        if let Some(threshold) = since
            && message.timestamp_ms <= threshold
        {
            continue;
        }

        // Extract leaf_id from sender field (must be 32 bytes)
        if message.sender.len() != 32 {
            tracing::warn!(
                "sender field is not 32 bytes (got {}), skipping message",
                message.sender.len()
            );
            continue;
        }
        // Safe conversion: we verified length == 32 above
        let leaf_id: [u8; 32] = message.sender[..32].try_into()?;
        let replay_context = MessageCryptoContext {
            gid: &gid,
            we_epoch_id: &we_epoch_id,
            xk_hash: &xk_hash,
            fs_ec,
            barrier_version,
            sender_leaf: &leaf_id,
            epoch_key: &epoch_key,
            k_barrier: &k_barrier,
        };
        let replay_tuple_tag =
            derive_msg_replay_tuple_tag(&replay_context).context("derive fs/msg/replay/tuple")?;
        msg_replay_state.ensure_tuple(replay_tuple_tag);

        // Decrypt using ChaCha20-Poly1305
        let (msg_index, authenticated_msg) =
            match decrypt_message_v2_with_index(&message.ciphertext, &replay_context) {
                Ok(outcome) => outcome,
                Err(e) => {
                    // Skip messages that fail decryption (might be from different epoch, sender, or corrupted)
                    tracing::warn!("failed to decrypt message: {}", e);
                    continue;
                }
            };
        if msg_replay_state.contains(replay_tuple_tag, msg_index) {
            tracing::warn!("dropping replayed msg_index={msg_index}");
            continue;
        }

        // Parse authenticated message format: plaintext || pub_key_len (4) || pub_key || signature
        // ML-DSA-65: public key is 1952 bytes, signature is 3293 bytes
        const MLDSA65_PUBKEY_SIZE: usize = ml_dsa_public_key_bytes();
        const MLDSA65_SIG_SIZE: usize = ml_dsa_signature_bytes();
        const MIN_MSG_SIZE: usize =
            MESSAGE_PREFIX.len() + 8 + 4 + 4 + MLDSA65_PUBKEY_SIZE + 4 + MLDSA65_SIG_SIZE;

        if authenticated_msg.len() < MIN_MSG_SIZE {
            tracing::warn!(
                "message too small for authenticated format: {} bytes < {} bytes minimum",
                authenticated_msg.len(),
                MIN_MSG_SIZE
            );
            continue; // Skip messages that don't meet minimum size
        }

        let envelope = match decode_authenticated_message(&authenticated_msg) {
            Ok(env) => env,
            Err(err) => {
                tracing::warn!("failed to decode authenticated message: {err}");
                continue;
            }
        };

        if envelope.public_key.len() != MLDSA65_PUBKEY_SIZE {
            tracing::warn!(
                "unexpected public key length: {} (expected {})",
                envelope.public_key.len(),
                MLDSA65_PUBKEY_SIZE
            );
            continue;
        }
        if envelope.signature.len() != MLDSA65_SIG_SIZE {
            tracing::warn!(
                "unexpected signature length: {} (expected {})",
                envelope.signature.len(),
                MLDSA65_SIG_SIZE
            );
            continue;
        }

        // Verify signature
        match verify_message_signature(
            &leaf_id,
            envelope.timestamp_ms,
            envelope.plaintext,
            envelope.signature,
            envelope.public_key,
        ) {
            Ok(()) => {
                let sender_display = format!("{}✓", hex_encode(&leaf_id[..4]));
                let plaintext = String::from_utf8_lossy(envelope.plaintext).into_owned();

                if message.timestamp_ms > max_timestamp {
                    max_timestamp = message.timestamp_ms;
                }
                msg_replay_state.record(replay_tuple_tag, msg_index);

                tracing::info!("message from {}: verification=verified", sender_display);

                messages.push(ChatMessageEntry {
                    sender_leaf: Some(leaf_id),
                    fallback_label: sender_display,
                    plaintext,
                    ciphertext_hex: hex_encode(&message.ciphertext),
                    timestamp_ms: message.timestamp_ms,
                    delivery: MessageDelivery::Sent,
                    pending_id: None,
                });
            }
            Err(e) => {
                tracing::warn!(
                    "signature verification failed for message from {}: {}",
                    hex_encode(&leaf_id[..4]),
                    e
                );
                // Skip messages with invalid signatures
                continue;
            }
        }
    }

    let last_timestamp_ms = if messages.is_empty() {
        since
    } else {
        Some(max_timestamp)
    };

    Ok(FetchOutcome {
        messages,
        last_timestamp_ms,
        msg_replay_state,
    })
}

async fn perform_epoch_sync(mut session: AppSession) -> Result<EpochSyncOutcome> {
    let client = new_api_client(&session.server_url);
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
                        "merge_ticket_refresh race/concurrency rejection during epoch sync; retrying"
                    );
                    sleep(delay).await;
                    continue;
                }

                return Err(err).context("failed to fetch merge ticket for epoch sync");
            }
        }
    };
    let ticket_kem_tree_hash_after = bytes32("kem_tree_hash_after", &ticket.kem_tree_hash_after)?;
    let ticket_n_max = if ticket.n_max == 0 {
        DEFAULT_BARRIER_N_MAX
    } else {
        ticket.n_max
    };
    let ticket_max_barrier_update_bytes_u64 = ticket.max_barrier_update_bytes.max(1);
    let ticket_max_barrier_update_bytes =
        normalize_max_barrier_update_bytes(ticket_max_barrier_update_bytes_u64)?;
    if session.barrier_state.max_barrier_update_bytes != 0
        && session.barrier_state.max_barrier_update_bytes != ticket_max_barrier_update_bytes_u64
    {
        return Err(anyhow!(
            "max_barrier_update_bytes mismatch: local={} server={}",
            session.barrier_state.max_barrier_update_bytes,
            ticket_max_barrier_update_bytes_u64
        ));
    }
    if ticket.cover_leaf_index >= ticket_n_max {
        return Err(anyhow!(
            "merge ticket cover_leaf_index out of range: {} >= {}",
            ticket.cover_leaf_index,
            ticket_n_max
        ));
    }
    let previous_we_epoch_id = session.we_epoch_id;
    session.barrier_state.max_barrier_update_bytes = ticket_max_barrier_update_bytes_u64;
    session.barrier_state.n_max = ticket_n_max;
    session.barrier_state.cover_leaf_index = ticket.cover_leaf_index;
    let pending_history_outcome = apply_pending_barrier_activation_from_history(
        &client,
        &mut session,
        ticket.barrier_version,
    )
    .await?;
    let barrier_changed = session.barrier_state.barrier_version != ticket.barrier_version
        || session.barrier_state.kem_tree_hash_after != ticket_kem_tree_hash_after
        || session.barrier_state.max_barrier_update_bytes != ticket_max_barrier_update_bytes_u64
        || session.barrier_state.n_max != ticket_n_max
        || session.barrier_state.cover_leaf_index != ticket.cover_leaf_index;

    if let Some(pivot) = select_pivot_parity(&ticket.parities) {
        session.xk_hash = pivot.xk_hash;
    }

    if ticket.we_epoch_id == session.we_epoch_id {
        session.barrier_state.barrier_version = ticket.barrier_version;
        session.barrier_state.kem_tree_hash_after = ticket_kem_tree_hash_after;
        return Ok(EpochSyncOutcome {
            session,
            changed: barrier_changed
                || !matches!(
                    pending_history_outcome,
                    PendingBarrierHistoryOutcome::Unchanged
                ),
        });
    }

    let bundle_response = client
        .get_bundle(&ticket.we_epoch_id)
        .await
        .context("failed to fetch latest epoch bundle")?;
    let mut bundle = ClientEpochBundle::from_cbor(&bundle_response.bundle_cbor)
        .context("failed to decode latest epoch bundle")?;

    if bundle.we_epoch_id != ticket.we_epoch_id {
        return Err(anyhow!(
            "merge ticket/bundle mismatch: ticket={} bundle={}",
            hex_encode(ticket.we_epoch_id),
            hex_encode(bundle.we_epoch_id)
        ));
    }

    if !ticket.witness_cbor.is_empty() {
        bundle.witness = Some(ticket.witness_cbor.clone());
    }

    let uses_barrier_hp_envelope = matches!(
        bundle
            .header_map
            .get(&hdr::HDR_HP_BYTES)
            .and_then(|value| match value {
                Value::Array(items) => items.first(),
                _ => None,
            }),
        Some(Value::Text(mode)) if mode == BARRIER_HP_MODE
    );
    let has_barrier_update = matches!(
        bundle.header_map.get(&hdr::HDR_BARRIER_UPDATE),
        Some(Value::Bytes(_))
    );

    let gid = bytes32("gid", &bundle.anchor.gid)?;
    if gid != session.gid {
        return Err(anyhow!(
            "bundle gid mismatch: expected {}, got {}",
            hex_encode(session.gid),
            hex_encode(gid)
        ));
    }

    let defer_epoch_derivation = uses_barrier_hp_envelope && has_barrier_update;
    let mut derived_epoch_key = None;
    if !defer_epoch_derivation {
        let (epoch_key, _) = if uses_barrier_hp_envelope {
            bundle
                .derive_epoch_secrets_with_barrier_key(&session.barrier_state.k_barrier)
                .context("failed to derive epoch key during sync from barrier state")?
        } else {
            bundle
                .derive_epoch_secrets()
                .map_err(|err| anyhow!("failed to derive epoch key during sync: {err}"))?
        };
        derived_epoch_key = Some(epoch_key);
    }

    session.we_epoch_id = bundle.we_epoch_id;
    session.xk_hash = bundle.hp_binding.xk_hash;
    session.epoch_key = derived_epoch_key.unwrap_or([0u8; 32]);
    session.parent_root = bundle.anchor.parent_root;
    session.join_delta_root = bundle.anchor.join_delta_root;
    session.revoked_since_root = bundle.anchor.revoked_since_prev_root;
    session.revoked_root = bundle.anchor.revoked_root;
    session.cat = bytes32("cat", &bundle.anchor.cat)?;
    session.tswe_salt_hash = bytes32("tswe_salt_hash", &bundle.anchor.tswe_salt_hash)?;
    if let Some(commit) = bundle.anchor.pox_r_commit {
        session.pox_r_commit = commit;
    }

    if let Some(fs_ec) = header_u64(&bundle.header_map, hdr::HDR_FS_EC) {
        session.fs_ec = fs_ec;
    }
    if let Some(commit) = header_bytes32(&bundle.header_map, hdr::HDR_FS_EPOCH_COMMIT) {
        session.fs_epoch_commit = commit;
    }
    if bundle_authored_by_local_device(&session, &bundle.header_map)
        && let Some(commit) = header_bytes32(&bundle.header_map, hdr::HDR_FS_DEV_COMMIT)
            .or_else(|| header_bytes32(&bundle.header_map, hdr::HDR_FS_DEV_PREV_COMMIT))
    {
        session.fs_dev_prev_commit = commit;
    }
    if let Some(base_ts) = header_u64(&bundle.header_map, hdr::HDR_FS_EPOCH_BASE_TS) {
        session.fs_epoch_base_ts = base_ts;
    }
    if let Some(policy) = header_policy_version(&bundle.header_map, hdr::HDR_FS_POLICY_VERSION) {
        session.fs_policy_version = policy;
    }
    session.policy_version = session.fs_policy_version.clone();
    if let Some(vrf_id) = header_text(&bundle.header_map, hdr::HDR_VRF_ID) {
        session.vrf_id = vrf_id.to_string();
    }
    if let Some(proof_mode) = header_text(&bundle.header_map, hdr::HDR_PROOF_MODE) {
        session.proof_mode = proof_mode.to_string();
    }
    if let Some(Value::Bytes(kbroad_pub)) = bundle.header_map.get(&hdr::HDR_KBROAD_PUB) {
        session.kbroad_public = kbroad_pub.clone();
    }

    let accepted_digest = extract_barrier_update_digest(&bundle.header_map)?;
    let observed_fs_ec = header_u64(&bundle.header_map, hdr::HDR_FS_EC);
    let observed_barrier_update_reason =
        header_u64(&bundle.header_map, hdr::HDR_BARRIER_UPDATE_REASON);
    let pending_changed_with_bundle = apply_pending_barrier_activation(
        &mut session,
        ticket.barrier_version,
        observed_fs_ec,
        observed_barrier_update_reason,
        accepted_digest,
    )?;
    let pending_applied = pending_changed_with_bundle
        || matches!(
            pending_history_outcome,
            PendingBarrierHistoryOutcome::Activated(we_epoch_id) if we_epoch_id == bundle.we_epoch_id
        );

    if !pending_applied && has_barrier_update {
        let raw_update = match bundle.header_map.get(&hdr::HDR_BARRIER_UPDATE) {
            Some(Value::Bytes(raw)) => raw.as_slice(),
            Some(_) => return Err(anyhow!("header barrier_update must be bytes")),
            None => return Err(anyhow!("missing barrier_update bytes")),
        };
        let chain_check_result = full_chain_check_barrier_update(
            &client,
            &session.room_id,
            &session,
            &bundle.header_map,
            raw_update,
            ticket_max_barrier_update_bytes,
        )
        .await;

        let is_version_gap = chain_check_result.as_ref().is_err_and(|err| {
            err.to_string()
                .contains("local barrier version progression mismatch")
        });

        if is_version_gap {
            // The local barrier state is behind by 2+ versions.  Full
            // chain-check is impossible (we missed intermediate updates), so
            // attempt a best-effort recovery using the leaf KEM key which
            // remains valid across barrier versions.
            warn!(
                local_barrier_version = session.barrier_state.barrier_version,
                ticket_barrier_version = ticket.barrier_version,
                "barrier version gap detected; attempting best-effort recovery"
            );
            match try_recover_barrier_best_effort(
                &session,
                &bundle.header_map,
                &session.we_epoch_id,
                session.fs_ec,
                ticket_max_barrier_update_bytes,
            ) {
                Ok(Some(recovered)) => {
                    if recovered.kem_tree_hash_after != ticket_kem_tree_hash_after {
                        return Err(anyhow!(
                            "barrier recover hash-chain mismatch: recovered hash does not match merge ticket"
                        ));
                    }
                    info!(
                        "best-effort barrier recovery succeeded; caught up to barrier version {}",
                        ticket.barrier_version
                    );
                    apply_recovered_barrier_state(&mut session, recovered)?;
                }
                Ok(None) => {
                    // Cannot decrypt the current barrier update (our path was
                    // not targeted. Accept the ticket's barrier version and
                    // wait for the next barrier update that targets our leaf.
                    warn!(
                        "best-effort barrier recovery produced no match; entering barrier_recovery_pending"
                    );
                    enter_barrier_recovery_pending(&mut session)?;
                }
                Err(err)
                    if err
                        .to_string()
                        .contains("candidate unwrap/decrypt failure (960.7)") =>
                {
                    // We found a candidate update on our path, but local
                    // internal node secrets are too stale to unwrap it.
                    // Preserve the accepted public state and wait for a future
                    // barrier update that targets our leaf directly.
                    warn!(
                        detail = %err,
                        "best-effort barrier recovery could not decrypt candidate; entering barrier_recovery_pending"
                    );
                    enter_barrier_recovery_pending(&mut session)?;
                }
                Err(err) => {
                    let detail = err.to_string();
                    if detail.contains("960.") {
                        return Err(anyhow!("barrier recover failed: {detail}"));
                    }
                    return Err(anyhow!("barrier recover failed (960.7): {detail}"));
                }
            }
        } else {
            let expected_before_hash = chain_check_result?;
            match try_recover_barrier_from_header_with_expected_before(
                &session,
                &bundle.header_map,
                &session.we_epoch_id,
                session.fs_ec,
                ticket_max_barrier_update_bytes,
                Some(expected_before_hash),
            ) {
                Ok(Some(recovered)) => {
                    if recovered.kem_tree_hash_after != ticket_kem_tree_hash_after {
                        return Err(anyhow!(
                            "barrier recover hash-chain mismatch: recovered hash does not match merge ticket"
                        ));
                    }
                    apply_recovered_barrier_state(&mut session, recovered)?;
                }
                Ok(None) => {
                    return Err(anyhow!(
                        "barrier recover produced no match (960.6) for a barrier update"
                    ));
                }
                Err(err) => {
                    let detail = err.to_string();
                    if detail.contains("960.") {
                        return Err(anyhow!("barrier recover failed: {detail}"));
                    }
                    return Err(anyhow!("barrier recover failed (960.7): {detail}"));
                }
            }
        }
    }

    if defer_epoch_derivation && !session.barrier_state.barrier_recovery_pending {
        let (epoch_key, _) = bundle
            .derive_epoch_secrets_with_barrier_key(&session.barrier_state.k_barrier)
            .context("failed to derive epoch key during sync from recovered barrier state")?;
        session.epoch_key = epoch_key;
    }
    session.barrier_state.barrier_version = ticket.barrier_version;
    session.barrier_state.kem_tree_hash_after = ticket_kem_tree_hash_after;

    session.regular_fingerprint = Some(bundle.hp_binding.seed_ctx_hash);
    session.fs_fingerprint = compute_fs_fingerprint_from_header(&bundle.header_map).or_else(|| {
        derive_fs_fingerprint_from_fields(
            session.fs_policy_version.as_str(),
            session.fs_ec,
            &session.fs_epoch_commit,
            session.fs_epoch_base_ts,
        )
    });
    session.fs_epoch_created_at = SystemTime::now();
    session.last_fetch_timestamp_ms = None;
    session
        .forward_state
        .set_last_we_epoch_id(session.we_epoch_id);
    session
        .forward_state
        .set_epoch_base_ts(session.fs_epoch_base_ts);

    Ok(EpochSyncOutcome {
        session,
        changed: previous_we_epoch_id != ticket.we_epoch_id
            || barrier_changed
            || !matches!(
                pending_history_outcome,
                PendingBarrierHistoryOutcome::Unchanged
            ),
    })
}

fn strip_rollup_metadata(header: &mut BTreeMap<u64, Value>) {
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
    if let Some(epoch_commit) = pivot.fs_epoch_commit {
        header
            .entry(hdr::HDR_FS_EPOCH_COMMIT)
            .or_insert_with(|| Value::Bytes(epoch_commit.to_vec()));
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

fn select_pivot_parity(parities: &[PivotParity]) -> Option<&PivotParity> {
    parities.iter().max_by(|a, b| {
        a.accept_seq
            .cmp(&b.accept_seq)
            .then_with(|| b.xk_hash.cmp(&a.xk_hash))
    })
}

fn hex_encode_prefix(bytes: &[u8; 32], prefix_len: usize) -> String {
    let hex = hex_encode(bytes);
    if prefix_len >= hex.len() {
        hex
    } else {
        format!("{}…", &hex[..prefix_len])
    }
}

fn room_admin_identity_preview(bytes: &[u8]) -> String {
    let hex = hex_encode(bytes);
    if hex.len() <= 24 {
        hex
    } else {
        let prefix = &hex[..12];
        let suffix = &hex[hex.len().saturating_sub(12)..];
        format!("{prefix}…{suffix}")
    }
}

fn format_alias_display(alias: &str, leaf: &[u8; 32]) -> String {
    format!("{alias} ({})", hex_encode_prefix(leaf, 8))
}

fn fingerprint_full_hex(bytes: &[u8; 32]) -> String {
    hex_encode(bytes)
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

fn format_regular_fingerprint(value: Option<&[u8; 32]>) -> String {
    match value {
        Some(bytes) => fingerprint_preview_hex(bytes),
        None => "Not available".to_string(),
    }
}

fn format_fs_fingerprint(value: Option<&[u8; 32]>, fs_ec: u64) -> String {
    match value {
        Some(bytes) => format!("{} · fs_ec {}", fingerprint_preview_hex(bytes), fs_ec),
        None => "Not available".to_string(),
    }
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
    let policy = header_policy_version(header, hdr::HDR_FS_POLICY_VERSION)?;
    let fs_ec = header_u64(header, hdr::HDR_FS_EC)?;
    let fs_epoch_commit = header_bytes32(header, hdr::HDR_FS_EPOCH_COMMIT)?;
    let fs_epoch_base_ts = header_u64(header, hdr::HDR_FS_EPOCH_BASE_TS)?;
    derive_fs_fingerprint_from_fields(policy.as_str(), fs_ec, &fs_epoch_commit, fs_epoch_base_ts)
}

fn header_policy_version(header: &BTreeMap<u64, Value>, key: u64) -> Option<String> {
    match header.get(&key)? {
        Value::Text(text) => Some(text.clone()),
        Value::Integer(value) => u64::try_from(*value).ok().map(|v| v.to_string()),
        _ => None,
    }
}

fn header_text(header: &BTreeMap<u64, Value>, key: u64) -> Option<&str> {
    match header.get(&key)? {
        Value::Text(text) => Some(text.as_str()),
        _ => None,
    }
}

fn header_u64(header: &BTreeMap<u64, Value>, key: u64) -> Option<u64> {
    match header.get(&key)? {
        Value::Integer(int) => (*int).try_into().ok(),
        _ => None,
    }
}

fn header_bytes32(header: &BTreeMap<u64, Value>, key: u64) -> Option<[u8; 32]> {
    match header.get(&key)? {
        Value::Bytes(bytes) => bytes.as_slice().try_into().ok(),
        _ => None,
    }
}

fn decode_hex_32(input: &str) -> Option<[u8; 32]> {
    let bytes = hex_decode(input).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Some(result)
}

fn decode_room_admin_target_hex(input: &str) -> Result<Vec<u8>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("room admin target identity must not be empty"));
    }
    let normalized = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let bytes = hex_decode(normalized).context("room admin target must be valid hex")?;
    let expected_len = dilithium5::public_key_bytes();
    if bytes.len() != expected_len {
        return Err(anyhow!(
            "room admin target must be {} bytes (got {})",
            expected_len,
            bytes.len()
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
fn configured_hex_from_env(var_name: &str) -> Result<Option<Vec<u8>>> {
    let raw = match std::env::var(var_name) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(err) => {
            return Err(anyhow!("failed reading {}: {}", var_name, err));
        }
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let normalized = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if normalized.is_empty() {
        return Ok(None);
    }

    let bytes =
        hex_decode(normalized).with_context(|| format!("{var_name} must contain hex bytes"))?;
    Ok(Some(bytes))
}

fn generate_kbroad_keypair() -> (Vec<u8>, Vec<u8>) {
    let (public, secret) = kyber768::keypair();
    (
        KemPublicKey::as_bytes(&public).to_vec(),
        KemSecretKey::as_bytes(&secret).to_vec(),
    )
}

fn build_identity_binding(
    alias: &str,
    pop_public_key: &[u8],
    pop_secret_key: &[u8],
) -> Result<cityg_api_client::IdentityBinding> {
    use ciborium::ser::into_writer;
    use cityg_api_client::IdentityBinding;
    use pqcrypto_traits::sign::DetachedSignature as _;
    use serde_bytes::ByteBuf;

    let pop_secret = dilithium5::SecretKey::from_bytes(pop_secret_key)
        .context("invalid persisted room identity secret key")?;
    let message_data = (
        ByteBuf::from(alias.as_bytes().to_vec()),
        ByteBuf::from(pop_public_key.to_vec()),
    );
    let mut message = Vec::new();
    into_writer(&message_data, &mut message)
        .context("failed to encode identity binding message")?;
    let signature = dilithium5::detached_sign(&message, &pop_secret);

    Ok(IdentityBinding {
        alias: alias.to_string(),
        pop_public_key: pop_public_key.to_vec(),
        signature: signature.as_bytes().to_vec(),
    })
}

fn format_member_label(member: &MemberEntry) -> String {
    if let Some(alias) = member.alias.as_ref().filter(|s| !s.is_empty()) {
        format_alias_display(alias, &member.leaf_id)
    } else {
        hex_encode(member.leaf_id)
    }
}

fn format_timestamp(ts_ms: u64) -> String {
    let dt = UNIX_EPOCH + Duration::from_millis(ts_ms);
    format_rfc3339_seconds(dt).to_string()
}

fn current_unix_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn short_leaf_display(leaf: &[u8; 32]) -> String {
    format!("{}…", hex_encode(&leaf[..4]))
}

fn recompute_proofs_commit(header: &BTreeMap<u64, Value>) -> Result<[u8; 32]> {
    let vrf = header_bytes(header, hdr::HDR_VRF_PROOF, "vrf_proof")?;
    let fs = header_bytes(header, hdr::HDR_FS_CAPSS, "fs_capss")?;
    let srx_root = header_bytes32_opt(header, hdr::HDR_SRX_ROOT_SW)?;
    let srx_smallwood = header_bytes_opt(header, hdr::HDR_SRX_SMALLWOOD)?;
    compute_proofs_commit_bytes(
        &vrf,
        &fs,
        srx_root.as_ref().map(|arr| arr.as_slice()),
        srx_smallwood.as_deref(),
    )
    .map_err(|err| anyhow!("compute proofs commit: {err}"))
}

fn recompute_srx_commit(header: &BTreeMap<u64, Value>) -> Result<Option<[u8; 32]>> {
    let payload = match header.get(&hdr::HDR_SRX_PAYLOAD) {
        Some(Value::Bytes(bytes)) => bytes.as_slice(),
        Some(Value::Null) | None => return Ok(None),
        Some(_) => return Err(anyhow!("srx_payload must be bytes")),
    };

    #[derive(Serialize)]
    struct SrxCommit<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

    let commit = h_l(ds::MSPHF_SRX_COMMIT, &SrxCommit(payload))
        .map_err(|err| anyhow!("compute srx commit: {err}"))?;
    Ok(Some(commit))
}

fn header_bytes(header: &BTreeMap<u64, Value>, key: u64, label: &'static str) -> Result<Vec<u8>> {
    match header.get(&key) {
        Some(Value::Bytes(bytes)) => Ok(bytes.clone()),
        Some(_) => Err(anyhow!("{label} must be bytes")),
        None => Err(anyhow!("{label} missing")),
    }
}

fn header_bytes_opt(header: &BTreeMap<u64, Value>, key: u64) -> Result<Option<Vec<u8>>> {
    match header.get(&key) {
        Some(Value::Bytes(bytes)) => Ok(Some(bytes.clone())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(anyhow!("header {key} must be bytes")),
    }
}

fn header_bytes32_opt(header: &BTreeMap<u64, Value>, key: u64) -> Result<Option<[u8; 32]>> {
    match header.get(&key) {
        Some(Value::Bytes(bytes)) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            Ok(Some(arr))
        }
        Some(Value::Bytes(_)) => Err(anyhow!("header {key} must be 32 bytes")),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(anyhow!("header {key} must be bytes")),
    }
}

fn bytes32(name: &str, data: &[u8]) -> Result<[u8; 32]> {
    data.try_into()
        .map_err(|_| anyhow!("{name} must be 32 bytes, received {} bytes", data.len()))
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::await_holding_lock,
    clippy::useless_conversion
)]
#[path = "native/tests/mod.rs"]
mod tests;
