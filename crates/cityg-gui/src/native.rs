#[cfg(test)]
use std::cell::RefCell;
#[cfg(not(test))]
use std::sync::{LazyLock, Mutex};
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    io::Write,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
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
use blake3::hash as blake3_hash;
use ciborium::value::{Integer, Value};
use cityg_api_client::{
    BarrierJoinRecord, BarrierPublicTree, CitygApiClient, Error as ApiClientError, MergeTicket,
};
use cityg_client::witness::SrxInputsOwned;
use cityg_client::{CityGClient, ClientEpochBundle};
use cityg_config::CityGConfig;
use dirs::config_dir;
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
use rand::{Rng, RngCore, thread_rng};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message as WsMessage};
use tracing::{debug, info, warn};
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
use cityg_client::demo;

fn generate_vrf_keys() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut params_seed = [0u8; 32];
    let mut key_seed = [0u8; 32];
    let mut rng = thread_rng();
    rng.fill_bytes(&mut params_seed);
    rng.fill_bytes(&mut key_seed);
    let params = msphf_orchestrator::lb::generate_parameters(params_seed)
        .map_err(|err| anyhow!("generate VRF params: {err}"))?;
    msphf_orchestrator::lb::generate_keypair(&params, key_seed)
        .map_err(|err| anyhow!("generate VRF keypair: {err}"))
}

const DEFAULT_BARRIER_N_MAX: u64 = 1_024;
#[cfg(test)]
const DEFAULT_MAX_BARRIER_UPDATE_BYTES: u64 = 1_048_576;
const BARRIER_TREE_INFO: &[u8] = b"city-g|barrier/tree|v1";
const BARRIER_KEY_INFO: &[u8] = b"city-g|barrier/key|v1";
const BARRIER_KEYGEN_D_INFO: &[u8] = b"city-g|barrier/keygen-d|v1";
const BARRIER_KEYGEN_Z_INFO: &[u8] = b"city-g|barrier/keygen-z|v1";
const FS_PCS_INFO: &[u8] = b"city-g|fs/pcs|v1";
const ML_KEM_SEED_BYTES: usize = 64;
const ML_KEM_EXPANDED_DK_BYTES: usize = 2400;
const BARRIER_CODE_RECOVER_NO_MATCH: u32 = 9606;
const BARRIER_CODE_SNAPSHOT_AUTH_FAILURE: u32 = 9609;
const TICKET_RETRY_MAX_ATTEMPTS: u32 = 4;
const TICKET_RETRY_BASE_DELAY_MS: u64 = 50;
const TICKET_RETRY_MAX_DELAY_MS: u64 = 800;
const TICKET_RETRY_JITTER_MS: u64 = 40;

fn should_retry_ticket_http_error(
    status_code: u16,
    message: &str,
    freeze_code: Option<u32>,
) -> bool {
    let lowered = message.to_ascii_lowercase();
    let looks_like_concurrency_race = lowered.contains("window full")
        || lowered.contains("mh_heads_invalid")
        || lowered.contains("barrier_version")
        || lowered.contains("pivot head missing")
        || lowered.contains("refresh payload diverges from stored parity")
        || lowered.contains("barrier_update required on revocation change")
        || lowered.contains("barrier update required on revocation change");
    let status_hint = matches!(status_code, 409 | 429 | 500 | 503);
    let freeze_hint = matches!(freeze_code, Some(925));
    status_hint && (looks_like_concurrency_race || freeze_hint)
}

fn ticket_retry_delay(attempt: u32) -> Duration {
    let exponent = attempt.min(5);
    let base = TICKET_RETRY_BASE_DELAY_MS.saturating_mul(1u64 << exponent);
    let capped = base.min(TICKET_RETRY_MAX_DELAY_MS);
    let jitter = thread_rng().gen_range(0..=TICKET_RETRY_JITTER_MS);
    Duration::from_millis(capped.saturating_add(jitter))
}

#[derive(Serialize)]
struct BarrierRootsPreimage<'a>(
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    #[serde(with = "serde_bytes")] &'a [u8; 32],
);

#[derive(Serialize)]
struct BarrierUpdateDigestPreimage<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

#[derive(Serialize)]
struct BarrierPkHashPreimage<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

#[derive(Serialize)]
struct BarrierTreeLeafHashPreimage<'a> {
    n_max: u64,
    node_index: u64,
    #[serde(with = "serde_bytes")]
    pk: &'a [u8],
}

#[derive(Serialize)]
struct BarrierTreeNodeHashPreimage<'a> {
    n_max: u64,
    node_index: u64,
    #[serde(with = "serde_bytes")]
    pk: &'a [u8],
    #[serde(with = "serde_bytes")]
    left_hash: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    right_hash: &'a [u8; 32],
}

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
struct BarrierTreePathSaltPreimage(u64);

#[derive(Serialize)]
struct BarrierDeriveSaltPreimage<'a>(u64, #[serde(with = "serde_bytes")] &'a [u8; 32]);

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

fn compute_revocation_roots_hash(
    revoked_since_root: &[u8; 32],
    revoked_root: &[u8; 32],
) -> Result<[u8; 32]> {
    h_l(
        "barrier/roots",
        &BarrierRootsPreimage(revoked_since_root, revoked_root),
    )
    .map_err(|err| anyhow!("compute revocation_roots_hash: {err}"))
}

fn compute_barrier_pkhash(ek: &[u8]) -> Result<[u8; 32]> {
    h_l("barrier/pk-hash", &BarrierPkHashPreimage(ek))
        .map_err(|err| anyhow!("compute barrier/pk-hash: {err}"))
}

fn compute_barrier_update_digest(raw_update: &[u8]) -> Result<[u8; 32]> {
    h_l(
        "barrier/update/digest",
        &BarrierUpdateDigestPreimage(raw_update),
    )
    .map_err(|err| anyhow!("compute barrier_update_digest: {err}"))
}

fn compute_barrier_tree_hash(n_max: u64, pk_entries: &[Vec<u8>]) -> Result<[u8; 32]> {
    let n_max_usize =
        usize::try_from(n_max).map_err(|_| anyhow!("barrier tree n_max too large"))?;
    let expected_len = n_max_usize
        .checked_mul(2)
        .and_then(|v| v.checked_sub(1))
        .ok_or_else(|| anyhow!("barrier tree size overflow"))?;
    if pk_entries.len() != expected_len {
        return Err(anyhow!(
            "barrier tree size mismatch: expected {expected_len}, got {}",
            pk_entries.len()
        ));
    }
    let leaf_base = n_max.saturating_sub(1);
    compute_barrier_tree_hash_recursive(0, leaf_base, n_max, pk_entries)
}

fn compute_barrier_tree_hash_recursive(
    node: u64,
    leaf_base: u64,
    n_max: u64,
    pk_entries: &[Vec<u8>],
) -> Result<[u8; 32]> {
    let node_index =
        usize::try_from(node).map_err(|_| anyhow!("barrier node index out of range"))?;
    let pk = pk_entries
        .get(node_index)
        .ok_or_else(|| anyhow!("barrier node index out of range"))?;
    if node >= leaf_base {
        return h_l(
            "barrier/tree/leaf-hash",
            &BarrierTreeLeafHashPreimage {
                n_max,
                node_index: node,
                pk: pk.as_slice(),
            },
        )
        .map_err(|err| anyhow!("compute barrier leaf hash: {err}"));
    }

    let left = node
        .checked_mul(2)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| anyhow!("barrier tree index overflow"))?;
    let right = node
        .checked_mul(2)
        .and_then(|v| v.checked_add(2))
        .ok_or_else(|| anyhow!("barrier tree index overflow"))?;
    let left_hash = compute_barrier_tree_hash_recursive(left, leaf_base, n_max, pk_entries)?;
    let right_hash = compute_barrier_tree_hash_recursive(right, leaf_base, n_max, pk_entries)?;
    h_l(
        "barrier/tree/node-hash",
        &BarrierTreeNodeHashPreimage {
            n_max,
            node_index: node,
            pk: pk.as_slice(),
            left_hash: &left_hash,
            right_hash: &right_hash,
        },
    )
    .map_err(|err| anyhow!("compute barrier node hash: {err}"))
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

fn sibling_node(node: u64) -> Option<u64> {
    if node == 0 {
        return None;
    }
    if node.is_multiple_of(2) {
        Some(node - 1)
    } else {
        Some(node + 1)
    }
}

fn blank_leaf_and_path(snapshot: &mut [Vec<u8>], leaf_node: u64) -> Result<()> {
    let mut node = leaf_node;
    loop {
        let index =
            usize::try_from(node).map_err(|_| anyhow!("barrier node index out of range"))?;
        let slot = snapshot
            .get_mut(index)
            .ok_or_else(|| anyhow!("barrier node index out of range"))?;
        slot.clear();
        if node == 0 {
            break;
        }
        node = (node - 1) / 2;
    }
    Ok(())
}

fn blank_internal_path_from_leaf(snapshot: &mut [Vec<u8>], leaf_node: u64) -> Result<()> {
    let mut node = leaf_node;
    while node > 0 {
        node = (node - 1) / 2;
        let index =
            usize::try_from(node).map_err(|_| anyhow!("barrier node index out of range"))?;
        let slot = snapshot
            .get_mut(index)
            .ok_or_else(|| anyhow!("barrier node index out of range"))?;
        slot.clear();
    }
    Ok(())
}

fn apply_join_set_to_snapshot(
    snapshot: &mut [Vec<u8>],
    n_max: u64,
    join_records: &[BarrierJoinRecord],
) -> Result<()> {
    let leaf_base = n_max.saturating_sub(1);
    for record in join_records {
        let leaf_node = leaf_base.saturating_add(u64::from(record.leaf_index));
        let index =
            usize::try_from(leaf_node).map_err(|_| anyhow!("barrier node index out of range"))?;
        let slot = snapshot
            .get_mut(index)
            .ok_or_else(|| anyhow!("barrier node index out of range"))?;
        *slot = record.ek_leaf.clone();
        blank_internal_path_from_leaf(snapshot, leaf_node)?;
    }
    Ok(())
}

fn apply_revoked_set_to_snapshot(
    snapshot: &mut [Vec<u8>],
    n_max: u64,
    revoked_indices: &[u32],
) -> Result<()> {
    let leaf_base = n_max.saturating_sub(1);
    for leaf_index in revoked_indices {
        let leaf_node = leaf_base.saturating_add(u64::from(*leaf_index));
        blank_leaf_and_path(snapshot, leaf_node)?;
    }
    Ok(())
}

fn collect_resolution_targets(
    snapshot: &[Vec<u8>],
    node: u64,
    leaf_base: u64,
    targets: &mut Vec<u64>,
) -> Result<()> {
    let index = usize::try_from(node).map_err(|_| anyhow!("barrier node index out of range"))?;
    let Some(pk) = snapshot.get(index) else {
        return Ok(());
    };
    if !pk.is_empty() {
        targets.push(node);
        return Ok(());
    }
    if node >= leaf_base {
        return Ok(());
    }
    let left = node
        .checked_mul(2)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| anyhow!("barrier tree index overflow"))?;
    let right = node
        .checked_mul(2)
        .and_then(|v| v.checked_add(2))
        .ok_or_else(|| anyhow!("barrier tree index overflow"))?;
    collect_resolution_targets(snapshot, left, leaf_base, targets)?;
    collect_resolution_targets(snapshot, right, leaf_base, targets)?;
    Ok(())
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
) -> Result<()> {
    let n_max = session.barrier_state.n_max.max(1);
    let parsed = parse_barrier_update_for_recover(raw_update, n_max, max_barrier_update_bytes)
        .map_err(|err| anyhow!("barrier full chain-check prevalidation failed (960.7): {err}"))?;
    let local_barrier_version = session.barrier_state.barrier_version;
    let barrier_reason = header_u64(header_map, hdr::HDR_BARRIER_UPDATE_REASON).ok_or_else(|| {
        anyhow!("barrier full chain-check prevalidation failed (960.7): missing barrier_update_reason")
    })?;
    let valid_local_progression = (parsed.prev_barrier_version == 0
        && parsed.barrier_version == 0
        && local_barrier_version == 0)
        || (parsed.prev_barrier_version == local_barrier_version
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
    let local_revocation_roots_hash =
        compute_revocation_roots_hash(&session.revoked_since_root, &session.revoked_root)?;
    let genesis_local_case = parsed.prev_barrier_version == 0
        && parsed.barrier_version == 0
        && local_barrier_version == 0;
    if !genesis_local_case {
        if local_revocation_roots_hash == parsed.revocation_roots_hash {
            if barrier_reason != 1 {
                return Err(anyhow!(
                    "barrier full chain-check prevalidation failed (960.7): local roots unchanged but barrier_update_reason != 1"
                ));
            }
        } else if barrier_reason != 0 {
            return Err(anyhow!(
                "barrier full chain-check prevalidation failed (960.7): local roots changed but barrier_update_reason != 0"
            ));
        }
    }

    let join_records = client
        .barrier_resolve_joins_since(room_id, parsed.prev_barrier_version)
        .await
        .map_err(|err| anyhow!("barrier full chain-check dependency failure (960.8): {err}"))?;
    let revoked_indices = client
        .barrier_resolve_revoked_leaves(room_id, &revocation_roots_hash)
        .await
        .map_err(|err| anyhow!("barrier full chain-check dependency failure (960.8): {err}"))?;

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

    Ok(())
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

fn try_recover_barrier_from_header(
    session: &AppSession,
    header_map: &BTreeMap<u64, Value>,
    weid: &[u8; 32],
    fs_ec: u64,
    max_barrier_update_bytes: usize,
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
    let local_barrier_version = session.barrier_state.barrier_version;
    let valid_local_progression = (parsed.prev_barrier_version == 0
        && parsed.barrier_version == 0
        && local_barrier_version == 0)
        || (parsed.prev_barrier_version == local_barrier_version
            && parsed.barrier_version == local_barrier_version.saturating_add(1));
    if !valid_local_progression {
        return Err(anyhow!(
            "barrier version progression does not match local barrier state"
        ));
    }
    if parsed.tree_size != n_max {
        return Err(anyhow!("barrier tree_size mismatch for local state"));
    }
    if parsed.kem_tree_hash_before != session.barrier_state.kem_tree_hash_after {
        return Err(anyhow!("barrier hash-chain before-hash mismatch"));
    }

    let revoked_since_root = header_bytes32(header_map, hdr::HDR_REVOKED_SINCE_ROOT)
        .ok_or_else(|| anyhow!("header revoked_since_prev_root is missing or malformed"))?;
    let revoked_root = header_bytes32(header_map, hdr::HDR_REVOKED_ROOT)
        .ok_or_else(|| anyhow!("header revoked_root is missing or malformed"))?;
    let expected_rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    if parsed.revocation_roots_hash != expected_rrh {
        return Err(anyhow!("barrier revocation_roots_hash mismatch"));
    }
    let local_rrh =
        compute_revocation_roots_hash(&session.revoked_since_root, &session.revoked_root)?;
    let reason = header_u64(header_map, hdr::HDR_BARRIER_UPDATE_REASON)
        .ok_or_else(|| anyhow!("barrier_update_reason is missing or malformed"))?;
    let genesis_local_case = parsed.prev_barrier_version == 0
        && parsed.barrier_version == 0
        && local_barrier_version == 0;
    if !genesis_local_case {
        if local_rrh == parsed.revocation_roots_hash {
            if reason != 1 {
                return Err(anyhow!(
                    "barrier_update_reason must be pcs_refresh (1) when local roots are unchanged"
                ));
            }
        } else if reason != 0 {
            return Err(anyhow!(
                "barrier_update_reason must be revocation_or_bootstrap (0) when local roots changed"
            ));
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
        snapshot.fs_dev_commit,
        snapshot.last_weid,
    );
    updated_state.set_epoch_base_ts(session.fs_epoch_base_ts);
    session.forward_state = updated_state;
}

fn apply_pending_barrier_activation(
    session: &mut AppSession,
    observed_barrier_version: u64,
    accepted_digest: Option<[u8; 32]>,
) -> Result<bool> {
    let Some(pending) = session.barrier_state.pending.clone() else {
        return Ok(false);
    };

    if observed_barrier_version < pending.barrier_version {
        return Ok(false);
    }

    if let Some(digest) = accepted_digest {
        if digest == pending.barrier_update_digest
            && observed_barrier_version == pending.barrier_version
        {
            let BarrierPendingState {
                barrier_version,
                k_barrier_new,
                kem_tree_hash_after,
                k_fs_after_pcs,
                on_path_key_material,
                ..
            } = pending;
            session.barrier_state.barrier_version = barrier_version;
            session.barrier_state.k_barrier = k_barrier_new;
            session.barrier_state.kem_tree_hash_after = kem_tree_hash_after;
            for (node, material) in on_path_key_material {
                session.barrier_state.dk_nodes.insert(node, material);
            }
            if let Some(k_fs_after_pcs) = k_fs_after_pcs {
                apply_forward_state_k_fs(session, *k_fs_after_pcs);
            }
            session.barrier_state.pending = None;
            session.barrier_state.barrier_recovery_pending = false;
            return Ok(true);
        }

        warn!(
            code = BARRIER_CODE_SNAPSHOT_AUTH_FAILURE,
            pending_barrier_version = pending.barrier_version,
            observed_barrier_version,
            "pending barrier activation digest mismatch; dropping pending state"
        );
        session.barrier_state.pending = None;
        return Ok(true);
    }

    if observed_barrier_version > pending.barrier_version {
        session.barrier_state.pending = None;
        return Ok(true);
    }

    Ok(false)
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
    let expected_nodes = usize::try_from(n_max)
        .ok()
        .and_then(|n| n.checked_mul(2))
        .and_then(|v| v.checked_sub(1))
        .ok_or_else(|| anyhow!("invalid barrier n_max"))?;
    if snapshot_pre.len() != expected_nodes {
        return Err(anyhow!(
            "barrier snapshot size mismatch: expected {expected_nodes}, got {}",
            snapshot_pre.len()
        ));
    }

    let leaf_base = n_max.saturating_sub(1);
    let mut path_nodes = vec![leaf_base.saturating_add(updater_leaf)];
    while let Some(&node) = path_nodes.last() {
        if node == 0 {
            break;
        }
        path_nodes.push((node - 1) / 2);
    }

    let mut path_secrets = BTreeMap::new();
    let mut ps_leaf = [0u8; 32];
    thread_rng().fill_bytes(&mut ps_leaf);
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

mod tokio_bridge {
    use anyhow::Error;
    use gpui::{App, AppContext, Global, Task};
    use std::future::Future;
    use tokio::{
        runtime::{Builder, Runtime},
        task::AbortHandle,
    };

    pub fn init(app: &mut App) {
        app.set_global(GlobalTokio::new());
    }

    struct GlobalTokio {
        runtime: Runtime,
    }

    impl Global for GlobalTokio {}

    impl GlobalTokio {
        #[allow(clippy::expect_used)]
        fn new() -> Self {
            let runtime = Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("Failed to build Tokio runtime");
            Self { runtime }
        }
    }

    struct AbortGuard(Option<AbortHandle>);

    impl Drop for AbortGuard {
        fn drop(&mut self) {
            if let Some(handle) = self.0.take() {
                handle.abort();
            }
        }
    }

    pub struct Tokio;

    impl Tokio {
        pub fn spawn_result<C, Fut, R>(cx: &C, f: Fut) -> C::Result<Task<anyhow::Result<R>>>
        where
            C: AppContext,
            Fut: Future<Output = anyhow::Result<R>> + Send + 'static,
            R: Send + 'static,
        {
            cx.read_global(|tokio: &GlobalTokio, cx| {
                let join_handle = tokio.runtime.spawn(f);
                let abort_handle = join_handle.abort_handle();
                let cancel = AbortGuard(Some(abort_handle));
                cx.background_spawn(async move {
                    let result = join_handle.await;
                    drop(cancel);
                    result.map_err(Error::from)?
                })
            })
        }
    }
}

use tokio_bridge::Tokio;

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
    epoch_sync_task: Option<Task<()>>, // Background task for membership-driven epoch sync
    ws_task: Option<Task<()>>,         // WebSocket connection task
    ws_connected: bool,                // WebSocket connection status
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
    reconnect_delay: Duration,
    tx: futures_mpsc::UnboundedSender<WebSocketEvent>,
) -> Result<()> {
    loop {
        debug!("Attempting WebSocket connection to {}", ws_url);

        match connect_async(&ws_url).await {
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
    kbroad_secret: Vec<u8>,
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
    barrier_version: u64,
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
            barrier_version: 0,
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
    revocation_roots_hash: [u8; 32],
    kem_tree_hash_after: [u8; 32],
    k_barrier_new: Zeroizing<[u8; 32]>,
    k_fs_after_pcs: Option<Zeroizing<[u8; 32]>>,
    barrier_update_reason: Option<u64>,
    barrier_update_digest: [u8; 32],
    on_path_key_material: BTreeMap<u32, BarrierNodeKeyMaterial>,
}

impl AppModel {
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
            epoch_sync_task: None,
            ws_task: None,
            ws_connected: false,
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
                model.show_ciphertext = false;
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
        thread_rng().fill_bytes(&mut bytes);
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
                    .child("Room IDs must be 64 hexadecimal characters.")
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

    fn render_session(
        &self,
        window: &mut Window,
        session: &AppSession,
        cx: &mut ViewContext<Self>,
    ) -> Div {
        let window_size = window.bounds().size;
        let window_width = f32::from(window_size.width);
        let sidebar_width = if window_width >= 1360.0 {
            248.0
        } else if window_width >= 1100.0 {
            214.0
        } else {
            176.0
        };
        let details_width = if window_width >= 1460.0 {
            392.0
        } else if window_width >= 1180.0 {
            332.0
        } else {
            284.0
        };

        let mut center_column = div()
            .flex()
            .flex_col()
            .flex_grow()
            .min_w(px(280.0))
            .min_h(px(0.0))
            .h_full()
            .gap(px(12.0))
            .child(self.render_chat_header(session, cx))
            .child(self.render_message_panel(session, cx));

        if let Some(info) = &self.info_message {
            center_column = center_column.child(
                div()
                    .text_size(px(13.0))
                    .text_color(rgb(UI_ACCENT_TEXT))
                    .child(info.clone()),
            );
        }

        if let Some(error_box) = self.render_error_box(cx) {
            center_column = center_column.child(error_box);
        } else if let Some(err) = &self.last_error {
            center_column = center_column.child(
                div()
                    .text_size(px(13.0))
                    .text_color(rgb(UI_WARN_TEXT))
                    .child(err.clone()),
            );
        }

        let left_column = div()
            .flex()
            .flex_col()
            .min_w(px(sidebar_width))
            .max_w(px(sidebar_width))
            .min_h(px(0.0))
            .h_full()
            .gap(px(12.0))
            .child(self.render_workspace_sidebar(session, cx))
            .child(self.render_leave_controls(cx));

        let details_scroll = div()
            .flex()
            .flex_col()
            .flex_grow()
            .min_h(px(0.0))
            .h_full()
            .gap(px(12.0))
            .id("session-details-scroll")
            .track_scroll(&self.right_sidebar_scroll_handle)
            .overflow_y_scroll()
            .block_mouse_except_scroll()
            .child(self.render_overview_panel(session, cx))
            .child(self.render_members_panel(cx))
            .child(self.render_security_panel(cx))
            .child(self.render_activity_panel(cx));

        let right_column = div()
            .flex()
            .flex_col()
            .min_w(px(details_width))
            .max_w(px(details_width))
            .min_h(px(0.0))
            .h_full()
            .child(details_scroll);

        div()
            .flex()
            .w_full()
            .h_full()
            .min_w(px(0.0))
            .min_h(px(420.0))
            .px(px(16.0))
            .py(px(16.0))
            .gap(px(14.0))
            .bg(rgb(UI_CANVAS_BG))
            .child(left_column)
            .child(center_column)
            .child(right_column)
    }

    fn render_workspace_sidebar(&self, session: &AppSession, cx: &mut ViewContext<Self>) -> Div {
        let members_total = self.members_total.max(self.members.len() as u64);
        let ws_state = if self.ws_connected {
            ("Live updates", UI_ACCENT_TEXT)
        } else {
            ("Polling mode", UI_SUBTLE_TEXT)
        };
        let room_preview = if session.room_id.len() > 20 {
            format!(
                "{}…{}",
                &session.room_id[..12],
                &session.room_id[session.room_id.len().saturating_sub(6)..]
            )
        } else {
            session.room_id.clone()
        };
        let mut copy_room_button = div()
            .px(px(10.0))
            .py(px(6.0))
            .rounded(px(10.0))
            .bg(rgb(UI_BUTTON_BG))
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(UI_PANEL_TEXT))
            .cursor(CursorStyle::PointingHand)
            .child("Copy room ID");
        copy_room_button =
            copy_room_button.on_mouse_down(MouseButton::Left, cx.listener(Self::on_copy_room_id));

        div()
            .flex()
            .flex_col()
            .gap(px(12.0))
            .px(px(14.0))
            .py(px(14.0))
            .rounded(px(14.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .bg(rgb(UI_SIDEBAR_BG))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(4.0))
                    .child(
                        div()
                            .text_size(px(17.0))
                            .font_weight(FontWeight::BOLD)
                            .text_color(rgb(UI_PANEL_TEXT))
                            .child("City-G"),
                    )
                    .child(
                        div()
                            .text_size(px(12.0))
                            .text_color(rgb(UI_SUBTLE_TEXT))
                            .child("Workspace"),
                    ),
            )
            .child(
                div()
                    .px(px(10.0))
                    .py(px(8.0))
                    .rounded(px(10.0))
                    .bg(rgb(UI_ROW_BG))
                    .child(
                        div()
                            .text_size(px(11.0))
                            .text_color(rgb(UI_MUTED_TEXT))
                            .child("Room"),
                    )
                    .child(
                        div()
                            .text_size(px(13.0))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(UI_PANEL_TEXT))
                            .child(format!("#{}", room_preview)),
                    ),
            )
            .child(copy_room_button)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(6.0))
                    .child(
                        div()
                            .text_size(px(12.0))
                            .text_color(rgb(ws_state.1))
                            .child(ws_state.0),
                    )
                    .child(
                        div()
                            .text_size(px(12.0))
                            .text_color(rgb(UI_SUBTLE_TEXT))
                            .child(format!("Alias: {}", session.alias)),
                    )
                    .child(
                        div()
                            .text_size(px(12.0))
                            .text_color(rgb(UI_SUBTLE_TEXT))
                            .child(format!("Members: {}/{}", self.members.len(), members_total)),
                    )
                    .child(
                        div()
                            .text_size(px(11.0))
                            .text_color(rgb(UI_MUTED_TEXT))
                            .child(session.server_url.clone()),
                    ),
            )
    }

    fn render_chat_header(&self, session: &AppSession, cx: &mut ViewContext<Self>) -> Div {
        let room_label = if session.room_id.len() > 28 {
            format!(
                "{}…{}",
                &session.room_id[..16],
                &session.room_id[session.room_id.len().saturating_sub(8)..]
            )
        } else {
            session.room_id.clone()
        };
        let ws_state = if self.ws_connected {
            "WebSocket live"
        } else {
            "Polling fallback"
        };
        let fetch_state = match self.fetch_status {
            FetchStatus::Idle => "Idle",
            FetchStatus::Refreshing => "Refreshing",
        };
        let status_text = format!("{} • {}", ws_state, fetch_state);
        let status_color = if matches!(self.fetch_status, FetchStatus::Refreshing) {
            rgb(UI_ACCENT_TEXT)
        } else {
            rgb(UI_SUBTLE_TEXT)
        };

        let mut toggle_ciphertext = div()
            .px(px(12.0))
            .py(px(7.0))
            .rounded(px(10.0))
            .bg(rgb(UI_ACCENT_TEXT))
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(UI_ACCENT_BUTTON_TEXT))
            .cursor(CursorStyle::PointingHand)
            .child(if self.show_ciphertext {
                "Hide ciphertext"
            } else {
                "Show ciphertext"
            });
        toggle_ciphertext = toggle_ciphertext
            .on_mouse_down(MouseButton::Left, cx.listener(Self::on_toggle_ciphertext));

        div()
            .flex()
            .items_center()
            .justify_between()
            .px(px(16.0))
            .py(px(12.0))
            .rounded(px(14.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .bg(rgb(UI_PANEL_BG))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(4.0))
                    .child(
                        div()
                            .text_size(px(21.0))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(UI_PANEL_TEXT))
                            .child(format!("# {}", room_label)),
                    )
                    .child(
                        div()
                            .text_size(px(12.0))
                            .text_color(status_color)
                            .child(status_text),
                    ),
            )
            .child(toggle_ciphertext)
    }

    fn render_overview_panel(&self, session: &AppSession, cx: &mut ViewContext<Self>) -> Div {
        div()
            .flex()
            .flex_col()
            .gap(px(8.0))
            .px(px(12.0))
            .py(px(12.0))
            .rounded(px(14.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .bg(rgb(UI_PANEL_BG))
            .child(
                div()
                    .text_size(px(16.0))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(UI_PANEL_TEXT))
                    .child("Session overview"),
            )
            .child(self.session_row("Server", &session.server_url))
            .child(self.render_copyable_session_row(
                "Room ID",
                &session.room_id,
                Self::on_copy_room_id,
                cx,
            ))
            .child(self.session_row("Alias", &session.alias))
            .child(self.session_row("WEID", &hex_encode(session.we_epoch_id)))
            .child(self.session_row("Epoch key", &hex_encode(session.epoch_key)))
            .child(self.session_row("Parent root", &hex_encode(session.parent_root)))
            .child(self.session_row("Join delta", &hex_encode(session.join_delta_root)))
            .child(self.session_row("Revoked since", &hex_encode(session.revoked_since_root)))
            .child(self.session_row("Revoked root", &hex_encode(session.revoked_root)))
            .child(self.render_regular_fingerprint_row(session, cx))
            .child(self.render_fs_fingerprint_row(session, cx))
            .child(self.session_row("Proof mode", &session.proof_mode))
            .child(self.session_row("VRF suite", &session.vrf_id))
            .child(self.session_row("Policy", &session.policy_version))
            .child(self.session_row("FS policy", &session.fs_policy_version))
            .child(self.render_epoch_age_row(session))
            .child(self.session_row("KBROAD key (hex)", &hex_encode(&session.kbroad_public)))
    }

    fn session_row(&self, label: &str, value: &str) -> Div {
        div()
            .flex()
            .flex_col()
            .gap(px(3.0))
            .px(px(10.0))
            .py(px(8.0))
            .rounded(px(10.0))
            .bg(rgb(UI_ROW_BG))
            .child(
                div()
                    .text_size(px(11.0))
                    .text_color(rgb(UI_MUTED_TEXT))
                    .child(label.to_string()),
            )
            .child(
                div()
                    .text_size(px(13.0))
                    .text_color(rgb(UI_PANEL_TEXT))
                    .child(value.to_string()),
            )
    }

    fn render_copyable_session_row(
        &self,
        label: &str,
        value: &str,
        handler: fn(&mut Self, &MouseDownEvent, &mut Window, &mut ViewContext<Self>),
        cx: &mut ViewContext<Self>,
    ) -> Div {
        div()
            .flex()
            .flex_col()
            .gap(px(4.0))
            .px(px(10.0))
            .py(px(8.0))
            .rounded(px(10.0))
            .bg(rgb(UI_ROW_BG))
            .child(
                div()
                    .text_size(px(11.0))
                    .text_color(rgb(UI_MUTED_TEXT))
                    .child(label.to_string()),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap(px(8.0))
                    .child(
                        div()
                            .flex_grow()
                            .text_size(px(13.0))
                            .text_color(rgb(UI_PANEL_TEXT))
                            .child(value.to_string()),
                    )
                    .child(
                        div()
                            .px(px(10.0))
                            .py(px(6.0))
                            .rounded(px(10.0))
                            .text_size(px(12.0))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(rgb(UI_ACCENT_BUTTON_TEXT))
                            .bg(rgb(UI_ACCENT_TEXT))
                            .cursor(CursorStyle::PointingHand)
                            .child("Copy")
                            .on_mouse_down(MouseButton::Left, cx.listener(handler)),
                    ),
            )
    }

    fn render_epoch_age_row(&self, session: &AppSession) -> Div {
        let epoch_age_secs = SystemTime::now()
            .duration_since(session.fs_epoch_created_at)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        let rotation_interval = session.fs_epoch_rotation_interval_secs;

        let age_text = if epoch_age_secs < 60 {
            format!("{} seconds", epoch_age_secs)
        } else if epoch_age_secs < 3600 {
            format!("{} minutes", epoch_age_secs / 60)
        } else {
            format!("{:.1} hours", epoch_age_secs as f64 / 3600.0)
        };

        let value_text = format!(
            "Epoch #{} - Age: {} (manual rekey target: {}s)",
            session.fs_ec, age_text, rotation_interval
        );

        div()
            .flex()
            .flex_col()
            .gap(px(3.0))
            .px(px(10.0))
            .py(px(8.0))
            .rounded(px(10.0))
            .bg(rgb(UI_ROW_BG))
            .child(
                div()
                    .text_size(px(11.0))
                    .text_color(rgb(UI_MUTED_TEXT))
                    .child("Forward Secrecy Epoch"),
            )
            .child(
                div()
                    .text_size(px(13.0))
                    .text_color(rgb(UI_PANEL_TEXT))
                    .child(value_text),
            )
    }

    fn render_regular_fingerprint_row(
        &self,
        session: &AppSession,
        cx: &mut ViewContext<Self>,
    ) -> Div {
        self.render_fingerprint_row(
            "Regular fingerprint",
            format_regular_fingerprint(session.regular_fingerprint.as_ref()),
            session.regular_fingerprint.is_some(),
            Self::on_copy_regular_fingerprint,
            cx,
        )
    }

    fn render_fs_fingerprint_row(&self, session: &AppSession, cx: &mut ViewContext<Self>) -> Div {
        self.render_fingerprint_row(
            "FS fingerprint",
            format_fs_fingerprint(session.fs_fingerprint.as_ref(), session.fs_ec),
            session.fs_fingerprint.is_some(),
            Self::on_copy_fs_fingerprint,
            cx,
        )
    }

    fn render_fingerprint_row(
        &self,
        label: &str,
        value: String,
        copy_enabled: bool,
        handler: fn(&mut Self, &MouseDownEvent, &mut Window, &mut ViewContext<Self>),
        cx: &mut ViewContext<Self>,
    ) -> Div {
        let mut copy_button = div()
            .px(px(10.0))
            .py(px(6.0))
            .rounded(px(10.0))
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(if copy_enabled {
                rgb(UI_ACCENT_BUTTON_TEXT)
            } else {
                rgb(UI_MUTED_TEXT)
            })
            .bg(if copy_enabled {
                rgb(UI_ACCENT_TEXT)
            } else {
                rgb(UI_BUTTON_BG)
            })
            .cursor(if copy_enabled {
                CursorStyle::PointingHand
            } else {
                CursorStyle::Arrow
            })
            .child("Copy");

        if copy_enabled {
            copy_button = copy_button.on_mouse_down(MouseButton::Left, cx.listener(handler));
        }

        div()
            .flex()
            .flex_col()
            .gap(px(4.0))
            .px(px(10.0))
            .py(px(8.0))
            .rounded(px(10.0))
            .bg(rgb(UI_ROW_BG))
            .child(
                div()
                    .text_size(px(11.0))
                    .text_color(rgb(UI_MUTED_TEXT))
                    .child(label.to_string()),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap(px(8.0))
                    .child(
                        div()
                            .flex_grow()
                            .text_size(px(13.0))
                            .text_color(rgb(UI_PANEL_TEXT))
                            .child(value),
                    )
                    .child(copy_button),
            )
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

    fn ensure_fetch_loop(&mut self, cx: &mut ViewContext<Self>) {
        if self.session.is_none() {
            self.reset_fetch_state();
            return;
        }

        if !self.fetch_in_flight && self.fetch_task.is_none() {
            self.schedule_fetch(cx, Duration::from_millis(0));
        }
    }

    fn reset_fetch_state(&mut self) {
        self.fetch_in_flight = false;
        self.fetch_status = FetchStatus::Idle;
        self.fetch_task = None;
    }

    fn ensure_epoch_sync_task(&mut self, _cx: &mut ViewContext<Self>) {
        // Keep the task lifecycle bounded to active sessions.
        if self.session.is_none() && self.epoch_sync_task.is_some() {
            self.stop_epoch_sync_task();
        }
    }

    fn ensure_websocket_task(&mut self, cx: &mut ViewContext<Self>) {
        if self.session.is_none() {
            self.stop_websocket();
            return;
        }

        if self.ws_task.is_none() {
            self.start_websocket(cx);
            self.schedule_epoch_sync(cx, "Syncing latest epoch after session restore…");
        }
    }

    fn ensure_members_refresh_task(&mut self, cx: &mut ViewContext<Self>) {
        if self.session.is_none() {
            self.stop_members_refresh_task();
            return;
        }

        if self.members_refresh_task.is_none() {
            self.start_members_refresh_task(cx);
        }
    }

    fn schedule_epoch_sync(&mut self, cx: &mut ViewContext<Self>, reason: &str) {
        if self.epoch_sync_task.is_some() {
            return;
        }

        let Some(session) = self.session.clone() else {
            return;
        };

        let expected_server = session.server_url.clone();
        let expected_room = session.room_id.clone();
        let expected_leaf = session.leaf_id;
        let reason_text = reason.to_string();

        info!("Scheduling epoch sync: {}", reason_text);

        let sync_task = Tokio::spawn_result(cx, async move { perform_epoch_sync(session).await });

        let task = cx.spawn(async move |this, cx| {
            let outcome = sync_task.await;
            let _ = this.update(cx, |model, cx| {
                model.epoch_sync_task = None;
                model.handle_epoch_sync_result(
                    outcome,
                    &expected_server,
                    &expected_room,
                    expected_leaf,
                    &reason_text,
                    cx,
                );
            });
        });

        self.epoch_sync_task = Some(task);
    }

    fn handle_epoch_sync_result(
        &mut self,
        outcome: anyhow::Result<EpochSyncOutcome>,
        expected_server: &str,
        expected_room: &str,
        expected_leaf: [u8; 32],
        reason: &str,
        cx: &mut ViewContext<Self>,
    ) {
        let matches_session = self
            .session
            .as_ref()
            .map(|session| {
                session.server_url == expected_server
                    && session.room_id == expected_room
                    && session.leaf_id == expected_leaf
            })
            .unwrap_or(false);

        if !matches_session {
            return;
        }

        match outcome {
            Ok(sync) => {
                if !sync.changed {
                    return;
                }

                self.session = Some(sync.session);
                if let Some(session) = self.session.as_mut()
                    && let Err(err) = persist_session(session)
                {
                    warn!("failed to persist session after epoch sync: {err:?}");
                }

                self.info_message = Some("Adopted latest epoch head.".to_string());
                self.record_activity(ActivityKind::Sync, "Adopted latest epoch head after sync");
                self.reset_fetch_state();
                self.schedule_fetch(cx, Duration::ZERO);
                self.refresh_members_soft(cx);
                cx.notify();
            }
            Err(err) => {
                if is_stale_server_session_error(&err) {
                    self.handle_stale_server_session(
                        "Saved session is no longer recognized by the server. Please join again.",
                        cx,
                    );
                    return;
                }
                warn!("epoch sync failed ({reason}): {err:?}");
                self.last_error = Some(format!("Failed to sync latest epoch: {err}"));
                self.record_activity_with_detail(
                    ActivityKind::Sync,
                    "Epoch sync failed",
                    Some(err.to_string()),
                );
                cx.notify();
            }
        }
    }

    fn schedule_fetch(&mut self, cx: &mut ViewContext<Self>, delay: Duration) {
        let Some(session) = self.session.clone() else {
            self.reset_fetch_state();
            return;
        };

        if self.fetch_in_flight {
            return;
        }

        self.fetch_in_flight = true;
        if delay.is_zero() {
            self.fetch_status = FetchStatus::Refreshing;
        }

        let since = session.last_fetch_timestamp_ms;
        let params = match FetchParams::from_session(&session, since) {
            Ok(params) => params,
            Err(err) => {
                self.fetch_in_flight = false;
                self.fetch_status = FetchStatus::Idle;
                self.last_error = Some(format!("Failed to prepare message fetch: {err}"));
                self.record_activity_with_detail(
                    ActivityKind::Message,
                    "Message fetch skipped",
                    Some(err.to_string()),
                );
                return;
            }
        };
        let expected_weid = session.we_epoch_id;

        let task = cx.spawn(async move |this, cx| {
            let fetch_future = match Tokio::spawn_result(cx, async move {
                if !delay.is_zero() {
                    sleep(delay).await;
                }
                perform_fetch(params).await
            }) {
                Ok(task) => task,
                Err(err) => {
                    let _ = this.update(cx, |model, _| {
                        model.fetch_task = None;
                        model.fetch_in_flight = false;
                        model.fetch_status = FetchStatus::Idle;
                        model.last_error = Some(format!("Failed to schedule message fetch: {err}"));
                    });
                    return;
                }
            };

            let outcome = fetch_future.await;

            let _ = this.update(cx, |model, cx| {
                model.fetch_task = None;
                model.fetch_in_flight = false;
                model.handle_fetch_result(outcome, expected_weid, cx);
            });
        });

        self.fetch_task = Some(task);
    }

    fn handle_fetch_result(
        &mut self,
        outcome: anyhow::Result<FetchOutcome>,
        expected_weid: [u8; 32],
        cx: &mut ViewContext<Self>,
    ) {
        let matches_session = self
            .session
            .as_ref()
            .map(|session| session.we_epoch_id == expected_weid)
            .unwrap_or(false);

        if !matches_session {
            self.fetch_status = FetchStatus::Idle;
            return;
        }

        let delay = match outcome {
            Ok(result) => {
                let FetchOutcome {
                    messages,
                    last_timestamp_ms,
                    msg_replay_state,
                } = result;

                if !messages.is_empty() {
                    let added = self.append_messages(messages);
                    if added > 0 {
                        self.info_message = Some(format!("Fetched {added} new message(s)."));
                        self.record_activity(
                            ActivityKind::Message,
                            format!("Fetched {added} new message(s)"),
                        );
                    }
                }

                if let Some(session) = self.session.as_mut() {
                    let mut should_persist = false;
                    if session.msg_replay_state != msg_replay_state {
                        session.msg_replay_state = msg_replay_state;
                        should_persist = true;
                    }
                    if let Some(ts) = last_timestamp_ms {
                        let timestamp_changed = session
                            .last_fetch_timestamp_ms
                            .map(|prev| ts > prev)
                            .unwrap_or(true);
                        if timestamp_changed {
                            session.last_fetch_timestamp_ms = Some(ts);
                            should_persist = true;
                        }
                    }
                    if should_persist && let Err(err) = persist_session(session) {
                        warn!("failed to persist session after fetch update: {err:?}");
                    }
                }

                self.fetch_status = FetchStatus::Idle;
                self.config.client.fetch_poll_interval()
            }
            Err(err) => {
                if is_stale_server_session_error(&err) {
                    self.fetch_status = FetchStatus::Idle;
                    self.handle_stale_server_session(
                        "Saved session is no longer recognized by the server. Please join again.",
                        cx,
                    );
                    return;
                }
                self.last_error = Some(format!("Failed to fetch messages: {err}"));
                self.record_activity_with_detail(
                    ActivityKind::Message,
                    "Message fetch failed",
                    Some(err.to_string()),
                );
                self.fetch_status = FetchStatus::Idle;
                self.config.client.fetch_retry_interval()
            }
        };

        if !self.fetch_in_flight {
            self.schedule_fetch(cx, delay);
        }
    }

    fn append_messages(&mut self, new_messages: Vec<ChatMessageEntry>) -> usize {
        let mut inserted = 0usize;
        for mut message in new_messages {
            if message.ciphertext_hex.is_empty() {
                continue;
            }
            message.delivery = MessageDelivery::Sent;
            message.pending_id = None;
            let key = MessageKey {
                ciphertext_hex: message.ciphertext_hex.clone(),
                sender_leaf: message.sender_leaf,
            };
            if self.message_keys.insert(key) {
                self.messages.push(message);
                inserted = inserted.saturating_add(1);
            }
        }
        self.messages.sort_by_key(|m| m.timestamp_ms);
        if inserted > 0 {
            self.scroll_chat_to_bottom();
        }
        inserted
    }

    fn queue_pending_message(&mut self, session: &AppSession, plaintext: &str) -> u64 {
        let pending_id = self.next_pending_message_id;
        self.next_pending_message_id = self.next_pending_message_id.saturating_add(1);
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.messages.push(ChatMessageEntry {
            sender_leaf: Some(session.leaf_id),
            fallback_label: session.alias.clone(),
            plaintext: plaintext.to_string(),
            ciphertext_hex: String::new(),
            timestamp_ms,
            delivery: MessageDelivery::Pending,
            pending_id: Some(pending_id),
        });
        self.messages.sort_by_key(|m| m.timestamp_ms);
        self.scroll_chat_to_bottom();
        pending_id
    }

    fn confirm_pending_message(&mut self, pending_id: u64, mut entry: ChatMessageEntry) {
        entry.delivery = MessageDelivery::Sent;
        entry.pending_id = None;
        let key = MessageKey {
            ciphertext_hex: entry.ciphertext_hex.clone(),
            sender_leaf: entry.sender_leaf,
        };

        if self.message_keys.insert(key) {
            if let Some(index) = self
                .messages
                .iter()
                .position(|message| message.pending_id == Some(pending_id))
            {
                self.messages[index] = entry;
            } else {
                self.messages.push(entry);
            }
        } else {
            self.messages
                .retain(|message| message.pending_id != Some(pending_id));
        }
        self.messages.sort_by_key(|m| m.timestamp_ms);
        self.scroll_chat_to_bottom();
    }

    fn mark_pending_message_failed(&mut self, pending_id: u64) {
        if let Some(message) = self
            .messages
            .iter_mut()
            .find(|message| message.pending_id == Some(pending_id))
        {
            message.delivery = MessageDelivery::Failed;
            message.pending_id = None;
        }
    }

    // Stop background epoch sync task
    fn stop_epoch_sync_task(&mut self) {
        if self.epoch_sync_task.is_some() {
            info!("Stopping epoch sync task");
            self.epoch_sync_task = None;
        }
    }

    fn start_members_refresh_task(&mut self, cx: &mut ViewContext<Self>) {
        let interval = self.config.gui.members_refresh_interval();
        let task = cx.spawn(async move |this, cx| {
            loop {
                let delay = match Tokio::spawn_result(cx, async move {
                    sleep(interval).await;
                    Ok(())
                }) {
                    Ok(task) => task,
                    Err(err) => {
                        warn!("failed to schedule members refresh delay: {err}");
                        break;
                    }
                };
                if let Err(err) = delay.await {
                    warn!("members refresh delay task failed: {err}");
                    break;
                }

                let keep_running = this
                    .update(cx, |model, cx| {
                        if model.session.is_some() {
                            model.refresh_members_soft(cx);
                            true
                        } else {
                            false
                        }
                    })
                    .unwrap_or(false);

                if !keep_running {
                    info!("Stopping members refresh task (session ended)");
                    break;
                }
            }
        });

        self.members_refresh_task = Some(task);
    }

    fn stop_members_refresh_task(&mut self) {
        if self.members_refresh_task.is_some() {
            info!("Stopping members refresh task");
            self.members_refresh_task = None;
        }
    }

    // Start WebSocket connection
    fn start_websocket(&mut self, cx: &mut ViewContext<Self>) {
        let Some(session) = &self.session else {
            return;
        };
        let Some(message_token) = configured_client_message_token() else {
            warn!("message auth token is not configured; skipping websocket startup");
            return;
        };

        // Convert HTTP URL to WebSocket URL
        let ws_url = session
            .server_url
            .replace("http://", "ws://")
            .replace("https://", "wss://");
        let ws_url = format!(
            "{}/v1/ws?gid={}&leaf_id={}&token={}",
            ws_url,
            hex_encode(session.gid),
            hex_encode(session.leaf_id),
            message_token
        );
        let reconnect_delay = self.config.client.websocket_reconnect_delay();

        info!("Starting WebSocket connection to {}", ws_url);

        let this = cx.weak_entity();
        let (event_tx, mut event_rx) = futures_mpsc::unbounded::<WebSocketEvent>();
        let task = cx.spawn(async move |_, cx| {
            let runner = match Tokio::spawn_result(
                cx,
                run_websocket_worker(ws_url.clone(), reconnect_delay, event_tx),
            ) {
                Ok(task) => task,
                Err(err) => {
                    warn!("failed to schedule websocket worker: {err}");
                    return;
                }
            };

            while let Some(event) = event_rx.next().await {
                let _ = this.update(cx, |model, cx| {
                    model.handle_websocket_event(event, cx);
                });
            }

            if let Err(err) = runner.await {
                warn!("websocket worker task failed: {err}");
            }
        });

        self.ws_task = Some(task);
    }

    fn handle_websocket_event(&mut self, event: WebSocketEvent, cx: &mut ViewContext<Self>) {
        match event {
            WebSocketEvent::Connected => {
                self.ws_connected = true;
                self.record_activity(
                    ActivityKind::Connection,
                    "WebSocket connected (live updates enabled)",
                );
                self.schedule_epoch_sync(cx, "Syncing latest epoch after WebSocket reconnect…");
                cx.notify();
            }
            WebSocketEvent::Disconnected => {
                self.ws_connected = false;
                self.record_activity(
                    ActivityKind::Connection,
                    "WebSocket disconnected (falling back to polling)",
                );
                cx.notify();
            }
            WebSocketEvent::Message => {
                self.record_activity(ActivityKind::Message, "New message notification");
                if !self.fetch_in_flight {
                    self.schedule_fetch(cx, Duration::ZERO);
                }
            }
            WebSocketEvent::Membership(signal) => {
                self.record_membership_activity(&signal);
                self.handle_membership_signal(&signal, cx);
            }
        }
    }

    // Stop WebSocket connection
    fn stop_websocket(&mut self) {
        if self.ws_task.is_some() {
            info!("Stopping WebSocket connection");
            self.ws_task = None;
            self.ws_connected = false;
        }
    }

    fn render_message_panel(&self, _session: &AppSession, cx: &mut ViewContext<Self>) -> Div {
        div()
            .flex()
            .flex_col()
            .flex_grow()
            .min_h(px(0.0))
            .h_full()
            .gap(px(14.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .rounded(px(14.0))
            .px(px(16.0))
            .py(px(14.0))
            .bg(rgb(UI_PANEL_BG))
            .child(self.render_message_list())
            .child(self.render_message_composer(cx))
    }

    fn render_message_list(&self) -> impl IntoElement {
        let mut list = div()
            .flex()
            .flex_col()
            .flex_grow()
            .min_h(px(0.0))
            .gap(px(8.0))
            .px(px(2.0))
            .py(px(2.0))
            .id("chat-message-list")
            .track_scroll(&self.chat_scroll_handle);
        list = list.overflow_y_scroll().block_mouse_except_scroll();

        if self.messages.is_empty() {
            return list.child(
                div()
                    .text_size(px(13.0))
                    .text_color(rgb(UI_MUTED_TEXT))
                    .child("No messages yet. Send one to warm up this room."),
            );
        }

        for message in &self.messages {
            let timestamp =
                format_rfc3339_seconds(UNIX_EPOCH + Duration::from_millis(message.timestamp_ms));
            let sender = self.resolve_sender_label(message);
            let (card_bg, card_border, body_color, meta_color, status_line) = match message.delivery
            {
                MessageDelivery::Pending => (
                    rgb(0x1d293b),
                    rgb(0x2d4057),
                    rgb(0xe1e7ff),
                    rgb(0xa2b2d6),
                    Some(("sending...", rgb(UI_ACCENT_TEXT))),
                ),
                MessageDelivery::Failed => (
                    rgb(0x32212c),
                    rgb(0x563342),
                    rgb(0xffd7e3),
                    rgb(0xffafc3),
                    Some(("failed to send", rgb(0xff8ca7))),
                ),
                MessageDelivery::Sent => (
                    rgb(0x171f31),
                    rgb(0x243149),
                    rgb(0xf2f5ff),
                    rgb(0x9eabd2),
                    None,
                ),
            };
            let mut entry = div()
                .flex()
                .flex_col()
                .gap(px(4.0))
                .bg(card_bg)
                .rounded(px(11.0))
                .border(px(1.0))
                .border_color(card_border)
                .px(px(12.0))
                .py(px(10.0))
                .child(
                    div()
                        .flex()
                        .justify_between()
                        .text_size(px(12.0))
                        .text_color(rgb(UI_SUBTLE_TEXT))
                        .child(format!("{} • {}", sender, timestamp)),
                )
                .child(
                    div()
                        .text_size(px(14.0))
                        .text_color(body_color)
                        .child(message.plaintext.clone()),
                )
                .child(div().text_size(px(11.0)).text_color(meta_color).child(
                    if self.show_ciphertext {
                        format!("ciphertext: {}", message.ciphertext_hex)
                    } else {
                        "ciphertext hidden".to_string()
                    },
                ));

            if let Some((label, color)) = status_line {
                entry = entry.child(div().text_size(px(11.0)).text_color(color).child(label));
            }

            list = list.child(entry);
        }

        list
    }

    fn resolve_sender_label(&self, message: &ChatMessageEntry) -> String {
        if let Some(leaf) = message.sender_leaf
            && let Some(label) = self.member_label_for_leaf(&leaf)
        {
            return label;
        }
        message.fallback_label.clone()
    }

    fn member_label_for_leaf(&self, leaf: &[u8; 32]) -> Option<String> {
        if let Some(member) = self.members.iter().find(|member| &member.leaf_id == leaf) {
            return Some(format_member_label(member));
        }
        if let Some(alias) = self.leaf_alias_index.get(leaf) {
            return Some(format_alias_display(alias, leaf));
        }
        None
    }

    fn reconcile_alias_bindings(&mut self, cx: &mut ViewContext<Self>) {
        let Some(session) = &self.session else {
            return;
        };
        let server_url = session.server_url.clone();
        let room_id = session.room_id.clone();

        let mut mismatches = Vec::new();
        let mut refreshed: AHashMap<String, AliasBindingRecord> = AHashMap::new();

        for member in &self.members {
            let Some(alias) = member
                .alias
                .as_ref()
                .map(|alias| alias.trim())
                .filter(|alias| !alias.is_empty())
                .map(|alias| alias.to_string())
            else {
                continue;
            };

            let Some(pop_key) = member.pop_public_key.as_ref().filter(|pk| !pk.is_empty()) else {
                continue;
            };

            if let Some(existing) = self.alias_bindings.get(&alias)
                && existing.pop_public_key != *pop_key
            {
                mismatches.push(alias.clone());
            }

            refreshed.insert(
                alias,
                AliasBindingRecord {
                    pop_public_key: pop_key.clone(),
                    leaf_id: member.leaf_id,
                },
            );
        }

        for alias in mismatches {
            let message = format!("TOFU alert: alias '{alias}' broadcast a new identity key.");
            self.show_error_toast(message.clone(), cx);
            self.record_security_event(&alias, message, cx);
        }

        let changed = refreshed != self.alias_bindings;
        self.alias_bindings = refreshed;
        self.refresh_leaf_alias_index();

        if changed
            && let Err(err) = persist_alias_bindings(&server_url, &room_id, &self.alias_bindings)
        {
            warn!("failed to persist alias bindings: {err:?}");
        }
    }

    fn hydrate_alias_bindings_from_disk(&mut self) {
        if let Some(session) = &self.session {
            match load_alias_bindings(&session.server_url, &session.room_id) {
                Ok(bindings) => {
                    self.alias_bindings = bindings;
                    self.refresh_leaf_alias_index();
                }
                Err(err) => {
                    warn!("failed to load alias bindings: {err:?}");
                    self.alias_bindings.clear();
                    self.leaf_alias_index.clear();
                }
            }
        } else {
            self.alias_bindings.clear();
            self.leaf_alias_index.clear();
        }
    }

    fn load_security_events_from_disk(&mut self) {
        if let Some(session) = &self.session {
            match load_security_log(&session.server_url, &session.room_id) {
                Ok(events) => {
                    self.security_events = events;
                    self.security_unread = 0;
                    self.security_panel_expanded = !self.security_events.is_empty();
                }
                Err(err) => {
                    warn!("failed to load security log: {err:?}");
                    self.security_events.clear();
                    self.security_unread = 0;
                    self.security_panel_expanded = false;
                }
            }
        } else {
            self.security_events.clear();
            self.security_unread = 0;
            self.security_panel_expanded = false;
        }
    }

    fn persist_security_events_to_disk(&self) {
        let Some(session) = &self.session else {
            return;
        };
        if let Err(err) =
            persist_security_log(&session.server_url, &session.room_id, &self.security_events)
        {
            warn!("failed to persist security log: {err:?}");
        }
    }

    fn record_security_event(
        &mut self,
        alias: &str,
        description: impl Into<String>,
        cx: &mut ViewContext<Self>,
    ) {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.security_events.push(SecurityEvent {
            alias: alias.to_string(),
            description: description.into(),
            timestamp_ms,
        });
        if self.security_events.len() > MAX_SECURITY_EVENTS {
            let drain = self.security_events.len() - MAX_SECURITY_EVENTS;
            self.security_events.drain(0..drain);
        }
        self.security_unread = self.security_unread.saturating_add(1);
        self.security_panel_expanded = true;
        self.persist_security_events_to_disk();
        cx.notify();
    }

    fn record_activity(&mut self, kind: ActivityKind, summary: impl Into<String>) {
        self.record_activity_with_detail(kind, summary, None);
    }

    fn record_activity_with_detail(
        &mut self,
        kind: ActivityKind,
        summary: impl Into<String>,
        detail: Option<String>,
    ) {
        self.activity_events.push(ActivityEvent {
            kind,
            summary: summary.into(),
            detail,
            timestamp_ms: current_unix_timestamp_ms(),
        });
        if self.activity_events.len() > MAX_ACTIVITY_EVENTS {
            let drain = self.activity_events.len() - MAX_ACTIVITY_EVENTS;
            self.activity_events.drain(0..drain);
        }
    }

    fn record_membership_activity(&mut self, signal: &MembershipSignal) {
        let summary = match (signal.kind, signal.leaf_id) {
            (Some(MembershipSignalKind::Join), Some(leaf)) => {
                format!("Roster join: {}", short_leaf_display(&leaf))
            }
            (Some(MembershipSignalKind::Revoke), Some(leaf)) => {
                format!("Roster revoke: {}", short_leaf_display(&leaf))
            }
            (Some(MembershipSignalKind::Join), None) => "Roster join detected".to_string(),
            (Some(MembershipSignalKind::Revoke), None) => "Roster revoke detected".to_string(),
            (None, Some(leaf)) => format!("Roster changed: {}", short_leaf_display(&leaf)),
            (None, None) => "Roster changed".to_string(),
        };
        let detail = signal
            .timestamp_ms
            .map(|ts| format!("server timestamp {}", format_timestamp(ts)));
        self.record_activity_with_detail(ActivityKind::Roster, summary, detail);
    }

    fn acknowledge_security_alerts(&mut self) {
        if self.security_unread > 0 {
            self.security_unread = 0;
        }
    }

    fn refresh_leaf_alias_index(&mut self) {
        self.leaf_alias_index.clear();
        for (alias, record) in &self.alias_bindings {
            if record.leaf_id.iter().all(|&b| b == 0) {
                continue;
            }
            self.leaf_alias_index.insert(record.leaf_id, alias.clone());
        }
    }

    fn scroll_chat_to_bottom(&self) {
        self.chat_scroll_handle.scroll_to_bottom();
    }

    fn render_message_composer(&self, cx: &mut ViewContext<Self>) -> Div {
        let border_color = if self.composer.active {
            rgb(0x72f88e)
        } else {
            rgb(0x2a3148)
        };
        let background = if self.composer.active {
            rgb(0x1b2135)
        } else {
            rgb(0x161b2a)
        };

        let text_color = if self.composer.text.is_empty() {
            rgb(0x5b6584)
        } else {
            rgb(0xf5f7ff)
        };

        let placeholder = if self.composer.active {
            "Type a message…"
        } else {
            "Click to start typing…"
        };

        let mut row = div().flex().items_center().gap(px(12.0));

        row = row.child(
            div()
                .flex_grow()
                .px(px(14.0))
                .py(px(10.0))
                .rounded(px(12.0))
                .border(px(1.0))
                .border_color(border_color)
                .bg(background)
                .cursor(CursorStyle::IBeam)
                .on_mouse_down(MouseButton::Left, cx.listener(Self::on_composer_clicked))
                .child(div().text_size(px(15.0)).text_color(text_color).child(
                    if self.composer.text.is_empty() {
                        placeholder.to_string()
                    } else {
                        self.composer.text.clone()
                    },
                )),
        );

        let send_disabled = !self.composer.is_ready()
            || matches!(self.send_status, SendStatus::Sending)
            || self.session.is_none();

        let label = match self.send_status {
            SendStatus::Sending => "Sending…",
            SendStatus::Idle => "Send",
        };

        let mut button = div()
            .px(px(16.0))
            .py(px(10.0))
            .rounded(px(10.0))
            .text_size(px(15.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(0x0f1118))
            .bg(if send_disabled {
                rgb(0x3a3f57)
            } else {
                rgb(0x72f88e)
            })
            .cursor(if send_disabled {
                CursorStyle::Arrow
            } else {
                CursorStyle::PointingHand
            })
            .child(label);

        if !send_disabled {
            button = button.on_mouse_down(MouseButton::Left, cx.listener(Self::on_send_clicked));
        }

        row.child(button)
    }

    fn render_leave_controls(&self, cx: &mut ViewContext<Self>) -> Div {
        let leaving = matches!(self.leave_status, LeaveStatus::Leaving);
        let refreshing = matches!(self.leave_status, LeaveStatus::Refreshing);
        let membership_op_busy = leaving || refreshing;
        let mut leave_button = div()
            .px(px(12.0))
            .py(px(8.0))
            .rounded(px(12.0))
            .text_size(px(14.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(0xfafafa))
            .bg(if leaving {
                rgb(0x5a4552)
            } else if membership_op_busy {
                rgb(0x4b3f45)
            } else {
                rgb(0xbb4f68)
            })
            .cursor(if membership_op_busy {
                CursorStyle::Arrow
            } else {
                CursorStyle::PointingHand
            })
            .child(if leaving { "Leaving…" } else { "Leave room" });

        if !membership_op_busy {
            leave_button =
                leave_button.on_mouse_down(MouseButton::Left, cx.listener(Self::on_leave_clicked));
        }

        let mut refresh_button = div()
            .px(px(12.0))
            .py(px(8.0))
            .rounded(px(12.0))
            .text_size(px(14.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(0xfafafa))
            .bg(if refreshing {
                rgb(0x42516d)
            } else if membership_op_busy {
                rgb(0x3b4559)
            } else {
                rgb(0x4f79bb)
            })
            .cursor(if membership_op_busy {
                CursorStyle::Arrow
            } else {
                CursorStyle::PointingHand
            })
            .child(if refreshing {
                "Refreshing…"
            } else {
                "PCS refresh"
            });

        if !membership_op_busy {
            refresh_button = refresh_button
                .on_mouse_down(MouseButton::Left, cx.listener(Self::on_refresh_clicked));
        }

        let reset_button = div()
            .px(px(12.0))
            .py(px(8.0))
            .rounded(px(12.0))
            .text_size(px(14.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(UI_PANEL_TEXT))
            .bg(rgb(UI_BUTTON_BG))
            .cursor(CursorStyle::PointingHand)
            .child("Reset session")
            .on_mouse_down(MouseButton::Left, cx.listener(Self::on_reset_clicked));

        div()
            .flex()
            .flex_col()
            .gap(px(8.0))
            .px(px(12.0))
            .py(px(12.0))
            .rounded(px(14.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .bg(rgb(UI_SIDEBAR_BG))
            .child(
                div()
                    .text_size(px(12.0))
                    .text_color(rgb(UI_MUTED_TEXT))
                    .child("Session controls"),
            )
            .child(leave_button)
            .child(refresh_button)
            .child(reset_button)
    }

    fn render_members_panel(&self, cx: &mut ViewContext<Self>) -> Div {
        let count = self.members.len();
        let total = self.members_total.max(count as u64);
        let title_text = match &self.members_mode {
            MembersMode::Full => format!("Members ({count} / {total})"),
            MembersMode::Search { query } => {
                format!("Search \"{}\" ({count} / {total})", query)
            }
        };
        let mut header = div().flex().items_center().justify_between().child(
            div()
                .text_size(px(15.0))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(rgb(UI_PANEL_TEXT))
                .child(title_text),
        );

        let refresh_button = div()
            .px(px(8.0))
            .py(px(5.0))
            .rounded(px(10.0))
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(UI_PANEL_TEXT))
            .bg(rgb(UI_BUTTON_BG))
            .cursor(CursorStyle::PointingHand)
            .child("Refresh")
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(Self::on_members_refresh_clicked),
            );

        header = header.child(refresh_button);

        if let Some(next_offset) = self.members_next_offset
            && next_offset < total
        {
            let load_more = div()
                .px(px(8.0))
                .py(px(5.0))
                .rounded(px(10.0))
                .text_size(px(12.0))
                .font_weight(FontWeight::MEDIUM)
                .text_color(rgb(UI_PANEL_TEXT))
                .bg(rgb(0x32415f))
                .cursor(CursorStyle::PointingHand)
                .child("Load more")
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(Self::on_members_load_more_clicked),
                );
            header = header.child(load_more);
        }

        let search_placeholder = "Filter alias or leaf hex";
        let search_active = self.members_search.active;
        let search_border = if search_active {
            rgb(UI_ACCENT_TEXT)
        } else {
            rgb(UI_PANEL_BORDER)
        };
        let search_background = if search_active {
            rgb(0x1b2840)
        } else {
            rgb(UI_ROW_BG)
        };
        let search_text_color = if self.members_search.query.is_empty() {
            rgb(UI_MUTED_TEXT)
        } else {
            rgb(UI_PANEL_TEXT)
        };
        let search_display = if self.members_search.query.is_empty() {
            search_placeholder.to_string()
        } else {
            self.members_search.query.clone()
        };

        let search_field = div()
            .flex()
            .items_center()
            .flex_grow()
            .px(px(10.0))
            .py(px(7.0))
            .rounded(px(10.0))
            .border(px(1.0))
            .border_color(search_border)
            .bg(search_background)
            .cursor(CursorStyle::IBeam)
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(Self::on_members_search_field_clicked),
            )
            .child(
                div()
                    .text_size(px(12.0))
                    .text_color(search_text_color)
                    .child(search_display),
            );

        let search_button = div()
            .px(px(8.0))
            .py(px(6.0))
            .rounded(px(10.0))
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(UI_PANEL_TEXT))
            .bg(rgb(UI_BUTTON_BG))
            .cursor(CursorStyle::PointingHand)
            .child("Search")
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(Self::on_members_search_button_clicked),
            );

        let mut search_row = div().flex().items_center().gap(px(10.0));
        search_row = search_row.child(search_field).child(search_button);

        let has_query = !self.members_search.query.trim().is_empty();
        if has_query || matches!(self.members_mode, MembersMode::Search { .. }) {
            let clear_button = div()
                .px(px(8.0))
                .py(px(6.0))
                .rounded(px(10.0))
                .text_size(px(12.0))
                .font_weight(FontWeight::MEDIUM)
                .text_color(rgb(UI_PANEL_TEXT))
                .bg(rgb(0x3e4b66))
                .cursor(CursorStyle::PointingHand)
                .child("Clear")
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(Self::on_members_search_clear_clicked),
                );
            search_row = search_row.child(clear_button);
        }

        let mut list = div().flex().flex_col().gap(px(6.0));

        if self.members.is_empty() {
            list = list.child(
                div()
                    .text_size(px(12.0))
                    .text_color(rgb(UI_SUBTLE_TEXT))
                    .child("No members reported for this root."),
            );
        } else {
            for member in &self.members {
                let primary_label = format_member_label(member);
                let mut entry = div()
                    .px(px(9.0))
                    .py(px(7.0))
                    .rounded(px(10.0))
                    .bg(rgb(UI_ROW_BG))
                    .border(px(1.0))
                    .border_color(rgb(0x2c3952))
                    .flex()
                    .flex_col()
                    .gap(px(3.0))
                    .child(
                        div()
                            .text_size(px(13.0))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(rgb(UI_PANEL_TEXT))
                            .child(primary_label),
                    )
                    .child(
                        div()
                            .text_size(px(11.0))
                            .text_color(rgb(UI_SUBTLE_TEXT))
                            .child(format!("leaf: {}", hex_encode(member.leaf_id))),
                    );

                if let Some(joined) = member.join_timestamp_ms {
                    entry = entry.child(
                        div()
                            .text_size(px(11.0))
                            .text_color(rgb(UI_MUTED_TEXT))
                            .child(format!("joined {}", format_timestamp(joined))),
                    );
                }

                if let Some(last_seen) = member.last_seen_timestamp_ms {
                    entry = entry.child(
                        div()
                            .text_size(px(11.0))
                            .text_color(rgb(UI_MUTED_TEXT))
                            .child(format!("last seen {}", format_timestamp(last_seen))),
                    );
                }

                list = list.child(entry);
            }
        }

        let status_text = match &self.members_status {
            MembersStatus::Idle => None,
            MembersStatus::Loading(message) => Some(message.clone()),
            MembersStatus::Error(message) => Some(message.clone()),
        };

        let mut root = div()
            .flex()
            .flex_col()
            .gap(px(8.0))
            .px(px(12.0))
            .py(px(12.0))
            .rounded(px(14.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .bg(rgb(UI_PANEL_BG))
            .child(header);
        root = root.child(search_row);
        if let Some(text) = status_text {
            root = root.child(
                div()
                    .text_size(px(12.0))
                    .text_color(rgb(UI_WARN_TEXT))
                    .child(text),
            );
        }
        root.child(list)
    }

    fn render_security_panel(&self, cx: &mut ViewContext<Self>) -> Div {
        let count = self.security_events.len();
        let title = div()
            .text_size(px(15.0))
            .font_weight(FontWeight::SEMIBOLD)
            .text_color(rgb(UI_PANEL_TEXT))
            .child(format!("Security alerts ({count})"));
        let mut header = div().flex().items_center().justify_between().child(title);

        let mut actions = div().flex().items_center().gap(px(8.0));
        if self.security_unread > 0 {
            let badge = div()
                .px(px(8.0))
                .py(px(2.0))
                .rounded(px(999.0))
                .bg(rgb(0xff9f68))
                .text_size(px(11.0))
                .font_weight(FontWeight::BOLD)
                .text_color(rgb(0x0f1118))
                .child(format!("{} new", self.security_unread));
            let ack_button = div()
                .px(px(8.0))
                .py(px(4.0))
                .rounded(px(8.0))
                .text_size(px(12.0))
                .font_weight(FontWeight::MEDIUM)
                .text_color(rgb(UI_PANEL_TEXT))
                .bg(rgb(UI_BUTTON_BG))
                .cursor(CursorStyle::PointingHand)
                .child("Mark read")
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(Self::on_security_panel_mark_read_clicked),
                );
            actions = actions.child(badge).child(ack_button);
        }

        let toggle_label = if self.security_panel_expanded {
            "Hide"
        } else {
            "Show"
        };
        let toggle_button = div()
            .px(px(8.0))
            .py(px(4.0))
            .rounded(px(8.0))
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(UI_PANEL_TEXT))
            .bg(rgb(UI_BUTTON_BG))
            .cursor(CursorStyle::PointingHand)
            .child(toggle_label)
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(Self::on_security_panel_toggle_clicked),
            );
        actions = actions.child(toggle_button);

        if self.security_panel_expanded && count > 0 {
            let clear_button = div()
                .px(px(8.0))
                .py(px(4.0))
                .rounded(px(8.0))
                .text_size(px(12.0))
                .font_weight(FontWeight::MEDIUM)
                .text_color(rgb(UI_PANEL_TEXT))
                .bg(rgb(0x3d4b66))
                .cursor(CursorStyle::PointingHand)
                .child("Clear log")
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(Self::on_security_log_clear_clicked),
                );
            actions = actions.child(clear_button);
        }

        header = header.child(actions);

        let mut list = div().flex().flex_col().gap(px(6.0));

        if !self.security_panel_expanded {
            let summary = if count == 0 {
                "No security alerts recorded."
            } else {
                "Alerts hidden. Click Show to review details."
            };
            list = list.child(
                div()
                    .text_size(px(12.0))
                    .text_color(rgb(UI_SUBTLE_TEXT))
                    .child(summary),
            );
        } else if self.security_events.is_empty() {
            list = list.child(
                div()
                    .text_size(px(12.0))
                    .text_color(rgb(UI_SUBTLE_TEXT))
                    .child("No security alerts recorded."),
            );
        } else {
            for event in self.security_events.iter().rev() {
                let entry = div()
                    .px(px(9.0))
                    .py(px(7.0))
                    .rounded(px(10.0))
                    .bg(rgb(0x2a1f31))
                    .border(px(1.0))
                    .border_color(rgb(0x4b334f))
                    .flex()
                    .flex_col()
                    .gap(px(2.0))
                    .child(
                        div()
                            .text_size(px(12.0))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(rgb(0xffe3ee))
                            .child(format!("{} – {}", event.alias, event.description)),
                    )
                    .child(
                        div()
                            .text_size(px(11.0))
                            .text_color(rgb(0xd3aec2))
                            .child(format_timestamp(event.timestamp_ms)),
                    );
                list = list.child(entry);
            }
        }

        div()
            .flex()
            .flex_col()
            .gap(px(8.0))
            .px(px(12.0))
            .py(px(12.0))
            .rounded(px(14.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .bg(rgb(UI_PANEL_BG))
            .child(header)
            .child(list)
    }

    fn render_activity_panel(&self, cx: &mut ViewContext<Self>) -> Div {
        let count = self.activity_events.len();
        let title = div()
            .text_size(px(15.0))
            .font_weight(FontWeight::SEMIBOLD)
            .text_color(rgb(UI_PANEL_TEXT))
            .child(format!("Live activity ({count})"));
        let mut header = div().flex().items_center().justify_between().child(title);

        if count > 0 {
            let clear_button = div()
                .px(px(8.0))
                .py(px(4.0))
                .rounded(px(8.0))
                .text_size(px(12.0))
                .font_weight(FontWeight::MEDIUM)
                .text_color(rgb(UI_PANEL_TEXT))
                .bg(rgb(UI_BUTTON_BG))
                .cursor(CursorStyle::PointingHand)
                .child("Clear")
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(Self::on_activity_clear_clicked),
                );
            header = header.child(clear_button);
        }

        let ws_status = if self.ws_connected {
            "WS live"
        } else {
            "Polling"
        };
        let total_members = self.members_total.max(self.members.len() as u64);
        let metrics = div()
            .flex()
            .flex_wrap()
            .gap(px(8.0))
            .child(
                div()
                    .px(px(8.0))
                    .py(px(4.0))
                    .rounded(px(999.0))
                    .bg(rgb(0x213146))
                    .text_size(px(11.0))
                    .text_color(rgb(0x95c7ff))
                    .child(ws_status),
            )
            .child(
                div()
                    .px(px(8.0))
                    .py(px(4.0))
                    .rounded(px(999.0))
                    .bg(rgb(0x21382f))
                    .text_size(px(11.0))
                    .text_color(rgb(0x95f0b6))
                    .child(format!("messages {}", self.messages.len())),
            )
            .child(
                div()
                    .px(px(8.0))
                    .py(px(4.0))
                    .rounded(px(999.0))
                    .bg(rgb(0x39272b))
                    .text_size(px(11.0))
                    .text_color(rgb(0xffbf93))
                    .child(format!("members {}/{}", self.members.len(), total_members)),
            );

        let mut list = div().flex().flex_col().gap(px(6.0));

        if self.activity_events.is_empty() {
            list = list.child(
                div()
                    .text_size(px(12.0))
                    .text_color(rgb(UI_SUBTLE_TEXT))
                    .child("No live activity yet."),
            );
        } else {
            for event in self.activity_events.iter().rev() {
                let (label, chip_bg, chip_text, card_bg) = match event.kind {
                    ActivityKind::Connection => {
                        ("connection", rgb(0x233553), rgb(0x95c7ff), rgb(0x1f2a3d))
                    }
                    ActivityKind::Roster => ("roster", rgb(0x4b2e2e), rgb(0xffbf93), rgb(0x302428)),
                    ActivityKind::Message => {
                        ("message", rgb(0x244032), rgb(0x95f0b6), rgb(0x1f2f27))
                    }
                    ActivityKind::Sync => ("sync", rgb(0x2a3f46), rgb(0x9fe7f0), rgb(0x212e34)),
                    ActivityKind::System => ("system", rgb(0x373c4a), rgb(0xd0d6ef), rgb(0x262a36)),
                };
                let mut entry = div()
                    .px(px(9.0))
                    .py(px(7.0))
                    .rounded(px(10.0))
                    .bg(card_bg)
                    .border(px(1.0))
                    .border_color(rgb(0x33445d))
                    .flex()
                    .flex_col()
                    .gap(px(3.0))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .px(px(8.0))
                                    .py(px(2.0))
                                    .rounded(px(999.0))
                                    .bg(chip_bg)
                                    .text_size(px(10.0))
                                    .font_weight(FontWeight::BOLD)
                                    .text_color(chip_text)
                                    .child(label),
                            )
                            .child(
                                div()
                                    .text_size(px(11.0))
                                    .text_color(rgb(UI_SUBTLE_TEXT))
                                    .child(format_timestamp(event.timestamp_ms)),
                            ),
                    )
                    .child(
                        div()
                            .text_size(px(12.0))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(rgb(UI_PANEL_TEXT))
                            .child(event.summary.clone()),
                    );
                if let Some(detail) = event.detail.as_ref().filter(|text| !text.is_empty()) {
                    entry = entry.child(
                        div()
                            .text_size(px(11.0))
                            .text_color(rgb(UI_MUTED_TEXT))
                            .child(detail.clone()),
                    );
                }
                list = list.child(entry);
            }
        }

        div()
            .flex()
            .flex_col()
            .gap(px(8.0))
            .px(px(12.0))
            .py(px(12.0))
            .rounded(px(14.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .bg(rgb(UI_PANEL_BG))
            .child(header)
            .child(metrics)
            .child(list)
    }

    fn focus_members_search(&mut self, cx: &mut ViewContext<Self>) {
        self.members_search.focus();
        self.composer.blur();
        cx.notify();
    }

    fn submit_members_search(&mut self, cx: &mut ViewContext<Self>) {
        let query = self.members_search.query.trim().to_string();
        if query.is_empty() {
            if matches!(self.members_mode, MembersMode::Search { .. }) {
                self.refresh_members(cx);
            } else {
                cx.notify();
            }
            return;
        }

        self.refresh_members_for_mode(
            cx,
            MembersMode::Search {
                query: query.clone(),
            },
            true,
            true,
            format!("Searching for \"{}\"…", query),
        );
    }

    fn clear_members_search(&mut self, cx: &mut ViewContext<Self>) {
        self.members_search.clear();
        self.members_search.blur();
        if matches!(self.members_mode, MembersMode::Search { .. }) {
            self.refresh_members(cx);
        } else {
            cx.notify();
        }
    }

    fn handle_membership_signal(&mut self, signal: &MembershipSignal, cx: &mut ViewContext<Self>) {
        let Some(session) = &self.session else {
            return;
        };
        if session.gid != signal.gid {
            return;
        }
        if matches!(self.members_status, MembersStatus::Loading(_)) {
            self.schedule_epoch_sync(cx, "Syncing latest epoch after membership change…");
            return;
        }
        let mode = self.members_mode.clone();
        let message = match &mode {
            MembersMode::Full => "Syncing roster after membership change…".to_string(),
            MembersMode::Search { query } => format!("Updating search for \"{}\"…", query),
        };
        self.refresh_members_for_mode(cx, mode, true, true, message);
        self.schedule_epoch_sync(cx, "Syncing latest epoch after membership change…");
    }

    fn on_composer_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.join_form.active = None;
        self.members_search.blur();
        self.composer.focus();
        self.last_error = None;
        cx.notify();
    }

    fn on_send_clicked(&mut self, _: &MouseDownEvent, _: &mut Window, cx: &mut ViewContext<Self>) {
        self.start_send(cx);
    }

    fn on_toggle_ciphertext(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.show_ciphertext = !self.show_ciphertext;
        cx.notify();
    }

    fn focus_field(&mut self, field: ActiveField, cx: &mut ViewContext<Self>) {
        self.join_form.active = Some(field);
        self.composer.blur();
        cx.notify();
    }

    fn on_join_clicked(&mut self, _: &MouseDownEvent, _: &mut Window, cx: &mut ViewContext<Self>) {
        self.start_join(cx);
    }

    fn on_retry_clicked(&mut self, _: &MouseDownEvent, _: &mut Window, cx: &mut ViewContext<Self>) {
        match self.last_retry_action {
            Some(RetryAction::Join) => self.start_join(cx),
            Some(RetryAction::Send) => self.start_send(cx),
            Some(RetryAction::Leave) => {
                if let Some(session) = &self.session {
                    let request = LeaveRequest::from_session(session);
                    self.leave_status = LeaveStatus::Leaving;
                    self.clear_error();
                    cx.notify();
                    let task = Tokio::spawn_result(cx, async move { perform_leave(request).await });
                    cx.spawn(async move |this, cx| {
                        let outcome = task.await;
                        let _ = this.update(cx, |model, cx| {
                            model.on_leave_finished(outcome, cx);
                            cx.notify();
                        });
                    })
                    .detach();
                }
            }
            Some(RetryAction::Refresh) => self.start_pcs_refresh(cx),
            None => {}
        }
        self.clear_error();
        cx.notify();
    }

    fn on_copy_error_details(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if let Some(error) = &self.categorized_error {
            let details = format!(
                "City-G Error Report\n\
                 ==================\n\n\
                 Category: {:?}\n\
                 Error: {}\n\n\
                 Technical Details:\n\
                 {}\n\n\
                 Recovery Suggestion:\n\
                 {}",
                error.category,
                error.user_message,
                error.technical_details,
                error.recovery_suggestion
            );

            cx.write_to_clipboard(ClipboardItem::new_string(details.clone()));
            info!("Error details copied to logs:\n{}", details);
            warn!("Error Report:\n{}", details);
            self.show_success("Error details copied to clipboard", cx);
        }
    }

    fn on_copy_regular_fingerprint(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if let Some(session) = &self.session {
            if let Some(bytes) = session.regular_fingerprint {
                let text = fingerprint_full_hex(&bytes);
                cx.write_to_clipboard(ClipboardItem::new_string(text.clone()));
                self.show_success("Regular fingerprint copied", cx);
            } else {
                self.show_error_toast("Regular fingerprint unavailable", cx);
            }
        } else {
            self.show_error_toast("No active session", cx);
        }
    }

    fn on_copy_fs_fingerprint(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if let Some(session) = &self.session {
            if let Some(bytes) = session.fs_fingerprint {
                let text = fingerprint_full_hex(&bytes);
                cx.write_to_clipboard(ClipboardItem::new_string(text.clone()));
                self.show_success("FS fingerprint copied", cx);
            } else {
                self.show_error_toast("FS fingerprint unavailable", cx);
            }
        } else {
            self.show_error_toast("No active session", cx);
        }
    }

    fn on_copy_room_id(&mut self, _: &MouseDownEvent, _: &mut Window, cx: &mut ViewContext<Self>) {
        if let Some(session) = &self.session {
            cx.write_to_clipboard(ClipboardItem::new_string(session.room_id.clone()));
            self.show_success("Room ID copied", cx);
        } else {
            self.show_error_toast("No active session", cx);
        }
    }

    fn handle_join_form_clipboard_shortcuts(
        &mut self,
        keystroke: &Keystroke,
        cx: &mut ViewContext<Self>,
    ) -> KeyOutcome {
        let Some(active) = self.join_form.active else {
            return KeyOutcome::None;
        };

        if is_primary_shortcut(keystroke, "c") {
            let text = self.join_form.field(active).to_string();
            cx.write_to_clipboard(ClipboardItem::new_string(text));
            return KeyOutcome::Updated;
        }

        if is_primary_shortcut(keystroke, "x") {
            let text = self.join_form.field(active).to_string();
            cx.write_to_clipboard(ClipboardItem::new_string(text));
            self.join_form.field_mut(active).clear();
            return KeyOutcome::Updated;
        }

        if is_primary_shortcut(keystroke, "v") {
            if let Some(text) = cx.read_from_clipboard().and_then(|item| item.text()) {
                let existing = self.join_form.field(active).to_string();
                let updated = apply_join_field_paste(active, &existing, &text);
                *self.join_form.field_mut(active) = updated;
            }
            return KeyOutcome::Updated;
        }

        KeyOutcome::None
    }

    fn handle_composer_clipboard_shortcuts(
        &mut self,
        keystroke: &Keystroke,
        cx: &mut ViewContext<Self>,
    ) -> KeyOutcome {
        if !self.composer.active {
            return KeyOutcome::None;
        }

        if is_primary_shortcut(keystroke, "c") {
            cx.write_to_clipboard(ClipboardItem::new_string(self.composer.text().to_string()));
            return KeyOutcome::Updated;
        }

        if is_primary_shortcut(keystroke, "x") {
            cx.write_to_clipboard(ClipboardItem::new_string(self.composer.text().to_string()));
            self.composer.clear();
            return KeyOutcome::Updated;
        }

        if is_primary_shortcut(keystroke, "v") {
            if let Some(text) = cx.read_from_clipboard().and_then(|item| item.text()) {
                let mut updated = self.composer.text().to_string();
                updated.push_str(&sanitize_clipboard_text(&text));
                self.composer.set_text(updated);
            }
            return KeyOutcome::Updated;
        }

        KeyOutcome::None
    }

    fn handle_members_search_clipboard_shortcuts(
        &mut self,
        keystroke: &Keystroke,
        cx: &mut ViewContext<Self>,
    ) -> KeyOutcome {
        if !self.members_search.active {
            return KeyOutcome::None;
        }

        if is_primary_shortcut(keystroke, "c") {
            cx.write_to_clipboard(ClipboardItem::new_string(
                self.members_search.query().to_string(),
            ));
            return KeyOutcome::Updated;
        }

        if is_primary_shortcut(keystroke, "x") {
            cx.write_to_clipboard(ClipboardItem::new_string(
                self.members_search.query().to_string(),
            ));
            self.members_search.clear();
            return KeyOutcome::Updated;
        }

        if is_primary_shortcut(keystroke, "v") {
            if let Some(text) = cx.read_from_clipboard().and_then(|item| item.text()) {
                let mut updated = self.members_search.query().to_string();
                updated.push_str(&sanitize_clipboard_text(&text));
                self.members_search.set_query(updated);
            }
            return KeyOutcome::Updated;
        }

        KeyOutcome::None
    }

    fn on_report_issue(&mut self, _: &MouseDownEvent, _: &mut Window, cx: &mut ViewContext<Self>) {
        if let Some(error) = &self.categorized_error {
            let report = format!(
                "City-G Error Report\n\
                 ==================\n\n\
                 Category: {:?}\n\
                 Error: {}\n\n\
                 Technical Details:\n\
                 {}\n\n\
                 Recovery Suggestion:\n\
                 {}\n\n\
                 To report this issue:\n\
                 1. Visit: https://github.com/pwnsdx/cityg/issues/new\n\
                 2. Copy the error details above\n\
                 3. Paste them into the issue description",
                error.category,
                error.user_message,
                error.technical_details,
                error.recovery_suggestion
            );

            warn!(
                "===== ERROR REPORT =====\n{}\n========================",
                report
            );
            self.show_info(
                "Error report logged to console - visit GitHub to submit issue",
                cx,
            );
        }
    }

    fn on_dismiss_error(&mut self, _: &MouseDownEvent, _: &mut Window, cx: &mut ViewContext<Self>) {
        self.clear_error();
        cx.notify();
    }

    fn on_generate_room_id(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.join_form.room_id = AppModel::random_room_id();
        self.join_form.active = Some(ActiveField::Room);
        self.last_error = None;
        self.info_message = Some("Generated a new room identifier.".to_string());
        cx.notify();
    }

    fn start_join(&mut self, cx: &mut ViewContext<Self>) {
        if matches!(self.join_status, JoinStatus::Joining) {
            return;
        }
        if !self.join_form.is_ready() {
            return;
        }

        self.reset_fetch_state();
        self.messages.clear();
        self.message_keys.clear();
        self.join_status = JoinStatus::Joining;
        self.last_error = None;
        self.info_message = None;
        self.composer.blur();
        cx.notify();

        let params = self.join_form.join_params();

        let task = Tokio::spawn_result(cx, async move { perform_join(params).await });

        cx.spawn(async move |this, cx| {
            let outcome = task.await;
            let _ = this.update(cx, |model, cx| {
                model.on_join_finished(outcome, cx);
                cx.notify();
            });
        })
        .detach();
    }

    fn start_send(&mut self, cx: &mut ViewContext<Self>) {
        let Some(session_snapshot) = self.session.clone() else {
            return;
        };
        if !self.composer.is_ready() {
            return;
        }
        if matches!(self.send_status, SendStatus::Sending) {
            return;
        }

        let plaintext = self.composer.text.trim().to_string();
        if plaintext.is_empty() {
            return;
        }
        let msg_index = thread_rng().next_u64();
        let params = match SendParams::from_session(&session_snapshot, plaintext.clone(), msg_index)
        {
            Ok(params) => params,
            Err(err) => {
                self.record_activity_with_detail(
                    ActivityKind::Message,
                    "Message send skipped",
                    Some(err.to_string()),
                );
                self.set_error(&err, "send", Some(RetryAction::Send));
                return;
            }
        };
        let pending_id = self.queue_pending_message(&session_snapshot, &plaintext);

        self.composer.clear();
        self.composer.focus();

        self.send_status = SendStatus::Sending;
        self.last_error = None;
        self.info_message = None;
        cx.notify();

        let task = Tokio::spawn_result(cx, async move { perform_send(params).await });

        cx.spawn(async move |this, cx| {
            let outcome = task.await;
            let _ = this.update(cx, |model, cx| {
                model.on_send_finished(outcome, pending_id, cx);
            });
        })
        .detach();
    }

    fn on_join_finished(&mut self, result: anyhow::Result<AppSession>, cx: &mut ViewContext<Self>) {
        self.join_status = JoinStatus::Idle;
        self.leave_status = LeaveStatus::Idle;
        match result {
            Ok(mut session) => {
                session.last_fetch_timestamp_ms = None;
                if let Err(err) = persist_session(&session) {
                    warn!("joined room but failed to persist session: {err:?}");
                    self.last_error =
                        Some(format!("Joined room, but failed to save session: {err}"));
                    self.info_message = None;
                    self.show_error_toast("Joined room, but failed to save session", cx);
                } else {
                    self.last_error = None;
                    self.categorized_error = None;
                    self.info_message = Some("Joined room. Session saved locally.".to_string());
                    self.show_success("Successfully joined room!", cx);
                }
                self.session = Some(session);
                self.hydrate_alias_bindings_from_disk();
                self.load_security_events_from_disk();
                self.activity_events.clear();
                self.record_activity(ActivityKind::System, "Joined room");
                self.messages.clear();
                self.message_keys.clear();
                self.next_pending_message_id = 1;
                self.composer.clear();
                self.composer.blur();
                self.send_status = SendStatus::Idle;
                self.join_form.active = None;
                self.reset_fetch_state();
                self.schedule_fetch(cx, Duration::from_millis(0));
                self.refresh_members(cx);

                // Start WebSocket connection
                self.start_websocket(cx);
                self.schedule_epoch_sync(cx, "Syncing latest epoch after join…");
            }
            Err(err) => {
                self.set_error(&err, "join", Some(RetryAction::Join));
                self.info_message = None;
                self.reset_fetch_state();
            }
        }
    }

    fn on_leave_clicked(&mut self, _: &MouseDownEvent, _: &mut Window, cx: &mut ViewContext<Self>) {
        if !matches!(self.leave_status, LeaveStatus::Idle) {
            return;
        }
        let session = match &self.session {
            Some(session) => session,
            None => return,
        };

        let request = LeaveRequest::from_session(session);
        self.leave_status = LeaveStatus::Leaving;
        self.last_error = None;
        self.info_message = None;
        cx.notify();

        let task = Tokio::spawn_result(cx, async move { perform_leave(request).await });

        cx.spawn(async move |this, cx| {
            let outcome = task.await;
            let _ = this.update(cx, |model, cx| {
                model.on_leave_finished(outcome, cx);
                cx.notify();
            });
        })
        .detach();
    }

    fn on_refresh_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.start_pcs_refresh(cx);
    }

    fn start_pcs_refresh(&mut self, cx: &mut ViewContext<Self>) {
        if !matches!(self.leave_status, LeaveStatus::Idle) {
            return;
        }
        let Some(session) = &self.session else {
            return;
        };

        let request = LeaveRequest::from_session(session);
        self.leave_status = LeaveStatus::Refreshing;
        self.last_error = None;
        self.info_message = None;
        cx.notify();

        let task = Tokio::spawn_result(cx, async move { perform_pcs_refresh(request).await });

        cx.spawn(async move |this, cx| {
            let outcome = task.await;
            let _ = this.update(cx, |model, cx| {
                model.on_refresh_finished(outcome, cx);
                cx.notify();
            });
        })
        .detach();
    }

    fn on_refresh_finished(&mut self, result: anyhow::Result<()>, cx: &mut ViewContext<Self>) {
        self.leave_status = LeaveStatus::Idle;
        match result {
            Ok(()) => {
                self.clear_error();
                self.info_message =
                    Some("PCS refresh submitted. Syncing latest epoch…".to_string());
                self.show_success("PCS refresh submitted", cx);
                self.schedule_epoch_sync(cx, "Syncing latest epoch after PCS refresh…");
            }
            Err(err) => {
                self.set_error(&err, "refresh", Some(RetryAction::Refresh));
                self.info_message = None;
            }
        }
    }

    fn on_leave_finished(&mut self, result: anyhow::Result<()>, cx: &mut ViewContext<Self>) {
        self.leave_status = LeaveStatus::Idle;
        match result {
            Ok(()) => {
                self.reset_fetch_state();
                self.stop_epoch_sync_task();
                self.stop_websocket();
                self.stop_members_refresh_task();
                if let Some(session) = self.session.take() {
                    if let Err(err) = remove_security_log(&session.server_url, &session.room_id) {
                        warn!("failed to remove security log: {err:?}");
                    }
                    match remove_persisted_session(&session.server_url, &session.room_id) {
                        Ok(()) => {
                            self.info_message = Some("Device left the room.".to_string());
                            self.clear_error();
                            self.show_success("Successfully left the room", cx);
                        }
                        Err(err) => {
                            let message =
                                format!("Left room, but failed to remove session data: {err}");
                            warn!("{message}");
                            self.last_error = Some(message.clone());
                            self.info_message = None;
                            self.show_error_toast(message, cx);
                        }
                    }
                } else {
                    self.info_message = Some("Device left the room.".to_string());
                    self.clear_error();
                    self.show_success("Successfully left the room", cx);
                }
                self.messages.clear();
                self.message_keys.clear();
                self.next_pending_message_id = 1;
                self.composer.clear();
                self.composer.blur();
                self.send_status = SendStatus::Idle;
                self.fetch_status = FetchStatus::Idle;
                self.members.clear();
                self.members_status = MembersStatus::Idle;
                self.members_total = 0;
                self.members_next_offset = None;
                self.members_loading_append = false;
                self.alias_bindings.clear();
                self.leaf_alias_index.clear();
                self.members_auto_page = false;
                self.members_mode = MembersMode::Full;
                self.members_search.clear();
                self.members_search.blur();
                self.members_alias_dirty = false;
                self.security_events.clear();
                self.security_unread = 0;
                self.security_panel_expanded = false;
                self.activity_events.clear();
            }
            Err(err) => {
                self.set_error(&err, "leave", Some(RetryAction::Leave));
                self.info_message = None;
            }
        }
    }

    fn refresh_members(&mut self, cx: &mut ViewContext<Self>) {
        self.refresh_members_for_mode(
            cx,
            MembersMode::Full,
            true,
            true,
            "Loading member roster…".to_string(),
        );
    }

    fn refresh_members_soft(&mut self, cx: &mut ViewContext<Self>) {
        if matches!(self.members_status, MembersStatus::Loading(_)) {
            return;
        }
        let mode = self.members_mode.clone();
        let message = match &mode {
            MembersMode::Full => "Refreshing member roster…".to_string(),
            MembersMode::Search { query } => format!("Refreshing search for \"{}\"…", query),
        };
        self.refresh_members_for_mode(cx, mode, false, true, message);
    }

    fn refresh_members_for_mode(
        &mut self,
        cx: &mut ViewContext<Self>,
        mode: MembersMode,
        reset_state: bool,
        auto_page: bool,
        message: String,
    ) {
        let session = match &self.session {
            Some(session) => session,
            None => return,
        };
        if reset_state {
            self.members.clear();
            self.members_total = 0;
            self.members_next_offset = None;
            self.members_alias_dirty = false;
        }
        if !matches!(mode, MembersMode::Full) {
            self.members_alias_dirty = false;
        }
        self.members_mode = mode.clone();
        self.members_auto_page = auto_page;
        let params =
            MembersParams::from_session(session, 0, self.config.gui.members_page_limit, mode);
        self.start_members_fetch(params, false, message, cx);
    }

    fn load_more_members(&mut self, cx: &mut ViewContext<Self>) {
        self.load_more_members_with_mode(cx, false);
    }

    fn load_more_members_with_mode(&mut self, cx: &mut ViewContext<Self>, auto_triggered: bool) {
        if matches!(self.members_status, MembersStatus::Loading(_)) {
            return;
        }
        if !auto_triggered {
            self.members_auto_page = false;
        }
        let session = match &self.session {
            Some(session) => session,
            None => return,
        };
        let next = match self.members_next_offset {
            Some(offset) if offset < self.members_total => offset,
            _ => return,
        };
        let params = MembersParams::from_session(
            session,
            next,
            self.config.gui.members_page_limit,
            self.members_mode.clone(),
        );
        self.start_members_fetch(params, true, "Loading more members…".to_string(), cx);
    }

    fn start_members_fetch(
        &mut self,
        params: MembersParams,
        append: bool,
        message: String,
        cx: &mut ViewContext<Self>,
    ) {
        self.members_status = MembersStatus::Loading(message);
        self.members_loading_append = append;
        cx.notify();
        let task = Tokio::spawn_result(cx, async move { perform_fetch_members(params).await });
        cx.spawn(async move |this, cx| {
            let outcome = task.await;
            let _ = this.update(cx, |model, cx| {
                model.on_members_refreshed(outcome, cx);
                cx.notify();
            });
        })
        .detach();
    }

    fn on_members_refreshed(
        &mut self,
        result: anyhow::Result<MembersPage>,
        cx: &mut ViewContext<Self>,
    ) {
        match result {
            Ok(mut page) => {
                let mut parent_root_changed = false;
                if let Some(session) = self.session.as_mut()
                    && session.parent_root != page.root
                {
                    session.parent_root = page.root;
                    parent_root_changed = true;
                    if let Err(err) = persist_session(session) {
                        warn!("failed to persist session after members root update: {err:?}");
                    }
                }
                page.members.sort_by(|a, b| {
                    let alias_cmp = a.alias.as_ref().cmp(&b.alias.as_ref());
                    if alias_cmp.is_eq() {
                        a.leaf_id.cmp(&b.leaf_id)
                    } else {
                        alias_cmp
                    }
                });
                if self.members_loading_append {
                    self.members.extend(page.members);
                } else {
                    self.members = page.members;
                    self.members_alias_dirty = matches!(self.members_mode, MembersMode::Full);
                }
                self.members_total = page.total_count;
                self.members_next_offset = if page.next_offset < page.total_count {
                    Some(page.next_offset)
                } else {
                    None
                };
                self.members_status = MembersStatus::Idle;
                self.record_activity(
                    ActivityKind::Roster,
                    format!(
                        "Roster refreshed: {} shown / {} total",
                        self.members.len(),
                        self.members_total
                    ),
                );
                if parent_root_changed {
                    self.schedule_epoch_sync(cx, "Syncing latest epoch after roster root update…");
                }
                if self.members_auto_page {
                    if self.members_next_offset.is_some() {
                        self.load_more_members_with_mode(cx, true);
                        return;
                    } else {
                        self.members_auto_page = false;
                    }
                }
                if self.members_alias_dirty && self.members_next_offset.is_none() {
                    self.members_alias_dirty = false;
                    if matches!(self.members_mode, MembersMode::Full) {
                        self.reconcile_alias_bindings(cx);
                    }
                }
            }
            Err(err) => {
                if is_stale_server_session_error(&err) {
                    self.handle_stale_server_session(
                        "Saved session is no longer recognized by the server. Please join again.",
                        cx,
                    );
                    return;
                }
                let detail = http_error_detail_from_anyhow(&err).unwrap_or_else(|| err.to_string());
                warn!("failed to refresh members: {detail}");
                self.record_activity_with_detail(
                    ActivityKind::Roster,
                    "Roster refresh failed",
                    Some(detail.clone()),
                );
                self.members_status = MembersStatus::Error(detail);
                self.members_auto_page = false;
                self.members_alias_dirty = false;
            }
        }
        self.members_loading_append = false;
    }

    fn on_reset_clicked(&mut self, _: &MouseDownEvent, _: &mut Window, cx: &mut ViewContext<Self>) {
        match self.reset_session_state() {
            Ok(()) => {
                self.info_message = Some("Session reset. Local state cleared.".to_string());
                self.last_error = None;
            }
            Err(err) => {
                self.last_error = Some(format!("Failed to reset session: {err}"));
                self.info_message = None;
            }
        }
        cx.notify();
    }

    fn handle_stale_server_session(&mut self, reason: &str, cx: &mut ViewContext<Self>) {
        warn!("stale server session detected: {reason}");
        if let Err(err) = self.reset_session_state() {
            warn!("failed to clear stale session state: {err:?}");
        }
        self.last_error = Some(reason.to_string());
        self.info_message = Some(
            "Saved session cleared because server state changed. Rejoin the room to continue."
                .to_string(),
        );
        self.show_error_toast("Session expired on server. Join room again.", cx);
        cx.notify();
    }

    fn on_members_refresh_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        let mode = self.members_mode.clone();
        let message = match &mode {
            MembersMode::Full => "Loading member roster…".to_string(),
            MembersMode::Search { query } => format!("Refreshing search for \"{}\"…", query),
        };
        self.refresh_members_for_mode(cx, mode, true, true, message);
    }

    fn on_members_load_more_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.load_more_members(cx);
    }

    fn on_members_search_field_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.focus_members_search(cx);
    }

    fn on_members_search_button_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.submit_members_search(cx);
    }

    fn on_members_search_clear_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.clear_members_search(cx);
    }

    fn on_security_log_clear_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.security_events.clear();
        self.persist_security_events_to_disk();
        self.security_unread = 0;
        self.security_panel_expanded = false;
        cx.notify();
    }

    fn on_activity_clear_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.activity_events.clear();
        cx.notify();
    }

    fn on_security_panel_toggle_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.security_panel_expanded = !self.security_panel_expanded;
        if self.security_panel_expanded {
            self.acknowledge_security_alerts();
        }
        cx.notify();
    }

    fn on_security_panel_mark_read_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.acknowledge_security_alerts();
        cx.notify();
    }

    fn reset_session_state(&mut self) -> Result<()> {
        let removal_result = if let Some(session) = self.session.take() {
            if let Err(err) = remove_security_log(&session.server_url, &session.room_id) {
                warn!("failed to remove security log: {err:?}");
            }
            remove_persisted_session(&session.server_url, &session.room_id)
        } else if let Some(pointer) = read_last_session_pointer()? {
            if let Err(err) = remove_security_log(&pointer.server_url, &pointer.room_id) {
                warn!("failed to remove security log: {err:?}");
            }
            remove_persisted_session(&pointer.server_url, &pointer.room_id)
        } else {
            Ok(())
        };

        self.reset_fetch_state();
        self.fetch_task = None;
        self.fetch_in_flight = false;
        self.join_status = JoinStatus::Idle;
        self.leave_status = LeaveStatus::Idle;
        self.send_status = SendStatus::Idle;
        self.fetch_status = FetchStatus::Idle;
        self.session = None;
        self.stop_epoch_sync_task();
        self.stop_members_refresh_task();
        self.alias_bindings.clear();
        self.leaf_alias_index.clear();
        self.members_auto_page = false;
        self.members_alias_dirty = false;
        self.members_mode = MembersMode::Full;
        self.members_search.clear();
        self.members_search.blur();
        self.security_events.clear();
        self.security_unread = 0;
        self.security_panel_expanded = false;
        self.activity_events.clear();
        self.messages.clear();
        self.message_keys.clear();
        self.next_pending_message_id = 1;
        self.composer.clear();
        self.composer.blur();
        self.show_ciphertext = false;
        self.join_form.active = Some(ActiveField::Alias);

        removal_result
    }

    fn on_send_finished(
        &mut self,
        result: anyhow::Result<ChatMessageEntry>,
        pending_id: u64,
        cx: &mut ViewContext<Self>,
    ) {
        self.send_status = SendStatus::Idle;
        match result {
            Ok(entry) => {
                let ts = entry.timestamp_ms;
                self.confirm_pending_message(pending_id, entry);
                self.info_message = Some("Message sent.".to_string());
                self.show_success("Message sent successfully", cx);
                self.record_activity(ActivityKind::Message, "You sent a message");

                if let Some(session) = self.session.as_mut() {
                    let needs_update = session
                        .last_fetch_timestamp_ms
                        .map(|prev| ts > prev)
                        .unwrap_or(true);
                    if needs_update {
                        session.last_fetch_timestamp_ms = Some(ts);
                        if let Err(err) = persist_session(session) {
                            warn!("failed to persist session after send: {err:?}");
                        }
                    }
                }

                if !self.fetch_in_flight {
                    self.schedule_fetch(cx, Duration::from_millis(500));
                }
            }
            Err(err) => {
                if is_stale_server_session_error(&err) {
                    self.handle_stale_server_session(
                        "Saved session is no longer recognized by the server. Please join again.",
                        cx,
                    );
                    return;
                }
                self.mark_pending_message_failed(pending_id);
                self.record_activity_with_detail(
                    ActivityKind::Message,
                    "Message send failed",
                    Some(err.to_string()),
                );
                self.set_error(&err, "send", Some(RetryAction::Send));
            }
        }
    }

    fn on_keystroke(&mut self, keystroke: &Keystroke, cx: &mut ViewContext<Self>) {
        if self.session.is_some() {
            if self.members_search.active {
                match self.handle_members_search_clipboard_shortcuts(keystroke, cx) {
                    KeyOutcome::None => {}
                    KeyOutcome::Updated => {
                        cx.notify();
                        return;
                    }
                    KeyOutcome::Submit => {}
                }
                match self.members_search.handle_keystroke(keystroke) {
                    KeyOutcome::None => {}
                    KeyOutcome::Updated => cx.notify(),
                    KeyOutcome::Submit => self.submit_members_search(cx),
                }
                return;
            }
            match self.handle_composer_clipboard_shortcuts(keystroke, cx) {
                KeyOutcome::None => {}
                KeyOutcome::Updated => {
                    cx.notify();
                    return;
                }
                KeyOutcome::Submit => {}
            }
            match self.composer.handle_keystroke(keystroke) {
                KeyOutcome::None => {}
                KeyOutcome::Updated => cx.notify(),
                KeyOutcome::Submit => self.start_send(cx),
            }
            return;
        }
        if matches!(self.join_status, JoinStatus::Joining) {
            return;
        }

        match self.handle_join_form_clipboard_shortcuts(keystroke, cx) {
            KeyOutcome::None => {}
            KeyOutcome::Updated => {
                cx.notify();
                return;
            }
            KeyOutcome::Submit => {}
        }

        match self.join_form.handle_keystroke(keystroke) {
            KeyOutcome::None => {}
            KeyOutcome::Updated => cx.notify(),
            KeyOutcome::Submit => self.start_join(cx),
        }
    }
}

#[derive(Clone)]
struct JoinParams {
    server_url: String,
    room_id: String,
    alias: String,
}

#[derive(Clone)]
struct LeaveRequest {
    server_url: String,
    room_id: String,
    gid: [u8; 32],
    leaf_id: [u8; 32],
    pop_public_key: Vec<u8>,
    pop_secret_key: Vec<u8>,
    vrf_secret_key: Vec<u8>,
    vrf_public_key: Vec<u8>,
    fs_ec: u64,
    fs_epoch_commit: [u8; 32],
    fs_dev_prev_commit: [u8; 32],
    k_fs_current: [u8; 32],
    we_epoch_id: [u8; 32],
    max_barrier_update_bytes: u64,
    barrier_recovery_pending: bool,
}

#[derive(Clone)]
struct MembersParams {
    server_url: String,
    gid: [u8; 32],
    parent_root: [u8; 32],
    offset: u64,
    limit: u32,
    mode: MembersMode,
}

struct MembersPage {
    members: Vec<MemberEntry>,
    root: [u8; 32],
    total_count: u64,
    next_offset: u64,
}

impl LeaveRequest {
    fn from_session(session: &AppSession) -> Self {
        Self {
            server_url: session.server_url.clone(),
            room_id: session.room_id.clone(),
            gid: session.gid,
            leaf_id: session.leaf_id,
            pop_public_key: session.pop_public_key.clone(),
            pop_secret_key: session.pop_secret_key.clone(),
            vrf_secret_key: session.vrf_secret_key.clone(),
            vrf_public_key: session.vrf_public_key.clone(),
            fs_ec: session.fs_ec,
            fs_epoch_commit: session.fs_epoch_commit,
            fs_dev_prev_commit: session.fs_dev_prev_commit,
            k_fs_current: session.forward_state.snapshot().k_fs,
            we_epoch_id: session.we_epoch_id,
            max_barrier_update_bytes: session.barrier_state.max_barrier_update_bytes,
            barrier_recovery_pending: session.barrier_state.barrier_recovery_pending,
        }
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

impl MembersParams {
    fn from_session(session: &AppSession, offset: u64, limit: u32, mode: MembersMode) -> Self {
        Self {
            server_url: session.server_url.clone(),
            gid: session.gid,
            parent_root: session.parent_root,
            offset,
            limit,
            mode,
        }
    }
}

#[derive(Clone)]
struct SendParams {
    server_url: String,
    gid: [u8; 32],
    we_epoch_id: [u8; 32],
    xk_hash: [u8; 32],
    epoch_key: [u8; 32],
    fs_ec: u64,
    barrier_version: u64,
    k_barrier: [u8; 32],
    msg_index: u64,
    leaf_id: [u8; 32],
    alias: String,
    plaintext: String,
    msg_sign_secret_key: Vec<u8>,
    msg_sign_public_key: Vec<u8>,
}

impl SendParams {
    fn from_session(session: &AppSession, plaintext: String, msg_index: u64) -> Result<Self> {
        if session.barrier_state.barrier_recovery_pending {
            return Err(anyhow!(
                "Cannot send messages while barrier recovery is pending. Waiting for next barrier update."
            ));
        }
        Ok(Self {
            server_url: session.server_url.clone(),
            gid: session.gid,
            we_epoch_id: session.we_epoch_id,
            xk_hash: session.xk_hash,
            epoch_key: session.epoch_key,
            fs_ec: session.fs_ec,
            barrier_version: session.barrier_state.barrier_version,
            k_barrier: *session.barrier_state.k_barrier,
            msg_index,
            leaf_id: session.leaf_id,
            alias: session.alias.clone(),
            plaintext,
            msg_sign_secret_key: session.msg_sign_secret_key.clone(),
            msg_sign_public_key: session.msg_sign_public_key.clone(),
        })
    }
}

#[derive(Clone)]
struct FetchParams {
    server_url: String,
    gid: [u8; 32],
    we_epoch_id: [u8; 32],
    xk_hash: [u8; 32],
    epoch_key: [u8; 32],
    fs_ec: u64,
    barrier_version: u64,
    k_barrier: [u8; 32],
    msg_replay_state: MsgReplayState,
    leaf_id: [u8; 32],
    since: Option<u64>,
}

impl FetchParams {
    fn from_session(session: &AppSession, since: Option<u64>) -> Result<Self> {
        if session.barrier_state.barrier_recovery_pending {
            return Err(anyhow!(
                "Cannot fetch/decrypt messages while barrier recovery is pending. Waiting for next barrier update."
            ));
        }
        Ok(Self {
            server_url: session.server_url.clone(),
            gid: session.gid,
            we_epoch_id: session.we_epoch_id,
            xk_hash: session.xk_hash,
            epoch_key: session.epoch_key,
            fs_ec: session.fs_ec,
            barrier_version: session.barrier_state.barrier_version,
            k_barrier: *session.barrier_state.k_barrier,
            msg_replay_state: session.msg_replay_state.clone(),
            leaf_id: session.leaf_id,
            since,
        })
    }
}

struct FetchOutcome {
    messages: Vec<ChatMessageEntry>,
    last_timestamp_ms: Option<u64>,
    msg_replay_state: MsgReplayState,
}

struct EpochSyncOutcome {
    session: AppSession,
    changed: bool,
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
    #[serde(default)]
    kbroad_secret_hex: String,
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
const KBROAD_SECRET_ENV: &str = "CITYG_GUI_KBROAD_SECRET_HEX";
const KBROAD_PUBLIC_ENV: &str = "CITYG_GUI_KBROAD_PUBLIC_HEX";
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
    barrier_version: u64,
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
            barrier_version: state.barrier_version,
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
            barrier_version: self.barrier_version,
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
            version: 10, // Version 10: Persist receive-side msg_index anti-replay state.
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
            kbroad_secret_hex: hex_encode(&session.kbroad_secret),
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
            kbroad_secret_hex,
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
            || version == 10)
        {
            return Err(anyhow!(
                "unsupported session file version {version} (expected 4, 5, 6, 7, 8, 9, or 10 with ML-DSA-65 authentication)"
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
        let kbroad_secret = decode_hex_vec("kbroad_secret_hex", &kbroad_secret_hex)?;
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
            kbroad_secret,
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

        Ok(session)
    }
}

fn write_file_atomic(path: &std::path::Path, data: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("path has no parent directory: {}", path.display()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("session");

    for attempt in 0..32u8 {
        let mut suffix = [0u8; 8];
        thread_rng().fill_bytes(&mut suffix);
        let suffix = u64::from_le_bytes(suffix);
        let temp_path = parent.join(format!(
            ".{file_name}.tmp-{}-{suffix}-{attempt}",
            std::process::id()
        ));

        let mut file = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to create {}", temp_path.display()));
            }
        };

        if let Err(err) = file
            .write_all(data)
            .and_then(|_| file.sync_all())
            .with_context(|| format!("failed to write {}", temp_path.display()))
        {
            let _ = fs::remove_file(&temp_path);
            return Err(err);
        }
        drop(file);

        if let Err(err) = fs::rename(&temp_path, path) {
            let _ = fs::remove_file(&temp_path);
            return Err(err).with_context(|| {
                format!(
                    "failed to atomically replace {} with {}",
                    path.display(),
                    temp_path.display()
                )
            });
        }

        #[cfg(unix)]
        {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }

        return Ok(());
    }

    Err(anyhow!(
        "failed to allocate unique temporary file for {}",
        path.display()
    ))
}

fn persist_session(session: &AppSession) -> Result<()> {
    let persisted = PersistedSession::from_session(session);
    let path = session_file_path(&session.server_url, &session.room_id)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let data = encrypt_persisted_session(&persisted, &path)?;
    write_file_atomic(&path, &data)?;

    let pointer = LastSessionPointer {
        server_url: session.server_url.clone(),
        room_id: session.room_id.clone(),
    };
    let pointer_path = last_session_pointer_path()?;
    if let Some(parent) = pointer_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let pointer_data = serde_json::to_vec(&pointer).context("failed to encode session pointer")?;
    write_file_atomic(&pointer_path, &pointer_data)?;

    Ok(())
}

fn remove_persisted_session(server_url: &str, room_id: &str) -> Result<()> {
    let path = session_file_path(server_url, room_id)?;
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("failed to remove {}", path.display()))?;
    }

    let pointer_path = last_session_pointer_path()?;
    if pointer_path.exists() {
        let should_remove = fs::read(&pointer_path)
            .ok()
            .and_then(|data| serde_json::from_slice::<LastSessionPointer>(&data).ok())
            .map(|pointer| pointer.server_url == server_url && pointer.room_id == room_id)
            .unwrap_or(false);

        if should_remove {
            fs::remove_file(&pointer_path)
                .with_context(|| format!("failed to remove {}", pointer_path.display()))?;
        }
    }

    Ok(())
}

fn load_last_session() -> Result<Option<AppSession>> {
    let pointer_path = last_session_pointer_path()?;
    if !pointer_path.exists() {
        return Ok(None);
    }

    let data = fs::read(&pointer_path)
        .with_context(|| format!("failed to read {}", pointer_path.display()))?;
    let pointer: LastSessionPointer =
        serde_json::from_slice(&data).context("invalid session pointer JSON")?;
    let session = load_session_at(&pointer.server_url, &pointer.room_id)?;
    if session.is_none() {
        let _ = fs::remove_file(&pointer_path);
    }
    Ok(session)
}

fn read_last_session_pointer() -> Result<Option<LastSessionPointer>> {
    let pointer_path = last_session_pointer_path()?;
    if !pointer_path.exists() {
        return Ok(None);
    }

    let data = fs::read(&pointer_path)
        .with_context(|| format!("failed to read {}", pointer_path.display()))?;
    let pointer: LastSessionPointer =
        serde_json::from_slice(&data).context("invalid session pointer JSON")?;
    Ok(Some(pointer))
}

fn load_session_at(server_url: &str, room_id: &str) -> Result<Option<AppSession>> {
    let path = session_file_path(server_url, room_id)?;
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let persisted = decode_persisted_session(&data, &path)?;
    persisted.into_app_session().map(Some)
}

fn encrypt_persisted_session(
    persisted: &PersistedSession,
    session_path: &std::path::Path,
) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        ChaCha20Poly1305,
        aead::{Aead, AeadCore, KeyInit, OsRng},
    };

    let payload =
        serde_json::to_vec(persisted).context("failed to serialize session payload JSON")?;
    let (key, key_source) = session_encryption_key(session_path)?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, payload.as_slice())
        .context("failed to encrypt session payload")?;

    let envelope = EncryptedSessionEnvelope {
        version: ENCRYPTED_SESSION_ENVELOPE_VERSION,
        alg: ENCRYPTED_SESSION_ALG.to_string(),
        key_source: key_source.as_str().to_string(),
        nonce_hex: hex_encode(nonce),
        ciphertext_hex: hex_encode(ciphertext),
    };
    serde_json::to_vec_pretty(&envelope).context("failed to serialize encrypted session envelope")
}

fn decode_persisted_session(
    data: &[u8],
    session_path: &std::path::Path,
) -> Result<PersistedSession> {
    use chacha20poly1305::{
        ChaCha20Poly1305,
        aead::{Aead, KeyInit},
    };

    if let Ok(envelope) = serde_json::from_slice::<EncryptedSessionEnvelope>(data) {
        if envelope.version != ENCRYPTED_SESSION_ENVELOPE_VERSION {
            return Err(anyhow!(
                "unsupported encrypted session envelope version {} (expected {})",
                envelope.version,
                ENCRYPTED_SESSION_ENVELOPE_VERSION
            ));
        }
        if envelope.alg != ENCRYPTED_SESSION_ALG {
            return Err(anyhow!(
                "unsupported encrypted session algorithm '{}' (expected '{}')",
                envelope.alg,
                ENCRYPTED_SESSION_ALG
            ));
        }

        let nonce_bytes = hex_decode(&envelope.nonce_hex)
            .context("encrypted session envelope nonce is not valid hex")?;
        if nonce_bytes.len() != 12 {
            return Err(anyhow!(
                "encrypted session envelope nonce must be 12 bytes, got {}",
                nonce_bytes.len()
            ));
        }
        let ciphertext = hex_decode(&envelope.ciphertext_hex)
            .context("encrypted session envelope ciphertext is not valid hex")?;

        let (key, active_source) = session_encryption_key(session_path)?;
        if envelope.key_source != active_source.as_str() {
            warn!(
                "session key source mismatch (file='{}', active='{}')",
                envelope.key_source,
                active_source.as_str()
            );
        }

        let cipher = ChaCha20Poly1305::new((&key).into());
        let plaintext = cipher
            .decrypt(nonce_bytes.as_slice().into(), ciphertext.as_slice())
            .context("failed to decrypt session payload")?;
        return serde_json::from_slice(&plaintext)
            .context("invalid decrypted session payload JSON");
    }

    serde_json::from_slice(data).context("invalid legacy session JSON")
}

fn session_encryption_key(session_path: &std::path::Path) -> Result<([u8; 32], SessionKeySource)> {
    if let Ok(passphrase) = std::env::var(SESSION_PASSPHRASE_ENV)
        && !passphrase.trim().is_empty()
    {
        return Ok((
            blake3::derive_key(SESSION_KEY_DERIVE_CONTEXT, passphrase.as_bytes()),
            SessionKeySource::EnvPassphrase,
        ));
    }

    Ok((
        load_or_create_local_session_key(session_path)?,
        SessionKeySource::LocalKeyFile,
    ))
}

fn load_or_create_local_session_key(session_path: &std::path::Path) -> Result<[u8; 32]> {
    use std::io::ErrorKind;

    let key_path = session_local_key_path(session_path)?;
    const READ_RETRIES: usize = 8;
    const READ_RETRY_DELAY_MS: u64 = 10;

    let read_key = |path: &std::path::Path| -> Result<[u8; 32]> {
        let raw = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        bytes32("session local key", &raw)
    };

    if key_path.exists() {
        return read_key(&key_path);
    }

    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let mut key = [0u8; 32];
    thread_rng().fill_bytes(&mut key);

    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&key_path)
    {
        Ok(mut file) => {
            file.write_all(&key)
                .with_context(|| format!("failed to write {}", key_path.display()))?;
            file.sync_all()
                .with_context(|| format!("failed to sync {}", key_path.display()))?;
            drop(file);
            set_sensitive_file_permissions(&key_path)?;
            Ok(key)
        }
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {
            // Another process/test created the file first; wait briefly in case it's still writing.
            for attempt in 0..READ_RETRIES {
                match read_key(&key_path) {
                    Ok(existing) => return Ok(existing),
                    Err(read_err) if attempt + 1 < READ_RETRIES => {
                        warn!(
                            "session key file exists but is not readable yet (attempt {}/{READ_RETRIES}): {}",
                            attempt + 1,
                            read_err
                        );
                        std::thread::sleep(Duration::from_millis(READ_RETRY_DELAY_MS));
                    }
                    Err(read_err) => return Err(read_err),
                }
            }
            Err(anyhow!(
                "session local key read retry exhausted for {}",
                key_path.display()
            ))
        }
        Err(err) => Err(err).with_context(|| format!("failed to create {}", key_path.display())),
    }
}

fn session_local_key_path(session_path: &std::path::Path) -> Result<PathBuf> {
    let base = session_path
        .parent()
        .ok_or_else(|| anyhow!("session path has no parent directory"))?;
    Ok(base.join(SESSION_LOCAL_KEY_FILE))
}

#[cfg(unix)]
fn set_sensitive_file_permissions(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn set_sensitive_file_permissions(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

fn session_key_hash(server_url: &str, room_id: &str) -> Result<String> {
    let mut key = server_url.as_bytes().to_vec();
    key.push(0u8);
    key.extend_from_slice(room_id.as_bytes());
    let hash = blake3_hash(&key);
    Ok(hex_encode(hash.as_bytes()))
}

fn session_file_path(server_url: &str, room_id: &str) -> Result<PathBuf> {
    let base = session_dir()?;
    let hash = session_key_hash(server_url, room_id)?;
    Ok(base.join(format!("session-{}.json", hash)))
}

fn roster_file_path(server_url: &str, room_id: &str) -> Result<PathBuf> {
    let base = session_dir()?;
    let hash = session_key_hash(server_url, room_id)?;
    Ok(base.join(format!("roster-{}.json", hash)))
}

fn last_session_pointer_path() -> Result<PathBuf> {
    Ok(session_dir()?.join("last-session.json"))
}

fn session_dir() -> Result<PathBuf> {
    #[cfg(test)]
    if let Some(path) = CONFIG_DIR_OVERRIDE.with(|override_path| override_path.borrow().clone()) {
        return Ok(path);
    }

    #[cfg(not(test))]
    if let Some(path) = CONFIG_DIR_OVERRIDE
        .lock()
        .map_err(|_| anyhow::anyhow!("Failed to acquire config dir lock"))?
        .clone()
    {
        return Ok(path);
    }

    if let Ok(override_path) = std::env::var("CITYG_GUI_CONFIG_DIR")
        && !override_path.is_empty()
    {
        let base = PathBuf::from(override_path).join("cityg").join("gui");
        return Ok(base);
    }

    let base = config_dir().ok_or_else(|| anyhow!("cannot determine config directory"))?;
    Ok(base.join("cityg").join("gui"))
}

fn load_alias_bindings(
    server_url: &str,
    room_id: &str,
) -> Result<AHashMap<String, AliasBindingRecord>> {
    let path = roster_file_path(server_url, room_id)?;
    if !path.exists() {
        return Ok(AHashMap::new());
    }

    let data = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let store: PersistedAliasStore = match serde_json::from_slice(&data) {
        Ok(store) => store,
        Err(_) => {
            let bindings: AHashMap<String, String> =
                serde_json::from_slice(&data).context("invalid alias store JSON")?;
            PersistedAliasStore {
                version: 0,
                bindings: bindings
                    .into_iter()
                    .map(|(alias, pop)| {
                        (
                            alias,
                            PersistedAliasBinding {
                                pop_public_key_hex: pop,
                                leaf_id_hex: String::new(),
                            },
                        )
                    })
                    .collect(),
            }
        }
    };

    let mut map = AHashMap::new();
    for (alias, entry) in store.bindings {
        if entry.pop_public_key_hex.is_empty() {
            continue;
        }
        let pop_key = match hex_decode(&entry.pop_public_key_hex) {
            Ok(bytes) => bytes,
            Err(err) => {
                warn!(
                    "skipping alias binding '{}' due to invalid public key hex: {}",
                    alias, err
                );
                continue;
            }
        };

        let leaf_id = if entry.leaf_id_hex.is_empty() {
            [0u8; 32]
        } else {
            match decode_hex32("alias_leaf", &entry.leaf_id_hex) {
                Ok(arr) => arr,
                Err(err) => {
                    warn!(
                        "alias '{}' has invalid leaf id '{}': {err}",
                        alias, entry.leaf_id_hex
                    );
                    [0u8; 32]
                }
            }
        };

        map.insert(
            alias,
            AliasBindingRecord {
                pop_public_key: pop_key,
                leaf_id,
            },
        );
    }
    Ok(map)
}

fn persist_alias_bindings(
    server_url: &str,
    room_id: &str,
    bindings: &AHashMap<String, AliasBindingRecord>,
) -> Result<()> {
    let path = roster_file_path(server_url, room_id)?;
    if bindings.is_empty() {
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
        }
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let store = PersistedAliasStore {
        version: ALIAS_STORE_VERSION,
        bindings: bindings
            .iter()
            .map(|(alias, record)| {
                (
                    alias.clone(),
                    PersistedAliasBinding {
                        pop_public_key_hex: hex_encode(&record.pop_public_key),
                        leaf_id_hex: hex_encode(record.leaf_id),
                    },
                )
            })
            .collect(),
    };
    let data =
        serde_json::to_vec_pretty(&store).context("failed to serialize alias bindings to JSON")?;
    fs::write(&path, data).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn security_log_file_path(server_url: &str, room_id: &str) -> Result<PathBuf> {
    let base = session_dir()?;
    let hash = session_key_hash(server_url, room_id)?;
    Ok(base.join(format!("security-log-{}.json", hash)))
}

fn load_security_log(server_url: &str, room_id: &str) -> Result<Vec<SecurityEvent>> {
    let path = security_log_file_path(server_url, room_id)?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let log: PersistedSecurityLog =
        serde_json::from_slice(&data).context("invalid security log JSON")?;
    let mut events = Vec::with_capacity(log.events.len());
    for entry in log.events {
        events.push(SecurityEvent {
            alias: entry.alias,
            description: entry.description,
            timestamp_ms: entry.timestamp_ms,
        });
    }
    Ok(events)
}

fn persist_security_log(server_url: &str, room_id: &str, events: &[SecurityEvent]) -> Result<()> {
    let path = security_log_file_path(server_url, room_id)?;
    if events.is_empty() {
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
        }
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let log = PersistedSecurityLog {
        version: SECURITY_LOG_VERSION,
        events: events
            .iter()
            .map(|event| PersistedSecurityEvent {
                alias: event.alias.clone(),
                description: event.description.clone(),
                timestamp_ms: event.timestamp_ms,
            })
            .collect(),
    };
    let data =
        serde_json::to_vec_pretty(&log).context("failed to serialize security log to JSON")?;
    fs::write(&path, data).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn remove_security_log(server_url: &str, room_id: &str) -> Result<()> {
    let path = security_log_file_path(server_url, room_id)?;
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("failed to remove {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
fn set_config_dir_override_for_tests(path: Option<PathBuf>) -> ConfigDirGuard {
    let previous = CONFIG_DIR_OVERRIDE.with(|override_path| {
        let mut slot = override_path.borrow_mut();
        let previous = slot.clone();
        *slot = path;
        previous
    });
    ConfigDirGuard { previous }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
struct ConfigDirGuard {
    previous: Option<PathBuf>,
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
impl Drop for ConfigDirGuard {
    fn drop(&mut self) {
        CONFIG_DIR_OVERRIDE.with(|override_path| {
            *override_path.borrow_mut() = self.previous.clone();
        });
    }
}

fn decode_hex32(name: &str, value: &str) -> Result<[u8; 32]> {
    let bytes = hex_decode(value).with_context(|| format!("{name} is not valid hex"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("{name} must decode to 32 bytes, got {}", bytes.len()))
}

fn decode_hex32_or_zero(name: &str, value: &str) -> Result<[u8; 32]> {
    if value.is_empty() {
        Ok([0u8; 32])
    } else {
        decode_hex32(name, value)
    }
}

fn decode_hex_vec(name: &str, value: &str) -> Result<Vec<u8>> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    hex_decode(value).with_context(|| format!("{name} is not valid hex"))
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

fn http_error_detail_from_anyhow(err: &anyhow::Error) -> Option<String> {
    for cause in err.chain() {
        if let Some(ApiClientError::HttpStatus {
            status,
            message,
            freeze_code,
            freeze_reason,
            ..
        }) = cause.downcast_ref::<ApiClientError>()
        {
            return Some(describe_http_failure(
                status.as_str(),
                message,
                *freeze_code,
                freeze_reason.as_deref(),
            ));
        }
    }
    None
}

fn api_http_status_from_anyhow(err: &anyhow::Error) -> Option<(u16, String)> {
    for cause in err.chain() {
        if let Some(ApiClientError::HttpStatus {
            status, message, ..
        }) = cause.downcast_ref::<ApiClientError>()
        {
            return Some((status.as_u16(), message.to_lowercase()));
        }
    }
    None
}

fn is_stale_server_session_error(err: &anyhow::Error) -> bool {
    let Some((status, message)) = api_http_status_from_anyhow(err) else {
        return false;
    };
    if status == 404 {
        return true;
    }
    status >= 500
        && (message.contains("no anchors accepted for group")
            || message.contains("leaf not present in roster")
            || message.contains("unknown membership root")
            || message.contains("resource not found"))
}

// Categorize errors into user-friendly messages with recovery suggestions
fn categorize_error(err: &anyhow::Error, context: &str) -> CategorizedError {
    let err_str = err.to_string().to_lowercase();
    let technical_details = http_error_detail_from_anyhow(err).unwrap_or_else(|| err.to_string());

    // Network errors
    if err_str.contains("connection refused") {
        return CategorizedError::new(
            ErrorCategory::Network,
            "Connection refused",
            technical_details.clone(),
            "The server actively refused the connection. Verify the server URL and ensure the server is running.",
            true,
        );
    }

    if err_str.contains("timeout") {
        return CategorizedError::new(
            ErrorCategory::Network,
            "Connection timeout",
            technical_details.clone(),
            "The server took too long to respond. Check your internet connection or try again later.",
            true,
        );
    }

    if err_str.contains("connection")
        || err_str.contains("dns")
        || err_str.contains("network")
        || err_str.contains("unreachable")
    {
        return CategorizedError::new(
            ErrorCategory::Network,
            "Unable to connect to server",
            technical_details.clone(),
            "Check your internet connection and verify the server URL is correct. The server may be temporarily unavailable.",
            true,
        );
    }

    // HTTP status errors
    if err_str.contains("404") || err_str.contains("not found") {
        return CategorizedError::new(
            ErrorCategory::Server,
            "Resource not found",
            technical_details.clone(),
            "The requested resource was not found on the server. The room may not exist or the server URL may be incorrect.",
            false,
        );
    }

    if err_str.contains("401") || err_str.contains("unauthorized") {
        return CategorizedError::new(
            ErrorCategory::Policy,
            "Authentication failed",
            technical_details.clone(),
            "Your credentials were rejected. You may need to rejoin the room with valid credentials.",
            true,
        );
    }

    if err_str.contains("403") || err_str.contains("forbidden") {
        return CategorizedError::new(
            ErrorCategory::Policy,
            "Access denied",
            technical_details.clone(),
            "You don't have permission to perform this action. Contact the room administrator.",
            false,
        );
    }

    // Crypto/proof errors
    if err_str.contains("proof")
        || err_str.contains("crypto")
        || err_str.contains("verification")
        || err_str.contains("witness")
        || err_str.contains("signature")
    {
        return CategorizedError::new(
            ErrorCategory::Crypto,
            "Cryptographic operation failed",
            technical_details.clone(),
            "The cryptographic proof generation or verification failed. This may indicate a system issue or invalid cryptographic parameters. Try rejoining the room.",
            true,
        );
    }

    // Policy/freeze errors
    if err_str.contains("rho_replay") {
        return CategorizedError::new(
            ErrorCategory::Policy,
            "Duplicate message detected",
            technical_details.clone(),
            "This message was already sent and the server prevented a duplicate. No action needed.",
            false,
        );
    }

    if err_str.contains("freeze") {
        return CategorizedError::new(
            ErrorCategory::Policy,
            "Room policy violation",
            technical_details.clone(),
            "The room's security policy prevented this action. You may need to rejoin the room or contact the administrator for details.",
            false,
        );
    }

    if err_str.contains("policy") {
        return CategorizedError::new(
            ErrorCategory::Policy,
            "Policy check failed",
            technical_details.clone(),
            "The action was blocked by a policy check. Ensure you're following room rules and try again.",
            false,
        );
    }

    // Validation errors
    if err_str.contains("must not be empty") {
        return CategorizedError::new(
            ErrorCategory::Validation,
            "Required field missing",
            technical_details.clone(),
            "One or more required fields are empty. Fill in all required information and try again.",
            false,
        );
    }

    if err_str.contains("invalid") || err_str.contains("not valid") {
        return CategorizedError::new(
            ErrorCategory::Validation,
            "Invalid input",
            technical_details.clone(),
            "Some input data is invalid. Check the format and content of your input fields.",
            false,
        );
    }

    if err_str.contains("required") {
        return CategorizedError::new(
            ErrorCategory::Validation,
            "Missing required information",
            technical_details.clone(),
            "Required information is missing. Please provide all necessary details.",
            false,
        );
    }

    // Server errors (5xx status codes)
    if err_str.contains("500") || err_str.contains("internal server error") {
        return CategorizedError::new(
            ErrorCategory::Server,
            "Internal server error",
            technical_details.clone(),
            "The server encountered an internal error. Please try again in a moment. If the problem persists, the server may need attention.",
            true,
        );
    }

    if err_str.contains("502") || err_str.contains("bad gateway") {
        return CategorizedError::new(
            ErrorCategory::Network,
            "Bad gateway",
            technical_details.clone(),
            "The server received an invalid response from an upstream server. Try again in a moment.",
            true,
        );
    }

    if err_str.contains("503") || err_str.contains("service unavailable") {
        return CategorizedError::new(
            ErrorCategory::Server,
            "Service temporarily unavailable",
            technical_details.clone(),
            "The server is temporarily unable to handle your request. Please try again in a few minutes.",
            true,
        );
    }

    if err_str.contains("server error") {
        return CategorizedError::new(
            ErrorCategory::Server,
            "Server error occurred",
            technical_details.clone(),
            "The server encountered an error. Please try again in a moment. If the problem persists, contact support.",
            true,
        );
    }

    // Default fallback
    let user_msg = match context {
        "join" => "Failed to join room",
        "send" => "Failed to send message",
        "leave" => "Failed to leave room",
        "fetch" => "Failed to fetch messages",
        _ => "Operation failed",
    };

    CategorizedError::new(
        ErrorCategory::Server,
        user_msg,
        technical_details.clone(),
        "An unexpected error occurred. Please try again or contact support if the issue persists.",
        true,
    )
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

    // Generate keypair BEFORE calling join_ticket so we can sign the identity binding
    let (pop_pk, pop_sk) = dilithium5::keypair();
    let pop_public_key = pop_pk.as_bytes().to_vec();
    let pop_secret_key = pop_sk.as_bytes().to_vec();

    // Create identity binding by signing (alias || pop_public_key)
    let identity_binding = {
        use ciborium::ser::into_writer;
        use cityg_api_client::IdentityBinding;
        use pqcrypto_dilithium::dilithium5;
        use pqcrypto_traits::sign::DetachedSignature as _;
        use serde_bytes::ByteBuf;

        // Create the message to sign: CBOR([alias, pop_public_key])
        let message_data = (
            ByteBuf::from(alias.as_bytes().to_vec()),
            ByteBuf::from(pop_public_key.clone()),
        );
        let mut message = Vec::new();
        into_writer(&message_data, &mut message)
            .context("failed to encode identity binding message")?;

        // Sign the message
        let signature = dilithium5::detached_sign(&message, &pop_sk);

        Some(IdentityBinding {
            alias: alias.clone(),
            pop_public_key: pop_public_key.clone(),
            signature: signature.as_bytes().to_vec(),
        })
    };

    let configured_kbroad_public = configured_kbroad_public_from_env()?;
    let configured_kbroad_secret = configured_kbroad_secret_from_env()?;
    let mut generated_kbroad_keypair: Option<(Vec<u8>, Vec<u8>)> = None;
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

                    let provisioning_public = if let Some(public) =
                        configured_kbroad_public.as_ref()
                    {
                        public.clone()
                    } else if let Some((public, _)) = generated_kbroad_keypair.as_ref() {
                        public.clone()
                    } else {
                        if configured_kbroad_secret.is_some() {
                            return Err(anyhow!(
                                "{} is set but {} is missing; cannot bootstrap an unprovisioned room",
                                KBROAD_SECRET_ENV,
                                KBROAD_PUBLIC_ENV
                            ));
                        }
                        let pair = generate_kbroad_keypair();
                        let public = pair.0.clone();
                        generated_kbroad_keypair = Some(pair);
                        public
                    };

                    match client.bootstrap_room(&room_id, &provisioning_public).await {
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

                let mut detail = describe_http_failure(
                    status.as_str(),
                    &message,
                    freeze_code,
                    freeze_reason.as_deref(),
                );
                if status.is_server_error() && message.contains("kbroad key missing") {
                    detail.push_str(
                        " (room is not KBROAD-provisioned; set CITYG_GUI_KBROAD_PUBLIC_HEX or allow local key generation)",
                    );
                }
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
    if let Some(expected_public) = configured_kbroad_public.as_ref()
        && expected_public != &kbroad_public
    {
        return Err(anyhow!(
            "{} does not match server room key for this room",
            KBROAD_PUBLIC_ENV
        ));
    }
    let kbroad_secret = if let Some(secret) = configured_kbroad_secret {
        secret
    } else if let Some((generated_public, generated_secret)) = generated_kbroad_keypair.as_ref() {
        if generated_public == &kbroad_public {
            generated_secret.clone()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
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
    rand::thread_rng().fill_bytes(&mut k_fs);
    let mut fs_state = ForwardSecrecyState::new(k_fs);

    // pop_pk, pop_sk, pop_public_key, pop_secret_key already generated above

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
            secret_key: &pop_sk,
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
    let session = AppSession {
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
        kbroad_secret,
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
            barrier_version: ticket.barrier_version,
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

    Ok(session)
}

async fn perform_leave(request: LeaveRequest) -> Result<()> {
    let persist_request = request.clone();
    let LeaveRequest {
        server_url,
        room_id,
        gid,
        leaf_id,
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
    let mut kbroad_rotation_attempted = false;
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
                {
                    if status.is_server_error()
                        && message.contains("kbroad rotation required")
                        && !kbroad_rotation_attempted
                    {
                        kbroad_rotation_attempted = true;
                        rotate_room_kbroad_with_fresh_key(&client, &room_id)
                            .await
                            .context("rotate KBROAD before merge")?;
                        continue;
                    }

                    if should_retry_ticket_http_error(status.as_u16(), message, *freeze_code)
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
    persist_pending_barrier_state_before_publish(
        &persist_request,
        BarrierPendingState {
            barrier_version: next_barrier_version,
            revocation_roots_hash,
            kem_tree_hash_after: barrier_update.kem_tree_hash_after,
            k_barrier_new: barrier_update.k_barrier_new,
            k_fs_after_pcs: None,
            barrier_update_reason: Some(0),
            barrier_update_digest: barrier_update.barrier_update_digest,
            on_path_key_material: barrier_update.on_path_key_material.clone(),
        },
    )?;

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

    let mut bundle =
        CityGClient::generate_merge(header, parts, params, &parities, None, witness_bytes)
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

    match client.refresh_pivot(&bundle).await {
        Ok(_) => {}
        Err(ApiClientError::HttpStatus {
            status, message, ..
        }) if status.is_server_error()
            && (message.contains("pivot head missing")
                || message.contains("refresh payload diverges from stored parity")) =>
        {
            warn!("leave refresh pivot skipped: {message}");
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
    let persist_request = request.clone();
    let LeaveRequest {
        server_url,
        room_id,
        gid,
        leaf_id,
        pop_public_key,
        pop_secret_key,
        vrf_secret_key,
        vrf_public_key,
        fs_ec,
        fs_epoch_commit,
        fs_dev_prev_commit,
        k_fs_current,
        we_epoch_id,
        max_barrier_update_bytes: stored_max_barrier_update_bytes,
        barrier_recovery_pending,
    } = request;

    if barrier_recovery_pending {
        return Err(anyhow!(
            "cannot originate PCS refresh while barrier recovery is pending; complete FULL barrier recovery first"
        ));
    }

    let client = new_api_client(&server_url);
    let mut kbroad_rotation_attempted = false;
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
                {
                    if status.is_server_error()
                        && message.contains("kbroad rotation required")
                        && !kbroad_rotation_attempted
                    {
                        kbroad_rotation_attempted = true;
                        rotate_room_kbroad_with_fresh_key(&client, &room_id)
                            .await
                            .context("rotate KBROAD before refresh merge")?;
                        continue;
                    }

                    if should_retry_ticket_http_error(status.as_u16(), message, *freeze_code)
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
                }

                return Err(err).context("failed to obtain refresh merge ticket");
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
            "refresh merge ticket unexpectedly contained SRX payload"
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
    let k_fs_after_pcs = derive_k_fs_after_pcs(
        &k_fs_current,
        &we_epoch_id,
        fs_ec,
        next_barrier_version,
        &barrier_update.k_barrier_new,
    )?;
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(barrier_update.raw_update.clone()),
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(1u64)),
    );
    persist_pending_barrier_state_before_publish(
        &persist_request,
        BarrierPendingState {
            barrier_version: next_barrier_version,
            revocation_roots_hash,
            kem_tree_hash_after: barrier_update.kem_tree_hash_after,
            k_barrier_new: barrier_update.k_barrier_new.clone(),
            k_fs_after_pcs: Some(Zeroizing::new(k_fs_after_pcs)),
            barrier_update_reason: Some(1),
            barrier_update_digest: barrier_update.barrier_update_digest,
            on_path_key_material: barrier_update.on_path_key_material.clone(),
        },
    )?;

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

    let mut bundle =
        CityGClient::generate_merge(header, parts, params, &parities, None, witness_bytes)
            .context("failed to build refresh merge bundle")?;

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

    match client.refresh_pivot(&bundle).await {
        Ok(_) => {}
        Err(ApiClientError::HttpStatus {
            status, message, ..
        }) if status.is_server_error()
            && (message.contains("pivot head missing")
                || message.contains("refresh payload diverges from stored parity")) =>
        {
            warn!("refresh pivot skipped: {message}");
        }
        Err(err) => return Err(err).context("refresh pivot parity"),
    }

    client
        .accept_epoch_bundle(&bundle)
        .await
        .context("server rejected refresh merge bundle")?;

    Ok(())
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
    let ticket = client
        .merge_ticket_refresh(&session.room_id, &session.leaf_id)
        .await
        .context("failed to fetch merge ticket for epoch sync")?;
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
    let barrier_changed = session.barrier_state.barrier_version != ticket.barrier_version
        || session.barrier_state.kem_tree_hash_after != ticket_kem_tree_hash_after
        || session.barrier_state.max_barrier_update_bytes != ticket_max_barrier_update_bytes_u64
        || session.barrier_state.n_max != ticket_n_max
        || session.barrier_state.cover_leaf_index != ticket.cover_leaf_index;
    session.barrier_state.barrier_version = ticket.barrier_version;
    session.barrier_state.max_barrier_update_bytes = ticket_max_barrier_update_bytes_u64;
    session.barrier_state.n_max = ticket_n_max;
    session.barrier_state.cover_leaf_index = ticket.cover_leaf_index;
    let pending_changed_without_bundle =
        apply_pending_barrier_activation(&mut session, ticket.barrier_version, None)?;

    if let Some(pivot) = select_pivot_parity(&ticket.parities) {
        session.xk_hash = pivot.xk_hash;
    }

    if ticket.we_epoch_id == session.we_epoch_id {
        session.barrier_state.kem_tree_hash_after = ticket_kem_tree_hash_after;
        return Ok(EpochSyncOutcome {
            session,
            changed: barrier_changed || pending_changed_without_bundle,
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

    let mut active_kbroad_secret = if session.kbroad_secret.is_empty() {
        None
    } else {
        Some(session.kbroad_secret.clone())
    };
    if active_kbroad_secret.is_none() {
        active_kbroad_secret = configured_kbroad_secret_from_env()?;
    }

    let (derived_epoch_key, _) = if let Some(kbroad_secret) = active_kbroad_secret.as_ref() {
        bundle
            .derive_epoch_secrets_with_kbroad_secret(kbroad_secret.as_slice())
            .context("failed to derive epoch key during sync")?
    } else {
        bundle.derive_epoch_secrets().map_err(|err| {
            if err.to_string()
                .contains("bundle missing local hp key; use derive_epoch_secrets_with_kbroad_secret")
            {
                anyhow!(
                    "failed to derive epoch key during sync: bundle is redacted; provide room KBROAD secret via {}",
                    KBROAD_SECRET_ENV
                )
            } else {
                anyhow!("failed to derive epoch key during sync: {err}")
            }
        })?
    };

    let gid = bytes32("gid", &bundle.anchor.gid)?;
    if gid != session.gid {
        return Err(anyhow!(
            "bundle gid mismatch: expected {}, got {}",
            hex_encode(session.gid),
            hex_encode(gid)
        ));
    }

    session.we_epoch_id = bundle.we_epoch_id;
    session.xk_hash = bundle.hp_binding.xk_hash;
    session.epoch_key = derived_epoch_key;
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
    if let Some(commit) = header_bytes32(&bundle.header_map, hdr::HDR_FS_DEV_COMMIT)
        .or_else(|| header_bytes32(&bundle.header_map, hdr::HDR_FS_DEV_PREV_COMMIT))
    {
        session.fs_dev_prev_commit = commit;
    }
    if let Some(barrier_version) = header_u64(&bundle.header_map, hdr::HDR_BARRIER_VERSION) {
        session.barrier_state.barrier_version = barrier_version;
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
    if let Some(secret) = active_kbroad_secret {
        session.kbroad_secret = secret;
    }

    let accepted_digest = extract_barrier_update_digest(&bundle.header_map)?;
    let pending_before = session.barrier_state.pending.clone();
    let _pending_changed_with_bundle =
        apply_pending_barrier_activation(&mut session, ticket.barrier_version, accepted_digest)?;
    let pending_applied = matches!(
        (pending_before.as_ref(), accepted_digest),
        (Some(pending), Some(digest))
            if digest == pending.barrier_update_digest && ticket.barrier_version >= pending.barrier_version
    );

    if !pending_applied {
        let has_barrier_update = matches!(
            bundle.header_map.get(&hdr::HDR_BARRIER_UPDATE),
            Some(Value::Bytes(_))
        );
        if has_barrier_update {
            let raw_update = match bundle.header_map.get(&hdr::HDR_BARRIER_UPDATE) {
                Some(Value::Bytes(raw)) => raw.as_slice(),
                Some(_) => return Err(anyhow!("header barrier_update must be bytes")),
                None => return Err(anyhow!("missing barrier_update bytes")),
            };
            full_chain_check_barrier_update(
                &client,
                &session.room_id,
                &session,
                &bundle.header_map,
                raw_update,
                ticket_max_barrier_update_bytes,
            )
            .await?;
            match try_recover_barrier_from_header(
                &session,
                &bundle.header_map,
                &session.we_epoch_id,
                session.fs_ec,
                ticket_max_barrier_update_bytes,
            ) {
                Ok(Some(recovered)) => {
                    let BarrierRecoverResult {
                        k_barrier_new,
                        kem_tree_hash_after,
                        k_fs_after_pcs,
                        derived_node_key_material,
                        ..
                    } = recovered;
                    if kem_tree_hash_after != ticket_kem_tree_hash_after {
                        return Err(anyhow!(
                            "barrier recover hash-chain mismatch: recovered hash does not match merge ticket"
                        ));
                    }
                    session.barrier_state.k_barrier = k_barrier_new;
                    for (node, material) in derived_node_key_material {
                        session.barrier_state.dk_nodes.insert(node, material);
                    }
                    if let Some(k_fs_after_pcs) = k_fs_after_pcs {
                        apply_forward_state_k_fs(&mut session, *k_fs_after_pcs);
                    }
                    session.barrier_state.barrier_recovery_pending = false;
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
        changed: true,
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

fn configured_kbroad_secret_from_env() -> Result<Option<Vec<u8>>> {
    configured_hex_from_env(KBROAD_SECRET_ENV)
}

fn configured_kbroad_public_from_env() -> Result<Option<Vec<u8>>> {
    configured_hex_from_env(KBROAD_PUBLIC_ENV)
}

fn generate_kbroad_keypair() -> (Vec<u8>, Vec<u8>) {
    let (public, secret) = kyber768::keypair();
    (
        KemPublicKey::as_bytes(&public).to_vec(),
        KemSecretKey::as_bytes(&secret).to_vec(),
    )
}

async fn rotate_room_kbroad_with_fresh_key(client: &CitygApiClient, room_id: &str) -> Result<()> {
    let (fresh_public, _) = generate_kbroad_keypair();
    client
        .rotate_room_kbroad(room_id, &fresh_public)
        .await
        .context("rotate room KBROAD")?;
    Ok(())
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

const MESSAGE_PREFIX: &[u8; 4] = b"CGM1";

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

/// Sign a message with ML-DSA-65 (Dilithium3)
/// The signature covers: leaf_id || timestamp_ms || plaintext
fn sign_message(
    leaf_id: &[u8; 32],
    timestamp_ms: u64,
    plaintext: &[u8],
    secret_key: &[u8],
) -> Result<Vec<u8>> {
    let sk = dilithium3::SecretKey::from_bytes(secret_key)
        .map_err(|_| anyhow!("invalid ML-DSA-65 secret key"))?;

    let mut payload = Vec::with_capacity(32 + 8 + plaintext.len());
    payload.extend_from_slice(leaf_id);
    payload.extend_from_slice(&timestamp_ms.to_le_bytes());
    payload.extend_from_slice(plaintext);

    let signature = dilithium3::detached_sign(&payload, &sk);
    Ok(signature.as_bytes().to_vec())
}

/// Verify a message signature using ML-DSA-65 (Dilithium3)
/// Returns Ok(()) if signature is valid, Err otherwise
fn verify_message_signature(
    leaf_id: &[u8; 32],
    timestamp_ms: u64,
    plaintext: &[u8],
    signature_bytes: &[u8],
    public_key_bytes: &[u8],
) -> Result<()> {
    let pk = dilithium3::PublicKey::from_bytes(public_key_bytes)
        .map_err(|_| anyhow!("invalid ML-DSA-65 public key"))?;

    let signature = dilithium3::DetachedSignature::from_bytes(signature_bytes)
        .map_err(|_| anyhow!("invalid ML-DSA-65 signature"))?;

    let mut payload = Vec::with_capacity(32 + 8 + plaintext.len());
    payload.extend_from_slice(leaf_id);
    payload.extend_from_slice(&timestamp_ms.to_le_bytes());
    payload.extend_from_slice(plaintext);

    dilithium3::verify_detached_signature(&signature, &payload, &pk)
        .map_err(|_| anyhow!("signature verification failed"))?;

    Ok(())
}

#[cfg(test)]
fn encrypt_message(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        ChaCha20Poly1305,
        aead::{Aead, AeadCore, KeyInit, OsRng},
    };

    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow!("encryption failed: {}", e))?;

    // Format: nonce (12 bytes) || ciphertext || tag (16 bytes, included in ciphertext)
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt message using ChaCha20-Poly1305 (post-quantum resistant AEAD)
/// Expects: nonce (12 bytes) || ciphertext || tag (16 bytes)
#[cfg(test)]
fn decrypt_message(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        ChaCha20Poly1305,
        aead::{Aead, KeyInit},
    };

    if data.len() < 12 {
        return Err(anyhow!(
            "ciphertext too short (need at least 12-byte nonce)"
        ));
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = nonce_bytes.into();

    let cipher = ChaCha20Poly1305::new(key.into());

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("decryption failed: {}", e))
}

fn encode_capss_witness(witness: &CapssWitnessBundle) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(witness, &mut buf).context("failed to encode CAPSS witness")?;
    Ok(buf)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
fn decode_capss_witness(data: &[u8]) -> Result<CapssWitnessBundle> {
    ciborium::de::from_reader(data).context("failed to decode CAPSS witness")
}

#[cfg(not(test))]
static CONFIG_DIR_OVERRIDE: LazyLock<Mutex<Option<PathBuf>>> = LazyLock::new(|| Mutex::new(None));

#[cfg(test)]
thread_local! {
    static CONFIG_DIR_OVERRIDE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::await_holding_lock,
    clippy::useless_conversion
)]
mod tests {
    use super::*;
    use futures::SinkExt;
    use gpui::{Modifiers, TestAppContext};
    use msphf_rlwe::CapssBranchWitness;
    use rand::{RngCore, SeedableRng, rngs::StdRng};
    use std::sync::{
        Arc, Once,
        atomic::{AtomicU16, Ordering},
    };
    use tempfile::TempDir;
    use tokio::{task::JoinHandle, time::sleep};

    static NEXT_TEST_PORT: AtomicU16 = AtomicU16::new(18400);
    static ENV_VAR_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    const TEST_ADMIN_TOKEN: &str = "cityg-test-admin-token";
    const TEST_MESSAGE_TOKEN: &str = "cityg-test-message-token";
    static TEST_AUTH_ENV_INIT: Once = Once::new();

    fn init_test_auth_env() {
        TEST_AUTH_ENV_INIT.call_once(|| {
            // SAFETY: test auth env is initialized once with process-stable values.
            unsafe {
                std::env::set_var("CITYG_SERVER_WINDOW_ADMIN_TOKEN", TEST_ADMIN_TOKEN);
                std::env::set_var("CITYG_SERVER_ROOMS_ADMIN_TOKEN", TEST_ADMIN_TOKEN);
                std::env::set_var("CITYG_SERVER_MESSAGE_AUTH_TOKEN", TEST_MESSAGE_TOKEN);
                std::env::set_var(CLIENT_ADMIN_TOKEN_ENV, TEST_ADMIN_TOKEN);
                std::env::set_var(CLIENT_MESSAGE_TOKEN_ENV, TEST_MESSAGE_TOKEN);
                std::env::remove_var("CITYG_SERVER_ALLOW_INSECURE_ADMIN");
            }
        });
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
            vrf_proof: vec![0x11, 0x22],
            vrf_public: vec![0x33, 0x44],
            mask_a: [0xAA; 32],
            mask_b: [0xBB; 32],
            fs_capss: vec![0x55],
            proofs_commit: [0x66; 32],
            srx_commit: Some([0x77; 32]),
            srx_root_sw: Some([0x78; 32]),
            is_join: true,
            hp_envelope: Arc::<[u8]>::from(vec![0x99, 0x88]),
            fs_epoch_commit: Some([0x42; 32]),
            fs_ec: Some(12),
            fs_dev_commit: Some([0x24; 32]),
        }
    }

    #[test]
    fn generate_vrf_keys_are_not_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let (secret_a, public_a) = generate_vrf_keys()?;
        let (secret_b, public_b) = generate_vrf_keys()?;
        assert!(!secret_a.is_empty());
        assert!(!public_a.is_empty());
        assert_ne!(secret_a, secret_b);
        assert_ne!(public_a, public_b);
        Ok(())
    }

    fn build_test_session(
        seed: u64,
        server_url: &str,
        room_id: &str,
        alias: &str,
    ) -> Result<AppSession, Box<dyn std::error::Error>> {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut random_vec = |len: usize| {
            let mut buf = vec![0u8; len];
            rng.fill_bytes(&mut buf);
            buf
        };

        let forward_state =
            ForwardSecrecyState::with_state([0xAAu8; 32], 17, [0x55u8; 32], [0x99u8; 32]);
        let capss_witness_bundle = CapssWitnessBundle {
            branch_a: msphf_rlwe::CapssBranchWitness {
                branch_artifact: random_vec(24),
                ctx_tag: random_vec(16),
            },
            branch_b: msphf_rlwe::CapssBranchWitness {
                branch_artifact: random_vec(24),
                ctx_tag: random_vec(16),
            },
        };
        let capss_witness_bytes = encode_capss_witness(&capss_witness_bundle)?;
        let barrier_state = BarrierSecretState::default();

        let mut session = AppSession {
            server_url: server_url.to_string(),
            room_id: room_id.to_string(),
            alias: alias.to_string(),
            gid: [0x01u8; 32],
            cat: [0x02u8; 32],
            leaf_id: [0x03u8; 32],
            parent_root: [0x04u8; 32],
            join_delta_root: [0x05u8; 32],
            revoked_since_root: [0x06u8; 32],
            revoked_root: [0x07u8; 32],
            regular_fingerprint: Some([0x21u8; 32]),
            fs_fingerprint: None,
            tswe_salt_hash: [0x08u8; 32],
            pox_r_commit: [0x09u8; 32],
            we_epoch_id: [0x10u8; 32],
            xk_hash: [0x14u8; 32],
            epoch_key: [0x11u8; 32],
            forward_state,
            fs_ec: 17,
            fs_epoch_commit: [0x12u8; 32],
            fs_dev_prev_commit: [0x13u8; 32],
            fs_epoch_created_at: SystemTime::now(),
            fs_epoch_rotation_interval_secs: 300,
            pop_public_key: random_vec(48),
            pop_secret_key: random_vec(96),
            msg_sign_public_key: random_vec(1952),
            msg_sign_secret_key: random_vec(4032),
            vrf_secret_key: random_vec(32),
            vrf_public_key: random_vec(32),
            kbroad_public: random_vec(24),
            kbroad_secret: random_vec(32),
            bootstrap_public: random_vec(24),
            proof_mode: "lin+zkvrf".to_string(),
            vrf_id: "vrf-demo".to_string(),
            policy_version: "v1".to_string(),
            msphf_crs_id: "rlwe-merkle/v1".to_string(),
            msphf_params_id: "rlwe-params/mock".to_string(),
            fs_policy_version: "7".to_string(),
            fs_epoch_base_ts: 42,
            last_fetch_timestamp_ms: Some(1_234_567),
            msg_replay_state: MsgReplayState::default(),
            capss_witness: capss_witness_bytes,
            barrier_state,
        };
        session.fs_fingerprint = derive_fs_fingerprint_from_fields(
            session.fs_policy_version.as_str(),
            session.fs_ec,
            &session.fs_epoch_commit,
            session.fs_epoch_base_ts,
        );
        Ok(session)
    }

    #[test]
    fn pending_barrier_activation_applies_on_digest_match() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut session = build_test_session(0xA11, "http://127.0.0.1:9", "room-a", "alice")?;
        let mut on_path = BTreeMap::new();
        on_path.insert(
            7,
            BarrierNodeKeyMaterial {
                dk: Zeroizing::new(vec![0x11; 32]),
                pkhash: [0x22; 32],
            },
        );
        let raw_update = vec![0xAB, 0xCD, 0xEF];
        let digest = compute_barrier_update_digest(raw_update.as_slice())?;
        session.barrier_state.pending = Some(BarrierPendingState {
            barrier_version: 9,
            revocation_roots_hash: [0x33; 32],
            kem_tree_hash_after: [0x44; 32],
            k_barrier_new: Zeroizing::new([0x55; 32]),
            k_fs_after_pcs: Some(Zeroizing::new([0x66; 32])),
            barrier_update_reason: Some(1),
            barrier_update_digest: digest,
            on_path_key_material: on_path,
        });

        let changed = apply_pending_barrier_activation(&mut session, 9, Some(digest))?;
        assert!(changed);
        assert!(session.barrier_state.pending.is_none());
        assert_eq!(session.barrier_state.barrier_version, 9);
        assert_eq!(*session.barrier_state.k_barrier, [0x55; 32]);
        assert_eq!(session.barrier_state.kem_tree_hash_after, [0x44; 32]);
        assert_eq!(
            session
                .barrier_state
                .dk_nodes
                .get(&7)
                .expect("node material persisted")
                .pkhash,
            [0x22; 32]
        );
        assert_eq!(session.forward_state.snapshot().k_fs, [0x66; 32]);
        Ok(())
    }

    #[test]
    fn pending_barrier_activation_drops_state_when_overtaken()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut session = build_test_session(0xB22, "http://127.0.0.1:9", "room-b", "bob")?;
        session.barrier_state.pending = Some(BarrierPendingState {
            barrier_version: 5,
            revocation_roots_hash: [0x11; 32],
            kem_tree_hash_after: [0x22; 32],
            k_barrier_new: Zeroizing::new([0x33; 32]),
            k_fs_after_pcs: None,
            barrier_update_reason: Some(1),
            barrier_update_digest: [0x44; 32],
            on_path_key_material: BTreeMap::new(),
        });

        let changed = apply_pending_barrier_activation(&mut session, 6, None)?;
        assert!(changed);
        assert!(session.barrier_state.pending.is_none());
        Ok(())
    }

    #[test]
    fn pending_barrier_activation_drops_state_on_digest_mismatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut session = build_test_session(0xB3, "http://127.0.0.1:9", "room-b2", "bob")?;
        session.barrier_state.pending = Some(BarrierPendingState {
            barrier_version: 7,
            revocation_roots_hash: [0x51; 32],
            kem_tree_hash_after: [0x61; 32],
            k_barrier_new: Zeroizing::new([0x71; 32]),
            k_fs_after_pcs: Some(Zeroizing::new([0x81; 32])),
            barrier_update_reason: Some(1),
            barrier_update_digest: [0x91; 32],
            on_path_key_material: BTreeMap::new(),
        });

        let changed = apply_pending_barrier_activation(&mut session, 7, Some([0x92; 32]))?;
        assert!(changed);
        assert!(session.barrier_state.pending.is_none());
        assert_eq!(session.barrier_state.barrier_version, 0);
        assert_eq!(session.forward_state.snapshot().k_fs, [0xAAu8; 32]);
        Ok(())
    }

    #[test]
    fn pending_barrier_activation_does_not_activate_on_digest_match_with_newer_observed_version()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut session = build_test_session(0xB4, "http://127.0.0.1:9", "room-b3", "bob")?;
        let digest = [0x31; 32];
        session.barrier_state.pending = Some(BarrierPendingState {
            barrier_version: 7,
            revocation_roots_hash: [0x41; 32],
            kem_tree_hash_after: [0x51; 32],
            k_barrier_new: Zeroizing::new([0x61; 32]),
            k_fs_after_pcs: Some(Zeroizing::new([0x71; 32])),
            barrier_update_reason: Some(1),
            barrier_update_digest: digest,
            on_path_key_material: BTreeMap::new(),
        });

        let changed = apply_pending_barrier_activation(&mut session, 8, Some(digest))?;
        assert!(changed);
        assert!(session.barrier_state.pending.is_none());
        assert_eq!(
            session.barrier_state.barrier_version, 0,
            "newer observed version must not activate older pending state"
        );
        assert_eq!(
            session.forward_state.snapshot().k_fs,
            [0xAAu8; 32],
            "PCS reseed must not activate when observed version overtook pending state"
        );
        Ok(())
    }

    #[test]
    fn extract_barrier_update_digest_uses_raw_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let mut header = BTreeMap::new();
        let raw = vec![0x01, 0x02, 0x03, 0x04];
        header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(raw.clone()));
        assert_eq!(
            extract_barrier_update_digest(&header)?,
            Some(compute_barrier_update_digest(raw.as_slice())?)
        );
        header.insert(hdr::HDR_BARRIER_UPDATE, Value::Integer(Integer::from(7u64)));
        assert!(extract_barrier_update_digest(&header).is_err());
        Ok(())
    }

    #[test]
    fn validate_barrier_tree_snapshot_auth_checks_hash_and_content()
    -> Result<(), Box<dyn std::error::Error>> {
        let n_max = 4u64;
        let pk_entries = vec![Vec::new(); 7];
        let expected_hash = compute_barrier_tree_hash(n_max, pk_entries.as_slice())?;
        let mut snapshot = BarrierPublicTree {
            n_max,
            kem_tree_hash_after: [0xAB; 32],
            pk_entries: pk_entries.clone(),
        };

        let err = validate_barrier_tree_snapshot_auth(&expected_hash, n_max, &snapshot)
            .expect_err("mismatched response hash must fail");
        assert!(
            err.to_string().contains("960.9"),
            "unexpected snapshot-auth error: {err}"
        );

        snapshot.kem_tree_hash_after = expected_hash;
        snapshot.pk_entries[3] = vec![0x11; 1184];
        let err = validate_barrier_tree_snapshot_auth(&expected_hash, n_max, &snapshot)
            .expect_err("mismatched tree content must fail");
        assert!(
            err.to_string().contains("960.9"),
            "unexpected snapshot-auth error: {err}"
        );

        let good_snapshot = BarrierPublicTree {
            n_max,
            kem_tree_hash_after: expected_hash,
            pk_entries,
        };
        validate_barrier_tree_snapshot_auth(&expected_hash, n_max, &good_snapshot)?;
        Ok(())
    }

    #[test]
    fn try_recover_barrier_from_header_returns_none_without_matches()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut session = build_test_session(0xC11, "http://127.0.0.1:9", "room-c", "carol")?;
        session.barrier_state.n_max = 8;
        session.barrier_state.cover_leaf_index = 3;
        session.barrier_state.barrier_version = 4;
        session.barrier_state.kem_tree_hash_after = [0xAA; 32];

        let (leaf_ek, leaf_dk) = kyber768::keypair();
        session.barrier_state.dk_leaf = Zeroizing::new(KemSecretKey::as_bytes(&leaf_dk).to_vec());
        session.barrier_state.pkhash_leaf =
            compute_barrier_pkhash(KemPublicKey::as_bytes(&leaf_ek))?;

        let revoked_since_root = [0x11; 32];
        let revoked_root = [0x22; 32];
        let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
        let new_public_keys = vec![
            NewPublicKeyWire(0, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
            NewPublicKeyWire(1, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
            NewPublicKeyWire(4, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
        ];
        let cover =
            KemTreeCoverPayloadWire(3, vec![10, 4, 1, 0], None, Vec::new(), new_public_keys);
        let cover_bytes = to_cbor_vec(&cover)?;
        let update = BarrierUpdateWire(
            "barrier-v1".to_string(),
            5,
            4,
            8,
            rrh.to_vec(),
            session.barrier_state.kem_tree_hash_after.to_vec(),
            [0xBB; 32].to_vec(),
            cover_bytes,
        );
        let update_bytes = to_cbor_vec(&update)?;

        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(update_bytes));
        header.insert(
            hdr::HDR_REVOKED_SINCE_ROOT,
            Value::Bytes(revoked_since_root.to_vec()),
        );
        header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(0u64)),
        );
        header.insert(hdr::HDR_POP_PK, Value::Bytes(vec![0xDD; 32]));

        let recovered = try_recover_barrier_from_header(
            &session,
            &header,
            &session.we_epoch_id,
            session.fs_ec,
            DEFAULT_MAX_BARRIER_UPDATE_BYTES as usize,
        )?;
        assert!(recovered.is_none());
        Ok(())
    }

    #[test]
    fn try_recover_barrier_from_header_rejects_oversized_update()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut session = build_test_session(0xC12, "http://127.0.0.1:9", "room-c2", "cora")?;
        session.barrier_state.n_max = 8;
        session.barrier_state.cover_leaf_index = 3;
        session.barrier_state.barrier_version = 4;
        session.barrier_state.kem_tree_hash_after = [0xAA; 32];

        let revoked_since_root = [0x11; 32];
        let revoked_root = [0x22; 32];
        let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
        let new_public_keys = vec![
            NewPublicKeyWire(0, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
            NewPublicKeyWire(1, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
            NewPublicKeyWire(4, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
        ];
        let cover =
            KemTreeCoverPayloadWire(3, vec![10, 4, 1, 0], None, Vec::new(), new_public_keys);
        let cover_bytes = to_cbor_vec(&cover)?;
        let update = BarrierUpdateWire(
            "barrier-v1".to_string(),
            5,
            4,
            8,
            rrh.to_vec(),
            session.barrier_state.kem_tree_hash_after.to_vec(),
            [0xBB; 32].to_vec(),
            cover_bytes,
        );
        let update_bytes = to_cbor_vec(&update)?;

        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(update_bytes.clone()));
        header.insert(
            hdr::HDR_REVOKED_SINCE_ROOT,
            Value::Bytes(revoked_since_root.to_vec()),
        );
        header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(0u64)),
        );
        header.insert(hdr::HDR_POP_PK, Value::Bytes(vec![0xDD; 32]));

        let err = try_recover_barrier_from_header(
            &session,
            &header,
            &session.we_epoch_id,
            session.fs_ec,
            update_bytes.len().saturating_sub(1),
        )
        .expect_err("oversized barrier_update must be rejected");
        assert!(
            err.to_string().contains("exceeds max_barrier_update_bytes"),
            "unexpected error: {err}"
        );
        Ok(())
    }

    #[test]
    fn try_recover_barrier_from_header_recovers_key_and_pcs_reseed()
    -> Result<(), Box<dyn std::error::Error>> {
        use chacha20poly1305::{
            ChaCha20Poly1305,
            aead::{Aead, KeyInit, Payload},
        };

        let mut session = build_test_session(0xD44, "http://127.0.0.1:9", "room-d", "diana")?;
        session.barrier_state.n_max = 8;
        session.barrier_state.cover_leaf_index = 3;
        session.barrier_state.barrier_version = 8;
        session.barrier_state.kem_tree_hash_after = [0xAA; 32];
        let fs_ec = 31;

        let (leaf_ek, leaf_dk) = kyber768::keypair();
        let leaf_ek_bytes = KemPublicKey::as_bytes(&leaf_ek).to_vec();
        session.barrier_state.dk_leaf = Zeroizing::new(KemSecretKey::as_bytes(&leaf_dk).to_vec());
        session.barrier_state.pkhash_leaf = compute_barrier_pkhash(leaf_ek_bytes.as_slice())?;

        let revoked_since_root = [0x31; 32];
        let revoked_root = [0x32; 32];
        let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
        session.revoked_since_root = revoked_since_root;
        session.revoked_root = revoked_root;

        let source_node = 4u64;
        let target_node = 10u64;
        let path_secret_source = [0x44; 32];
        let salt_1 = h_l("barrier/tree/path", &BarrierTreePathSaltPreimage(1))?;
        let ps_1 = hkdf_blake3(&salt_1, &path_secret_source, BARRIER_TREE_INFO);
        let salt_0 = h_l("barrier/tree/path", &BarrierTreePathSaltPreimage(0))?;
        let ps_0 = hkdf_blake3(&salt_0, &ps_1, BARRIER_TREE_INFO);
        let target_pk = kyber768::PublicKey::from_bytes(leaf_ek_bytes.as_slice())?;
        let (ss, ct) = kyber768::encapsulate(&target_pk);
        let target_pkhash = compute_barrier_pkhash(leaf_ek_bytes.as_slice())?;
        let aad = to_cbor_vec(&BarrierWrapAadPreimage(
            &session.gid,
            9,
            &rrh,
            3,
            source_node,
            target_node,
            &target_pkhash,
        ))?;
        let nonce_full = h_l(
            "barrier/wrap/nonce",
            &BarrierWrapNoncePreimage(source_node, target_node),
        )?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_full[..12]);
        let cipher = ChaCha20Poly1305::new(ss.as_bytes().into());
        let wrapped_ps = cipher.encrypt(
            (&nonce).into(),
            Payload {
                msg: path_secret_source.as_slice(),
                aad: aad.as_slice(),
            },
        )?;

        let mut target_prefix = [0u8; 16];
        target_prefix.copy_from_slice(&target_pkhash[..16]);
        let node_ciphertexts = vec![NodeCiphertextWire(
            source_node,
            target_node,
            target_prefix.to_vec(),
            KemCiphertext::as_bytes(&ct).to_vec(),
            wrapped_ps,
        )];
        let (_, _, ek_0) = derive_internal_node_key_material(&ps_0, 9, &rrh, 8, 0)?;
        let (_, _, ek_1) = derive_internal_node_key_material(&ps_1, 9, &rrh, 8, 1)?;
        let (_, _, ek_4) = derive_internal_node_key_material(&path_secret_source, 9, &rrh, 8, 4)?;
        let new_public_keys = vec![
            NewPublicKeyWire(0, ek_0),
            NewPublicKeyWire(1, ek_1),
            NewPublicKeyWire(4, ek_4),
        ];
        let cover = KemTreeCoverPayloadWire(
            3,
            vec![10, 4, 1, 0],
            None,
            node_ciphertexts,
            new_public_keys,
        );
        let cover_bytes = to_cbor_vec(&cover)?;
        let update = BarrierUpdateWire(
            "barrier-v1".to_string(),
            9,
            8,
            8,
            rrh.to_vec(),
            session.barrier_state.kem_tree_hash_after.to_vec(),
            [0xBB; 32].to_vec(),
            cover_bytes,
        );
        let update_bytes = to_cbor_vec(&update)?;

        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(update_bytes));
        header.insert(
            hdr::HDR_REVOKED_SINCE_ROOT,
            Value::Bytes(revoked_since_root.to_vec()),
        );
        header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(1u64)),
        );
        header.insert(hdr::HDR_POP_PK, Value::Bytes(vec![0xEE; 32]));

        let recovered = try_recover_barrier_from_header(
            &session,
            &header,
            &session.we_epoch_id,
            fs_ec,
            DEFAULT_MAX_BARRIER_UPDATE_BYTES as usize,
        )?
        .ok_or_else(|| anyhow!("expected recover result"))?;

        let barrier_salt = h_l("barrier/derive/salt", &BarrierDeriveSaltPreimage(9, &rrh))?;
        let expected_k_barrier = hkdf_blake3(&barrier_salt, &ps_0, BARRIER_KEY_INFO);
        assert_eq!(*recovered.k_barrier_new, expected_k_barrier);
        assert_eq!(recovered.derived_node_key_material.len(), 3);
        assert!(recovered.derived_node_key_material.contains_key(&0));
        assert!(recovered.derived_node_key_material.contains_key(&1));
        assert!(recovered.derived_node_key_material.contains_key(&4));

        let expected_k_fs_after_pcs = derive_k_fs_after_pcs(
            &session.forward_state.snapshot().k_fs,
            &session.we_epoch_id,
            fs_ec,
            9,
            &expected_k_barrier,
        )?;
        assert_eq!(
            recovered.k_fs_after_pcs.as_deref().copied(),
            Some(expected_k_fs_after_pcs)
        );
        Ok(())
    }

    #[test]
    fn try_recover_barrier_from_header_rejects_new_public_key_mismatch()
    -> Result<(), Box<dyn std::error::Error>> {
        use chacha20poly1305::{
            ChaCha20Poly1305,
            aead::{Aead, KeyInit, Payload},
        };

        let mut session = build_test_session(0xD4E, "http://127.0.0.1:9", "room-f", "frank")?;
        session.barrier_state.n_max = 8;
        session.barrier_state.cover_leaf_index = 3;
        session.barrier_state.barrier_version = 8;
        session.barrier_state.kem_tree_hash_after = [0xAA; 32];

        let (leaf_ek, leaf_dk) = kyber768::keypair();
        let leaf_ek_bytes = KemPublicKey::as_bytes(&leaf_ek).to_vec();
        session.barrier_state.dk_leaf = Zeroizing::new(KemSecretKey::as_bytes(&leaf_dk).to_vec());
        session.barrier_state.pkhash_leaf = compute_barrier_pkhash(leaf_ek_bytes.as_slice())?;

        let revoked_since_root = [0x31; 32];
        let revoked_root = [0x32; 32];
        let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
        session.revoked_since_root = revoked_since_root;
        session.revoked_root = revoked_root;

        let source_node = 4u64;
        let target_node = 10u64;
        let path_secret_source = [0x44; 32];
        let salt_1 = h_l("barrier/tree/path", &BarrierTreePathSaltPreimage(1))?;
        let ps_1 = hkdf_blake3(&salt_1, &path_secret_source, BARRIER_TREE_INFO);
        let salt_0 = h_l("barrier/tree/path", &BarrierTreePathSaltPreimage(0))?;
        let ps_0 = hkdf_blake3(&salt_0, &ps_1, BARRIER_TREE_INFO);
        let target_pk = kyber768::PublicKey::from_bytes(leaf_ek_bytes.as_slice())?;
        let (ss, ct) = kyber768::encapsulate(&target_pk);
        let target_pkhash = compute_barrier_pkhash(leaf_ek_bytes.as_slice())?;
        let aad = to_cbor_vec(&BarrierWrapAadPreimage(
            &session.gid,
            9,
            &rrh,
            3,
            source_node,
            target_node,
            &target_pkhash,
        ))?;
        let nonce_full = h_l(
            "barrier/wrap/nonce",
            &BarrierWrapNoncePreimage(source_node, target_node),
        )?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_full[..12]);
        let cipher = ChaCha20Poly1305::new(ss.as_bytes().into());
        let wrapped_ps = cipher.encrypt(
            (&nonce).into(),
            Payload {
                msg: path_secret_source.as_slice(),
                aad: aad.as_slice(),
            },
        )?;

        let mut target_prefix = [0u8; 16];
        target_prefix.copy_from_slice(&target_pkhash[..16]);
        let node_ciphertexts = vec![NodeCiphertextWire(
            source_node,
            target_node,
            target_prefix.to_vec(),
            KemCiphertext::as_bytes(&ct).to_vec(),
            wrapped_ps,
        )];
        let (_, _, ek_0) = derive_internal_node_key_material(&ps_0, 9, &rrh, 8, 0)?;
        let (_, _, mut ek_1) = derive_internal_node_key_material(&ps_1, 9, &rrh, 8, 1)?;
        let (_, _, ek_4) = derive_internal_node_key_material(&path_secret_source, 9, &rrh, 8, 4)?;
        ek_1[0] ^= 0xA5;
        let new_public_keys = vec![
            NewPublicKeyWire(0, ek_0),
            NewPublicKeyWire(1, ek_1),
            NewPublicKeyWire(4, ek_4),
        ];
        let cover = KemTreeCoverPayloadWire(
            3,
            vec![10, 4, 1, 0],
            None,
            node_ciphertexts,
            new_public_keys,
        );
        let cover_bytes = to_cbor_vec(&cover)?;
        let update = BarrierUpdateWire(
            "barrier-v1".to_string(),
            9,
            8,
            8,
            rrh.to_vec(),
            session.barrier_state.kem_tree_hash_after.to_vec(),
            [0xBB; 32].to_vec(),
            cover_bytes,
        );
        let update_bytes = to_cbor_vec(&update)?;

        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(update_bytes));
        header.insert(
            hdr::HDR_REVOKED_SINCE_ROOT,
            Value::Bytes(revoked_since_root.to_vec()),
        );
        header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(1u64)),
        );
        header.insert(hdr::HDR_POP_PK, Value::Bytes(vec![0xEF; 32]));

        let err = try_recover_barrier_from_header(
            &session,
            &header,
            &session.we_epoch_id,
            session.fs_ec,
            DEFAULT_MAX_BARRIER_UPDATE_BYTES as usize,
        )
        .expect_err("ek_n mismatch must fail closed");
        assert!(
            err.to_string().contains("new_public_keys mismatch"),
            "unexpected error for ek_n mismatch: {err}"
        );
        Ok(())
    }

    #[test]
    fn try_recover_barrier_from_header_rejects_when_pkhash_t_breaks_aad()
    -> Result<(), Box<dyn std::error::Error>> {
        use chacha20poly1305::{
            ChaCha20Poly1305,
            aead::{Aead, KeyInit, Payload},
        };

        let mut session = build_test_session(0xD4F, "http://127.0.0.1:9", "room-g", "gina")?;
        session.barrier_state.n_max = 8;
        session.barrier_state.cover_leaf_index = 3;
        session.barrier_state.barrier_version = 8;
        session.barrier_state.kem_tree_hash_after = [0xAA; 32];

        let (leaf_ek, leaf_dk) = kyber768::keypair();
        let leaf_ek_bytes = KemPublicKey::as_bytes(&leaf_ek).to_vec();
        session.barrier_state.dk_leaf = Zeroizing::new(KemSecretKey::as_bytes(&leaf_dk).to_vec());
        let correct_pkhash = compute_barrier_pkhash(leaf_ek_bytes.as_slice())?;
        session.barrier_state.pkhash_leaf = correct_pkhash;

        let revoked_since_root = [0x31; 32];
        let revoked_root = [0x32; 32];
        let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
        session.revoked_since_root = revoked_since_root;
        session.revoked_root = revoked_root;

        let source_node = 4u64;
        let target_node = 10u64;
        let path_secret_source = [0x44; 32];
        let salt_1 = h_l("barrier/tree/path", &BarrierTreePathSaltPreimage(1))?;
        let ps_1 = hkdf_blake3(&salt_1, &path_secret_source, BARRIER_TREE_INFO);
        let salt_0 = h_l("barrier/tree/path", &BarrierTreePathSaltPreimage(0))?;
        let ps_0 = hkdf_blake3(&salt_0, &ps_1, BARRIER_TREE_INFO);
        let target_pk = kyber768::PublicKey::from_bytes(leaf_ek_bytes.as_slice())?;
        let (ss, ct) = kyber768::encapsulate(&target_pk);
        let aad = to_cbor_vec(&BarrierWrapAadPreimage(
            &session.gid,
            9,
            &rrh,
            3,
            source_node,
            target_node,
            &correct_pkhash,
        ))?;
        let nonce_full = h_l(
            "barrier/wrap/nonce",
            &BarrierWrapNoncePreimage(source_node, target_node),
        )?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_full[..12]);
        let cipher = ChaCha20Poly1305::new(ss.as_bytes().into());
        let wrapped_ps = cipher.encrypt(
            (&nonce).into(),
            Payload {
                msg: path_secret_source.as_slice(),
                aad: aad.as_slice(),
            },
        )?;

        let mut target_prefix = [0u8; 16];
        target_prefix.copy_from_slice(&correct_pkhash[..16]);
        let node_ciphertexts = vec![NodeCiphertextWire(
            source_node,
            target_node,
            target_prefix.to_vec(),
            KemCiphertext::as_bytes(&ct).to_vec(),
            wrapped_ps,
        )];
        let (_, _, ek_0) = derive_internal_node_key_material(&ps_0, 9, &rrh, 8, 0)?;
        let (_, _, ek_1) = derive_internal_node_key_material(&ps_1, 9, &rrh, 8, 1)?;
        let (_, _, ek_4) = derive_internal_node_key_material(&path_secret_source, 9, &rrh, 8, 4)?;
        let new_public_keys = vec![
            NewPublicKeyWire(0, ek_0),
            NewPublicKeyWire(1, ek_1),
            NewPublicKeyWire(4, ek_4),
        ];
        let cover = KemTreeCoverPayloadWire(
            3,
            vec![10, 4, 1, 0],
            None,
            node_ciphertexts,
            new_public_keys,
        );
        let cover_bytes = to_cbor_vec(&cover)?;
        let update = BarrierUpdateWire(
            "barrier-v1".to_string(),
            9,
            8,
            8,
            rrh.to_vec(),
            session.barrier_state.kem_tree_hash_after.to_vec(),
            [0xBB; 32].to_vec(),
            cover_bytes,
        );
        let update_bytes = to_cbor_vec(&update)?;

        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(update_bytes));
        header.insert(
            hdr::HDR_REVOKED_SINCE_ROOT,
            Value::Bytes(revoked_since_root.to_vec()),
        );
        header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(1u64)),
        );
        header.insert(hdr::HDR_POP_PK, Value::Bytes(vec![0xEF; 32]));

        let mut bad_pkhash = correct_pkhash;
        bad_pkhash[31] ^= 0x01;
        session.barrier_state.pkhash_leaf = bad_pkhash;

        let err = try_recover_barrier_from_header(
            &session,
            &header,
            &session.we_epoch_id,
            session.fs_ec,
            DEFAULT_MAX_BARRIER_UPDATE_BYTES as usize,
        )
        .expect_err("AAD mismatch from pkhash_t must fail closed");
        assert!(
            err.to_string().contains("candidate unwrap/decrypt failure"),
            "unexpected error for pkhash_t AAD mismatch: {err}"
        );
        Ok(())
    }

    #[test]
    fn try_recover_barrier_from_header_rejects_when_client_pkhash_t_mismatches()
    -> Result<(), Box<dyn std::error::Error>> {
        use chacha20poly1305::{
            ChaCha20Poly1305,
            aead::{Aead, KeyInit, Payload},
        };

        let mut session = build_test_session(0xD45, "http://127.0.0.1:9", "room-e", "erin")?;
        session.barrier_state.n_max = 8;
        session.barrier_state.cover_leaf_index = 3;
        session.barrier_state.barrier_version = 8;
        session.barrier_state.kem_tree_hash_after = [0xAA; 32];

        let (leaf_ek, leaf_dk) = kyber768::keypair();
        let leaf_ek_bytes = KemPublicKey::as_bytes(&leaf_ek).to_vec();
        session.barrier_state.dk_leaf = Zeroizing::new(KemSecretKey::as_bytes(&leaf_dk).to_vec());
        let target_pkhash = compute_barrier_pkhash(leaf_ek_bytes.as_slice())?;
        session.barrier_state.pkhash_leaf = target_pkhash;

        let revoked_since_root = [0x31; 32];
        let revoked_root = [0x32; 32];
        let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
        session.revoked_since_root = revoked_since_root;
        session.revoked_root = revoked_root;

        let source_node = 4u64;
        let target_node = 10u64;
        let path_secret_source = [0x44; 32];
        let target_pk = kyber768::PublicKey::from_bytes(leaf_ek_bytes.as_slice())?;
        let (ss, ct) = kyber768::encapsulate(&target_pk);
        let aad = to_cbor_vec(&BarrierWrapAadPreimage(
            &session.gid,
            9,
            &rrh,
            3,
            source_node,
            target_node,
            &target_pkhash,
        ))?;
        let nonce_full = h_l(
            "barrier/wrap/nonce",
            &BarrierWrapNoncePreimage(source_node, target_node),
        )?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_full[..12]);
        let cipher = ChaCha20Poly1305::new(ss.as_bytes().into());
        let wrapped_ps = cipher.encrypt(
            (&nonce).into(),
            Payload {
                msg: path_secret_source.as_slice(),
                aad: aad.as_slice(),
            },
        )?;

        let mut target_prefix = [0u8; 16];
        target_prefix.copy_from_slice(&target_pkhash[..16]);
        let node_ciphertexts = vec![NodeCiphertextWire(
            source_node,
            target_node,
            target_prefix.to_vec(),
            KemCiphertext::as_bytes(&ct).to_vec(),
            wrapped_ps,
        )];
        let new_public_keys = vec![
            NewPublicKeyWire(0, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
            NewPublicKeyWire(1, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
            NewPublicKeyWire(4, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
        ];
        let cover = KemTreeCoverPayloadWire(
            3,
            vec![10, 4, 1, 0],
            None,
            node_ciphertexts,
            new_public_keys,
        );
        let cover_bytes = to_cbor_vec(&cover)?;
        let update = BarrierUpdateWire(
            "barrier-v1".to_string(),
            9,
            8,
            8,
            rrh.to_vec(),
            session.barrier_state.kem_tree_hash_after.to_vec(),
            [0xBB; 32].to_vec(),
            cover_bytes,
        );
        let update_bytes = to_cbor_vec(&update)?;

        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(update_bytes));
        header.insert(
            hdr::HDR_REVOKED_SINCE_ROOT,
            Value::Bytes(revoked_since_root.to_vec()),
        );
        header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(1u64)),
        );
        header.insert(hdr::HDR_POP_PK, Value::Bytes(vec![0xEF; 32]));

        session.barrier_state.pkhash_leaf = [0xFF; 32];
        let recovered = try_recover_barrier_from_header(
            &session,
            &header,
            &session.we_epoch_id,
            session.fs_ec,
            DEFAULT_MAX_BARRIER_UPDATE_BYTES as usize,
        )?;
        assert!(
            recovered.is_none(),
            "pkhash mismatch must prevent barrier recovery"
        );
        Ok(())
    }

    #[test]
    fn try_recover_barrier_from_header_rejects_reason_mismatch_for_local_roots()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut session = build_test_session(0xD50, "http://127.0.0.1:9", "room-h", "helen")?;
        session.barrier_state.n_max = 8;
        session.barrier_state.cover_leaf_index = 3;
        session.barrier_state.barrier_version = 4;
        session.barrier_state.kem_tree_hash_after = [0xAA; 32];

        let revoked_since_root = [0x41; 32];
        let revoked_root = [0x42; 32];
        let rrh = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
        let new_public_keys = vec![
            NewPublicKeyWire(0, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
            NewPublicKeyWire(1, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
            NewPublicKeyWire(4, KemPublicKey::as_bytes(&kyber768::keypair().0).to_vec()),
        ];
        let update_bytes = to_cbor_vec(&BarrierUpdateWire(
            "barrier-v1".to_string(),
            5,
            4,
            8,
            rrh.to_vec(),
            session.barrier_state.kem_tree_hash_after.to_vec(),
            [0xBB; 32].to_vec(),
            to_cbor_vec(&KemTreeCoverPayloadWire(
                3,
                vec![10, 4, 1, 0],
                None,
                Vec::new(),
                new_public_keys,
            ))?,
        ))?;

        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(update_bytes));
        header.insert(
            hdr::HDR_REVOKED_SINCE_ROOT,
            Value::Bytes(revoked_since_root.to_vec()),
        );
        header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(1u64)),
        );

        let err = try_recover_barrier_from_header(
            &session,
            &header,
            &session.we_epoch_id,
            session.fs_ec,
            DEFAULT_MAX_BARRIER_UPDATE_BYTES as usize,
        )
        .expect_err("local revocation roots mismatch must reject pcs_refresh reason");
        assert!(
            err.to_string()
                .contains("barrier_update_reason must be revocation_or_bootstrap (0)"),
            "unexpected error for reason mismatch: {err}"
        );
        Ok(())
    }

    struct EnvVarRestore {
        original: Option<String>,
    }

    impl Drop for EnvVarRestore {
        fn drop(&mut self) {
            match self.original.as_deref() {
                Some(value) => {
                    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
                    unsafe { std::env::set_var(SESSION_PASSPHRASE_ENV, value) };
                }
                None => {
                    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
                    unsafe { std::env::remove_var(SESSION_PASSPHRASE_ENV) };
                }
            }
        }
    }

    struct KbroadEnvVarRestore {
        original: Option<String>,
    }

    impl Drop for KbroadEnvVarRestore {
        fn drop(&mut self) {
            match self.original.as_deref() {
                Some(value) => {
                    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
                    unsafe { std::env::set_var(KBROAD_SECRET_ENV, value) };
                }
                None => {
                    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
                    unsafe { std::env::remove_var(KBROAD_SECRET_ENV) };
                }
            }
        }
    }

    struct KbroadPublicEnvVarRestore {
        original: Option<String>,
    }

    impl Drop for KbroadPublicEnvVarRestore {
        fn drop(&mut self) {
            match self.original.as_deref() {
                Some(value) => {
                    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
                    unsafe { std::env::set_var(KBROAD_PUBLIC_ENV, value) };
                }
                None => {
                    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
                    unsafe { std::env::remove_var(KBROAD_PUBLIC_ENV) };
                }
            }
        }
    }

    async fn spawn_server_on(port: u16) -> JoinHandle<()> {
        init_test_auth_env();
        tokio::spawn(async move {
            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            let mut config = CityGConfig::default();
            config.server.seed_demo_room = false;
            if let Err(err) = cityg_api::run_with_config(addr, config).await {
                eprintln!("server exited with error: {err}");
            }
        })
    }

    async fn spawn_server_with_seed_demo_room(port: u16, seed_demo_room: bool) -> JoinHandle<()> {
        init_test_auth_env();
        tokio::spawn(async move {
            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            let mut config = CityGConfig::default();
            config.server.seed_demo_room = seed_demo_room;
            if let Err(err) = cityg_api::run_with_config(addr, config).await {
                eprintln!("server exited with error: {err}");
            }
        })
    }

    async fn bootstrap_test_room(server_url: &str, room_id: &str) -> Result<(), anyhow::Error> {
        new_api_client(server_url)
            .bootstrap_room(room_id, demo::kbroad_public())
            .await
            .map_err(anyhow::Error::from)
    }

    fn test_mouse_down_event() -> MouseDownEvent {
        MouseDownEvent {
            position: point(px(0.0), px(0.0)),
            modifiers: Modifiers::none(),
            button: MouseButton::Left,
            click_count: 1,
            first_mouse: false,
        }
    }

    #[gpui::test]
    fn gpui_render_and_callback_paths_cover_ui_state(cx: &mut TestAppContext) {
        cx.update(tokio_bridge::init);
        let temp_dir = TempDir::new().expect("create temp dir");
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));

        let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
        cx.refresh().expect("initial refresh");
        cx.run_until_parked();

        let session = build_test_session(
            0xC17,
            "http://127.0.0.1:9",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "sab",
        )
        .expect("build test session");

        view.update(cx, |model, _| {
            model.session = Some(session);
            model.messages.push(ChatMessageEntry {
                sender_leaf: Some([0x11; 32]),
                fallback_label: "sab".to_string(),
                plaintext: "hello".to_string(),
                ciphertext_hex: "abcd".to_string(),
                timestamp_ms: 1,
                delivery: MessageDelivery::Sent,
                pending_id: None,
            });
            model.members.push(MemberEntry {
                leaf_id: [0x11; 32],
                alias: Some("sab".to_string()),
                pop_public_key: Some(vec![0x01]),
                join_timestamp_ms: Some(1),
                last_seen_timestamp_ms: Some(2),
            });
            model.members_total = 1;
            model.members_status = MembersStatus::Idle;
            model.security_events.push(SecurityEvent {
                alias: "sab".to_string(),
                description: "security".to_string(),
                timestamp_ms: 11,
            });
            model.security_unread = 1;
            model.activity_events.push(ActivityEvent {
                timestamp_ms: 7,
                kind: ActivityKind::System,
                summary: "boot".to_string(),
                detail: Some("detail".to_string()),
            });
            model.categorized_error = Some(CategorizedError {
                category: ErrorCategory::Network,
                user_message: "network".to_string(),
                technical_details: "connection refused".to_string(),
                recovery_suggestion: "retry".to_string(),
                can_retry: true,
            });
            model.last_retry_action = Some(RetryAction::Join);
        });

        cx.refresh().expect("session refresh");
        cx.run_until_parked();

        cx.update(|window, app| {
            view.update(app, |model, view_cx| {
                let event = test_mouse_down_event();

                model.on_copy_room_id(&event, window, view_cx);
                let copied_room = view_cx
                    .read_from_clipboard()
                    .and_then(|item| item.text())
                    .expect("clipboard room id");
                assert_eq!(
                    copied_room,
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                );

                model.on_copy_regular_fingerprint(&event, window, view_cx);
                let copied_regular = view_cx
                    .read_from_clipboard()
                    .and_then(|item| item.text())
                    .expect("clipboard regular fingerprint");
                assert_eq!(copied_regular.len(), 64);

                model.on_copy_fs_fingerprint(&event, window, view_cx);
                let copied_fs = view_cx
                    .read_from_clipboard()
                    .and_then(|item| item.text())
                    .expect("clipboard fs fingerprint");
                assert_eq!(copied_fs.len(), 64);

                model.on_copy_error_details(&event, window, view_cx);
                model.on_report_issue(&event, window, view_cx);
                model.on_dismiss_error(&event, window, view_cx);
                assert!(model.categorized_error.is_none());

                model.on_generate_room_id(&event, window, view_cx);
                assert_eq!(model.join_form.room_id.len(), 64);

                model.on_toggle_ciphertext(&event, window, view_cx);
                assert!(model.show_ciphertext);

                model.on_security_panel_toggle_clicked(&event, window, view_cx);
                assert!(model.security_panel_expanded);
                assert_eq!(model.security_unread, 0);
                model.on_security_panel_mark_read_clicked(&event, window, view_cx);

                model.on_activity_clear_clicked(&event, window, view_cx);
                assert!(model.activity_events.is_empty());
                model.on_security_log_clear_clicked(&event, window, view_cx);
                assert!(model.security_events.is_empty());

                model.on_reset_clicked(&event, window, view_cx);
                assert!(model.session.is_none());
                model.on_leave_clicked(&event, window, view_cx);
                model.on_copy_room_id(&event, window, view_cx);
                model.on_copy_regular_fingerprint(&event, window, view_cx);
                model.on_copy_fs_fingerprint(&event, window, view_cx);
                model.on_retry_clicked(&event, window, view_cx);
            });
        });

        cx.refresh().expect("post-callback refresh");
        cx.run_until_parked();
    }

    #[gpui::test]
    fn gpui_missing_tokio_global_surfaces_scheduler_failures(cx: &mut TestAppContext) {
        cx.update(tokio_bridge::init);
        init_test_auth_env();
        let temp_dir = TempDir::new().expect("create temp dir");
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));

        let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
        let session = build_test_session(
            0xD00D,
            "http://127.0.0.1:9",
            "8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677",
            "no-tokio",
        )
        .expect("build session");

        view.update(cx, |model, view_cx| {
            model.session = Some(session.clone());
            model.schedule_fetch(view_cx, Duration::ZERO);
            model.start_websocket(view_cx);
            model.start_members_refresh_task(view_cx);
        });

        view.update(cx, |model, _| {
            assert!(model.fetch_task.is_some(), "fetch task should be scheduled");
            assert!(
                model.ws_task.is_some(),
                "websocket task should be scheduled"
            );
            assert!(
                model.members_refresh_task.is_some(),
                "members refresh task should be scheduled"
            );
            assert!(model.fetch_in_flight, "fetch should be marked in-flight");
            assert!(matches!(model.fetch_status, FetchStatus::Refreshing));
        });
    }

    #[gpui::test]
    fn gpui_handle_websocket_event_updates_state(cx: &mut TestAppContext) {
        cx.update(tokio_bridge::init);
        let temp_dir = TempDir::new().expect("create temp dir");
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));

        let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
        let session = build_test_session(
            0xA11CE,
            "http://127.0.0.1:9",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "ws",
        )
        .expect("build session");

        view.update(cx, |model, view_cx| {
            model.session = Some(session.clone());
            model.handle_websocket_event(WebSocketEvent::Connected, view_cx);
            assert!(model.ws_connected);

            model.handle_websocket_event(WebSocketEvent::Message, view_cx);
            assert!(matches!(model.fetch_status, FetchStatus::Refreshing));

            model.handle_websocket_event(
                WebSocketEvent::Membership(MembershipSignal {
                    gid: session.gid,
                    leaf_id: Some(session.leaf_id),
                    kind: Some(MembershipSignalKind::Join),
                    timestamp_ms: Some(42),
                }),
                view_cx,
            );
            assert!(
                model
                    .activity_events
                    .iter()
                    .any(|event| event.summary.contains("Roster join"))
            );

            model.handle_websocket_event(WebSocketEvent::Disconnected, view_cx);
            assert!(!model.ws_connected);
        });
    }

    #[gpui::test]
    fn gpui_render_panels_cover_conditional_branches(cx: &mut TestAppContext) {
        cx.update(tokio_bridge::init);
        let temp_dir = TempDir::new().expect("create temp dir");
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));

        let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
        let session = build_test_session(
            0xBEEF,
            "http://127.0.0.1:9",
            "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
            "render",
        )
        .expect("build session");

        view.update(cx, |model, view_cx| {
            model.session = Some(session);
            model.ws_connected = true;
            model.members = vec![MemberEntry {
                leaf_id: [0x11; 32],
                alias: Some("alice".to_string()),
                pop_public_key: Some(vec![0x01]),
                join_timestamp_ms: Some(1),
                last_seen_timestamp_ms: Some(2),
            }];
            model.members_total = 3;
            model.members_next_offset = Some(1);
            model.members_mode = MembersMode::Search {
                query: "ali".to_string(),
            };
            model.members_search.focus();
            model.members_search.set_query("ali".to_string());
            let _ = model.render_members_panel(view_cx);

            model.security_events = vec![SecurityEvent {
                alias: "alice".to_string(),
                description: "joined".to_string(),
                timestamp_ms: 7,
            }];
            model.security_unread = 1;
            model.security_panel_expanded = true;
            let _ = model.render_security_panel(view_cx);

            model.security_events.clear();
            let _ = model.render_security_panel(view_cx);

            model.security_events = vec![SecurityEvent {
                alias: "bob".to_string(),
                description: "revoked".to_string(),
                timestamp_ms: 9,
            }];
            model.security_panel_expanded = false;
            let _ = model.render_security_panel(view_cx);

            model.activity_events = vec![
                ActivityEvent {
                    timestamp_ms: 1,
                    kind: ActivityKind::Connection,
                    summary: "connected".to_string(),
                    detail: Some("ws".to_string()),
                },
                ActivityEvent {
                    timestamp_ms: 2,
                    kind: ActivityKind::Roster,
                    summary: "roster".to_string(),
                    detail: None,
                },
                ActivityEvent {
                    timestamp_ms: 3,
                    kind: ActivityKind::Message,
                    summary: "message".to_string(),
                    detail: Some("cipher".to_string()),
                },
                ActivityEvent {
                    timestamp_ms: 4,
                    kind: ActivityKind::Sync,
                    summary: "sync".to_string(),
                    detail: None,
                },
                ActivityEvent {
                    timestamp_ms: 5,
                    kind: ActivityKind::System,
                    summary: "system".to_string(),
                    detail: Some("ok".to_string()),
                },
            ];
            let _ = model.render_activity_panel(view_cx);
        });
    }

    #[gpui::test]
    fn gpui_members_refresh_and_search_cover_branch_paths(cx: &mut TestAppContext) {
        cx.update(tokio_bridge::init);
        let temp_dir = TempDir::new().expect("create temp dir");
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));

        let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
        let session = build_test_session(
            0xFACE,
            "http://127.0.0.1:9",
            "33445566778899aabbccddeeff00112233445566778899aabbccddeeff001122",
            "members",
        )
        .expect("build session");

        view.update(cx, |model, view_cx| {
            model.session = Some(session.clone());

            model.members_mode = MembersMode::Full;
            model.members_search.clear();
            model.submit_members_search(view_cx);

            model.members_mode = MembersMode::Search {
                query: "old".to_string(),
            };
            model.members_search.clear();
            model.submit_members_search(view_cx);

            model.members_search.set_query("ali".to_string());
            model.submit_members_search(view_cx);

            model.members_mode = MembersMode::Full;
            model.members_search.set_query("ali".to_string());
            model.clear_members_search(view_cx);

            model.members_mode = MembersMode::Search {
                query: "ali".to_string(),
            };
            model.members_search.set_query("ali".to_string());
            model.clear_members_search(view_cx);

            model.members_status = MembersStatus::Idle;
            model.members_mode = MembersMode::Search {
                query: "ali".to_string(),
            };
            model.refresh_members_soft(view_cx);

            model.members_status = MembersStatus::Loading("busy".to_string());
            model.refresh_members_soft(view_cx);
            model.members_status = MembersStatus::Idle;

            model.members_total = 3;
            model.members_next_offset = Some(1);
            model.load_more_members_with_mode(view_cx, false);
            model.members_next_offset = Some(3);
            model.load_more_members_with_mode(view_cx, true);

            model.members_loading_append = false;
            model.members_mode = MembersMode::Full;
            model.members_alias_dirty = true;
            model.members_auto_page = false;
            model.on_members_refreshed(
                Ok(MembersPage {
                    members: vec![MemberEntry {
                        leaf_id: [0xAA; 32],
                        alias: Some("ali".to_string()),
                        pop_public_key: Some(vec![0x42]),
                        join_timestamp_ms: Some(1),
                        last_seen_timestamp_ms: Some(2),
                    }],
                    root: [0xAA; 32],
                    total_count: 1,
                    next_offset: 1,
                }),
                view_cx,
            );
            assert!(!model.members_alias_dirty);

            model.members_mode = MembersMode::Search {
                query: "ali".to_string(),
            };
            model.members_auto_page = true;
            model.on_members_refreshed(
                Ok(MembersPage {
                    members: vec![MemberEntry {
                        leaf_id: [0xBB; 32],
                        alias: Some("bob".to_string()),
                        pop_public_key: Some(vec![0x24]),
                        join_timestamp_ms: Some(3),
                        last_seen_timestamp_ms: Some(4),
                    }],
                    root: [0xAA; 32],
                    total_count: 2,
                    next_offset: 1,
                }),
                view_cx,
            );
        });
    }

    #[gpui::test]
    fn gpui_callback_and_shortcut_branches_cover_edge_paths(cx: &mut TestAppContext) {
        cx.update(tokio_bridge::init);
        let temp_dir = TempDir::new().expect("create temp dir");
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));

        let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
        let session = build_test_session(
            0x7E57,
            "http://127.0.0.1:9",
            "5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344",
            "edges",
        )
        .expect("build session");

        let session_path =
            session_file_path(&session.server_url, &session.room_id).expect("session path");
        fs::create_dir_all(&session_path).expect("create blocking session path");

        cx.update(|window, app| {
            view.update(app, |model, view_cx| {
                let event = test_mouse_down_event();
                model.session = Some(session.clone());

                model.last_error = Some("join-fallback".to_string());
                model.categorized_error = None;
                model.info_message = Some("join-info".to_string());
                let _ = model.render_join(view_cx);

                let mut session_for_render = session.clone();
                session_for_render.regular_fingerprint = None;
                session_for_render.fs_fingerprint = None;
                model.last_error = Some("session-fallback".to_string());
                let _ = model.render_session(window, &session_for_render, view_cx);
                model.session = Some(session_for_render.clone());
                model.on_copy_regular_fingerprint(&event, window, view_cx);
                model.on_copy_fs_fingerprint(&event, window, view_cx);
                assert!(
                    model
                        .toasts
                        .iter()
                        .any(|toast| toast.message.contains("fingerprint unavailable"))
                );
                model.session = Some(session.clone());

                model.focus_field(ActiveField::Alias, view_cx);
                assert!(matches!(model.join_form.active, Some(ActiveField::Alias)));

                model.categorized_error = Some(CategorizedError {
                    category: ErrorCategory::Server,
                    user_message: "err".to_string(),
                    technical_details: "detail".to_string(),
                    recovery_suggestion: "retry".to_string(),
                    can_retry: true,
                });
                model.on_report_issue(&event, window, view_cx);

                model.join_form.active = Some(ActiveField::Alias);
                model.join_form.alias = "ab".to_string();
                view_cx.write_to_clipboard(ClipboardItem::new_string("c".to_string()));
                let paste = Keystroke::parse("cmd-v").expect("parse cmd-v");
                assert!(matches!(
                    model.handle_join_form_clipboard_shortcuts(&paste, view_cx),
                    KeyOutcome::Updated
                ));

                model.composer.focus();
                model.composer.set_text("pre".to_string());
                view_cx.write_to_clipboard(ClipboardItem::new_string("\npost".to_string()));
                assert!(matches!(
                    model.handle_composer_clipboard_shortcuts(&paste, view_cx),
                    KeyOutcome::Updated
                ));
                assert_eq!(model.composer.text(), "pre post");

                model.members_search.focus();
                model.members_search.set_query("xy".to_string());
                let copy = Keystroke::parse("cmd-c").expect("parse cmd-c");
                let cut = Keystroke::parse("cmd-x").expect("parse cmd-x");
                assert!(matches!(
                    model.handle_members_search_clipboard_shortcuts(&copy, view_cx),
                    KeyOutcome::Updated
                ));
                assert!(matches!(
                    model.handle_members_search_clipboard_shortcuts(&cut, view_cx),
                    KeyOutcome::Updated
                ));
                view_cx.write_to_clipboard(ClipboardItem::new_string("zz".to_string()));
                assert!(matches!(
                    model.handle_members_search_clipboard_shortcuts(&paste, view_cx),
                    KeyOutcome::Updated
                ));

                model.join_status = JoinStatus::Joining;
                model.start_join(view_cx);
                model.join_status = JoinStatus::Idle;
                model.join_form.room_id.clear();
                model.start_join(view_cx);

                model.session = None;
                model.start_send(view_cx);
                model.session = Some(session.clone());
                model.composer.clear();
                model.start_send(view_cx);
                model.composer.set_text("hello".to_string());
                model.send_status = SendStatus::Sending;
                model.start_send(view_cx);
                model.send_status = SendStatus::Idle;
                model.composer.set_text("   ".to_string());
                model.start_send(view_cx);

                model.security_events.clear();
                model.security_unread = 0;
                model.session = Some(session.clone());
                for index in 0..(MAX_SECURITY_EVENTS + 2) {
                    model.record_security_event("sab", format!("evt {index}"), view_cx);
                }
                assert_eq!(model.security_events.len(), MAX_SECURITY_EVENTS);
                assert!(model.security_unread > 0);

                model.session = None;
                model.fetch_in_flight = true;
                model.fetch_status = FetchStatus::Refreshing;
                model.ensure_fetch_loop(view_cx);
                assert!(matches!(model.fetch_status, FetchStatus::Idle));
                model.schedule_fetch(view_cx, Duration::ZERO);

                model.session = Some(session.clone());
                model.ensure_fetch_loop(view_cx);
                model.schedule_fetch(view_cx, Duration::from_millis(1));

                model.epoch_sync_task = Some(view_cx.spawn(async move |_, _| {}));
                model.session = None;
                model.ensure_epoch_sync_task(view_cx);
                assert!(model.epoch_sync_task.is_none());

                model.session = Some(session.clone());
                model.fetch_in_flight = false;
                model.handle_fetch_result(
                    Ok(FetchOutcome {
                        messages: vec![ChatMessageEntry {
                            sender_leaf: Some(session.leaf_id),
                            fallback_label: session.alias.clone(),
                            plaintext: "ignored".to_string(),
                            ciphertext_hex: String::new(),
                            timestamp_ms: 1,
                            delivery: MessageDelivery::Sent,
                            pending_id: None,
                        }],
                        last_timestamp_ms: Some(99),
                        msg_replay_state: MsgReplayState::default(),
                    }),
                    session.we_epoch_id,
                    view_cx,
                );
                model.handle_fetch_result(
                    Err(anyhow::anyhow!("404 not found resource not found")),
                    session.we_epoch_id,
                    view_cx,
                );

                model.last_retry_action = Some(RetryAction::Leave);
                model.session = Some(session.clone());
                model.on_retry_clicked(&event, window, view_cx);
                assert!(matches!(model.leave_status, LeaveStatus::Leaving));

                model.leave_status = LeaveStatus::Leaving;
                model.on_leave_clicked(&event, window, view_cx);

                model.session = Some(session.clone());
                let pending_id = model.queue_pending_message(&session, "queued");
                model.fetch_in_flight = false;
                model.on_send_finished(
                    Ok(ChatMessageEntry {
                        sender_leaf: Some(session.leaf_id),
                        fallback_label: session.alias.clone(),
                        plaintext: "sent".to_string(),
                        ciphertext_hex: "aa".to_string(),
                        timestamp_ms: 555,
                        delivery: MessageDelivery::Sent,
                        pending_id: None,
                    }),
                    pending_id,
                    view_cx,
                );
                model.on_send_finished(
                    Err(anyhow::anyhow!("404 not found resource not found")),
                    pending_id.saturating_add(1),
                    view_cx,
                );
            });
        });

        cx.run_until_parked();
    }

    #[gpui::test]
    fn gpui_on_leave_finished_surfaces_session_cleanup_error(cx: &mut TestAppContext) {
        cx.update(tokio_bridge::init);
        let temp_dir = TempDir::new().expect("create temp dir");
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));

        let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
        let session = build_test_session(
            0xBADD,
            "http://127.0.0.1:18080",
            "99aabbccddeeff00112233445566778899aabbccddeeff001122334455667788",
            "leave-err",
        )
        .expect("build session");
        let blocking_path =
            session_file_path(&session.server_url, &session.room_id).expect("session path");
        fs::create_dir_all(&blocking_path).expect("create blocking path");

        view.update(cx, |model, view_cx| {
            model.session = Some(session.clone());
            model.on_leave_finished(Ok(()), view_cx);
            assert!(
                model
                    .last_error
                    .as_deref()
                    .unwrap_or_default()
                    .contains("failed to remove session data")
            );
        });
    }

    #[gpui::test]
    fn gpui_keystroke_routing_covers_clipboard_shortcuts(cx: &mut TestAppContext) {
        cx.update(tokio_bridge::init);
        let temp_dir = TempDir::new().expect("create temp dir");
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));

        let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));

        cx.write_to_clipboard(ClipboardItem::new_string("http://demo".to_string()));
        view.update(cx, |model, view_cx| {
            model.join_form.server.clear();
            model.join_form.room_id.clear();
            model.join_form.alias = "sab".to_string();
            model.join_form.active = Some(ActiveField::Server);
            model.on_keystroke(&Keystroke::parse("cmd-v").expect("parse cmd-v"), view_cx);
            assert_eq!(model.join_form.server, "http://demo");

            model.on_keystroke(&Keystroke::parse("cmd-c").expect("parse cmd-c"), view_cx);
            let copied = view_cx
                .read_from_clipboard()
                .and_then(|item| item.text())
                .expect("clipboard join field");
            assert_eq!(copied, "http://demo");

            model.on_keystroke(&Keystroke::parse("cmd-x").expect("parse cmd-x"), view_cx);
            assert!(model.join_form.server.is_empty());

            model.join_status = JoinStatus::Joining;
            model.join_form.alias = "keep".to_string();
            model.on_keystroke(&Keystroke::parse("x->z").expect("parse x"), view_cx);
            assert_eq!(model.join_form.alias, "keep");
            model.join_status = JoinStatus::Idle;
            model.join_form.active = Some(ActiveField::Alias);
            model.on_keystroke(&Keystroke::parse("ctrl-a").expect("parse ctrl-a"), view_cx);
            model.on_keystroke(&Keystroke::parse("x->q").expect("parse x->q"), view_cx);
        });

        let session = build_test_session(
            0x77,
            "http://127.0.0.1:9",
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            "goy",
        )
        .expect("build test session");
        cx.write_to_clipboard(ClipboardItem::new_string("\nxyz".to_string()));
        view.update(cx, |model, view_cx| {
            model.session = Some(session);

            model.members_search.focus();
            model.members_search.set_query("ab".to_string());
            model.on_keystroke(&Keystroke::parse("cmd-v").expect("parse cmd-v"), view_cx);
            assert_eq!(model.members_search.query(), "ab xyz");
            model.on_keystroke(&Keystroke::parse("x->d").expect("parse x->d"), view_cx);
            model.on_keystroke(&Keystroke::parse("ctrl-a").expect("parse ctrl-a"), view_cx);
            model.on_keystroke(&Keystroke::parse("enter").expect("parse enter"), view_cx);

            model.on_keystroke(&Keystroke::parse("cmd-x").expect("parse cmd-x"), view_cx);
            assert!(model.members_search.query().is_empty());

            model.members_search.blur();
            model.composer.focus();
            model.composer.set_text("hello".to_string());
            model.on_keystroke(&Keystroke::parse("x->r").expect("parse x->r"), view_cx);
            model.on_keystroke(&Keystroke::parse("ctrl-a").expect("parse ctrl-a"), view_cx);
            model.on_keystroke(&Keystroke::parse("cmd-c").expect("parse cmd-c"), view_cx);
            let copied = view_cx
                .read_from_clipboard()
                .and_then(|item| item.text())
                .expect("clipboard composer");
            assert_eq!(copied, "hellor");

            model.on_keystroke(&Keystroke::parse("cmd-x").expect("parse cmd-x"), view_cx);
            assert!(model.composer.text().is_empty());
            model.composer.set_text("ok".to_string());
            model.on_keystroke(&Keystroke::parse("enter").expect("parse enter"), view_cx);
        });

        cx.update(|window, app| {
            view.update(app, |model, view_cx| {
                let event = test_mouse_down_event();
                model.composer.set_text(String::new());
                model.on_send_clicked(&event, window, view_cx);
                model.on_composer_clicked(&event, window, view_cx);
                model.on_join_clicked(&event, window, view_cx);
                model.on_members_search_field_clicked(&event, window, view_cx);
                model.on_members_search_button_clicked(&event, window, view_cx);
                model.on_members_search_clear_clicked(&event, window, view_cx);
                model.on_members_refresh_clicked(&event, window, view_cx);
                model.on_members_load_more_clicked(&event, window, view_cx);
            });
        });
    }

    #[gpui::test]
    fn gpui_async_handler_paths_cover_state_machine(cx: &mut TestAppContext) {
        cx.update(tokio_bridge::init);
        let temp_dir = TempDir::new().expect("create temp dir");
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));

        let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
        cx.refresh().expect("initial refresh");
        cx.run_until_parked();

        let session = build_test_session(
            0xA11CE,
            "http://127.0.0.1:9",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "async",
        )
        .expect("build test session");

        cx.update(|window, app| {
            view.update(app, |model, view_cx| {
                let event = test_mouse_down_event();

                model.join_form.server = "http://127.0.0.1:9".to_string();
                model.join_form.room_id =
                    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string();
                model.join_form.alias = "async".to_string();
                model.start_join(view_cx);
                assert!(matches!(model.join_status, JoinStatus::Joining));

                model.on_join_finished(Err(anyhow::anyhow!("join failed")), view_cx);
                assert!(matches!(model.join_status, JoinStatus::Idle));

                model.on_join_finished(Ok(session.clone()), view_cx);
                assert!(model.session.is_some());

                model.composer.set_text("hello".to_string());
                model.start_send(view_cx);
                assert!(matches!(model.send_status, SendStatus::Sending));
                let pending_id = model.next_pending_message_id.saturating_sub(1);
                model.on_send_finished(
                    Ok(ChatMessageEntry {
                        sender_leaf: Some(session.leaf_id),
                        fallback_label: session.alias.clone(),
                        plaintext: "hello".to_string(),
                        ciphertext_hex: "abcd".to_string(),
                        timestamp_ms: 42,
                        delivery: MessageDelivery::Sent,
                        pending_id: None,
                    }),
                    pending_id,
                    view_cx,
                );
                model.on_send_finished(
                    Err(anyhow::anyhow!("send failed")),
                    pending_id.saturating_add(10),
                    view_cx,
                );

                let expected_weid = session.we_epoch_id;
                model.handle_fetch_result(
                    Ok(FetchOutcome {
                        messages: vec![ChatMessageEntry {
                            sender_leaf: Some(session.leaf_id),
                            fallback_label: session.alias.clone(),
                            plaintext: "synced".to_string(),
                            ciphertext_hex: "beef".to_string(),
                            timestamp_ms: 100,
                            delivery: MessageDelivery::Sent,
                            pending_id: None,
                        }],
                        last_timestamp_ms: Some(100),
                        msg_replay_state: MsgReplayState::default(),
                    }),
                    expected_weid,
                    view_cx,
                );
                model.handle_fetch_result(
                    Err(anyhow::anyhow!("fetch failed")),
                    expected_weid,
                    view_cx,
                );
                model.handle_fetch_result(
                    Ok(FetchOutcome {
                        messages: vec![],
                        last_timestamp_ms: None,
                        msg_replay_state: MsgReplayState::default(),
                    }),
                    [0xFF; 32],
                    view_cx,
                );

                model.on_members_refreshed(
                    Ok(MembersPage {
                        members: vec![MemberEntry {
                            leaf_id: session.leaf_id,
                            alias: Some(session.alias.clone()),
                            pop_public_key: Some(vec![0x01]),
                            join_timestamp_ms: Some(10),
                            last_seen_timestamp_ms: Some(11),
                        }],
                        root: session.parent_root,
                        total_count: 1,
                        next_offset: 1,
                    }),
                    view_cx,
                );
                model.on_members_refreshed(Err(anyhow::anyhow!("members failed")), view_cx);

                model.handle_epoch_sync_result(
                    Ok(EpochSyncOutcome {
                        session: session.clone(),
                        changed: false,
                    }),
                    &session.server_url,
                    &session.room_id,
                    session.leaf_id,
                    "noop",
                    view_cx,
                );
                let mut changed_session = session.clone();
                changed_session.we_epoch_id = [0x55; 32];
                model.handle_epoch_sync_result(
                    Ok(EpochSyncOutcome {
                        session: changed_session,
                        changed: true,
                    }),
                    &session.server_url,
                    &session.room_id,
                    session.leaf_id,
                    "changed",
                    view_cx,
                );
                model.handle_epoch_sync_result(
                    Err(anyhow::anyhow!("sync failed")),
                    &session.server_url,
                    &session.room_id,
                    session.leaf_id,
                    "err",
                    view_cx,
                );

                model.handle_stale_server_session("stale", view_cx);
                assert!(model.session.is_none());

                model.session = Some(session.clone());
                model.on_leave_clicked(&event, window, view_cx);
                assert!(matches!(model.leave_status, LeaveStatus::Leaving));
                model.on_leave_finished(Err(anyhow::anyhow!("leave failed")), view_cx);
                model.on_leave_finished(Ok(()), view_cx);
            });
        });

        cx.refresh().expect("post async state refresh");
        cx.run_until_parked();
    }

    #[test]
    fn session_encryption_key_prefers_env_passphrase() -> Result<(), Box<dyn std::error::Error>> {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let _restore = EnvVarRestore {
            original: std::env::var(SESSION_PASSPHRASE_ENV).ok(),
        };

        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::set_var(SESSION_PASSPHRASE_ENV, "cityg-test-passphrase") };

        let temp_dir = TempDir::new()?;
        let session_path = temp_dir
            .path()
            .join("cityg")
            .join("gui")
            .join("session.json");
        let (key, source) = session_encryption_key(&session_path)?;

        assert_eq!(source.as_str(), SessionKeySource::EnvPassphrase.as_str());
        assert_eq!(
            key,
            blake3::derive_key(SESSION_KEY_DERIVE_CONTEXT, b"cityg-test-passphrase")
        );
        assert!(
            !session_local_key_path(&session_path)?.exists(),
            "env-derived key path must not create local key file"
        );
        Ok(())
    }

    #[test]
    fn configured_kbroad_secret_env_parses_prefixed_hex() -> Result<(), Box<dyn std::error::Error>>
    {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let _restore = KbroadEnvVarRestore {
            original: std::env::var(KBROAD_SECRET_ENV).ok(),
        };

        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::set_var(KBROAD_SECRET_ENV, " 0x0a0B0c ") };

        let parsed = configured_kbroad_secret_from_env()?
            .ok_or_else(|| anyhow!("expected configured secret bytes"))?;
        assert_eq!(parsed, vec![0x0a, 0x0b, 0x0c]);
        Ok(())
    }

    #[test]
    fn configured_kbroad_secret_env_rejects_bad_hex() -> Result<(), Box<dyn std::error::Error>> {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let _restore = KbroadEnvVarRestore {
            original: std::env::var(KBROAD_SECRET_ENV).ok(),
        };

        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::set_var(KBROAD_SECRET_ENV, "not-hex") };

        let err = configured_kbroad_secret_from_env().expect_err("invalid hex should fail");
        assert!(
            err.to_string().contains(KBROAD_SECRET_ENV),
            "error should reference env var: {err}"
        );
        Ok(())
    }

    #[test]
    fn session_encryption_key_uses_local_key_file_when_env_missing()
    -> Result<(), Box<dyn std::error::Error>> {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let _restore = EnvVarRestore {
            original: std::env::var(SESSION_PASSPHRASE_ENV).ok(),
        };

        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(SESSION_PASSPHRASE_ENV) };

        let temp_dir = TempDir::new()?;
        let session_path = temp_dir
            .path()
            .join("cityg")
            .join("gui")
            .join("session.json");

        let (first_key, first_source) = session_encryption_key(&session_path)?;
        assert_eq!(
            first_source.as_str(),
            SessionKeySource::LocalKeyFile.as_str(),
            "missing env passphrase should use local key file"
        );
        let key_path = session_local_key_path(&session_path)?;
        assert!(key_path.exists(), "local key file should be created");
        assert_eq!(fs::read(&key_path)?.len(), 32, "local key must be 32 bytes");

        let (second_key, second_source) = session_encryption_key(&session_path)?;
        assert_eq!(
            second_source.as_str(),
            SessionKeySource::LocalKeyFile.as_str()
        );
        assert_eq!(
            first_key, second_key,
            "local key should be stable across reads"
        );
        Ok(())
    }

    #[test]
    fn load_or_create_local_session_key_rejects_invalid_file_len()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let session_path = temp_dir
            .path()
            .join("cityg")
            .join("gui")
            .join("session.json");
        let key_path = session_local_key_path(&session_path)?;
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&key_path, vec![0xAB; 31])?;

        let err = load_or_create_local_session_key(&session_path)
            .expect_err("invalid key length should fail");
        assert!(
            err.to_string()
                .contains("session local key must be 32 bytes"),
            "unexpected error: {err}"
        );
        Ok(())
    }

    #[test]
    fn read_last_session_pointer_missing_invalid_and_valid()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));

        assert!(
            read_last_session_pointer()?.is_none(),
            "missing pointer => None"
        );

        let pointer_path = last_session_pointer_path()?;
        if let Some(parent) = pointer_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&pointer_path, b"{not-json")?;
        assert!(
            read_last_session_pointer().is_err(),
            "invalid pointer JSON should error"
        );

        let pointer = LastSessionPointer {
            server_url: "http://127.0.0.1:8080".to_string(),
            room_id: "room-a".to_string(),
        };
        fs::write(&pointer_path, serde_json::to_vec(&pointer)?)?;
        let loaded = read_last_session_pointer()?
            .ok_or_else(|| anyhow!("expected valid pointer to be loaded"))?;
        assert_eq!(loaded.server_url, pointer.server_url);
        assert_eq!(loaded.room_id, pointer.room_id);
        Ok(())
    }

    #[test]
    fn session_dir_respects_cityg_gui_config_dir_env() -> Result<(), Box<dyn std::error::Error>> {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let _config_guard = set_config_dir_override_for_tests(None);

        let original = std::env::var("CITYG_GUI_CONFIG_DIR").ok();
        let override_root = TempDir::new()?;
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe {
            std::env::set_var(
                "CITYG_GUI_CONFIG_DIR",
                override_root.path().to_string_lossy().to_string(),
            )
        };

        let resolved = session_dir()?;
        assert_eq!(
            resolved,
            override_root.path().join("cityg").join("gui"),
            "session dir should respect CITYG_GUI_CONFIG_DIR override"
        );

        match original {
            Some(value) => {
                // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
                unsafe { std::env::set_var("CITYG_GUI_CONFIG_DIR", value) };
            }
            None => {
                // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
                unsafe { std::env::remove_var("CITYG_GUI_CONFIG_DIR") };
            }
        }
        Ok(())
    }

    #[test]
    fn session_dir_falls_back_to_user_config_directory() -> Result<(), Box<dyn std::error::Error>> {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let _config_guard = set_config_dir_override_for_tests(None);

        let original = std::env::var("CITYG_GUI_CONFIG_DIR").ok();
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var("CITYG_GUI_CONFIG_DIR") };

        let resolved = session_dir()?;
        assert!(
            resolved.ends_with("cityg/gui"),
            "fallback session dir should include cityg/gui suffix: {}",
            resolved.display()
        );

        match original {
            Some(value) => {
                // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
                unsafe { std::env::set_var("CITYG_GUI_CONFIG_DIR", value) };
            }
            None => {
                // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
                unsafe { std::env::remove_var("CITYG_GUI_CONFIG_DIR") };
            }
        }
        Ok(())
    }

    #[test]
    fn load_last_session_removes_dangling_pointer() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));

        let pointer = LastSessionPointer {
            server_url: "http://127.0.0.1:8080".to_string(),
            room_id: "missing-room".to_string(),
        };
        let pointer_path = last_session_pointer_path()?;
        if let Some(parent) = pointer_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&pointer_path, serde_json::to_vec(&pointer)?)?;

        let session = load_last_session()?;
        assert!(
            session.is_none(),
            "dangling pointer should return no session"
        );
        assert!(
            !pointer_path.exists(),
            "dangling pointer should be removed automatically"
        );
        Ok(())
    }

    #[test]
    fn load_last_session_invalid_pointer_json_errors() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));

        let pointer_path = last_session_pointer_path()?;
        if let Some(parent) = pointer_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&pointer_path, b"not-json")?;
        assert!(
            load_last_session().is_err(),
            "invalid pointer JSON should produce an error"
        );
        Ok(())
    }

    #[test]
    fn remove_persisted_session_keeps_unrelated_pointer() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));

        let pointer = LastSessionPointer {
            server_url: "http://127.0.0.1:8080".to_string(),
            room_id: "room-a".to_string(),
        };
        let pointer_path = last_session_pointer_path()?;
        if let Some(parent) = pointer_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&pointer_path, serde_json::to_vec(&pointer)?)?;

        remove_persisted_session("http://127.0.0.1:8080", "room-b")?;
        assert!(
            pointer_path.exists(),
            "pointer should remain when removing unrelated session"
        );
        let loaded = read_last_session_pointer()?
            .ok_or_else(|| anyhow!("expected pointer to remain present"))?;
        assert_eq!(loaded.server_url, pointer.server_url);
        assert_eq!(loaded.room_id, pointer.room_id);
        Ok(())
    }

    #[test]
    fn reset_session_state_uses_pointer_and_handles_security_log_remove_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));

        let pointer = LastSessionPointer {
            server_url: "http://127.0.0.1:8080".to_string(),
            room_id: "room-reset".to_string(),
        };
        let pointer_path = last_session_pointer_path()?;
        if let Some(parent) = pointer_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&pointer_path, serde_json::to_vec(&pointer)?)?;

        // Force remove_security_log to fail with "is a directory".
        let log_path = security_log_file_path(&pointer.server_url, &pointer.room_id)?;
        fs::create_dir_all(&log_path)?;

        let mut model = AppModel::new(CityGConfig::default());
        model.reset_session_state()?;
        assert!(model.session.is_none());
        assert!(model.members.is_empty());
        assert!(model.security_events.is_empty());
        Ok(())
    }

    #[test]
    fn reset_session_state_without_session_or_pointer_is_ok()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));
        let mut model = AppModel::new(CityGConfig::default());
        model.reset_session_state()?;
        assert!(model.session.is_none());
        Ok(())
    }

    #[test]
    fn alias_bindings_persist_load_legacy_and_cleanup() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));
        let server = "http://127.0.0.1:8080";
        let room = "room-alias";

        let mut bindings = AHashMap::new();
        bindings.insert(
            "alice".to_string(),
            AliasBindingRecord {
                pop_public_key: vec![0x01, 0x02, 0x03],
                leaf_id: [0xAA; 32],
            },
        );
        persist_alias_bindings(server, room, &bindings)?;

        let loaded = load_alias_bindings(server, room)?;
        let alice = loaded
            .get("alice")
            .ok_or_else(|| anyhow!("alice binding missing"))?;
        assert_eq!(alice.pop_public_key, vec![0x01, 0x02, 0x03]);
        assert_eq!(alice.leaf_id, [0xAA; 32]);

        let roster_path = roster_file_path(server, room)?;
        let legacy: AHashMap<String, String> = [("bob".to_string(), "0a0b".to_string())]
            .into_iter()
            .collect();
        fs::write(&roster_path, serde_json::to_vec(&legacy)?)?;
        let legacy_loaded = load_alias_bindings(server, room)?;
        let bob = legacy_loaded
            .get("bob")
            .ok_or_else(|| anyhow!("legacy bob binding missing"))?;
        assert_eq!(bob.pop_public_key, vec![0x0A, 0x0B]);
        assert_eq!(bob.leaf_id, [0u8; 32], "legacy format has zero leaf id");

        let invalid_store = PersistedAliasStore {
            version: ALIAS_STORE_VERSION,
            bindings: [
                (
                    "bad_pop".to_string(),
                    PersistedAliasBinding {
                        pop_public_key_hex: "zzzz".to_string(),
                        leaf_id_hex: hex_encode([0x11; 32]),
                    },
                ),
                (
                    "bad_leaf".to_string(),
                    PersistedAliasBinding {
                        pop_public_key_hex: "aa".to_string(),
                        leaf_id_hex: "not-hex".to_string(),
                    },
                ),
                (
                    "empty_pop".to_string(),
                    PersistedAliasBinding {
                        pop_public_key_hex: String::new(),
                        leaf_id_hex: hex_encode([0x22; 32]),
                    },
                ),
            ]
            .into_iter()
            .collect(),
        };
        fs::write(&roster_path, serde_json::to_vec(&invalid_store)?)?;
        let invalid_loaded = load_alias_bindings(server, room)?;
        assert!(
            !invalid_loaded.contains_key("bad_pop"),
            "invalid pop key entry should be skipped"
        );
        let bad_leaf = invalid_loaded
            .get("bad_leaf")
            .ok_or_else(|| anyhow!("bad_leaf binding should remain with zeroed leaf id"))?;
        assert_eq!(bad_leaf.pop_public_key, vec![0xAA]);
        assert_eq!(bad_leaf.leaf_id, [0u8; 32]);
        assert!(
            !invalid_loaded.contains_key("empty_pop"),
            "entries with empty pop keys should be skipped"
        );

        persist_alias_bindings(server, room, &AHashMap::new())?;
        assert!(
            !roster_path.exists(),
            "empty bindings should remove roster file"
        );
        Ok(())
    }

    #[test]
    fn load_alias_bindings_invalid_json_errors() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));
        let server = "http://127.0.0.1:8080";
        let room = "room-alias-invalid";
        let roster_path = roster_file_path(server, room)?;
        if let Some(parent) = roster_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&roster_path, b"not-json")?;
        assert!(
            load_alias_bindings(server, room).is_err(),
            "invalid alias store JSON should error"
        );
        Ok(())
    }

    #[test]
    fn security_log_persist_load_and_remove() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));
        let server = "http://127.0.0.1:8080";
        let room = "room-sec";

        assert!(
            load_security_log(server, room)?.is_empty(),
            "missing security log should return empty vec"
        );

        let events = vec![
            SecurityEvent {
                alias: "alice".to_string(),
                description: "joined".to_string(),
                timestamp_ms: 1,
            },
            SecurityEvent {
                alias: "bob".to_string(),
                description: "revoked".to_string(),
                timestamp_ms: 2,
            },
        ];
        persist_security_log(server, room, &events)?;
        let loaded = load_security_log(server, room)?;
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].alias, "alice");
        assert_eq!(loaded[1].description, "revoked");

        let log_path = security_log_file_path(server, room)?;
        assert!(
            log_path.exists(),
            "security log file should exist after persist"
        );

        persist_security_log(server, room, &[])?;
        assert!(!log_path.exists(), "empty security log should remove file");

        persist_security_log(server, room, &events)?;
        remove_security_log(server, room)?;
        assert!(!log_path.exists(), "remove_security_log should delete file");
        Ok(())
    }

    #[test]
    fn load_security_events_from_disk_handles_invalid_and_missing_session()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));
        let mut model = AppModel::new(CityGConfig::default());

        let session = build_test_session(
            0x5151,
            "http://127.0.0.1:18080",
            "feedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeed",
            "security",
        )?;
        let log_path = security_log_file_path(&session.server_url, &session.room_id)?;
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&log_path, b"not-json")?;

        model.session = Some(session);
        model.security_events = vec![SecurityEvent {
            alias: "seed".to_string(),
            description: "stale".to_string(),
            timestamp_ms: 1,
        }];
        model.security_unread = 7;
        model.security_panel_expanded = true;
        model.load_security_events_from_disk();
        assert!(model.security_events.is_empty());
        assert_eq!(model.security_unread, 0);
        assert!(!model.security_panel_expanded);

        model.session = None;
        model.security_events = vec![SecurityEvent {
            alias: "seed".to_string(),
            description: "stale".to_string(),
            timestamp_ms: 2,
        }];
        model.security_unread = 3;
        model.security_panel_expanded = true;
        model.load_security_events_from_disk();
        assert!(model.security_events.is_empty());
        assert_eq!(model.security_unread, 0);
        assert!(!model.security_panel_expanded);
        Ok(())
    }

    #[test]
    fn hydrate_alias_bindings_from_disk_handles_invalid_and_missing_session()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));
        let mut model = AppModel::new(CityGConfig::default());

        let session = build_test_session(
            0x5152,
            "http://127.0.0.1:18080",
            "deafdeafdeafdeafdeafdeafdeafdeafdeafdeafdeafdeafdeafdeafdeafdeaf",
            "aliases",
        )?;
        let bindings_path = roster_file_path(&session.server_url, &session.room_id)?;
        if let Some(parent) = bindings_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&bindings_path, b"not-json")?;

        model.session = Some(session);
        model.alias_bindings.insert(
            "seed".to_string(),
            AliasBindingRecord {
                pop_public_key: vec![0xAA],
                leaf_id: [0x11; 32],
            },
        );
        model
            .leaf_alias_index
            .insert([0x11; 32], "seed".to_string());
        model.hydrate_alias_bindings_from_disk();
        assert!(model.alias_bindings.is_empty());
        assert!(model.leaf_alias_index.is_empty());

        model.session = None;
        model.alias_bindings.insert(
            "stale".to_string(),
            AliasBindingRecord {
                pop_public_key: vec![0xBB],
                leaf_id: [0x22; 32],
            },
        );
        model
            .leaf_alias_index
            .insert([0x22; 32], "stale".to_string());
        model.hydrate_alias_bindings_from_disk();
        assert!(model.alias_bindings.is_empty());
        assert!(model.leaf_alias_index.is_empty());
        Ok(())
    }

    #[gpui::test]
    fn gpui_reconcile_alias_bindings_covers_mismatch_and_early_return(cx: &mut TestAppContext) {
        cx.update(tokio_bridge::init);
        let temp_dir = TempDir::new().expect("create temp dir");
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));
        let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
        let session = build_test_session(
            0xABCD,
            "http://127.0.0.1:18080",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sab",
        )
        .expect("build session");

        view.update(cx, |model, view_cx| {
            model.session = None;
            model.alias_bindings.insert(
                "keep".to_string(),
                AliasBindingRecord {
                    pop_public_key: vec![0x01],
                    leaf_id: [0x01; 32],
                },
            );
            model.reconcile_alias_bindings(view_cx);
            assert!(
                model.alias_bindings.contains_key("keep"),
                "early return without session should keep existing bindings"
            );
        });

        view.update(cx, |model, view_cx| {
            model.session = Some(session.clone());
            model.alias_bindings.insert(
                "sab".to_string(),
                AliasBindingRecord {
                    pop_public_key: vec![0xAA],
                    leaf_id: [0x10; 32],
                },
            );
            model.members = vec![
                MemberEntry {
                    leaf_id: [0x20; 32],
                    alias: Some("sab".to_string()),
                    pop_public_key: Some(vec![0xBB]),
                    join_timestamp_ms: Some(1),
                    last_seen_timestamp_ms: Some(2),
                },
                MemberEntry {
                    leaf_id: [0x21; 32],
                    alias: None,
                    pop_public_key: Some(vec![0xCC]),
                    join_timestamp_ms: None,
                    last_seen_timestamp_ms: None,
                },
                MemberEntry {
                    leaf_id: [0x22; 32],
                    alias: Some(String::new()),
                    pop_public_key: Some(vec![0xDD]),
                    join_timestamp_ms: None,
                    last_seen_timestamp_ms: None,
                },
                MemberEntry {
                    leaf_id: [0x23; 32],
                    alias: Some("dock".to_string()),
                    pop_public_key: None,
                    join_timestamp_ms: None,
                    last_seen_timestamp_ms: None,
                },
            ];

            model.reconcile_alias_bindings(view_cx);

            let updated = model.alias_bindings.get("sab").expect("alias updated");
            assert_eq!(updated.pop_public_key, vec![0xBB]);
            assert_eq!(updated.leaf_id, [0x20; 32]);
            assert_eq!(
                model.leaf_alias_index.get(&[0x20; 32]).map(String::as_str),
                Some("sab")
            );
            assert_eq!(model.security_events.len(), 1);
            assert!(
                model.security_events[0].description.contains("TOFU alert"),
                "TOFU mismatch should record a security event"
            );
            assert!(
                !model.toasts.is_empty(),
                "TOFU mismatch should show a toast"
            );
        });
    }

    #[gpui::test]
    fn gpui_reconcile_alias_bindings_handles_persist_failure(cx: &mut TestAppContext) {
        cx.update(tokio_bridge::init);
        let temp_dir = TempDir::new().expect("create temp dir");
        let base_file = temp_dir.path().join("not-a-directory");
        fs::write(&base_file, b"blocking dir").expect("create blocking file");
        let _override_guard = set_config_dir_override_for_tests(Some(base_file));
        let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
        let session = build_test_session(
            0xABCE,
            "http://127.0.0.1:18080",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "dock",
        )
        .expect("build session");

        view.update(cx, |model, view_cx| {
            model.session = Some(session.clone());
            model.members = vec![MemberEntry {
                leaf_id: [0x42; 32],
                alias: Some("dock".to_string()),
                pop_public_key: Some(vec![0x42]),
                join_timestamp_ms: None,
                last_seen_timestamp_ms: None,
            }];
            model.reconcile_alias_bindings(view_cx);
            assert!(
                model.alias_bindings.contains_key("dock"),
                "binding should still update when disk persistence fails"
            );
        });
    }

    #[test]
    fn decode_persisted_session_rejects_bad_envelope_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let session_path = temp_dir
            .path()
            .join("cityg")
            .join("gui")
            .join("session.json");

        let bad_version = EncryptedSessionEnvelope {
            version: ENCRYPTED_SESSION_ENVELOPE_VERSION + 1,
            alg: ENCRYPTED_SESSION_ALG.to_string(),
            key_source: SessionKeySource::LocalKeyFile.as_str().to_string(),
            nonce_hex: "000102030405060708090a0b".to_string(),
            ciphertext_hex: "00".to_string(),
        };
        let err = match decode_persisted_session(&serde_json::to_vec(&bad_version)?, &session_path)
        {
            Ok(_) => return Err(anyhow!("unsupported envelope version should fail").into()),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("unsupported encrypted session envelope version"),
            "unexpected error: {err}"
        );

        let bad_alg = EncryptedSessionEnvelope {
            version: ENCRYPTED_SESSION_ENVELOPE_VERSION,
            alg: "aes-gcm".to_string(),
            key_source: SessionKeySource::LocalKeyFile.as_str().to_string(),
            nonce_hex: "000102030405060708090a0b".to_string(),
            ciphertext_hex: "00".to_string(),
        };
        let err = match decode_persisted_session(&serde_json::to_vec(&bad_alg)?, &session_path) {
            Ok(_) => return Err(anyhow!("unsupported envelope algorithm should fail").into()),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("unsupported encrypted session algorithm"),
            "unexpected error: {err}"
        );
        Ok(())
    }

    #[test]
    fn decode_persisted_session_rejects_bad_nonce_and_ciphertext_hex()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let session_path = temp_dir
            .path()
            .join("cityg")
            .join("gui")
            .join("session.json");

        let bad_nonce = EncryptedSessionEnvelope {
            version: ENCRYPTED_SESSION_ENVELOPE_VERSION,
            alg: ENCRYPTED_SESSION_ALG.to_string(),
            key_source: SessionKeySource::LocalKeyFile.as_str().to_string(),
            nonce_hex: "000102".to_string(),
            ciphertext_hex: "00".to_string(),
        };
        let err = match decode_persisted_session(&serde_json::to_vec(&bad_nonce)?, &session_path) {
            Ok(_) => return Err(anyhow!("invalid nonce length should fail").into()),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("nonce must be 12 bytes"),
            "unexpected error: {err}"
        );

        let bad_ciphertext = EncryptedSessionEnvelope {
            version: ENCRYPTED_SESSION_ENVELOPE_VERSION,
            alg: ENCRYPTED_SESSION_ALG.to_string(),
            key_source: SessionKeySource::LocalKeyFile.as_str().to_string(),
            nonce_hex: "000102030405060708090a0b".to_string(),
            ciphertext_hex: "zzzz".to_string(),
        };
        let err =
            match decode_persisted_session(&serde_json::to_vec(&bad_ciphertext)?, &session_path) {
                Ok(_) => return Err(anyhow!("invalid ciphertext hex should fail").into()),
                Err(err) => err,
            };
        assert!(
            err.to_string()
                .contains("encrypted session envelope ciphertext is not valid hex"),
            "unexpected error: {err}"
        );
        Ok(())
    }

    #[test]
    fn decode_persisted_session_accepts_payload_when_key_source_label_mismatches()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let session_path = temp_dir
            .path()
            .join("cityg")
            .join("gui")
            .join("session.json");
        if let Some(parent) = session_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let session = build_test_session(
            0xDA7A,
            "https://example.invalid",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "mismatch",
        )?;
        let persisted = PersistedSession::from_session(&session);
        let encrypted = encrypt_persisted_session(&persisted, &session_path)?;
        let mut envelope: EncryptedSessionEnvelope = serde_json::from_slice(&encrypted)?;
        envelope.key_source = SessionKeySource::EnvPassphrase.as_str().to_string();

        let decoded = decode_persisted_session(&serde_json::to_vec(&envelope)?, &session_path)?;
        assert_eq!(decoded.room_id, session.room_id);
        assert_eq!(decoded.server_url, session.server_url);
        Ok(())
    }

    #[test]
    fn decode_hex_helpers_validate_shape() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(decode_hex32("gid", &hex_encode([0xAB; 32]))?, [0xAB; 32]);
        assert_eq!(decode_hex_vec("vec", "0a0b")?, vec![0x0A, 0x0B]);
        assert_eq!(decode_hex_vec("empty", "")?, Vec::<u8>::new());
        assert!(decode_hex32("gid", "zz").is_err());
        assert!(decode_hex32("gid", "aa").is_err());
        assert!(decode_hex_vec("vec", "gg").is_err());
        Ok(())
    }

    #[test]
    fn rollup_strip_and_pivot_selection_rules() {
        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_ROLLUP_PROVENANCE_COMMIT, Value::Bytes(vec![1]));
        header.insert(hdr::HDR_ROLLUP_EPOCH_REPLAY, Value::Bytes(vec![2]));
        header.insert(hdr::HDR_ROLLUP_VCK_COMMIT, Value::Bytes(vec![3]));
        header.insert(99, Value::Text("keep".to_string()));
        strip_rollup_metadata(&mut header);
        assert!(!header.contains_key(&hdr::HDR_ROLLUP_PROVENANCE_COMMIT));
        assert!(!header.contains_key(&hdr::HDR_ROLLUP_EPOCH_REPLAY));
        assert!(!header.contains_key(&hdr::HDR_ROLLUP_VCK_COMMIT));
        assert!(header.contains_key(&99));

        let mut low = sample_pivot_parity();
        low.accept_seq = 1;
        low.xk_hash = [0x10; 32];
        let mut high = sample_pivot_parity();
        high.accept_seq = 2;
        high.xk_hash = [0x20; 32];
        let mut tie_break = sample_pivot_parity();
        tie_break.accept_seq = 2;
        tie_break.xk_hash = [0x01; 32];

        let parities = [low, high, tie_break];
        let selected = select_pivot_parity(&parities).expect("must select pivot");
        assert_eq!(selected.accept_seq, 2, "highest accept_seq should win");
        assert_eq!(
            selected.xk_hash, [0x01; 32],
            "ties use lexicographically smallest xk_hash"
        );
    }

    #[test]
    fn header_helpers_and_label_formatting() -> Result<(), Box<dyn std::error::Error>> {
        let mut header = BTreeMap::new();
        header.insert(1, Value::Text("hello".to_string()));
        header.insert(2, Value::Integer(Integer::from(77u64)));
        header.insert(3, Value::Bytes([0x11; 32].to_vec()));
        header.insert(4, Value::Bytes(vec![1, 2, 3]));
        header.insert(5, Value::Null);

        assert_eq!(header_text(&header, 1), Some("hello"));
        assert_eq!(header_u64(&header, 2), Some(77));
        assert_eq!(header_bytes32(&header, 3), Some([0x11; 32]));
        assert_eq!(header_bytes(&header, 4, "field4")?, vec![1, 2, 3]);
        assert_eq!(header_bytes_opt(&header, 4)?, Some(vec![1, 2, 3]));
        assert_eq!(header_bytes_opt(&header, 5)?, None);
        assert_eq!(header_bytes_opt(&header, 99)?, None);
        assert_eq!(header_bytes32_opt(&header, 3)?, Some([0x11; 32]));
        assert_eq!(header_bytes32_opt(&header, 5)?, None);
        assert!(
            header_bytes32_opt(&header, 4).is_err(),
            "not 32 bytes must fail"
        );
        assert!(
            header_bytes(&header, 2, "field2").is_err(),
            "wrong type must fail"
        );
        assert!(
            header_bytes(&header, 99, "missing").is_err(),
            "missing must fail"
        );

        let member_with_alias = MemberEntry {
            leaf_id: [0xAA; 32],
            alias: Some("alice".to_string()),
            pop_public_key: None,
            join_timestamp_ms: None,
            last_seen_timestamp_ms: None,
        };
        let member_without_alias = MemberEntry {
            alias: None,
            ..member_with_alias.clone()
        };
        assert_eq!(
            format_alias_display("alice", &[0xAA; 32]),
            "alice (aaaaaaaa…)"
        );
        assert_eq!(format_member_label(&member_with_alias), "alice (aaaaaaaa…)");
        assert_eq!(
            format_member_label(&member_without_alias),
            hex_encode([0xAA; 32])
        );
        assert_eq!(hex_encode_prefix(&[0xBB; 32], 8), "bbbbbbbb…");
        assert_eq!(hex_encode_prefix(&[0xBB; 32], 128), hex_encode([0xBB; 32]));
        assert_eq!(decode_hex_32(&hex_encode([0xCD; 32])), Some([0xCD; 32]));
        assert!(decode_hex_32("bad").is_none());
        assert!(decode_hex_32("aa").is_none());
        assert_eq!(format_timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(bytes32("good", &[0xEF; 32])?, [0xEF; 32]);
        assert!(bytes32("bad", &[0xEF; 31]).is_err());
        Ok(())
    }

    #[test]
    fn pivot_alignment_and_commit_recomputations() -> Result<(), Box<dyn std::error::Error>> {
        let mut pivot = sample_pivot_parity();
        pivot.fs_ec = Some(44);
        pivot.fs_epoch_commit = Some([0x33; 32]);
        pivot.fs_dev_commit = Some([0x22; 32]);

        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_FS_EC, Value::Integer(Integer::from(7u64)));
        header.insert(hdr::HDR_FS_EPOCH_COMMIT, Value::Bytes([0x11; 32].to_vec()));
        apply_pivot_alignment(&mut header, &pivot);
        assert_eq!(
            header.get(&hdr::HDR_FS_POLICY_VERSION),
            Some(&Value::Integer(Integer::from(7u64)))
        );
        assert_eq!(
            header.get(&hdr::HDR_FS_EC),
            Some(&Value::Integer(Integer::from(7u64))),
            "existing fs_ec should not be overwritten"
        );
        assert_eq!(
            header.get(&hdr::HDR_FS_CHECKPOINT_EC),
            Some(&Value::Integer(Integer::from(44u64)))
        );
        assert_eq!(
            header.get(&hdr::HDR_FS_EPOCH_COMMIT),
            Some(&Value::Bytes([0x11; 32].to_vec())),
            "existing epoch commit should remain"
        );
        assert_eq!(
            header.get(&hdr::HDR_FS_DEV_PREV_COMMIT),
            Some(&Value::Bytes([0x22; 32].to_vec()))
        );
        assert_eq!(
            header.get(&hdr::HDR_FS_DEV_COMMIT),
            Some(&Value::Bytes([0x22; 32].to_vec()))
        );

        let hydrated = hydrate_parities(
            &[{
                let mut p = sample_pivot_parity();
                p.fs_ec = None;
                p.fs_epoch_commit = None;
                p.fs_dev_commit = None;
                p
            }],
            88,
            [0xAB; 32],
            [0xBC; 32],
        );
        assert_eq!(hydrated[0].fs_ec, Some(88));
        assert_eq!(hydrated[0].fs_epoch_commit, Some([0xAB; 32]));
        assert_eq!(hydrated[0].fs_dev_commit, Some([0xBC; 32]));

        let mut commit_header = BTreeMap::new();
        commit_header.insert(hdr::HDR_VRF_PROOF, Value::Bytes(vec![0x01, 0x02]));
        commit_header.insert(hdr::HDR_FS_CAPSS, Value::Bytes(vec![0x03, 0x04]));
        let base_commit = recompute_proofs_commit(&commit_header)?;
        commit_header.insert(hdr::HDR_SRX_ROOT_SW, Value::Bytes([0x10; 32].to_vec()));
        commit_header.insert(hdr::HDR_SRX_SMALLWOOD, Value::Bytes(vec![0x20, 0x21]));
        let with_srx_commit = recompute_proofs_commit(&commit_header)?;
        assert_ne!(base_commit, with_srx_commit);
        commit_header.insert(hdr::HDR_SRX_ROOT_SW, Value::Bytes(vec![0x10]));
        assert!(recompute_proofs_commit(&commit_header).is_err());
        commit_header.insert(hdr::HDR_SRX_ROOT_SW, Value::Bytes([0x10; 32].to_vec()));
        commit_header.insert(hdr::HDR_VRF_PROOF, Value::Text("bad".to_string()));
        assert!(recompute_proofs_commit(&commit_header).is_err());

        let mut srx_header = BTreeMap::new();
        srx_header.insert(hdr::HDR_SRX_PAYLOAD, Value::Bytes(vec![0xAA, 0xBB]));
        assert!(recompute_srx_commit(&srx_header)?.is_some());
        srx_header.insert(hdr::HDR_SRX_PAYLOAD, Value::Text("bad".to_string()));
        assert!(recompute_srx_commit(&srx_header).is_err());
        Ok(())
    }

    #[test]
    fn fs_fingerprint_header_helper_roundtrip() {
        let fs_epoch_commit = [0xAA; 32];
        let mut header = BTreeMap::new();
        header.insert(
            hdr::HDR_FS_POLICY_VERSION,
            Value::Integer(Integer::from(7u64)),
        );
        header.insert(hdr::HDR_FS_EC, Value::Integer(Integer::from(21u64)));
        header.insert(
            hdr::HDR_FS_EPOCH_COMMIT,
            Value::Bytes(fs_epoch_commit.to_vec()),
        );
        header.insert(
            hdr::HDR_FS_EPOCH_BASE_TS,
            Value::Integer(Integer::from(777u64)),
        );

        let direct = derive_fs_fingerprint_from_fields("7", 21, &fs_epoch_commit, 777);
        let from_header = compute_fs_fingerprint_from_header(&header);
        assert_eq!(from_header, direct);
        assert!(compute_fs_fingerprint_from_header(&header).is_some());
    }

    #[test]
    fn pivot_alignment_inserts_optional_fs_fields_when_missing() {
        let mut header = BTreeMap::new();
        let mut pivot = sample_pivot_parity();
        pivot.fs_ec = Some(91);
        pivot.fs_epoch_commit = Some([0x9A; 32]);
        pivot.fs_dev_commit = Some([0xBC; 32]);

        apply_pivot_alignment(&mut header, &pivot);

        assert_eq!(
            header.get(&hdr::HDR_FS_EC),
            Some(&Value::Integer(Integer::from(91u64)))
        );
        assert_eq!(
            header.get(&hdr::HDR_FS_CHECKPOINT_EC),
            Some(&Value::Integer(Integer::from(91u64)))
        );
        assert_eq!(
            header.get(&hdr::HDR_FS_EPOCH_COMMIT),
            Some(&Value::Bytes([0x9A; 32].to_vec()))
        );
        assert_eq!(
            header.get(&hdr::HDR_FS_DEV_PREV_COMMIT),
            Some(&Value::Bytes([0xBC; 32].to_vec()))
        );
        assert_eq!(
            header.get(&hdr::HDR_FS_DEV_COMMIT),
            Some(&Value::Bytes([0xBC; 32].to_vec()))
        );
    }

    #[test]
    fn helper_none_and_error_paths_cover_header_and_fingerprint_logic()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(format_regular_fingerprint(None), "Not available");
        assert_eq!(format_fs_fingerprint(None, 12), "Not available");

        let mut typed = BTreeMap::new();
        typed.insert(1, Value::Integer(Integer::from(9u64)));
        typed.insert(2, Value::Text("bad".to_string()));
        typed.insert(3, Value::Integer(Integer::from(7u64)));
        typed.insert(4, Value::Integer(Integer::from(1u64)));
        assert_eq!(header_text(&typed, 1), None);
        assert_eq!(header_u64(&typed, 2), None);
        assert_eq!(header_bytes32(&typed, 3), None);
        assert!(
            header_bytes_opt(&typed, 4).is_err(),
            "header_bytes_opt should reject non-bytes"
        );
        assert!(
            header_bytes32_opt(&typed, 4).is_err(),
            "header_bytes32_opt should reject non-bytes"
        );

        let mut header = BTreeMap::new();
        header.insert(
            hdr::HDR_FS_POLICY_VERSION,
            Value::Integer(Integer::from(7u64)),
        );
        assert!(
            compute_fs_fingerprint_from_header(&header).is_none(),
            "missing fs_ec should fail"
        );
        header.insert(hdr::HDR_FS_EC, Value::Integer(Integer::from(7u64)));
        assert!(
            compute_fs_fingerprint_from_header(&header).is_none(),
            "missing fs_epoch_commit should fail"
        );
        header.insert(hdr::HDR_FS_EPOCH_COMMIT, Value::Bytes([0x44; 32].to_vec()));
        assert!(
            compute_fs_fingerprint_from_header(&header).is_none(),
            "missing fs_epoch_base_ts should fail"
        );
        header.insert(
            hdr::HDR_FS_EPOCH_BASE_TS,
            Value::Integer(Integer::from(99u64)),
        );
        assert!(
            compute_fs_fingerprint_from_header(&header).is_some(),
            "fully populated header should derive a fingerprint"
        );
        Ok(())
    }

    #[test]
    fn env_hex_parsing_and_kbroad_helper_paths() -> Result<(), Box<dyn std::error::Error>> {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let _public_restore = KbroadPublicEnvVarRestore {
            original: std::env::var(KBROAD_PUBLIC_ENV).ok(),
        };
        let temp_var = "CITYG_GUI_TEST_HEX_ENV";
        let temp_original = std::env::var_os(temp_var);

        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::set_var(KBROAD_PUBLIC_ENV, " \n\t ") };
        assert_eq!(configured_kbroad_public_from_env()?, None);

        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::set_var(KBROAD_PUBLIC_ENV, "0x") };
        assert_eq!(configured_kbroad_public_from_env()?, None);

        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::set_var(KBROAD_PUBLIC_ENV, "0Xa1b2") };
        assert_eq!(configured_kbroad_public_from_env()?, Some(vec![0xA1, 0xB2]));

        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::set_var(temp_var, "zz") };
        assert!(
            configured_hex_from_env(temp_var).is_err(),
            "invalid hex should fail parsing"
        );

        #[cfg(unix)]
        {
            use std::{ffi::OsString, os::unix::ffi::OsStringExt};
            // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
            unsafe { std::env::set_var(temp_var, OsString::from_vec(vec![0xFF, 0xFE])) };
            assert!(
                configured_hex_from_env(temp_var).is_err(),
                "invalid unicode env var should be surfaced"
            );
        }

        let (public_key, secret_key) = generate_kbroad_keypair();
        assert!(
            !public_key.is_empty(),
            "generated public key should be non-empty"
        );
        assert!(
            !secret_key.is_empty(),
            "generated secret key should be non-empty"
        );

        let now_ms = current_unix_timestamp_ms();
        assert!(
            now_ms > 1_000_000_000,
            "current timestamp should be epoch milliseconds"
        );

        match temp_original {
            Some(value) => {
                // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
                unsafe { std::env::set_var(temp_var, value) };
            }
            None => {
                // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
                unsafe { std::env::remove_var(temp_var) };
            }
        }
        Ok(())
    }

    #[test]
    fn authenticated_message_decode_reports_precise_truncation_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        let encoded = encode_authenticated_message(7, b"abc", b"key!", b"siggg");

        let mut truncated_plaintext = encoded.clone();
        truncated_plaintext[12..16].copy_from_slice(&(99u32).to_le_bytes());
        let err = decode_authenticated_message(&truncated_plaintext).expect_err("must fail");
        assert!(
            err.to_string().contains("truncated (plaintext)"),
            "expected plaintext truncation error"
        );

        let mut truncated_public = encoded.clone();
        truncated_public[19..23].copy_from_slice(&(77u32).to_le_bytes());
        let err = decode_authenticated_message(&truncated_public).expect_err("must fail");
        assert!(
            err.to_string().contains("truncated (public key)"),
            "expected public key truncation error"
        );

        let mut truncated_signature = encoded.clone();
        truncated_signature[27..31].copy_from_slice(&(9u32).to_le_bytes());
        let err = decode_authenticated_message(&truncated_signature).expect_err("must fail");
        assert!(
            err.to_string().contains("truncated (signature)"),
            "expected signature truncation error"
        );
        Ok(())
    }

    #[test]
    fn signing_helpers_reject_invalid_key_material() -> Result<(), Box<dyn std::error::Error>> {
        let leaf = [0x11; 32];
        let ts = 42u64;
        let payload = b"hello";

        assert!(
            sign_message(&leaf, ts, payload, &[0u8; 8]).is_err(),
            "invalid secret key bytes should fail"
        );

        let (pk, sk) = dilithium3::keypair();
        let signature = sign_message(&leaf, ts, payload, sk.as_bytes())?;

        assert!(
            verify_message_signature(&leaf, ts, payload, &signature, &[0u8; 8]).is_err(),
            "invalid public key bytes should fail"
        );
        assert!(
            verify_message_signature(&leaf, ts, payload, &[0u8; 8], pk.as_bytes()).is_err(),
            "invalid signature bytes should fail"
        );
        Ok(())
    }

    #[test]
    fn primary_shortcut_detection_accepts_cmd_and_ctrl() -> Result<(), Box<dyn std::error::Error>> {
        let cmd_v = Keystroke::parse("cmd-v")?;
        let ctrl_c = Keystroke::parse("ctrl-c")?;
        let alt_v = Keystroke::parse("alt-v")?;

        assert!(is_primary_shortcut(&cmd_v, "v"));
        assert!(is_primary_shortcut(&ctrl_c, "c"));
        assert!(!is_primary_shortcut(&alt_v, "v"));
        Ok(())
    }

    #[test]
    fn clipboard_text_sanitization_and_room_paste_rules() {
        assert_eq!(
            sanitize_clipboard_text("one\ntwo\tthree\r"),
            "one two three "
        );

        let existing = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let pasted_room = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let replaced = apply_join_field_paste(ActiveField::Room, existing, pasted_room);
        assert_eq!(replaced, pasted_room);

        let appended = apply_join_field_paste(ActiveField::Alias, "alice", "\n bob");
        assert_eq!(appended, "alice  bob");
    }

    #[test]
    fn message_composer_keystroke_paths() -> Result<(), Box<dyn std::error::Error>> {
        let mut composer = MessageComposer::default();
        let a = Keystroke::parse("a")?;
        assert!(matches!(composer.handle_keystroke(&a), KeyOutcome::None));

        composer.focus();
        composer.set_text("hi".to_string());
        assert_eq!(composer.text(), "hi");

        let backspace = Keystroke::parse("backspace")?;
        assert!(matches!(
            composer.handle_keystroke(&backspace),
            KeyOutcome::Updated
        ));
        assert_eq!(composer.text(), "h");

        let space = Keystroke::parse("space")?;
        assert!(matches!(
            composer.handle_keystroke(&space),
            KeyOutcome::Updated
        ));
        assert_eq!(composer.text(), "h ");

        let delete = Keystroke::parse("delete")?;
        assert!(matches!(
            composer.handle_keystroke(&delete),
            KeyOutcome::Updated
        ));
        assert_eq!(composer.text(), "");

        composer.set_text("ok".to_string());
        let enter = Keystroke::parse("enter")?;
        assert!(matches!(
            composer.handle_keystroke(&enter),
            KeyOutcome::Submit
        ));

        let escape = Keystroke::parse("escape")?;
        assert!(matches!(
            composer.handle_keystroke(&escape),
            KeyOutcome::Updated
        ));
        assert!(!composer.active);
        Ok(())
    }

    #[test]
    fn members_search_keystroke_paths() -> Result<(), Box<dyn std::error::Error>> {
        let mut search = MembersSearchState::default();
        let a = Keystroke::parse("a")?;
        assert!(matches!(search.handle_keystroke(&a), KeyOutcome::None));

        search.focus();
        search.set_query("ab".to_string());
        assert_eq!(search.query(), "ab");

        let backspace = Keystroke::parse("backspace")?;
        assert!(matches!(
            search.handle_keystroke(&backspace),
            KeyOutcome::Updated
        ));
        assert_eq!(search.query(), "a");

        let delete = Keystroke::parse("delete")?;
        assert!(matches!(
            search.handle_keystroke(&delete),
            KeyOutcome::Updated
        ));
        assert_eq!(search.query(), "");

        let enter = Keystroke::parse("enter")?;
        assert!(matches!(
            search.handle_keystroke(&enter),
            KeyOutcome::Submit
        ));

        let tab = Keystroke::parse("tab")?;
        assert!(matches!(search.handle_keystroke(&tab), KeyOutcome::Updated));
        assert!(!search.active);
        Ok(())
    }

    #[test]
    fn join_form_keystroke_paths() -> Result<(), Box<dyn std::error::Error>> {
        let mut form = JoinFormState {
            server: "http://127.0.0.1:18080".to_string(),
            room_id: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            alias: "alice".to_string(),
            active: Some(ActiveField::Server),
        };

        assert!(JoinFormState::next_field(ActiveField::Server) == ActiveField::Room);
        assert!(JoinFormState::previous_field(ActiveField::Server) == ActiveField::Alias);

        let tab = Keystroke::parse("tab")?;
        assert!(matches!(form.handle_keystroke(&tab), KeyOutcome::Updated));
        assert!(form.active == Some(ActiveField::Room));
        assert_eq!(form.field(ActiveField::Alias), "alice");

        {
            let room = form.field_mut(ActiveField::Room);
            room.truncate(63);
        }
        assert!(!form.is_ready());
        form.field_mut(ActiveField::Room).push('f');
        assert!(form.is_ready());

        let enter = Keystroke::parse("enter")?;
        assert!(matches!(form.handle_keystroke(&enter), KeyOutcome::Submit));

        let escape = Keystroke::parse("escape")?;
        assert!(matches!(
            form.handle_keystroke(&escape),
            KeyOutcome::Updated
        ));
        assert!(form.active.is_none());
        Ok(())
    }

    #[test]
    fn helper_and_model_state_paths_cover_edge_cases() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));

        let mut model = AppModel::new(CityGConfig::default());
        let room_id = AppModel::random_room_id();
        assert_eq!(room_id.len(), 64);
        assert!(room_id.chars().all(|c| c.is_ascii_hexdigit()));

        let success = Toast::success("ok");
        let error = Toast::error("err");
        let info = Toast::info("info");
        assert_eq!(success.kind, ToastKind::Success);
        assert_eq!(error.kind, ToastKind::Error);
        assert_eq!(info.kind, ToastKind::Info);
        assert!(!success.is_expired());

        let mut expired = Toast::info("expired");
        expired.created_at = SystemTime::now() - Duration::from_secs(10);
        expired.duration_secs = 1;
        model.toasts.push(expired);
        model.toasts.push(success.clone());
        model.cleanup_expired_toasts();
        assert_eq!(model.toasts.len(), 1);
        assert_eq!(model.toasts[0].kind, ToastKind::Success);

        let err = anyhow!("connection reset by peer");
        model.set_error(&err, "send", Some(RetryAction::Send));
        assert!(model.last_error.is_some());
        assert!(model.categorized_error.is_some());
        assert_eq!(model.last_retry_action, Some(RetryAction::Send));
        model.clear_error();
        assert!(model.last_error.is_none());
        assert!(model.categorized_error.is_none());
        assert!(model.last_retry_action.is_none());
        Ok(())
    }

    #[test]
    fn app_model_new_restores_saved_session() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));

        let session = build_test_session(
            4242,
            "https://restore.example.com",
            "restore-room-123",
            "restorer",
        )?;
        persist_session(&session)?;

        let model = AppModel::new(CityGConfig::default());
        let restored = model
            .session
            .as_ref()
            .ok_or_else(|| anyhow!("expected restored session"))?;
        assert_eq!(restored.server_url, session.server_url);
        assert_eq!(restored.room_id, session.room_id);
        assert_eq!(restored.alias, session.alias);
        assert_eq!(model.join_form.server, session.server_url);
        assert_eq!(model.join_form.room_id, session.room_id);
        assert_eq!(model.join_form.alias, session.alias);
        assert!(model.join_form.active.is_none());
        assert_eq!(
            model.info_message.as_deref(),
            Some("Restored saved session.")
        );
        assert!(matches!(model.fetch_status, FetchStatus::Idle));
        assert!(matches!(model.send_status, SendStatus::Idle));
        assert!(model.messages.is_empty());
        assert!(model.message_keys.is_empty());
        assert!(model.fetch_task.is_none());
        assert!(!model.fetch_in_flight);
        assert!(!model.show_ciphertext);
        assert!(!model.composer.active);
        Ok(())
    }

    #[test]
    fn app_model_new_handles_invalid_saved_session_pointer()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));

        let pointer_path = last_session_pointer_path()?;
        fs::create_dir_all(
            pointer_path
                .parent()
                .ok_or_else(|| anyhow!("missing pointer parent"))?,
        )?;
        fs::write(pointer_path, "{invalid-json")?;

        let model = AppModel::new(CityGConfig::default());
        assert!(model.session.is_none());
        Ok(())
    }

    #[test]
    fn keystroke_helpers_cover_modifier_and_empty_paths() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut composer = MessageComposer::default();
        composer.focus();
        let backspace = Keystroke::parse("backspace")?;
        assert!(matches!(
            composer.handle_keystroke(&backspace),
            KeyOutcome::None
        ));
        let delete = Keystroke::parse("delete")?;
        assert!(matches!(
            composer.handle_keystroke(&delete),
            KeyOutcome::None
        ));
        composer.set_text("  ".to_string());
        assert!(!composer.is_ready());
        composer.clear();
        assert_eq!(composer.text(), "");
        let x = Keystroke::parse("x->x")?;
        assert!(matches!(composer.handle_keystroke(&x), KeyOutcome::Updated));
        assert_eq!(composer.text(), "x");
        let ctrl_a = Keystroke::parse("ctrl-a")?;
        assert!(matches!(
            composer.handle_keystroke(&ctrl_a),
            KeyOutcome::None
        ));
        composer.blur();

        let mut search = MembersSearchState::default();
        search.focus();
        assert!(matches!(
            search.handle_keystroke(&backspace),
            KeyOutcome::None
        ));
        assert!(matches!(search.handle_keystroke(&delete), KeyOutcome::None));
        search.set_query("abc".to_string());
        search.clear();
        assert_eq!(search.query(), "");
        assert!(matches!(search.handle_keystroke(&x), KeyOutcome::Updated));
        let escape = Keystroke::parse("escape")?;
        assert!(matches!(
            search.handle_keystroke(&escape),
            KeyOutcome::Updated
        ));
        assert!(!search.active);
        search.focus();
        assert!(matches!(search.handle_keystroke(&ctrl_a), KeyOutcome::None));
        search.blur();
        Ok(())
    }

    #[test]
    fn join_form_and_shortcut_edge_paths() -> Result<(), Box<dyn std::error::Error>> {
        let mut form = JoinFormState {
            server: " http://127.0.0.1:18080 ".to_string(),
            room_id: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
            alias: " alice ".to_string(),
            active: None,
        };
        let tab = Keystroke::parse("tab")?;
        assert!(matches!(form.handle_keystroke(&tab), KeyOutcome::None));

        form.active = Some(ActiveField::Server);
        let shift_tab = Keystroke::parse("shift-tab")?;
        assert!(matches!(
            form.handle_keystroke(&shift_tab),
            KeyOutcome::Updated
        ));
        assert!(form.active == Some(ActiveField::Alias));

        let backspace = Keystroke::parse("backspace")?;
        form.alias.clear();
        assert!(matches!(
            form.handle_keystroke(&backspace),
            KeyOutcome::None
        ));

        let delete = Keystroke::parse("delete")?;
        assert!(matches!(
            form.handle_keystroke(&delete),
            KeyOutcome::Updated
        ));
        assert_eq!(form.alias, "");

        let space = Keystroke::parse("space")?;
        assert!(matches!(form.handle_keystroke(&space), KeyOutcome::Updated));
        assert_eq!(form.alias, " ");

        let ctrl_a = Keystroke::parse("ctrl-a")?;
        assert!(matches!(form.handle_keystroke(&ctrl_a), KeyOutcome::None));

        let x = Keystroke::parse("x->x")?;
        assert!(matches!(form.handle_keystroke(&x), KeyOutcome::Updated));
        assert_eq!(form.alias, " x");

        form.room_id = "bad-room".to_string();
        let enter = Keystroke::parse("enter")?;
        assert!(matches!(form.handle_keystroke(&enter), KeyOutcome::None));
        form.room_id =
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string();
        form.alias = "zed".to_string();
        assert!(matches!(form.handle_keystroke(&enter), KeyOutcome::Submit));

        form.active = Some(ActiveField::Alias);
        form.alias = " zed ".to_string();
        let params = form.join_params();
        assert_eq!(params.server_url, "http://127.0.0.1:18080");
        assert_eq!(params.alias, "zed");
        assert_eq!(
            params.room_id,
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        );

        assert!(JoinFormState::is_valid_room_id(&params.room_id));
        assert!(!JoinFormState::is_valid_room_id("too-short"));

        let plain_v = Keystroke::parse("v")?;
        assert!(!is_primary_shortcut(&plain_v, "v"));
        Ok(())
    }

    #[tokio::test]
    async fn websocket_worker_reports_revoke_membership_event()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let membership_gid = [0x24u8; 32];
        let membership_gid_hex = hex_encode(membership_gid);
        let membership_leaf = [0xCDu8; 32];
        let membership_leaf_hex = hex_encode(membership_leaf);

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut ws = tokio_tungstenite::accept_async(stream).await?;
            ws.send(WsMessage::Text(
                format!(
                    r#"{{"type":"membership","gid":"{membership_gid_hex}","leaf_id":"{membership_leaf_hex}","event":"revoke","timestamp_ms":55}}"#
                )
                .into(),
            ))
            .await?;
            ws.close(None).await?;
            Ok::<(), anyhow::Error>(())
        });

        let (tx, mut rx) = futures_mpsc::unbounded::<WebSocketEvent>();
        let worker = tokio::spawn(run_websocket_worker(
            format!("ws://{addr}/v1/ws"),
            Duration::from_millis(20),
            tx,
        ));

        let mut saw_revoke = false;
        for _ in 0..8 {
            let next = tokio::time::timeout(Duration::from_secs(1), rx.next()).await?;
            let Some(event) = next else {
                break;
            };
            if let WebSocketEvent::Membership(signal) = event
                && signal.gid == membership_gid
                && signal.leaf_id == Some(membership_leaf)
                && signal.kind == Some(MembershipSignalKind::Revoke)
            {
                saw_revoke = true;
                break;
            }
        }
        assert!(saw_revoke, "expected revoke membership event");

        drop(rx);
        tokio::time::timeout(Duration::from_secs(1), server).await???;
        tokio::time::timeout(Duration::from_secs(1), worker).await???;
        Ok(())
    }

    #[tokio::test]
    async fn websocket_worker_returns_when_event_channel_is_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut ws = tokio_tungstenite::accept_async(stream).await?;
            ws.close(None).await?;
            Ok::<(), anyhow::Error>(())
        });

        let (tx, rx) = futures_mpsc::unbounded::<WebSocketEvent>();
        drop(rx);

        tokio::time::timeout(
            Duration::from_secs(1),
            run_websocket_worker(format!("ws://{addr}/v1/ws"), Duration::from_secs(1), tx),
        )
        .await??;

        tokio::time::timeout(Duration::from_secs(1), server).await???;
        Ok(())
    }

    #[tokio::test]
    async fn websocket_worker_emits_membership_and_message_events()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let membership_gid = [0x42u8; 32];
        let membership_gid_hex = hex_encode(membership_gid);
        let membership_leaf = [0xABu8; 32];
        let membership_leaf_hex = hex_encode(membership_leaf);

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut ws = tokio_tungstenite::accept_async(stream).await?;
            ws.send(WsMessage::Text(r#"{"type":"message"}"#.to_string().into()))
                .await?;
            ws.send(WsMessage::Text(
                format!(
                    r#"{{"type":"membership","gid":"{membership_gid_hex}","leaf_id":"{membership_leaf_hex}","event":"join","timestamp_ms":12345}}"#
                )
                .into(),
            ))
            .await?;
            ws.send(WsMessage::Text(
                r#"{"type":"membership","gid":"not-hex"}"#.to_string().into(),
            ))
            .await?;
            ws.send(WsMessage::Text(
                r#"{"type":"lag","detail":"slow_consumer"}"#.to_string().into(),
            ))
            .await?;
            ws.close(None).await?;
            Ok::<(), anyhow::Error>(())
        });

        let (tx, mut rx) = futures_mpsc::unbounded::<WebSocketEvent>();
        let worker = tokio::spawn(run_websocket_worker(
            format!("ws://{addr}/v1/ws"),
            Duration::from_millis(20),
            tx,
        ));

        let mut saw_connected = false;
        let mut saw_message = false;
        let mut saw_membership = false;
        let mut saw_disconnected = false;
        for _ in 0..12 {
            let next = tokio::time::timeout(Duration::from_secs(1), rx.next()).await?;
            let Some(event) = next else {
                break;
            };

            match event {
                WebSocketEvent::Connected => saw_connected = true,
                WebSocketEvent::Message => saw_message = true,
                WebSocketEvent::Membership(signal) => {
                    if signal.gid == membership_gid
                        && signal.leaf_id == Some(membership_leaf)
                        && signal.kind == Some(MembershipSignalKind::Join)
                    {
                        saw_membership = true;
                    }
                }
                WebSocketEvent::Disconnected => {
                    saw_disconnected = true;
                    if saw_connected && saw_message && saw_membership {
                        break;
                    }
                }
            }
        }

        assert!(saw_connected, "expected Connected event");
        assert!(saw_message, "expected Message event");
        assert!(saw_membership, "expected Membership event");
        assert!(saw_disconnected, "expected Disconnected event");

        drop(rx);
        tokio::time::timeout(Duration::from_secs(1), server).await???;
        tokio::time::timeout(Duration::from_secs(1), worker).await???;
        Ok(())
    }

    #[tokio::test]
    async fn websocket_worker_parses_unknown_membership_and_ping()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let membership_gid = [0x66u8; 32];
        let membership_gid_hex = hex_encode(membership_gid);
        let membership_leaf = [0x99u8; 32];
        let membership_leaf_hex = hex_encode(membership_leaf);

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut ws = tokio_tungstenite::accept_async(stream).await?;
            ws.send(WsMessage::Text(
                format!(
                    r#"{{"type":"membership","gid":"{membership_gid_hex}","leaf_id":"{membership_leaf_hex}","event":"unknown","timestamp_ms":77}}"#
                )
                .into(),
            ))
            .await?;
            ws.send(WsMessage::Ping(vec![1, 2, 3].into())).await?;
            ws.close(None).await?;
            Ok::<(), anyhow::Error>(())
        });

        let (tx, mut rx) = futures_mpsc::unbounded::<WebSocketEvent>();
        let worker = tokio::spawn(run_websocket_worker(
            format!("ws://{addr}/v1/ws"),
            Duration::from_millis(20),
            tx,
        ));

        let mut saw_unknown_kind = false;
        for _ in 0..8 {
            let next = tokio::time::timeout(Duration::from_secs(1), rx.next()).await?;
            let Some(event) = next else {
                break;
            };
            if let WebSocketEvent::Membership(signal) = event
                && signal.gid == membership_gid
                && signal.leaf_id == Some(membership_leaf)
            {
                saw_unknown_kind = signal.kind.is_none();
                break;
            }
        }
        assert!(
            saw_unknown_kind,
            "expected membership event with unknown kind"
        );

        drop(rx);
        tokio::time::timeout(Duration::from_secs(1), server).await???;
        tokio::time::timeout(Duration::from_secs(1), worker).await???;
        Ok(())
    }

    #[tokio::test]
    async fn websocket_worker_returns_when_message_delivery_channel_closes()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut ws = tokio_tungstenite::accept_async(stream).await?;
            sleep(Duration::from_millis(60)).await;
            ws.send(WsMessage::Text(r#"{"type":"message"}"#.to_string().into()))
                .await?;
            ws.close(None).await?;
            Ok::<(), anyhow::Error>(())
        });

        let (tx, mut rx) = futures_mpsc::unbounded::<WebSocketEvent>();
        let worker = tokio::spawn(run_websocket_worker(
            format!("ws://{addr}/v1/ws"),
            Duration::from_secs(1),
            tx,
        ));

        let first = tokio::time::timeout(Duration::from_secs(1), rx.next()).await?;
        assert!(matches!(first, Some(WebSocketEvent::Connected)));
        drop(rx);

        tokio::time::timeout(Duration::from_secs(1), worker).await???;
        tokio::time::timeout(Duration::from_secs(1), server).await???;
        Ok(())
    }

    #[tokio::test]
    async fn websocket_worker_returns_when_membership_delivery_channel_closes()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let gid_hex = hex_encode([0x33u8; 32]);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut ws = tokio_tungstenite::accept_async(stream).await?;
            sleep(Duration::from_millis(60)).await;
            ws.send(WsMessage::Text(
                format!(r#"{{"type":"membership","gid":"{gid_hex}","event":"join"}}"#).into(),
            ))
            .await?;
            ws.close(None).await?;
            Ok::<(), anyhow::Error>(())
        });

        let (tx, mut rx) = futures_mpsc::unbounded::<WebSocketEvent>();
        let worker = tokio::spawn(run_websocket_worker(
            format!("ws://{addr}/v1/ws"),
            Duration::from_secs(1),
            tx,
        ));

        let first = tokio::time::timeout(Duration::from_secs(1), rx.next()).await?;
        assert!(matches!(first, Some(WebSocketEvent::Connected)));
        drop(rx);

        tokio::time::timeout(Duration::from_secs(1), worker).await???;
        tokio::time::timeout(Duration::from_secs(1), server).await???;
        Ok(())
    }

    #[tokio::test]
    async fn websocket_worker_ignores_invalid_json_and_unknown_notification_type()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut ws = tokio_tungstenite::accept_async(stream).await?;
            ws.send(WsMessage::Text("not-json".to_string().into()))
                .await?;
            ws.send(WsMessage::Text(r#"{"type":"other"}"#.to_string().into()))
                .await?;
            ws.close(None).await?;
            Ok::<(), anyhow::Error>(())
        });

        let (tx, mut rx) = futures_mpsc::unbounded::<WebSocketEvent>();
        let worker = tokio::spawn(run_websocket_worker(
            format!("ws://{addr}/v1/ws"),
            Duration::from_millis(20),
            tx,
        ));

        let mut saw_connected = false;
        let mut saw_disconnected = false;
        for _ in 0..6 {
            let next = tokio::time::timeout(Duration::from_secs(1), rx.next()).await?;
            let Some(event) = next else {
                break;
            };
            match event {
                WebSocketEvent::Connected => saw_connected = true,
                WebSocketEvent::Disconnected => {
                    saw_disconnected = true;
                    break;
                }
                WebSocketEvent::Message | WebSocketEvent::Membership(_) => {
                    return Err(anyhow!("unexpected event from invalid payloads").into());
                }
            }
        }

        assert!(saw_connected, "expected Connected event");
        assert!(saw_disconnected, "expected Disconnected event");

        drop(rx);
        tokio::time::timeout(Duration::from_secs(1), server).await???;
        tokio::time::timeout(Duration::from_secs(1), worker).await???;
        Ok(())
    }

    #[tokio::test]
    async fn websocket_worker_handles_stream_protocol_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut ws = tokio_tungstenite::accept_async(stream).await?;
            ws.get_mut().write_all(b"not-a-websocket-frame").await?;
            ws.get_mut().shutdown().await?;
            Ok::<(), anyhow::Error>(())
        });

        let (tx, mut rx) = futures_mpsc::unbounded::<WebSocketEvent>();
        let worker = tokio::spawn(run_websocket_worker(
            format!("ws://{addr}/v1/ws"),
            Duration::from_millis(20),
            tx,
        ));

        let mut saw_disconnected = false;
        for _ in 0..6 {
            let next = tokio::time::timeout(Duration::from_secs(1), rx.next()).await?;
            let Some(event) = next else {
                break;
            };
            if matches!(event, WebSocketEvent::Disconnected) {
                saw_disconnected = true;
                break;
            }
        }
        assert!(
            saw_disconnected,
            "protocol errors should produce a disconnected event"
        );

        drop(rx);
        tokio::time::timeout(Duration::from_secs(1), server).await???;
        tokio::time::timeout(Duration::from_secs(1), worker).await???;
        Ok(())
    }

    #[test]
    fn session_persistence_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));

        let mut rng = StdRng::seed_from_u64(42);
        let array = |val: u8| {
            let mut bytes = [0u8; 32];
            bytes.fill(val);
            bytes
        };

        let mut random_vec = |len: usize| {
            let mut buf = vec![0u8; len];
            rng.fill_bytes(&mut buf);
            buf
        };

        let forward_state =
            ForwardSecrecyState::with_state(array(0xAA), 17, array(0x55), array(0x99));
        let capss_witness_bundle = CapssWitnessBundle {
            branch_a: CapssBranchWitness {
                branch_artifact: random_vec(24),
                ctx_tag: random_vec(16),
            },
            branch_b: CapssBranchWitness {
                branch_artifact: random_vec(24),
                ctx_tag: random_vec(16),
            },
        };
        let capss_witness_bytes = encode_capss_witness(&capss_witness_bundle)?;

        let mut session = AppSession {
            server_url: "https://example.invalid".to_string(),
            room_id: "room-123".to_string(),
            alias: "alice".to_string(),
            gid: array(0x01),
            cat: array(0x02),
            leaf_id: array(0x03),
            parent_root: array(0x04),
            join_delta_root: array(0x05),
            revoked_since_root: array(0x06),
            revoked_root: array(0x07),
            regular_fingerprint: Some(array(0x0A)),
            fs_fingerprint: None,
            tswe_salt_hash: array(0x08),
            pox_r_commit: array(0x09),
            we_epoch_id: array(0x10),
            xk_hash: array(0x14),
            epoch_key: array(0x11),
            forward_state,
            fs_ec: 17,
            fs_epoch_commit: array(0x12),
            fs_dev_prev_commit: array(0x13),
            fs_epoch_created_at: SystemTime::now(),
            fs_epoch_rotation_interval_secs: 300,
            pop_public_key: random_vec(48),
            pop_secret_key: random_vec(96),
            msg_sign_public_key: random_vec(1952), // ML-DSA-65 public key
            msg_sign_secret_key: random_vec(4032), // ML-DSA-65 secret key
            vrf_secret_key: random_vec(32),
            vrf_public_key: random_vec(32),
            kbroad_public: random_vec(24),
            kbroad_secret: random_vec(32),
            bootstrap_public: random_vec(24),
            proof_mode: "lin+zkvrf".to_string(),
            vrf_id: "vrf-demo".to_string(),
            policy_version: "v1".to_string(),
            msphf_crs_id: "rlwe-merkle/v1".to_string(),
            msphf_params_id: "rlwe-params/mock".to_string(),
            fs_policy_version: "7".to_string(),
            fs_epoch_base_ts: 42,
            last_fetch_timestamp_ms: Some(1_234_567),
            msg_replay_state: MsgReplayState::default(),
            capss_witness: capss_witness_bytes.clone(),
            barrier_state: BarrierSecretState::default(),
        };
        let mut barrier_dk_nodes = BTreeMap::new();
        barrier_dk_nodes.insert(
            1,
            BarrierNodeKeyMaterial {
                dk: Zeroizing::new(random_vec(kyber768::secret_key_bytes())),
                pkhash: array(0x24),
            },
        );
        let mut pending_on_path = BTreeMap::new();
        pending_on_path.insert(
            0,
            BarrierNodeKeyMaterial {
                dk: Zeroizing::new(random_vec(kyber768::secret_key_bytes())),
                pkhash: array(0x2A),
            },
        );
        pending_on_path.insert(
            1,
            BarrierNodeKeyMaterial {
                dk: Zeroizing::new(random_vec(kyber768::secret_key_bytes())),
                pkhash: array(0x2B),
            },
        );
        session.barrier_state = BarrierSecretState {
            barrier_version: 5,
            k_barrier: Zeroizing::new(array(0x21)),
            kem_tree_hash_after: array(0x22),
            max_barrier_update_bytes: DEFAULT_MAX_BARRIER_UPDATE_BYTES,
            n_max: 8,
            cover_leaf_index: 3,
            dk_leaf: Zeroizing::new(random_vec(kyber768::secret_key_bytes())),
            pkhash_leaf: array(0x23),
            dk_nodes: barrier_dk_nodes,
            pending: Some(BarrierPendingState {
                barrier_version: 6,
                revocation_roots_hash: array(0x25),
                kem_tree_hash_after: array(0x26),
                k_barrier_new: Zeroizing::new(array(0x27)),
                k_fs_after_pcs: Some(Zeroizing::new(array(0x28))),
                barrier_update_reason: Some(1),
                barrier_update_digest: array(0x29),
                on_path_key_material: pending_on_path,
            }),
            barrier_recovery_pending: true,
        };
        let tuple_tag = array(0x30);
        let mut replay_state = MsgReplayState::default();
        replay_state.ensure_tuple(tuple_tag);
        replay_state.record(tuple_tag, 11);
        replay_state.record(tuple_tag, 22);
        replay_state.record(tuple_tag, 33);
        replay_state.record(tuple_tag, 44);
        session.msg_replay_state = replay_state;
        session.fs_fingerprint = derive_fs_fingerprint_from_fields(
            session.fs_policy_version.as_str(),
            session.fs_ec,
            &session.fs_epoch_commit,
            session.fs_epoch_base_ts,
        );

        persist_session(&session)?;
        let session_path = session_file_path(&session.server_url, &session.room_id)?;
        let raw_session_file = fs::read(&session_path)?;
        let raw_session_text = String::from_utf8_lossy(&raw_session_file);
        assert!(
            raw_session_text.contains("ciphertext_hex"),
            "session file must store encrypted payload envelope"
        );
        assert!(
            !raw_session_text.contains("pop_secret_hex"),
            "session file must not expose plaintext secret field names"
        );
        assert!(
            !raw_session_text.contains(&hex_encode(&session.pop_secret_key)),
            "session file must not expose plaintext pop secret bytes"
        );
        assert!(
            !raw_session_text.contains(&hex_encode(&session.msg_sign_secret_key)),
            "session file must not expose plaintext message signing secret bytes"
        );
        assert!(
            !raw_session_text.contains(&hex_encode(&session.vrf_secret_key)),
            "session file must not expose plaintext vrf secret bytes"
        );
        let loaded = load_session_at(&session.server_url, &session.room_id)?
            .ok_or_else(|| anyhow!("expected persisted session to load"))?;

        assert_eq!(loaded.server_url, session.server_url);
        assert_eq!(loaded.room_id, session.room_id);
        assert_eq!(loaded.alias, session.alias);
        assert_eq!(loaded.gid, session.gid);
        assert_eq!(loaded.cat, session.cat);
        assert_eq!(loaded.leaf_id, session.leaf_id);
        assert_eq!(loaded.parent_root, session.parent_root);
        assert_eq!(loaded.join_delta_root, session.join_delta_root);
        assert_eq!(loaded.revoked_since_root, session.revoked_since_root);
        assert_eq!(loaded.revoked_root, session.revoked_root);
        assert_eq!(loaded.regular_fingerprint, session.regular_fingerprint);
        assert_eq!(loaded.fs_fingerprint, session.fs_fingerprint);
        assert_eq!(loaded.tswe_salt_hash, session.tswe_salt_hash);
        assert_eq!(loaded.pox_r_commit, session.pox_r_commit);
        assert_eq!(loaded.we_epoch_id, session.we_epoch_id);
        assert_eq!(loaded.epoch_key, session.epoch_key);
        assert_eq!(loaded.kbroad_public, session.kbroad_public);
        assert_eq!(loaded.kbroad_secret, session.kbroad_secret);
        assert_eq!(loaded.bootstrap_public, session.bootstrap_public);
        assert_eq!(loaded.pop_public_key, session.pop_public_key);
        assert_eq!(loaded.pop_secret_key, session.pop_secret_key);
        assert_eq!(loaded.vrf_public_key, session.vrf_public_key);
        assert_eq!(loaded.vrf_secret_key, session.vrf_secret_key);
        assert_eq!(loaded.proof_mode, session.proof_mode);
        assert_eq!(loaded.vrf_id, session.vrf_id);
        assert_eq!(loaded.policy_version, session.policy_version);
        assert_eq!(loaded.msphf_crs_id, session.msphf_crs_id);
        assert_eq!(loaded.msphf_params_id, session.msphf_params_id);
        assert_eq!(loaded.fs_policy_version, session.fs_policy_version);
        assert_eq!(loaded.fs_epoch_base_ts, session.fs_epoch_base_ts);
        assert_eq!(
            loaded.last_fetch_timestamp_ms,
            session.last_fetch_timestamp_ms
        );
        assert_eq!(loaded.msg_replay_state, session.msg_replay_state);

        assert_eq!(
            loaded.forward_state.snapshot(),
            session.forward_state.snapshot()
        );
        assert_eq!(loaded.fs_ec, session.fs_ec);
        assert_eq!(loaded.fs_epoch_commit, session.fs_epoch_commit);
        assert_eq!(loaded.fs_dev_prev_commit, session.fs_dev_prev_commit);
        assert_eq!(
            loaded.fs_epoch_rotation_interval_secs,
            session.fs_epoch_rotation_interval_secs
        );
        // Verify epoch timestamp is persisted (allow small time difference)
        let epoch_age_diff = loaded
            .fs_epoch_created_at
            .duration_since(session.fs_epoch_created_at)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        assert!(
            epoch_age_diff <= 1,
            "epoch timestamp should be preserved within 1 second"
        );
        assert_eq!(loaded.capss_witness, capss_witness_bytes);
        assert_eq!(
            loaded.barrier_state.barrier_version,
            session.barrier_state.barrier_version
        );
        assert_eq!(
            loaded.barrier_state.k_barrier,
            session.barrier_state.k_barrier
        );
        assert_eq!(
            loaded.barrier_state.kem_tree_hash_after,
            session.barrier_state.kem_tree_hash_after
        );
        assert_eq!(loaded.barrier_state.n_max, session.barrier_state.n_max);
        assert_eq!(
            loaded.barrier_state.cover_leaf_index,
            session.barrier_state.cover_leaf_index
        );
        assert_eq!(
            loaded.barrier_state.barrier_recovery_pending,
            session.barrier_state.barrier_recovery_pending
        );
        assert_eq!(loaded.barrier_state.dk_leaf, session.barrier_state.dk_leaf);
        assert_eq!(
            loaded.barrier_state.pkhash_leaf,
            session.barrier_state.pkhash_leaf
        );
        assert_eq!(
            loaded.barrier_state.dk_nodes.len(),
            session.barrier_state.dk_nodes.len()
        );
        for (node, expected) in &session.barrier_state.dk_nodes {
            let actual = loaded
                .barrier_state
                .dk_nodes
                .get(node)
                .ok_or_else(|| anyhow!("missing dk_nodes entry for node {node}"))?;
            assert_eq!(actual.dk, expected.dk);
            assert_eq!(actual.pkhash, expected.pkhash);
        }
        let loaded_pending = loaded
            .barrier_state
            .pending
            .as_ref()
            .ok_or_else(|| anyhow!("missing persisted barrier pending state"))?;
        let expected_pending = session
            .barrier_state
            .pending
            .as_ref()
            .ok_or_else(|| anyhow!("missing expected barrier pending state"))?;
        assert_eq!(
            loaded_pending.barrier_version,
            expected_pending.barrier_version
        );
        assert_eq!(
            loaded_pending.revocation_roots_hash,
            expected_pending.revocation_roots_hash
        );
        assert_eq!(
            loaded_pending.kem_tree_hash_after,
            expected_pending.kem_tree_hash_after
        );
        assert_eq!(loaded_pending.k_barrier_new, expected_pending.k_barrier_new);
        assert_eq!(
            loaded_pending.k_fs_after_pcs,
            expected_pending.k_fs_after_pcs
        );
        assert_eq!(
            loaded_pending.barrier_update_reason,
            expected_pending.barrier_update_reason
        );
        assert_eq!(
            loaded_pending.barrier_update_digest,
            expected_pending.barrier_update_digest
        );
        assert_eq!(
            loaded_pending.on_path_key_material.len(),
            expected_pending.on_path_key_material.len()
        );
        for (node, expected) in &expected_pending.on_path_key_material {
            let actual = loaded_pending
                .on_path_key_material
                .get(node)
                .ok_or_else(|| anyhow!("missing pending key material for node {node}"))?;
            assert_eq!(actual.dk, expected.dk);
            assert_eq!(actual.pkhash, expected.pkhash);
        }

        let decoded = decode_capss_witness(&loaded.capss_witness)?;
        assert_eq!(decoded, capss_witness_bundle);

        // Clean up persisted files to avoid leaking into other tests.
        remove_persisted_session(&session.server_url, &session.room_id)?;
        Ok(())
    }

    #[test]
    fn persisted_session_into_app_session_covers_version_and_legacy_fallbacks()
    -> Result<(), Box<dyn std::error::Error>> {
        let session = build_test_session(
            0xCAFE,
            "https://example.invalid",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "legacy",
        )?;

        let mut unsupported = PersistedSession::from_session(&session);
        unsupported.version = 999;
        assert!(
            unsupported.into_app_session().is_err(),
            "unsupported persisted session versions must be rejected"
        );

        let mut persisted = PersistedSession::from_session(&session);
        persisted.regular_fingerprint_hex.clear();
        persisted.forward_state.fs_last_weid_hex.clear();
        persisted.fs_epoch_created_at_unix_ms = 0;

        let restored = persisted.into_app_session()?;
        assert!(
            restored.regular_fingerprint.is_none(),
            "empty regular fingerprint should deserialize as missing"
        );
        assert_eq!(
            restored.forward_state.snapshot().last_weid,
            restored.we_epoch_id,
            "missing forward_state.last_weid should fall back to we_epoch_id"
        );
        let restored_ms = restored
            .fs_epoch_created_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        assert!(
            restored_ms > 0,
            "zero persisted epoch timestamp should fall back to current time"
        );
        Ok(())
    }

    #[tokio::test]
    async fn epoch_sync_adopts_new_member_head() -> Result<(), Box<dyn std::error::Error>> {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let _restore = KbroadEnvVarRestore {
            original: std::env::var(KBROAD_SECRET_ENV).ok(),
        };
        let _public_restore = KbroadPublicEnvVarRestore {
            original: std::env::var(KBROAD_PUBLIC_ENV).ok(),
        };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::set_var(KBROAD_SECRET_ENV, hex_encode(demo::kbroad_secret())) };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_PUBLIC_ENV) };

        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex_encode([0x44u8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;

        let mut alice = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?;
        alice.barrier_state.barrier_recovery_pending = false;
        let mut bob = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?;
        bob.barrier_state.barrier_recovery_pending = false;
        assert_ne!(
            alice.we_epoch_id, bob.we_epoch_id,
            "second join should advance the epoch head"
        );

        let sync = perform_epoch_sync(alice.clone()).await?;
        assert!(sync.changed, "sync should detect and adopt newer head");
        assert_eq!(sync.session.we_epoch_id, bob.we_epoch_id);
        assert_eq!(
            sync.session.epoch_key, bob.epoch_key,
            "adopted session should derive current epoch key"
        );

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn epoch_sync_noop_when_already_current() -> Result<(), Box<dyn std::error::Error>> {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let _secret_restore = KbroadEnvVarRestore {
            original: std::env::var(KBROAD_SECRET_ENV).ok(),
        };
        let _public_restore = KbroadPublicEnvVarRestore {
            original: std::env::var(KBROAD_PUBLIC_ENV).ok(),
        };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_SECRET_ENV) };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_PUBLIC_ENV) };

        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex_encode([0x55u8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;

        let alice = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?;
        let sync = perform_epoch_sync(alice.clone()).await?;

        let barrier_delta = sync.session.barrier_state.barrier_version
            != alice.barrier_state.barrier_version
            || sync.session.barrier_state.k_barrier != alice.barrier_state.k_barrier
            || sync.session.barrier_state.kem_tree_hash_after
                != alice.barrier_state.kem_tree_hash_after
            || sync.session.barrier_state.n_max != alice.barrier_state.n_max
            || sync.session.barrier_state.cover_leaf_index != alice.barrier_state.cover_leaf_index;
        assert_eq!(
            sync.changed, barrier_delta,
            "sync.changed should reflect barrier-only reconciliation when head is unchanged"
        );
        assert_eq!(sync.session.we_epoch_id, alice.we_epoch_id);
        assert_eq!(sync.session.epoch_key, alice.epoch_key);

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn sequential_member_leaves_succeed() -> Result<(), Box<dyn std::error::Error>> {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let _secret_restore = KbroadEnvVarRestore {
            original: std::env::var(KBROAD_SECRET_ENV).ok(),
        };
        let _public_restore = KbroadPublicEnvVarRestore {
            original: std::env::var(KBROAD_PUBLIC_ENV).ok(),
        };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_SECRET_ENV) };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_PUBLIC_ENV) };

        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let mut room_id_bytes = [0x66u8; 32];
        room_id_bytes[..2].copy_from_slice(&port.to_le_bytes());
        let room_id = hex_encode(room_id_bytes);
        bootstrap_test_room(&server_url, &room_id).await?;

        let mut alice = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?;
        alice.barrier_state.barrier_recovery_pending = false;
        let mut bob = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?;
        bob.barrier_state.barrier_recovery_pending = false;

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

        persist_session(&alice)?;
        perform_leave(LeaveRequest::from_session(&alice)).await?;
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

        // Membership changes require KBROAD rotation before the next merge ticket.
        let (rotated_kbroad_public, _) = generate_kbroad_keypair();
        client
            .rotate_room_kbroad(&room_id, &rotated_kbroad_public)
            .await?;

        persist_session(&bob)?;
        perform_leave(LeaveRequest::from_session(&bob)).await?;
        let after_bob_leave = client.members(&alice.gid, None).await?;
        assert_eq!(after_bob_leave.total_count, 0);
        assert!(after_bob_leave.members.is_empty());

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn send_fetch_and_members_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let _restore = KbroadEnvVarRestore {
            original: std::env::var(KBROAD_SECRET_ENV).ok(),
        };
        let _public_restore = KbroadPublicEnvVarRestore {
            original: std::env::var(KBROAD_PUBLIC_ENV).ok(),
        };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::set_var(KBROAD_SECRET_ENV, hex_encode(demo::kbroad_secret())) };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_PUBLIC_ENV) };

        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex_encode([0x77u8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;

        let mut alice = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?;
        alice.barrier_state.barrier_recovery_pending = false;
        let mut bob = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?;
        bob.barrier_state.barrier_recovery_pending = false;

        let members =
            perform_fetch_members(MembersParams::from_session(&bob, 0, 50, MembersMode::Full))
                .await?;
        assert!(
            members.total_count >= members.members.len() as u64,
            "total_count should bound page length"
        );
        assert!(
            members.next_offset >= members.members.len() as u64 || members.next_offset == 0,
            "next_offset should be coherent with page size"
        );

        let search = perform_fetch_members(MembersParams::from_session(
            &bob,
            0,
            50,
            MembersMode::Search {
                query: "ali".to_string(),
            },
        ))
        .await?;
        assert!(
            search.total_count >= search.members.len() as u64,
            "search total_count should bound page length"
        );

        let plaintext = "hello-from-bob".to_string();
        let sent = perform_send(SendParams::from_session(&bob, plaintext.clone(), 0)?).await?;
        assert_eq!(sent.plaintext, plaintext);
        assert_eq!(sent.sender_leaf, Some(bob.leaf_id));

        let stale_fetch = perform_fetch(FetchParams::from_session(&alice, None)?).await?;
        assert!(
            stale_fetch
                .messages
                .iter()
                .all(|message| message.plaintext != plaintext),
            "pre-sync fetch should not decrypt messages from a newer epoch"
        );

        let alice_members = perform_fetch_members(MembersParams::from_session(
            &alice,
            0,
            50,
            MembersMode::Full,
        ))
        .await?;
        let mut alice_with_latest_root = alice.clone();
        alice_with_latest_root.parent_root = alice_members.root;
        let synced_alice = perform_epoch_sync(alice_with_latest_root).await?;
        assert!(
            synced_alice.changed,
            "epoch sync should adopt latest head after another member joins"
        );

        let mut synced_alice_session = synced_alice.session;
        synced_alice_session.barrier_state.barrier_recovery_pending = false;
        let synced_fetch =
            perform_fetch(FetchParams::from_session(&synced_alice_session, None)?).await?;
        assert!(
            synced_fetch
                .messages
                .iter()
                .any(|message| message.plaintext == plaintext
                    && message.sender_leaf == Some(bob.leaf_id)),
            "post-sync fetch should include messages from the latest epoch"
        );

        let fetched = perform_fetch(FetchParams::from_session(&bob, None)?).await?;
        assert!(
            !fetched.messages.is_empty(),
            "fetch should return at least one message"
        );
        assert!(
            fetched
                .messages
                .iter()
                .any(|message| message.plaintext == plaintext
                    && message.sender_leaf == Some(bob.leaf_id)),
            "fetch should include sent message"
        );

        let since = fetched.last_timestamp_ms;
        let fetched_after = perform_fetch(FetchParams::from_session(&bob, since)?).await?;
        if let Some(threshold) = since {
            assert!(
                fetched_after
                    .messages
                    .iter()
                    .all(|message| message.timestamp_ms > threshold),
                "since filter must drop already-seen messages"
            );
        }

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[test]
    #[ignore = "manual benchmark for msg_index persistence cost"]
    fn benchmark_msg_index_persistence_cost_profile() -> Result<(), Box<dyn std::error::Error>> {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));
        let mut session = build_test_session(0xBEEF, "http://127.0.0.1:9", "bench-room", "bench")?;

        let iterations: u64 = 2_000;
        let start_counter = std::time::Instant::now();
        let mut counter: u64 = 0;
        for _ in 0..iterations {
            counter = counter.saturating_add(1);
        }
        let counter_elapsed = start_counter.elapsed();
        assert_eq!(counter, iterations);

        let start_persist = std::time::Instant::now();
        for i in 0..iterations {
            session.last_fetch_timestamp_ms = Some(i);
            persist_session(&session)?;
        }
        let persist_elapsed = start_persist.elapsed();

        let persist_ops = (iterations as f64) / persist_elapsed.as_secs_f64().max(1e-9);
        let persist_ms = persist_elapsed.as_secs_f64() * 1_000.0 / (iterations as f64);
        let counter_ops = (iterations as f64) / counter_elapsed.as_secs_f64().max(1e-9);
        eprintln!(
            "BENCH[msg_index_persist] iterations={iterations} persist_total_ms={:.2} persist_per_op_ms={persist_ms:.4} persist_ops_per_sec={persist_ops:.1} counter_ops_per_sec={counter_ops:.1}",
            persist_elapsed.as_secs_f64() * 1_000.0
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore = "manual benchmark for send throughput with and without msg_index persistence"]
    async fn benchmark_send_throughput_with_vs_without_msg_index_persist()
    -> Result<(), Box<dyn std::error::Error>> {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let _secret_restore = KbroadEnvVarRestore {
            original: std::env::var(KBROAD_SECRET_ENV).ok(),
        };
        let _public_restore = KbroadPublicEnvVarRestore {
            original: std::env::var(KBROAD_PUBLIC_ENV).ok(),
        };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::set_var(KBROAD_SECRET_ENV, hex_encode(demo::kbroad_secret())) };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_PUBLIC_ENV) };

        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));

        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex_encode([0xE1u8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;
        let session = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id,
            alias: "bench-sender".to_string(),
        })
        .await?;

        let iterations: u64 = 120;
        let mut msg_index: u64 = 0;

        for i in 0..10u64 {
            perform_send(SendParams::from_session(
                &session,
                format!("warmup-no-persist-{i}"),
                msg_index,
            )?)
            .await?;
            msg_index = msg_index.saturating_add(1);
        }

        let no_persist_start = std::time::Instant::now();
        for i in 0..iterations {
            perform_send(SendParams::from_session(
                &session,
                format!("bench-no-persist-{i}"),
                msg_index,
            )?)
            .await?;
            msg_index = msg_index.saturating_add(1);
        }
        let no_persist_elapsed = no_persist_start.elapsed();

        let mut strict_session = session.clone();
        let mut strict_msg_index = msg_index;
        let persist_start = std::time::Instant::now();
        for i in 0..iterations {
            let current = strict_msg_index;
            strict_msg_index = strict_msg_index.saturating_add(1);
            strict_session.last_fetch_timestamp_ms = Some(current);
            persist_session(&strict_session)?;
            perform_send(SendParams::from_session(
                &strict_session,
                format!("bench-with-persist-{i}"),
                current,
            )?)
            .await?;
        }
        let persist_elapsed = persist_start.elapsed();

        let no_persist_tps = (iterations as f64) / no_persist_elapsed.as_secs_f64().max(1e-9);
        let persist_tps = (iterations as f64) / persist_elapsed.as_secs_f64().max(1e-9);
        eprintln!(
            "BENCH[send_throughput] iterations={iterations} no_persist_total_ms={:.2} no_persist_msg_per_sec={no_persist_tps:.1} with_persist_total_ms={:.2} with_persist_msg_per_sec={persist_tps:.1}",
            no_persist_elapsed.as_secs_f64() * 1_000.0,
            persist_elapsed.as_secs_f64() * 1_000.0
        );

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "manual benchmark for barrier chain-check latency and large-n hashing"]
    async fn benchmark_barrier_chain_check_latency_profile()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::Arc;

        fn synthetic_entries(n_max: u64) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
            let n_max_usize = usize::try_from(n_max)?;
            let total = n_max_usize
                .checked_mul(2)
                .and_then(|v| v.checked_sub(1))
                .ok_or_else(|| anyhow!("synthetic entry length overflow"))?;
            let mut out = Vec::with_capacity(total);
            for i in 0..total {
                if i % 7 == 0 {
                    out.push(vec![0xA5; 1184]);
                } else {
                    out.push(Vec::new());
                }
            }
            Ok(out)
        }

        let mut hash_profiles = Vec::new();
        for &n_max in &[1024u64, 2048u64] {
            let mut entries_post = synthetic_entries(n_max)?;
            let entries_pre = synthetic_entries(n_max)?;
            // Simulate post-update tree delta on a handful of nodes.
            for idx in (0..entries_post.len()).step_by(257) {
                entries_post[idx] = vec![0x5A; 1184];
            }
            let pre = Arc::new(entries_pre);
            let post = Arc::new(entries_post);
            let rounds = 20u64;
            let cpu_start = std::time::Instant::now();
            let mut last = [0u8; 32];
            for _ in 0..rounds {
                let before = compute_barrier_tree_hash(n_max, pre.as_slice())?;
                let after = compute_barrier_tree_hash(n_max, post.as_slice())?;
                last = before;
                for i in 0..last.len() {
                    last[i] ^= after[i];
                }
            }
            let cpu_elapsed = cpu_start.elapsed();

            let blocking_start = std::time::Instant::now();
            for _ in 0..rounds {
                let pre = Arc::clone(&pre);
                let post = Arc::clone(&post);
                let _: ([u8; 32], [u8; 32]) =
                    tokio::task::spawn_blocking(move || -> Result<_, anyhow::Error> {
                        Ok((
                            compute_barrier_tree_hash(n_max, pre.as_slice())?,
                            compute_barrier_tree_hash(n_max, post.as_slice())?,
                        ))
                    })
                    .await??;
            }
            let blocking_elapsed = blocking_start.elapsed();
            hash_profiles.push((n_max, cpu_elapsed, blocking_elapsed, rounds, last));
        }

        for (n_max, cpu_elapsed, blocking_elapsed, rounds, last) in hash_profiles {
            let cpu_per_round_ms = cpu_elapsed.as_secs_f64() * 1_000.0 / (rounds as f64);
            let blocking_per_round_ms = blocking_elapsed.as_secs_f64() * 1_000.0 / (rounds as f64);
            eprintln!(
                "BENCH[barrier_chain_check] n_max={n_max} rounds={rounds} cpu_total_ms={:.2} cpu_mean_ms={cpu_per_round_ms:.3} spawn_blocking_total_ms={:.2} spawn_blocking_mean_ms={blocking_per_round_ms:.3} hash_prefix={}",
                cpu_elapsed.as_secs_f64() * 1_000.0,
                blocking_elapsed.as_secs_f64() * 1_000.0,
                hex_encode(&last[..4])
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn members_fetch_recovers_from_stale_parent_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let _secret_restore = KbroadEnvVarRestore {
            original: std::env::var(KBROAD_SECRET_ENV).ok(),
        };
        let _public_restore = KbroadPublicEnvVarRestore {
            original: std::env::var(KBROAD_PUBLIC_ENV).ok(),
        };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_SECRET_ENV) };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_PUBLIC_ENV) };

        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex_encode([0x79u8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;

        let _alice = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?;
        let mut bob = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?;

        // Simulate stale local state (e.g., restored session with outdated parent_root).
        bob.parent_root = [0xAB; 32];

        let members =
            perform_fetch_members(MembersParams::from_session(&bob, 0, 50, MembersMode::Full))
                .await?;
        assert!(
            !members.members.is_empty(),
            "fallback to latest root should return members"
        );
        assert_ne!(
            members.root, [0xAB; 32],
            "fallback should adopt the server-reported root"
        );

        let search = perform_fetch_members(MembersParams::from_session(
            &bob,
            0,
            50,
            MembersMode::Search {
                query: "ali".to_string(),
            },
        ))
        .await?;
        assert!(
            search.total_count >= search.members.len() as u64,
            "search fallback should produce coherent pagination metadata"
        );

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn members_fetch_recovers_from_stale_parent_root_on_nonzero_offset()
    -> Result<(), Box<dyn std::error::Error>> {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let _secret_restore = KbroadEnvVarRestore {
            original: std::env::var(KBROAD_SECRET_ENV).ok(),
        };
        let _public_restore = KbroadPublicEnvVarRestore {
            original: std::env::var(KBROAD_PUBLIC_ENV).ok(),
        };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_SECRET_ENV) };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_PUBLIC_ENV) };

        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex_encode([0x7Bu8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;

        let _alice = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?;
        let mut bob = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?;

        bob.parent_root = [0xCD; 32];
        let full_page =
            perform_fetch_members(MembersParams::from_session(&bob, 1, 1, MembersMode::Full))
                .await?;
        assert!(
            full_page.total_count >= 2,
            "fallback on nonzero offset should preserve roster total"
        );
        assert_ne!(
            full_page.root, [0xCD; 32],
            "fallback should replace stale root on nonzero offset"
        );

        let search_page = perform_fetch_members(MembersParams::from_session(
            &bob,
            1,
            1,
            MembersMode::Search {
                query: "a".to_string(),
            },
        ))
        .await?;
        assert!(
            search_page.total_count >= search_page.members.len() as u64,
            "search fallback should return coherent pagination metadata"
        );

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn members_fetch_prefers_latest_root_when_old_root_is_still_valid()
    -> Result<(), Box<dyn std::error::Error>> {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let _secret_restore = KbroadEnvVarRestore {
            original: std::env::var(KBROAD_SECRET_ENV).ok(),
        };
        let _public_restore = KbroadPublicEnvVarRestore {
            original: std::env::var(KBROAD_PUBLIC_ENV).ok(),
        };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_SECRET_ENV) };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_PUBLIC_ENV) };

        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex_encode([0x7Au8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;

        let mut alice = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?;
        alice.barrier_state.barrier_recovery_pending = false;
        let bob = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?;
        assert_ne!(
            alice.parent_root, bob.parent_root,
            "second join should advance parent root"
        );

        // Alice's root is still valid, but stale. Members fetch should now resolve
        // against latest server root for page 0.
        let page = perform_fetch_members(MembersParams::from_session(
            &alice,
            0,
            50,
            MembersMode::Full,
        ))
        .await?;
        assert!(
            page.total_count >= 2,
            "latest-root roster should include both members"
        );
        assert_ne!(
            page.root, alice.parent_root,
            "page 0 should not remain on stale local root"
        );

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn epoch_sync_rejects_gid_mismatch_between_session_and_bundle()
    -> Result<(), Box<dyn std::error::Error>> {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let _restore = KbroadEnvVarRestore {
            original: std::env::var(KBROAD_SECRET_ENV).ok(),
        };
        let _public_restore = KbroadPublicEnvVarRestore {
            original: std::env::var(KBROAD_PUBLIC_ENV).ok(),
        };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::set_var(KBROAD_SECRET_ENV, hex_encode(demo::kbroad_secret())) };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_PUBLIC_ENV) };

        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex_encode([0x7Cu8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;

        let mut alice = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?;
        alice.barrier_state.barrier_recovery_pending = false;
        let _bob = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?;

        let mut mismatched = alice.clone();
        mismatched.gid = [0xEE; 32];
        let err = match perform_epoch_sync(mismatched).await {
            Ok(_) => return Err(anyhow!("epoch sync should fail when gid mismatches").into()),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("bundle gid mismatch"),
            "expected explicit gid mismatch error: {err}"
        );

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn epoch_sync_requires_kbroad_secret_for_redacted_bundle_derivation()
    -> Result<(), Box<dyn std::error::Error>> {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let _restore = KbroadEnvVarRestore {
            original: std::env::var(KBROAD_SECRET_ENV).ok(),
        };
        let _public_restore = KbroadPublicEnvVarRestore {
            original: std::env::var(KBROAD_PUBLIC_ENV).ok(),
        };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_SECRET_ENV) };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_PUBLIC_ENV) };

        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex_encode([0x7Du8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;

        let mut alice = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?;
        let _bob = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?;

        alice.kbroad_secret.clear();
        let err = match perform_epoch_sync(alice).await {
            Ok(_) => {
                return Err(anyhow!(
                    "epoch sync should require KBROAD secret for redacted bundles"
                )
                .into());
            }
            Err(err) => err,
        };
        let err_text = err.to_string();
        assert!(
            err_text.contains(KBROAD_SECRET_ENV) || err_text.contains("failed to derive epoch key"),
            "expected KBROAD derivation failure detail: {err_text}"
        );

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn perform_join_succeeds_with_bootstrap_disabled()
    -> Result<(), Box<dyn std::error::Error>> {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let _secret_restore = KbroadEnvVarRestore {
            original: std::env::var(KBROAD_SECRET_ENV).ok(),
        };
        let _public_restore = KbroadPublicEnvVarRestore {
            original: std::env::var(KBROAD_PUBLIC_ENV).ok(),
        };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_SECRET_ENV) };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_PUBLIC_ENV) };

        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
        let handle = spawn_server_with_seed_demo_room(port, false).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex_encode([0x88u8; 32]);
        new_api_client(&server_url)
            .bootstrap_room(&room_id, demo::kbroad_public())
            .await?;

        let alice = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?;
        assert!(
            alice.bootstrap_public.is_empty(),
            "bootstrap key should be absent when bootstrap policy is disabled"
        );

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn perform_join_populates_barrier_leaf_key_material()
    -> Result<(), Box<dyn std::error::Error>> {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let _secret_restore = KbroadEnvVarRestore {
            original: std::env::var(KBROAD_SECRET_ENV).ok(),
        };
        let _public_restore = KbroadPublicEnvVarRestore {
            original: std::env::var(KBROAD_PUBLIC_ENV).ok(),
        };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_SECRET_ENV) };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_PUBLIC_ENV) };

        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
        let handle = spawn_server_with_seed_demo_room(port, false).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex_encode([0x8Fu8; 32]);
        new_api_client(&server_url)
            .bootstrap_room(&room_id, demo::kbroad_public())
            .await?;

        let session = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "barrier-keys".to_string(),
        })
        .await?;

        assert_eq!(
            session.barrier_state.dk_leaf.len(),
            kyber768::secret_key_bytes(),
            "join should persist ML-KEM leaf private key material"
        );
        assert_ne!(
            session.barrier_state.pkhash_leaf, [0u8; 32],
            "join should persist non-zero leaf public key hash"
        );

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn perform_leave_rejects_while_barrier_recovery_is_pending()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut session =
            build_test_session(0xC31, "http://127.0.0.1:9", "room-leave-guard", "alice")?;
        session.barrier_state.barrier_recovery_pending = true;

        let err = perform_leave(LeaveRequest::from_session(&session))
            .await
            .expect_err("leave should be blocked while barrier recovery is pending");
        assert!(
            err.to_string()
                .contains("complete FULL barrier recovery first"),
            "expected explicit recover-before-update guidance: {err}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn perform_pcs_refresh_rejects_while_barrier_recovery_is_pending()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut session =
            build_test_session(0xC32, "http://127.0.0.1:9", "room-refresh-guard", "alice")?;
        session.barrier_state.barrier_recovery_pending = true;

        let err = perform_pcs_refresh(LeaveRequest::from_session(&session))
            .await
            .expect_err("pcs refresh should be blocked while barrier recovery is pending");
        assert!(
            err.to_string()
                .contains("complete FULL barrier recovery first"),
            "expected explicit recover-before-update guidance: {err}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn perform_join_bootstraps_unprovisioned_room() -> Result<(), Box<dyn std::error::Error>>
    {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let _secret_restore = KbroadEnvVarRestore {
            original: std::env::var(KBROAD_SECRET_ENV).ok(),
        };
        let _public_restore = KbroadPublicEnvVarRestore {
            original: std::env::var(KBROAD_PUBLIC_ENV).ok(),
        };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_SECRET_ENV) };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_PUBLIC_ENV) };

        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
        let handle = spawn_server_with_seed_demo_room(port, false).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex_encode([0x89u8; 32]);

        let session = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?;
        assert!(
            !session.kbroad_public.is_empty(),
            "auto-bootstrap join should persist room KBROAD public key"
        );
        assert!(
            !session.kbroad_secret.is_empty(),
            "auto-bootstrap join should persist generated KBROAD secret"
        );

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn perform_join_bootstraps_with_configured_kbroad_material()
    -> Result<(), Box<dyn std::error::Error>> {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let _secret_restore = KbroadEnvVarRestore {
            original: std::env::var(KBROAD_SECRET_ENV).ok(),
        };
        let _public_restore = KbroadPublicEnvVarRestore {
            original: std::env::var(KBROAD_PUBLIC_ENV).ok(),
        };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::set_var(KBROAD_SECRET_ENV, hex_encode(demo::kbroad_secret())) };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::set_var(KBROAD_PUBLIC_ENV, hex_encode(demo::kbroad_public())) };

        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
        let handle = spawn_server_with_seed_demo_room(port, false).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex_encode([0x8Du8; 32]);
        let session = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id,
            alias: "alice".to_string(),
        })
        .await?;
        assert_eq!(
            session.kbroad_public,
            demo::kbroad_public(),
            "configured KBROAD public should match room key"
        );
        assert_eq!(
            session.kbroad_secret,
            demo::kbroad_secret(),
            "configured KBROAD secret should be persisted in session"
        );

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn perform_join_errors_when_kbroad_secret_set_without_public_on_unprovisioned_room()
    -> Result<(), Box<dyn std::error::Error>> {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let _secret_restore = KbroadEnvVarRestore {
            original: std::env::var(KBROAD_SECRET_ENV).ok(),
        };
        let _public_restore = KbroadPublicEnvVarRestore {
            original: std::env::var(KBROAD_PUBLIC_ENV).ok(),
        };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::set_var(KBROAD_SECRET_ENV, hex_encode(demo::kbroad_secret())) };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_PUBLIC_ENV) };

        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
        let handle = spawn_server_with_seed_demo_room(port, false).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex_encode([0x8Au8; 32]);
        let err = match perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id,
            alias: "alice".to_string(),
        })
        .await
        {
            Ok(_) => return Err(anyhow!("join should fail when only KBROAD secret is set").into()),
            Err(err) => err,
        };
        let err_text = err.to_string();
        assert!(
            err_text.contains(KBROAD_SECRET_ENV) && err_text.contains(KBROAD_PUBLIC_ENV),
            "error should explain missing paired KBROAD public env var: {err_text}"
        );

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn perform_join_rejects_configured_kbroad_public_that_does_not_match_room()
    -> Result<(), Box<dyn std::error::Error>> {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let _secret_restore = KbroadEnvVarRestore {
            original: std::env::var(KBROAD_SECRET_ENV).ok(),
        };
        let _public_restore = KbroadPublicEnvVarRestore {
            original: std::env::var(KBROAD_PUBLIC_ENV).ok(),
        };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_SECRET_ENV) };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::set_var(KBROAD_PUBLIC_ENV, hex_encode(vec![0xEE; 1184])) };

        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
        let handle = spawn_server_with_seed_demo_room(port, false).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex_encode([0x8Bu8; 32]);
        new_api_client(&server_url)
            .bootstrap_room(&room_id, demo::kbroad_public())
            .await?;

        let err = match perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id,
            alias: "alice".to_string(),
        })
        .await
        {
            Ok(_) => {
                return Err(anyhow!("join should fail when KBROAD public does not match").into());
            }
            Err(err) => err,
        };
        let err_text = err.to_string();
        assert!(
            err_text.contains(KBROAD_PUBLIC_ENV) && err_text.contains("does not match"),
            "error should report KBROAD public mismatch: {err_text}"
        );

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[tokio::test]
    async fn perform_fetch_skips_malformed_ciphertexts_and_invalid_auth_envelopes()
    -> Result<(), Box<dyn std::error::Error>> {
        let _env_lock = ENV_VAR_LOCK
            .lock()
            .map_err(|_| anyhow!("env var lock poisoned"))?;
        let _secret_restore = KbroadEnvVarRestore {
            original: std::env::var(KBROAD_SECRET_ENV).ok(),
        };
        let _public_restore = KbroadPublicEnvVarRestore {
            original: std::env::var(KBROAD_PUBLIC_ENV).ok(),
        };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_SECRET_ENV) };
        // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
        unsafe { std::env::remove_var(KBROAD_PUBLIC_ENV) };

        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
        let handle = spawn_server_on(port).await;
        sleep(Duration::from_millis(250)).await;

        let server_url = format!("http://127.0.0.1:{port}");
        let room_id = hex_encode([0x8Cu8; 32]);
        bootstrap_test_room(&server_url, &room_id).await?;

        let mut alice = perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?;
        alice.barrier_state.barrier_recovery_pending = false;

        let client = new_api_client(&server_url);
        client
            .send_message(
                &alice.we_epoch_id,
                &[0x01, 0x02, 0x03],
                Some(&alice.leaf_id),
            )
            .await?;

        let short_payload = encrypt_message(b"tiny", &alice.epoch_key)?;
        client
            .send_message(&alice.we_epoch_id, &short_payload, Some(&alice.leaf_id))
            .await?;

        let mut wrong_prefix = encode_authenticated_message(
            2,
            &vec![b'a'; 2100],
            &vec![0x11; ml_dsa_public_key_bytes()],
            &vec![0x22; ml_dsa_signature_bytes()],
        );
        wrong_prefix[0] = b'X';
        let wrong_prefix_ct = encrypt_message(&wrong_prefix, &alice.epoch_key)?;
        client
            .send_message(&alice.we_epoch_id, &wrong_prefix_ct, Some(&alice.leaf_id))
            .await?;

        let short_public_key = encode_authenticated_message(
            3,
            &vec![b'b'; 2200],
            b"pk",
            &vec![0x33; ml_dsa_signature_bytes()],
        );
        let short_public_key_ct = encrypt_message(&short_public_key, &alice.epoch_key)?;
        client
            .send_message(
                &alice.we_epoch_id,
                &short_public_key_ct,
                Some(&alice.leaf_id),
            )
            .await?;

        let short_signature = encode_authenticated_message(
            4,
            &vec![b'c'; 3500],
            &vec![0x44; ml_dsa_public_key_bytes()],
            b"sig",
        );
        let short_signature_ct = encrypt_message(&short_signature, &alice.epoch_key)?;
        client
            .send_message(
                &alice.we_epoch_id,
                &short_signature_ct,
                Some(&alice.leaf_id),
            )
            .await?;

        let invalid_signature = encode_authenticated_message(
            5,
            b"invalid-signature",
            &vec![0x55; ml_dsa_public_key_bytes()],
            &vec![0x66; ml_dsa_signature_bytes()],
        );
        let invalid_signature_ct = encrypt_message(&invalid_signature, &alice.epoch_key)?;
        client
            .send_message(
                &alice.we_epoch_id,
                &invalid_signature_ct,
                Some(&alice.leaf_id),
            )
            .await?;

        let senderless_payload = encode_authenticated_message(
            6,
            &vec![b'd'; 2200],
            &vec![0x77; ml_dsa_public_key_bytes()],
            &vec![0x88; ml_dsa_signature_bytes()],
        );
        let senderless_payload_ct = encrypt_message(&senderless_payload, &alice.epoch_key)?;
        let senderless_err = client
            .send_message(&alice.we_epoch_id, &senderless_payload_ct, None)
            .await
            .expect_err("server should reject messages without a sender leaf");
        assert!(
            senderless_err
                .to_string()
                .contains("sender must be 32 bytes"),
            "missing sender should fail validation"
        );

        let marker = "valid-message-marker".to_string();
        perform_send(SendParams::from_session(&alice, marker.clone(), 0)?).await?;

        let fetched = perform_fetch(FetchParams::from_session(&alice, None)?).await?;
        assert!(
            fetched
                .messages
                .iter()
                .any(|message| message.plaintext == marker),
            "valid authenticated messages should still be returned"
        );
        assert!(
            fetched
                .messages
                .iter()
                .all(|message| message.ciphertext_hex != hex_encode(&short_payload)),
            "messages failing minimum authenticated size should be skipped"
        );
        assert!(
            fetched
                .messages
                .iter()
                .all(|message| message.ciphertext_hex != hex_encode(&wrong_prefix_ct)),
            "messages with invalid authenticated prefix should be skipped"
        );
        assert!(
            fetched
                .messages
                .iter()
                .all(|message| message.ciphertext_hex != hex_encode(&invalid_signature_ct)),
            "messages with invalid signatures should be skipped"
        );

        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[test]
    fn encrypt_decrypt_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let key = [42u8; 32];
        let plaintext = b"Hello, City-G! This is a test message.";

        let ciphertext = encrypt_message(plaintext, &key)?;
        let decrypted = decrypt_message(&ciphertext, &key)?;

        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn payload_envelope_v2_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let gid = [0x11u8; 32];
        let we_epoch_id = [0x22u8; 32];
        let xk_hash = [0x23u8; 32];
        let epoch_key = [0x33u8; 32];
        let k_barrier = [0x44u8; 32];
        let sender_leaf = [0x45u8; 32];
        let context = MessageCryptoContext {
            gid: &gid,
            we_epoch_id: &we_epoch_id,
            xk_hash: &xk_hash,
            fs_ec: 9,
            barrier_version: 5,
            sender_leaf: &sender_leaf,
            epoch_key: &epoch_key,
            k_barrier: &k_barrier,
        };
        let plaintext = b"payload-v2-roundtrip";
        let envelope = encrypt_message_v2(plaintext, &context, 7)?;
        let decrypted = decrypt_message_v2(&envelope, &context)?;
        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn payload_envelope_v2_roundtrip_exposes_msg_index() -> Result<(), Box<dyn std::error::Error>> {
        let gid = [0x71u8; 32];
        let we_epoch_id = [0x72u8; 32];
        let xk_hash = [0x73u8; 32];
        let epoch_key = [0x74u8; 32];
        let k_barrier = [0x75u8; 32];
        let sender_leaf = [0x76u8; 32];
        let context = MessageCryptoContext {
            gid: &gid,
            we_epoch_id: &we_epoch_id,
            xk_hash: &xk_hash,
            fs_ec: 5,
            barrier_version: 2,
            sender_leaf: &sender_leaf,
            epoch_key: &epoch_key,
            k_barrier: &k_barrier,
        };
        let envelope = encrypt_message_v2(b"payload-v2-index", &context, 42)?;
        let (msg_index, decrypted) = decrypt_message_v2_with_index(&envelope, &context)?;
        assert_eq!(msg_index, 42);
        assert_eq!(decrypted, b"payload-v2-index");
        Ok(())
    }

    #[test]
    fn payload_envelope_v2_context_mismatch_fails() -> Result<(), Box<dyn std::error::Error>> {
        let gid = [0x51u8; 32];
        let we_epoch_id = [0x52u8; 32];
        let xk_hash = [0x53u8; 32];
        let epoch_key = [0x53u8; 32];
        let k_barrier = [0x54u8; 32];
        let sender_leaf = [0x55u8; 32];
        let good_context = MessageCryptoContext {
            gid: &gid,
            we_epoch_id: &we_epoch_id,
            xk_hash: &xk_hash,
            fs_ec: 12,
            barrier_version: 4,
            sender_leaf: &sender_leaf,
            epoch_key: &epoch_key,
            k_barrier: &k_barrier,
        };
        let bad_context = MessageCryptoContext {
            barrier_version: 5,
            ..good_context
        };
        let envelope = encrypt_message_v2(b"context-bound", &good_context, 1)?;
        assert!(
            decrypt_message_v2(&envelope, &bad_context).is_err(),
            "barrier_version mismatch must fail decryption"
        );
        Ok(())
    }

    #[test]
    fn payload_envelope_v2_msg_index_changes_ciphertext() -> Result<(), Box<dyn std::error::Error>>
    {
        let gid = [0x61u8; 32];
        let we_epoch_id = [0x62u8; 32];
        let xk_hash = [0x63u8; 32];
        let epoch_key = [0x63u8; 32];
        let k_barrier = [0x64u8; 32];
        let sender_leaf = [0x65u8; 32];
        let context = MessageCryptoContext {
            gid: &gid,
            we_epoch_id: &we_epoch_id,
            xk_hash: &xk_hash,
            fs_ec: 3,
            barrier_version: 1,
            sender_leaf: &sender_leaf,
            epoch_key: &epoch_key,
            k_barrier: &k_barrier,
        };
        let payload_a = encrypt_message_v2(b"same-plaintext", &context, 1)?;
        let payload_b = encrypt_message_v2(b"same-plaintext", &context, 2)?;
        assert_ne!(payload_a, payload_b, "msg_index must influence ciphertext");
        Ok(())
    }

    #[test]
    fn payload_envelope_v2_sender_scope_changes_ciphertext()
    -> Result<(), Box<dyn std::error::Error>> {
        let gid = [0x81u8; 32];
        let we_epoch_id = [0x82u8; 32];
        let xk_hash = [0x83u8; 32];
        let epoch_key = [0x84u8; 32];
        let k_barrier = [0x85u8; 32];
        let sender_leaf_a = [0x86u8; 32];
        let sender_leaf_b = [0x87u8; 32];
        let context_a = MessageCryptoContext {
            gid: &gid,
            we_epoch_id: &we_epoch_id,
            xk_hash: &xk_hash,
            fs_ec: 7,
            barrier_version: 3,
            sender_leaf: &sender_leaf_a,
            epoch_key: &epoch_key,
            k_barrier: &k_barrier,
        };
        let context_b = MessageCryptoContext {
            sender_leaf: &sender_leaf_b,
            ..context_a
        };
        let payload_a = encrypt_message_v2(b"same-plaintext", &context_a, 11)?;
        let payload_b = encrypt_message_v2(b"same-plaintext", &context_b, 11)?;
        assert_ne!(payload_a, payload_b, "sender scope must affect ciphertext");
        assert!(
            decrypt_message_v2(&payload_a, &context_b).is_err(),
            "wrong sender scope must fail decryption"
        );
        Ok(())
    }

    #[test]
    fn msg_replay_state_tracks_multiple_tuples_and_caps_window()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut replay = MsgReplayState::default();
        let tuple_a = [0xA1; 32];
        replay.ensure_tuple(tuple_a);
        for msg_index in 0..(MSG_INDEX_REPLAY_WINDOW as u64 + 8) {
            replay.record(tuple_a, msg_index);
        }
        assert_eq!(replay.len(tuple_a), MSG_INDEX_REPLAY_WINDOW);
        assert!(
            !replay.contains(tuple_a, 0),
            "oldest indices should be evicted"
        );
        assert!(replay.contains(tuple_a, MSG_INDEX_REPLAY_WINDOW as u64 + 7));

        let tuple_b = [0xB2; 32];
        replay.ensure_tuple(tuple_b);
        assert!(
            replay.contains(tuple_a, MSG_INDEX_REPLAY_WINDOW as u64 + 7),
            "adding a second tuple must preserve the first tuple window"
        );
        assert_eq!(replay.len(tuple_b), 0);
        replay.record(tuple_b, 99);
        assert!(replay.contains(tuple_b, 99));
        Ok(())
    }

    #[test]
    fn msg_replay_state_ignores_duplicate_indices() -> Result<(), Box<dyn std::error::Error>> {
        let mut replay = MsgReplayState::default();
        let tuple = [0x42; 32];
        replay.ensure_tuple(tuple);
        replay.record(tuple, 7);
        replay.record(tuple, 7);
        replay.record(tuple, 7);
        assert_eq!(
            replay.len(tuple),
            1,
            "duplicate indices must not grow replay state"
        );
        assert!(replay.contains(tuple, 7));
        Ok(())
    }

    #[test]
    fn msg_replay_state_allows_reuse_after_window_eviction()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut replay = MsgReplayState::default();
        let tuple = [0x55; 32];
        replay.ensure_tuple(tuple);
        for msg_index in 0..=(MSG_INDEX_REPLAY_WINDOW as u64) {
            replay.record(tuple, msg_index);
        }
        assert!(
            !replay.contains(tuple, 0),
            "oldest index must be evicted once window is exceeded"
        );
        replay.record(tuple, 0);
        assert!(
            replay.contains(tuple, 0),
            "evicted index can be re-seen by design outside replay window"
        );
        Ok(())
    }

    #[test]
    fn derive_msg_replay_tuple_tag_changes_with_tuple_inputs()
    -> Result<(), Box<dyn std::error::Error>> {
        let gid = [0x31u8; 32];
        let we_epoch_id = [0x32u8; 32];
        let xk_hash = [0x33u8; 32];
        let epoch_key = [0x34u8; 32];
        let k_barrier = [0x35u8; 32];
        let sender_leaf_a = [0x36u8; 32];
        let sender_leaf_b = [0x37u8; 32];
        let context_a = MessageCryptoContext {
            gid: &gid,
            we_epoch_id: &we_epoch_id,
            xk_hash: &xk_hash,
            fs_ec: 8,
            barrier_version: 1,
            sender_leaf: &sender_leaf_a,
            epoch_key: &epoch_key,
            k_barrier: &k_barrier,
        };
        let context_b = MessageCryptoContext {
            sender_leaf: &sender_leaf_b,
            ..context_a
        };
        let tag_a = derive_msg_replay_tuple_tag(&context_a)?;
        let tag_b = derive_msg_replay_tuple_tag(&context_b)?;
        assert_ne!(tag_a, tag_b, "sender scope must affect replay tuple tag");
        Ok(())
    }

    #[test]
    fn encrypt_produces_different_ciphertexts() -> Result<(), Box<dyn std::error::Error>> {
        let key = [42u8; 32];
        let plaintext = b"Same message, different ciphertext";

        let ciphertext1 = encrypt_message(plaintext, &key)?;
        let ciphertext2 = encrypt_message(plaintext, &key)?;

        // Different nonces should produce different ciphertexts
        assert_ne!(ciphertext1, ciphertext2);

        // But both should decrypt to the same plaintext
        let decrypted1 = decrypt_message(&ciphertext1, &key)?;
        let decrypted2 = decrypt_message(&ciphertext2, &key)?;
        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
        Ok(())
    }

    #[test]
    fn decrypt_with_wrong_key_fails() -> Result<(), Box<dyn std::error::Error>> {
        let correct_key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let plaintext = b"Secret message";

        let ciphertext = encrypt_message(plaintext, &correct_key)?;
        let result = decrypt_message(&ciphertext, &wrong_key);

        assert!(result.is_err(), "Decryption should fail with wrong key");
        let err = match result {
            Err(e) => e,
            Ok(_) => return Err("expected error".into()),
        };
        assert!(
            err.to_string().contains("decryption failed"),
            "Error message should indicate decryption failure"
        );
        Ok(())
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() -> Result<(), Box<dyn std::error::Error>> {
        let key = [42u8; 32];
        let plaintext = b"Authenticated message";

        let mut ciphertext = encrypt_message(plaintext, &key)?;

        // Tamper with the ciphertext (flip a bit in the middle)
        if ciphertext.len() > 20 {
            ciphertext[20] ^= 0x01;
        }

        let result = decrypt_message(&ciphertext, &key);

        assert!(result.is_err(), "Decryption should fail for tampered data");
        let err = match result {
            Err(e) => e,
            Ok(_) => return Err("expected error".into()),
        };
        assert!(
            err.to_string().contains("decryption failed"),
            "Error message should indicate decryption failure"
        );
        Ok(())
    }

    #[test]
    fn decrypt_short_ciphertext_fails() -> Result<(), Box<dyn std::error::Error>> {
        let key = [42u8; 32];
        let short_data = b"short"; // Less than 12 bytes (nonce size)

        let result = decrypt_message(short_data, &key);

        assert!(result.is_err(), "Decryption should fail for short data");
        let err = match result {
            Err(e) => e,
            Ok(_) => return Err("expected error".into()),
        };
        assert!(
            err.to_string().contains("too short"),
            "Error should mention data is too short"
        );
        Ok(())
    }

    #[test]
    fn encrypt_empty_message() -> Result<(), Box<dyn std::error::Error>> {
        let key = [42u8; 32];
        let plaintext = b"";

        let ciphertext = encrypt_message(plaintext, &key)?;
        let decrypted = decrypt_message(&ciphertext, &key)?;

        assert_eq!(decrypted, plaintext);
        assert_eq!(decrypted.len(), 0);
        Ok(())
    }

    #[test]
    fn encrypt_large_message() -> Result<(), Box<dyn std::error::Error>> {
        let key = [42u8; 32];
        let plaintext = vec![b'A'; 10_000]; // 10KB message

        let ciphertext = encrypt_message(&plaintext, &key)?;
        let decrypted = decrypt_message(&ciphertext, &key)?;

        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn ciphertext_format_validation() -> Result<(), Box<dyn std::error::Error>> {
        let key = [42u8; 32];
        let plaintext = b"Test message";

        let ciphertext = encrypt_message(plaintext, &key)?;

        // Ciphertext should be: nonce (12) + encrypted_data + tag (16)
        // Minimum size: 12 (nonce) + 16 (tag) = 28 bytes
        assert!(
            ciphertext.len() >= 28,
            "Ciphertext should be at least 28 bytes (nonce + tag)"
        );

        // For non-empty plaintext, should be larger
        assert_eq!(
            ciphertext.len(),
            12 + plaintext.len() + 16,
            "Ciphertext size should be nonce + plaintext + tag"
        );
        Ok(())
    }

    #[test]
    fn multiple_keys_independence() -> Result<(), Box<dyn std::error::Error>> {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let plaintext = b"Multi-key test";

        let ciphertext1 = encrypt_message(plaintext, &key1)?;
        let ciphertext2 = encrypt_message(plaintext, &key2)?;

        // Same plaintext with different keys should produce different ciphertexts
        assert_ne!(ciphertext1, ciphertext2);

        // Each key should only decrypt its own ciphertext
        assert!(decrypt_message(&ciphertext1, &key1).is_ok());
        assert!(decrypt_message(&ciphertext2, &key2).is_ok());
        assert!(decrypt_message(&ciphertext1, &key2).is_err());
        assert!(decrypt_message(&ciphertext2, &key1).is_err());
        Ok(())
    }

    // ============================================================
    // Tests for categorize_error function
    // ============================================================

    #[test]
    fn categorize_error_connection_refused() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("connection refused by server");
        let result = categorize_error(&err, "join");
        assert!(matches!(result.category, ErrorCategory::Network));
        assert_eq!(result.user_message, "Connection refused");
        assert!(result.can_retry);
        Ok(())
    }

    #[test]
    fn categorize_error_timeout() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("request timeout after 30s");
        let result = categorize_error(&err, "send");
        assert!(matches!(result.category, ErrorCategory::Network));
        assert_eq!(result.user_message, "Connection timeout");
        assert!(result.can_retry);
        Ok(())
    }

    #[test]
    fn categorize_error_dns_failure() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("DNS resolution failed");
        let result = categorize_error(&err, "fetch");
        assert!(matches!(result.category, ErrorCategory::Network));
        assert_eq!(result.user_message, "Unable to connect to server");
        assert!(result.can_retry);
        Ok(())
    }

    #[test]
    fn categorize_error_network_unreachable() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("network unreachable");
        let result = categorize_error(&err, "join");
        assert!(matches!(result.category, ErrorCategory::Network));
        assert_eq!(result.user_message, "Unable to connect to server");
        assert!(result.can_retry);
        Ok(())
    }

    #[test]
    fn categorize_error_404_not_found() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("404 not found");
        let result = categorize_error(&err, "join");
        assert!(matches!(result.category, ErrorCategory::Server));
        assert_eq!(result.user_message, "Resource not found");
        assert!(!result.can_retry);
        Ok(())
    }

    #[test]
    fn stale_server_session_detection_matches_expected_http_errors() {
        let not_found = anyhow!(ApiClientError::HttpStatus {
            status: "404".parse().expect("parse 404 status"),
            message: "resource not found".to_string(),
            freeze_code: None,
            freeze_reason: None,
            failed_index: None,
        });
        assert!(is_stale_server_session_error(&not_found));

        let missing_group = anyhow!(ApiClientError::HttpStatus {
            status: "500".parse().expect("parse 500 status"),
            message: "invalid input: no anchors accepted for group".to_string(),
            freeze_code: None,
            freeze_reason: None,
            failed_index: None,
        });
        assert!(is_stale_server_session_error(&missing_group));

        let unrelated = anyhow!(ApiClientError::HttpStatus {
            status: "500".parse().expect("parse 500 status"),
            message: "internal error".to_string(),
            freeze_code: None,
            freeze_reason: None,
            failed_index: None,
        });
        assert!(!is_stale_server_session_error(&unrelated));
    }

    #[test]
    fn append_messages_dedupes_same_ciphertext_across_timestamp_drift()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));
        let mut model = AppModel::new(CityGConfig::default());
        let leaf = [0x11; 32];

        let first = ChatMessageEntry {
            sender_leaf: Some(leaf),
            fallback_label: "alice".to_string(),
            plaintext: "hello".to_string(),
            ciphertext_hex: "deadbeef".to_string(),
            timestamp_ms: 1_000,
            delivery: MessageDelivery::Sent,
            pending_id: None,
        };
        let second = ChatMessageEntry {
            sender_leaf: Some(leaf),
            fallback_label: "alice".to_string(),
            plaintext: "hello".to_string(),
            ciphertext_hex: "deadbeef".to_string(),
            timestamp_ms: 1_350,
            delivery: MessageDelivery::Sent,
            pending_id: None,
        };

        assert_eq!(model.append_messages(vec![first]), 1);
        assert_eq!(model.append_messages(vec![second]), 0);
        assert_eq!(model.messages.len(), 1);
        Ok(())
    }

    #[test]
    fn validate_members_root_from_leaves_accepts_matching_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let leaves = vec![[0x01; 32], [0x02; 32]];
        let root = canonical_set_root(&leaves)?;
        validate_members_root_from_leaves(root, vec![leaves[1], leaves[0]], 2)?;
        Ok(())
    }

    #[test]
    fn validate_members_root_from_leaves_rejects_duplicates()
    -> Result<(), Box<dyn std::error::Error>> {
        let leaf = [0xAA; 32];
        let result = validate_members_root_from_leaves(leaf, vec![leaf, leaf], 2);
        assert!(
            result.is_err(),
            "duplicate leaves should fail root validation"
        );
        Ok(())
    }

    #[test]
    fn validate_members_root_from_leaves_rejects_incorrect_total_count()
    -> Result<(), Box<dyn std::error::Error>> {
        let leaves = vec![[0x0Au8; 32], [0x0Bu8; 32]];
        let root = canonical_set_root(&leaves)?;
        let result = validate_members_root_from_leaves(root, leaves, 3);
        assert!(
            result
                .as_ref()
                .err()
                .is_some_and(|err| err.to_string().contains("expected 3 leaves")),
            "mismatched roster totals must fail validation: {result:?}"
        );
        Ok(())
    }

    #[test]
    fn activity_log_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));
        let mut model = AppModel::new(CityGConfig::default());

        for index in 0..(MAX_ACTIVITY_EVENTS + 10) {
            model.record_activity(ActivityKind::System, format!("event {index}"));
        }

        assert_eq!(model.activity_events.len(), MAX_ACTIVITY_EVENTS);
        assert_eq!(model.activity_events[0].summary, "event 10");
        let expected_last = format!("event {}", MAX_ACTIVITY_EVENTS + 9);
        assert_eq!(
            model.activity_events.last().map(|e| e.summary.as_str()),
            Some(expected_last.as_str())
        );
        Ok(())
    }

    #[test]
    fn confirm_pending_message_replaces_placeholder() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));
        let mut model = AppModel::new(CityGConfig::default());
        let pending_id = 42;
        let leaf = [0x22; 32];

        model.messages.push(ChatMessageEntry {
            sender_leaf: Some(leaf),
            fallback_label: "sab".to_string(),
            plaintext: "Test".to_string(),
            ciphertext_hex: String::new(),
            timestamp_ms: 2_000,
            delivery: MessageDelivery::Pending,
            pending_id: Some(pending_id),
        });

        model.confirm_pending_message(
            pending_id,
            ChatMessageEntry {
                sender_leaf: Some(leaf),
                fallback_label: "sab".to_string(),
                plaintext: "Test".to_string(),
                ciphertext_hex: "cafebabe".to_string(),
                timestamp_ms: 2_010,
                delivery: MessageDelivery::Sent,
                pending_id: None,
            },
        );

        assert_eq!(model.messages.len(), 1);
        assert_eq!(model.messages[0].ciphertext_hex, "cafebabe");
        assert_eq!(model.messages[0].delivery, MessageDelivery::Sent);
        assert_eq!(model.messages[0].pending_id, None);
        Ok(())
    }

    #[test]
    fn pending_message_lifecycle_marks_failed() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));
        let mut model = AppModel::new(CityGConfig::default());
        let session = build_test_session(
            0xA11CE,
            "http://127.0.0.1:18080",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "alice",
        )?;

        let pending_id = model.queue_pending_message(&session, "hello");
        assert_eq!(model.messages.len(), 1);
        assert_eq!(model.messages[0].delivery, MessageDelivery::Pending);
        assert_eq!(model.messages[0].pending_id, Some(pending_id));
        assert_eq!(model.messages[0].fallback_label, "alice");

        model.mark_pending_message_failed(pending_id);
        assert_eq!(model.messages[0].delivery, MessageDelivery::Failed);
        assert_eq!(model.messages[0].pending_id, None);

        // Missing pending IDs should be ignored.
        model.mark_pending_message_failed(u64::MAX);
        assert_eq!(model.messages.len(), 1);
        Ok(())
    }

    #[test]
    fn render_helpers_cover_session_and_message_list_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));
        let mut model = AppModel::new(CityGConfig::default());

        // No-panics smoke tests for helper UI builders.
        let _ = model.render_spinner();
        let _ = model.session_row("Server", "http://127.0.0.1:18080");

        let mut session = build_test_session(
            0xE0C0,
            "http://127.0.0.1:18080",
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "sab",
        )?;

        session.fs_epoch_created_at = SystemTime::now() - Duration::from_secs(42);
        let _ = model.render_epoch_age_row(&session);
        session.fs_epoch_created_at = SystemTime::now() - Duration::from_secs(15 * 60);
        let _ = model.render_epoch_age_row(&session);
        session.fs_epoch_created_at = SystemTime::now() - Duration::from_secs(3 * 3600);
        let _ = model.render_epoch_age_row(&session);

        // Empty list branch.
        let _ = model.render_message_list();

        model.messages = vec![
            ChatMessageEntry {
                sender_leaf: Some([0x01; 32]),
                fallback_label: "pending".to_string(),
                plaintext: "pending text".to_string(),
                ciphertext_hex: "aa".to_string(),
                timestamp_ms: 1,
                delivery: MessageDelivery::Pending,
                pending_id: Some(1),
            },
            ChatMessageEntry {
                sender_leaf: Some([0x02; 32]),
                fallback_label: "failed".to_string(),
                plaintext: "failed text".to_string(),
                ciphertext_hex: "bb".to_string(),
                timestamp_ms: 2,
                delivery: MessageDelivery::Failed,
                pending_id: None,
            },
            ChatMessageEntry {
                sender_leaf: Some([0x03; 32]),
                fallback_label: "sent".to_string(),
                plaintext: "sent text".to_string(),
                ciphertext_hex: "cc".to_string(),
                timestamp_ms: 3,
                delivery: MessageDelivery::Sent,
                pending_id: None,
            },
        ];
        model.show_ciphertext = false;
        let _ = model.render_message_list();
        model.show_ciphertext = true;
        let _ = model.render_message_list();

        Ok(())
    }

    #[test]
    fn sender_resolution_membership_activity_and_security_persist()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));
        let mut model = AppModel::new(CityGConfig::default());
        let leaf = [0xAB; 32];

        model.members.push(MemberEntry {
            leaf_id: leaf,
            alias: Some("goy".to_string()),
            pop_public_key: Some(vec![0x01]),
            join_timestamp_ms: Some(1),
            last_seen_timestamp_ms: Some(2),
        });
        let from_member = ChatMessageEntry {
            sender_leaf: Some(leaf),
            fallback_label: "fallback".to_string(),
            plaintext: "hello".to_string(),
            ciphertext_hex: "abcd".to_string(),
            timestamp_ms: 100,
            delivery: MessageDelivery::Sent,
            pending_id: None,
        };
        assert!(model.resolve_sender_label(&from_member).contains("goy"));

        model.members.clear();
        model.leaf_alias_index.insert(leaf, "sab".to_string());
        assert!(model.resolve_sender_label(&from_member).contains("sab"));

        model.leaf_alias_index.clear();
        assert_eq!(model.resolve_sender_label(&from_member), "fallback");

        model.record_membership_activity(&MembershipSignal {
            gid: [0x11; 32],
            leaf_id: Some(leaf),
            kind: Some(MembershipSignalKind::Join),
            timestamp_ms: Some(1234),
        });
        model.record_membership_activity(&MembershipSignal {
            gid: [0x11; 32],
            leaf_id: Some(leaf),
            kind: Some(MembershipSignalKind::Revoke),
            timestamp_ms: None,
        });
        model.record_membership_activity(&MembershipSignal {
            gid: [0x11; 32],
            leaf_id: None,
            kind: None,
            timestamp_ms: None,
        });
        assert_eq!(model.activity_events.len(), 3);
        assert!(model.activity_events[0].summary.contains("Roster join"));
        assert!(model.activity_events[1].summary.contains("Roster revoke"));
        assert!(model.activity_events[2].summary.contains("Roster changed"));

        let session = build_test_session(
            0x5EED,
            "http://127.0.0.1:18080",
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            "sab",
        )?;
        model.session = Some(session.clone());
        model.security_events = vec![SecurityEvent {
            alias: "sab".to_string(),
            description: "security check".to_string(),
            timestamp_ms: 88,
        }];
        model.persist_security_events_to_disk();
        let loaded = load_security_log(&session.server_url, &session.room_id)?;
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].description, "security check");

        // Early-return path when no session.
        model.session = None;
        model.persist_security_events_to_disk();
        Ok(())
    }

    #[test]
    fn helper_formatters_cover_http_epoch_and_leaf_paths() -> Result<(), Box<dyn std::error::Error>>
    {
        let no_freeze = describe_http_failure("500", "internal", None, None);
        assert_eq!(no_freeze, "server error (500): internal");

        let freeze_only = describe_http_failure("500", "bad", Some(925), None);
        assert!(freeze_only.contains("[freeze 925]"));

        let freeze_with_reason = describe_http_failure("400", "invalid", Some(910), Some("rho"));
        assert!(freeze_with_reason.contains("[freeze 910 rho]"));

        assert_eq!(default_epoch_rotation_interval(), 300);

        let leaf = [0xCD; 32];
        let short = short_leaf_display(&leaf);
        assert!(short.ends_with('…'));
        assert_eq!(short.chars().count(), 9);
        Ok(())
    }

    #[test]
    fn categorize_error_401_unauthorized() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("401 unauthorized");
        let result = categorize_error(&err, "send");
        assert!(matches!(result.category, ErrorCategory::Policy));
        assert_eq!(result.user_message, "Authentication failed");
        assert!(result.can_retry);
        Ok(())
    }

    #[test]
    fn categorize_error_403_forbidden() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("403 forbidden");
        let result = categorize_error(&err, "leave");
        assert!(matches!(result.category, ErrorCategory::Policy));
        assert_eq!(result.user_message, "Access denied");
        assert!(!result.can_retry);
        Ok(())
    }

    #[test]
    fn categorize_error_crypto_proof_failure() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("proof generation failed");
        let result = categorize_error(&err, "join");
        assert!(matches!(result.category, ErrorCategory::Crypto));
        assert_eq!(result.user_message, "Cryptographic operation failed");
        assert!(result.can_retry);
        Ok(())
    }

    #[test]
    fn categorize_error_crypto_verification() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("verification failed");
        let result = categorize_error(&err, "send");
        assert!(matches!(result.category, ErrorCategory::Crypto));
        assert_eq!(result.user_message, "Cryptographic operation failed");
        assert!(result.can_retry);
        Ok(())
    }

    #[test]
    fn categorize_error_crypto_witness() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("witness bundle generation failed");
        let result = categorize_error(&err, "join");
        assert!(matches!(result.category, ErrorCategory::Crypto));
        assert_eq!(result.user_message, "Cryptographic operation failed");
        assert!(result.can_retry);
        Ok(())
    }

    #[test]
    fn categorize_error_crypto_signature() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("signature validation error");
        let result = categorize_error(&err, "fetch");
        assert!(matches!(result.category, ErrorCategory::Crypto));
        assert_eq!(result.user_message, "Cryptographic operation failed");
        assert!(result.can_retry);
        Ok(())
    }

    #[test]
    fn categorize_error_rho_replay() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("rho_replay detected");
        let result = categorize_error(&err, "send");
        assert!(matches!(result.category, ErrorCategory::Policy));
        assert_eq!(result.user_message, "Duplicate message detected");
        assert!(!result.can_retry);
        Ok(())
    }

    #[test]
    fn categorize_error_freeze_violation() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("freeze policy violated");
        let result = categorize_error(&err, "join");
        assert!(matches!(result.category, ErrorCategory::Policy));
        assert_eq!(result.user_message, "Room policy violation");
        assert!(!result.can_retry);
        Ok(())
    }

    #[test]
    fn categorize_error_policy_check() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("policy check failed");
        let result = categorize_error(&err, "send");
        assert!(matches!(result.category, ErrorCategory::Policy));
        assert_eq!(result.user_message, "Policy check failed");
        assert!(!result.can_retry);
        Ok(())
    }

    #[test]
    fn categorize_error_empty_field() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("field must not be empty");
        let result = categorize_error(&err, "join");
        assert!(matches!(result.category, ErrorCategory::Validation));
        assert_eq!(result.user_message, "Required field missing");
        assert!(!result.can_retry);
        Ok(())
    }

    #[test]
    fn categorize_error_invalid_input() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("invalid room ID format");
        let result = categorize_error(&err, "join");
        assert!(matches!(result.category, ErrorCategory::Validation));
        assert_eq!(result.user_message, "Invalid input");
        assert!(!result.can_retry);
        Ok(())
    }

    #[test]
    fn categorize_error_not_valid() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("room ID is not valid");
        let result = categorize_error(&err, "join");
        assert!(matches!(result.category, ErrorCategory::Validation));
        assert_eq!(result.user_message, "Invalid input");
        assert!(!result.can_retry);
        Ok(())
    }

    #[test]
    fn categorize_error_required_field() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("alias is required");
        let result = categorize_error(&err, "join");
        assert!(matches!(result.category, ErrorCategory::Validation));
        assert_eq!(result.user_message, "Missing required information");
        assert!(!result.can_retry);
        Ok(())
    }

    #[test]
    fn categorize_error_500_internal_server() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("500 internal server error");
        let result = categorize_error(&err, "send");
        assert!(matches!(result.category, ErrorCategory::Server));
        assert_eq!(result.user_message, "Internal server error");
        assert!(result.can_retry);
        Ok(())
    }

    #[test]
    fn categorize_error_502_bad_gateway() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("502 bad gateway");
        let result = categorize_error(&err, "fetch");
        assert!(matches!(result.category, ErrorCategory::Network));
        assert_eq!(result.user_message, "Bad gateway");
        assert!(result.can_retry);
        Ok(())
    }

    #[test]
    fn categorize_error_503_service_unavailable() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("503 service unavailable");
        let result = categorize_error(&err, "join");
        assert!(matches!(result.category, ErrorCategory::Server));
        assert_eq!(result.user_message, "Service temporarily unavailable");
        assert!(result.can_retry);
        Ok(())
    }

    #[test]
    fn categorize_error_generic_server_error() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("server error occurred");
        let result = categorize_error(&err, "send");
        assert!(matches!(result.category, ErrorCategory::Server));
        assert_eq!(result.user_message, "Server error occurred");
        assert!(result.can_retry);
        Ok(())
    }

    #[test]
    fn categorize_error_default_fallback_join() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("some unknown error");
        let result = categorize_error(&err, "join");
        assert!(matches!(result.category, ErrorCategory::Server));
        assert!(result.user_message.contains("Failed to join room"));
        Ok(())
    }

    #[test]
    fn categorize_error_default_fallback_send() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("some unknown error");
        let result = categorize_error(&err, "send");
        assert!(matches!(result.category, ErrorCategory::Server));
        assert!(result.user_message.contains("Failed to send message"));
        Ok(())
    }

    #[test]
    fn categorize_error_default_fallback_leave() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("some unknown error");
        let result = categorize_error(&err, "leave");
        assert!(matches!(result.category, ErrorCategory::Server));
        assert!(result.user_message.contains("Failed to leave room"));
        Ok(())
    }

    #[test]
    fn categorize_error_default_fallback_fetch() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("some unknown error");
        let result = categorize_error(&err, "fetch");
        assert!(matches!(result.category, ErrorCategory::Server));
        assert!(result.user_message.contains("Failed to fetch messages"));
        Ok(())
    }

    #[test]
    fn categorize_error_default_fallback_generic() -> Result<(), Box<dyn std::error::Error>> {
        let err = anyhow!("some unknown error");
        let result = categorize_error(&err, "unknown_context");
        assert!(matches!(result.category, ErrorCategory::Server));
        assert!(result.user_message.contains("Operation failed"));
        Ok(())
    }

    #[test]
    fn categorize_error_case_insensitive() -> Result<(), Box<dyn std::error::Error>> {
        // Test that error matching is case insensitive
        let err1 = anyhow!("CONNECTION REFUSED");
        let result1 = categorize_error(&err1, "join");
        assert!(matches!(result1.category, ErrorCategory::Network));

        let err2 = anyhow!("TIMEOUT");
        let result2 = categorize_error(&err2, "send");
        assert!(matches!(result2.category, ErrorCategory::Network));

        let err3 = anyhow!("PROOF generation failed");
        let result3 = categorize_error(&err3, "join");
        assert!(matches!(result3.category, ErrorCategory::Crypto));
        Ok(())
    }

    // ============================================================
    // Tests for authenticated message encoding/decoding
    // ============================================================

    #[test]
    fn encode_decode_authenticated_message_empty_plaintext()
    -> Result<(), Box<dyn std::error::Error>> {
        let (pk, sk) = dilithium3::keypair();
        let msg_sign_public_key = pk.as_bytes().to_vec();
        let msg_sign_secret_key = sk.as_bytes().to_vec();

        let leaf_id = [0x42u8; 32];
        let plaintext = b"";
        let timestamp_ms = 1_234_567_890u64;

        let signature = sign_message(&leaf_id, timestamp_ms, plaintext, &msg_sign_secret_key)?;
        let authenticated_msg =
            encode_authenticated_message(timestamp_ms, plaintext, &msg_sign_public_key, &signature);

        let envelope = decode_authenticated_message(&authenticated_msg)?;
        assert_eq!(envelope.timestamp_ms, timestamp_ms);
        assert_eq!(envelope.plaintext, plaintext);
        assert_eq!(envelope.public_key, msg_sign_public_key.as_slice());
        assert_eq!(envelope.signature, signature.as_slice());
        Ok(())
    }

    #[test]
    fn encode_decode_authenticated_message_large_plaintext()
    -> Result<(), Box<dyn std::error::Error>> {
        let (pk, sk) = dilithium3::keypair();
        let msg_sign_public_key = pk.as_bytes().to_vec();
        let msg_sign_secret_key = sk.as_bytes().to_vec();

        let leaf_id = [0x42u8; 32];
        let plaintext = vec![b'A'; 5000]; // 5KB message
        let timestamp_ms = 1_234_567_890u64;

        let signature = sign_message(&leaf_id, timestamp_ms, &plaintext, &msg_sign_secret_key)?;
        let authenticated_msg = encode_authenticated_message(
            timestamp_ms,
            &plaintext,
            &msg_sign_public_key,
            &signature,
        );

        let envelope = decode_authenticated_message(&authenticated_msg)?;
        assert_eq!(envelope.timestamp_ms, timestamp_ms);
        assert_eq!(envelope.plaintext, plaintext.as_slice());
        assert_eq!(envelope.public_key, msg_sign_public_key.as_slice());
        assert_eq!(envelope.signature, signature.as_slice());
        Ok(())
    }

    #[test]
    fn decode_authenticated_message_too_short() -> Result<(), Box<dyn std::error::Error>> {
        // Message shorter than minimum size should fail
        let short_data = vec![0u8; 10];
        let result = decode_authenticated_message(&short_data);
        assert!(result.is_err());
        let err = match result {
            Err(e) => e,
            Ok(_) => return Err("expected error".into()),
        };
        assert!(err.to_string().contains("authenticated message too short"));
        Ok(())
    }

    #[test]
    fn decode_authenticated_message_wrong_prefix() -> Result<(), Box<dyn std::error::Error>> {
        let (pk, sk) = dilithium3::keypair();
        let msg_sign_public_key = pk.as_bytes().to_vec();
        let msg_sign_secret_key = sk.as_bytes().to_vec();

        let leaf_id = [0x42u8; 32];
        let plaintext = b"test";
        let timestamp_ms = 1_234_567_890u64;

        let signature = sign_message(&leaf_id, timestamp_ms, plaintext, &msg_sign_secret_key)?;
        let mut authenticated_msg =
            encode_authenticated_message(timestamp_ms, plaintext, &msg_sign_public_key, &signature);

        // Corrupt the prefix
        authenticated_msg[0] ^= 0xFF;

        let result = decode_authenticated_message(&authenticated_msg);
        assert!(result.is_err());
        let err = match result {
            Err(e) => e,
            Ok(_) => return Err("expected error".into()),
        };
        assert!(err.to_string().contains("invalid message prefix"));
        Ok(())
    }

    // ============================================================
    // Tests for CAPSS witness encoding/decoding
    // ============================================================

    #[test]
    fn encode_decode_capss_witness_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        use msphf_rlwe::CapssBranchWitness;
        use rand::{RngCore, SeedableRng, rngs::StdRng};

        let mut rng = StdRng::seed_from_u64(12345);
        let mut random_vec = |len: usize| {
            let mut buf = vec![0u8; len];
            rng.fill_bytes(&mut buf);
            buf
        };

        let witness = CapssWitnessBundle {
            branch_a: CapssBranchWitness {
                branch_artifact: random_vec(24),
                ctx_tag: random_vec(16),
            },
            branch_b: CapssBranchWitness {
                branch_artifact: random_vec(24),
                ctx_tag: random_vec(16),
            },
        };

        let encoded = encode_capss_witness(&witness)?;
        let decoded = decode_capss_witness(&encoded)?;

        assert_eq!(decoded, witness);
        Ok(())
    }

    #[test]
    fn decode_capss_witness_invalid_data() -> Result<(), Box<dyn std::error::Error>> {
        // Try to decode garbage data
        let invalid_data = vec![0xFF; 100];
        let result = decode_capss_witness(&invalid_data);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn decode_capss_witness_empty_data() -> Result<(), Box<dyn std::error::Error>> {
        let empty_data = vec![];
        let result = decode_capss_witness(&empty_data);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn format_regular_fingerprint_blocks_hex() -> Result<(), Box<dyn std::error::Error>> {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let formatted = format_regular_fingerprint(Some(&bytes));
        assert_eq!(formatted, "0001-0203 0405-0607 …");
        Ok(())
    }

    #[test]
    fn format_fs_fingerprint_includes_epoch() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = [0xABu8; 32];
        let formatted = format_fs_fingerprint(Some(&bytes), 42);
        assert_eq!(formatted, "abab-abab abab-abab … · fs_ec 42");
        Ok(())
    }

    #[test]
    fn format_fs_fingerprint_reports_missing() -> Result<(), Box<dyn std::error::Error>> {
        let formatted = format_fs_fingerprint(None, 99);
        assert_eq!(formatted, "Not available");
        Ok(())
    }

    // ============================================================
    // Tests for session removal
    // ============================================================

    #[test]
    fn session_removal_after_persistence() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));

        let mut rng = StdRng::seed_from_u64(999);
        let mut random_vec = |len: usize| {
            let mut buf = vec![0u8; len];
            rng.fill_bytes(&mut buf);
            buf
        };

        let forward_state =
            ForwardSecrecyState::with_state([0xAAu8; 32], 17, [0x55u8; 32], [0x99u8; 32]);
        let capss_witness_bundle = CapssWitnessBundle {
            branch_a: msphf_rlwe::CapssBranchWitness {
                branch_artifact: random_vec(24),
                ctx_tag: random_vec(16),
            },
            branch_b: msphf_rlwe::CapssBranchWitness {
                branch_artifact: random_vec(24),
                ctx_tag: random_vec(16),
            },
        };
        let capss_witness_bytes = encode_capss_witness(&capss_witness_bundle)?;

        let mut session = AppSession {
            server_url: "https://remove-test.example.com".to_string(),
            room_id: "remove-room-123".to_string(),
            alias: "test-user".to_string(),
            gid: [0x01u8; 32],
            cat: [0x02u8; 32],
            leaf_id: [0x03u8; 32],
            parent_root: [0x04u8; 32],
            join_delta_root: [0x05u8; 32],
            revoked_since_root: [0x06u8; 32],
            revoked_root: [0x07u8; 32],
            regular_fingerprint: Some([0x21u8; 32]),
            fs_fingerprint: None,
            tswe_salt_hash: [0x08u8; 32],
            pox_r_commit: [0x09u8; 32],
            we_epoch_id: [0x10u8; 32],
            xk_hash: [0x14u8; 32],
            epoch_key: [0x11u8; 32],
            forward_state,
            fs_ec: 17,
            fs_epoch_commit: [0x12u8; 32],
            fs_dev_prev_commit: [0x13u8; 32],
            fs_epoch_created_at: SystemTime::now(),
            fs_epoch_rotation_interval_secs: 300,
            pop_public_key: random_vec(48),
            pop_secret_key: random_vec(96),
            msg_sign_public_key: random_vec(1952),
            msg_sign_secret_key: random_vec(4032),
            vrf_secret_key: random_vec(32),
            vrf_public_key: random_vec(32),
            kbroad_public: random_vec(24),
            kbroad_secret: random_vec(32),
            bootstrap_public: random_vec(24),
            proof_mode: "lin+zkvrf".to_string(),
            vrf_id: "vrf-demo".to_string(),
            policy_version: "v1".to_string(),
            msphf_crs_id: "rlwe-merkle/v1".to_string(),
            msphf_params_id: "rlwe-params/mock".to_string(),
            fs_policy_version: "7".to_string(),
            fs_epoch_base_ts: 42,
            last_fetch_timestamp_ms: Some(1_234_567),
            msg_replay_state: MsgReplayState::default(),
            capss_witness: capss_witness_bytes,
            barrier_state: BarrierSecretState::default(),
        };
        session.fs_fingerprint = derive_fs_fingerprint_from_fields(
            session.fs_policy_version.as_str(),
            session.fs_ec,
            &session.fs_epoch_commit,
            session.fs_epoch_base_ts,
        );

        // Persist, then remove
        persist_session(&session)?;
        let loaded = load_session_at(&session.server_url, &session.room_id)?
            .ok_or_else(|| anyhow!("expected persisted session to load"))?;
        assert_eq!(loaded.room_id, session.room_id);

        // Remove and verify it's gone
        remove_persisted_session(&session.server_url, &session.room_id)?;
        let after_removal = load_session_at(&session.server_url, &session.room_id)?;
        assert!(after_removal.is_none(), "session should be removed");
        Ok(())
    }

    #[test]
    fn session_load_nonexistent() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let base = temp_dir.path().join("cityg").join("gui");
        let _override_guard = set_config_dir_override_for_tests(Some(base));

        // Try to load a session that doesn't exist
        let result = load_session_at("https://nonexistent.example.com", "nonexistent-room")?;
        assert!(result.is_none(), "nonexistent session should return None");
        Ok(())
    }
}

#[test]
fn test_message_signing_and_verification() -> Result<(), Box<dyn std::error::Error>> {
    // Generate test keys
    let (msg_sign_pk, msg_sign_sk) = dilithium3::keypair();
    let msg_sign_public_key = msg_sign_pk.as_bytes().to_vec();
    let msg_sign_secret_key = msg_sign_sk.as_bytes().to_vec();

    // Test data
    let leaf_id = [0x42u8; 32];
    let plaintext = b"Hello, authenticated world!";
    let timestamp_ms = 1_234_567_890u64;

    // Sign the message
    let signature = sign_message(&leaf_id, timestamp_ms, plaintext, &msg_sign_secret_key)?;

    // Verify the signature - should succeed
    let result = verify_message_signature(
        &leaf_id,
        timestamp_ms,
        plaintext,
        &signature,
        &msg_sign_public_key,
    );
    assert!(result.is_ok(), "signature verification should succeed");

    // Verify with wrong plaintext - should fail
    let wrong_plaintext = b"Wrong message";
    let result = verify_message_signature(
        &leaf_id,
        timestamp_ms,
        wrong_plaintext,
        &signature,
        &msg_sign_public_key,
    );
    assert!(
        result.is_err(),
        "verification should fail with wrong plaintext"
    );

    // Verify with wrong timestamp - should fail
    let wrong_timestamp = timestamp_ms + 1;
    let result = verify_message_signature(
        &leaf_id,
        wrong_timestamp,
        plaintext,
        &signature,
        &msg_sign_public_key,
    );
    assert!(
        result.is_err(),
        "verification should fail with wrong timestamp"
    );

    // Verify with wrong leaf_id - should fail
    let wrong_leaf_id = [0x99u8; 32];
    let result = verify_message_signature(
        &wrong_leaf_id,
        timestamp_ms,
        plaintext,
        &signature,
        &msg_sign_public_key,
    );
    assert!(
        result.is_err(),
        "verification should fail with wrong leaf_id"
    );

    // Verify with corrupted signature - should fail
    let mut corrupted_signature = signature.clone();
    corrupted_signature[100] ^= 0xFF; // Flip some bits
    let result = verify_message_signature(
        &leaf_id,
        timestamp_ms,
        plaintext,
        &corrupted_signature,
        &msg_sign_public_key,
    );
    assert!(
        result.is_err(),
        "verification should fail with corrupted signature"
    );

    Ok(())
}

#[test]
fn test_authenticated_message_format() -> Result<(), Box<dyn std::error::Error>> {
    let (msg_sign_pk, msg_sign_sk) = dilithium3::keypair();
    let msg_sign_public_key = msg_sign_pk.as_bytes().to_vec();
    let msg_sign_secret_key = msg_sign_sk.as_bytes().to_vec();

    let leaf_id = [0x42u8; 32];
    let plaintext = b"Test message";
    let timestamp_ms = 987_654_321u64;
    let epoch_key = [0x55u8; 32];

    let signature = sign_message(&leaf_id, timestamp_ms, plaintext, &msg_sign_secret_key)?;
    let authenticated_msg =
        encode_authenticated_message(timestamp_ms, plaintext, &msg_sign_public_key, &signature);

    let ciphertext = encrypt_message(&authenticated_msg, &epoch_key)?;
    let decrypted = decrypt_message(&ciphertext, &epoch_key)?;
    assert_eq!(decrypted, authenticated_msg);

    let envelope = decode_authenticated_message(&decrypted)?;
    assert_eq!(envelope.timestamp_ms, timestamp_ms);
    assert_eq!(envelope.plaintext, plaintext);
    assert_eq!(envelope.public_key, msg_sign_public_key.as_slice());
    assert_eq!(envelope.signature, signature.as_slice());

    verify_message_signature(
        &leaf_id,
        envelope.timestamp_ms,
        envelope.plaintext,
        envelope.signature,
        envelope.public_key,
    )?;

    Ok(())
}

#[test]
fn test_message_authentication_prevents_spoofing() -> Result<(), Box<dyn std::error::Error>> {
    // Create two different identities
    let (pk_alice, sk_alice) = dilithium3::keypair();
    let (pk_bob, _sk_bob) = dilithium3::keypair();

    let leaf_id_alice = [0x11u8; 32];
    let leaf_id_bob = [0x22u8; 32];
    let plaintext = b"Message from Alice";
    let timestamp_ms = 555_555_555u64;

    // Alice signs a message
    let signature = sign_message(&leaf_id_alice, timestamp_ms, plaintext, sk_alice.as_bytes())?;

    // Verify with Alice's public key - should succeed
    let result = verify_message_signature(
        &leaf_id_alice,
        timestamp_ms,
        plaintext,
        &signature,
        pk_alice.as_bytes(),
    );
    assert!(
        result.is_ok(),
        "Alice's signature should verify with Alice's key"
    );

    // Try to verify with Bob's public key - should fail (prevents impersonation)
    let result = verify_message_signature(
        &leaf_id_alice,
        timestamp_ms,
        plaintext,
        &signature,
        pk_bob.as_bytes(),
    );
    assert!(
        result.is_err(),
        "Alice's signature should NOT verify with Bob's key"
    );

    // Try to claim message is from Bob using Alice's signature - should fail
    let result = verify_message_signature(
        &leaf_id_bob,
        timestamp_ms,
        plaintext,
        &signature,
        pk_alice.as_bytes(),
    );
    assert!(
        result.is_err(),
        "Cannot claim message is from Bob using Alice's signature"
    );

    // Verify with wrong timestamp - should fail
    let result = verify_message_signature(
        &leaf_id_alice,
        timestamp_ms + 1,
        plaintext,
        &signature,
        pk_alice.as_bytes(),
    );
    assert!(
        result.is_err(),
        "Verification should fail with wrong timestamp"
    );

    Ok(())
}

#[test]
fn test_message_format_size_constraints() -> Result<(), Box<dyn std::error::Error>> {
    const MLDSA65_PUBKEY_SIZE: usize = ml_dsa_public_key_bytes();
    const MLDSA65_SIG_SIZE: usize = ml_dsa_signature_bytes();
    const MIN_MSG_SIZE: usize =
        MESSAGE_PREFIX.len() + 8 + 4 + 4 + MLDSA65_PUBKEY_SIZE + 4 + MLDSA65_SIG_SIZE;

    // Test that minimum size is correct
    assert_eq!(
        MIN_MSG_SIZE,
        4 + 8 + 4 + 4 + MLDSA65_PUBKEY_SIZE + 4 + MLDSA65_SIG_SIZE
    );

    // Verify dilithium3 key sizes match constants
    let (pk, sk) = dilithium3::keypair();
    assert_eq!(pk.as_bytes().len(), MLDSA65_PUBKEY_SIZE);
    assert_eq!(
        sk.as_bytes().len(),
        4032,
        "ML-DSA-65 secret key is 4032 bytes"
    );

    // Verify signature size
    let leaf_id = [0u8; 32];
    let plaintext = b"test";
    let sig = sign_message(&leaf_id, 42, plaintext, sk.as_bytes())?;
    assert_eq!(sig.len(), MLDSA65_SIG_SIZE);

    Ok(())
}
