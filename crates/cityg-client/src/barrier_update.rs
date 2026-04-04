use std::collections::{BTreeMap, HashSet};

use anyhow::{Result, anyhow};
use msphf_core::{hash::h_l, serde_utils::to_cbor_vec};
use pqcrypto_kyber::kyber768;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::barrier::validate_barrier_n_max;

#[derive(Serialize)]
struct BarrierUpdateDigestPreimage<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

#[derive(Clone, Serialize, Deserialize)]
pub struct BarrierUpdateWire(
    pub String,
    pub u64,
    pub u64,
    pub u64,
    #[serde(with = "serde_bytes")] pub Vec<u8>,
    #[serde(with = "serde_bytes")] pub Vec<u8>,
    #[serde(with = "serde_bytes")] pub Vec<u8>,
    #[serde(with = "serde_bytes")] pub Vec<u8>,
);

#[derive(Clone, Serialize, Deserialize)]
pub struct KemTreeCoverPayloadWire(
    pub u64,
    pub u64,
    pub Vec<u64>,
    pub Option<Vec<u64>>,
    pub Vec<NodeCiphertextWire>,
    pub Vec<NewPublicKeyWire>,
);

#[derive(Clone, Serialize, Deserialize)]
pub struct NodeCiphertextWire(
    pub u64,
    pub u64,
    #[serde(with = "serde_bytes")] pub Vec<u8>,
    #[serde(with = "serde_bytes")] pub Vec<u8>,
    #[serde(with = "serde_bytes")] pub Vec<u8>,
);

#[derive(Clone, Serialize, Deserialize)]
pub struct NewPublicKeyWire(pub u64, #[serde(with = "serde_bytes")] pub Vec<u8>);

#[derive(Clone, Debug)]
pub struct ParsedNodeCiphertext {
    pub source_node: u64,
    pub target_node: u64,
    pub target_pk_hash: [u8; 16],
    pub kem_ct: Vec<u8>,
    pub wrapped_ps: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ParsedBarrierUpdate {
    pub barrier_version: u64,
    pub prev_barrier_version: u64,
    pub tree_size: u64,
    pub revocation_roots_hash: [u8; 32],
    pub kem_tree_hash_before: [u8; 32],
    pub kem_tree_hash_after: [u8; 32],
    pub updater_leaf: u64,
    pub updater_slot_generation: u64,
    pub path_nodes: Vec<u64>,
    pub node_ciphertexts: Vec<ParsedNodeCiphertext>,
    pub new_public_keys: BTreeMap<u64, Vec<u8>>,
}

pub fn compute_barrier_update_digest(raw_update: &[u8]) -> Result<[u8; 32]> {
    h_l(
        "barrier/update/digest",
        &BarrierUpdateDigestPreimage(raw_update),
    )
    .map_err(|err| anyhow!("compute barrier_update_digest: {err}"))
}

fn parse_deterministic_cbor<T>(raw: &[u8], label: &str) -> Result<T>
where
    T: DeserializeOwned + Serialize,
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

pub fn normalize_max_barrier_update_bytes(limit: u64) -> Result<usize> {
    if limit == 0 {
        return Err(anyhow!("max_barrier_update_bytes must be positive"));
    }
    usize::try_from(limit).map_err(|_| anyhow!("max_barrier_update_bytes is too large"))
}

pub fn parse_barrier_update_for_recover(
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
    let expected_n_max = validate_barrier_n_max(expected_n_max)?;

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
        updater_slot_generation,
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
        updater_slot_generation,
        path_nodes,
        node_ciphertexts,
        new_public_keys: parsed_new_public_keys,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn compute_barrier_update_digest_is_stable() {
        let raw = [0xAB, 0xCD, 0xEF];
        let first = compute_barrier_update_digest(raw.as_slice()).expect("digest must compute");
        let second = compute_barrier_update_digest(raw.as_slice()).expect("digest must compute");
        assert_eq!(first, second);
    }

    #[test]
    fn parse_barrier_update_for_recover_accepts_canonical_payload() {
        let cover = KemTreeCoverPayloadWire(
            2,
            7,
            vec![5, 2, 0],
            None,
            Vec::new(),
            vec![
                NewPublicKeyWire(0, vec![0x41; kyber768::public_key_bytes()]),
                NewPublicKeyWire(2, vec![0x42; kyber768::public_key_bytes()]),
            ],
        );
        let update = BarrierUpdateWire(
            "barrier-v1".into(),
            4,
            3,
            4,
            vec![0x11; 32],
            vec![0x22; 32],
            vec![0x33; 32],
            to_cbor_vec(&cover).expect("cover must encode"),
        );
        let raw = to_cbor_vec(&update).expect("update must encode");

        let parsed =
            parse_barrier_update_for_recover(raw.as_slice(), 4, 4096).expect("update must parse");
        assert_eq!(parsed.barrier_version, 4);
        assert_eq!(parsed.prev_barrier_version, 3);
        assert_eq!(parsed.tree_size, 4);
        assert_eq!(parsed.updater_leaf, 2);
        assert_eq!(parsed.updater_slot_generation, 7);
        assert_eq!(parsed.path_nodes, vec![5, 2, 0]);
        assert_eq!(parsed.new_public_keys.len(), 2);
    }
}
