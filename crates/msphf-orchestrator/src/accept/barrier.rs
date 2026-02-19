//! Barrier update wire parsing and structural validation.

use std::collections::BTreeSet;

use ciborium::de;
use ciborium::value::Value;
use msphf_core::serde_utils::to_cbor_vec;
use pqcrypto_kyber::kyber768::{
    ciphertext_bytes as ml_kem_ciphertext_bytes, public_key_bytes as ml_kem_public_key_bytes,
};
use serde::{Deserialize, Serialize};

use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ParsedBarrierUpdate {
    pub barrier_version: u64,
    pub prev_barrier_version: u64,
    pub tree_size: u64,
    pub revocation_roots_hash: [u8; 32],
    pub kem_tree_hash_before: [u8; 32],
    pub kem_tree_hash_after: [u8; 32],
}

#[derive(Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
struct KemTreeCoverPayloadWire(
    u64,
    Vec<u64>,
    Option<Vec<u64>>,
    Vec<NodeCiphertextWire>,
    Vec<NewPublicKeyWire>,
);

#[derive(Serialize, Deserialize)]
struct NodeCiphertextWire(
    u64,
    u64,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
);

#[derive(Serialize, Deserialize)]
struct NewPublicKeyWire(u64, #[serde(with = "serde_bytes")] Vec<u8>);

fn malformed() -> AcceptanceError {
    AcceptanceError::Freeze(FREEZE_BARRIER_UPDATE_MALFORMED)
}

fn parse_deterministic<T>(raw: &[u8]) -> Result<T, AcceptanceError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let decoded: T = de::from_reader(raw).map_err(|_| malformed())?;
    let canonical = to_cbor_vec(&decoded).map_err(|_| malformed())?;
    if canonical.as_slice() != raw {
        return Err(malformed());
    }
    Ok(decoded)
}

fn vec32(bytes: Vec<u8>) -> Result<[u8; 32], AcceptanceError> {
    bytes.try_into().map_err(|_| malformed())
}

fn ensure_range(index: u64, max_index: u64) -> Result<(), AcceptanceError> {
    if index > max_index {
        return Err(malformed());
    }
    Ok(())
}

fn validate_revoked_hint(hint: Option<&[u64]>) -> Result<(), AcceptanceError> {
    let Some(hint) = hint else {
        return Ok(());
    };
    let mut prev: Option<u64> = None;
    for &value in hint {
        if prev.is_some_and(|p| p >= value) {
            return Err(malformed());
        }
        prev = Some(value);
    }
    Ok(())
}

fn validate_path_nodes(
    path_nodes: &[u64],
    updater_leaf: u64,
    n_max: u64,
    max_index: u64,
) -> Result<(), AcceptanceError> {
    if path_nodes.is_empty() {
        return Err(malformed());
    }
    if updater_leaf >= n_max {
        return Err(malformed());
    }

    let leaf_base = n_max.saturating_sub(1);
    let expected_first = leaf_base.checked_add(updater_leaf).ok_or_else(malformed)?;
    if path_nodes.first().copied() != Some(expected_first) {
        return Err(malformed());
    }
    if path_nodes.last().copied() != Some(0) {
        return Err(malformed());
    }

    let mut seen = BTreeSet::new();
    for &node in path_nodes {
        ensure_range(node, max_index)?;
        if !seen.insert(node) {
            return Err(malformed());
        }
    }

    for pair in path_nodes.windows(2) {
        let child = pair[0];
        let parent = pair[1];
        if child == 0 {
            return Err(malformed());
        }
        if (child - 1) / 2 != parent {
            return Err(malformed());
        }
    }

    Ok(())
}

fn validate_new_public_keys(
    keys: &[NewPublicKeyWire],
    path_nodes: &[u64],
    n_max: u64,
    max_index: u64,
) -> Result<(), AcceptanceError> {
    let leaf_base = n_max.saturating_sub(1);
    let expected_set: BTreeSet<u64> = path_nodes.iter().copied().skip(1).collect();
    if keys.len() != expected_set.len() {
        return Err(malformed());
    }

    let mut seen = BTreeSet::new();
    let mut prev_node: Option<u64> = None;
    for NewPublicKeyWire(node_index, ek) in keys {
        ensure_range(*node_index, max_index)?;
        if *node_index >= leaf_base {
            return Err(malformed());
        }
        if ek.len() != ml_kem_public_key_bytes() {
            return Err(malformed());
        }
        if prev_node.is_some_and(|prev| prev >= *node_index) {
            return Err(malformed());
        }
        prev_node = Some(*node_index);
        if !seen.insert(*node_index) {
            return Err(malformed());
        }
    }

    if seen != expected_set {
        return Err(malformed());
    }

    Ok(())
}

fn validate_node_ciphertexts(
    node_ciphertexts: &[NodeCiphertextWire],
    max_index: u64,
) -> Result<(), AcceptanceError> {
    let mut prev_pair: Option<(u64, u64)> = None;
    for NodeCiphertextWire(source, target, target_pk_hash, kem_ct, wrapped_ps) in node_ciphertexts {
        ensure_range(*source, max_index)?;
        ensure_range(*target, max_index)?;
        if target_pk_hash.len() != 16 {
            return Err(malformed());
        }
        if kem_ct.len() != ml_kem_ciphertext_bytes() {
            return Err(malformed());
        }
        if wrapped_ps.len() != 48 {
            return Err(malformed());
        }
        let pair = (*source, *target);
        if prev_pair.is_some_and(|prev| prev >= pair) {
            return Err(malformed());
        }
        prev_pair = Some(pair);
    }
    Ok(())
}

pub(super) fn parse_barrier_update_from_header(
    header: &BTreeMap<u64, Value>,
    expected_n_max: u64,
    max_barrier_update_bytes: usize,
) -> Result<ParsedBarrierUpdate, AcceptanceError> {
    if expected_n_max == 0 || !expected_n_max.is_power_of_two() {
        return Err(malformed());
    }

    let Some(Value::Bytes(raw_update)) = header.get(&HDR_BARRIER_UPDATE) else {
        return Err(malformed());
    };

    if raw_update.len() > max_barrier_update_bytes {
        return Err(malformed());
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
    ) = parse_deterministic(raw_update.as_slice())?;

    if mode != "barrier-v1" {
        return Err(malformed());
    }
    if tree_size != expected_n_max {
        return Err(malformed());
    }

    let KemTreeCoverPayloadWire(
        updater_leaf,
        path_nodes,
        revoked_leaf_indices_hint,
        node_ciphertexts,
        new_public_keys,
    ) = parse_deterministic(cover_payload.as_slice())?;

    let max_index = expected_n_max
        .checked_mul(2)
        .and_then(|v| v.checked_sub(2))
        .ok_or_else(malformed)?;

    validate_revoked_hint(revoked_leaf_indices_hint.as_deref())?;
    validate_path_nodes(
        path_nodes.as_slice(),
        updater_leaf,
        expected_n_max,
        max_index,
    )?;
    validate_node_ciphertexts(node_ciphertexts.as_slice(), max_index)?;
    validate_new_public_keys(
        new_public_keys.as_slice(),
        path_nodes.as_slice(),
        expected_n_max,
        max_index,
    )?;

    Ok(ParsedBarrierUpdate {
        barrier_version,
        prev_barrier_version,
        tree_size,
        revocation_roots_hash: vec32(revocation_roots_hash)?,
        kem_tree_hash_before: vec32(kem_tree_hash_before)?,
        kem_tree_hash_after: vec32(kem_tree_hash_after)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_header() -> Result<BTreeMap<u64, Value>, AcceptanceError> {
        let cover = KemTreeCoverPayloadWire(
            3,
            vec![10, 4, 1, 0],
            None,
            Vec::new(),
            vec![
                NewPublicKeyWire(0, vec![0xA1; ml_kem_public_key_bytes()]),
                NewPublicKeyWire(1, vec![0xA2; ml_kem_public_key_bytes()]),
                NewPublicKeyWire(4, vec![0xA3; ml_kem_public_key_bytes()]),
            ],
        );
        let cover_bytes = to_cbor_vec(&cover).map_err(|_| malformed())?;
        let update = BarrierUpdateWire(
            "barrier-v1".to_string(),
            8,
            7,
            8,
            vec![0x11; 32],
            vec![0x22; 32],
            vec![0x33; 32],
            cover_bytes,
        );
        let update_bytes = to_cbor_vec(&update).map_err(|_| malformed())?;

        let mut header = BTreeMap::new();
        header.insert(HDR_BARRIER_UPDATE, Value::Bytes(update_bytes));
        Ok(header)
    }

    fn extract_update(header: &BTreeMap<u64, Value>) -> Result<BarrierUpdateWire, AcceptanceError> {
        let raw = match header.get(&HDR_BARRIER_UPDATE) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err(malformed()),
        };
        parse_deterministic(raw.as_slice())
    }

    fn replace_update(
        header: &mut BTreeMap<u64, Value>,
        update: &BarrierUpdateWire,
    ) -> Result<(), AcceptanceError> {
        header.insert(
            HDR_BARRIER_UPDATE,
            Value::Bytes(to_cbor_vec(update).map_err(|_| malformed())?),
        );
        Ok(())
    }

    #[test]
    fn parse_barrier_update_accepts_valid_shape() -> Result<(), AcceptanceError> {
        let header = make_valid_header()?;
        let parsed = parse_barrier_update_from_header(&header, 8, 1_000_000)?;
        assert_eq!(parsed.barrier_version, 8);
        assert_eq!(parsed.prev_barrier_version, 7);
        assert_eq!(parsed.tree_size, 8);
        assert_eq!(parsed.revocation_roots_hash, [0x11; 32]);
        assert_eq!(parsed.kem_tree_hash_before, [0x22; 32]);
        assert_eq!(parsed.kem_tree_hash_after, [0x33; 32]);
        Ok(())
    }

    #[test]
    fn parse_barrier_update_rejects_new_public_keys_contract_violation()
    -> Result<(), AcceptanceError> {
        let mut header = make_valid_header()?;
        let mut update = extract_update(&header)?;
        let mut cover: KemTreeCoverPayloadWire = parse_deterministic(update.7.as_slice())?;
        cover.4.pop(); // missing one expected node
        update.7 = to_cbor_vec(&cover).map_err(|_| malformed())?;
        replace_update(&mut header, &update)?;

        assert!(parse_barrier_update_from_header(&header, 8, 1_000_000).is_err());
        Ok(())
    }

    #[test]
    fn parse_barrier_update_rejects_size_limit() -> Result<(), AcceptanceError> {
        let header = make_valid_header()?;
        assert!(parse_barrier_update_from_header(&header, 8, 8).is_err());
        Ok(())
    }

    #[test]
    fn parse_barrier_update_rejects_invalid_mode_string() -> Result<(), AcceptanceError> {
        let mut header = make_valid_header()?;
        let mut update = extract_update(&header)?;
        update.0 = "barrier-v0".to_string();
        replace_update(&mut header, &update)?;
        assert!(parse_barrier_update_from_header(&header, 8, 1_000_000).is_err());
        Ok(())
    }

    #[test]
    fn parse_barrier_update_rejects_invalid_path_nodes() -> Result<(), AcceptanceError> {
        let mut header = make_valid_header()?;
        let mut update = extract_update(&header)?;
        let mut cover: KemTreeCoverPayloadWire = parse_deterministic(update.7.as_slice())?;
        cover.1 = vec![10, 1, 0]; // invalid parent chain for n_max=8
        update.7 = to_cbor_vec(&cover).map_err(|_| malformed())?;
        replace_update(&mut header, &update)?;
        assert!(parse_barrier_update_from_header(&header, 8, 1_000_000).is_err());
        Ok(())
    }

    #[test]
    fn parse_barrier_update_rejects_revoked_hint_duplicates() -> Result<(), AcceptanceError> {
        let mut header = make_valid_header()?;
        let mut update = extract_update(&header)?;
        let mut cover: KemTreeCoverPayloadWire = parse_deterministic(update.7.as_slice())?;
        cover.2 = Some(vec![1, 1]);
        update.7 = to_cbor_vec(&cover).map_err(|_| malformed())?;
        replace_update(&mut header, &update)?;
        assert!(parse_barrier_update_from_header(&header, 8, 1_000_000).is_err());
        Ok(())
    }

    #[test]
    fn parse_barrier_update_rejects_malformed_node_ciphertext() -> Result<(), AcceptanceError> {
        let mut header = make_valid_header()?;
        let mut update = extract_update(&header)?;
        let mut cover: KemTreeCoverPayloadWire = parse_deterministic(update.7.as_slice())?;
        cover.3 = vec![NodeCiphertextWire(
            4,
            3,
            vec![0xAA; 16],
            vec![0xBB; ml_kem_ciphertext_bytes()],
            vec![0xCC; 47], // wrapped_ps must be 48 bytes
        )];
        update.7 = to_cbor_vec(&cover).map_err(|_| malformed())?;
        replace_update(&mut header, &update)?;
        assert!(parse_barrier_update_from_header(&header, 8, 1_000_000).is_err());
        Ok(())
    }

    #[test]
    fn parse_barrier_update_rejects_invalid_nmax_parameters() -> Result<(), AcceptanceError> {
        let header = make_valid_header()?;
        assert!(parse_barrier_update_from_header(&header, 0, 1_000_000).is_err());
        assert!(parse_barrier_update_from_header(&header, 6, 1_000_000).is_err());
        Ok(())
    }

    #[test]
    fn parse_barrier_update_rejects_missing_update_field() {
        let header = BTreeMap::new();
        assert!(parse_barrier_update_from_header(&header, 8, 1_000_000).is_err());
    }

    #[test]
    fn parse_barrier_update_rejects_tree_size_mismatch() -> Result<(), AcceptanceError> {
        let mut header = make_valid_header()?;
        let mut update = extract_update(&header)?;
        update.3 = 16; // expected n_max is 8 in parser call below
        replace_update(&mut header, &update)?;
        assert!(parse_barrier_update_from_header(&header, 8, 1_000_000).is_err());
        Ok(())
    }

    #[test]
    fn parse_barrier_update_rejects_unsorted_node_ciphertexts() -> Result<(), AcceptanceError> {
        let mut header = make_valid_header()?;
        let mut update = extract_update(&header)?;
        let mut cover: KemTreeCoverPayloadWire = parse_deterministic(update.7.as_slice())?;
        cover.3 = vec![
            NodeCiphertextWire(
                4,
                3,
                vec![0xAA; 16],
                vec![0xBB; ml_kem_ciphertext_bytes()],
                vec![0xCC; 48],
            ),
            NodeCiphertextWire(
                1,
                2,
                vec![0xDD; 16],
                vec![0xEE; ml_kem_ciphertext_bytes()],
                vec![0xFF; 48],
            ),
        ];
        update.7 = to_cbor_vec(&cover).map_err(|_| malformed())?;
        replace_update(&mut header, &update)?;
        assert!(parse_barrier_update_from_header(&header, 8, 1_000_000).is_err());
        Ok(())
    }

    #[test]
    fn parse_barrier_update_rejects_leaf_new_public_key_index() -> Result<(), AcceptanceError> {
        let mut header = make_valid_header()?;
        let mut update = extract_update(&header)?;
        let mut cover: KemTreeCoverPayloadWire = parse_deterministic(update.7.as_slice())?;
        cover.4 = vec![
            NewPublicKeyWire(0, vec![0xA1; ml_kem_public_key_bytes()]),
            NewPublicKeyWire(1, vec![0xA2; ml_kem_public_key_bytes()]),
            NewPublicKeyWire(7, vec![0xA3; ml_kem_public_key_bytes()]), // leaf index for n_max=8
        ];
        update.7 = to_cbor_vec(&cover).map_err(|_| malformed())?;
        replace_update(&mut header, &update)?;
        assert!(parse_barrier_update_from_header(&header, 8, 1_000_000).is_err());
        Ok(())
    }

    #[test]
    fn parse_deterministic_rejects_non_canonical_cbor() {
        // [1] encoded with non-shortest uint form (0x18 0x01).
        let non_canonical = [0x81u8, 0x18, 0x01];
        assert!(parse_deterministic::<Vec<u64>>(&non_canonical).is_err());
    }

    #[test]
    fn helper_validators_cover_remaining_error_branches() -> Result<(), AcceptanceError> {
        assert!(ensure_range(5, 4).is_err());
        validate_revoked_hint(Some(&[1, 3, 7]))?;

        let max_index = 14; // for n_max=8
        assert!(validate_path_nodes(&[], 3, 8, max_index).is_err());
        assert!(validate_path_nodes(&[10, 4, 1, 0], 8, 8, max_index).is_err());
        assert!(validate_path_nodes(&[9, 4, 1, 0], 3, 8, max_index).is_err());
        assert!(validate_path_nodes(&[10, 4, 1, 2], 3, 8, max_index).is_err());
        assert!(validate_path_nodes(&[10, 4, 1, 1, 0], 3, 8, max_index).is_err());

        let path_nodes = vec![10, 4, 1, 0];
        let valid_ek = vec![0x55; ml_kem_public_key_bytes()];
        let mismatched_keys = vec![
            NewPublicKeyWire(0, valid_ek.clone()),
            NewPublicKeyWire(1, valid_ek.clone()),
            NewPublicKeyWire(2, valid_ek.clone()),
        ];
        assert!(
            validate_new_public_keys(
                mismatched_keys.as_slice(),
                path_nodes.as_slice(),
                8,
                max_index
            )
            .is_err()
        );

        let unsorted_keys = vec![
            NewPublicKeyWire(1, valid_ek.clone()),
            NewPublicKeyWire(0, valid_ek.clone()),
            NewPublicKeyWire(4, valid_ek.clone()),
        ];
        assert!(
            validate_new_public_keys(
                unsorted_keys.as_slice(),
                path_nodes.as_slice(),
                8,
                max_index
            )
            .is_err()
        );

        let short_ek_keys = vec![
            NewPublicKeyWire(0, vec![0x01; 32]),
            NewPublicKeyWire(1, valid_ek.clone()),
            NewPublicKeyWire(4, valid_ek.clone()),
        ];
        assert!(
            validate_new_public_keys(
                short_ek_keys.as_slice(),
                path_nodes.as_slice(),
                8,
                max_index
            )
            .is_err()
        );

        let bad_pk_hash_ciphertext = vec![NodeCiphertextWire(
            4,
            3,
            vec![0xAA; 15],
            vec![0xBB; ml_kem_ciphertext_bytes()],
            vec![0xCC; 48],
        )];
        assert!(validate_node_ciphertexts(bad_pk_hash_ciphertext.as_slice(), max_index).is_err());

        let bad_kem_ct_ciphertext = vec![NodeCiphertextWire(
            4,
            3,
            vec![0xAA; 16],
            vec![0xBB; 1],
            vec![0xCC; 48],
        )];
        assert!(validate_node_ciphertexts(bad_kem_ct_ciphertext.as_slice(), max_index).is_err());
        Ok(())
    }
}
