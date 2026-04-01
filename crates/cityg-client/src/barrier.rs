use std::{collections::BTreeMap, time::Duration};

use anyhow::{Result, anyhow};
use ciborium::Value;
use msphf_core::{hash::h_l, serde_utils::to_cbor_vec};
use msphf_orchestrator::hdr;
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use rand::{Rng, rng};
use serde::{Deserialize, Serialize};

pub const DEFAULT_BARRIER_N_MAX: u64 = 1_024;
pub const MAX_BARRIER_N_MAX: u64 = 65_536;
pub const BARRIER_TREE_INFO: &[u8] = b"city-g|barrier/tree|v1";
pub const BARRIER_KEY_INFO: &[u8] = b"city-g|barrier/key|v1";
pub const TICKET_RETRY_MAX_ATTEMPTS: u32 = 4;
pub const TICKET_RETRY_BASE_DELAY_MS: u64 = 50;
pub const TICKET_RETRY_MAX_DELAY_MS: u64 = 800;
pub const TICKET_RETRY_JITTER_MS: u64 = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BarrierHistoryCommitment {
    pub history_view_id: [u8; 32],
    pub history_commitment_id: [u8; 32],
    pub prev_history_commitment_id: [u8; 32],
    pub history_seq: u64,
}

#[derive(Serialize)]
struct BarrierRootsPreimage<'a>(
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    #[serde(with = "serde_bytes")] &'a [u8; 32],
);

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

#[derive(Serialize, Deserialize)]
struct FullVerificationReceiptWire {
    #[serde(with = "serde_bytes")]
    author_leaf_id: Vec<u8>,
    barrier_update_reason: u64,
    updater_leaf: u64,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}

#[derive(Serialize)]
struct FullVerificationReceiptSignedPayload<'a> {
    label: &'static str,
    #[serde(with = "serde_bytes")]
    gid: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    author_leaf_id: &'a [u8; 32],
    barrier_update_reason: u64,
    updater_leaf: u64,
    #[serde(with = "serde_bytes")]
    barrier_history_commitment: &'a [u8],
    #[serde(with = "serde_bytes")]
    global_history_attestation: &'a [u8],
    #[serde(with = "serde_bytes")]
    barrier_update: &'a [u8],
}

#[derive(Serialize)]
pub struct BarrierTreePathSaltPreimage<'a>(#[serde(with = "serde_bytes")] pub &'a [u8], pub u64);

#[derive(Serialize)]
pub struct BarrierDeriveSaltPreimage<'a>(
    #[serde(with = "serde_bytes")] pub &'a [u8],
    pub u64,
    #[serde(with = "serde_bytes")] pub &'a [u8; 32],
);

pub fn should_retry_ticket_http_error(
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

pub fn ticket_retry_delay(attempt: u32) -> Duration {
    let exponent = attempt.min(5);
    let base = TICKET_RETRY_BASE_DELAY_MS.saturating_mul(1u64 << exponent);
    let capped = base.min(TICKET_RETRY_MAX_DELAY_MS);
    let jitter = rng().random_range(0..=TICKET_RETRY_JITTER_MS);
    Duration::from_millis(capped.saturating_add(jitter))
}

pub fn compute_revocation_roots_hash(
    revoked_since_root: &[u8; 32],
    revoked_root: &[u8; 32],
) -> Result<[u8; 32]> {
    h_l(
        "barrier/roots",
        &BarrierRootsPreimage(revoked_since_root, revoked_root),
    )
    .map_err(|err| anyhow!("compute revocation_roots_hash: {err}"))
}

pub fn require_same_history_commitment(
    lhs: &BarrierHistoryCommitment,
    rhs: &BarrierHistoryCommitment,
) -> Result<()> {
    if lhs.history_view_id == [0u8; 32] || lhs.history_commitment_id == [0u8; 32] || lhs != rhs {
        return Err(anyhow!(
            "authenticated history commitment mismatch across barrier dependencies"
        ));
    }
    Ok(())
}

pub fn require_current_state_history_commitment(
    snapshot: &BarrierHistoryCommitment,
    joins: &BarrierHistoryCommitment,
    revoked: &BarrierHistoryCommitment,
) -> Result<()> {
    require_same_history_commitment(snapshot, joins)?;
    require_same_history_commitment(snapshot, revoked)?;
    Ok(())
}

#[derive(Serialize)]
struct BarrierHistoryCommitmentHeader<'a>(
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    u64,
);

#[derive(Serialize, Deserialize)]
struct BarrierHistoryCommitmentHeaderOwned(
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    u64,
);

pub fn encode_history_commitment_header(commitment: &BarrierHistoryCommitment) -> Result<Vec<u8>> {
    to_cbor_vec(&BarrierHistoryCommitmentHeader(
        &commitment.history_view_id,
        &commitment.history_commitment_id,
        &commitment.prev_history_commitment_id,
        commitment.history_seq,
    ))
    .map_err(|err| anyhow!("encode barrier history commitment header: {err}"))
}

pub fn decode_history_commitment_header(raw: &[u8]) -> Result<BarrierHistoryCommitment> {
    let decoded: BarrierHistoryCommitmentHeaderOwned = ciborium::de::from_reader(raw)
        .map_err(|err| anyhow!("failed to parse barrier history commitment header: {err}"))?;
    let canonical = to_cbor_vec(&decoded).map_err(|err| {
        anyhow!("failed to re-encode canonical barrier history commitment header: {err}")
    })?;
    if canonical.as_slice() != raw {
        return Err(anyhow!("non-canonical barrier history commitment header"));
    }
    Ok(BarrierHistoryCommitment {
        history_view_id: decoded.0.as_slice().try_into().map_err(|_| {
            anyhow!("barrier history commitment header history_view_id must be 32 bytes")
        })?,
        history_commitment_id: decoded.1.as_slice().try_into().map_err(|_| {
            anyhow!("barrier history commitment header history_commitment_id must be 32 bytes")
        })?,
        prev_history_commitment_id: decoded.2.as_slice().try_into().map_err(|_| {
            anyhow!("barrier history commitment header prev_history_commitment_id must be 32 bytes")
        })?,
        history_seq: decoded.3,
    })
}

pub fn header_history_commitment(
    header_map: &BTreeMap<u64, Value>,
) -> Result<Option<BarrierHistoryCommitment>> {
    match header_map.get(&hdr::HDR_BARRIER_HISTORY_COMMITMENT) {
        Some(Value::Bytes(raw)) => decode_history_commitment_header(raw).map(Some),
        Some(_) => Err(anyhow!("barrier history commitment header must be bytes")),
        None => Ok(None),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn encode_full_verification_receipt(
    gid: &[u8; 32],
    author_leaf_id: &[u8; 32],
    barrier_update_reason: u64,
    updater_leaf: u64,
    barrier_history_commitment: &[u8],
    global_history_attestation: &[u8],
    barrier_update: &[u8],
    author_pop_secret_key: &[u8],
) -> Result<Vec<u8>> {
    let payload = to_cbor_vec(&FullVerificationReceiptSignedPayload {
        label: "cityg/full-verification-receipt-v1",
        gid,
        author_leaf_id,
        barrier_update_reason,
        updater_leaf,
        barrier_history_commitment,
        global_history_attestation,
        barrier_update,
    })
    .map_err(|err| anyhow!("encode full verification receipt payload: {err}"))?;
    let secret_key = dilithium5::SecretKey::from_bytes(author_pop_secret_key)
        .map_err(|_| anyhow!("invalid ML-DSA-65 POP secret key"))?;
    let signature = dilithium5::detached_sign(payload.as_slice(), &secret_key)
        .as_bytes()
        .to_vec();
    to_cbor_vec(&FullVerificationReceiptWire {
        author_leaf_id: author_leaf_id.to_vec(),
        barrier_update_reason,
        updater_leaf,
        signature,
    })
    .map_err(|err| anyhow!("encode full verification receipt: {err}"))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_full_verification_receipt(
    raw: &[u8],
    gid: &[u8; 32],
    expected_author_leaf_id: &[u8; 32],
    expected_barrier_update_reason: u64,
    expected_updater_leaf: u64,
    barrier_history_commitment: &[u8],
    global_history_attestation: &[u8],
    barrier_update: &[u8],
    author_pop_public_key: &[u8],
) -> Result<()> {
    let decoded: FullVerificationReceiptWire = ciborium::de::from_reader(raw)
        .map_err(|err| anyhow!("failed to parse full verification receipt: {err}"))?;
    let canonical = to_cbor_vec(&decoded)
        .map_err(|err| anyhow!("failed to canonicalize full verification receipt: {err}"))?;
    if canonical.as_slice() != raw {
        return Err(anyhow!("non-canonical full verification receipt"));
    }
    let author_leaf_id: [u8; 32] = decoded
        .author_leaf_id
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("full verification receipt author_leaf_id must be 32 bytes"))?;
    if author_leaf_id != *expected_author_leaf_id
        || decoded.barrier_update_reason != expected_barrier_update_reason
        || decoded.updater_leaf != expected_updater_leaf
    {
        return Err(anyhow!("full verification receipt fields mismatch"));
    }
    let payload = to_cbor_vec(&FullVerificationReceiptSignedPayload {
        label: "cityg/full-verification-receipt-v1",
        gid,
        author_leaf_id: expected_author_leaf_id,
        barrier_update_reason: expected_barrier_update_reason,
        updater_leaf: expected_updater_leaf,
        barrier_history_commitment,
        global_history_attestation,
        barrier_update,
    })
    .map_err(|err| anyhow!("encode full verification receipt payload: {err}"))?;
    let public_key = dilithium5::PublicKey::from_bytes(author_pop_public_key)
        .map_err(|_| anyhow!("invalid ML-DSA-65 POP public key"))?;
    let signature = dilithium5::DetachedSignature::from_bytes(decoded.signature.as_slice())
        .map_err(|_| anyhow!("invalid ML-DSA-65 receipt signature"))?;
    dilithium5::verify_detached_signature(&signature, payload.as_slice(), &public_key)
        .map_err(|_| anyhow!("full verification receipt signature verification failed"))
}

pub fn validate_barrier_n_max(n_max: u64) -> Result<u64> {
    if n_max == 0 || !n_max.is_power_of_two() {
        return Err(anyhow!("barrier n_max must be a non-zero power of two"));
    }
    if n_max > MAX_BARRIER_N_MAX {
        return Err(anyhow!(
            "barrier n_max exceeds MAX_BARRIER_N_MAX: {n_max} > {MAX_BARRIER_N_MAX}"
        ));
    }
    Ok(n_max)
}

pub fn compute_barrier_pkhash(ek: &[u8]) -> Result<[u8; 32]> {
    h_l("barrier/pk-hash", &BarrierPkHashPreimage(ek))
        .map_err(|err| anyhow!("compute barrier/pk-hash: {err}"))
}

pub fn compute_barrier_tree_hash(n_max: u64, pk_entries: &[Vec<u8>]) -> Result<[u8; 32]> {
    let n_max = validate_barrier_n_max(n_max)?;
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

pub fn expected_barrier_tree_nodes(n_max: u64) -> Result<usize> {
    let n_max = validate_barrier_n_max(n_max)?;
    usize::try_from(n_max)
        .ok()
        .and_then(|n| n.checked_mul(2))
        .and_then(|v| v.checked_sub(1))
        .ok_or_else(|| anyhow!("invalid barrier n_max"))
}

pub fn barrier_path_nodes(n_max: u64, updater_leaf: u64) -> Result<Vec<u64>> {
    let n_max = validate_barrier_n_max(n_max)?;
    if updater_leaf >= n_max {
        return Err(anyhow!("invalid barrier update tree parameters"));
    }
    let leaf_base = n_max.saturating_sub(1);
    let mut path_nodes = vec![leaf_base.saturating_add(updater_leaf)];
    while let Some(&node) = path_nodes.last() {
        if node == 0 {
            break;
        }
        path_nodes.push((node - 1) / 2);
    }
    Ok(path_nodes)
}

pub fn sibling_node(node: u64) -> Option<u64> {
    if node == 0 {
        return None;
    }
    if node.is_multiple_of(2) {
        Some(node - 1)
    } else {
        Some(node + 1)
    }
}

pub fn blank_leaf_and_path(snapshot: &mut [Vec<u8>], leaf_node: u64) -> Result<()> {
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

pub fn blank_internal_path_from_leaf(snapshot: &mut [Vec<u8>], leaf_node: u64) -> Result<()> {
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

pub fn apply_revoked_set_to_snapshot(
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

pub fn collect_resolution_targets(
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn validate_barrier_n_max_rejects_invalid_shapes_and_oversized_values() {
        assert_eq!(
            validate_barrier_n_max(DEFAULT_BARRIER_N_MAX).expect("default n_max must be valid"),
            DEFAULT_BARRIER_N_MAX
        );
        assert!(validate_barrier_n_max(0).is_err());
        assert!(validate_barrier_n_max(3).is_err());
        assert!(validate_barrier_n_max(MAX_BARRIER_N_MAX * 2).is_err());
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
    fn compute_revocation_roots_hash_is_stable() -> Result<()> {
        let since = [0x11; 32];
        let revoked = [0x22; 32];
        let first = compute_revocation_roots_hash(&since, &revoked)?;
        let second = compute_revocation_roots_hash(&since, &revoked)?;
        assert_eq!(first, second);
        assert_ne!(first, compute_revocation_roots_hash(&since, &[0x23; 32])?);
        Ok(())
    }

    #[test]
    fn require_current_state_history_commitment_rejects_snapshot_mismatch() {
        let current = BarrierHistoryCommitment {
            history_view_id: [0xA1; 32],
            history_commitment_id: [0xB1; 32],
            prev_history_commitment_id: [0x00; 32],
            history_seq: 7,
        };
        let joins = current;
        let revoked = BarrierHistoryCommitment {
            history_view_id: [0xA1; 32],
            history_commitment_id: [0xB2; 32],
            prev_history_commitment_id: [0xB1; 32],
            history_seq: 8,
        };

        assert!(require_current_state_history_commitment(&current, &joins, &revoked).is_err());
    }

    #[test]
    fn require_current_state_history_commitment_accepts_one_common_commitment() {
        let current = BarrierHistoryCommitment {
            history_view_id: [0xC1; 32],
            history_commitment_id: [0xD1; 32],
            prev_history_commitment_id: [0x00; 32],
            history_seq: 9,
        };

        require_current_state_history_commitment(&current, &current, &current)
            .expect("one authenticated current-state commitment must pass");
    }

    #[test]
    fn encode_history_commitment_header_roundtrips_expected_tuple_shape() {
        let current = BarrierHistoryCommitment {
            history_view_id: [0xC1; 32],
            history_commitment_id: [0xD1; 32],
            prev_history_commitment_id: [0xE1; 32],
            history_seq: 11,
        };

        let encoded = encode_history_commitment_header(&current)
            .expect("history commitment header must encode deterministically");
        let decoded: (Vec<u8>, Vec<u8>, Vec<u8>, u64) =
            ciborium::from_reader(encoded.as_slice()).expect("header must decode");
        assert_eq!(decoded.0, current.history_view_id);
        assert_eq!(decoded.1, current.history_commitment_id);
        assert_eq!(decoded.2, current.prev_history_commitment_id);
        assert_eq!(decoded.3, current.history_seq);
    }

    #[test]
    fn compute_barrier_tree_hash_is_deterministic() -> Result<()> {
        let entries = vec![
            vec![0x01; 8],
            vec![0x02; 8],
            vec![0x03; 8],
            vec![0x04; 8],
            vec![0x05; 8],
            vec![0x06; 8],
            vec![0x07; 8],
        ];
        let first = compute_barrier_tree_hash(4, &entries)?;
        let second = compute_barrier_tree_hash(4, &entries)?;
        assert_eq!(first, second);

        let mut changed = entries.clone();
        changed[6][0] ^= 0xFF;
        assert_ne!(first, compute_barrier_tree_hash(4, &changed)?);
        Ok(())
    }

    #[test]
    fn collect_resolution_targets_descends_empty_internal_nodes() -> Result<()> {
        let snapshot = vec![
            Vec::new(),
            Vec::new(),
            vec![0xA1],
            vec![0xB1],
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
    fn full_verification_receipt_roundtrips() -> Result<()> {
        let (public_key, secret_key) = dilithium5::keypair();
        let gid = [0x11; 32];
        let author_leaf_id = [0x22; 32];
        let barrier_history_commitment = [0x33; 12];
        let global_history_attestation = [0x44; 18];
        let barrier_update = [0x55; 27];
        let receipt = encode_full_verification_receipt(
            &gid,
            &author_leaf_id,
            9,
            2,
            barrier_history_commitment.as_slice(),
            global_history_attestation.as_slice(),
            barrier_update.as_slice(),
            secret_key.as_bytes(),
        )?;
        verify_full_verification_receipt(
            receipt.as_slice(),
            &gid,
            &author_leaf_id,
            9,
            2,
            barrier_history_commitment.as_slice(),
            global_history_attestation.as_slice(),
            barrier_update.as_slice(),
            public_key.as_bytes(),
        )
    }
}
