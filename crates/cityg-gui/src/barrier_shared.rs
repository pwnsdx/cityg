use std::collections::BTreeMap;

use anyhow::{Result, anyhow};
use ciborium::Value;
use cityg_api_client::{BarrierJoinRecord, HistoryCommitment};
use msphf_core::serde_utils::to_cbor_vec;
use msphf_orchestrator::hdr;
use serde::{Deserialize, Serialize};

#[allow(unused_imports)]
pub use cityg_client::barrier::{
    BARRIER_KEY_INFO, BARRIER_TREE_INFO, BarrierDeriveSaltPreimage, BarrierTreePathSaltPreimage,
    DEFAULT_BARRIER_N_MAX, MAX_BARRIER_N_MAX, TICKET_RETRY_BASE_DELAY_MS, TICKET_RETRY_JITTER_MS,
    TICKET_RETRY_MAX_ATTEMPTS, TICKET_RETRY_MAX_DELAY_MS, apply_revoked_set_to_snapshot,
    barrier_path_nodes, blank_internal_path_from_leaf, blank_leaf_and_path,
    collect_resolution_targets, compute_barrier_pkhash, compute_barrier_tree_hash,
    compute_revocation_roots_hash, encode_full_verification_receipt, expected_barrier_tree_nodes,
    should_retry_ticket_http_error, sibling_node, ticket_retry_delay, validate_barrier_n_max,
    verify_full_verification_receipt,
};

pub fn require_same_history_commitment(
    lhs: &HistoryCommitment,
    rhs: &HistoryCommitment,
) -> Result<()> {
    if lhs.history_view_id == [0u8; 32] || lhs.history_commitment_id == [0u8; 32] || lhs != rhs {
        return Err(anyhow!(
            "authenticated history commitment mismatch across barrier dependencies"
        ));
    }
    Ok(())
}

pub fn require_current_state_history_commitment(
    snapshot: &HistoryCommitment,
    joins: &HistoryCommitment,
    revoked: &HistoryCommitment,
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

pub fn encode_history_commitment_header(commitment: &HistoryCommitment) -> Result<Vec<u8>> {
    to_cbor_vec(&BarrierHistoryCommitmentHeader(
        &commitment.history_view_id,
        &commitment.history_commitment_id,
        &commitment.prev_history_commitment_id,
        commitment.history_seq,
    ))
    .map_err(|err| anyhow!("encode barrier history commitment header: {err}"))
}

pub fn decode_history_commitment_header(raw: &[u8]) -> Result<HistoryCommitment> {
    let decoded: BarrierHistoryCommitmentHeaderOwned = ciborium::de::from_reader(raw)
        .map_err(|err| anyhow!("failed to parse barrier history commitment header: {err}"))?;
    let canonical = to_cbor_vec(&decoded).map_err(|err| {
        anyhow!("failed to re-encode canonical barrier history commitment header: {err}")
    })?;
    if canonical.as_slice() != raw {
        return Err(anyhow!("non-canonical barrier history commitment header"));
    }
    Ok(HistoryCommitment {
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
) -> Result<Option<HistoryCommitment>> {
    match header_map.get(&hdr::HDR_BARRIER_HISTORY_COMMITMENT) {
        Some(Value::Bytes(raw)) => decode_history_commitment_header(raw).map(Some),
        Some(_) => Err(anyhow!("barrier history commitment header must be bytes")),
        None => Ok(None),
    }
}

pub fn apply_join_set_to_snapshot(
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn require_current_state_history_commitment_rejects_snapshot_mismatch() {
        let current = HistoryCommitment {
            history_view_id: [0xA1; 32],
            history_commitment_id: [0xB1; 32],
            prev_history_commitment_id: [0x00; 32],
            history_seq: 7,
        };
        let joins = current;
        let revoked = HistoryCommitment {
            history_view_id: [0xA1; 32],
            history_commitment_id: [0xB2; 32],
            prev_history_commitment_id: [0xB1; 32],
            history_seq: 8,
        };

        assert!(require_current_state_history_commitment(&current, &joins, &revoked).is_err());
    }

    #[test]
    fn require_current_state_history_commitment_accepts_one_common_commitment() {
        let current = HistoryCommitment {
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
        let current = HistoryCommitment {
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
}
