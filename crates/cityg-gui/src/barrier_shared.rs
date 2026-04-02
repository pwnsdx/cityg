use anyhow::Result;
use cityg_api_client::{
    BarrierJoinRecord, HistoryCommitment, to_core_history_commitment, to_core_join_snapshot_records,
};

#[allow(unused_imports)]
pub use cityg_client::barrier::{
    BARRIER_KEY_INFO, BARRIER_TREE_INFO, BarrierDeriveSaltPreimage, BarrierHistoryCommitment,
    BarrierJoinSnapshotRecord, BarrierTreePathSaltPreimage, DEFAULT_BARRIER_N_MAX,
    MAX_BARRIER_N_MAX, TICKET_RETRY_BASE_DELAY_MS, TICKET_RETRY_JITTER_MS,
    TICKET_RETRY_MAX_ATTEMPTS, TICKET_RETRY_MAX_DELAY_MS, apply_revoked_set_to_snapshot,
    barrier_path_nodes, blank_internal_path_from_leaf, blank_leaf_and_path,
    collect_resolution_targets, compute_barrier_pkhash, compute_barrier_tree_hash,
    compute_revocation_roots_hash,
    decode_history_commitment_header as decode_core_history_commitment_header,
    encode_full_verification_receipt,
    encode_history_commitment_header as encode_core_history_commitment_header,
    expected_barrier_tree_nodes,
    require_current_state_history_commitment as require_core_current_state_history_commitment,
    require_same_history_commitment as require_core_same_history_commitment,
    should_retry_ticket_http_error, sibling_node, ticket_retry_delay, validate_barrier_n_max,
    verify_full_verification_receipt,
};

#[allow(dead_code)]
pub fn require_same_history_commitment(
    lhs: &HistoryCommitment,
    rhs: &HistoryCommitment,
) -> Result<()> {
    require_core_same_history_commitment(
        &to_core_history_commitment(lhs),
        &to_core_history_commitment(rhs),
    )
}

pub fn require_current_state_history_commitment(
    snapshot: &HistoryCommitment,
    joins: &HistoryCommitment,
    revoked: &HistoryCommitment,
) -> Result<()> {
    require_core_current_state_history_commitment(
        &to_core_history_commitment(snapshot),
        &to_core_history_commitment(joins),
        &to_core_history_commitment(revoked),
    )
}

#[allow(dead_code)]
fn from_core_history_commitment(commitment: BarrierHistoryCommitment) -> HistoryCommitment {
    HistoryCommitment {
        history_view_id: commitment.history_view_id,
        history_commitment_id: commitment.history_commitment_id,
        prev_history_commitment_id: commitment.prev_history_commitment_id,
        history_seq: commitment.history_seq,
    }
}

#[allow(dead_code)]
pub fn encode_history_commitment_header(commitment: &HistoryCommitment) -> Result<Vec<u8>> {
    encode_core_history_commitment_header(&to_core_history_commitment(commitment))
}

#[allow(dead_code)]
pub fn decode_history_commitment_header(raw: &[u8]) -> Result<HistoryCommitment> {
    decode_core_history_commitment_header(raw).map(from_core_history_commitment)
}

#[allow(dead_code)]
pub fn apply_join_set_to_snapshot(
    snapshot: &mut [Vec<u8>],
    n_max: u64,
    join_records: &[BarrierJoinRecord],
) -> Result<()> {
    let core_records = to_core_join_snapshot_records(join_records);
    cityg_client::barrier::apply_join_set_to_snapshot(snapshot, n_max, core_records.as_slice())
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
