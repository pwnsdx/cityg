use anyhow::{Result, anyhow};

use crate::barrier::{BarrierHistoryCommitment, compute_barrier_tree_hash};

pub fn validate_barrier_tree_snapshot_auth(
    expected_hash: &[u8; 32],
    expected_n_max: u64,
    snapshot_kem_tree_hash_after: &[u8; 32],
    snapshot_pk_entries: &[Vec<u8>],
) -> Result<()> {
    if snapshot_kem_tree_hash_after != expected_hash {
        return Err(anyhow!(
            "barrier tree snapshot auth failure (960.9): hash mismatch"
        ));
    }
    let computed_hash = compute_barrier_tree_hash(expected_n_max, snapshot_pk_entries)?;
    if &computed_hash != expected_hash {
        return Err(anyhow!(
            "barrier tree snapshot auth failure (960.9): tree hash mismatch"
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn ensure_non_regressing_authenticated_current_state<T>(
    local_barrier_version: u64,
    local_kem_tree_hash_after: &[u8; 32],
    local_history_commitment: Option<&BarrierHistoryCommitment>,
    local_history_authority_extension: Option<&T>,
    advertised_barrier_version: u64,
    advertised_kem_tree_hash_after: &[u8; 32],
    advertised_history_commitment: &BarrierHistoryCommitment,
    advertised_history_authority_extension: Option<&T>,
    context: &str,
) -> Result<()>
where
    T: Eq,
{
    if advertised_barrier_version < local_barrier_version {
        return Err(anyhow!(
            "{context} current barrier_version regressed below locally authenticated state (960.9)"
        ));
    }

    let Some(local_history_commitment) = local_history_commitment else {
        return Ok(());
    };

    if advertised_history_commitment.history_seq < local_history_commitment.history_seq {
        return Err(anyhow!(
            "{context} current history commitment regressed below locally authenticated state (960.9)"
        ));
    }

    if advertised_history_commitment.history_seq == local_history_commitment.history_seq {
        if advertised_history_commitment != local_history_commitment {
            return Err(anyhow!(
                "{context} current history commitment conflicts with locally authenticated state (960.9)"
            ));
        }
        if advertised_barrier_version != local_barrier_version {
            return Err(anyhow!(
                "{context} current barrier_version conflicts with locally authenticated current history commitment (960.9)"
            ));
        }
        if advertised_kem_tree_hash_after != local_kem_tree_hash_after {
            return Err(anyhow!(
                "{context} current kem_tree_hash_after conflicts with locally authenticated current history commitment (960.9)"
            ));
        }
        if advertised_history_authority_extension != local_history_authority_extension {
            return Err(anyhow!(
                "{context} history authority extension conflicts with locally authenticated state (960.9)"
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn validate_barrier_tree_snapshot_auth_rejects_hash_mismatch() {
        let err = validate_barrier_tree_snapshot_auth(&[0x11; 32], 4, &[0x22; 32], &[])
            .expect_err("mismatched advertised hash must fail");
        assert!(err.to_string().contains("hash mismatch"));
    }

    #[test]
    fn ensure_non_regressing_authenticated_current_state_rejects_history_regression() {
        let local = BarrierHistoryCommitment {
            history_view_id: [0xA1; 32],
            history_commitment_id: [0xB1; 32],
            prev_history_commitment_id: [0x00; 32],
            history_seq: 7,
        };
        let advertised = BarrierHistoryCommitment {
            history_view_id: [0xA1; 32],
            history_commitment_id: [0xB0; 32],
            prev_history_commitment_id: [0x00; 32],
            history_seq: 6,
        };

        let err = ensure_non_regressing_authenticated_current_state(
            4,
            &[0x55; 32],
            Some(&local),
            Some(&1u8),
            4,
            &[0x55; 32],
            &advertised,
            Some(&1u8),
            "test context",
        )
        .expect_err("history_seq regression must fail");
        assert!(err.to_string().contains("history commitment regressed"));
    }
}
