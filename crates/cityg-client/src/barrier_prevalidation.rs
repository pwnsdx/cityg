use anyhow::{Result, anyhow};

use crate::barrier::{
    BarrierHistoryCommitment, BarrierJoinSnapshotRecord, compute_revocation_roots_hash,
    expected_same_rrh_barrier_reason, require_same_history_commitment,
};
use crate::barrier_update::{
    ParsedBarrierUpdate, normalize_max_barrier_update_bytes, parse_barrier_update_for_recover,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BarrierFullChainPrevalidation {
    pub genesis_local_case: bool,
    pub expected_snapshot_hash: [u8; 32],
    pub revocation_roots_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
pub struct BootstrapCurrentStateInput<'a> {
    pub expected_commitment: &'a BarrierHistoryCommitment,
    pub current_commitment: &'a BarrierHistoryCommitment,
    pub expected_extension_present: bool,
    pub current_global_history_attestation_bytes: &'a [u8],
    pub predecessor_hash: [u8; 32],
    pub raw_update: &'a [u8],
    pub local_barrier_version: u64,
    pub local_kem_tree_hash_after: [u8; 32],
    pub local_n_max: u64,
    pub local_max_barrier_update_bytes: u64,
}

pub fn prevalidate_full_chain_update(
    parsed: &ParsedBarrierUpdate,
    local_barrier_initialized: bool,
    local_barrier_version: u64,
    revoked_since_root: [u8; 32],
    revoked_root: [u8; 32],
) -> Result<BarrierFullChainPrevalidation> {
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

    let revocation_roots_hash = compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?;
    if parsed.revocation_roots_hash != revocation_roots_hash {
        return Err(anyhow!(
            "barrier full chain-check prevalidation failed (960.7): revocation_roots_hash mismatch"
        ));
    }

    Ok(BarrierFullChainPrevalidation {
        genesis_local_case,
        expected_snapshot_hash: parsed.kem_tree_hash_before,
        revocation_roots_hash,
    })
}

pub fn validate_full_chain_reason(
    genesis_local_case: bool,
    local_barrier_roots_hash: [u8; 32],
    parsed_revocation_roots_hash: [u8; 32],
    barrier_reason: u64,
    join_records: &[BarrierJoinSnapshotRecord],
    updater_leaf: u64,
) -> Result<()> {
    if genesis_local_case {
        return Ok(());
    }
    if local_barrier_roots_hash == parsed_revocation_roots_hash {
        let expected_reason = expected_same_rrh_barrier_reason(join_records, updater_leaf);
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
    Ok(())
}

pub fn prevalidate_bootstrap_current_state(
    input: BootstrapCurrentStateInput<'_>,
) -> Result<ParsedBarrierUpdate> {
    require_same_history_commitment(input.current_commitment, input.expected_commitment)
        .map_err(|_| anyhow!("join_finalize bootstrap current_history_commitment mismatch"))?;
    if input.current_global_history_attestation_bytes.is_empty() {
        if input.expected_extension_present {
            return Err(anyhow!(
                "join_finalize bootstrap missing current global history attestation bytes for authority-bound current state"
            ));
        }
    } else if !input.expected_extension_present {
        return Err(anyhow!(
            "join_finalize bootstrap uses unsupported or missing history authority extension for attested current state"
        ));
    }
    if input.predecessor_hash == [0u8; 32] {
        return Err(anyhow!(
            "join_finalize bootstrap missing predecessor committed kem_tree_hash_after"
        ));
    }
    if input.raw_update.is_empty() {
        return Err(anyhow!(
            "join_finalize bootstrap missing current barrier_update bytes"
        ));
    }

    let n_max = input.local_n_max.max(1);
    let max_barrier_update_bytes =
        normalize_max_barrier_update_bytes(input.local_max_barrier_update_bytes.max(1))?;
    let parsed =
        parse_barrier_update_for_recover(input.raw_update, n_max, max_barrier_update_bytes)
            .map_err(|err| anyhow!("join_finalize bootstrap verification failed (960.7): {err}"))?;
    if parsed.barrier_version != input.local_barrier_version {
        return Err(anyhow!(
            "join_finalize bootstrap verification failed (960.7): current barrier_version mismatch"
        ));
    }
    if parsed.kem_tree_hash_after != input.local_kem_tree_hash_after {
        return Err(anyhow!(
            "join_finalize bootstrap verification failed (960.7): current kem_tree_hash_after mismatch"
        ));
    }

    Ok(parsed)
}

pub fn validate_bootstrap_provisioning(
    join_records: &[BarrierJoinSnapshotRecord],
    revoked_leaf_indices: &[u32],
    parsed: &ParsedBarrierUpdate,
) -> Result<()> {
    if join_records.is_empty()
        && revoked_leaf_indices.is_empty()
        && (parsed.prev_barrier_version != 0 || parsed.revocation_roots_hash != [0u8; 32])
    {
        return Err(anyhow!(
            "join_finalize bootstrap missing authenticated JoinSet / RevokedLeafSet provisioning"
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn prevalidate_full_chain_update_accepts_genesis_progression() -> Result<()> {
        let parsed = ParsedBarrierUpdate {
            barrier_version: 0,
            prev_barrier_version: 0,
            tree_size: 8,
            revocation_roots_hash: compute_revocation_roots_hash(&[0x11; 32], &[0x22; 32])?,
            kem_tree_hash_before: [0x33; 32],
            kem_tree_hash_after: [0x44; 32],
            updater_leaf: 3,
            path_nodes: vec![10, 4, 1, 0],
            node_ciphertexts: Vec::new(),
            new_public_keys: Default::default(),
        };

        let validated = prevalidate_full_chain_update(&parsed, false, 0, [0x11; 32], [0x22; 32])?;
        assert!(validated.genesis_local_case);
        assert_eq!(validated.expected_snapshot_hash, [0x33; 32]);
        Ok(())
    }

    #[test]
    fn validate_bootstrap_provisioning_rejects_missing_sets_for_non_genesis() {
        let parsed = ParsedBarrierUpdate {
            barrier_version: 3,
            prev_barrier_version: 2,
            tree_size: 8,
            revocation_roots_hash: [0x55; 32],
            kem_tree_hash_before: [0x33; 32],
            kem_tree_hash_after: [0x44; 32],
            updater_leaf: 3,
            path_nodes: vec![10, 4, 1, 0],
            node_ciphertexts: Vec::new(),
            new_public_keys: Default::default(),
        };

        let err = validate_bootstrap_provisioning(&[], &[], &parsed)
            .expect_err("non-genesis bootstrap without join/revoke sets must fail");
        assert!(err.to_string().contains("JoinSet / RevokedLeafSet"));
    }
}
