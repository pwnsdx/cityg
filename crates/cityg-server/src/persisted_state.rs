use super::*;

pub(crate) fn persisted_history_commitment(
    commitment: HistoryCommitment,
) -> PersistedHistoryCommitment {
    PersistedHistoryCommitment {
        history_view_id_hex: hex::encode(commitment.history_view_id),
        history_commitment_id_hex: hex::encode(commitment.history_commitment_id),
        prev_history_commitment_id_hex: hex::encode(commitment.prev_history_commitment_id),
        history_seq: commitment.history_seq,
    }
}

pub(crate) fn decode_persisted_history_commitment(
    gid: &[u8],
    persisted: &PersistedHistoryCommitment,
    fallback_history_view_id: [u8; 32],
) -> Result<HistoryCommitment, CityGError> {
    let history_view_id = hex::decode(&persisted.history_view_id_hex)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .unwrap_or(fallback_history_view_id);
    let history_commitment_id = hex::decode(&persisted.history_commitment_id_hex)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .unwrap_or([0u8; 32]);
    let prev_history_commitment_id = hex::decode(&persisted.prev_history_commitment_id_hex)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .unwrap_or([0u8; 32]);
    if history_commitment_id == [0u8; 32] {
        return synthesize_legacy_history_commitment(gid, history_view_id);
    }
    Ok(HistoryCommitment {
        history_view_id,
        history_commitment_id,
        prev_history_commitment_id,
        history_seq: persisted.history_seq,
    })
}

fn persisted_barrier_public_tree_history(
    state: &GroupState,
) -> Vec<PersistedBarrierPublicTreeSnapshot> {
    state
        .barrier_public_tree_history
        .iter()
        .map(|(hash, snapshot)| PersistedBarrierPublicTreeSnapshot {
            kem_tree_hash_after_hex: hex::encode(hash),
            barrier_version: snapshot.barrier_version,
            history_view_id_hex: hex::encode(snapshot.history_view_id),
            history_commitment: persisted_history_commitment(snapshot.history_commitment),
            blob_indices: snapshot.blob_indices.clone(),
            pk_entries: Vec::new(),
        })
        .collect()
}

pub(crate) fn persisted_accepted_barrier_merges(
    state: &GroupState,
) -> Vec<PersistedAcceptedBarrierMergeRecord> {
    state
        .accepted_barrier_merges
        .values()
        .map(|record| PersistedAcceptedBarrierMergeRecord {
            barrier_version: record.barrier_version,
            fs_ec: record.fs_ec,
            reason: record.reason,
            digest_hex: hex::encode(record.digest),
            we_epoch_id_hex: hex::encode(record.we_epoch_id),
        })
        .collect()
}

pub(crate) fn decode_persisted_accepted_barrier_merges(
    records: &[PersistedAcceptedBarrierMergeRecord],
) -> BTreeMap<u64, AcceptedBarrierMergeRecord> {
    records
        .iter()
        .filter_map(|record| {
            let digest = hex::decode(&record.digest_hex)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())?;
            let we_epoch_id = hex::decode(&record.we_epoch_id_hex)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())?;
            Some((
                record.barrier_version,
                AcceptedBarrierMergeRecord {
                    barrier_version: record.barrier_version,
                    fs_ec: record.fs_ec,
                    reason: record.reason,
                    digest,
                    we_epoch_id,
                },
            ))
        })
        .collect()
}

pub(crate) fn persisted_join_finalize_auth(
    state: &GroupState,
) -> Vec<PersistedJoinFinalizeAuthRecord> {
    state
        .pending_join_finalize_auth
        .values()
        .map(|record| PersistedJoinFinalizeAuthRecord {
            leaf_id_hex: hex::encode(record.leaf_id),
            cover_leaf_index: record.lease.slot_index,
            slot_generation: record.lease.slot_generation,
            token_hex: hex::encode(record.token),
        })
        .collect()
}

pub(crate) fn persisted_leaf_slot_leases(
    leases: &BTreeMap<[u8; 32], SlotLease>,
) -> Vec<PersistedLeafSlotLeaseRecord> {
    leases
        .iter()
        .map(|(leaf_id, lease)| PersistedLeafSlotLeaseRecord {
            leaf_id_hex: hex::encode(leaf_id),
            slot_index: lease.slot_index,
            slot_generation: lease.slot_generation,
        })
        .collect()
}

pub(crate) fn decode_persisted_leaf_slot_leases(
    records: &[PersistedLeafSlotLeaseRecord],
) -> BTreeMap<[u8; 32], SlotLease> {
    records
        .iter()
        .filter_map(|record| {
            let leaf_id = hex::decode(&record.leaf_id_hex)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())?;
            Some((
                leaf_id,
                SlotLease {
                    slot_index: record.slot_index,
                    slot_generation: record.slot_generation,
                },
            ))
        })
        .collect()
}

pub(crate) fn decode_persisted_join_finalize_auth(
    records: &[PersistedJoinFinalizeAuthRecord],
) -> BTreeMap<[u8; 32], JoinFinalizeAuthRecord> {
    records
        .iter()
        .filter_map(|record| {
            let leaf_id = hex::decode(&record.leaf_id_hex)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())?;
            let token = hex::decode(&record.token_hex)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())?;
            Some((
                leaf_id,
                JoinFinalizeAuthRecord {
                    leaf_id,
                    lease: SlotLease {
                        slot_index: record.cover_leaf_index,
                        slot_generation: record.slot_generation,
                    },
                    token,
                },
            ))
        })
        .collect()
}

pub(crate) fn persisted_kbroad_room_state(
    state: Option<&GroupState>,
    kbroad_public: Vec<u8>,
    kbroad_generation: u64,
    rotation_required: bool,
    device_chain_states: Vec<PersistedDeviceChainState>,
) -> PersistedKbroadRoomState {
    let mut room = PersistedKbroadRoomState {
        kbroad_public,
        kbroad_generation,
        rotation_required,
        room_admin_pop_keys: Vec::new(),
        room_admin_proof_replay_keys: Vec::new(),
        n_max: DEFAULT_BARRIER_N_MAX,
        pcs_refresh_min_delta_device_ec: default_pcs_refresh_min_delta_device_ec(),
        pcs_refresh_min_delta_group_ec: default_pcs_refresh_min_delta_group_ec(),
        pcs_refresh_slot_width_ec: default_pcs_refresh_slot_width_ec(),
        max_barrier_update_bytes: default_max_barrier_update_bytes(),
        device_chain_states,
        ..PersistedKbroadRoomState::default()
    };
    let mut compacted_state = state.cloned();
    if let Some(state) = compacted_state.as_mut() {
        let _ = prune_barrier_public_tree_history(state);
        room.room_admin_pop_keys = state.room_admin_pop_keys.iter().cloned().collect();
        room.room_admin_proof_replay_keys =
            state.room_admin_proof_replay_keys.iter().copied().collect();
        room.revoked_leaf_ids_hex = state.revoked.iter().map(hex::encode).collect();
        room.barrier_initialized = state.barrier_initialized;
        room.barrier_version = state.barrier_version;
        room.barrier_roots_hash = state.barrier_roots_hash;
        room.kem_tree_hash_after = state.kem_tree_hash_after;
        room.last_checkpoint_ec = state.last_checkpoint_ec;
        room.last_accepted_ec = state.last_accepted_ec;
        room.srx_root_sw = state.srx_root_sw;
        room.barrier_pk_entries = state.barrier_pk_entries.clone();
        room.barrier_public_tree_blobs = state.barrier_public_tree_blobs.clone();
        room.barrier_public_tree_history = persisted_barrier_public_tree_history(state);
        room.n_max = state.n_max.max(1);
        room.last_pcs_refresh_ec = state.last_pcs_refresh_ec;
        room.pcs_refresh_min_delta_device_ec = state.pcs_refresh_min_delta_device_ec.max(1);
        room.pcs_refresh_min_delta_group_ec = state.pcs_refresh_min_delta_group_ec.max(1);
        room.pcs_refresh_slot_width_ec = state.pcs_refresh_slot_width_ec.max(1);
        room.max_barrier_update_bytes =
            u64::try_from(state.max_barrier_update_bytes).unwrap_or(u64::MAX);
        room.accepted_barrier_merges = persisted_accepted_barrier_merges(state);
        room.current_history_commitment =
            persisted_history_commitment(state.current_history_commitment);
        room.current_accepted_barrier_update = state.current_accepted_barrier_update.clone();
        room.current_accepted_barrier_predecessor_hash =
            state.current_accepted_barrier_predecessor_hash;
        room.pending_join_finalize_auth = persisted_join_finalize_auth(state);
        room.active_slot_leases = persisted_leaf_slot_leases(&state.leaf_slot_leases);
        room.revoked_slot_leases = persisted_leaf_slot_leases(&state.revoked_slot_leases);
    }
    room
}

pub(crate) fn merge_optional_u64_max(current: Option<u64>, persisted: Option<u64>) -> Option<u64> {
    match (current, persisted) {
        (Some(lhs), Some(rhs)) => Some(lhs.max(rhs)),
        (Some(lhs), None) => Some(lhs),
        (None, Some(rhs)) => Some(rhs),
        (None, None) => None,
    }
}
