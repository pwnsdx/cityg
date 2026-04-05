use super::*;

pub(crate) fn build_pk_entries_view<'a>(
    state: &'a GroupState,
) -> Result<Cow<'a, [Vec<u8>]>, CityGError> {
    ensure_distinct_active_slot_indices(state)?;
    let (_, expected_len, _) = barrier_pk_entry_layout(state.n_max)?;
    if state.barrier_pk_entries.len() == expected_len {
        return Ok(Cow::Borrowed(state.barrier_pk_entries.as_slice()));
    }
    Ok(Cow::Owned(build_fallback_pk_entries(
        state,
        Vec::new(),
        |ek_leaf| ek_leaf.clone(),
    )?))
}

#[cfg(test)]
pub(crate) fn build_pk_entries(state: &GroupState) -> Result<Vec<Vec<u8>>, CityGError> {
    Ok(build_pk_entries_cow(state)?
        .into_iter()
        .map(|cow| cow.into_owned())
        .collect())
}

pub(crate) fn rebuild_barrier_public_tree_blob_index(
    state: &mut GroupState,
) -> Result<(), CityGError> {
    state.barrier_public_tree_blob_index.clear();
    for (index, blob) in state.barrier_public_tree_blobs.iter().enumerate() {
        let blob_index = u32::try_from(index)
            .map_err(|_| CityGError::InvalidInput("barrier public tree blob index overflow"))?;
        state
            .barrier_public_tree_blob_index
            .insert(blob.clone(), blob_index);
    }
    Ok(())
}

fn intern_barrier_public_tree_blob(
    state: &mut GroupState,
    entry: &[u8],
) -> Result<BarrierBlobIndex, CityGError> {
    if let Some(index) = state.barrier_public_tree_blob_index.get(entry) {
        return Ok(*index);
    }
    let index = u32::try_from(state.barrier_public_tree_blobs.len())
        .map_err(|_| CityGError::InvalidInput("barrier public tree blob index overflow"))?;
    let owned = entry.to_vec();
    state.barrier_public_tree_blobs.push(owned.clone());
    state.barrier_public_tree_blob_index.insert(owned, index);
    Ok(index)
}

pub(crate) fn encode_barrier_public_tree_snapshot_ref(
    state: &mut GroupState,
    pk_entries: &[Vec<u8>],
) -> Result<BarrierPublicTreeSnapshotRef, CityGError> {
    let mut blob_indices = Vec::with_capacity(pk_entries.len());
    for entry in pk_entries {
        blob_indices.push(intern_barrier_public_tree_blob(state, entry.as_slice())?);
    }
    Ok(BarrierPublicTreeSnapshotRef {
        blob_indices,
        barrier_version: 0,
        history_view_id: [0u8; 32],
        history_commitment: HistoryCommitment::default(),
    })
}

pub(crate) fn decode_barrier_public_tree_snapshot_ref(
    state: &GroupState,
    snapshot: &BarrierPublicTreeSnapshotRef,
) -> Result<Vec<Vec<u8>>, CityGError> {
    decode_barrier_public_tree_snapshot_ref_with_blobs(
        state.barrier_public_tree_blobs.as_slice(),
        snapshot,
    )
}

fn decode_barrier_public_tree_snapshot_ref_with_blobs(
    blobs: &[Vec<u8>],
    snapshot: &BarrierPublicTreeSnapshotRef,
) -> Result<Vec<Vec<u8>>, CityGError> {
    snapshot
        .blob_indices
        .iter()
        .map(|index| {
            let index = usize::try_from(*index)
                .map_err(|_| CityGError::InvalidInput("barrier public tree blob index overflow"))?;
            blobs
                .get(index)
                .cloned()
                .ok_or(CityGError::InvalidInput("barrier public tree blob missing"))
        })
        .collect()
}

#[cfg(test)]
pub(crate) fn history_barrier_public_tree_entries(
    state: &GroupState,
    kem_tree_hash_after: &[u8; 32],
) -> Option<Vec<Vec<u8>>> {
    state
        .barrier_public_tree_history
        .get(kem_tree_hash_after)
        .and_then(|snapshot| decode_barrier_public_tree_snapshot_ref(state, snapshot).ok())
}

pub(crate) fn record_barrier_public_tree_snapshot(
    gid: &[u8],
    state: &mut GroupState,
) -> Result<(), CityGError> {
    if state.barrier_pk_entries.is_empty() {
        return Ok(());
    }
    let current_entries = state.barrier_pk_entries.clone();
    let mut snapshot = encode_barrier_public_tree_snapshot_ref(state, current_entries.as_slice())?;
    snapshot.barrier_version = state.barrier_version;
    snapshot.history_commitment = ensure_current_history_commitment(gid, state)?;
    snapshot.history_view_id = snapshot.history_commitment.history_view_id;
    state
        .barrier_public_tree_history
        .insert(state.kem_tree_hash_after, snapshot);
    prune_barrier_public_tree_history(state)?;
    Ok(())
}

pub(crate) fn record_barrier_public_tree_snapshot_with_metadata(
    state: &mut GroupState,
    kem_tree_hash_after: [u8; 32],
    barrier_version: u64,
    history_commitment: HistoryCommitment,
    pk_entries: &[Vec<u8>],
) -> Result<(), CityGError> {
    if pk_entries.is_empty() {
        return Ok(());
    }
    if let Some(snapshot) = state
        .barrier_public_tree_history
        .get_mut(&kem_tree_hash_after)
    {
        snapshot.barrier_version = barrier_version;
        snapshot.history_commitment = history_commitment;
        snapshot.history_view_id = history_commitment.history_view_id;
        return Ok(());
    }
    let mut snapshot = encode_barrier_public_tree_snapshot_ref(state, pk_entries)?;
    snapshot.barrier_version = barrier_version;
    snapshot.history_commitment = history_commitment;
    snapshot.history_view_id = history_commitment.history_view_id;
    state
        .barrier_public_tree_history
        .insert(kem_tree_hash_after, snapshot);
    Ok(())
}

pub(crate) fn refresh_current_barrier_snapshot_commitments(
    state: &mut GroupState,
    history_commitment: HistoryCommitment,
) -> Result<(), CityGError> {
    if !state.barrier_pk_entries.is_empty() {
        let current_entries = build_pk_entries_view(state)?.into_owned();
        let current_hash =
            compute_barrier_tree_hash(state.n_max.max(1), current_entries.as_slice())?;
        record_barrier_public_tree_snapshot_with_metadata(
            state,
            current_hash,
            state.barrier_version,
            history_commitment,
            current_entries.as_slice(),
        )?;
    }

    let predecessor_hash = current_accepted_barrier_predecessor_hash(state);
    if predecessor_hash != [0u8; 32]
        && let Some(snapshot) = state.barrier_public_tree_history.get_mut(&predecessor_hash)
    {
        snapshot.barrier_version = state.barrier_version;
        snapshot.history_commitment = history_commitment;
        snapshot.history_view_id = history_commitment.history_view_id;
    }
    Ok(())
}

pub(crate) fn prune_join_history(state: &mut GroupState) -> Result<(), CityGError> {
    if state.join_history.is_empty() {
        return Ok(());
    }
    let n_max = validate_barrier_n_max(state.n_max)?;
    let max_records =
        usize::try_from(n_max).map_err(|_| CityGError::InvalidInput("barrier n_max too large"))?;
    let active_leaves: BTreeSet<[u8; 32]> = state
        .latest_snapshot()
        .map(|snapshot| snapshot.members().copied().collect())
        .unwrap_or_default();
    if active_leaves.is_empty() {
        state.join_history.clear();
        return Ok(());
    }
    let mut latest_by_leaf: BTreeMap<[u8; 32], JoinLeafHistoryRecord> = BTreeMap::new();
    for record in &state.join_history {
        if !active_leaves.contains(&record.leaf_id) {
            continue;
        }
        match latest_by_leaf.get_mut(&record.leaf_id) {
            Some(existing) if record.barrier_version >= existing.barrier_version => {
                *existing = record.clone();
            }
            None => {
                latest_by_leaf.insert(record.leaf_id, record.clone());
            }
            _ => {}
        }
    }
    if latest_by_leaf.len() > max_records {
        return Err(CityGError::InvalidInput(
            UNRESOLVED_JOIN_HISTORY_EXHAUSTED_ERR,
        ));
    }
    let mut pruned: Vec<JoinLeafHistoryRecord> = latest_by_leaf.into_values().collect();
    pruned.sort_by_key(|record| (record.slot_index, record.barrier_version, record.leaf_id));
    state.join_history = pruned;
    Ok(())
}

pub(crate) fn prune_barrier_public_tree_history(state: &mut GroupState) -> Result<(), CityGError> {
    if state.barrier_public_tree_history.is_empty() {
        state.barrier_public_tree_blobs.clear();
        state.barrier_public_tree_blob_index.clear();
        return Ok(());
    }

    let current_hash = state.kem_tree_hash_after;
    let mut retained: Vec<([u8; 32], BarrierPublicTreeSnapshotRef)> = state
        .barrier_public_tree_history
        .iter()
        .map(|(hash, snapshot)| (*hash, snapshot.clone()))
        .collect();
    retained.sort_by(|(left_hash, left), (right_hash, right)| {
        (*right_hash == current_hash)
            .cmp(&(*left_hash == current_hash))
            .then_with(|| {
                right
                    .history_commitment
                    .history_seq
                    .cmp(&left.history_commitment.history_seq)
            })
            .then_with(|| right_hash.cmp(left_hash))
    });
    retained.truncate(MAX_RETAINED_BARRIER_PUBLIC_TREE_SNAPSHOTS);

    let old_blobs = state.barrier_public_tree_blobs.clone();
    state.barrier_public_tree_history.clear();
    state.barrier_public_tree_blobs.clear();
    state.barrier_public_tree_blob_index.clear();

    for (hash, snapshot) in retained {
        let pk_entries =
            decode_barrier_public_tree_snapshot_ref_with_blobs(old_blobs.as_slice(), &snapshot)?;
        let mut encoded = encode_barrier_public_tree_snapshot_ref(state, pk_entries.as_slice())?;
        encoded.history_view_id = snapshot.history_view_id;
        encoded.history_commitment = snapshot.history_commitment;
        state.barrier_public_tree_history.insert(hash, encoded);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn compute_group_barrier_tree_hash(state: &GroupState) -> Result<[u8; 32], CityGError> {
    let n_max_usize = usize::try_from(state.n_max)
        .map_err(|_| CityGError::InvalidInput("barrier n_max too large"))?;
    let expected_len = n_max_usize
        .checked_mul(2)
        .and_then(|v| v.checked_sub(1))
        .ok_or(CityGError::InvalidInput("barrier tree size overflow"))?;

    if state.barrier_pk_entries.len() == expected_len {
        return compute_barrier_tree_hash(state.n_max, state.barrier_pk_entries.as_slice());
    }

    let pk_entries = build_pk_entries_view(state)?;
    compute_barrier_tree_hash(state.n_max, pk_entries.as_ref())
}
