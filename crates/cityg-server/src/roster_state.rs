use super::*;

#[derive(Clone, Default)]
pub(crate) struct GroupRoster {
    pub(crate) groups: BTreeMap<Vec<u8>, GroupState>,
}

impl GroupRoster {
    pub(crate) fn apply_delta(
        &mut self,
        gid: &[u8],
        base_root: &[u8; 32],
        delta: &MembershipDelta,
    ) -> Result<[u8; 32], CityGError> {
        let state = self.groups.entry(gid.to_vec()).or_default();
        let base_snapshot = if let Some(snapshot) = state.snapshots.get(base_root) {
            snapshot.clone()
        } else if is_zero_root(base_root) && state.snapshots.is_empty() {
            GroupMembership::default()
        } else {
            return Err(CityGError::InvalidInput("unknown membership base root"));
        };

        state
            .snapshots
            .entry(*base_root)
            .or_insert_with(|| base_snapshot.clone());

        let mut next = base_snapshot;
        for leaf in &delta.joined {
            state.revoked.remove(leaf);
        }
        for leaf in &delta.revoked {
            state.revoked.insert(*leaf);
        }
        for leaf in &delta.revoked {
            if !next.contains(leaf) {
                return Err(CityGError::InvalidInput("revoking non-member"));
            }
        }
        for leaf in &delta.joined {
            if next.contains(leaf) {
                return Err(CityGError::InvalidInput("duplicate join"));
            }
        }
        next.apply_delta(delta);

        let leaves: Vec<[u8; 32]> = next.members().copied().collect();
        let new_root = canonical_set_root(&leaves)
            .map_err(|_| CityGError::InvalidInput("unable to compute membership root"))?;

        state.snapshots.insert(new_root, next);
        state.latest_root = Some(new_root);
        state.sync_next_index();
        Ok(new_root)
    }

    pub(crate) fn members(&self, gid: &[u8]) -> Vec<[u8; 32]> {
        self.groups
            .get(gid)
            .and_then(|state| state.latest_snapshot())
            .map(|set| set.members().copied().collect())
            .unwrap_or_default()
    }

    pub(crate) fn members_for_root(&self, gid: &[u8], root: &[u8; 32]) -> Option<Vec<[u8; 32]>> {
        self.groups
            .get(gid)
            .and_then(|state| state.snapshots.get(root))
            .map(|set| set.members().copied().collect())
    }

    pub(crate) fn latest_root(&self, gid: &[u8]) -> Option<[u8; 32]> {
        self.groups.get(gid).and_then(|state| state.latest_root)
    }

    pub(crate) fn revoked(&self, gid: &[u8]) -> Vec<[u8; 32]> {
        self.groups
            .get(gid)
            .map(|state| state.revoked.iter().copied().collect())
            .unwrap_or_default()
    }

    pub(crate) fn has_history(&self, gid: &[u8]) -> bool {
        self.groups
            .get(gid)
            .map(|state| {
                state.latest_root.is_some()
                    || !state.snapshots.is_empty()
                    || !state.revoked.is_empty()
            })
            .unwrap_or(false)
    }

    pub(crate) fn kbroad_generation(&self, gid: &[u8]) -> u64 {
        self.groups
            .get(gid)
            .map(|state| state.kbroad_generation)
            .unwrap_or(0)
    }

    pub(crate) fn increment_kbroad_generation(&mut self, gid: &[u8]) -> u64 {
        let state = self.groups.entry(gid.to_vec()).or_default();
        state.kbroad_generation = state.kbroad_generation.saturating_add(1);
        state.kbroad_generation
    }

    pub(crate) fn kbroad_rotation_required(&self, gid: &[u8]) -> bool {
        self.groups
            .get(gid)
            .map(|state| state.rotation_required)
            .unwrap_or(false)
    }

    pub(crate) fn mark_kbroad_rotation_required(&mut self, gid: &[u8]) {
        self.groups
            .entry(gid.to_vec())
            .or_default()
            .rotation_required = true;
    }

    pub(crate) fn clear_kbroad_rotation_required(&mut self, gid: &[u8]) {
        self.groups
            .entry(gid.to_vec())
            .or_default()
            .rotation_required = false;
    }

    pub(crate) fn has_explicit_room_admins(&self, gid: &[u8]) -> bool {
        self.groups
            .get(gid)
            .map(|state| !state.room_admin_pop_keys.is_empty())
            .unwrap_or(false)
    }

    pub(crate) fn is_room_admin(&self, gid: &[u8], actor_pop_public_key: &[u8]) -> bool {
        self.groups
            .get(gid)
            .map(|state| state.room_admin_pop_keys.contains(actor_pop_public_key))
            .unwrap_or(false)
    }
}

#[derive(Clone)]
pub(crate) struct GroupState {
    pub(crate) latest_root: Option<[u8; 32]>,
    pub(crate) snapshots: BTreeMap<[u8; 32], GroupMembership>,
    pub(crate) revoked: BTreeSet<[u8; 32]>,
    pub(crate) next_index: u32,
    pub(crate) free_slots: BTreeSet<u32>,
    pub(crate) slot_generations: BTreeMap<u32, u64>,
    pub(crate) leaf_slot_leases: BTreeMap<[u8; 32], SlotLease>,
    pub(crate) revoked_slot_leases: BTreeMap<[u8; 32], SlotLease>,
    pub(crate) kbroad_generation: u64,
    pub(crate) rotation_required: bool,
    pub(crate) barrier_initialized: bool,
    pub(crate) barrier_version: u64,
    pub(crate) barrier_roots_hash: [u8; 32],
    pub(crate) kem_tree_hash_after: [u8; 32],
    pub(crate) last_checkpoint_ec: u64,
    pub(crate) last_accepted_ec: u64,
    pub(crate) srx_root_sw: Option<[u8; 32]>,
    pub(crate) n_max: u64,
    pub(crate) last_pcs_refresh_ec: Option<u64>,
    pub(crate) pcs_refresh_min_delta_device_ec: u64,
    pub(crate) pcs_refresh_min_delta_group_ec: u64,
    pub(crate) pcs_refresh_slot_width_ec: u64,
    pub(crate) max_barrier_update_bytes: usize,
    pub(crate) accepted_barrier_merges: BTreeMap<u64, AcceptedBarrierMergeRecord>,
    pub(crate) join_history: Vec<JoinLeafHistoryRecord>,
    pub(crate) leaf_device_pk: BTreeMap<[u8; 32], Vec<u8>>,
    pub(crate) leaf_barrier_public: BTreeMap<[u8; 32], Vec<u8>>,
    pub(crate) barrier_pk_entries: Vec<Vec<u8>>,
    pub(crate) barrier_public_tree_blobs: Vec<Vec<u8>>,
    pub(crate) barrier_public_tree_blob_index: HashMap<Vec<u8>, BarrierBlobIndex>,
    pub(crate) barrier_public_tree_history: BTreeMap<[u8; 32], BarrierPublicTreeSnapshotRef>,
    pub(crate) barrier_hash_cache: Option<Arc<HashMap<usize, [u8; 32]>>>,
    pub(crate) current_history_commitment: HistoryCommitment,
    pub(crate) current_accepted_barrier_update: Vec<u8>,
    pub(crate) current_accepted_barrier_predecessor_hash: [u8; 32],
    pub(crate) pending_join_finalize_auth: BTreeMap<[u8; 32], JoinFinalizeAuthRecord>,
    pub(crate) room_admin_pop_keys: BTreeSet<Vec<u8>>,
    pub(crate) room_admin_proof_replay_keys: BTreeSet<[u8; 32]>,
}

impl Default for GroupState {
    fn default() -> Self {
        Self {
            latest_root: None,
            snapshots: BTreeMap::new(),
            revoked: BTreeSet::new(),
            next_index: 0,
            free_slots: BTreeSet::new(),
            slot_generations: BTreeMap::new(),
            leaf_slot_leases: BTreeMap::new(),
            revoked_slot_leases: BTreeMap::new(),
            kbroad_generation: 0,
            rotation_required: false,
            barrier_initialized: false,
            barrier_version: 0,
            barrier_roots_hash: [0u8; 32],
            kem_tree_hash_after: [0u8; 32],
            last_checkpoint_ec: 0,
            last_accepted_ec: 0,
            srx_root_sw: None,
            n_max: DEFAULT_BARRIER_N_MAX,
            last_pcs_refresh_ec: None,
            pcs_refresh_min_delta_device_ec: default_pcs_refresh_min_delta_device_ec(),
            pcs_refresh_min_delta_group_ec: default_pcs_refresh_min_delta_group_ec(),
            pcs_refresh_slot_width_ec: default_pcs_refresh_slot_width_ec(),
            max_barrier_update_bytes: usize::try_from(default_max_barrier_update_bytes())
                .unwrap_or(1_048_576),
            accepted_barrier_merges: BTreeMap::new(),
            join_history: Vec::new(),
            leaf_device_pk: BTreeMap::new(),
            leaf_barrier_public: BTreeMap::new(),
            barrier_pk_entries: Vec::new(),
            barrier_public_tree_blobs: Vec::new(),
            barrier_public_tree_blob_index: HashMap::new(),
            barrier_public_tree_history: BTreeMap::new(),
            barrier_hash_cache: None,
            current_history_commitment: HistoryCommitment::default(),
            current_accepted_barrier_update: Vec::new(),
            current_accepted_barrier_predecessor_hash: [0u8; 32],
            pending_join_finalize_auth: BTreeMap::new(),
            room_admin_pop_keys: BTreeSet::new(),
            room_admin_proof_replay_keys: BTreeSet::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct JoinLeafHistoryRecord {
    pub(crate) leaf_id: [u8; 32],
    pub(crate) barrier_version: u64,
    pub(crate) leaf_index: u32,
    pub(crate) slot_generation: u64,
    pub(crate) device_pk: Vec<u8>,
    pub(crate) ek_leaf: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct SlotLease {
    pub(crate) slot_index: u32,
    pub(crate) slot_generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AcceptedBarrierMergeRecord {
    pub(crate) barrier_version: u64,
    pub(crate) fs_ec: u64,
    pub(crate) reason: u64,
    pub(crate) digest: [u8; 32],
    pub(crate) we_epoch_id: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct JoinFinalizeAuthRecord {
    pub(crate) leaf_id: [u8; 32],
    pub(crate) lease: SlotLease,
    pub(crate) token: [u8; 32],
}

pub(crate) type BarrierBlobIndex = u32;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct BarrierPublicTreeSnapshotRef {
    pub(crate) blob_indices: Vec<BarrierBlobIndex>,
    pub(crate) barrier_version: u64,
    pub(crate) history_view_id: [u8; 32],
    pub(crate) history_commitment: HistoryCommitment,
}

impl GroupState {
    pub(crate) fn slot_capacity(&self) -> u32 {
        self.n_max.max(1).min(u32::MAX as u64) as u32
    }

    fn ensure_slot_allocator_initialized(&mut self) {
        let slot_capacity = self.slot_capacity();
        if self.slot_generations.is_empty() {
            for slot_index in 0..slot_capacity {
                self.slot_generations.insert(slot_index, 0);
            }
        }
        if self.free_slots.is_empty() && self.slot_generations.len() == slot_capacity as usize {
            self.free_slots = (0..slot_capacity).collect();
            for lease in self.leaf_slot_leases.values() {
                self.free_slots.remove(&lease.slot_index);
            }
            for record in self.pending_join_finalize_auth.values() {
                self.free_slots.remove(&record.lease.slot_index);
            }
        }
    }

    pub(crate) fn allocate_slot_lease(
        &mut self,
        leaf_id: [u8; 32],
    ) -> Result<SlotLease, CityGError> {
        if let Some(existing) = self.leaf_slot_leases.get(&leaf_id) {
            return Ok(*existing);
        }
        if let Some(existing) = self.pending_join_finalize_auth.get(&leaf_id) {
            return Ok(existing.lease);
        }
        self.ensure_slot_allocator_initialized();
        let slot_index = *self
            .free_slots
            .iter()
            .next()
            .ok_or(CityGError::InvalidInput("slot allocator exhausted"))?;
        self.free_slots.remove(&slot_index);
        let slot_generation = *self.slot_generations.get(&slot_index).unwrap_or(&0);
        let lease = SlotLease {
            slot_index,
            slot_generation,
        };
        Ok(lease)
    }

    pub(crate) fn reserve_slot_lease(
        &mut self,
        leaf_id: [u8; 32],
        lease: SlotLease,
    ) -> Result<(), CityGError> {
        if lease.slot_index >= self.slot_capacity() {
            return Err(CityGError::InvalidInput("slot lease index out of range"));
        }
        self.ensure_slot_allocator_initialized();
        let generation = self.slot_generations.entry(lease.slot_index).or_insert(0);
        if *generation != lease.slot_generation {
            return Err(CityGError::InvalidInput("slot lease generation mismatch"));
        }
        if let Some(existing) = self.leaf_slot_leases.get(&leaf_id) {
            if *existing != lease {
                return Err(CityGError::InvalidInput(
                    "leaf already bound to another slot lease",
                ));
            }
            return Ok(());
        }
        self.free_slots.remove(&lease.slot_index);
        self.leaf_slot_leases.insert(leaf_id, lease);
        Ok(())
    }

    pub(crate) fn release_slot_lease(&mut self, leaf_id: &[u8; 32]) -> Option<SlotLease> {
        self.ensure_slot_allocator_initialized();
        let lease = self.leaf_slot_leases.remove(leaf_id)?;
        self.slot_generations
            .insert(lease.slot_index, lease.slot_generation.saturating_add(1));
        self.free_slots.insert(lease.slot_index);
        Some(lease)
    }

    pub(crate) fn activate_slot_lease(
        &mut self,
        leaf_id: [u8; 32],
        lease: SlotLease,
    ) -> Result<(), CityGError> {
        self.reserve_slot_lease(leaf_id, lease)?;
        self.revoked.remove(&leaf_id);
        self.revoked_slot_leases.remove(&leaf_id);
        Ok(())
    }

    pub(crate) fn finalize_slot_reclaim(&mut self, lease: SlotLease) {
        let superseded: Vec<[u8; 32]> = self
            .revoked_slot_leases
            .iter()
            .filter(|(_, revoked_lease)| revoked_lease.slot_index == lease.slot_index)
            .map(|(revoked_leaf, _)| *revoked_leaf)
            .collect();
        for revoked_leaf in superseded {
            self.revoked.remove(&revoked_leaf);
            self.revoked_slot_leases.remove(&revoked_leaf);
        }
    }

    pub(crate) fn latest_snapshot(&self) -> Option<&GroupMembership> {
        self.latest_root.and_then(|root| self.snapshots.get(&root))
    }

    pub(crate) fn allocate_leaf(&mut self) -> u32 {
        if self.next_index == 0 {
            self.next_index = 1;
        }
        let index = self.next_index;
        self.next_index = self.next_index.saturating_add(1);
        index
    }

    pub(crate) fn sync_next_index(&mut self) {
        let max = self
            .snapshots
            .values()
            .flat_map(|set| set.members().map(leaf_index))
            .max()
            .unwrap_or(0);
        let candidate = max.saturating_add(1);
        if self.next_index < candidate {
            self.next_index = candidate;
        }
    }
}

pub(crate) type PersistedKbroadState = BTreeMap<Vec<u8>, PersistedKbroadRoomState>;

pub(crate) const DEFAULT_BARRIER_N_MAX: u64 = 1_024;
pub(crate) const MAX_BARRIER_N_MAX: u64 = 65_536;
pub(crate) const MAX_RETAINED_BARRIER_PUBLIC_TREE_SNAPSHOTS: usize = 256;

pub(crate) fn default_barrier_n_max() -> u64 {
    DEFAULT_BARRIER_N_MAX
}

pub(crate) fn validate_barrier_n_max(n_max: u64) -> Result<u64, CityGError> {
    if n_max == 0 || !n_max.is_power_of_two() {
        return Err(CityGError::InvalidInput(
            "barrier n_max must be a non-zero power of two",
        ));
    }
    if n_max > MAX_BARRIER_N_MAX {
        return Err(CityGError::InvalidInput(
            "barrier n_max exceeds MAX_BARRIER_N_MAX",
        ));
    }
    Ok(n_max)
}

pub(crate) fn default_pcs_refresh_min_delta_device_ec() -> u64 {
    1
}

pub(crate) fn default_pcs_refresh_min_delta_group_ec() -> u64 {
    1
}

pub(crate) fn default_pcs_refresh_slot_width_ec() -> u64 {
    1
}

pub(crate) fn default_max_barrier_update_bytes() -> u64 {
    u64::try_from(msphf_orchestrator::BarrierGroupState::default().max_barrier_update_bytes)
        .unwrap_or(u64::MAX)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PersistedKbroadRoomState {
    pub(crate) kbroad_public: Vec<u8>,
    pub(crate) kbroad_generation: u64,
    pub(crate) rotation_required: bool,
    #[serde(default)]
    pub(crate) room_admin_pop_keys: Vec<Vec<u8>>,
    #[serde(default)]
    pub(crate) room_admin_proof_replay_keys: Vec<[u8; 32]>,
    #[serde(default)]
    pub(crate) revoked_leaf_ids_hex: Vec<String>,
    #[serde(default)]
    pub(crate) barrier_initialized: bool,
    #[serde(default)]
    pub(crate) barrier_version: u64,
    #[serde(default)]
    pub(crate) barrier_roots_hash: [u8; 32],
    #[serde(default)]
    pub(crate) kem_tree_hash_after: [u8; 32],
    #[serde(default)]
    pub(crate) last_checkpoint_ec: u64,
    #[serde(default)]
    pub(crate) last_accepted_ec: u64,
    #[serde(default)]
    pub(crate) srx_root_sw: Option<[u8; 32]>,
    #[serde(default)]
    pub(crate) barrier_pk_entries: Vec<Vec<u8>>,
    #[serde(default)]
    pub(crate) barrier_public_tree_blobs: Vec<Vec<u8>>,
    #[serde(default)]
    pub(crate) barrier_public_tree_history: Vec<PersistedBarrierPublicTreeSnapshot>,
    #[serde(default = "default_barrier_n_max")]
    pub(crate) n_max: u64,
    #[serde(default)]
    pub(crate) last_pcs_refresh_ec: Option<u64>,
    #[serde(default = "default_pcs_refresh_min_delta_device_ec")]
    pub(crate) pcs_refresh_min_delta_device_ec: u64,
    #[serde(default = "default_pcs_refresh_min_delta_group_ec")]
    pub(crate) pcs_refresh_min_delta_group_ec: u64,
    #[serde(default = "default_pcs_refresh_slot_width_ec")]
    pub(crate) pcs_refresh_slot_width_ec: u64,
    #[serde(default = "default_max_barrier_update_bytes")]
    pub(crate) max_barrier_update_bytes: u64,
    #[serde(default)]
    pub(crate) accepted_barrier_merges: Vec<PersistedAcceptedBarrierMergeRecord>,
    #[serde(default)]
    pub(crate) current_history_commitment: PersistedHistoryCommitment,
    #[serde(default)]
    pub(crate) current_accepted_barrier_update: Vec<u8>,
    #[serde(default)]
    pub(crate) current_accepted_barrier_predecessor_hash: [u8; 32],
    #[serde(default)]
    pub(crate) pending_join_finalize_auth: Vec<PersistedJoinFinalizeAuthRecord>,
    #[serde(default)]
    pub(crate) active_slot_leases: Vec<PersistedLeafSlotLeaseRecord>,
    #[serde(default)]
    pub(crate) revoked_slot_leases: Vec<PersistedLeafSlotLeaseRecord>,
    #[serde(default)]
    pub(crate) device_chain_states: Vec<PersistedDeviceChainState>,
}

impl Default for PersistedKbroadRoomState {
    fn default() -> Self {
        Self {
            kbroad_public: Vec::new(),
            kbroad_generation: 0,
            rotation_required: false,
            room_admin_pop_keys: Vec::new(),
            room_admin_proof_replay_keys: Vec::new(),
            revoked_leaf_ids_hex: Vec::new(),
            barrier_initialized: false,
            barrier_version: 0,
            barrier_roots_hash: [0u8; 32],
            kem_tree_hash_after: [0u8; 32],
            last_checkpoint_ec: 0,
            last_accepted_ec: 0,
            srx_root_sw: None,
            barrier_pk_entries: Vec::new(),
            barrier_public_tree_blobs: Vec::new(),
            barrier_public_tree_history: Vec::new(),
            n_max: default_barrier_n_max(),
            last_pcs_refresh_ec: None,
            pcs_refresh_min_delta_device_ec: default_pcs_refresh_min_delta_device_ec(),
            pcs_refresh_min_delta_group_ec: default_pcs_refresh_min_delta_group_ec(),
            pcs_refresh_slot_width_ec: default_pcs_refresh_slot_width_ec(),
            max_barrier_update_bytes: default_max_barrier_update_bytes(),
            accepted_barrier_merges: Vec::new(),
            current_history_commitment: PersistedHistoryCommitment::default(),
            current_accepted_barrier_update: Vec::new(),
            current_accepted_barrier_predecessor_hash: [0u8; 32],
            pending_join_finalize_auth: Vec::new(),
            active_slot_leases: Vec::new(),
            revoked_slot_leases: Vec::new(),
            device_chain_states: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct PersistedDeviceChainState {
    pub(crate) device_pk: Vec<u8>,
    #[serde(default)]
    pub(crate) last_commit: Option<[u8; 32]>,
    #[serde(default)]
    pub(crate) last_ec: u64,
    #[serde(default)]
    pub(crate) last_pcs_refresh_ec: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct PersistedAcceptedBarrierMergeRecord {
    #[serde(default)]
    pub(crate) barrier_version: u64,
    #[serde(default)]
    pub(crate) fs_ec: u64,
    #[serde(default)]
    pub(crate) reason: u64,
    #[serde(default)]
    pub(crate) digest_hex: String,
    #[serde(default)]
    pub(crate) we_epoch_id_hex: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct PersistedJoinFinalizeAuthRecord {
    #[serde(default)]
    pub(crate) leaf_id_hex: String,
    #[serde(default)]
    pub(crate) slot_index: u32,
    #[serde(default)]
    pub(crate) slot_generation: u64,
    #[serde(default)]
    pub(crate) token_hex: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct PersistedLeafSlotLeaseRecord {
    #[serde(default)]
    pub(crate) leaf_id_hex: String,
    #[serde(default)]
    pub(crate) slot_index: u32,
    #[serde(default)]
    pub(crate) slot_generation: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct PersistedBarrierPublicTreeSnapshot {
    #[serde(default)]
    pub(crate) kem_tree_hash_after_hex: String,
    #[serde(default)]
    pub(crate) barrier_version: u64,
    #[serde(default)]
    pub(crate) history_view_id_hex: String,
    #[serde(default)]
    pub(crate) history_commitment: PersistedHistoryCommitment,
    #[serde(default)]
    pub(crate) blob_indices: Vec<BarrierBlobIndex>,
    #[serde(default)]
    pub(crate) pk_entries: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct PersistedHistoryCommitment {
    #[serde(default)]
    pub(crate) history_view_id_hex: String,
    #[serde(default)]
    pub(crate) history_commitment_id_hex: String,
    #[serde(default)]
    pub(crate) prev_history_commitment_id_hex: String,
    #[serde(default)]
    pub(crate) history_seq: u64,
}

pub(crate) fn is_zero_root(root: &[u8; 32]) -> bool {
    root.iter().all(|byte| *byte == 0)
}

pub(crate) fn leaf_index(leaf: &[u8; 32]) -> u32 {
    let bytes: [u8; 4] = leaf[28..32].try_into().unwrap_or_default();
    u32::from_be_bytes(bytes)
}

/// Spec S3.2 cover index mapping.
///
/// The mapping is deterministic across components:
/// `cover_leaf_index(device_pk) = leaf_index(device_pk) mod n_max`.
/// We clamp `n_max` to `[1, u32::MAX]` before applying modulo.
#[cfg(test)]
pub(crate) fn cover_leaf_index(leaf: &[u8; 32], n_max: u64) -> u32 {
    let n_max = n_max.max(1).min(u32::MAX as u64) as u32;
    leaf_index(leaf) % n_max
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_lease_allocator_reuses_released_slot_with_incremented_generation() {
        let mut state = GroupState {
            n_max: 4,
            ..GroupState::default()
        };
        let lease_a = state.allocate_slot_lease([0x11; 32]).expect("lease a");
        state
            .reserve_slot_lease([0x11; 32], lease_a)
            .expect("reserve a");
        let lease_b = state.allocate_slot_lease([0x22; 32]).expect("lease b");
        state
            .reserve_slot_lease([0x22; 32], lease_b)
            .expect("reserve b");
        assert_eq!(lease_a.slot_index, 0);
        assert_eq!(lease_a.slot_generation, 0);
        assert_eq!(lease_b.slot_index, 1);
        assert_eq!(lease_b.slot_generation, 0);

        let released = state.release_slot_lease(&[0x11; 32]).expect("release a");
        assert_eq!(released, lease_a);

        let lease_c = state.allocate_slot_lease([0x33; 32]).expect("lease c");
        assert_eq!(lease_c.slot_index, lease_a.slot_index);
        assert_eq!(lease_c.slot_generation, lease_a.slot_generation + 1);
    }

    #[test]
    fn reserve_slot_lease_rejects_generation_mismatch() {
        let mut state = GroupState {
            n_max: 2,
            ..GroupState::default()
        };
        let lease = state.allocate_slot_lease([0x41; 32]).expect("lease");
        state
            .reserve_slot_lease([0x41; 32], lease)
            .expect("reserve");
        state.release_slot_lease(&[0x41; 32]).expect("release");

        let err = state
            .reserve_slot_lease([0x42; 32], lease)
            .expect_err("stale generation must be rejected");
        assert!(matches!(
            err,
            CityGError::InvalidInput("slot lease generation mismatch")
        ));
    }

    #[test]
    fn allocate_slot_lease_reuses_existing_pending_reservation() {
        let mut state = GroupState {
            n_max: 2,
            ..GroupState::default()
        };
        let lease = state.allocate_slot_lease([0x51; 32]).expect("lease");
        state.pending_join_finalize_auth.insert(
            [0x51; 32],
            JoinFinalizeAuthRecord {
                leaf_id: [0x51; 32],
                lease,
                token: [0x77; 32],
            },
        );

        let reused = state
            .allocate_slot_lease([0x51; 32])
            .expect("reuse pending lease");
        assert_eq!(reused, lease);
    }

    #[test]
    fn finalize_slot_reclaim_clears_only_matching_revoked_slot() {
        let mut state = GroupState {
            n_max: 4,
            ..GroupState::default()
        };
        state.revoked.insert([0x11; 32]);
        state.revoked.insert([0x22; 32]);
        state.revoked_slot_leases.insert(
            [0x11; 32],
            SlotLease {
                slot_index: 1,
                slot_generation: 0,
            },
        );
        state.revoked_slot_leases.insert(
            [0x22; 32],
            SlotLease {
                slot_index: 2,
                slot_generation: 0,
            },
        );

        state.finalize_slot_reclaim(SlotLease {
            slot_index: 1,
            slot_generation: 1,
        });

        assert!(!state.revoked.contains(&[0x11; 32]));
        assert!(!state.revoked_slot_leases.contains_key(&[0x11; 32]));
        assert!(state.revoked.contains(&[0x22; 32]));
        assert!(state.revoked_slot_leases.contains_key(&[0x22; 32]));
    }
}
