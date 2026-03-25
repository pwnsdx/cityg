use super::*;

#[derive(Serialize, Deserialize)]
pub(in crate::native) struct PersistedForwardState {
    pub(in crate::native) k_fs_hex: String,
    pub(in crate::native) fs_ec: u64,
    pub(in crate::native) fs_dev_commit_hex: String,
    #[serde(default)]
    pub(in crate::native) fs_last_weid_hex: String,
}

#[derive(Serialize, Deserialize, Default)]
pub(in crate::native) struct PersistedBarrierState {
    #[serde(default)]
    pub(in crate::native) barrier_initialized: bool,
    #[serde(default)]
    pub(in crate::native) barrier_version: u64,
    #[serde(default)]
    pub(in crate::native) barrier_roots_hash_hex: String,
    #[serde(default)]
    pub(in crate::native) current_history_view_id_hex: String,
    #[serde(default)]
    pub(in crate::native) k_barrier_hex: String,
    #[serde(default)]
    pub(in crate::native) kem_tree_hash_after_hex: String,
    #[serde(default = "super::default_max_barrier_update_bytes")]
    pub(in crate::native) max_barrier_update_bytes: u64,
    #[serde(default = "super::default_barrier_n_max")]
    pub(in crate::native) n_max: u64,
    #[serde(default)]
    pub(in crate::native) cover_leaf_index: u64,
    #[serde(default)]
    pub(in crate::native) dk_leaf_hex: String,
    #[serde(default)]
    pub(in crate::native) pkhash_leaf_hex: String,
    #[serde(default)]
    pub(in crate::native) dk_nodes: BTreeMap<u32, PersistedBarrierNodeKeyMaterial>,
    #[serde(default)]
    pub(in crate::native) pending: Option<PersistedBarrierPendingState>,
    #[serde(default = "super::default_barrier_recovery_pending")]
    pub(in crate::native) barrier_recovery_pending: bool,
    #[serde(default = "super::default_current_barrier_full_verified")]
    pub(in crate::native) current_barrier_full_verified: bool,
}

#[derive(Serialize, Deserialize, Default)]
pub(in crate::native) struct PersistedBarrierNodeKeyMaterial {
    #[serde(default)]
    pub(in crate::native) dk_hex: String,
    #[serde(default)]
    pub(in crate::native) pkhash_hex: String,
}

#[derive(Serialize, Deserialize, Default)]
pub(in crate::native) struct PersistedBarrierPendingState {
    #[serde(default)]
    pub(in crate::native) barrier_version: u64,
    #[serde(default)]
    pub(in crate::native) we_epoch_id_hex: String,
    #[serde(default)]
    pub(in crate::native) fs_ec: u64,
    #[serde(default)]
    pub(in crate::native) next_forward_fs_ec: u64,
    #[serde(default)]
    pub(in crate::native) next_forward_fs_dev_commit_hex: String,
    #[serde(default)]
    pub(in crate::native) next_forward_last_weid_hex: String,
    #[serde(default)]
    pub(in crate::native) revocation_roots_hash_hex: String,
    #[serde(default)]
    pub(in crate::native) kem_tree_hash_after_hex: String,
    #[serde(default)]
    pub(in crate::native) k_barrier_new_hex: String,
    #[serde(default)]
    pub(in crate::native) k_fs_after_pcs_hex: String,
    #[serde(default)]
    pub(in crate::native) barrier_update_reason: Option<u64>,
    #[serde(default)]
    pub(in crate::native) barrier_update_digest_hex: String,
    #[serde(default)]
    pub(in crate::native) on_path_key_material: BTreeMap<u32, PersistedBarrierNodeKeyMaterial>,
}

impl PersistedBarrierNodeKeyMaterial {
    pub(in crate::native) fn from_runtime(material: &BarrierNodeKeyMaterial) -> Self {
        Self {
            dk_hex: hex_encode(material.dk.as_slice()),
            pkhash_hex: hex_encode(material.pkhash),
        }
    }

    pub(in crate::native) fn into_runtime(
        self,
        field_prefix: &str,
    ) -> Result<BarrierNodeKeyMaterial> {
        let dk = decode_hex_vec(&format!("{field_prefix}.dk_hex"), &self.dk_hex)?;
        let pkhash = decode_hex32_or_zero(&format!("{field_prefix}.pkhash_hex"), &self.pkhash_hex)?;
        Ok(BarrierNodeKeyMaterial {
            dk: Zeroizing::new(dk),
            pkhash,
        })
    }
}

impl PersistedBarrierPendingState {
    pub(in crate::native) fn from_runtime(pending: &BarrierPendingState) -> Self {
        let on_path_key_material = pending
            .on_path_key_material
            .iter()
            .map(|(node, material)| {
                (
                    *node,
                    PersistedBarrierNodeKeyMaterial::from_runtime(material),
                )
            })
            .collect();
        Self {
            barrier_version: pending.barrier_version,
            we_epoch_id_hex: hex_encode(pending.we_epoch_id),
            fs_ec: pending.fs_ec,
            next_forward_fs_ec: pending.next_forward_fs_ec,
            next_forward_fs_dev_commit_hex: hex_encode(pending.next_forward_fs_dev_commit),
            next_forward_last_weid_hex: hex_encode(pending.next_forward_last_weid),
            revocation_roots_hash_hex: hex_encode(pending.revocation_roots_hash),
            kem_tree_hash_after_hex: hex_encode(pending.kem_tree_hash_after),
            k_barrier_new_hex: hex_encode(*pending.k_barrier_new),
            k_fs_after_pcs_hex: pending
                .k_fs_after_pcs
                .as_ref()
                .map(|value| hex_encode(**value))
                .unwrap_or_default(),
            barrier_update_reason: pending.barrier_update_reason,
            barrier_update_digest_hex: hex_encode(pending.barrier_update_digest),
            on_path_key_material,
        }
    }

    pub(in crate::native) fn into_runtime(self) -> Result<BarrierPendingState> {
        let mut on_path_key_material = BTreeMap::new();
        for (node, material) in self.on_path_key_material {
            on_path_key_material.insert(
                node,
                material.into_runtime(&format!(
                    "barrier_state.pending.on_path_key_material[{node}]"
                ))?,
            );
        }
        let k_fs_after_pcs = if self.k_fs_after_pcs_hex.is_empty() {
            None
        } else {
            Some(decode_hex32(
                "barrier_state.pending.k_fs_after_pcs_hex",
                &self.k_fs_after_pcs_hex,
            )?)
        };
        Ok(BarrierPendingState {
            barrier_version: self.barrier_version,
            we_epoch_id: decode_hex32_or_zero(
                "barrier_state.pending.we_epoch_id_hex",
                &self.we_epoch_id_hex,
            )?,
            fs_ec: self.fs_ec,
            next_forward_fs_ec: self.next_forward_fs_ec,
            next_forward_fs_dev_commit: decode_hex32_or_zero(
                "barrier_state.pending.next_forward_fs_dev_commit_hex",
                &self.next_forward_fs_dev_commit_hex,
            )?,
            next_forward_last_weid: decode_hex32_or_zero(
                "barrier_state.pending.next_forward_last_weid_hex",
                &self.next_forward_last_weid_hex,
            )?,
            revocation_roots_hash: decode_hex32_or_zero(
                "barrier_state.pending.revocation_roots_hash_hex",
                &self.revocation_roots_hash_hex,
            )?,
            kem_tree_hash_after: decode_hex32_or_zero(
                "barrier_state.pending.kem_tree_hash_after_hex",
                &self.kem_tree_hash_after_hex,
            )?,
            k_barrier_new: decode_hex32_or_zero(
                "barrier_state.pending.k_barrier_new_hex",
                &self.k_barrier_new_hex,
            )
            .map(Zeroizing::new)?,
            k_fs_after_pcs: k_fs_after_pcs.map(Zeroizing::new),
            barrier_update_reason: self.barrier_update_reason,
            barrier_update_digest: decode_hex32_or_zero(
                "barrier_state.pending.barrier_update_digest_hex",
                &self.barrier_update_digest_hex,
            )?,
            on_path_key_material,
        })
    }
}

impl PersistedBarrierState {
    pub(in crate::native) fn from_runtime(state: &BarrierSecretState) -> Self {
        let dk_nodes = state
            .dk_nodes
            .iter()
            .map(|(node, material)| {
                (
                    *node,
                    PersistedBarrierNodeKeyMaterial::from_runtime(material),
                )
            })
            .collect();
        Self {
            barrier_initialized: state.barrier_initialized,
            barrier_version: state.barrier_version,
            barrier_roots_hash_hex: hex_encode(state.barrier_roots_hash),
            current_history_view_id_hex: hex_encode(state.current_history_view_id),
            k_barrier_hex: hex_encode(*state.k_barrier),
            kem_tree_hash_after_hex: hex_encode(state.kem_tree_hash_after),
            max_barrier_update_bytes: state.max_barrier_update_bytes,
            n_max: state.n_max.max(1),
            cover_leaf_index: state.cover_leaf_index,
            dk_leaf_hex: hex_encode(state.dk_leaf.as_slice()),
            pkhash_leaf_hex: hex_encode(state.pkhash_leaf),
            dk_nodes,
            pending: state
                .pending
                .as_ref()
                .map(PersistedBarrierPendingState::from_runtime),
            barrier_recovery_pending: state.barrier_recovery_pending,
            current_barrier_full_verified: state.current_barrier_full_verified,
        }
    }

    pub(in crate::native) fn into_runtime(self) -> Result<BarrierSecretState> {
        let mut dk_nodes = BTreeMap::new();
        for (node, material) in self.dk_nodes {
            dk_nodes.insert(
                node,
                material.into_runtime(&format!("barrier_state.dk_nodes[{node}]"))?,
            );
        }
        Ok(BarrierSecretState {
            barrier_initialized: self.barrier_initialized,
            barrier_version: self.barrier_version,
            barrier_roots_hash: decode_hex32_or_zero(
                "barrier_state.barrier_roots_hash_hex",
                &self.barrier_roots_hash_hex,
            )?,
            current_history_view_id: decode_hex32_or_zero(
                "barrier_state.current_history_view_id_hex",
                &self.current_history_view_id_hex,
            )?,
            k_barrier: Zeroizing::new(decode_hex32_or_zero(
                "barrier_state.k_barrier_hex",
                &self.k_barrier_hex,
            )?),
            kem_tree_hash_after: decode_hex32_or_zero(
                "barrier_state.kem_tree_hash_after_hex",
                &self.kem_tree_hash_after_hex,
            )?,
            max_barrier_update_bytes: self.max_barrier_update_bytes,
            n_max: self.n_max.max(1),
            cover_leaf_index: self.cover_leaf_index,
            dk_leaf: Zeroizing::new(decode_hex_vec(
                "barrier_state.dk_leaf_hex",
                &self.dk_leaf_hex,
            )?),
            pkhash_leaf: decode_hex32_or_zero(
                "barrier_state.pkhash_leaf_hex",
                &self.pkhash_leaf_hex,
            )?,
            dk_nodes,
            pending: self
                .pending
                .map(PersistedBarrierPendingState::into_runtime)
                .transpose()?,
            barrier_recovery_pending: self.barrier_recovery_pending,
            current_barrier_full_verified: self.current_barrier_full_verified,
        })
    }
}
