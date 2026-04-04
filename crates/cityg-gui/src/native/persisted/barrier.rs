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
    pub(in crate::native) current_history_commitment: Option<PersistedBarrierHistoryCommitment>,
    #[serde(default)]
    pub(in crate::native) current_history_authority_extension: String,
    #[serde(default)]
    pub(in crate::native) current_global_history_attestation_hex: String,
    #[serde(default)]
    pub(in crate::native) bootstrap_history_commitment: Option<PersistedBarrierHistoryCommitment>,
    #[serde(default)]
    pub(in crate::native) bootstrap_predecessor_kem_tree_hash_after_hex: String,
    #[serde(default)]
    pub(in crate::native) bootstrap_join_records: Vec<PersistedBarrierJoinRecord>,
    #[serde(default)]
    pub(in crate::native) bootstrap_revoked_records: Vec<PersistedBarrierRevokedRecord>,
    #[serde(default)]
    pub(in crate::native) bootstrap_revoked_leaf_indices: Vec<u32>,
    #[serde(default)]
    pub(in crate::native) bootstrap_join_finalize_auth_token_hex: String,
    #[serde(default)]
    pub(in crate::native) k_barrier_hex: String,
    #[serde(default)]
    pub(in crate::native) kem_tree_hash_after_hex: String,
    #[serde(default)]
    pub(in crate::native) bootstrap_current_barrier_update_hex: String,
    #[serde(default = "super::default_max_barrier_update_bytes")]
    pub(in crate::native) max_barrier_update_bytes: u64,
    #[serde(default = "super::default_barrier_n_max")]
    pub(in crate::native) n_max: u64,
    #[serde(default)]
    pub(in crate::native) cover_leaf_index: u64,
    #[serde(default)]
    pub(in crate::native) slot_generation: u64,
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
    #[serde(default)]
    pub(in crate::native) barrier_recovery_issue: Option<BarrierRecoveryIssue>,
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
pub(in crate::native) struct PersistedBarrierHistoryCommitment {
    #[serde(default)]
    pub(in crate::native) history_view_id_hex: String,
    #[serde(default)]
    pub(in crate::native) history_commitment_id_hex: String,
    #[serde(default)]
    pub(in crate::native) prev_history_commitment_id_hex: String,
    #[serde(default)]
    pub(in crate::native) history_seq: u64,
}

#[derive(Serialize, Deserialize, Default)]
pub(in crate::native) struct PersistedBarrierJoinRecord {
    #[serde(default)]
    pub(in crate::native) device_pk_hex: String,
    #[serde(default)]
    pub(in crate::native) leaf_index: u32,
    #[serde(default)]
    pub(in crate::native) slot_generation: u64,
    #[serde(default)]
    pub(in crate::native) ek_leaf_hex: String,
}

#[derive(Serialize, Deserialize, Default)]
pub(in crate::native) struct PersistedBarrierRevokedRecord {
    #[serde(default)]
    pub(in crate::native) leaf_index: u32,
    #[serde(default)]
    pub(in crate::native) slot_generation: u64,
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
    #[serde(default)]
    pub(in crate::native) activation_source: Option<PersistedBarrierPendingActivationSource>,
}

#[derive(Serialize, Deserialize, Default)]
pub(in crate::native) struct PersistedBarrierPendingActivationSource {
    #[serde(default)]
    pub(in crate::native) barrier_version: u64,
    #[serde(default)]
    pub(in crate::native) barrier_roots_hash_hex: String,
    #[serde(default)]
    pub(in crate::native) kem_tree_hash_after_hex: String,
    #[serde(default)]
    pub(in crate::native) current_history_commitment: Option<PersistedBarrierHistoryCommitment>,
    #[serde(default)]
    pub(in crate::native) current_history_authority_extension: String,
    #[serde(default)]
    pub(in crate::native) current_global_history_attestation_hex: String,
    #[serde(default)]
    pub(in crate::native) fs_ec: u64,
    #[serde(default)]
    pub(in crate::native) fs_dev_prev_commit_hex: String,
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

impl PersistedBarrierHistoryCommitment {
    pub(in crate::native) fn from_runtime(commitment: HistoryCommitment) -> Self {
        Self {
            history_view_id_hex: hex_encode(commitment.history_view_id),
            history_commitment_id_hex: hex_encode(commitment.history_commitment_id),
            prev_history_commitment_id_hex: hex_encode(commitment.prev_history_commitment_id),
            history_seq: commitment.history_seq,
        }
    }

    pub(in crate::native) fn into_runtime(self, field_prefix: &str) -> Result<HistoryCommitment> {
        Ok(HistoryCommitment {
            history_view_id: decode_hex32_or_zero(
                &format!("{field_prefix}.history_view_id_hex"),
                &self.history_view_id_hex,
            )?,
            history_commitment_id: decode_hex32_or_zero(
                &format!("{field_prefix}.history_commitment_id_hex"),
                &self.history_commitment_id_hex,
            )?,
            prev_history_commitment_id: decode_hex32_or_zero(
                &format!("{field_prefix}.prev_history_commitment_id_hex"),
                &self.prev_history_commitment_id_hex,
            )?,
            history_seq: self.history_seq,
        })
    }
}

fn encode_history_authority_extension(extension: Option<HistoryAuthorityExtension>) -> String {
    extension
        .map(|extension| extension.as_str().to_string())
        .unwrap_or_default()
}

fn decode_history_authority_extension(
    field_name: &str,
    raw: &str,
) -> Result<Option<HistoryAuthorityExtension>> {
    if raw.is_empty() {
        return Ok(None);
    }
    match raw {
        "local-history-authority-v1" => {
            Ok(Some(HistoryAuthorityExtension::LocalHistoryAuthorityV1))
        }
        "global-history-authority-v1" => {
            Ok(Some(HistoryAuthorityExtension::GlobalHistoryAuthorityV1))
        }
        other => Err(anyhow!(
            "{field_name} carries unsupported history authority extension: {other}"
        )),
    }
}

impl PersistedBarrierJoinRecord {
    pub(in crate::native) fn from_runtime(record: &BarrierJoinRecord) -> Self {
        Self {
            device_pk_hex: hex_encode(record.device_pk.as_slice()),
            leaf_index: record.leaf_index,
            slot_generation: record.slot_generation,
            ek_leaf_hex: hex_encode(record.ek_leaf.as_slice()),
        }
    }

    pub(in crate::native) fn into_runtime(self) -> Result<BarrierJoinRecord> {
        Ok(BarrierJoinRecord {
            device_pk: decode_hex_vec(
                "barrier_state.bootstrap_join_records[].device_pk_hex",
                &self.device_pk_hex,
            )?,
            leaf_index: self.leaf_index,
            slot_generation: self.slot_generation,
            ek_leaf: decode_hex_vec(
                "barrier_state.bootstrap_join_records[].ek_leaf_hex",
                &self.ek_leaf_hex,
            )?,
        })
    }
}

impl PersistedBarrierRevokedRecord {
    pub(in crate::native) fn from_runtime(record: &BarrierRevokedLeafRecord) -> Self {
        Self {
            leaf_index: record.leaf_index,
            slot_generation: record.slot_generation,
        }
    }

    pub(in crate::native) fn into_runtime(self) -> BarrierRevokedLeafRecord {
        BarrierRevokedLeafRecord {
            leaf_index: self.leaf_index,
            slot_generation: self.slot_generation,
        }
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
            activation_source: pending
                .activation_source
                .as_ref()
                .map(PersistedBarrierPendingActivationSource::from_runtime),
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
            activation_source: self
                .activation_source
                .map(PersistedBarrierPendingActivationSource::into_runtime)
                .transpose()?,
        })
    }
}

impl PersistedBarrierPendingActivationSource {
    pub(in crate::native) fn from_runtime(source: &BarrierPendingActivationSource) -> Self {
        Self {
            barrier_version: source.barrier_version,
            barrier_roots_hash_hex: hex_encode(source.barrier_roots_hash),
            kem_tree_hash_after_hex: hex_encode(source.kem_tree_hash_after),
            current_history_commitment: source
                .current_history_commitment
                .map(PersistedBarrierHistoryCommitment::from_runtime),
            current_history_authority_extension: encode_history_authority_extension(
                source.current_history_authority_extension,
            ),
            current_global_history_attestation_hex: hex_encode(
                source.current_global_history_attestation_bytes.as_slice(),
            ),
            fs_ec: source.fs_ec,
            fs_dev_prev_commit_hex: hex_encode(source.fs_dev_prev_commit),
        }
    }

    pub(in crate::native) fn into_runtime(self) -> Result<BarrierPendingActivationSource> {
        Ok(BarrierPendingActivationSource {
            barrier_version: self.barrier_version,
            barrier_roots_hash: decode_hex32_or_zero(
                "barrier_state.pending.activation_source.barrier_roots_hash_hex",
                &self.barrier_roots_hash_hex,
            )?,
            kem_tree_hash_after: decode_hex32_or_zero(
                "barrier_state.pending.activation_source.kem_tree_hash_after_hex",
                &self.kem_tree_hash_after_hex,
            )?,
            current_history_commitment: self
                .current_history_commitment
                .map(|commitment| {
                    commitment.into_runtime(
                        "barrier_state.pending.activation_source.current_history_commitment",
                    )
                })
                .transpose()?,
            current_history_authority_extension: decode_history_authority_extension(
                "barrier_state.pending.activation_source.current_history_authority_extension",
                &self.current_history_authority_extension,
            )?,
            current_global_history_attestation_bytes: decode_hex_vec(
                "barrier_state.pending.activation_source.current_global_history_attestation_hex",
                &self.current_global_history_attestation_hex,
            )?,
            fs_ec: self.fs_ec,
            fs_dev_prev_commit: decode_hex32_or_zero(
                "barrier_state.pending.activation_source.fs_dev_prev_commit_hex",
                &self.fs_dev_prev_commit_hex,
            )?,
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
            current_history_commitment: state
                .current_history_commitment
                .map(PersistedBarrierHistoryCommitment::from_runtime),
            current_history_authority_extension: encode_history_authority_extension(
                state.current_history_authority_extension,
            ),
            current_global_history_attestation_hex: hex_encode(
                state.current_global_history_attestation_bytes.as_slice(),
            ),
            bootstrap_history_commitment: state
                .bootstrap_history_commitment
                .map(PersistedBarrierHistoryCommitment::from_runtime),
            bootstrap_predecessor_kem_tree_hash_after_hex: hex_encode(
                state.bootstrap_predecessor_kem_tree_hash_after,
            ),
            bootstrap_join_records: state
                .bootstrap_join_records
                .iter()
                .map(PersistedBarrierJoinRecord::from_runtime)
                .collect(),
            bootstrap_revoked_records: state
                .bootstrap_revoked_records
                .iter()
                .map(PersistedBarrierRevokedRecord::from_runtime)
                .collect(),
            bootstrap_revoked_leaf_indices: state.bootstrap_revoked_leaf_indices.clone(),
            bootstrap_join_finalize_auth_token_hex: hex_encode(
                state.bootstrap_join_finalize_auth_token,
            ),
            k_barrier_hex: hex_encode(*state.k_barrier),
            kem_tree_hash_after_hex: hex_encode(state.kem_tree_hash_after),
            bootstrap_current_barrier_update_hex: hex_encode(
                state.bootstrap_current_barrier_update.as_slice(),
            ),
            max_barrier_update_bytes: state.max_barrier_update_bytes,
            n_max: state.n_max.max(1),
            cover_leaf_index: state.cover_leaf_index,
            slot_generation: state.slot_generation,
            dk_leaf_hex: hex_encode(state.dk_leaf.as_slice()),
            pkhash_leaf_hex: hex_encode(state.pkhash_leaf),
            dk_nodes,
            pending: state
                .pending
                .as_ref()
                .map(PersistedBarrierPendingState::from_runtime),
            barrier_recovery_pending: state.barrier_recovery_pending,
            barrier_recovery_issue: state.barrier_recovery_issue,
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
            current_history_commitment: self
                .current_history_commitment
                .map(|commitment| {
                    commitment.into_runtime("barrier_state.current_history_commitment")
                })
                .transpose()?,
            current_history_authority_extension: decode_history_authority_extension(
                "barrier_state.current_history_authority_extension",
                &self.current_history_authority_extension,
            )?,
            current_global_history_attestation_bytes: decode_hex_vec(
                "barrier_state.current_global_history_attestation_hex",
                &self.current_global_history_attestation_hex,
            )?,
            current_public_tree: None,
            retained_public_trees: Vec::new(),
            bootstrap_history_commitment: self
                .bootstrap_history_commitment
                .map(|commitment| {
                    commitment.into_runtime("barrier_state.bootstrap_history_commitment")
                })
                .transpose()?,
            bootstrap_predecessor_kem_tree_hash_after: decode_hex32_or_zero(
                "barrier_state.bootstrap_predecessor_kem_tree_hash_after_hex",
                &self.bootstrap_predecessor_kem_tree_hash_after_hex,
            )?,
            bootstrap_join_records: self
                .bootstrap_join_records
                .into_iter()
                .map(PersistedBarrierJoinRecord::into_runtime)
                .collect::<Result<Vec<_>>>()?,
            bootstrap_revoked_records: self
                .bootstrap_revoked_records
                .into_iter()
                .map(PersistedBarrierRevokedRecord::into_runtime)
                .collect(),
            bootstrap_revoked_leaf_indices: self.bootstrap_revoked_leaf_indices,
            bootstrap_join_finalize_auth_token: decode_hex32_or_zero(
                "barrier_state.bootstrap_join_finalize_auth_token_hex",
                &self.bootstrap_join_finalize_auth_token_hex,
            )?,
            k_barrier: Zeroizing::new(decode_hex32_or_zero(
                "barrier_state.k_barrier_hex",
                &self.k_barrier_hex,
            )?),
            kem_tree_hash_after: decode_hex32_or_zero(
                "barrier_state.kem_tree_hash_after_hex",
                &self.kem_tree_hash_after_hex,
            )?,
            bootstrap_current_barrier_update: decode_hex_vec(
                "barrier_state.bootstrap_current_barrier_update_hex",
                &self.bootstrap_current_barrier_update_hex,
            )?,
            max_barrier_update_bytes: self.max_barrier_update_bytes,
            n_max: self.n_max.max(1),
            cover_leaf_index: self.cover_leaf_index,
            slot_generation: self.slot_generation,
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
            barrier_recovery_issue: self.barrier_recovery_issue,
            current_barrier_full_verified: self.current_barrier_full_verified,
        })
    }
}
