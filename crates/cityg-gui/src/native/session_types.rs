use super::*;
use std::sync::Arc;

#[derive(Clone)]
pub(super) struct AppSession {
    pub(super) server_url: String,
    pub(super) room_id: String,
    pub(super) alias: String,
    pub(super) gid: [u8; 32],
    pub(super) cat: [u8; 32],
    pub(super) leaf_id: [u8; 32],
    pub(super) parent_root: [u8; 32],
    pub(super) join_delta_root: [u8; 32],
    pub(super) revoked_since_root: [u8; 32],
    pub(super) revoked_root: [u8; 32],
    pub(super) regular_fingerprint: Option<[u8; 32]>,
    pub(super) fs_fingerprint: Option<[u8; 32]>,
    pub(super) tswe_salt_hash: [u8; 32],
    pub(super) pox_r_commit: [u8; 32],
    pub(super) we_epoch_id: [u8; 32],
    pub(super) xk_hash: [u8; 32],
    pub(super) epoch_key: [u8; 32],
    pub(super) forward_state: ForwardSecrecyState,
    pub(super) fs_ec: u64,
    pub(super) fs_epoch_commit: [u8; 32],
    pub(super) fs_dev_prev_commit: [u8; 32],
    pub(super) fs_epoch_created_at: SystemTime, // Timestamp when current epoch was created
    pub(super) fs_epoch_rotation_interval_secs: u64, // Epoch rotation interval (default: 300 = 5 min)
    pub(super) pop_public_key: Vec<u8>,
    pub(super) pop_secret_key: Vec<u8>,
    pub(super) msg_sign_public_key: Vec<u8>, // message-auth signer public key
    pub(super) msg_sign_secret_key: Vec<u8>, // message-auth signer secret key
    pub(super) vrf_secret_key: Vec<u8>,
    pub(super) vrf_public_key: Vec<u8>,
    pub(super) kbroad_public: Vec<u8>,
    pub(super) bootstrap_public: Vec<u8>,
    pub(super) proof_mode: String,
    pub(super) vrf_id: String,
    pub(super) policy_version: String,
    pub(super) msphf_crs_id: String,
    pub(super) msphf_params_id: String,
    pub(super) fs_policy_version: String,
    pub(super) fs_epoch_base_ts: u64,
    pub(super) fs_forward_leap_policy: FsForwardLeapPolicy,
    pub(super) last_accepted_ec: u64,
    pub(super) last_fetch_timestamp_ms: Option<u64>,
    pub(super) msg_replay_state: MsgReplayState,
    pub(super) capss_witness: Vec<u8>,
    pub(super) barrier_state: BarrierSecretState,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct FsForwardLeapPolicy {
    pub(super) h: u64,
    pub(super) checkpoint_interval: u64,
    pub(super) slack_anchor: u64,
    pub(super) slack_first_device: u64,
    pub(super) slack_device: u64,
}

#[derive(Clone)]
pub(super) struct BarrierSecretState {
    pub(super) barrier_initialized: bool,
    pub(super) barrier_version: u64,
    pub(super) barrier_roots_hash: [u8; 32],
    pub(super) current_history_view_id: [u8; 32],
    pub(super) current_history_commitment: Option<HistoryCommitment>,
    pub(super) current_history_authority_extension: Option<HistoryAuthorityExtension>,
    pub(super) current_global_history_attestation_bytes: Vec<u8>,
    pub(super) current_public_tree: Option<Arc<BarrierPublicTree>>,
    pub(super) retained_public_trees: Vec<RetainedBarrierPublicTree>,
    pub(super) bootstrap_history_commitment: Option<HistoryCommitment>,
    pub(super) bootstrap_predecessor_kem_tree_hash_after: [u8; 32],
    pub(super) bootstrap_join_records: Vec<BarrierJoinRecord>,
    pub(super) bootstrap_revoked_records: Vec<BarrierRevokedOccupancyRecord>,
    pub(super) bootstrap_join_finalize_auth_token: [u8; 32],
    pub(super) k_barrier: Zeroizing<[u8; 32]>,
    pub(super) kem_tree_hash_after: [u8; 32],
    pub(super) bootstrap_current_barrier_update: Vec<u8>,
    pub(super) max_barrier_update_bytes: u64,
    pub(super) n_max: u64,
    pub(super) slot_lease: SlotLease,
    pub(super) dk_leaf: Zeroizing<Vec<u8>>,
    pub(super) pkhash_leaf: [u8; 32],
    pub(super) dk_nodes: BTreeMap<u32, BarrierNodeKeyMaterial>,
    pub(super) pending: Option<BarrierPendingState>,
    pub(super) barrier_recovery_pending: bool,
    pub(super) barrier_recovery_issue: Option<BarrierRecoveryIssue>,
    pub(super) last_pending_history_trace: Option<BarrierPendingHistoryTrace>,
    pub(super) current_barrier_full_verified: bool,
}

impl Default for BarrierSecretState {
    fn default() -> Self {
        Self {
            barrier_initialized: false,
            barrier_version: 0,
            barrier_roots_hash: [0u8; 32],
            current_history_view_id: [0u8; 32],
            current_history_commitment: None,
            current_history_authority_extension: None,
            current_global_history_attestation_bytes: Vec::new(),
            current_public_tree: None,
            retained_public_trees: Vec::new(),
            bootstrap_history_commitment: None,
            bootstrap_predecessor_kem_tree_hash_after: [0u8; 32],
            bootstrap_join_records: Vec::new(),
            bootstrap_revoked_records: Vec::new(),
            bootstrap_join_finalize_auth_token: [0u8; 32],
            k_barrier: Zeroizing::new([0u8; 32]),
            kem_tree_hash_after: [0u8; 32],
            bootstrap_current_barrier_update: Vec::new(),
            max_barrier_update_bytes: 0,
            n_max: DEFAULT_BARRIER_N_MAX,
            slot_lease: SlotLease {
                slot_index: 0,
                slot_generation: 0,
            },
            dk_leaf: Zeroizing::new(Vec::new()),
            pkhash_leaf: [0u8; 32],
            dk_nodes: BTreeMap::new(),
            pending: None,
            barrier_recovery_pending: false,
            barrier_recovery_issue: None,
            last_pending_history_trace: None,
            current_barrier_full_verified: false,
        }
    }
}

#[derive(Clone)]
pub(super) struct RetainedBarrierPublicTree {
    pub(super) barrier_version: u64,
    pub(super) history_commitment: Option<HistoryCommitment>,
    pub(super) snapshot: Arc<BarrierPublicTree>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum BarrierRecoveryIssue {
    InsufficientAuthenticatedHistory,
    ContradictoryAuthenticatedHistory,
    LegacyPendingLocatorMissing,
}

impl BarrierRecoveryIssue {
    pub(super) fn user_message(self) -> &'static str {
        match self {
            Self::InsufficientAuthenticatedHistory | Self::LegacyPendingLocatorMissing => {
                "Barrier recovery requires authenticated history before messaging can resume."
            }
            Self::ContradictoryAuthenticatedHistory => {
                "Barrier recovery found contradictory authenticated history. Sync again or reset this session."
            }
        }
    }
}

#[derive(Clone, Default, Debug)]
pub(super) struct BarrierNodeKeyMaterial {
    pub(super) dk: Zeroizing<Vec<u8>>,
    pub(super) pkhash: [u8; 32],
}

impl Drop for BarrierNodeKeyMaterial {
    fn drop(&mut self) {
        self.dk.zeroize();
        self.pkhash.zeroize();
    }
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub(super) struct BarrierPendingActivationSource {
    pub(super) barrier_version: u64,
    pub(super) barrier_roots_hash: [u8; 32],
    pub(super) kem_tree_hash_after: [u8; 32],
    pub(super) current_history_commitment: Option<HistoryCommitment>,
    pub(super) current_history_authority_extension: Option<HistoryAuthorityExtension>,
    pub(super) current_global_history_attestation_bytes: Vec<u8>,
    pub(super) fs_ec: u64,
    pub(super) fs_dev_prev_commit: [u8; 32],
}

#[derive(Clone, Default)]
pub(super) struct BarrierPendingState {
    pub(super) barrier_version: u64,
    pub(super) we_epoch_id: [u8; 32],
    pub(super) fs_ec: u64,
    pub(super) next_forward_fs_ec: u64,
    pub(super) next_forward_fs_dev_commit: [u8; 32],
    pub(super) next_forward_last_weid: [u8; 32],
    pub(super) revocation_roots_hash: [u8; 32],
    pub(super) kem_tree_hash_after: [u8; 32],
    pub(super) k_barrier_new: Zeroizing<[u8; 32]>,
    pub(super) k_fs_after_pcs: Option<Zeroizing<[u8; 32]>>,
    pub(super) barrier_update_reason: Option<u64>,
    pub(super) barrier_update_digest: [u8; 32],
    pub(super) on_path_key_material: BTreeMap<u32, BarrierNodeKeyMaterial>,
    pub(super) activation_source: Option<BarrierPendingActivationSource>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum BarrierPendingLookupTraceStatus {
    LegacyLocatorUnavailable,
    Pending,
    Accepted,
    Superseded,
    FinalRejected,
    NotFound,
    TransportError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum BarrierPendingTraceDecision {
    Unchanged,
    Activated,
    Discarded,
    RecoveryRequired,
    LookupFailed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BarrierPendingHistoryTrace {
    pub(super) pending_barrier_version: u64,
    pub(super) pending_we_epoch_id: [u8; 32],
    pub(super) current_barrier_version: u64,
    pub(super) lookup_status: BarrierPendingLookupTraceStatus,
    pub(super) accepted_barrier_version: Option<u64>,
    pub(super) accepted_fs_ec: Option<u64>,
    pub(super) accepted_reason: Option<u64>,
    pub(super) accepted_digest: Option<[u8; 32]>,
    pub(super) decision: BarrierPendingTraceDecision,
    pub(super) recovery_issue: Option<BarrierRecoveryIssue>,
    pub(super) detail: Option<String>,
}

impl BarrierPendingHistoryTrace {
    pub(super) fn user_summary(&self) -> String {
        match (self.lookup_status, self.decision) {
            (
                BarrierPendingLookupTraceStatus::LegacyLocatorUnavailable,
                BarrierPendingTraceDecision::Unchanged,
            ) => "Last authenticated check: pending merge predates locator persistence; waiting for more history.".to_string(),
            (
                BarrierPendingLookupTraceStatus::LegacyLocatorUnavailable,
                BarrierPendingTraceDecision::RecoveryRequired,
            ) => "Last authenticated check: pending merge predates locator persistence and now requires explicit recovery.".to_string(),
            (
                BarrierPendingLookupTraceStatus::Pending,
                BarrierPendingTraceDecision::Unchanged,
            ) => "Last authenticated check: merge is still pending.".to_string(),
            (
                BarrierPendingLookupTraceStatus::Accepted,
                BarrierPendingTraceDecision::Activated,
            ) => "Last authenticated check: matching merge was accepted.".to_string(),
            (
                BarrierPendingLookupTraceStatus::Accepted,
                BarrierPendingTraceDecision::RecoveryRequired,
            ) => "Last authenticated check: accepted merge contradicted local pending state.".to_string(),
            (
                BarrierPendingLookupTraceStatus::Superseded,
                BarrierPendingTraceDecision::Discarded,
            ) => "Last authenticated check: pending merge was superseded.".to_string(),
            (
                BarrierPendingLookupTraceStatus::FinalRejected,
                BarrierPendingTraceDecision::Discarded,
            ) => "Last authenticated check: pending merge was finally rejected.".to_string(),
            (
                BarrierPendingLookupTraceStatus::NotFound,
                BarrierPendingTraceDecision::Unchanged,
            ) => "Last authenticated check: acceptance record not found yet; waiting for authenticated history.".to_string(),
            (
                BarrierPendingLookupTraceStatus::NotFound,
                BarrierPendingTraceDecision::RecoveryRequired,
            ) => "Last authenticated check: acceptance record is still missing after a newer barrier version appeared.".to_string(),
            (BarrierPendingLookupTraceStatus::TransportError, BarrierPendingTraceDecision::LookupFailed) => {
                let detail = self.detail.as_deref().unwrap_or("transport failure");
                format!("Last authenticated check failed: {detail}.")
            }
            _ => "Last authenticated check: pending merge state changed.".to_string(),
        }
    }

    pub(super) fn technical_summary(&self) -> String {
        let mut parts = vec![
            format!("pending_version={}", self.pending_barrier_version),
            format!("current_version={}", self.current_barrier_version),
            format!("lookup={:?}", self.lookup_status),
            format!("decision={:?}", self.decision),
        ];
        if let Some(version) = self.accepted_barrier_version {
            parts.push(format!("accepted_version={version}"));
        }
        if let Some(fs_ec) = self.accepted_fs_ec {
            parts.push(format!("accepted_fs_ec={fs_ec}"));
        }
        if let Some(reason) = self.accepted_reason {
            parts.push(format!("accepted_reason={reason}"));
        }
        if let Some(issue) = self.recovery_issue {
            parts.push(format!("recovery_issue={issue:?}"));
        }
        if let Some(detail) = self.detail.as_deref().filter(|detail| !detail.is_empty()) {
            parts.push(detail.to_string());
        }
        parts.join(" · ")
    }
}

#[derive(Clone)]
pub(super) struct PublishedBarrierMerge {
    pub(super) bundle: ClientEpochBundle,
    pub(super) pending_barrier_state: BarrierPendingState,
    pub(super) pre_publish_barrier_version: u64,
    pub(super) pre_publish_barrier_roots_hash: [u8; 32],
    pub(super) pre_publish_kem_tree_hash_after: [u8; 32],
    pub(super) pre_publish_current_history_commitment: HistoryCommitment,
    pub(super) pre_publish_current_history_authority_extension: Option<HistoryAuthorityExtension>,
    pub(super) pre_publish_current_global_history_attestation_bytes: Vec<u8>,
    pub(super) forward_state_after: ForwardSecrecyState,
    pub(super) fs_forward_leap_policy: FsForwardLeapPolicy,
    pub(super) last_accepted_ec: u64,
    pub(super) current_public_tree: Arc<BarrierPublicTree>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BarrierMergeMode {
    PcsRefresh,
    JoinFinalize,
}

impl BarrierMergeMode {
    pub(super) fn reason(self) -> u64 {
        match self {
            Self::PcsRefresh => 1,
            Self::JoinFinalize => 2,
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::PcsRefresh => "refresh",
            Self::JoinFinalize => "join_finalize",
        }
    }

    pub(super) fn publish_context(self) -> &'static str {
        match self {
            Self::PcsRefresh => "publish PCS refresh",
            Self::JoinFinalize => "publish join finalization barrier update",
        }
    }

    pub(super) fn persist_context(self) -> &'static str {
        match self {
            Self::PcsRefresh => "persist refreshed room session",
            Self::JoinFinalize => "persist join-finalized room session",
        }
    }

    pub(super) fn fallback_sync_context(self) -> &'static str {
        match self {
            Self::PcsRefresh => "recover initial barrier state after setup merge",
            Self::JoinFinalize => "recover barrier state after join finalization merge",
        }
    }

    pub(super) fn still_pending_message(self) -> &'static str {
        match self {
            Self::PcsRefresh => {
                "initial room setup completed but barrier recovery is still pending"
            }
            Self::JoinFinalize => {
                "join finalization completed but barrier recovery is still pending"
            }
        }
    }

    pub(super) fn build_bundle_context(self) -> &'static str {
        match self {
            Self::PcsRefresh => "failed to build refresh merge bundle",
            Self::JoinFinalize => "failed to build join finalize merge bundle",
        }
    }

    pub(super) fn accept_bundle_context(self) -> &'static str {
        match self {
            Self::PcsRefresh => "server rejected refresh merge bundle",
            Self::JoinFinalize => "server rejected join finalize merge bundle",
        }
    }

    pub(super) fn reseeds_k_fs(self) -> bool {
        matches!(self, Self::PcsRefresh)
    }
}
