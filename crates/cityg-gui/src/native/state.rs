use super::*;

pub(super) struct AppModel {
    pub(super) config: CityGConfig,
    pub(super) join_form: JoinFormState,
    pub(super) join_status: JoinStatus,
    pub(super) leave_status: LeaveStatus,
    pub(super) session: Option<AppSession>,
    pub(super) last_error: Option<String>,
    pub(super) categorized_error: Option<CategorizedError>,
    pub(super) info_message: Option<String>,
    pub(super) toasts: Vec<Toast>,
    pub(super) messages: Vec<ChatMessageEntry>,
    pub(super) message_keys: HashSet<MessageKey>,
    pub(super) next_pending_message_id: u64,
    pub(super) fetch_status: FetchStatus,
    pub(super) send_status: SendStatus,
    pub(super) composer: MessageComposer,
    pub(super) fetch_task: Option<Task<()>>,
    pub(super) fetch_in_flight: bool,
    pub(super) fetch_after_epoch_sync: bool,
    pub(super) show_ciphertext: bool,
    pub(super) members: Vec<MemberEntry>,
    pub(super) members_status: MembersStatus,
    pub(super) members_total: u64,
    pub(super) members_next_offset: Option<u64>,
    pub(super) members_loading_append: bool,
    pub(super) members_auto_page: bool,
    pub(super) members_alias_dirty: bool,
    pub(super) members_mode: MembersMode,
    pub(super) members_search: MembersSearchState,
    pub(super) members_refresh_task: Option<Task<()>>,
    pub(super) alias_bindings: AHashMap<String, AliasBindingRecord>,
    pub(super) leaf_alias_index: AHashMap<[u8; 32], String>,
    pub(super) room_admins: Vec<Vec<u8>>,
    pub(super) room_admins_loaded: bool,
    pub(super) room_admin_status: RoomAdminStatus,
    pub(super) room_admin_target: RoomAdminTargetState,
    pub(super) room_admin_revoke_confirmation: Option<Vec<u8>>,
    pub(super) epoch_sync_task: Option<Task<()>>, // Background task for membership-driven epoch sync
    pub(super) ws_task: Option<Task<()>>,         // WebSocket connection task
    pub(super) ws_connected: bool,                // WebSocket connection status
    pub(super) ws_autostart_attempted: bool,
    pub(super) restore_epoch_sync_pending: bool,
    pub(super) last_retry_action: Option<RetryAction>, // Track what action to retry
    pub(super) security_events: Vec<SecurityEvent>,
    pub(super) security_unread: u32,
    pub(super) security_panel_expanded: bool,
    pub(super) activity_events: Vec<ActivityEvent>,
    pub(super) chat_scroll_handle: ScrollHandle,
    pub(super) right_sidebar_scroll_handle: ScrollHandle,
}

pub(super) enum JoinStatus {
    Idle,
    Joining,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum LeaveStatus {
    Idle,
    Leaving,
    Refreshing,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum FetchStatus {
    Idle,
    Refreshing,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SendStatus {
    Idle,
    Sending,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) enum RoomAdminStatus {
    Idle,
    Loading(String),
    Error(String),
}

#[derive(Clone, PartialEq, Eq)]
pub(super) enum MembersStatus {
    Idle,
    Loading(String),
    Error(String),
}

// Error categorization for user-friendly error handling
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ErrorCategory {
    Network,
    Crypto,
    Policy,
    Server,
    Validation,
}

#[derive(Debug, Clone)]
pub(super) struct CategorizedError {
    pub(super) category: ErrorCategory,
    pub(super) user_message: String,
    pub(super) technical_details: String,
    pub(super) recovery_suggestion: String,
    pub(super) can_retry: bool,
}

impl CategorizedError {
    pub(super) fn new(
        category: ErrorCategory,
        user_message: impl Into<String>,
        technical_details: impl Into<String>,
        recovery_suggestion: impl Into<String>,
        can_retry: bool,
    ) -> Self {
        Self {
            category,
            user_message: user_message.into(),
            technical_details: technical_details.into(),
            recovery_suggestion: recovery_suggestion.into(),
            can_retry,
        }
    }
}

// Toast notification system
#[derive(Debug, Clone, PartialEq)]
pub(super) enum ToastKind {
    Success,
    Error,
    Info,
}

#[derive(Debug, Clone)]
pub(super) struct Toast {
    pub(super) kind: ToastKind,
    pub(super) message: String,
    pub(super) created_at: SystemTime,
    pub(super) duration_secs: u64,
}

impl Toast {
    pub(super) fn success(message: impl Into<String>) -> Self {
        Self {
            kind: ToastKind::Success,
            message: message.into(),
            created_at: SystemTime::now(),
            duration_secs: 4,
        }
    }

    pub(super) fn error(message: impl Into<String>) -> Self {
        Self {
            kind: ToastKind::Error,
            message: message.into(),
            created_at: SystemTime::now(),
            duration_secs: 6,
        }
    }

    pub(super) fn info(message: impl Into<String>) -> Self {
        Self {
            kind: ToastKind::Info,
            message: message.into(),
            created_at: SystemTime::now(),
            duration_secs: 3,
        }
    }

    pub(super) fn is_expired(&self) -> bool {
        SystemTime::now()
            .duration_since(self.created_at)
            .map(|d| d.as_secs() >= self.duration_secs)
            .unwrap_or(true)
    }
}

// Track which action can be retried
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RetryAction {
    Join,
    Send,
    Leave,
    Refresh,
}

#[derive(Clone, Default)]
pub(super) struct MessageComposer {
    pub(super) text: String,
    pub(super) active: bool,
}

// Configuration constants have been moved to cityg_config
// These are kept as fallback if needed but should use config from AppModel

impl MessageComposer {
    pub(super) fn clear(&mut self) {
        self.text.clear();
    }

    pub(super) fn is_ready(&self) -> bool {
        !self.text.trim().is_empty()
    }

    pub(super) fn focus(&mut self) {
        self.active = true;
    }

    pub(super) fn blur(&mut self) {
        self.active = false;
    }

    pub(super) fn set_text(&mut self, text: String) {
        self.text = text;
    }

    pub(super) fn text(&self) -> &str {
        self.text.as_str()
    }

    pub(super) fn handle_keystroke(&mut self, ks: &Keystroke) -> KeyOutcome {
        if !self.active {
            return KeyOutcome::None;
        }

        if ks.key == "escape" {
            self.blur();
            return KeyOutcome::Updated;
        }

        if ks.key == "return" || ks.key == "enter" {
            if self.is_ready() {
                return KeyOutcome::Submit;
            }
            return KeyOutcome::None;
        }

        if ks.key == "backspace" {
            if !self.text.is_empty() {
                self.text.pop();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "delete" {
            if !self.text.is_empty() {
                self.text.clear();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "space" {
            self.text.push(' ');
            return KeyOutcome::Updated;
        }

        if let Some(ch) = ks.key_char.as_ref() {
            if ks.modifiers.control
                || ks.modifiers.alt
                || ks.modifiers.platform
                || ks.modifiers.function
            {
                return KeyOutcome::None;
            }
            if ch.chars().any(|c| c == '\n' || c == '\r' || c == '\t') {
                return KeyOutcome::None;
            }
            self.text.push_str(ch);
            return KeyOutcome::Updated;
        }

        KeyOutcome::None
    }
}

#[derive(Clone, Default)]
pub(super) struct MembersSearchState {
    pub(super) query: String,
    pub(super) active: bool,
}

impl MembersSearchState {
    pub(super) fn focus(&mut self) {
        self.active = true;
    }

    pub(super) fn blur(&mut self) {
        self.active = false;
    }

    pub(super) fn clear(&mut self) {
        self.query.clear();
    }

    pub(super) fn set_query(&mut self, query: String) {
        self.query = query;
    }

    pub(super) fn query(&self) -> &str {
        self.query.as_str()
    }

    pub(super) fn handle_keystroke(&mut self, ks: &Keystroke) -> KeyOutcome {
        if !self.active {
            return KeyOutcome::None;
        }

        if ks.key == "escape" {
            self.blur();
            return KeyOutcome::Updated;
        }

        if ks.key == "tab" {
            self.blur();
            return KeyOutcome::Updated;
        }

        if ks.key == "return" || ks.key == "enter" {
            return KeyOutcome::Submit;
        }

        if ks.key == "backspace" {
            if !self.query.is_empty() {
                self.query.pop();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "delete" {
            if !self.query.is_empty() {
                self.query.clear();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "space" {
            self.query.push(' ');
            return KeyOutcome::Updated;
        }

        if let Some(ch) = ks.key_char.as_ref() {
            if ks.modifiers.control
                || ks.modifiers.alt
                || ks.modifiers.platform
                || ks.modifiers.function
            {
                return KeyOutcome::None;
            }

            if ch.chars().any(|c| c == '\n' || c == '\r' || c == '\t') {
                return KeyOutcome::None;
            }

            self.query.push_str(ch);
            return KeyOutcome::Updated;
        }

        KeyOutcome::None
    }
}

#[derive(Clone, Default)]
pub(super) struct RoomAdminTargetState {
    pub(super) value: String,
    pub(super) active: bool,
}

impl RoomAdminTargetState {
    pub(super) fn focus(&mut self) {
        self.active = true;
    }

    pub(super) fn blur(&mut self) {
        self.active = false;
    }

    pub(super) fn clear(&mut self) {
        self.value.clear();
    }

    pub(super) fn set_value(&mut self, value: String) {
        self.value = value;
    }

    pub(super) fn value(&self) -> &str {
        self.value.as_str()
    }

    pub(super) fn handle_keystroke(&mut self, ks: &Keystroke) -> KeyOutcome {
        if !self.active {
            return KeyOutcome::None;
        }

        if ks.key == "escape" {
            self.blur();
            return KeyOutcome::Updated;
        }

        if ks.key == "tab" {
            self.blur();
            return KeyOutcome::Updated;
        }

        if ks.key == "return" || ks.key == "enter" {
            return KeyOutcome::Submit;
        }

        if ks.key == "backspace" {
            if !self.value.is_empty() {
                self.value.pop();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "delete" {
            if !self.value.is_empty() {
                self.value.clear();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "space" {
            self.value.push(' ');
            return KeyOutcome::Updated;
        }

        if let Some(ch) = ks.key_char.as_ref() {
            if ks.modifiers.control
                || ks.modifiers.alt
                || ks.modifiers.platform
                || ks.modifiers.function
            {
                return KeyOutcome::None;
            }

            if ch.chars().any(|c| c == '\n' || c == '\r' || c == '\t') {
                return KeyOutcome::None;
            }

            self.value.push_str(ch);
            return KeyOutcome::Updated;
        }

        KeyOutcome::None
    }
}

#[derive(Clone, Default)]
pub(super) enum MembersMode {
    #[default]
    Full,
    Search {
        query: String,
    },
}

#[derive(Clone)]
pub(super) struct SecurityEvent {
    pub(super) alias: String,
    pub(super) description: String,
    pub(super) timestamp_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ActivityKind {
    Connection,
    Roster,
    Message,
    Sync,
    System,
}

#[derive(Clone, Debug)]
pub(super) struct ActivityEvent {
    pub(super) kind: ActivityKind,
    pub(super) summary: String,
    pub(super) detail: Option<String>,
    pub(super) timestamp_ms: u64,
}

#[derive(Clone)]
pub(super) struct ChatMessageEntry {
    pub(super) sender_leaf: Option<[u8; 32]>,
    pub(super) fallback_label: String,
    pub(super) plaintext: String,
    pub(super) ciphertext_hex: String,
    pub(super) timestamp_ms: u64,
    pub(super) delivery: MessageDelivery,
    pub(super) pending_id: Option<u64>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum MessageDelivery {
    Pending,
    Sent,
    Failed,
}

#[derive(Hash, Eq, PartialEq, Clone)]
pub(super) struct MessageKey {
    pub(super) ciphertext_hex: String,
    pub(super) sender_leaf: Option<[u8; 32]>,
}

#[derive(Clone)]
pub(super) struct MemberEntry {
    pub(super) leaf_id: [u8; 32],
    pub(super) alias: Option<String>,
    pub(super) pop_public_key: Option<Vec<u8>>,
    pub(super) join_timestamp_ms: Option<u64>,
    pub(super) last_seen_timestamp_ms: Option<u64>,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct AliasBindingRecord {
    pub(super) pop_public_key: Vec<u8>,
    pub(super) leaf_id: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RoomIdentity {
    pub(super) pop_public_key: Vec<u8>,
    pub(super) pop_secret_key: Vec<u8>,
}

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
    pub(super) msg_sign_public_key: Vec<u8>, // ML-DSA-65 (Dilithium3) for message authentication
    pub(super) msg_sign_secret_key: Vec<u8>, // ML-DSA-65 (Dilithium3) for message authentication
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
    pub(super) last_fetch_timestamp_ms: Option<u64>,
    pub(super) msg_replay_state: MsgReplayState,
    pub(super) capss_witness: Vec<u8>,
    pub(super) barrier_state: BarrierSecretState,
}

#[derive(Clone)]
pub(super) struct BarrierSecretState {
    pub(super) barrier_initialized: bool,
    pub(super) barrier_version: u64,
    pub(super) barrier_roots_hash: [u8; 32],
    pub(super) k_barrier: Zeroizing<[u8; 32]>,
    pub(super) kem_tree_hash_after: [u8; 32],
    pub(super) max_barrier_update_bytes: u64,
    pub(super) n_max: u64,
    pub(super) cover_leaf_index: u64,
    pub(super) dk_leaf: Zeroizing<Vec<u8>>,
    pub(super) pkhash_leaf: [u8; 32],
    pub(super) dk_nodes: BTreeMap<u32, BarrierNodeKeyMaterial>,
    pub(super) pending: Option<BarrierPendingState>,
    pub(super) barrier_recovery_pending: bool,
}

impl Default for BarrierSecretState {
    fn default() -> Self {
        Self {
            barrier_initialized: false,
            barrier_version: 0,
            barrier_roots_hash: [0u8; 32],
            k_barrier: Zeroizing::new([0u8; 32]),
            kem_tree_hash_after: [0u8; 32],
            max_barrier_update_bytes: 0,
            n_max: DEFAULT_BARRIER_N_MAX,
            cover_leaf_index: 0,
            dk_leaf: Zeroizing::new(Vec::new()),
            pkhash_leaf: [0u8; 32],
            dk_nodes: BTreeMap::new(),
            pending: None,
            barrier_recovery_pending: false,
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
}

#[derive(Clone)]
pub(super) struct PublishedBarrierMerge {
    pub(super) bundle: ClientEpochBundle,
    pub(super) pending_barrier_state: BarrierPendingState,
    pub(super) forward_state_after: ForwardSecrecyState,
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

    pub(super) fn pending_guard_message(self) -> &'static str {
        match self {
            Self::PcsRefresh => {
                "cannot originate PCS refresh while barrier recovery is pending; complete FULL barrier recovery first"
            }
            Self::JoinFinalize => {
                "cannot originate join finalization while barrier recovery is pending without join-finalize eligibility"
            }
        }
    }

    pub(super) fn reseeds_k_fs(self) -> bool {
        matches!(self, Self::PcsRefresh)
    }
}
