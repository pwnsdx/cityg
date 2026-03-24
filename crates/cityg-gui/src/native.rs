#[cfg(test)]
use std::fs;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::barrier_shared::{
    BARRIER_KEY_INFO, BARRIER_TREE_INFO, BarrierDeriveSaltPreimage, BarrierTreePathSaltPreimage,
    DEFAULT_BARRIER_N_MAX, TICKET_RETRY_MAX_ATTEMPTS, apply_join_set_to_snapshot,
    apply_revoked_set_to_snapshot, barrier_path_nodes, blank_leaf_and_path,
    collect_resolution_targets, compute_barrier_pkhash, compute_barrier_tree_hash,
    compute_revocation_roots_hash, expected_barrier_tree_nodes, should_retry_ticket_http_error,
    sibling_node, ticket_retry_delay,
};
#[cfg(test)]
use crate::message_crypto::{MSG_INDEX_REPLAY_WINDOW, decrypt_message_v2};
use crate::message_crypto::{MsgReplayState, PersistedMsgReplayState};
use ahash::AHashMap;
use anchor_seed::{
    SeedCommitFields, build_anchor_seed_ctx, compute_seed_bundle_commit, compute_seed_commit,
    compute_seed_ctx_hash,
};
use anyhow::{Context as AnyhowContext, Result, anyhow};
use ciborium::value::{Integer, Value};
use cityg_api_client::{
    BarrierJoinRecord, BarrierPublicTree, CitygApiClient, Error as ApiClientError, MergeTicket,
    RoomAdminOperation, build_room_admin_listing_proof, build_room_admin_proof,
    build_room_admin_target_proof,
};
use cityg_client::witness::SrxInputsOwned;
use cityg_client::{CityGClient, ClientEpochBundle};
use cityg_config::CityGConfig;
use gpui::prelude::*;
#[cfg(not(test))]
use gpui::{
    App, Application, Bounds, TitlebarOptions, WindowBounds, WindowDecorations, WindowOptions, size,
};
use gpui::{
    ClipboardItem, Context as ViewContext, CursorStyle, Div, FontWeight, Keystroke, MouseButton,
    MouseDownEvent, Render, ScrollHandle, Task, Window, div, point, px, rgb,
};
use hex::{decode as hex_decode, encode as hex_encode};
use humantime::format_rfc3339_seconds;
use ml_kem::{
    ExpandedDecapsulationKey as MlKemExpandedDecapsulationKey, Seed as MlKemSeed,
    kem::{Decapsulate as MlKemDecapsulate, KeyExport as MlKemKeyExport},
    ml_kem_768,
    ml_kem_768::DecapsulationKey as MlKem768DecapsulationKey,
};
use msphf_core::{
    ds, hash::h_l, hkdf::hkdf_blake3, merkle::canonical_set_root, serde_utils::to_cbor_vec,
};
use msphf_orchestrator::CapssWitnessBundle;
use msphf_orchestrator::{
    AnchorInstanceParts, ForwardSecrecyState, FsJoinInputs, FsMergeInputs, LeafIdMode,
    OrchestrationParams, PivotParity, PopKeypair, SrxMode, compute_proofs_commit_bytes,
    derive_we_epoch_id, hdr,
};
use pqcrypto_dilithium::{
    dilithium3::{self},
    dilithium5,
};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
};
use pqcrypto_traits::sign::{
    DetachedSignature, PublicKey as DilithiumPublicKey, SecretKey as DilithiumSecretKey,
};
use rand::{RngExt, rng};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::time::sleep;
use tracing::{debug, info, warn};
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
use cityg_client::demo;

#[path = "native/app_shell.rs"]
mod app_shell;
#[path = "native/barrier_core.rs"]
mod barrier_core;
#[path = "native/barrier_ops.rs"]
mod barrier_ops;
#[path = "native/barrier_runtime.rs"]
mod barrier_runtime;
#[path = "native/chat_ui.rs"]
mod chat_ui;
#[path = "native/epoch_sync.rs"]
mod epoch_sync;
#[path = "native/errors.rs"]
mod errors;
#[path = "native/fault_injection.rs"]
mod fault_injection;
#[path = "native/helpers.rs"]
mod helpers;
#[path = "native/interactions.rs"]
mod interactions;
#[path = "native/join_form.rs"]
mod join_form;
#[path = "native/join_ops.rs"]
mod join_ops;
#[path = "native/lifecycle.rs"]
mod lifecycle;
#[path = "native/member_validation.rs"]
mod member_validation;
#[path = "native/members.rs"]
mod members;
#[path = "native/message_auth.rs"]
mod message_auth;
#[path = "native/network_ops.rs"]
mod network_ops;
#[path = "native/params.rs"]
mod params;
#[path = "native/persisted.rs"]
mod persisted;
#[path = "native/pivot_helpers.rs"]
mod pivot_helpers;
#[path = "native/render_panels.rs"]
mod render_panels;
#[path = "native/render_session.rs"]
mod render_session;
#[path = "native/room_admin.rs"]
mod room_admin;
#[path = "native/session_runtime.rs"]
mod session_runtime;
#[path = "native/session_state.rs"]
mod session_state;
#[path = "native/storage.rs"]
mod storage;
#[path = "native/tokio_bridge.rs"]
mod tokio_bridge;
#[path = "native/websocket.rs"]
mod websocket;

use app_shell::*;
use barrier_core::*;
use barrier_ops::*;
use barrier_runtime::*;
use errors::*;
#[cfg(test)]
use fault_injection::*;
use helpers::*;
use join_form::*;
use join_ops::*;
use member_validation::*;
use message_auth::*;
use network_ops::*;
use params::*;
use persisted::*;
use pivot_helpers::*;
use storage::*;
use tokio_bridge::Tokio;

fn generate_vrf_keys() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut params_seed = [0u8; 32];
    let mut key_seed = [0u8; 32];
    let mut rng = rng();
    rng.fill(&mut params_seed);
    rng.fill(&mut key_seed);
    let params = msphf_orchestrator::lb::generate_parameters(params_seed)
        .map_err(|err| anyhow!("generate VRF params: {err}"))?;
    msphf_orchestrator::lb::generate_keypair(&params, key_seed)
        .map_err(|err| anyhow!("generate VRF keypair: {err}"))
}

#[cfg(test)]
const DEFAULT_MAX_BARRIER_UPDATE_BYTES: u64 = 1_048_576;
const JOIN_INVITE_PREFIX: &str = "cityg-invite:";

fn is_refresh_pivot_conflict(status_code: u16, message: &str) -> bool {
    matches!(status_code, 409 | 500)
        && (message.contains("pivot head missing")
            || message.contains("refresh payload diverges from stored parity"))
}

#[cfg(not(test))]
pub fn main() {
    app_shell::run_native_app();
}

struct AppModel {
    config: CityGConfig,
    join_form: JoinFormState,
    join_status: JoinStatus,
    leave_status: LeaveStatus,
    session: Option<AppSession>,
    last_error: Option<String>,
    categorized_error: Option<CategorizedError>,
    info_message: Option<String>,
    toasts: Vec<Toast>,
    messages: Vec<ChatMessageEntry>,
    message_keys: HashSet<MessageKey>,
    next_pending_message_id: u64,
    fetch_status: FetchStatus,
    send_status: SendStatus,
    composer: MessageComposer,
    fetch_task: Option<Task<()>>,
    fetch_in_flight: bool,
    fetch_after_epoch_sync: bool,
    show_ciphertext: bool,
    members: Vec<MemberEntry>,
    members_status: MembersStatus,
    members_total: u64,
    members_next_offset: Option<u64>,
    members_loading_append: bool,
    members_auto_page: bool,
    members_alias_dirty: bool,
    members_mode: MembersMode,
    members_search: MembersSearchState,
    members_refresh_task: Option<Task<()>>,
    alias_bindings: AHashMap<String, AliasBindingRecord>,
    leaf_alias_index: AHashMap<[u8; 32], String>,
    room_admins: Vec<Vec<u8>>,
    room_admins_loaded: bool,
    room_admin_status: RoomAdminStatus,
    room_admin_target: RoomAdminTargetState,
    room_admin_revoke_confirmation: Option<Vec<u8>>,
    epoch_sync_task: Option<Task<()>>, // Background task for membership-driven epoch sync
    ws_task: Option<Task<()>>,         // WebSocket connection task
    ws_connected: bool,                // WebSocket connection status
    ws_autostart_attempted: bool,
    restore_epoch_sync_pending: bool,
    last_retry_action: Option<RetryAction>, // Track what action to retry
    security_events: Vec<SecurityEvent>,
    security_unread: u32,
    security_panel_expanded: bool,
    activity_events: Vec<ActivityEvent>,
    chat_scroll_handle: ScrollHandle,
    right_sidebar_scroll_handle: ScrollHandle,
}

enum JoinStatus {
    Idle,
    Joining,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LeaveStatus {
    Idle,
    Leaving,
    Refreshing,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FetchStatus {
    Idle,
    Refreshing,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SendStatus {
    Idle,
    Sending,
}

#[derive(Clone, PartialEq, Eq)]
enum RoomAdminStatus {
    Idle,
    Loading(String),
    Error(String),
}

#[derive(Clone, PartialEq, Eq)]
enum MembersStatus {
    Idle,
    Loading(String),
    Error(String),
}

// Error categorization for user-friendly error handling
#[derive(Debug, Clone, PartialEq, Eq)]
enum ErrorCategory {
    Network,
    Crypto,
    Policy,
    Server,
    Validation,
}

#[derive(Debug, Clone)]
struct CategorizedError {
    category: ErrorCategory,
    user_message: String,
    technical_details: String,
    recovery_suggestion: String,
    can_retry: bool,
}

impl CategorizedError {
    fn new(
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
enum ToastKind {
    Success,
    Error,
    Info,
}

#[derive(Debug, Clone)]
struct Toast {
    kind: ToastKind,
    message: String,
    created_at: SystemTime,
    duration_secs: u64,
}

impl Toast {
    fn success(message: impl Into<String>) -> Self {
        Self {
            kind: ToastKind::Success,
            message: message.into(),
            created_at: SystemTime::now(),
            duration_secs: 4,
        }
    }

    fn error(message: impl Into<String>) -> Self {
        Self {
            kind: ToastKind::Error,
            message: message.into(),
            created_at: SystemTime::now(),
            duration_secs: 6,
        }
    }

    fn info(message: impl Into<String>) -> Self {
        Self {
            kind: ToastKind::Info,
            message: message.into(),
            created_at: SystemTime::now(),
            duration_secs: 3,
        }
    }

    fn is_expired(&self) -> bool {
        SystemTime::now()
            .duration_since(self.created_at)
            .map(|d| d.as_secs() >= self.duration_secs)
            .unwrap_or(true)
    }
}

// Track which action can be retried
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryAction {
    Join,
    Send,
    Leave,
    Refresh,
}

#[derive(Clone, Default)]
struct MessageComposer {
    text: String,
    active: bool,
}

// Configuration constants have been moved to cityg_config
// These are kept as fallback if needed but should use config from AppModel

impl MessageComposer {
    fn clear(&mut self) {
        self.text.clear();
    }

    fn is_ready(&self) -> bool {
        !self.text.trim().is_empty()
    }

    fn focus(&mut self) {
        self.active = true;
    }

    fn blur(&mut self) {
        self.active = false;
    }

    fn set_text(&mut self, text: String) {
        self.text = text;
    }

    fn text(&self) -> &str {
        self.text.as_str()
    }

    fn handle_keystroke(&mut self, ks: &Keystroke) -> KeyOutcome {
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
struct MembersSearchState {
    query: String,
    active: bool,
}

impl MembersSearchState {
    fn focus(&mut self) {
        self.active = true;
    }

    fn blur(&mut self) {
        self.active = false;
    }

    fn clear(&mut self) {
        self.query.clear();
    }

    fn set_query(&mut self, query: String) {
        self.query = query;
    }

    fn query(&self) -> &str {
        self.query.as_str()
    }

    fn handle_keystroke(&mut self, ks: &Keystroke) -> KeyOutcome {
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
struct RoomAdminTargetState {
    value: String,
    active: bool,
}

impl RoomAdminTargetState {
    fn focus(&mut self) {
        self.active = true;
    }

    fn blur(&mut self) {
        self.active = false;
    }

    fn clear(&mut self) {
        self.value.clear();
    }

    fn set_value(&mut self, value: String) {
        self.value = value;
    }

    fn value(&self) -> &str {
        self.value.as_str()
    }

    fn handle_keystroke(&mut self, ks: &Keystroke) -> KeyOutcome {
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
enum MembersMode {
    #[default]
    Full,
    Search {
        query: String,
    },
}

#[derive(Clone)]
struct SecurityEvent {
    alias: String,
    description: String,
    timestamp_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActivityKind {
    Connection,
    Roster,
    Message,
    Sync,
    System,
}

#[derive(Clone, Debug)]
struct ActivityEvent {
    kind: ActivityKind,
    summary: String,
    detail: Option<String>,
    timestamp_ms: u64,
}

#[derive(Clone)]
struct ChatMessageEntry {
    sender_leaf: Option<[u8; 32]>,
    fallback_label: String,
    plaintext: String,
    ciphertext_hex: String,
    timestamp_ms: u64,
    delivery: MessageDelivery,
    pending_id: Option<u64>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MessageDelivery {
    Pending,
    Sent,
    Failed,
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct MessageKey {
    ciphertext_hex: String,
    sender_leaf: Option<[u8; 32]>,
}

#[derive(Clone)]
struct MemberEntry {
    leaf_id: [u8; 32],
    alias: Option<String>,
    pop_public_key: Option<Vec<u8>>,
    join_timestamp_ms: Option<u64>,
    last_seen_timestamp_ms: Option<u64>,
}

#[derive(Clone, PartialEq, Eq)]
struct AliasBindingRecord {
    pop_public_key: Vec<u8>,
    leaf_id: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RoomIdentity {
    pop_public_key: Vec<u8>,
    pop_secret_key: Vec<u8>,
}

#[derive(Clone)]
struct AppSession {
    server_url: String,
    room_id: String,
    alias: String,
    gid: [u8; 32],
    cat: [u8; 32],
    leaf_id: [u8; 32],
    parent_root: [u8; 32],
    join_delta_root: [u8; 32],
    revoked_since_root: [u8; 32],
    revoked_root: [u8; 32],
    regular_fingerprint: Option<[u8; 32]>,
    fs_fingerprint: Option<[u8; 32]>,
    tswe_salt_hash: [u8; 32],
    pox_r_commit: [u8; 32],
    we_epoch_id: [u8; 32],
    xk_hash: [u8; 32],
    epoch_key: [u8; 32],
    forward_state: ForwardSecrecyState,
    fs_ec: u64,
    fs_epoch_commit: [u8; 32],
    fs_dev_prev_commit: [u8; 32],
    fs_epoch_created_at: SystemTime, // Timestamp when current epoch was created
    fs_epoch_rotation_interval_secs: u64, // Epoch rotation interval (default: 300 = 5 min)
    pop_public_key: Vec<u8>,
    pop_secret_key: Vec<u8>,
    msg_sign_public_key: Vec<u8>, // ML-DSA-65 (Dilithium3) for message authentication
    msg_sign_secret_key: Vec<u8>, // ML-DSA-65 (Dilithium3) for message authentication
    vrf_secret_key: Vec<u8>,
    vrf_public_key: Vec<u8>,
    kbroad_public: Vec<u8>,
    bootstrap_public: Vec<u8>,
    proof_mode: String,
    vrf_id: String,
    policy_version: String,
    msphf_crs_id: String,
    msphf_params_id: String,
    fs_policy_version: String,
    fs_epoch_base_ts: u64,
    last_fetch_timestamp_ms: Option<u64>,
    msg_replay_state: MsgReplayState,
    capss_witness: Vec<u8>,
    barrier_state: BarrierSecretState,
}

#[derive(Clone)]
struct BarrierSecretState {
    barrier_initialized: bool,
    barrier_version: u64,
    barrier_roots_hash: [u8; 32],
    k_barrier: Zeroizing<[u8; 32]>,
    kem_tree_hash_after: [u8; 32],
    max_barrier_update_bytes: u64,
    n_max: u64,
    cover_leaf_index: u64,
    dk_leaf: Zeroizing<Vec<u8>>,
    pkhash_leaf: [u8; 32],
    dk_nodes: BTreeMap<u32, BarrierNodeKeyMaterial>,
    pending: Option<BarrierPendingState>,
    barrier_recovery_pending: bool,
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
struct BarrierNodeKeyMaterial {
    dk: Zeroizing<Vec<u8>>,
    pkhash: [u8; 32],
}

impl Drop for BarrierNodeKeyMaterial {
    fn drop(&mut self) {
        self.dk.zeroize();
        self.pkhash.zeroize();
    }
}

#[derive(Clone, Default)]
struct BarrierPendingState {
    barrier_version: u64,
    we_epoch_id: [u8; 32],
    fs_ec: u64,
    next_forward_fs_ec: u64,
    next_forward_fs_dev_commit: [u8; 32],
    next_forward_last_weid: [u8; 32],
    revocation_roots_hash: [u8; 32],
    kem_tree_hash_after: [u8; 32],
    k_barrier_new: Zeroizing<[u8; 32]>,
    k_fs_after_pcs: Option<Zeroizing<[u8; 32]>>,
    barrier_update_reason: Option<u64>,
    barrier_update_digest: [u8; 32],
    on_path_key_material: BTreeMap<u32, BarrierNodeKeyMaterial>,
}

#[derive(Clone)]
struct PublishedBarrierMerge {
    bundle: ClientEpochBundle,
    pending_barrier_state: BarrierPendingState,
    forward_state_after: ForwardSecrecyState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BarrierMergeMode {
    PcsRefresh,
    JoinFinalize,
}

impl BarrierMergeMode {
    fn reason(self) -> u64 {
        match self {
            Self::PcsRefresh => 1,
            Self::JoinFinalize => 2,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::PcsRefresh => "refresh",
            Self::JoinFinalize => "join_finalize",
        }
    }

    fn publish_context(self) -> &'static str {
        match self {
            Self::PcsRefresh => "publish PCS refresh",
            Self::JoinFinalize => "publish join finalization barrier update",
        }
    }

    fn persist_context(self) -> &'static str {
        match self {
            Self::PcsRefresh => "persist refreshed room session",
            Self::JoinFinalize => "persist join-finalized room session",
        }
    }

    fn fallback_sync_context(self) -> &'static str {
        match self {
            Self::PcsRefresh => "recover initial barrier state after setup merge",
            Self::JoinFinalize => "recover barrier state after join finalization merge",
        }
    }

    fn still_pending_message(self) -> &'static str {
        match self {
            Self::PcsRefresh => {
                "initial room setup completed but barrier recovery is still pending"
            }
            Self::JoinFinalize => {
                "join finalization completed but barrier recovery is still pending"
            }
        }
    }

    fn build_bundle_context(self) -> &'static str {
        match self {
            Self::PcsRefresh => "failed to build refresh merge bundle",
            Self::JoinFinalize => "failed to build join finalize merge bundle",
        }
    }

    fn accept_bundle_context(self) -> &'static str {
        match self {
            Self::PcsRefresh => "server rejected refresh merge bundle",
            Self::JoinFinalize => "server rejected join finalize merge bundle",
        }
    }

    fn pending_guard_message(self) -> &'static str {
        match self {
            Self::PcsRefresh => {
                "cannot originate PCS refresh while barrier recovery is pending; complete FULL barrier recovery first"
            }
            Self::JoinFinalize => {
                "cannot originate join finalization while barrier recovery is pending without join-finalize eligibility"
            }
        }
    }

    fn reseeds_k_fs(self) -> bool {
        matches!(self, Self::PcsRefresh)
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::await_holding_lock,
    clippy::useless_conversion
)]
#[path = "native/tests/mod.rs"]
mod tests;
