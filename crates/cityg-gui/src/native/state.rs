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
    pub(super) window_active: bool,
    pub(super) restore_epoch_sync_pending: bool,
    pub(super) last_retry_action: Option<RetryAction>, // Track what action to retry
    pub(super) security_events: Vec<SecurityEvent>,
    pub(super) security_unread: u32,
    pub(super) security_panel_expanded: bool,
    pub(super) activity_events: Vec<ActivityEvent>,
    pub(super) chat_scroll_handle: ScrollHandle,
    pub(super) right_sidebar_scroll_handle: ScrollHandle,
    pub(super) session_overview_window: Option<AnyWindowHandle>,
    pub(super) root_focus_handle: Option<FocusHandle>,
    pub(super) native_text_inputs_bound: bool,
}

pub(super) enum JoinStatus {
    Idle,
    Joining,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum LeaveStatus {
    Idle,
    Leaving,
    Expelling,
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
