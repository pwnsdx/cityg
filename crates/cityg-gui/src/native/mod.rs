#[cfg(test)]
use std::fs;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(test)]
use crate::barrier_shared::compute_barrier_pkhash;
#[cfg(test)]
use crate::barrier_shared::compute_barrier_tree_hash;
#[cfg(test)]
use crate::barrier_shared::expected_barrier_tree_nodes;
#[cfg(test)]
use crate::barrier_shared::validate_barrier_n_max;
#[cfg(test)]
use crate::barrier_shared::{
    BARRIER_KEY_INFO, BARRIER_TREE_INFO, BarrierDeriveSaltPreimage, BarrierTreePathSaltPreimage,
};
use crate::barrier_shared::{
    DEFAULT_BARRIER_N_MAX, TICKET_RETRY_MAX_ATTEMPTS, compute_revocation_roots_hash,
    should_retry_ticket_http_error, ticket_retry_delay,
};
#[cfg(test)]
use crate::message_crypto::{
    MAX_MSGS_PER_REPLAY_TUPLE, MessageCryptoContext, decrypt_message_v2,
    decrypt_message_v2_with_index, derive_msg_replay_tuple_tag, encrypt_message_v2,
};
use crate::message_crypto::{MsgReplayState, PersistedMsgReplayState};
use ahash::AHashMap;
use anyhow::{Context as AnyhowContext, Result, anyhow};
#[cfg(test)]
use ciborium::value::Integer;
use ciborium::value::Value;
#[cfg(test)]
use cityg_api_client::room_admin_public_key_bytes;
use cityg_api_client::{
    BarrierJoinRecord, BarrierPublicTree, CitygApiClient, Error as ApiClientError,
    HistoryAuthorityExtension, HistoryCommitment, MergeAcceptanceStatus, MergeTicket,
    RoomAdminIdentity as RoomIdentity, RoomAdminOperation,
};
use cityg_client::ClientEpochBundle;
#[cfg(test)]
use cityg_client::message_auth::{
    message_signature_bytes as ml_dsa_signature_bytes,
    message_signing_public_key_bytes as ml_dsa_public_key_bytes,
};
use cityg_config::CityGConfig;
#[cfg(not(test))]
use gpui::Application;
use gpui::prelude::*;
use gpui::{
    App, Bounds, ClipboardItem, Context as ViewContext, CursorStyle, Div, DragMoveEvent, Element,
    ElementId, ElementInputHandler, EmptyView, Entity, EntityInputHandler, FocusHandle, FontWeight,
    GlobalElementId, Keystroke, LayoutId, MaterialEmphasis, MaterialStyle, MouseButton,
    MouseDownEvent, MouseMoveEvent, MouseUpEvent, PaintQuad, Pixels, PromptLevel, Render,
    ScrollHandle, ShapedLine, SharedString, Style, Task, TextRun, UTF16Selection, UnderlineStyle,
    Window, div, fill, material_surface, point, px, relative, rgb, rgba, size,
};
#[cfg(not(test))]
use gpui::{
    TitlebarOptions, WindowBackgroundAppearance, WindowBounds, WindowDecorations, WindowOptions,
};
use hex::{decode as hex_decode, encode as hex_encode};
use humantime::format_rfc3339_seconds;
#[cfg(test)]
use msphf_core::hash::h_l;
use msphf_core::merkle::canonical_set_root;
#[cfg(test)]
use msphf_core::{hkdf::hkdf_blake3, serde_utils::to_cbor_vec};
#[cfg(test)]
use msphf_orchestrator::CapssWitnessBundle;
#[cfg(test)]
use msphf_orchestrator::compute_fs_dev_commit_v2;
use msphf_orchestrator::{
    AnchorInstanceParts, ForwardSecrecyState, OrchestrationParams, PivotParity, hdr,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::time::sleep;
#[cfg(test)]
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;
use tracing::{debug, info, warn};
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
pub(crate) use crate::websocket_replay::{
    websocket_ack_message, websocket_lag_notice, websocket_notification_replayed,
    websocket_notification_sequence, websocket_resume_message, websocket_sync_required_notice,
};
#[cfg(test)]
use cityg_client::demo;
#[cfg(test)]
use futures::StreamExt;
#[cfg(test)]
use futures::channel::mpsc as futures_mpsc;

mod activity_state;
mod app_actions;
mod app_shell;
mod barrier_activation_runtime;
mod barrier_core;
mod barrier_epoch_sync_runtime;
mod barrier_finalize_runtime;
mod barrier_merge_execution_runtime;
mod barrier_merge_prepare_runtime;
mod barrier_merge_publish_runtime;
mod barrier_merge_runtime;
mod barrier_merge_ticket_runtime;
mod barrier_public_tree_cache;
mod barrier_recovery_runtime;
mod barrier_revocation_runtime;
mod barrier_state_transitions;
mod barrier_verification_runtime;
mod chat_actions;
mod chat_render;
mod clipboard_shortcuts;
mod endpoint_mode;
mod epoch_sync;
mod errors;
mod fault_injection;
mod helpers;
mod input_state;
mod interactions;
mod join_form;
mod join_ops;
mod lifecycle;
mod lifecycle_join_send;
mod member_validation;
mod members;
mod message_auth;
mod native_notifications;
mod native_text_input;
mod network_members;
mod network_messages;
mod network_room_admin;
mod overview_window;
mod params;
mod persisted;
mod pivot_helpers;
mod render_activity_panel;
mod render_details;
mod render_members_panel;
mod render_message_composer;
mod render_overview_panel;
mod render_room_admin_panel;
mod render_security_panel;
mod render_session;
mod render_session_controls;
mod render_workspace;
mod room_admin;
mod session_epoch_sync;
mod session_fetch;
mod session_runtime;
mod session_state;
mod session_types;
mod session_websocket;
mod shell_feedback;
mod shell_join_view;
mod shell_ui;
mod state;
mod storage;
mod storage_crypto;
mod storage_logs;
mod storage_paths;
mod tokio_bridge;
mod websocket;

use activity_state::*;
use barrier_activation_runtime::*;
use barrier_core::*;
use barrier_epoch_sync_runtime::*;
use barrier_finalize_runtime::*;
use barrier_merge_runtime::*;
use barrier_public_tree_cache::*;
use barrier_recovery_runtime::*;
use barrier_revocation_runtime::*;
use barrier_state_transitions::*;
use barrier_verification_runtime::*;
#[cfg(test)]
use epoch_sync::*;
use errors::*;
#[cfg(test)]
use fault_injection::*;
use helpers::*;
use input_state::*;
use join_form::*;
use join_ops::*;
use member_validation::*;
use message_auth::*;
use native_text_input::*;
use network_members::*;
use network_messages::*;
use network_room_admin::*;
use params::*;
use persisted::*;
use pivot_helpers::*;
use session_types::*;
use shell_ui::*;
use state::*;
use storage::*;
use storage_crypto::*;
use storage_logs::*;
use storage_paths::*;
use tokio_bridge::Tokio;
#[cfg(test)]
use websocket::*;

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

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::await_holding_lock,
    clippy::useless_conversion
)]
mod tests;
