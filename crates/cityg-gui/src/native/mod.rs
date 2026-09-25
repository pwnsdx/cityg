use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ahash::AHashMap;
use anyhow::{Context as AnyhowContext, Result, anyhow};
use cityg_api_client::{INVITE_PREFIX, InviteLink, Member};
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
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::time::sleep;
use tracing::{info, warn};
use zeroize::Zeroizing;

mod activity_state;
mod app_actions;
mod app_shell;
mod chat_actions;
mod chat_render;
mod clipboard_shortcuts;
mod endpoint_mode;
mod engine;
mod errors;
mod helpers;
mod input_state;
mod interactions;
mod join_form;
mod lifecycle;
mod lifecycle_join_send;
mod members;
mod native_notifications;
mod native_text_input;
mod overview_window;
mod persisted;
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
use errors::*;
use helpers::*;
use input_state::*;
use join_form::*;
use native_text_input::*;
use persisted::*;
use room_admin::*;
use session_types::*;
use shell_ui::*;
use state::*;
use storage::*;
use storage_crypto::*;
use storage_logs::*;
use storage_paths::*;
use tokio_bridge::Tokio;

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
