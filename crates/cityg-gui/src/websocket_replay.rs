use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use anyhow::{Context, Result, anyhow};
use serde_json::Value as JsonValue;
use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest,
    http::{HeaderName, HeaderValue, Request},
};

#[derive(Clone, Debug, Default)]
pub(crate) struct WebSocketReplayCursor {
    last_sequence: Arc<AtomicU64>,
}

impl WebSocketReplayCursor {
    pub(crate) fn last_sequence(&self) -> u64 {
        self.last_sequence.load(Ordering::Relaxed)
    }

    pub(crate) fn observe(&self, sequence: u64) {
        let _ = self
            .last_sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                (sequence > current).then_some(sequence)
            });
    }
}

pub(crate) fn websocket_request(
    ws_url: &str,
    token_header: &str,
    token: Option<&str>,
) -> Result<Request<()>> {
    let mut request = ws_url
        .into_client_request()
        .map_err(|err| anyhow!("failed to build websocket handshake request: {err}"))?;
    if let Some(token) = token {
        let header_name = HeaderName::from_bytes(token_header.as_bytes())
            .context("message auth header name is not a valid header")?;
        let token =
            HeaderValue::from_str(token).context("message auth token is not a valid header")?;
        request.headers_mut().insert(header_name, token);
    }
    Ok(request)
}

pub(crate) fn websocket_notification_sequence(notification: &JsonValue) -> Option<u64> {
    notification
        .get("sequence")
        .and_then(|value| value.as_u64())
}

pub(crate) fn websocket_notification_replayed(notification: &JsonValue) -> bool {
    notification
        .get("replayed")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WebSocketLagNotice {
    pub(crate) lagged_messages: u64,
    pub(crate) max_lag: Option<u64>,
    pub(crate) sequence: Option<u64>,
    pub(crate) server_time_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WebSocketSyncRequiredNotice {
    pub(crate) lagged_messages: u64,
    pub(crate) max_lag: Option<u64>,
    pub(crate) sequence: Option<u64>,
    pub(crate) server_time_ms: Option<u64>,
    pub(crate) retained_from_sequence: Option<u64>,
    pub(crate) reason: Option<String>,
    pub(crate) action: Option<String>,
    pub(crate) reconcile_via: Option<String>,
}

pub(crate) fn websocket_lag_notice(notification: &JsonValue) -> Option<WebSocketLagNotice> {
    (notification.get("type")?.as_str()? == "lag").then(|| WebSocketLagNotice {
        lagged_messages: notification
            .get("lagged_messages")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        max_lag: notification.get("max_lag").and_then(|value| value.as_u64()),
        sequence: websocket_notification_sequence(notification),
        server_time_ms: notification
            .get("server_time_ms")
            .and_then(|value| value.as_u64()),
    })
}

pub(crate) fn websocket_sync_required_notice(
    notification: &JsonValue,
) -> Option<WebSocketSyncRequiredNotice> {
    matches!(
        notification.get("type")?.as_str()?,
        "sync_required" | "lag_disconnect"
    )
    .then(|| WebSocketSyncRequiredNotice {
        lagged_messages: notification
            .get("lagged_messages")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        max_lag: notification.get("max_lag").and_then(|value| value.as_u64()),
        sequence: websocket_notification_sequence(notification),
        server_time_ms: notification
            .get("server_time_ms")
            .and_then(|value| value.as_u64()),
        retained_from_sequence: notification
            .get("retained_from_sequence")
            .and_then(|value| value.as_u64()),
        reason: notification
            .get("reason")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned),
        action: notification
            .get("action")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned),
        reconcile_via: notification
            .get("reconcile_via")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned),
    })
}

pub(crate) fn websocket_ack_message(last_sequence: u64) -> String {
    serde_json::json!({
        "type": "ack",
        "last_sequence": last_sequence,
    })
    .to_string()
}

pub(crate) fn websocket_resume_message(last_sequence: u64) -> String {
    serde_json::json!({
        "type": "resume",
        "last_sequence": last_sequence,
    })
    .to_string()
}
