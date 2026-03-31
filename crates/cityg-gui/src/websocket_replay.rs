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
