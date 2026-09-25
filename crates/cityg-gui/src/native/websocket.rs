use futures::{StreamExt, channel::mpsc as futures_mpsc};
use tokio::time::sleep;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message as WsMessage};

use super::*;

/// Events of the log-head notification socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum WebSocketEvent {
    Connected,
    Disconnected,
    /// The room log grew up to `head_seq`.
    Head(u64),
    /// The server dropped notices; refetch.
    Resync,
}

/// Parse one notification frame.
pub(super) fn parse_notice(text: &str) -> Option<WebSocketEvent> {
    let notice: serde_json::Value = serde_json::from_str(text).ok()?;
    match notice.get("type").and_then(|kind| kind.as_str()) {
        Some("head") => notice
            .get("head_seq")
            .and_then(serde_json::Value::as_u64)
            .map(WebSocketEvent::Head),
        Some("resync") => Some(WebSocketEvent::Resync),
        _ => None,
    }
}

/// Keep a notification socket open for the room of `member`, reconnecting
/// after `reconnect_delay` (each connection uses a fresh session token).
pub(super) async fn run_websocket_worker(
    member: SharedMember,
    reconnect_delay: Duration,
    tx: futures_mpsc::UnboundedSender<WebSocketEvent>,
) -> Result<()> {
    loop {
        let url = {
            let mut member = member.lock().await;
            member.websocket_url().await
        };
        match url {
            Ok(url) => match connect_async(url.as_str()).await {
                Ok((stream, _)) => {
                    info!("WebSocket connected");
                    if tx.unbounded_send(WebSocketEvent::Connected).is_err() {
                        return Ok(());
                    }
                    let (_, mut read) = stream.split();
                    while let Some(frame) = read.next().await {
                        match frame {
                            Ok(WsMessage::Text(text)) => {
                                if let Some(event) = parse_notice(&text)
                                    && tx.unbounded_send(event).is_err()
                                {
                                    return Ok(());
                                }
                            }
                            Ok(WsMessage::Close(_)) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                }
                Err(err) => warn!("WebSocket connection failed: {err}"),
            },
            Err(err) => warn!("WebSocket token request failed: {err}"),
        }
        if tx.unbounded_send(WebSocketEvent::Disconnected).is_err() {
            return Ok(());
        }
        sleep(reconnect_delay).await;
    }
}
