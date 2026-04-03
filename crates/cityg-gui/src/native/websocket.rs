use futures::{SinkExt, StreamExt, channel::mpsc as futures_mpsc};
use tokio::time::sleep;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message as WsMessage};

use super::*;
use crate::client_env::MESSAGE_AUTH_HEADER;
use crate::websocket_replay::{
    WebSocketReplayCursor, websocket_ack_message, websocket_lag_notice,
    websocket_notification_replayed, websocket_notification_sequence, websocket_request,
    websocket_resume_message, websocket_sync_required_notice,
};

pub(super) enum WebSocketEvent {
    Connected,
    Disconnected,
    Message(WebSocketMessageSignal),
    Membership(MembershipSignal),
    SyncRequired(WebSocketSyncRequiredSignal),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct WebSocketMessageSignal {
    pub(super) sequence: Option<u64>,
    pub(super) replayed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MembershipSignalKind {
    Join,
    Revoke,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct MembershipSignal {
    pub(super) gid: [u8; 32],
    pub(super) leaf_id: Option<[u8; 32]>,
    pub(super) kind: Option<MembershipSignalKind>,
    pub(super) sequence: Option<u64>,
    pub(super) replayed: bool,
    pub(super) timestamp_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WebSocketSyncRequiredSignal {
    pub(super) lagged_messages: u64,
    pub(super) sequence: Option<u64>,
    pub(super) timestamp_ms: Option<u64>,
    pub(super) retained_from_sequence: Option<u64>,
    pub(super) reason: Option<String>,
    pub(super) action: Option<String>,
    pub(super) reconcile_via: Option<String>,
}

pub(super) async fn run_websocket_worker(
    ws_url: String,
    message_token: Option<String>,
    reconnect_delay: Duration,
    tx: futures_mpsc::UnboundedSender<WebSocketEvent>,
) -> Result<()> {
    let sequence_cursor = WebSocketReplayCursor::default();
    loop {
        debug!("Attempting WebSocket connection to {}", ws_url);

        let request = websocket_request(&ws_url, MESSAGE_AUTH_HEADER, message_token.as_deref())?;
        match connect_async(request).await {
            Ok((ws_stream, _)) => {
                info!("WebSocket connected successfully");
                if tx.unbounded_send(WebSocketEvent::Connected).is_err() {
                    return Ok(());
                }

                let (mut write, mut read) = ws_stream.split();
                'connection: {
                    if sequence_cursor.last_sequence() > 0 {
                        let resume = websocket_resume_message(sequence_cursor.last_sequence());
                        if let Err(error) = write.send(WsMessage::Text(resume.into())).await {
                            warn!("failed to send websocket resume frame: {}", error);
                            break 'connection;
                        }
                    }
                    while let Some(msg_result) = read.next().await {
                        match msg_result {
                            Ok(WsMessage::Text(text)) => {
                                debug!("WebSocket message received: {}", text);
                                if let Ok(notification) =
                                    serde_json::from_str::<serde_json::Value>(&text)
                                {
                                    if let Some(sequence) =
                                        websocket_notification_sequence(&notification)
                                    {
                                        sequence_cursor.observe(sequence);
                                        let ack =
                                            websocket_ack_message(sequence_cursor.last_sequence());
                                        if let Err(error) =
                                            write.send(WsMessage::Text(ack.into())).await
                                        {
                                            warn!("failed to send websocket ack frame: {}", error);
                                            break 'connection;
                                        }
                                    }
                                    if let Some(signal) =
                                        websocket_sync_required_notice(&notification)
                                    {
                                        if tx
                                            .unbounded_send(WebSocketEvent::SyncRequired(
                                                WebSocketSyncRequiredSignal {
                                                    lagged_messages: signal.lagged_messages,
                                                    sequence: signal.sequence,
                                                    timestamp_ms: signal.server_time_ms,
                                                    retained_from_sequence: signal
                                                        .retained_from_sequence,
                                                    reason: signal.reason,
                                                    action: signal.action,
                                                    reconcile_via: signal.reconcile_via,
                                                },
                                            ))
                                            .is_err()
                                        {
                                            return Ok(());
                                        }
                                        break 'connection;
                                    }
                                    if let Some(signal) = websocket_lag_notice(&notification) {
                                        warn!(
                                            "WebSocket lag notification: lagged_messages={} max_lag={:?} sequence={:?}",
                                            signal.lagged_messages, signal.max_lag, signal.sequence,
                                        );
                                        continue;
                                    }
                                    match notification.get("type").and_then(|t| t.as_str()) {
                                        Some("message") => {
                                            let signal = WebSocketMessageSignal {
                                                sequence: websocket_notification_sequence(
                                                    &notification,
                                                ),
                                                replayed: websocket_notification_replayed(
                                                    &notification,
                                                ),
                                            };
                                            if tx
                                                .unbounded_send(WebSocketEvent::Message(signal))
                                                .is_err()
                                            {
                                                return Ok(());
                                            }
                                        }
                                        Some("membership") => {
                                            if let Some(gid_hex) =
                                                notification.get("gid").and_then(|v| v.as_str())
                                                && let Some(gid) = decode_hex_32(gid_hex)
                                            {
                                                let signal = MembershipSignal {
                                                    gid,
                                                    leaf_id: notification
                                                        .get("leaf_id")
                                                        .and_then(|v| v.as_str())
                                                        .and_then(decode_hex_32),
                                                    kind: match notification
                                                        .get("event")
                                                        .and_then(|v| v.as_str())
                                                    {
                                                        Some("join") => {
                                                            Some(MembershipSignalKind::Join)
                                                        }
                                                        Some("revoke") => {
                                                            Some(MembershipSignalKind::Revoke)
                                                        }
                                                        _ => None,
                                                    },
                                                    sequence: websocket_notification_sequence(
                                                        &notification,
                                                    ),
                                                    replayed: websocket_notification_replayed(
                                                        &notification,
                                                    ),
                                                    timestamp_ms: notification
                                                        .get("timestamp_ms")
                                                        .and_then(|v| v.as_u64()),
                                                };
                                                if tx
                                                    .unbounded_send(WebSocketEvent::Membership(
                                                        signal,
                                                    ))
                                                    .is_err()
                                                {
                                                    return Ok(());
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            Ok(WsMessage::Close(_)) => {
                                info!("WebSocket closed by server");
                                break 'connection;
                            }
                            Ok(WsMessage::Ping(_)) | Ok(WsMessage::Pong(_)) => {
                                debug!("WebSocket ping/pong");
                            }
                            Err(e) => {
                                warn!("WebSocket error: {}", e);
                                break 'connection;
                            }
                            _ => {}
                        }
                    }
                }
                info!(
                    "WebSocket connection closed, will retry in {:?}",
                    reconnect_delay
                );
            }
            Err(e) => {
                warn!("WebSocket connection failed: {}", e);
            }
        }

        if tx.unbounded_send(WebSocketEvent::Disconnected).is_err() {
            return Ok(());
        }

        sleep(reconnect_delay).await;
    }
}
