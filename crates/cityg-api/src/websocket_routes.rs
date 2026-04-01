use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::ws::{Message as WsMessage, WebSocket},
    extract::{Query, State, WebSocketUpgrade},
    http::HeaderMap,
    response::Response,
};
use futures::{SinkExt, StreamExt};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use crate::{
    ApiError, ApiState, BroadcastNotification, MembershipEventKind, WebSocketSubscriptionQuery,
    configured_message_auth_token, configured_ws_max_lag, enforce_message_auth_websocket,
    ensure_leaf_member_for_room, parse_gid, parse_hex_32, should_disconnect_for_lag,
};

pub(crate) async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<WebSocketSubscriptionQuery>,
) -> Result<Response, ApiError> {
    enforce_message_auth_websocket(&headers, configured_message_auth_token().as_deref())?;
    let gid = parse_gid(&query.gid)?;
    let leaf_id = parse_hex_32("leaf_id must be 64 hex characters", &query.leaf_id)?;
    ensure_leaf_member_for_room(&state, &gid, leaf_id).await?;
    Ok(ws.on_upgrade(move |socket| handle_websocket(socket, state, gid)))
}

pub(crate) async fn handle_websocket(socket: WebSocket, state: ApiState, subscribed_gid: [u8; 32]) {
    let (mut sender, mut receiver) = socket.split();

    let mut rx = state.notification_tx.subscribe();
    let max_lag = configured_ws_max_lag();

    debug!(
        "WebSocket client connected for gid {}",
        hex::encode(subscribed_gid)
    );

    let connection_healthy = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let conn_healthy_clone = connection_healthy.clone();

    let mut recv_task = tokio::spawn(async move {
        let mut last_pong = Instant::now();
        let pong_timeout = Duration::from_secs(60);

        while let Some(result) = receiver.next().await {
            match result {
                Ok(WsMessage::Close(_)) => {
                    debug!("WebSocket client sent close message");
                    conn_healthy_clone.store(false, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
                Ok(WsMessage::Ping(_)) => {
                    debug!("WebSocket received ping");
                    last_pong = Instant::now();
                }
                Ok(WsMessage::Pong(_)) => {
                    debug!("WebSocket received pong");
                    last_pong = Instant::now();
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("WebSocket receive error: {}", e);
                    conn_healthy_clone.store(false, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
            }

            if last_pong.elapsed() > pong_timeout {
                warn!("WebSocket pong timeout, considering connection unhealthy");
                conn_healthy_clone.store(false, std::sync::atomic::Ordering::Relaxed);
                break;
            }
        }
    });

    let mut send_task = tokio::spawn(async move {
        let ping_interval = Duration::from_secs(30);
        let mut last_ping = Instant::now();

        loop {
            if !connection_healthy.load(std::sync::atomic::Ordering::Relaxed) {
                debug!("WebSocket connection marked unhealthy, closing send loop");
                break;
            }

            tokio::select! {
                result = rx.recv() => {
                    match result {
                        Ok(notification) => {
                            let payload = match notification {
                                BroadcastNotification::Message(msg) => {
                                    if msg.gid != subscribed_gid {
                                        continue;
                                    }
                                    serde_json::json!({
                                        "type": "message",
                                        "gid": hex::encode(msg.gid),
                                        "we_epoch_id": hex::encode(msg.we_epoch_id),
                                        "timestamp_ms": msg.timestamp_ms,
                                        "connection_healthy": true
                                    })
                                }
                                BroadcastNotification::Membership(event) => {
                                    if event.gid != subscribed_gid {
                                        continue;
                                    }
                                    let kind = match event.event {
                                        MembershipEventKind::Join => "join",
                                        MembershipEventKind::Revoke => "revoke",
                                    };
                                    serde_json::json!({
                                        "type": "membership",
                                        "gid": hex::encode(event.gid),
                                        "leaf_id": hex::encode(event.leaf_id),
                                        "event": kind,
                                        "timestamp_ms": event.timestamp_ms
                                    })
                                }
                            };

                            let text = match serde_json::to_string(&payload) {
                                Ok(t) => t,
                                Err(e) => {
                                    error!("Failed to serialize notification: {}", e);
                                    continue;
                                }
                            };

                            if let Err(e) = sender.send(WsMessage::Text(text.into())).await {
                                warn!("Failed to send WebSocket message: {}", e);
                                connection_healthy.store(false, std::sync::atomic::Ordering::Relaxed);
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!(
                                "WebSocket client lagged by {} messages (max allowed: {})",
                                n, max_lag
                            );
                            if should_disconnect_for_lag(n, max_lag) {
                                let disconnect_notification = serde_json::json!({
                                    "type": "lag_disconnect",
                                    "lagged_messages": n,
                                    "max_lag": max_lag,
                                });
                                if let Ok(text) = serde_json::to_string(&disconnect_notification) {
                                    let _ = sender.send(WsMessage::Text(text.into())).await;
                                }
                                warn!("WebSocket client exceeded lag threshold; disconnecting");
                                connection_healthy
                                    .store(false, std::sync::atomic::Ordering::Relaxed);
                                break;
                            }
                            let lag_notification = serde_json::json!({
                                "type": "lag",
                                "lagged_messages": n,
                                "recommendation": "consider reconnecting"
                            });
                            if let Ok(text) = serde_json::to_string(&lag_notification) {
                                let _ = sender.send(WsMessage::Text(text.into())).await;
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            info!("Message broadcast channel closed");
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(ping_interval) => {
                    if last_ping.elapsed() >= ping_interval {
                        if let Err(e) = sender.send(WsMessage::Ping(vec![].into())).await {
                            warn!("Failed to send ping: {}", e);
                            connection_healthy.store(false, std::sync::atomic::Ordering::Relaxed);
                            break;
                        }
                        last_ping = Instant::now();
                    }
                }
            }
        }
    });

    tokio::select! {
        _ = &mut send_task => {
            debug!("WebSocket send task completed");
            recv_task.abort();
        }
        _ = &mut recv_task => {
            debug!("WebSocket receive task completed");
            send_task.abort();
        }
    }

    info!("WebSocket client disconnected");
}
