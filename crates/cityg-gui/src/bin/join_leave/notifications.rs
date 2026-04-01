use super::*;

#[derive(Debug)]
pub(super) enum Notification {
    Message {
        we_epoch_id: [u8; 32],
        sequence: Option<u64>,
        replayed: bool,
        timestamp_ms: u64,
    },
    Membership {
        gid: [u8; 32],
        leaf_id: [u8; 32],
        event: String,
        sequence: Option<u64>,
        replayed: bool,
        timestamp_ms: u64,
    },
    Lag {
        lagged_messages: u64,
    },
    SyncRequired {
        lagged_messages: u64,
        sequence: Option<u64>,
        timestamp_ms: Option<u64>,
        retained_from_sequence: Option<u64>,
        reason: Option<String>,
        action: Option<String>,
        reconcile_via: Option<String>,
    },
    Other,
}

pub(super) async fn spawn_notification_listener(
    ws_url: &str,
    token: Option<&str>,
    cursor: WebSocketReplayCursor,
) -> Result<(mpsc::Receiver<Notification>, tokio::task::JoinHandle<()>)> {
    let request = websocket_request(ws_url, MESSAGE_AUTH_HEADER, token)?;
    let (stream, _) = connect_async(request)
        .await
        .with_context(|| format!("failed to connect to websocket {ws_url}"))?;
    let (mut write, mut read) = stream.split();
    if cursor.last_sequence() > 0 {
        write
            .send(WsMessage::Text(
                websocket_resume_message(cursor.last_sequence()).into(),
            ))
            .await
            .context("failed to send websocket resume frame")?;
    }
    let (tx, rx) = mpsc::channel(64);
    let handle = tokio::spawn(async move {
        while let Some(msg) = read.next().await {
            match msg {
                Ok(WsMessage::Text(text)) => {
                    if let Ok(value) = serde_json::from_str::<JsonValue>(&text)
                        && let Some(notification) = Notification::from_json(&value)
                    {
                        if let Some(sequence) = notification.sequence() {
                            cursor.observe(sequence);
                            let ack = websocket_ack_message(cursor.last_sequence());
                            if let Err(err) = write.send(WsMessage::Text(ack.into())).await {
                                eprintln!("websocket ack error: {err}");
                                break;
                            }
                        }
                        let should_disconnect = notification.should_disconnect();
                        if tx.send(notification).await.is_err() {
                            break;
                        }
                        if should_disconnect {
                            break;
                        }
                    }
                }
                Ok(WsMessage::Close(_)) => break,
                Ok(_) => {}
                Err(err) => {
                    eprintln!("websocket read error: {err}");
                    break;
                }
            }
        }
    });
    Ok((rx, handle))
}

pub(super) async fn expect_membership_event(
    rx: &mut mpsc::Receiver<Notification>,
    gid: &[u8; 32],
    leaf_id: &[u8; 32],
    expected_kind: &str,
    label: String,
) -> Result<()> {
    let expected_kind = expected_kind.to_string();
    timeout(EVENT_TIMEOUT, async {
        while let Some(event) = rx.recv().await {
            match event {
                Notification::Membership {
                    gid: event_gid,
                    leaf_id: event_leaf,
                    event,
                    sequence,
                    replayed,
                    timestamp_ms,
                } => {
                    println!(
                        "membership event type={event} gid={} leaf={} seq={} replayed={} ts={}",
                        hex::encode(event_gid),
                        hex::encode(event_leaf),
                        sequence
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                        replayed,
                        timestamp_ms
                    );
                    if event == expected_kind && event_gid == *gid && event_leaf == *leaf_id {
                        return Ok(());
                    }
                }
                Notification::Lag { lagged_messages } => {
                    println!("websocket lag notice: dropped {lagged_messages} messages");
                }
                Notification::SyncRequired {
                    lagged_messages,
                    timestamp_ms,
                    retained_from_sequence,
                    reason,
                    action,
                    reconcile_via,
                    ..
                } => {
                    println!(
                        "websocket sync required: dropped {lagged_messages} messages reason={} action={} reconcile_via={} retained_from={} ts={}",
                        reason.as_deref().unwrap_or("-"),
                        action.as_deref().unwrap_or("-"),
                        reconcile_via.as_deref().unwrap_or("-"),
                        retained_from_sequence
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                        timestamp_ms
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                    );
                }
                _ => {}
            }
        }
        Err(anyhow!(
            "websocket channel closed while waiting for {label}"
        ))
    })
    .await?
}

pub(super) async fn expect_message_event(
    rx: &mut mpsc::Receiver<Notification>,
    we_epoch_id: &[u8; 32],
    require_live: bool,
    label: String,
) -> Result<()> {
    timeout(EVENT_TIMEOUT, async {
        while let Some(event) = rx.recv().await {
            match event {
                Notification::Message {
                    we_epoch_id: event_weid,
                    sequence,
                    replayed,
                    timestamp_ms,
                } => {
                    println!(
                        "message event weid={} seq={} replayed={} ts={}",
                        hex::encode(event_weid),
                        sequence
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                        replayed,
                        timestamp_ms
                    );
                    if event_weid == *we_epoch_id && (!require_live || !replayed) {
                        return Ok(());
                    }
                }
                Notification::Lag { lagged_messages } => {
                    println!("websocket lag notice: dropped {lagged_messages} messages");
                }
                Notification::SyncRequired {
                    lagged_messages,
                    timestamp_ms,
                    retained_from_sequence,
                    reason,
                    action,
                    reconcile_via,
                    ..
                } => {
                    println!(
                        "websocket sync required: dropped {lagged_messages} messages reason={} action={} reconcile_via={} retained_from={} ts={}",
                        reason.as_deref().unwrap_or("-"),
                        action.as_deref().unwrap_or("-"),
                        reconcile_via.as_deref().unwrap_or("-"),
                        retained_from_sequence
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                        timestamp_ms
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                    );
                }
                _ => {}
            }
        }
        Err(anyhow!(
            "websocket channel closed while waiting for {label}"
        ))
    })
    .await?
}

pub(super) fn websocket_url(server_url: &str, gid: &[u8; 32], leaf_id: &[u8; 32]) -> String {
    let base = if let Some(rest) = server_url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = server_url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        format!("ws://{server_url}")
    };
    format!(
        "{base}/v1/ws?gid={}&leaf_id={}",
        hex::encode(gid),
        hex::encode(leaf_id)
    )
}

impl Notification {
    pub(super) fn from_json(value: &JsonValue) -> Option<Self> {
        let event_type = value.get("type")?.as_str()?;
        match event_type {
            "message" => {
                let weid = parse_hex32_field(value, "we_epoch_id")?;
                let timestamp = value
                    .get("timestamp_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                Some(Notification::Message {
                    we_epoch_id: weid,
                    sequence: websocket_notification_sequence(value),
                    replayed: websocket_notification_replayed(value),
                    timestamp_ms: timestamp,
                })
            }
            "membership" => {
                let gid = parse_hex32_field(value, "gid")?;
                let leaf = parse_hex32_field(value, "leaf_id")?;
                let event = value.get("event")?.as_str()?.to_string();
                let timestamp = value
                    .get("timestamp_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                Some(Notification::Membership {
                    gid,
                    leaf_id: leaf,
                    event,
                    sequence: websocket_notification_sequence(value),
                    replayed: websocket_notification_replayed(value),
                    timestamp_ms: timestamp,
                })
            }
            "lag" => websocket_lag_notice(value).map(|notice| Notification::Lag {
                lagged_messages: notice.lagged_messages,
            }),
            "sync_required" | "lag_disconnect" => {
                websocket_sync_required_notice(value).map(|notice| Notification::SyncRequired {
                    lagged_messages: notice.lagged_messages,
                    sequence: notice.sequence,
                    timestamp_ms: notice.server_time_ms,
                    retained_from_sequence: notice.retained_from_sequence,
                    reason: notice.reason,
                    action: notice.action,
                    reconcile_via: notice.reconcile_via,
                })
            }
            _ => Some(Notification::Other),
        }
    }

    fn sequence(&self) -> Option<u64> {
        match self {
            Notification::Message { sequence, .. }
            | Notification::Membership { sequence, .. }
            | Notification::SyncRequired { sequence, .. } => *sequence,
            Notification::Lag { .. } | Notification::Other => None,
        }
    }

    fn should_disconnect(&self) -> bool {
        matches!(self, Notification::SyncRequired { .. })
    }
}

fn parse_hex32_field(value: &JsonValue, key: &str) -> Option<[u8; 32]> {
    let hex_str = value.get(key)?.as_str()?;
    let bytes = hex_decode(hex_str).ok()?;
    bytes.as_slice().try_into().ok()
}
