use super::*;

#[test]
fn websocket_control_messages_encode_expected_shapes() {
    assert_eq!(
        websocket_ack_message(12),
        r#"{"last_sequence":12,"type":"ack"}"#
    );
    assert_eq!(
        websocket_resume_message(34),
        r#"{"last_sequence":34,"type":"resume"}"#
    );
    assert_eq!(
        websocket_notification_sequence(&serde_json::json!({
            "type": "message",
            "sequence": 56,
        })),
        Some(56)
    );
    assert!(websocket_notification_replayed(&serde_json::json!({
        "type": "message",
        "replayed": true,
    })));
    assert!(!websocket_notification_replayed(&serde_json::json!({
        "type": "message",
    })));
    let sync_required = websocket_sync_required_notice(&serde_json::json!({
        "type": "sync_required",
        "lagged_messages": 9,
        "max_lag": 12,
        "sequence": 56,
        "retained_from_sequence": 41,
        "server_time_ms": 77,
        "reason": "replay_window_exhausted",
        "action": "refetch_and_reconnect",
        "reconcile_via": "http",
    }))
    .expect("sync_required notice");
    assert_eq!(sync_required.lagged_messages, 9);
    assert_eq!(sync_required.max_lag, Some(12));
    assert_eq!(sync_required.sequence, Some(56));
    assert_eq!(sync_required.retained_from_sequence, Some(41));
    assert_eq!(sync_required.server_time_ms, Some(77));
    assert_eq!(
        sync_required.reason.as_deref(),
        Some("replay_window_exhausted")
    );
    assert_eq!(
        sync_required.action.as_deref(),
        Some("refetch_and_reconnect")
    );
    assert_eq!(sync_required.reconcile_via.as_deref(), Some("http"));
    let lag_notice = websocket_lag_notice(&serde_json::json!({
        "type": "lag",
        "lagged_messages": 3,
        "max_lag": 8,
        "sequence": 5,
    }))
    .expect("lag notice");
    assert_eq!(lag_notice.lagged_messages, 3);
    assert_eq!(lag_notice.max_lag, Some(8));
    assert_eq!(lag_notice.sequence, Some(5));
}

#[tokio::test]
async fn websocket_worker_reports_revoke_membership_event() -> Result<(), Box<dyn std::error::Error>>
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let membership_gid = [0x24u8; 32];
    let membership_gid_hex = hex_encode(membership_gid);
    let membership_leaf = [0xCDu8; 32];
    let membership_leaf_hex = hex_encode(membership_leaf);

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut ws = tokio_tungstenite::accept_async(stream).await?;
        ws.send(WsMessage::Text(
            format!(
                r#"{{"type":"membership","gid":"{membership_gid_hex}","leaf_id":"{membership_leaf_hex}","event":"revoke","timestamp_ms":55}}"#
            )
            .into(),
        ))
        .await?;
        ws.close(None).await?;
        Ok::<(), anyhow::Error>(())
    });

    let (tx, mut rx) = futures_mpsc::unbounded::<WebSocketEvent>();
    let worker = tokio::spawn(run_websocket_worker(
        format!("ws://{addr}/v1/ws"),
        None,
        Duration::from_millis(20),
        tx,
    ));

    let mut saw_revoke = false;
    for _ in 0..8 {
        let next = tokio::time::timeout(Duration::from_secs(1), rx.next()).await?;
        let Some(event) = next else {
            break;
        };
        if let WebSocketEvent::Membership(signal) = event
            && signal.gid == membership_gid
            && signal.leaf_id == Some(membership_leaf)
            && signal.kind == Some(MembershipSignalKind::Revoke)
            && signal.sequence.is_none()
            && !signal.replayed
        {
            saw_revoke = true;
            break;
        }
    }
    assert!(saw_revoke, "expected revoke membership event");

    drop(rx);
    tokio::time::timeout(Duration::from_secs(1), server).await???;
    tokio::time::timeout(Duration::from_secs(1), worker).await???;
    Ok(())
}

#[tokio::test]
async fn websocket_worker_acks_sequences_and_resumes_on_reconnect()
-> Result<(), Box<dyn std::error::Error>> {
    use tokio_tungstenite::tungstenite::Message as ServerMessage;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut ws = tokio_tungstenite::accept_async(stream).await?;
        ws.send(ServerMessage::Text(
            r#"{"type":"message","sequence":12}"#.to_string().into(),
        ))
        .await?;
        let ack = ws.next().await.expect("ack frame").expect("ack frame ok");
        let ack_text = ack.into_text().expect("ack text frame");
        let ack_json: serde_json::Value = serde_json::from_str(&ack_text).expect("ack json");
        assert_eq!(ack_json["type"], "ack");
        assert_eq!(ack_json["last_sequence"], 12);
        ws.close(None).await?;

        let (stream, _) = listener.accept().await?;
        let mut ws = tokio_tungstenite::accept_async(stream).await?;
        let resume = ws
            .next()
            .await
            .expect("resume frame")
            .expect("resume frame ok");
        let resume_text = resume.into_text().expect("resume text frame");
        let resume_json: serde_json::Value =
            serde_json::from_str(&resume_text).expect("resume json");
        assert_eq!(resume_json["type"], "resume");
        assert_eq!(resume_json["last_sequence"], 12);
        ws.close(None).await?;

        Ok::<(), anyhow::Error>(())
    });

    let (tx, mut rx) = futures_mpsc::unbounded::<WebSocketEvent>();
    let worker = tokio::spawn(run_websocket_worker(
        format!("ws://{addr}/v1/ws"),
        None,
        Duration::from_millis(20),
        tx,
    ));

    let mut connected_count = 0usize;
    while connected_count < 2 {
        let next = tokio::time::timeout(Duration::from_secs(1), rx.next()).await?;
        match next {
            Some(WebSocketEvent::Connected) => connected_count += 1,
            Some(WebSocketEvent::Disconnected)
            | Some(WebSocketEvent::Message(_))
            | Some(WebSocketEvent::Membership(_))
            | Some(WebSocketEvent::SyncRequired(_)) => {}
            None => break,
        }
    }
    assert_eq!(connected_count, 2, "expected reconnect with resume");

    drop(rx);
    tokio::time::timeout(Duration::from_secs(1), server).await???;
    tokio::time::timeout(Duration::from_secs(1), worker).await???;
    Ok(())
}

#[tokio::test]
async fn websocket_worker_returns_when_event_channel_is_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut ws = tokio_tungstenite::accept_async(stream).await?;
        ws.close(None).await?;
        Ok::<(), anyhow::Error>(())
    });

    let (tx, rx) = futures_mpsc::unbounded::<WebSocketEvent>();
    drop(rx);

    tokio::time::timeout(
        Duration::from_secs(1),
        run_websocket_worker(
            format!("ws://{addr}/v1/ws"),
            None,
            Duration::from_secs(1),
            tx,
        ),
    )
    .await??;

    tokio::time::timeout(Duration::from_secs(1), server).await???;
    Ok(())
}

#[tokio::test]
async fn websocket_worker_emits_membership_and_message_events()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let membership_gid = [0x42u8; 32];
    let membership_gid_hex = hex_encode(membership_gid);
    let membership_leaf = [0xABu8; 32];
    let membership_leaf_hex = hex_encode(membership_leaf);

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut ws = tokio_tungstenite::accept_async(stream).await?;
        ws.send(WsMessage::Text(r#"{"type":"message"}"#.to_string().into()))
            .await?;
        ws.send(WsMessage::Text(
            format!(r#"{{"type":"membership","gid":"{membership_gid_hex}","leaf_id":"{membership_leaf_hex}","event":"join","timestamp_ms":12345,"sequence":9,"replayed":true}}"#)
            .into(),
        ))
        .await?;
        ws.send(WsMessage::Text(
            r#"{"type":"membership","gid":"not-hex"}"#.to_string().into(),
        ))
        .await?;
        ws.send(WsMessage::Text(
            r#"{"type":"lag","detail":"slow_consumer"}"#.to_string().into(),
        ))
        .await?;
        ws.close(None).await?;
        Ok::<(), anyhow::Error>(())
    });

    let (tx, mut rx) = futures_mpsc::unbounded::<WebSocketEvent>();
    let worker = tokio::spawn(run_websocket_worker(
        format!("ws://{addr}/v1/ws"),
        None,
        Duration::from_millis(20),
        tx,
    ));

    let mut saw_connected = false;
    let mut saw_message = false;
    let mut saw_membership = false;
    let mut saw_disconnected = false;
    for _ in 0..12 {
        let next = tokio::time::timeout(Duration::from_secs(1), rx.next()).await?;
        let Some(event) = next else {
            break;
        };

        match event {
            WebSocketEvent::Connected => saw_connected = true,
            WebSocketEvent::Message(signal) => {
                saw_message = !signal.replayed && signal.sequence.is_none();
            }
            WebSocketEvent::Membership(signal) => {
                if signal.gid == membership_gid
                    && signal.leaf_id == Some(membership_leaf)
                    && signal.kind == Some(MembershipSignalKind::Join)
                    && signal.sequence == Some(9)
                    && signal.replayed
                {
                    saw_membership = true;
                }
            }
            WebSocketEvent::Disconnected => {
                saw_disconnected = true;
                if saw_connected && saw_message && saw_membership {
                    break;
                }
            }
            WebSocketEvent::SyncRequired(_) => {}
        }
    }

    assert!(saw_connected, "expected Connected event");
    assert!(saw_message, "expected Message event");
    assert!(saw_membership, "expected Membership event");
    assert!(saw_disconnected, "expected Disconnected event");

    drop(rx);
    tokio::time::timeout(Duration::from_secs(1), server).await???;
    tokio::time::timeout(Duration::from_secs(1), worker).await???;
    Ok(())
}

#[tokio::test]
async fn websocket_worker_parses_unknown_membership_and_ping()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let membership_gid = [0x66u8; 32];
    let membership_gid_hex = hex_encode(membership_gid);
    let membership_leaf = [0x99u8; 32];
    let membership_leaf_hex = hex_encode(membership_leaf);

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut ws = tokio_tungstenite::accept_async(stream).await?;
        ws.send(WsMessage::Text(
            format!(
                r#"{{"type":"membership","gid":"{membership_gid_hex}","leaf_id":"{membership_leaf_hex}","event":"unknown","timestamp_ms":77}}"#
            )
            .into(),
        ))
        .await?;
        ws.send(WsMessage::Ping(vec![1, 2, 3].into())).await?;
        ws.close(None).await?;
        Ok::<(), anyhow::Error>(())
    });

    let (tx, mut rx) = futures_mpsc::unbounded::<WebSocketEvent>();
    let worker = tokio::spawn(run_websocket_worker(
        format!("ws://{addr}/v1/ws"),
        None,
        Duration::from_millis(20),
        tx,
    ));

    let mut saw_unknown_kind = false;
    for _ in 0..8 {
        let next = tokio::time::timeout(Duration::from_secs(1), rx.next()).await?;
        let Some(event) = next else {
            break;
        };
        if let WebSocketEvent::Membership(signal) = event
            && signal.gid == membership_gid
            && signal.leaf_id == Some(membership_leaf)
        {
            saw_unknown_kind =
                signal.kind.is_none() && signal.sequence.is_none() && !signal.replayed;
            break;
        }
    }
    assert!(
        saw_unknown_kind,
        "expected membership event with unknown kind"
    );

    drop(rx);
    tokio::time::timeout(Duration::from_secs(1), server).await???;
    tokio::time::timeout(Duration::from_secs(1), worker).await???;
    Ok(())
}

#[tokio::test]
async fn websocket_worker_returns_when_message_delivery_channel_closes()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut ws = tokio_tungstenite::accept_async(stream).await?;
        sleep(Duration::from_millis(60)).await;
        ws.send(WsMessage::Text(r#"{"type":"message"}"#.to_string().into()))
            .await?;
        ws.close(None).await?;
        Ok::<(), anyhow::Error>(())
    });

    let (tx, mut rx) = futures_mpsc::unbounded::<WebSocketEvent>();
    let worker = tokio::spawn(run_websocket_worker(
        format!("ws://{addr}/v1/ws"),
        None,
        Duration::from_secs(1),
        tx,
    ));

    let first = tokio::time::timeout(Duration::from_secs(1), rx.next()).await?;
    assert!(matches!(first, Some(WebSocketEvent::Connected)));
    drop(rx);

    tokio::time::timeout(Duration::from_secs(1), worker).await???;
    tokio::time::timeout(Duration::from_secs(1), server).await???;
    Ok(())
}

#[tokio::test]
async fn websocket_worker_returns_when_membership_delivery_channel_closes()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let gid_hex = hex_encode([0x33u8; 32]);
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut ws = tokio_tungstenite::accept_async(stream).await?;
        sleep(Duration::from_millis(60)).await;
        ws.send(WsMessage::Text(
            format!(r#"{{"type":"membership","gid":"{gid_hex}","event":"join"}}"#).into(),
        ))
        .await?;
        ws.close(None).await?;
        Ok::<(), anyhow::Error>(())
    });

    let (tx, mut rx) = futures_mpsc::unbounded::<WebSocketEvent>();
    let worker = tokio::spawn(run_websocket_worker(
        format!("ws://{addr}/v1/ws"),
        None,
        Duration::from_secs(1),
        tx,
    ));

    let first = tokio::time::timeout(Duration::from_secs(1), rx.next()).await?;
    assert!(matches!(first, Some(WebSocketEvent::Connected)));
    drop(rx);

    tokio::time::timeout(Duration::from_secs(1), worker).await???;
    tokio::time::timeout(Duration::from_secs(1), server).await???;
    Ok(())
}

#[tokio::test]
async fn websocket_worker_ignores_invalid_json_and_unknown_notification_type()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut ws = tokio_tungstenite::accept_async(stream).await?;
        ws.send(WsMessage::Text("not-json".to_string().into()))
            .await?;
        ws.send(WsMessage::Text(r#"{"type":"other"}"#.to_string().into()))
            .await?;
        ws.close(None).await?;
        Ok::<(), anyhow::Error>(())
    });

    let (tx, mut rx) = futures_mpsc::unbounded::<WebSocketEvent>();
    let worker = tokio::spawn(run_websocket_worker(
        format!("ws://{addr}/v1/ws"),
        None,
        Duration::from_millis(20),
        tx,
    ));

    let mut saw_connected = false;
    let mut saw_disconnected = false;
    for _ in 0..6 {
        let next = tokio::time::timeout(Duration::from_secs(1), rx.next()).await?;
        let Some(event) = next else {
            break;
        };
        match event {
            WebSocketEvent::Connected => saw_connected = true,
            WebSocketEvent::Disconnected => {
                saw_disconnected = true;
                break;
            }
            WebSocketEvent::Message(_)
            | WebSocketEvent::Membership(_)
            | WebSocketEvent::SyncRequired(_) => {
                return Err(anyhow!("unexpected event from invalid payloads").into());
            }
        }
    }

    assert!(saw_connected, "expected Connected event");
    assert!(saw_disconnected, "expected Disconnected event");

    drop(rx);
    tokio::time::timeout(Duration::from_secs(1), server).await???;
    tokio::time::timeout(Duration::from_secs(1), worker).await???;
    Ok(())
}

#[tokio::test]
async fn websocket_worker_handles_stream_protocol_errors() -> Result<(), Box<dyn std::error::Error>>
{
    use tokio::io::AsyncWriteExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut ws = tokio_tungstenite::accept_async(stream).await?;
        ws.get_mut().write_all(b"not-a-websocket-frame").await?;
        ws.get_mut().shutdown().await?;
        Ok::<(), anyhow::Error>(())
    });

    let (tx, mut rx) = futures_mpsc::unbounded::<WebSocketEvent>();
    let worker = tokio::spawn(run_websocket_worker(
        format!("ws://{addr}/v1/ws"),
        None,
        Duration::from_millis(20),
        tx,
    ));

    let mut saw_disconnected = false;
    for _ in 0..6 {
        let next = tokio::time::timeout(Duration::from_secs(1), rx.next()).await?;
        let Some(event) = next else {
            break;
        };
        if matches!(event, WebSocketEvent::Disconnected) {
            saw_disconnected = true;
            break;
        }
    }
    assert!(
        saw_disconnected,
        "protocol errors should produce a disconnected event"
    );

    drop(rx);
    tokio::time::timeout(Duration::from_secs(1), server).await???;
    tokio::time::timeout(Duration::from_secs(1), worker).await???;
    Ok(())
}

#[tokio::test]
async fn websocket_worker_emits_sync_required_before_disconnect()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut ws = tokio_tungstenite::accept_async(stream).await?;
        ws.send(WsMessage::Text(
            serde_json::json!({
                "type": "sync_required",
                "lagged_messages": 23u64,
                "max_lag": 64u64,
                "sequence": 55u64,
                "retained_from_sequence": 40u64,
                "server_time_ms": 999u64,
                "reason": "replay_window_exhausted",
                "action": "refetch_and_reconnect",
                "reconcile_via": "http",
            })
            .to_string()
            .into(),
        ))
        .await?;
        ws.close(None).await?;
        Ok::<(), anyhow::Error>(())
    });

    let (tx, mut rx) = futures_mpsc::unbounded::<WebSocketEvent>();
    let worker = tokio::spawn(run_websocket_worker(
        format!("ws://{addr}/v1/ws"),
        None,
        Duration::from_millis(20),
        tx,
    ));

    let mut saw_sync_required = false;
    let mut saw_disconnected = false;
    for _ in 0..8 {
        let next = tokio::time::timeout(Duration::from_secs(1), rx.next()).await?;
        let Some(event) = next else {
            break;
        };
        match event {
            WebSocketEvent::SyncRequired(signal) => {
                saw_sync_required = signal.lagged_messages == 23
                    && signal.sequence == Some(55)
                    && signal.retained_from_sequence == Some(40)
                    && signal.timestamp_ms == Some(999)
                    && signal.reason.as_deref() == Some("replay_window_exhausted")
                    && signal.action.as_deref() == Some("refetch_and_reconnect")
                    && signal.reconcile_via.as_deref() == Some("http");
            }
            WebSocketEvent::Disconnected => {
                saw_disconnected = true;
                if saw_sync_required {
                    break;
                }
            }
            WebSocketEvent::Connected
            | WebSocketEvent::Message(_)
            | WebSocketEvent::Membership(_) => {}
        }
    }

    assert!(saw_sync_required, "expected sync_required control event");
    assert!(saw_disconnected, "expected disconnect after sync_required");

    drop(rx);
    tokio::time::timeout(Duration::from_secs(1), server).await???;
    tokio::time::timeout(Duration::from_secs(1), worker).await???;
    Ok(())
}
