use super::*;

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
            format!(
                r#"{{"type":"membership","gid":"{membership_gid_hex}","leaf_id":"{membership_leaf_hex}","event":"join","timestamp_ms":12345}}"#
            )
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
            WebSocketEvent::Message => saw_message = true,
            WebSocketEvent::Membership(signal) => {
                if signal.gid == membership_gid
                    && signal.leaf_id == Some(membership_leaf)
                    && signal.kind == Some(MembershipSignalKind::Join)
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
            saw_unknown_kind = signal.kind.is_none();
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
            WebSocketEvent::Message | WebSocketEvent::Membership(_) => {
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
