use super::*;

#[tokio::test]
async fn watch_reconnect_fetches_offline_backlog_and_resumes_live_notifications()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");

    let port = next_test_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0xA5u8; 32]);
    bootstrap_test_room(&server_url, &room_id).await?;

    let alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?
    };
    let bob = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?
    };
    let alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        let latest_members = perform_fetch_members(MembersParams::from_session(
            &alice,
            0,
            50,
            MembersMode::Full,
        ))
        .await?;
        let mut alice_with_latest_root = alice.clone();
        alice_with_latest_root.parent_root = latest_members.root;
        let synced = perform_epoch_sync(alice_with_latest_root).await?.session;
        persist_session(&synced)?;
        synced
    };

    let ws_url = format!(
        "{}/v1/ws?gid={}&leaf_id={}",
        server_url
            .replace("http://", "ws://")
            .replace("https://", "wss://"),
        hex_encode(alice.gid),
        hex_encode(alice.leaf_id)
    );

    let (first_tx, mut first_rx) = futures_mpsc::unbounded::<WebSocketEvent>();
    let first_worker = tokio::spawn(run_websocket_worker(
        ws_url.clone(),
        Some(TEST_MESSAGE_TOKEN.to_string()),
        Duration::from_millis(20),
        first_tx,
    ));

    let mut first_connected = false;
    for _ in 0..8 {
        let next = tokio::time::timeout(Duration::from_secs(1), first_rx.next()).await?;
        let Some(event) = next else {
            break;
        };
        if matches!(event, WebSocketEvent::Connected) {
            first_connected = true;
            break;
        }
    }
    assert!(
        first_connected,
        "watch reconnect flow must establish the first websocket before forcing disconnect"
    );

    first_worker.abort();
    let _ = first_worker.await;

    let backlog_plaintext = "bob-while-watcher-offline".to_string();
    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_send(SendParams::from_session(
            &bob,
            backlog_plaintext.clone(),
            0,
        )?)
        .await?;
    }

    let (second_tx, mut second_rx) = futures_mpsc::unbounded::<WebSocketEvent>();
    let second_worker = tokio::spawn(run_websocket_worker(
        ws_url,
        Some(TEST_MESSAGE_TOKEN.to_string()),
        Duration::from_millis(20),
        second_tx,
    ));

    let mut second_connected = false;
    for _ in 0..8 {
        let next = tokio::time::timeout(Duration::from_secs(1), second_rx.next()).await?;
        let Some(event) = next else {
            break;
        };
        if matches!(event, WebSocketEvent::Connected) {
            second_connected = true;
            break;
        }
    }
    assert!(
        second_connected,
        "watch reconnect flow must re-establish the websocket before backlog fetch"
    );

    let mut alice_after_backlog_fetch = alice.clone();
    let backlog_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_fetch(FetchParams::from_session(&alice_after_backlog_fetch, None)?).await?
    };
    assert!(
        backlog_fetch
            .messages
            .iter()
            .any(|message| message.plaintext == backlog_plaintext
                && message.sender_leaf == Some(bob.leaf_id)),
        "fetch after reconnect must bridge the backlog emitted while the watcher was offline"
    );
    apply_fetch_outcome_to_session(&mut alice_after_backlog_fetch, &backlog_fetch);

    let live_plaintext = "bob-after-watch-reconnect".to_string();
    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        perform_send(SendParams::from_session(&bob, live_plaintext.clone(), 1)?).await?;
    }

    let mut saw_live_notification = false;
    for _ in 0..8 {
        let next = tokio::time::timeout(Duration::from_secs(1), second_rx.next()).await?;
        let Some(event) = next else {
            break;
        };
        match event {
            WebSocketEvent::Message(signal) if !signal.replayed => {
                saw_live_notification = true;
                break;
            }
            WebSocketEvent::Message(_) => {}
            WebSocketEvent::Connected
            | WebSocketEvent::Disconnected
            | WebSocketEvent::Membership(_) => {}
        }
    }
    assert!(
        saw_live_notification,
        "watch reconnect flow must resume live message notifications after reconnect"
    );

    let mut alice_after_live_fetch = alice_after_backlog_fetch.clone();
    let live_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_fetch(FetchParams::from_session(&alice_after_live_fetch, None)?).await?
    };
    assert!(
        live_fetch
            .messages
            .iter()
            .any(|message| message.plaintext == live_plaintext
                && message.sender_leaf == Some(bob.leaf_id)),
        "post-reconnect fetch must still deliver fresh live traffic"
    );
    assert!(
        live_fetch
            .messages
            .iter()
            .all(|message| message.plaintext != backlog_plaintext),
        "post-reconnect live fetch must not replay the backlog once replay-state advanced"
    );
    apply_fetch_outcome_to_session(&mut alice_after_live_fetch, &live_fetch);

    let final_empty_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        perform_fetch(FetchParams::from_session(&alice_after_live_fetch, None)?).await?
    };
    assert!(
        final_empty_fetch.messages.is_empty(),
        "after backlog and live traffic are fetched once, repeated fetches should be empty"
    );

    second_worker.abort();
    let _ = second_worker.await;
    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn dual_restarted_watchers_fetch_offline_backlog_and_resume_live_notifications()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");
    let charlie_base = temp_dir.path().join("cityg").join("gui-charlie");

    let port = next_test_port();
    let handle = spawn_server_on(port).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let room_id = hex_encode([0xA7u8; 32]);
    bootstrap_test_room(&server_url, &room_id).await?;

    let alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "alice".to_string(),
        })
        .await?
    };
    let bob = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "bob".to_string(),
        })
        .await?
    };
    let charlie = {
        let _override_guard = set_config_dir_override_for_tests(Some(charlie_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "charlie".to_string(),
        })
        .await?
    };

    let alice_after_sync = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        let latest_members = perform_fetch_members(MembersParams::from_session(
            &alice,
            0,
            50,
            MembersMode::Full,
        ))
        .await?;
        let mut alice_with_latest_root = alice.clone();
        alice_with_latest_root.parent_root = latest_members.root;
        let synced = perform_epoch_sync(alice_with_latest_root).await?.session;
        persist_session(&synced)?;
        synced
    };
    let bob_after_sync = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        let latest_members =
            perform_fetch_members(MembersParams::from_session(&bob, 0, 50, MembersMode::Full))
                .await?;
        let mut bob_with_latest_root = bob.clone();
        bob_with_latest_root.parent_root = latest_members.root;
        let synced = perform_epoch_sync(bob_with_latest_root).await?.session;
        persist_session(&synced)?;
        synced
    };
    assert!(
        !alice_after_sync.barrier_state.barrier_recovery_pending
            && !bob_after_sync.barrier_state.barrier_recovery_pending
            && !charlie.barrier_state.barrier_recovery_pending,
        "all three members must be message-ready before simulating dual watcher restart"
    );

    let restarted_alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        load_session_at(&server_url, &room_id)?
            .ok_or_else(|| anyhow!("expected persisted alice session after restart"))?
    };
    let restarted_bob = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        load_session_at(&server_url, &room_id)?
            .ok_or_else(|| anyhow!("expected persisted bob session after restart"))?
    };

    let backlog_messages = ["charlie-backlog-1", "charlie-backlog-2"];
    {
        let _override_guard = set_config_dir_override_for_tests(Some(charlie_base.clone()));
        perform_send(SendParams::from_session(
            &charlie,
            backlog_messages[0].to_string(),
            0,
        )?)
        .await?;
        perform_send(SendParams::from_session(
            &charlie,
            backlog_messages[1].to_string(),
            1,
        )?)
        .await?;
    }

    let alice_ws_url = format!(
        "{}/v1/ws?gid={}&leaf_id={}",
        server_url
            .replace("http://", "ws://")
            .replace("https://", "wss://"),
        hex_encode(restarted_alice.gid),
        hex_encode(restarted_alice.leaf_id)
    );
    let bob_ws_url = format!(
        "{}/v1/ws?gid={}&leaf_id={}",
        server_url
            .replace("http://", "ws://")
            .replace("https://", "wss://"),
        hex_encode(restarted_bob.gid),
        hex_encode(restarted_bob.leaf_id)
    );

    let (alice_tx, mut alice_rx) = futures_mpsc::unbounded::<WebSocketEvent>();
    let alice_worker = tokio::spawn(run_websocket_worker(
        alice_ws_url,
        Some(TEST_MESSAGE_TOKEN.to_string()),
        Duration::from_millis(20),
        alice_tx,
    ));
    let (bob_tx, mut bob_rx) = futures_mpsc::unbounded::<WebSocketEvent>();
    let bob_worker = tokio::spawn(run_websocket_worker(
        bob_ws_url,
        Some(TEST_MESSAGE_TOKEN.to_string()),
        Duration::from_millis(20),
        bob_tx,
    ));

    let mut alice_connected = false;
    for _ in 0..8 {
        let next = tokio::time::timeout(Duration::from_secs(1), alice_rx.next()).await?;
        let Some(event) = next else {
            break;
        };
        if matches!(event, WebSocketEvent::Connected) {
            alice_connected = true;
            break;
        }
    }
    let mut bob_connected = false;
    for _ in 0..8 {
        let next = tokio::time::timeout(Duration::from_secs(1), bob_rx.next()).await?;
        let Some(event) = next else {
            break;
        };
        if matches!(event, WebSocketEvent::Connected) {
            bob_connected = true;
            break;
        }
    }
    assert!(
        alice_connected && bob_connected,
        "both restarted watchers must reconnect before backlog fetch"
    );

    let mut alice_after_backlog = restarted_alice.clone();
    let alice_backlog_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_fetch(FetchParams::from_session(&alice_after_backlog, None)?).await?
    };
    for plaintext in backlog_messages {
        assert!(
            alice_backlog_fetch
                .messages
                .iter()
                .any(|message| message.plaintext == plaintext
                    && message.sender_leaf == Some(charlie.leaf_id)),
            "alice must bridge every backlog message emitted while both watchers were offline"
        );
    }
    apply_fetch_outcome_to_session(&mut alice_after_backlog, &alice_backlog_fetch);

    let mut bob_after_backlog = restarted_bob.clone();
    let bob_backlog_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_fetch(FetchParams::from_session(&bob_after_backlog, None)?).await?
    };
    for plaintext in backlog_messages {
        assert!(
            bob_backlog_fetch
                .messages
                .iter()
                .any(|message| message.plaintext == plaintext
                    && message.sender_leaf == Some(charlie.leaf_id)),
            "bob must bridge every backlog message emitted while both watchers were offline"
        );
    }
    apply_fetch_outcome_to_session(&mut bob_after_backlog, &bob_backlog_fetch);

    let alice_empty_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_fetch(FetchParams::from_session(&alice_after_backlog, None)?).await?
    };
    let bob_empty_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_fetch(FetchParams::from_session(&bob_after_backlog, None)?).await?
    };
    assert!(
        alice_empty_fetch.messages.is_empty() && bob_empty_fetch.messages.is_empty(),
        "once both restarted watchers bridge backlog, repeated fetches must stay empty"
    );

    let live_plaintext = "charlie-live-after-dual-restart".to_string();
    {
        let _override_guard = set_config_dir_override_for_tests(Some(charlie_base));
        perform_send(SendParams::from_session(
            &charlie,
            live_plaintext.clone(),
            2,
        )?)
        .await?;
    }

    let mut alice_saw_live_notification = false;
    for _ in 0..8 {
        let next = tokio::time::timeout(Duration::from_secs(1), alice_rx.next()).await?;
        let Some(event) = next else {
            break;
        };
        match event {
            WebSocketEvent::Message(signal) if !signal.replayed => {
                alice_saw_live_notification = true;
                break;
            }
            WebSocketEvent::Message(_) => {}
            WebSocketEvent::Connected
            | WebSocketEvent::Disconnected
            | WebSocketEvent::Membership(_) => {}
        }
    }
    let mut bob_saw_live_notification = false;
    for _ in 0..8 {
        let next = tokio::time::timeout(Duration::from_secs(1), bob_rx.next()).await?;
        let Some(event) = next else {
            break;
        };
        match event {
            WebSocketEvent::Message(signal) if !signal.replayed => {
                bob_saw_live_notification = true;
                break;
            }
            WebSocketEvent::Message(_) => {}
            WebSocketEvent::Connected
            | WebSocketEvent::Disconnected
            | WebSocketEvent::Membership(_) => {}
        }
    }
    assert!(
        alice_saw_live_notification && bob_saw_live_notification,
        "both restarted watchers must resume live notifications after backlog bridging"
    );

    let alice_live_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_fetch(FetchParams::from_session(&alice_after_backlog, None)?).await?
    };
    assert!(
        alice_live_fetch
            .messages
            .iter()
            .any(|message| message.plaintext == live_plaintext
                && message.sender_leaf == Some(charlie.leaf_id)),
        "alice must fetch the fresh live message after reconnect"
    );
    assert!(
        alice_live_fetch
            .messages
            .iter()
            .all(|message| !backlog_messages.contains(&message.plaintext.as_str())),
        "alice live fetch must not replay the bridged backlog"
    );

    let bob_live_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_fetch(FetchParams::from_session(&bob_after_backlog, None)?).await?
    };
    assert!(
        bob_live_fetch
            .messages
            .iter()
            .any(|message| message.plaintext == live_plaintext
                && message.sender_leaf == Some(charlie.leaf_id)),
        "bob must fetch the fresh live message after reconnect"
    );
    assert!(
        bob_live_fetch
            .messages
            .iter()
            .all(|message| !backlog_messages.contains(&message.plaintext.as_str())),
        "bob live fetch must not replay the bridged backlog"
    );

    alice_worker.abort();
    let _ = alice_worker.await;
    bob_worker.abort();
    let _ = bob_worker.await;
    handle.abort();
    let _ = handle.await;
    Ok(())
}
