use super::*;

#[tokio::test]
async fn message_replay_state_only_releases_new_messages_between_fetch_rounds()
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
    let room_id = hex_encode([0xA3u8; 32]);
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

    let first_round_plaintexts = ["bob-round-one-1", "bob-round-one-2"];
    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_send(SendParams::from_session(
            &bob,
            first_round_plaintexts[0].to_string(),
            0,
        )?)
        .await?;
        perform_send(SendParams::from_session(
            &bob,
            first_round_plaintexts[1].to_string(),
            1,
        )?)
        .await?;
    }

    let mut alice_after_first_fetch = alice.clone();
    let first_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_fetch(FetchParams::from_session(&alice_after_first_fetch, None)?).await?
    };
    for plaintext in first_round_plaintexts {
        assert!(
            first_fetch
                .messages
                .iter()
                .any(|message| message.plaintext == plaintext
                    && message.sender_leaf == Some(bob.leaf_id)),
            "initial fetch should include every message from the first round"
        );
    }
    apply_fetch_outcome_to_session(&mut alice_after_first_fetch, &first_fetch);

    let empty_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_fetch(FetchParams::from_session(&alice_after_first_fetch, None)?).await?
    };
    assert!(
        empty_fetch.messages.is_empty(),
        "repeated fetch with unchanged replay state should be empty"
    );
    apply_fetch_outcome_to_session(&mut alice_after_first_fetch, &empty_fetch);

    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        perform_send(SendParams::from_session(
            &bob,
            "bob-round-two-1".to_string(),
            2,
        )?)
        .await?;
        perform_send(SendParams::from_session(
            &bob,
            "bob-round-two-2".to_string(),
            3,
        )?)
        .await?;
    }

    let mut alice_after_second_fetch = alice_after_first_fetch.clone();
    let second_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_fetch(FetchParams::from_session(&alice_after_second_fetch, None)?).await?
    };
    assert!(
        second_fetch
            .messages
            .iter()
            .any(|message| message.plaintext == "bob-round-two-1"
                && message.sender_leaf == Some(bob.leaf_id)),
        "second fetch should include the first new message only after replay state advanced"
    );
    assert!(
        second_fetch
            .messages
            .iter()
            .any(|message| message.plaintext == "bob-round-two-2"
                && message.sender_leaf == Some(bob.leaf_id)),
        "second fetch should include the second new message only after replay state advanced"
    );
    assert!(
        second_fetch
            .messages
            .iter()
            .all(|message| !first_round_plaintexts.contains(&message.plaintext.as_str())),
        "second fetch must not replay the first round of traffic"
    );
    apply_fetch_outcome_to_session(&mut alice_after_second_fetch, &second_fetch);

    let final_empty_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        perform_fetch(FetchParams::from_session(&alice_after_second_fetch, None)?).await?
    };
    assert!(
        final_empty_fetch.messages.is_empty(),
        "after updating replay state again, a third fetch should be empty"
    );

    let members_after_burst = new_api_client(&server_url)
        .members(&alice_after_second_fetch.gid, None)
        .await?;
    assert_eq!(members_after_burst.total_count, 2);
    assert!(
        members_after_burst
            .members
            .iter()
            .any(|member| member.leaf_id.as_slice() == alice.leaf_id.as_slice()),
        "receiver should remain visible in the roster"
    );
    assert!(
        members_after_burst
            .members
            .iter()
            .any(|member| member.leaf_id.as_slice() == bob.leaf_id.as_slice()),
        "sender should remain visible in the roster"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn message_replay_state_survives_client_restart_between_fetch_rounds()
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
    let room_id = hex_encode([0xA4u8; 32]);
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

    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_send(SendParams::from_session(
            &bob,
            "bob-before-restart-1".to_string(),
            0,
        )?)
        .await?;
        perform_send(SendParams::from_session(
            &bob,
            "bob-before-restart-2".to_string(),
            1,
        )?)
        .await?;
    }

    let mut alice_after_first_fetch = alice.clone();
    let first_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_fetch(FetchParams::from_session(&alice_after_first_fetch, None)?).await?
    };
    assert!(
        first_fetch
            .messages
            .iter()
            .any(|message| message.plaintext == "bob-before-restart-1"
                && message.sender_leaf == Some(bob.leaf_id))
    );
    assert!(
        first_fetch
            .messages
            .iter()
            .any(|message| message.plaintext == "bob-before-restart-2"
                && message.sender_leaf == Some(bob.leaf_id))
    );
    apply_fetch_outcome_to_session(&mut alice_after_first_fetch, &first_fetch);
    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        persist_session(&alice_after_first_fetch)?;
    }

    let alice_after_restart = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        load_session_at(&server_url, &room_id)?
            .ok_or_else(|| anyhow!("expected persisted session after simulated client restart"))?
    };
    assert_eq!(
        alice_after_restart.last_fetch_timestamp_ms,
        alice_after_first_fetch.last_fetch_timestamp_ms,
        "simulated restart must preserve the last fetch watermark"
    );

    let empty_fetch_after_restart = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_fetch(FetchParams::from_session(&alice_after_restart, None)?).await?
    };
    assert!(
        empty_fetch_after_restart.messages.is_empty(),
        "restart without new traffic must not re-deliver old messages"
    );

    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        perform_send(SendParams::from_session(
            &bob,
            "bob-after-restart-1".to_string(),
            2,
        )?)
        .await?;
        perform_send(SendParams::from_session(
            &bob,
            "bob-after-restart-2".to_string(),
            3,
        )?)
        .await?;
    }

    let second_fetch_after_restart = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_fetch(FetchParams::from_session(&alice_after_restart, None)?).await?
    };
    assert!(
        second_fetch_after_restart
            .messages
            .iter()
            .any(|message| message.plaintext == "bob-after-restart-1"
                && message.sender_leaf == Some(bob.leaf_id)),
        "new traffic after restart must still be delivered"
    );
    assert!(
        second_fetch_after_restart
            .messages
            .iter()
            .any(|message| message.plaintext == "bob-after-restart-2"
                && message.sender_leaf == Some(bob.leaf_id)),
        "new traffic after restart must still be delivered"
    );
    assert!(
        second_fetch_after_restart.messages.iter().all(|message| {
            message.plaintext != "bob-before-restart-1"
                && message.plaintext != "bob-before-restart-2"
        }),
        "restart path must not re-deliver the pre-restart burst"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}
