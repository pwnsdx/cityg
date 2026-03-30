use super::*;

#[tokio::test]
async fn client_restart_during_multi_version_catchup_after_refresh_and_leave_recovers_cleanly()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");

    let port = next_test_port();
    let handle = spawn_server_with_seed_demo_room(port, false).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let mut room_id_bytes = [0xAAu8; 32];
    room_id_bytes[..2].copy_from_slice(&port.to_le_bytes());
    let room_id = hex_encode(room_id_bytes);

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
    let synced_alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        let synced = perform_epoch_sync(alice).await?.session;
        persist_session(&synced)?;
        synced
    };

    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_pcs_refresh(LeaveRequest::from_session(&synced_alice)).await?;
    }
    let refreshed_alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        let pending = load_session_at(&server_url, &room_id)?
            .ok_or_else(|| anyhow!("expected persisted alice session after refresh"))?;
        let synced = perform_epoch_sync(pending).await?.session;
        persist_session(&synced)?;
        synced
    };
    assert!(
        !refreshed_alice.barrier_state.barrier_recovery_pending,
        "refresh author should finalize local pending state before leaving"
    );

    let alice_plaintext = "alice-before-leave-after-refresh".to_string();
    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_send(SendParams::from_session(
            &refreshed_alice,
            alice_plaintext.clone(),
            0,
        )?)
        .await?;
    }

    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        perform_leave(LeaveRequest::from_session(&refreshed_alice)).await?;
    }
    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        persist_session(&bob)?;
    }
    let reloaded_bob = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        load_session_at(&server_url, &room_id)?.ok_or_else(|| {
            anyhow!("expected persisted stale bob session after simulated restart")
        })?
    };

    let bob_after_sync = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        let outcome = perform_epoch_sync(reloaded_bob).await?;
        persist_session(&outcome.session)?;
        outcome.session
    };
    assert!(
        !bob_after_sync.barrier_state.barrier_recovery_pending,
        "stale restarted member should recover to a message-ready state"
    );
    let members_after = new_api_client(&server_url)
        .members(&bob_after_sync.gid, None)
        .await?;
    assert_eq!(members_after.total_count, 1);
    assert!(
        members_after
            .members
            .iter()
            .any(|member| member.leaf_id.as_slice() == bob_after_sync.leaf_id.as_slice()),
        "surviving member must remain present after restart + catch-up"
    );

    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        let _ = perform_fetch(FetchParams::from_session(&bob_after_sync, None)?).await?;
    }

    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        perform_send(SendParams::from_session(
            &bob_after_sync,
            "bob-after-restart-catchup".to_string(),
            0,
        )?)
        .await?;
    }

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn two_restarted_members_exchange_traffic_without_duplicate_delivery()
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
    let room_id = hex_encode([0xA6u8; 32]);
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
        let synced = perform_epoch_sync(bob).await?.session;
        persist_session(&synced)?;
        synced
    };
    assert!(
        !alice_after_sync.barrier_state.barrier_recovery_pending
            && !bob_after_sync.barrier_state.barrier_recovery_pending,
        "both members must be message-ready before simulating dual restart"
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
    assert_eq!(
        restarted_alice.we_epoch_id, restarted_bob.we_epoch_id,
        "dual restart should reload both peers onto the same accepted epoch"
    );

    let mut alice_after_restart = restarted_alice.clone();
    let mut bob_after_restart = restarted_bob.clone();

    let alice_burst = ["alice-after-restart-1", "alice-after-restart-2"];
    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_send(SendParams::from_session(
            &alice_after_restart,
            alice_burst[0].to_string(),
            0,
        )?)
        .await?;
        perform_send(SendParams::from_session(
            &alice_after_restart,
            alice_burst[1].to_string(),
            1,
        )?)
        .await?;
    }

    let bob_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_fetch(FetchParams::from_session(&bob_after_restart, None)?).await?
    };
    for plaintext in alice_burst {
        assert!(
            bob_fetch
                .messages
                .iter()
                .any(|message| message.plaintext == plaintext
                    && message.sender_leaf == Some(alice_after_restart.leaf_id)),
            "bob must decrypt alice's burst after both clients restart"
        );
    }
    apply_fetch_outcome_to_session(&mut bob_after_restart, &bob_fetch);

    let bob_empty_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_fetch(FetchParams::from_session(&bob_after_restart, None)?).await?
    };
    assert!(
        bob_empty_fetch.messages.is_empty(),
        "repeated fetch after bob advances replay-state must be empty"
    );

    let bob_burst = ["bob-after-restart-1", "bob-after-restart-2"];
    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_send(SendParams::from_session(
            &bob_after_restart,
            bob_burst[0].to_string(),
            2,
        )?)
        .await?;
        perform_send(SendParams::from_session(
            &bob_after_restart,
            bob_burst[1].to_string(),
            3,
        )?)
        .await?;
    }

    let alice_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_fetch(FetchParams::from_session(&alice_after_restart, None)?).await?
    };
    for plaintext in bob_burst {
        assert!(
            alice_fetch
                .messages
                .iter()
                .any(|message| message.plaintext == plaintext
                    && message.sender_leaf == Some(bob_after_restart.leaf_id)),
            "alice must decrypt bob's burst after both clients restart"
        );
    }
    apply_fetch_outcome_to_session(&mut alice_after_restart, &alice_fetch);

    let alice_empty_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_fetch(FetchParams::from_session(&alice_after_restart, None)?).await?
    };
    assert!(
        alice_empty_fetch.messages.is_empty(),
        "repeated fetch after alice advances replay-state must be empty"
    );

    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        persist_session(&alice_after_restart)?;
    }
    {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        persist_session(&bob_after_restart)?;
    }

    let alice_reloaded_again = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        load_session_at(&server_url, &room_id)?
            .ok_or_else(|| anyhow!("expected alice session after second simulated restart"))?
    };
    let bob_reloaded_again = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        load_session_at(&server_url, &room_id)?
            .ok_or_else(|| anyhow!("expected bob session after second simulated restart"))?
    };
    assert_eq!(
        alice_reloaded_again.last_fetch_timestamp_ms, alice_after_restart.last_fetch_timestamp_ms,
        "alice replay watermark must survive repeated restart boundaries"
    );
    assert_eq!(
        bob_reloaded_again.last_fetch_timestamp_ms, bob_after_restart.last_fetch_timestamp_ms,
        "bob replay watermark must survive repeated restart boundaries"
    );

    let final_plaintext = "alice-final-after-dual-restart".to_string();
    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base));
        perform_send(SendParams::from_session(
            &alice_reloaded_again,
            final_plaintext.clone(),
            4,
        )?)
        .await?;
    }
    let bob_final_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        perform_fetch(FetchParams::from_session(&bob_reloaded_again, None)?).await?
    };
    assert!(
        bob_final_fetch
            .messages
            .iter()
            .any(|message| message.plaintext == final_plaintext
                && message.sender_leaf == Some(alice_reloaded_again.leaf_id)),
        "traffic must still flow after both members cross a second restart boundary"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}
