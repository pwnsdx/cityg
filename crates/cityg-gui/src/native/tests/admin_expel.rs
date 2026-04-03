use super::*;

#[tokio::test]
async fn room_admin_grant_and_revoke_flow_preserves_authorization_boundaries()
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
    let mut room_id_bytes = [0xA4u8; 32];
    room_id_bytes[..2].copy_from_slice(&port.to_le_bytes());
    let room_id = hex_encode(room_id_bytes);
    let (bootstrap_admin_pop_public_key, bootstrap_admin_pop_secret_key) =
        bootstrap_test_room_with_admin_identity(&server_url, &room_id).await?;

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
    let client = new_api_client(&server_url);
    let bootstrap_admin = RoomIdentity::new(
        bootstrap_admin_pop_public_key.clone(),
        bootstrap_admin_pop_secret_key.clone(),
    );
    let alice_admin = RoomIdentity::new(alice.pop_public_key.clone(), alice.pop_secret_key.clone());
    let bob_admin = RoomIdentity::new(bob.pop_public_key.clone(), bob.pop_secret_key.clone());

    let bootstrap_grant_alice = bootstrap_admin.build_target_proof(
        RoomAdminOperation::GrantAdmin,
        &room_id,
        &alice.pop_public_key,
    )?;
    client
        .grant_room_admin(&room_id, &alice.pop_public_key, bootstrap_grant_alice)
        .await?;

    let alice_listing = alice_admin.build_listing_proof(&room_id)?;
    let admins_after_alice = client.list_room_admins(&room_id, alice_listing).await?;
    assert!(
        admins_after_alice
            .admin_pop_public_keys
            .iter()
            .any(|admin| admin.as_slice() == bootstrap_admin_pop_public_key.as_slice()),
        "bootstrap admin must remain in the ACL after delegating alice"
    );
    assert!(
        admins_after_alice
            .admin_pop_public_keys
            .iter()
            .any(|admin| admin.as_slice() == alice.pop_public_key.as_slice()),
        "alice must appear in the ACL after grant"
    );

    let alice_grant_bob = alice_admin.build_target_proof(
        RoomAdminOperation::GrantAdmin,
        &room_id,
        &bob.pop_public_key,
    )?;
    client
        .grant_room_admin(&room_id, &bob.pop_public_key, alice_grant_bob)
        .await?;

    let bob_listing = bob_admin.build_listing_proof(&room_id)?;
    let admins_after_bob = client.list_room_admins(&room_id, bob_listing).await?;
    assert!(
        admins_after_bob
            .admin_pop_public_keys
            .iter()
            .any(|admin| admin.as_slice() == bob.pop_public_key.as_slice()),
        "bob must appear in the ACL after alice grants admin"
    );

    let alice_revoke_bob = alice_admin.build_target_proof(
        RoomAdminOperation::RevokeAdmin,
        &room_id,
        &bob.pop_public_key,
    )?;
    client
        .revoke_room_admin(&room_id, &bob.pop_public_key, alice_revoke_bob)
        .await?;

    let alice_listing_after_revoke = alice_admin.build_listing_proof(&room_id)?;
    let admins_after_revoke = client
        .list_room_admins(&room_id, alice_listing_after_revoke)
        .await?;
    assert!(
        !admins_after_revoke
            .admin_pop_public_keys
            .iter()
            .any(|admin| admin.as_slice() == bob.pop_public_key.as_slice()),
        "bob must disappear from the ACL after revoke"
    );

    let bob_listing_after_revoke = bob_admin.build_listing_proof(&room_id)?;
    let err = client
        .list_room_admins(&room_id, bob_listing_after_revoke)
        .await
        .expect_err("revoked admin should lose admin-list visibility");
    assert!(
        err.to_string().contains("unauthorized") || err.to_string().contains("not authorized"),
        "revoked admin must get an authorization failure"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn admin_expel_removes_member_and_preserves_survivor_messaging()
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
    let mut room_id_bytes = [0xA5u8; 32];
    room_id_bytes[..2].copy_from_slice(&port.to_le_bytes());
    let room_id = hex_encode(room_id_bytes);
    let (bootstrap_admin_pop_public_key, bootstrap_admin_pop_secret_key) =
        bootstrap_test_room_with_admin_identity(&server_url, &room_id).await?;

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
        let synced = perform_epoch_sync(alice).await?.session;
        persist_session(&synced)?;
        synced
    };

    let client = new_api_client(&server_url);
    let bootstrap_admin = RoomIdentity::new(
        bootstrap_admin_pop_public_key.clone(),
        bootstrap_admin_pop_secret_key.clone(),
    );
    let alice_admin = RoomIdentity::new(alice.pop_public_key.clone(), alice.pop_secret_key.clone());
    let grant_proof = bootstrap_admin.build_target_proof(
        RoomAdminOperation::GrantAdmin,
        &room_id,
        &alice.pop_public_key,
    )?;
    client
        .grant_room_admin(&room_id, &alice.pop_public_key, grant_proof)
        .await?;

    let alice_admin_listing_proof = alice_admin.build_listing_proof(&room_id)?;
    let admins = client
        .list_room_admins(&room_id, alice_admin_listing_proof)
        .await?;
    assert!(
        admins
            .admin_pop_public_keys
            .iter()
            .any(|admin| admin.as_slice() == alice.pop_public_key.as_slice()),
        "newly granted admin must be visible before expel"
    );

    let alice_after_expel = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        persist_session(&alice)?;
        perform_room_admin_expel(alice.clone(), bob.leaf_id).await?
    };
    assert!(
        !alice_after_expel.barrier_state.barrier_recovery_pending,
        "survivor should stay message-ready after expelling another member"
    );

    let members_after_expel = client.members(&alice_after_expel.gid, None).await?;
    assert_eq!(members_after_expel.total_count, 1);
    assert!(
        members_after_expel
            .members
            .iter()
            .any(|member| member.leaf_id.as_slice() == alice_after_expel.leaf_id.as_slice()),
        "survivor must remain in the room after expel"
    );
    assert!(
        !members_after_expel
            .members
            .iter()
            .any(|member| member.leaf_id.as_slice() == bob.leaf_id.as_slice()),
        "expelled member must disappear from the roster"
    );

    let survivor_plaintext = "alice-after-expel".to_string();
    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_send(SendParams::from_session(
            &alice_after_expel,
            survivor_plaintext.clone(),
            0,
        )?)
        .await?;
    }

    let expelled_send_err = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        match perform_send(SendParams::from_session(
            &bob,
            "bob-after-expel".to_string(),
            0,
        )?)
        .await
        {
            Ok(_) => {
                return Err(
                    anyhow!("expelled member should not be able to send new traffic").into(),
                );
            }
            Err(err) => err,
        }
    };
    assert!(
        !expelled_send_err.to_string().is_empty(),
        "expelled send path should surface a concrete failure"
    );

    let expelled_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_fetch(FetchParams::from_session(&bob, None)?).await?
    };
    assert!(
        expelled_fetch
            .messages
            .iter()
            .all(|message| message.plaintext != survivor_plaintext),
        "expelled stale client must not decrypt survivor traffic from the new epoch"
    );

    let expelled_epoch_sync = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        perform_epoch_sync(bob).await
    };
    if let Ok(outcome) = expelled_epoch_sync {
        let err = match perform_send(SendParams::from_session(
            &outcome.session,
            "bob-after-expel-post-sync".to_string(),
            1,
        )?)
        .await
        {
            Ok(_) => {
                return Err(anyhow!(
                    "expelled member must stay unable to send after any sync outcome"
                )
                .into());
            }
            Err(err) => err,
        };
        assert!(
            !err.to_string().is_empty(),
            "post-sync expel rejection should remain explicit"
        );
    }

    let charlie = {
        let _override_guard = set_config_dir_override_for_tests(Some(charlie_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "charlie".to_string(),
        })
        .await?
    };
    let charlie = if charlie.barrier_state.barrier_recovery_pending {
        let _override_guard = set_config_dir_override_for_tests(Some(charlie_base.clone()));
        perform_epoch_sync(charlie).await?.session
    } else {
        charlie
    };
    assert!(
        !charlie.barrier_state.barrier_recovery_pending,
        "new joiner must become message-ready after admin expel"
    );
    {
        let _override_guard = set_config_dir_override_for_tests(Some(charlie_base));
        perform_send(SendParams::from_session(
            &charlie,
            "charlie-after-expel".to_string(),
            0,
        )?)
        .await?;
    }

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn restart_after_admin_expel_preserves_survivor_state_and_new_joiner_messaging()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let temp_dir = TempDir::new().expect("create temp dir");
    let alice_base = temp_dir.path().join("cityg").join("gui-alice");
    let bob_base = temp_dir.path().join("cityg").join("gui-bob");
    let charlie_base = temp_dir.path().join("cityg").join("gui-charlie");
    let journal_dir = temp_dir.path().join("cityg").join("server");
    std::fs::create_dir_all(&journal_dir)?;
    let journal_path = journal_dir.join("restart-after-admin-expel.journal");

    let port = next_test_port();
    let mut handle = spawn_server_on_with_state_path(port, journal_path.clone()).await;
    sleep(Duration::from_millis(250)).await;

    let server_url = format!("http://127.0.0.1:{port}");
    let mut room_id_bytes = [0xA7u8; 32];
    room_id_bytes[..2].copy_from_slice(&port.to_le_bytes());
    let room_id = hex_encode(room_id_bytes);
    let (bootstrap_admin_pop_public_key, bootstrap_admin_pop_secret_key) =
        bootstrap_test_room_with_admin_identity(&server_url, &room_id).await?;

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
        let synced = perform_epoch_sync(alice).await?.session;
        persist_session(&synced)?;
        synced
    };

    let client = new_api_client(&server_url);
    let bootstrap_admin = RoomIdentity::new(
        bootstrap_admin_pop_public_key.clone(),
        bootstrap_admin_pop_secret_key.clone(),
    );
    let grant_proof = bootstrap_admin.build_target_proof(
        RoomAdminOperation::GrantAdmin,
        &room_id,
        &alice.pop_public_key,
    )?;
    client
        .grant_room_admin(&room_id, &alice.pop_public_key, grant_proof)
        .await?;

    let expelled_alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        persist_session(&alice)?;
        perform_room_admin_expel(alice, bob.leaf_id).await?
    };
    let before_restart = client.members(&expelled_alice.gid, None).await?;
    assert_eq!(before_restart.total_count, 1);
    assert!(
        before_restart
            .members
            .iter()
            .any(|member| member.leaf_id.as_slice() == expelled_alice.leaf_id.as_slice()),
        "survivor must remain visible before restart"
    );
    assert!(
        !before_restart
            .members
            .iter()
            .any(|member| member.leaf_id.as_slice() == bob.leaf_id.as_slice()),
        "expelled member must stay absent before restart"
    );

    handle.abort();
    let _ = handle.await;
    sleep(Duration::from_millis(150)).await;

    handle = spawn_server_on_with_state_path(port, journal_path).await;
    sleep(Duration::from_millis(250)).await;

    let after_restart = new_api_client(&server_url)
        .members(&expelled_alice.gid, None)
        .await?;
    assert_eq!(after_restart.total_count, 1);
    assert!(
        after_restart
            .members
            .iter()
            .any(|member| member.leaf_id.as_slice() == expelled_alice.leaf_id.as_slice()),
        "survivor must remain visible after restart"
    );
    assert!(
        !after_restart
            .members
            .iter()
            .any(|member| member.leaf_id.as_slice() == bob.leaf_id.as_slice()),
        "expelled member must stay absent after restart"
    );

    let post_restart_alice = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        let synced = perform_epoch_sync(expelled_alice)
            .await
            .map_err(|err| anyhow!("post-restart alice epoch sync after expel: {err:#}"))?
            .session;
        persist_session(&synced)?;
        synced
    };
    assert!(
        !post_restart_alice.barrier_state.barrier_recovery_pending,
        "survivor should remain message-ready after restart sync"
    );

    let charlie = {
        let _override_guard = set_config_dir_override_for_tests(Some(charlie_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id,
            alias: "charlie".to_string(),
        })
        .await
        .map_err(|err| anyhow!("post-restart charlie join after expel: {err:#}"))?
    };
    let charlie = if charlie.barrier_state.barrier_recovery_pending {
        let _override_guard = set_config_dir_override_for_tests(Some(charlie_base.clone()));
        perform_epoch_sync(charlie)
            .await
            .map_err(|err| anyhow!("post-restart charlie join epoch sync after expel: {err:#}"))?
            .session
    } else {
        charlie
    };
    assert!(
        !charlie.barrier_state.barrier_recovery_pending,
        "new join must still become message-ready after restart + expel churn"
    );
    {
        let _override_guard = set_config_dir_override_for_tests(Some(charlie_base.clone()));
        perform_send(SendParams::from_session(
            &charlie,
            "charlie-after-restart-expel".to_string(),
            0,
        )?)
        .await
        .map_err(|err| anyhow!("post-restart charlie send after expel: {err:#}"))?;
    }

    handle.abort();
    let _ = handle.await;
    Ok(())
}

#[tokio::test]
async fn admin_expel_then_survivor_refresh_preserves_room_and_new_joiner_messaging()
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
    let mut room_id_bytes = [0xA8u8; 32];
    room_id_bytes[..2].copy_from_slice(&port.to_le_bytes());
    let room_id = hex_encode(room_id_bytes);
    let (bootstrap_admin_pop_public_key, bootstrap_admin_pop_secret_key) =
        bootstrap_test_room_with_admin_identity(&server_url, &room_id).await?;

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
        let synced = perform_epoch_sync(alice).await?.session;
        persist_session(&synced)?;
        synced
    };

    let client = new_api_client(&server_url);
    let bootstrap_admin = RoomIdentity::new(
        bootstrap_admin_pop_public_key.clone(),
        bootstrap_admin_pop_secret_key.clone(),
    );
    let grant_proof = bootstrap_admin.build_target_proof(
        RoomAdminOperation::GrantAdmin,
        &room_id,
        &alice.pop_public_key,
    )?;
    client
        .grant_room_admin(&room_id, &alice.pop_public_key, grant_proof)
        .await?;

    let alice_after_expel = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        persist_session(&alice)?;
        perform_room_admin_expel(alice.clone(), bob.leaf_id).await?
    };
    let alice_after_refresh = {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        persist_session(&alice_after_expel)?;
        perform_pcs_refresh(LeaveRequest::from_session(&alice_after_expel)).await?;
        let pending = load_session_at(&server_url, &room_id)?
            .ok_or_else(|| anyhow!("expected persisted alice session after expel+refresh"))?;
        let synced = perform_epoch_sync(pending).await?.session;
        persist_session(&synced)?;
        synced
    };
    assert!(
        !alice_after_refresh.barrier_state.barrier_recovery_pending,
        "survivor should remain message-ready after expel followed by refresh"
    );

    let members_after_refresh = client.members(&alice_after_refresh.gid, None).await?;
    assert_eq!(members_after_refresh.total_count, 1);
    assert!(
        members_after_refresh
            .members
            .iter()
            .any(|member| member.leaf_id.as_slice() == alice_after_refresh.leaf_id.as_slice()),
        "survivor must remain visible after expel+refresh"
    );
    assert!(
        !members_after_refresh
            .members
            .iter()
            .any(|member| member.leaf_id.as_slice() == bob.leaf_id.as_slice()),
        "expelled member must stay absent after survivor refresh"
    );

    let survivor_plaintext = "alice-after-expel-refresh".to_string();
    {
        let _override_guard = set_config_dir_override_for_tests(Some(alice_base.clone()));
        perform_send(SendParams::from_session(
            &alice_after_refresh,
            survivor_plaintext.clone(),
            0,
        )?)
        .await?;
    }

    let stale_bob_fetch = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base.clone()));
        perform_fetch(FetchParams::from_session(&bob, None)?).await?
    };
    assert!(
        stale_bob_fetch
            .messages
            .iter()
            .all(|message| message.plaintext != survivor_plaintext),
        "expelled stale client must not decrypt survivor traffic after expel+refresh"
    );

    let stale_bob_sync = {
        let _override_guard = set_config_dir_override_for_tests(Some(bob_base));
        perform_epoch_sync(bob).await
    };
    if let Ok(outcome) = stale_bob_sync {
        let err = match perform_send(SendParams::from_session(
            &outcome.session,
            "bob-after-expel-refresh".to_string(),
            1,
        )?)
        .await
        {
            Ok(_) => {
                return Err(anyhow!(
                    "expelled member must stay unable to send after expel+refresh"
                )
                .into());
            }
            Err(err) => err,
        };
        assert!(
            !err.to_string().is_empty(),
            "post-sync expel rejection must remain explicit after survivor refresh"
        );
    }

    let charlie = {
        let _override_guard = set_config_dir_override_for_tests(Some(charlie_base.clone()));
        perform_join(JoinParams {
            server_url: server_url.clone(),
            room_id: room_id.clone(),
            alias: "charlie".to_string(),
        })
        .await?
    };
    let charlie = if charlie.barrier_state.barrier_recovery_pending {
        let _override_guard = set_config_dir_override_for_tests(Some(charlie_base.clone()));
        perform_epoch_sync(charlie).await?.session
    } else {
        charlie
    };
    assert!(
        !charlie.barrier_state.barrier_recovery_pending,
        "new joiner must still become message-ready after expel+refresh churn"
    );
    let charlie_plaintext = "charlie-after-expel-refresh".to_string();
    {
        let _override_guard = set_config_dir_override_for_tests(Some(charlie_base));
        perform_send(SendParams::from_session(
            &charlie,
            charlie_plaintext.clone(),
            0,
        )?)
        .await?;
    }
    assert!(
        new_api_client(&server_url)
            .members(&alice_after_refresh.gid, None)
            .await?
            .members
            .iter()
            .any(|member| member.leaf_id.as_slice() == charlie.leaf_id.as_slice()),
        "fresh joiner must appear in the roster after expel+refresh churn"
    );

    handle.abort();
    let _ = handle.await;
    Ok(())
}
