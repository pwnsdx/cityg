use super::*;

#[gpui::test]
fn gpui_on_leave_finished_surfaces_session_cleanup_error(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let session = build_test_session(
        0xBADD,
        "http://127.0.0.1:18080",
        "99aabbccddeeff00112233445566778899aabbccddeeff001122334455667788",
        "leave-err",
    )
    .expect("build session");
    let blocking_path =
        session_file_path(&session.server_url, &session.room_id).expect("session path");
    fs::create_dir_all(&blocking_path).expect("create blocking path");

    view.update(cx, |model, view_cx| {
        model.session = Some(session.clone());
        model.on_leave_finished(Ok(()), view_cx);
        assert!(
            model
                .last_error
                .as_deref()
                .unwrap_or_default()
                .contains("failed to remove session data")
        );
    });
}

#[gpui::test]
fn gpui_on_refresh_finished_reloads_persisted_pending_barrier_state(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let stale_session = build_test_session(
        0xCAFE,
        "http://127.0.0.1:18081",
        "11aabbccddeeff00112233445566778899aabbccddeeff001122334455667799",
        "refresh-reload",
    )
    .expect("build stale session");
    let mut persisted_session = stale_session.clone();
    persisted_session.barrier_state.barrier_initialized = true;
    persisted_session.barrier_state.barrier_version = 7;
    persisted_session.barrier_state.barrier_recovery_pending = true;
    persisted_session.barrier_state.pending = Some(BarrierPendingState {
        barrier_version: 8,
        we_epoch_id: [0x44; 32],
        barrier_update_digest: [0x55; 32],
        barrier_update_reason: Some(1),
        ..BarrierPendingState::default()
    });
    persist_session(&persisted_session).expect("persist session with pending barrier state");

    view.update(cx, |model, view_cx| {
        model.session = Some(stale_session);
        model.on_refresh_finished(Ok(()), view_cx);

        let reloaded = model.session.as_ref().expect("reloaded session");
        assert_eq!(reloaded.barrier_state.barrier_version, 7);
        assert!(reloaded.barrier_state.barrier_recovery_pending);
        assert!(
            reloaded.barrier_state.pending.is_some(),
            "refresh completion must reload pending barrier activation data"
        );
        assert_eq!(
            model.info_message.as_deref(),
            Some("PCS refresh submitted. Syncing latest epoch…")
        );
    });
}

#[gpui::test]
fn gpui_handle_fetch_result_requires_replay_persistence_before_release(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let session = build_test_session(
        0xD15C,
        "http://127.0.0.1:18082",
        "22aabbccddeeff00112233445566778899aabbccddeeff001122334455667799",
        "fetch-persist",
    )
    .expect("build session");
    let mut session = session;
    session.last_fetch_timestamp_ms = None;
    let blocking_path =
        session_file_path(&session.server_url, &session.room_id).expect("session path");
    fs::create_dir_all(&blocking_path).expect("create blocking path");

    view.update(cx, |model, view_cx| {
        model.session = Some(session.clone());
        model.handle_fetch_result(
            Ok(FetchOutcome {
                messages: vec![ChatMessageEntry {
                    sender_leaf: Some(session.leaf_id),
                    fallback_label: session.alias.clone(),
                    plaintext: "must-not-release".to_string(),
                    ciphertext_hex: "deadbeef".to_string(),
                    timestamp_ms: 2_000_000,
                    delivery: MessageDelivery::Sent,
                    pending_id: None,
                }],
                last_timestamp_ms: Some(2_000_000),
                msg_replay_state: MsgReplayState::default(),
            }),
            session.we_epoch_id,
            view_cx,
        );

        assert!(
            model.messages.is_empty(),
            "messages must not be released before replay persistence succeeds"
        );
        assert!(
            model
                .last_error
                .as_deref()
                .unwrap_or_default()
                .contains("Failed to persist session after fetch update"),
            "persist failure must surface as fetch persistence failure"
        );
        assert_eq!(
            model
                .session
                .as_ref()
                .and_then(|s| s.last_fetch_timestamp_ms),
            None,
            "failed replay persistence must not advance in-memory fetch watermark"
        );
    });
}

#[gpui::test]
fn gpui_keystroke_routing_covers_clipboard_shortcuts(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));

    cx.write_to_clipboard(ClipboardItem::new_string("http://demo".to_string()));
    view.update(cx, |model, view_cx| {
        model.join_form.server.clear();
        model.join_form.room_id.clear();
        model.join_form.alias = "sab".to_string();
        model.join_form.active = Some(ActiveField::Server);
        model.on_keystroke(&Keystroke::parse("cmd-v").expect("parse cmd-v"), view_cx);
        assert_eq!(model.join_form.server, "http://demo");

        let server_text = model.join_form.server.clone();
        model.join_form.server_editor.select_all(&server_text);
        model.on_keystroke(&Keystroke::parse("cmd-c").expect("parse cmd-c"), view_cx);
        let copied = view_cx
            .read_from_clipboard()
            .and_then(|item| item.text())
            .expect("clipboard join field");
        assert_eq!(copied, "http://demo");

        model.on_keystroke(&Keystroke::parse("cmd-x").expect("parse cmd-x"), view_cx);
        assert!(model.join_form.server.is_empty());

        model.join_status = JoinStatus::Joining;
        model.join_form.alias = "keep".to_string();
        model.on_keystroke(&Keystroke::parse("x->z").expect("parse x"), view_cx);
        assert_eq!(model.join_form.alias, "keep");
        model.join_status = JoinStatus::Idle;
        model.join_form.active = Some(ActiveField::Alias);
        model.on_keystroke(&Keystroke::parse("ctrl-a").expect("parse ctrl-a"), view_cx);
        model.on_keystroke(&Keystroke::parse("x->q").expect("parse x->q"), view_cx);
    });

    let session = build_test_session(
        0x77,
        "http://127.0.0.1:9",
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        "goy",
    )
    .expect("build test session");
    cx.write_to_clipboard(ClipboardItem::new_string("\nxyz".to_string()));
    view.update(cx, |model, view_cx| {
        model.session = Some(session);
        model.join_form.active = None;

        model.members_search.focus();
        model.members_search.set_query("ab".to_string());
        model.on_keystroke(&Keystroke::parse("cmd-v").expect("parse cmd-v"), view_cx);
        assert_eq!(model.members_search.query(), "ab xyz");
        model.on_keystroke(&Keystroke::parse("x->d").expect("parse x->d"), view_cx);
        model.on_keystroke(&Keystroke::parse("ctrl-a").expect("parse ctrl-a"), view_cx);
        model.on_keystroke(&Keystroke::parse("enter").expect("parse enter"), view_cx);

        let members_query = model.members_search.query().to_string();
        model.members_search.editor.select_all(&members_query);
        model.on_keystroke(&Keystroke::parse("cmd-x").expect("parse cmd-x"), view_cx);
        assert!(model.members_search.query().is_empty());

        model.members_search.blur();
        model.composer.focus();
        model.composer.set_text("hello".to_string());
        model.on_keystroke(&Keystroke::parse("x->r").expect("parse x->r"), view_cx);
        assert_eq!(model.composer.text(), "hello");
        let composer_text = model.composer.text().to_string();
        model.composer.editor.select_all(&composer_text);
        model.on_keystroke(&Keystroke::parse("cmd-c").expect("parse cmd-c"), view_cx);
        let copied = view_cx
            .read_from_clipboard()
            .and_then(|item| item.text())
            .expect("clipboard composer");
        assert_eq!(copied, "hello");

        model.on_keystroke(&Keystroke::parse("cmd-x").expect("parse cmd-x"), view_cx);
        assert!(model.composer.text().is_empty());
        model.composer.set_text("ok".to_string());
        model.on_keystroke(&Keystroke::parse("enter").expect("parse enter"), view_cx);
    });

    cx.update(|window, app| {
        view.update(app, |model, view_cx| {
            let event = test_mouse_down_event();
            model.composer.set_text(String::new());
            model.on_send_clicked(&event, window, view_cx);
            model.on_composer_clicked(&event, window, view_cx);
            model.on_join_clicked(&event, window, view_cx);
            model.on_members_search_field_clicked(&event, window, view_cx);
            model.on_members_search_button_clicked(&event, window, view_cx);
            model.on_members_search_clear_clicked(&event, window, view_cx);
            model.on_members_refresh_clicked(&event, window, view_cx);
            model.on_members_load_more_clicked(&event, window, view_cx);
        });
    });
}

#[gpui::test]
fn gpui_async_handler_paths_cover_state_machine(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    cx.refresh().expect("initial refresh");
    cx.run_until_parked();

    let session = build_test_session(
        0xA11CE,
        "http://127.0.0.1:9",
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        "async",
    )
    .expect("build test session");

    cx.update(|window, app| {
        view.update(app, |model, view_cx| {
            let event = test_mouse_down_event();

            model.join_form.server = "http://127.0.0.1:9".to_string();
            model.join_form.room_id =
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string();
            model.join_form.alias = "async".to_string();
            model.start_join(view_cx);
            assert!(matches!(model.join_status, JoinStatus::Joining));

            model.on_join_finished(Err(anyhow::anyhow!("join failed")), view_cx);
            assert!(matches!(model.join_status, JoinStatus::Idle));

            model.on_join_finished(Ok(session.clone()), view_cx);
            assert!(model.session.is_some());

            model.composer.set_text("hello".to_string());
            model.start_send(view_cx);
            assert!(matches!(model.send_status, SendStatus::Sending));
            let pending_id = model.next_pending_message_id.saturating_sub(1);
            model.on_send_finished(
                Ok(ChatMessageEntry {
                    sender_leaf: Some(session.leaf_id),
                    fallback_label: session.alias.clone(),
                    plaintext: "hello".to_string(),
                    ciphertext_hex: "abcd".to_string(),
                    timestamp_ms: 42,
                    delivery: MessageDelivery::Sent,
                    pending_id: None,
                }),
                pending_id,
                view_cx,
            );
            model.on_send_finished(
                Err(anyhow::anyhow!("send failed")),
                pending_id.saturating_add(10),
                view_cx,
            );

            let expected_weid = session.we_epoch_id;
            model.handle_fetch_result(
                Ok(FetchOutcome {
                    messages: vec![ChatMessageEntry {
                        sender_leaf: Some(session.leaf_id),
                        fallback_label: session.alias.clone(),
                        plaintext: "synced".to_string(),
                        ciphertext_hex: "beef".to_string(),
                        timestamp_ms: 100,
                        delivery: MessageDelivery::Sent,
                        pending_id: None,
                    }],
                    last_timestamp_ms: Some(100),
                    msg_replay_state: MsgReplayState::default(),
                }),
                expected_weid,
                view_cx,
            );
            model.handle_fetch_result(Err(anyhow::anyhow!("fetch failed")), expected_weid, view_cx);
            model.handle_fetch_result(
                Ok(FetchOutcome {
                    messages: vec![],
                    last_timestamp_ms: None,
                    msg_replay_state: MsgReplayState::default(),
                }),
                [0xFF; 32],
                view_cx,
            );

            model.on_members_refreshed(
                Ok(MembersPage {
                    members: vec![MemberEntry {
                        leaf_id: session.leaf_id,
                        alias: Some(session.alias.clone()),
                        pop_public_key: Some(vec![0x01]),
                        join_timestamp_ms: Some(10),
                        last_seen_timestamp_ms: Some(11),
                    }],
                    root: session.parent_root,
                    total_count: 1,
                    next_offset: 1,
                }),
                view_cx,
            );
            model.on_members_refreshed(Err(anyhow::anyhow!("members failed")), view_cx);

            model.handle_epoch_sync_result(
                Ok(EpochSyncOutcome {
                    session: session.clone(),
                    changed: false,
                }),
                &session.server_url,
                &session.room_id,
                session.leaf_id,
                "noop",
                view_cx,
            );
            let mut changed_session = session.clone();
            changed_session.we_epoch_id = [0x55; 32];
            model.handle_epoch_sync_result(
                Ok(EpochSyncOutcome {
                    session: changed_session,
                    changed: true,
                }),
                &session.server_url,
                &session.room_id,
                session.leaf_id,
                "changed",
                view_cx,
            );
            model.handle_epoch_sync_result(
                Err(anyhow::anyhow!("sync failed")),
                &session.server_url,
                &session.room_id,
                session.leaf_id,
                "err",
                view_cx,
            );

            model.handle_stale_server_session("stale", view_cx);
            assert!(model.session.is_none());

            model.session = Some(session.clone());
            model.on_leave_clicked(&event, window, view_cx);
            assert!(matches!(model.leave_status, LeaveStatus::Leaving));
            model.on_leave_finished(Err(anyhow::anyhow!("leave failed")), view_cx);
            model.on_leave_finished(Ok(()), view_cx);
        });
    });

    cx.refresh().expect("post async state refresh");
    cx.run_until_parked();
}
