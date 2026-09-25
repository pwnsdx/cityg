//! End-to-end flows of the GUI against an in-process v3 delivery service.

use super::*;

fn has_message(model: &AppModel, text: &str) -> bool {
    model
        .messages
        .iter()
        .any(|message| message.plaintext == text && message.delivery == MessageDelivery::Sent)
}

fn has_activity(model: &AppModel, text: &str) -> bool {
    model
        .activity_events
        .iter()
        .any(|event| event.summary.contains(text))
}

/// Create a room from the join form; returns once the session is active.
fn create_room_from_form(
    cx: &mut VisualTestContext,
    view: &Entity<AppModel>,
    server: &TestServer,
    alias: &str,
) {
    view.update(cx, |model, cx| {
        model.join_form.server = server.url.clone();
        model.join_form.room_id.clear();
        model.join_form.alias = alias.to_string();
        assert!(matches!(
            model.join_form.join_request(),
            Ok(JoinRequest::Create { .. })
        ));
        model.start_join(cx);
        assert!(matches!(model.join_status, JoinStatus::Joining));
    });
    wait_for(cx, view, "room creation", |model| {
        model.session.is_some() && matches!(model.join_status, JoinStatus::Idle)
    });
}

/// Join the room of `invite` from the join form.
fn join_from_form(cx: &mut VisualTestContext, view: &Entity<AppModel>, invite: &str, alias: &str) {
    view.update(cx, |model, cx| {
        let link = parse_join_invite(invite).expect("parse").expect("invite");
        model
            .join_form
            .apply_invite(invite, &link)
            .expect("apply invite");
        model.join_form.alias = alias.to_string();
        assert!(matches!(
            model.join_form.join_request(),
            Ok(JoinRequest::Invite { .. })
        ));
        model.start_join(cx);
    });
    wait_for(cx, view, "join", |model| {
        model.session.is_some() && matches!(model.join_status, JoinStatus::Idle)
    });
}

fn sync_now(cx: &mut VisualTestContext, view: &Entity<AppModel>) {
    view.update(cx, |model, cx| model.schedule_fetch(cx, Duration::ZERO));
}

#[gpui::test]
fn gpui_room_lifecycle_against_the_v3_service(cx: &mut TestAppContext) {
    let config = ConfigDir::new();
    let server = TestServer::start();
    let (view, cx) = open_window(cx, None);

    // Alice creates a room from the join form and becomes its admin.
    create_room_from_form(cx, &view, &server, "alice");
    let (room_id, alice_pk) = view.update(cx, |model, _| {
        let session = model.session.as_ref().expect("session");
        assert!(session.is_admin());
        assert_eq!(model.members_total, 1);
        assert!(model.room_admins_loaded);
        assert!(has_activity(model, "Joined room"));
        assert!(
            model
                .info_message
                .as_deref()
                .is_some_and(|info| info.contains("Room created"))
        );
        assert!(model.join_form.active.is_none());
        (session.room_id.clone(), session.pop_public_key.clone())
    });
    assert!(
        session_file_path(&server.url, &room_id)
            .expect("session path")
            .exists()
    );
    assert!(config.dir.path().exists());

    // The runtime tasks start with the session; the notification socket
    // connects with a session token.
    wait_for(cx, &view, "websocket", |model| model.ws_connected);
    view.update(cx, |model, _| {
        assert!(model.maintenance_task.is_some());
        assert!(model.ws_task.is_some());
    });
    wait_for(cx, &view, "endpoint probe", |model| {
        model.endpoint_mode == super::super::endpoint_mode::EndpointMode::DirectApi
    });

    // Alice copies an invite link; Bob and Carol join with it.
    view.update(cx, |model, cx| model.copy_room_invite_to_clipboard(cx));
    wait_for(cx, &view, "invite", |model| {
        has_activity(model, "Created an invite link")
    });
    let invite = clipboard_text(cx).expect("invite on the clipboard");
    assert!(invite.starts_with(INVITE_PREFIX));
    let bob = server.join(&invite, "bob");
    let carol = server.join(&invite, "carol");
    sync_now(cx, &view);
    wait_for(cx, &view, "two joins", |model| {
        model.members_total == 3
            && model
                .member_alias_index
                .values()
                .any(|alias| alias == "bob")
            && model
                .member_alias_index
                .values()
                .any(|alias| alias == "carol")
    });
    view.update(cx, |model, _| {
        assert!(has_activity(model, "Joined: bob"));
        assert!(model.members.iter().all(|member| member.alias.is_some()));
    });

    // Bob talks; the GUI receives it (the log-head notice or a poll).
    server
        .block_on(engine::send_text(&bob, "hi alice"))
        .expect("bob sends");
    sync_now(cx, &view);
    wait_for(cx, &view, "bob's message", |model| {
        has_message(model, "hi alice")
    });

    // Alice answers from the composer; Bob decrypts it.
    view.update(cx, |model, cx| {
        model.composer.focus();
        model.composer.set_text("hello bob".to_string());
        model.start_send(cx);
        assert!(matches!(model.send_status, SendStatus::Sending));
        assert!(
            model
                .messages
                .iter()
                .any(|message| message.delivery == MessageDelivery::Pending)
        );
    });
    wait_for(cx, &view, "send", |model| {
        matches!(model.send_status, SendStatus::Idle) && has_message(model, "hello bob")
    });
    let bob_view = server.sync(&bob);
    assert!(
        bob_view
            .messages
            .iter()
            .any(|message| message.text == "hello bob")
    );

    // Admin rights: grant Bob, then revoke (the revoke needs a confirmation).
    let bob_pk = server.block_on(async { bob.lock().await.identity().public_key().to_vec() });
    view.update(cx, |model, cx| {
        model.set_room_admin_target(bob_pk.clone(), cx);
        model.start_room_admin_mutation_from_input(RoomAdminMutationKind::Grant, cx);
        assert!(matches!(
            model.room_admin_status,
            RoomAdminStatus::Loading(_)
        ));
    });
    wait_for(cx, &view, "grant", |model| {
        matches!(model.room_admin_status, RoomAdminStatus::Idle)
            && model.room_admins.contains(&bob_pk)
    });
    view.update(cx, |model, cx| {
        model.set_room_admin_target(bob_pk.clone(), cx);
        model.start_room_admin_mutation_from_input(RoomAdminMutationKind::Revoke, cx);
        assert!(model.room_admin_revoke_is_staged_for_input());
        model.start_room_admin_mutation_from_input(RoomAdminMutationKind::Revoke, cx);
    });
    wait_for(cx, &view, "revoke", |model| {
        matches!(model.room_admin_status, RoomAdminStatus::Idle)
            && !model.room_admins.contains(&bob_pk)
            && model.room_admins.contains(&alice_pk)
    });

    // Carol leaves: her request is recorded; the maintenance commits it.
    server
        .block_on(engine::leave_room(&carol))
        .expect("carol leaves");
    sync_now(cx, &view);
    wait_for(cx, &view, "leave request", |model| {
        model
            .session
            .as_ref()
            .is_some_and(|session| session.view.pending_removals == 1)
    });
    view.update(cx, |model, _| {
        assert!(model.members.iter().any(|member| member.pending_removal));
        assert!(has_activity(model, "Leave requested: carol"));
        let session = model.session.as_ref().expect("session");
        assert_eq!(
            session_runtime::maintenance_action(session, engine::now_ms()),
            Some(session_runtime::MaintenanceAction::CommitPending)
        );
    });
    view.update(cx, |model, cx| model.run_maintenance(cx));
    wait_for(cx, &view, "removal commit", |model| {
        !model.removal_commit_in_flight && model.members_total == 2
    });
    view.update(cx, |model, _| {
        assert!(has_activity(
            model,
            "Committed the pending leave and join requests"
        ));
    });

    // PCS refresh from the session controls.
    let epoch_before = view.update(cx, |model, cx| {
        let epoch = model.session.as_ref().expect("session").view.epoch;
        model.start_pcs_refresh(cx);
        assert!(matches!(model.leave_status, LeaveStatus::Refreshing));
        epoch
    });
    wait_for(cx, &view, "refresh", |model| {
        matches!(model.leave_status, LeaveStatus::Idle)
            && model
                .session
                .as_ref()
                .is_some_and(|session| session.view.epoch > epoch_before)
    });
    view.update(cx, |model, _| {
        assert_eq!(
            model
                .session
                .as_ref()
                .expect("session")
                .view
                .epochs_since_own_update,
            0
        );
    });

    // A second window restores the saved session and its chat history.
    {
        let restored = AppModel::new(CityGConfig::default());
        let session = restored.session.as_ref().expect("restored session");
        assert_eq!(session.room_id, room_id);
        assert_eq!(session.alias, "alice");
        assert!(has_message(&restored, "hi alice"));
        assert!(has_message(&restored, "hello bob"));
        assert_eq!(
            restored.info_message.as_deref(),
            Some("Restored saved session.")
        );
    }

    // Alice expels Bob.
    let bob_ref = server.block_on(async { bob.lock().await.session().me() });
    cx.update(|window, app| {
        view.update(app, |model, cx| {
            model.prompt_member_expulsion(bob_ref, "bob".to_string(), window, cx);
        });
    });
    let (question, detail) = cx.pending_prompt().expect("expel prompt");
    assert_eq!(question, "Expel bob from this room?");
    assert!(detail.contains(&member_ref_text(bob_ref)));
    cx.simulate_prompt_answer("Expel");
    wait_for(cx, &view, "expel", |model| {
        matches!(model.leave_status, LeaveStatus::Idle) && model.members_total == 1
    });
    view.update(cx, |model, _| {
        assert!(has_activity(model, "Removed a member"))
    });
    assert!(server.sync(&bob).removed);

    // Alice, the last member, leaves: her leave is recorded (nobody is left
    // to commit it) and the local state is erased.
    view.update(cx, |model, cx| {
        model.start_leave(cx);
        assert!(matches!(model.leave_status, LeaveStatus::Leaving));
    });
    wait_for(cx, &view, "leave", |model| model.session.is_none());
    view.update(cx, |model, _| {
        assert_eq!(
            model.info_message.as_deref(),
            Some("Leave requested. The remaining members commit your removal.")
        );
        assert!(model.members.is_empty());
        assert!(model.maintenance_task.is_none());
        assert!(model.ws_task.is_none());
    });
    assert!(
        !session_file_path(&server.url, &room_id)
            .expect("session path")
            .exists()
    );
    assert!(read_last_session_pointer().expect("pointer").is_none());
}

#[gpui::test]
fn gpui_member_joins_by_invite_and_notices_its_removal(cx: &mut TestAppContext) {
    let _config = ConfigDir::new();
    let server = TestServer::start();
    let alice = server.create_member("alice");
    let invite = server.invite(&alice);
    let (view, cx) = open_window(cx, None);

    // Pasting the invite fills the form; joining uses it.
    view.update(cx, |model, cx| {
        model.join_form.active = Some(ActiveField::Room);
        cx.write_to_clipboard(ClipboardItem::new_string(invite.clone()));
    });
    cx.update(|window, app| {
        view.update(app, |model, cx| {
            model.focus_text_field(NativeTextFieldKind::JoinRoom, window, cx);
            assert!(model.paste_focused_text(cx));
            assert_eq!(model.join_form.server, server.url);
            assert_eq!(model.join_form.room_id, invite);
        });
    });
    join_from_form(cx, &view, &invite, "bob");
    view.update(cx, |model, _| {
        let session = model.session.as_ref().expect("session");
        assert!(!session.is_admin());
        assert_eq!(model.members_total, 2);
        assert!(
            model
                .info_message
                .as_deref()
                .is_some_and(|info| info.contains("Joined room"))
        );
        // The invite (an admission secret) is erased from the form.
        assert!(model.join_form.room_id.is_empty());
    });

    // Non-admins cannot create invites or change admins.
    view.update(cx, |model, cx| {
        model.copy_room_invite_to_clipboard(cx);
        assert!(
            model
                .toasts
                .iter()
                .any(|toast| toast.message.contains("Only room admins"))
        );
        let session = model.session.clone().expect("session");
        assert!(model.room_admin_controls_locked(&session));
        model.start_room_admin_mutation_from_input(RoomAdminMutationKind::Grant, cx);
        assert!(matches!(
            &model.room_admin_status,
            RoomAdminStatus::Error(message) if message.contains("room-admin authority")
        ));
    });

    // Alice (synced to Bob's join: a joiner cannot read older epochs) sends
    // a message; Bob's device receives it.
    server.sync(&alice);
    server
        .block_on(engine::send_text(&alice, "welcome"))
        .expect("alice sends");
    sync_now(cx, &view);
    wait_for(cx, &view, "welcome", |model| has_message(model, "welcome"));

    // Alice removes Bob; Bob's next sync resets the GUI.
    let outcome = server.sync(&alice);
    let bob_leaf = outcome
        .view
        .roster
        .iter()
        .find(|entry| entry.alias.as_deref() == Some("bob"))
        .map(|entry| entry.member)
        .expect("bob in the roster");
    server
        .block_on(engine::expel(&alice, bob_leaf))
        .expect("expel bob");
    sync_now(cx, &view);
    wait_for(cx, &view, "removal", |model| model.session.is_none());
    view.update(cx, |model, _| {
        assert_eq!(
            model.info_message.as_deref(),
            Some("This device was removed from the room.")
        );
        assert!(
            model
                .toasts
                .iter()
                .any(|toast| toast.kind == ToastKind::Error)
        );
    });
}

#[gpui::test]
fn gpui_send_after_removal_clears_the_session(cx: &mut TestAppContext) {
    let _config = ConfigDir::new();
    let server = TestServer::start();
    let alice = server.create_member("alice");
    let invite = server.invite(&alice);
    let (view, cx) = open_window(cx, None);
    join_from_form(cx, &view, &invite, "bob");
    // Keep the background sync out of the way: the send must meet the
    // removal first.
    view.update(cx, |model, _| {
        model.fetch_task = None;
        model.fetch_in_flight = true;
        model.ws_task = None;
    });

    let outcome = server.sync(&alice);
    let bob_leaf = outcome
        .view
        .roster
        .iter()
        .find(|entry| !entry.admin)
        .map(|entry| entry.member)
        .expect("bob in the roster");
    server
        .block_on(engine::expel(&alice, bob_leaf))
        .expect("expel bob");

    view.update(cx, |model, cx| {
        model.composer.focus();
        model.composer.set_text("still here?".to_string());
        model.start_send(cx);
    });
    wait_for(cx, &view, "stale session", |model| model.session.is_none());
    view.update(cx, |model, _| {
        assert!(
            model
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("no longer a member"))
        );
    });
}

#[gpui::test]
fn gpui_join_failures_are_reported(cx: &mut TestAppContext) {
    let _config = ConfigDir::new();
    let server = TestServer::start();
    let alice = server.create_member("alice");
    let invite = server.invite(&alice);
    let (view, cx) = open_window(cx, None);

    // An invite of a room the server does not know.
    let mut link = parse_join_invite(&invite).expect("parse").expect("invite");
    link.gid = [0x55; 32];
    let foreign = link.encode();
    join_from_form_expecting_error(cx, &view, &foreign);
    view.update(cx, |model, _| {
        let error = model.categorized_error.as_ref().expect("categorized error");
        assert_eq!(error.user_message, "Room not found");
        assert_eq!(model.last_retry_action, Some(RetryAction::Join));
    });

    // A server that does not answer.
    view.update(cx, |model, cx| {
        model.join_form.server = OFFLINE_URL.to_string();
        model.join_form.room_id.clear();
        model.join_form.alias = "alice".to_string();
        model.start_join(cx);
    });
    wait_for(cx, &view, "unreachable server", |model| {
        matches!(model.join_status, JoinStatus::Idle) && model.categorized_error.is_some()
    });
    view.update(cx, |model, _| {
        let error = model.categorized_error.as_ref().expect("categorized error");
        assert_eq!(error.category, ErrorCategory::Network);
        assert!(model.session.is_none());
    });
    // Retry runs the join again.
    cx.update(|window, app| {
        view.update(app, |model, cx| {
            model.on_retry_clicked(&click(), window, cx);
            assert!(matches!(model.join_status, JoinStatus::Joining));
            assert!(model.categorized_error.is_none());
        });
    });
    wait_for(cx, &view, "second failure", |model| {
        matches!(model.join_status, JoinStatus::Idle) && model.categorized_error.is_some()
    });
}

fn join_from_form_expecting_error(
    cx: &mut VisualTestContext,
    view: &Entity<AppModel>,
    invite: &str,
) {
    view.update(cx, |model, cx| {
        let link = parse_join_invite(invite).expect("parse").expect("invite");
        model
            .join_form
            .apply_invite(invite, &link)
            .expect("apply invite");
        model.join_form.alias = "mallory".to_string();
        model.start_join(cx);
    });
    wait_for(cx, view, "join failure", |model| {
        matches!(model.join_status, JoinStatus::Idle) && model.categorized_error.is_some()
    });
}
