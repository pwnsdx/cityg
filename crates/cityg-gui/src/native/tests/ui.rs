//! Rendering, window actions, text input and form handling.

use super::*;
use crate::native::app_actions::{
    CopyRoomIdAction, CopyRoomInviteAction, CopySelectionAction, CutSelectionAction,
    FocusComposerAction, FocusMembersSearchAction, FocusRoomAdminTargetAction, JoinRoomAction,
    LeaveRoomAction, PasteSelectionAction, RefreshRoomAction, SendMessageAction,
    ShowSessionOverviewAction, TextBackspaceAction, TextDeleteAction, TextEndAction,
    TextHomeAction, TextMoveLeftAction, TextMoveRightAction, TextSelectAllAction,
    TextSelectLeftAction, TextSelectRightAction, ToggleCiphertextAction, ToggleSidebarAction,
};

fn sample_member(leaf: u8, alias: &str, admin: bool, pending_removal: bool) -> MemberEntry {
    MemberEntry {
        leaf_id: [leaf; 32],
        alias: Some(alias.to_string()),
        pop_public_key: Some(vec![leaf; cityg_pqc::ML_DSA_87_PUBLIC_KEY_BYTES]),
        slot: u32::from(leaf),
        admin,
        pending_removal,
    }
}

fn sample_activity() -> Vec<ActivityEvent> {
    [
        ActivityKind::Connection,
        ActivityKind::Roster,
        ActivityKind::Message,
        ActivityKind::Sync,
        ActivityKind::System,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, kind)| ActivityEvent {
        kind,
        summary: format!("event {index}"),
        detail: (index % 2 == 0).then(|| "detail".to_string()),
        timestamp_ms: index as u64 + 1,
    })
    .collect()
}

/// Fill `model` with content for every panel.
fn populate(model: &mut AppModel, session: &AppSession) {
    model.messages.push(ChatMessageEntry {
        sender_leaf: Some(session.leaf_id),
        fallback_label: session.alias.clone(),
        plaintext: "mine".to_string(),
        ciphertext_hex: "k1".to_string(),
        timestamp_ms: 1,
        delivery: MessageDelivery::Sent,
        pending_id: None,
    });
    for (index, delivery) in [MessageDelivery::Pending, MessageDelivery::Failed]
        .into_iter()
        .enumerate()
    {
        model.messages.push(ChatMessageEntry {
            sender_leaf: Some([0x33; 32]),
            fallback_label: "peer".to_string(),
            plaintext: format!("peer {index}"),
            ciphertext_hex: format!("k{}", index + 2),
            timestamp_ms: 2 + index as u64,
            delivery,
            pending_id: None,
        });
    }
    model.members = vec![
        sample_member(0x11, "alice", true, false),
        sample_member(0x22, "bob", false, true),
    ];
    model.members_total = 2;
    model.security_events.push(SecurityEvent {
        alias: "bob".to_string(),
        description: "TOFU alert".to_string(),
        timestamp_ms: 11,
    });
    model.security_unread = 1;
    model.activity_events = sample_activity();
}

#[gpui::test]
fn gpui_render_every_panel_state(cx: &mut TestAppContext) {
    let _config = ConfigDir::new();
    let (view, cx) = open_window(cx, None);
    cx.refresh().expect("join screen");
    cx.run_until_parked();

    // Join screen variants: create mode, invite mode, busy, errors.
    view.update(cx, |model, _| {
        model.join_form.server = OFFLINE_URL.to_string();
        model.join_form.alias = "alice".to_string();
        model.last_error = Some("join failed".to_string());
        model.info_message = Some("info".to_string());
    });
    cx.refresh().expect("create mode");
    view.update(cx, |model, _| {
        model.join_form.room_id = "cityg-invite:{}".to_string();
        model.join_status = JoinStatus::Joining;
        model.categorized_error = Some(CategorizedError::new(
            ErrorCategory::Validation,
            "Invalid invite link",
            "detail",
            "paste it again",
            false,
        ));
    });
    cx.refresh().expect("invite mode");
    view.update(cx, |model, _| {
        model.join_form.room_id.clear();
        model.join_status = JoinStatus::Idle;
        model.clear_error();
    });

    // A session with every panel filled.
    let session = offline_session(20, "render");
    view.update(cx, |model, cx| {
        model.install_session(session.clone());
        populate(model, &session);
        model.show_ciphertext = true;
        model.ws_connected = true;
        for category in [
            ErrorCategory::Network,
            ErrorCategory::Crypto,
            ErrorCategory::Policy,
            ErrorCategory::Server,
            ErrorCategory::Validation,
        ] {
            model.categorized_error = Some(CategorizedError::new(
                category,
                "failure",
                "details",
                "retry",
                true,
            ));
            let _ = model.render_error_box(cx);
        }
        model.show_success("done", cx);
        model.show_error_toast("failed", cx);
        model.show_info("note", cx);
    });
    cx.refresh().expect("session");
    cx.run_until_parked();

    cx.update(|window, app| {
        view.update(app, |model, cx| {
            let session = model.session.clone().expect("session");
            let _ = model.render_members_panel(window, cx);
            let _ = model.render_room_admin_panel(window, &session, cx);
            let _ = model.render_security_panel(window, cx);
            let _ = model.render_activity_panel(window, cx);
            let _ = model.render_overview_panel(window, &session, cx);
            let _ = model.render_leave_controls(window, cx);
            let _ = model.render_message_composer(cx);
            let _ = model.render_message_list();

            // Busy states of the session controls and the composer.
            for status in [
                LeaveStatus::Leaving,
                LeaveStatus::Expelling,
                LeaveStatus::Refreshing,
            ] {
                model.leave_status = status;
                let _ = model.render_leave_controls(window, cx);
                let _ = model.render_members_panel(window, cx);
            }
            model.leave_status = LeaveStatus::Idle;
            model.send_status = SendStatus::Sending;
            let _ = model.render_message_composer(cx);
            model.send_status = SendStatus::Idle;
            model.composer.focus();
            model.composer.set_text("draft".to_string());
            let _ = model.render_message_composer(cx);

            // This device's removal is pending: sending is disabled.
            let leaf = session.leaf_id;
            let session = model.session.as_mut().expect("session");
            for entry in &mut session.view.roster {
                if entry.leaf_id == leaf {
                    entry.pending_removal = true;
                }
            }
            assert!(session.removal_pending());
            let _ = model.render_message_composer(cx);

            // Empty and search states of the panels.
            model.members.clear();
            model.members_mode = MembersMode::Search {
                query: "nobody".to_string(),
            };
            model.members_search.set_query("nobody".to_string());
            model.members_status = MembersStatus::Error("sync failed".to_string());
            let _ = model.render_members_panel(window, cx);
            model.members_status = MembersStatus::Loading("syncing".to_string());
            let _ = model.render_members_panel(window, cx);
            model.security_events.clear();
            let _ = model.render_security_panel(window, cx);
            model.security_panel_expanded = false;
            let _ = model.render_security_panel(window, cx);
            model.activity_events.clear();
            let _ = model.render_activity_panel(window, cx);
            model.messages.clear();
            let _ = model.render_message_list();

            // Room-admin panel: staged revoke, loading, error, locked.
            let session = model.session.clone().expect("session");
            model.room_admin_target.focus();
            model
                .room_admin_target
                .set_value(hex_encode(vec![0xAA; cityg_pqc::ML_DSA_87_PUBLIC_KEY_BYTES]));
            model.room_admin_revoke_confirmation =
                Some(vec![0xAA; cityg_pqc::ML_DSA_87_PUBLIC_KEY_BYTES]);
            let _ = model.render_room_admin_panel(window, &session, cx);
            model.room_admin_status = RoomAdminStatus::Loading("granting".to_string());
            let _ = model.render_room_admin_panel(window, &session, cx);
            model.room_admin_status = RoomAdminStatus::Error("denied".to_string());
            let _ = model.render_room_admin_panel(window, &session, cx);
            model.room_admins = vec![vec![0xBB; 8]];
            let _ = model.render_room_admin_panel(window, &session, cx);
            model.room_admins_loaded = false;
            let _ = model.render_room_admin_panel(window, &session, cx);
        });
    });
    cx.refresh().expect("edge states");
    cx.run_until_parked();

    // The same panels with an inactive window.
    cx.deactivate_window();
    cx.update(|window, app| {
        assert!(!window.is_window_active());
        view.update(app, |model, cx| {
            let session = model.session.clone().expect("session");
            let _ = model.render_join(window, cx);
            let _ = model.render_session(window, &session, cx);
            let _ = model.render_members_panel(window, cx);
            let _ = model.render_security_panel(window, cx);
            let _ = model.render_activity_panel(window, cx);
        });
    });
}

#[gpui::test]
fn gpui_render_does_not_start_background_work(cx: &mut TestAppContext) {
    let _config = ConfigDir::new();
    let (view, cx) = open_window(cx, None);
    let session = offline_session(21, "pure-render");
    cx.update_window_entity(&view, |model, window, cx| {
        model.install_session(session);
        let _ = model.render(window, cx);
        assert!(!model.fetch_in_flight);
        assert!(model.fetch_task.is_none());
        assert!(model.ws_task.is_none());
        assert!(!model.ws_autostart_attempted);
        assert!(model.maintenance_task.is_none());
        assert!(model.endpoint_mode_task.is_none());
    });
    // Bootstrapping starts them, once.
    view.update(cx, |model, cx| {
        model.bootstrap_session_runtime(cx);
        assert!(model.fetch_in_flight);
        assert!(model.ws_task.is_some());
        assert!(model.maintenance_task.is_some());
        assert!(model.endpoint_mode_task.is_some());
        model.bootstrap_session_runtime(cx);
        model.stop_websocket();
        model.stop_maintenance_task();
    });
}

#[gpui::test]
fn gpui_callbacks_copy_toggle_and_reset(cx: &mut TestAppContext) {
    let _config = ConfigDir::new();
    let session = offline_session(22, "clicks");
    let expected_room = session.room_id.clone();
    let expected_code = hex_encode(session.view.transcript_fingerprint);
    let expected_roster = hex_encode(session.view.roster_hash);
    let expected_identity = hex_encode(&session.pop_public_key);
    let (view, cx) = open_window(cx, Some(session));

    cx.update(|window, app| {
        view.update(app, |model, cx| {
            let event = click();
            model.on_copy_room_id(&event, window, cx);
            assert_eq!(
                cx.read_from_clipboard().and_then(|item| item.text()),
                Some(expected_room.clone())
            );
            model.on_copy_room_identity(&event, window, cx);
            assert_eq!(
                cx.read_from_clipboard().and_then(|item| item.text()),
                Some(expected_identity.clone())
            );
            model.on_copy_regular_fingerprint(&event, window, cx);
            assert_eq!(
                cx.read_from_clipboard().and_then(|item| item.text()),
                Some(expected_code.clone())
            );
            model.on_copy_fs_fingerprint(&event, window, cx);
            assert_eq!(
                cx.read_from_clipboard().and_then(|item| item.text()),
                Some(expected_roster.clone())
            );

            model.set_error(&anyhow!("connection refused"), "send", Some(RetryAction::Send));
            model.on_copy_error_details(&event, window, cx);
            assert!(
                cx.read_from_clipboard()
                    .and_then(|item| item.text())
                    .is_some_and(|text| text.contains("City-G Error Report"))
            );
            model.on_report_issue(&event, window, cx);
            model.on_dismiss_error(&event, window, cx);
            assert!(model.categorized_error.is_none());
            model.on_retry_clicked(&event, window, cx);

            model.on_toggle_ciphertext(&event, window, cx);
            assert!(model.show_ciphertext);
            model.record_security_event("bob", "alert", cx);
            model.security_panel_expanded = false;
            model.on_security_panel_toggle_clicked(&event, window, cx);
            assert!(model.security_panel_expanded);
            assert_eq!(model.security_unread, 0);
            model.on_security_panel_mark_read_clicked(&event, window, cx);
            model.on_activity_clear_clicked(&event, window, cx);
            assert!(model.activity_events.is_empty());
            model.on_security_log_clear_clicked(&event, window, cx);
            assert!(model.security_events.is_empty());

            model.on_members_refresh_clicked(&event, window, cx);
            assert!(matches!(model.members_status, MembersStatus::Loading(_)));
            model.on_room_admins_refresh_clicked(&event, window, cx);
            model.on_members_load_more_clicked(&event, window, cx);
            model.on_room_admin_revoke_cancel_clicked(&event, window, cx);
            model.on_room_admin_target_clear_clicked(&event, window, cx);
            model.on_composer_clicked(&event, window, cx);
            assert!(model.composer.active);

            model.on_reset_clicked(&event, window, cx);
            assert!(model.session.is_none());
            assert_eq!(
                model.info_message.as_deref(),
                Some("Session reset. Local state cleared.")
            );

            // Without a session the copy actions explain why nothing happened.
            model.toasts.clear();
            model.on_copy_room_id(&event, window, cx);
            model.on_copy_room_identity(&event, window, cx);
            model.on_copy_room_invite(&event, window, cx);
            model.on_copy_regular_fingerprint(&event, window, cx);
            model.on_copy_fs_fingerprint(&event, window, cx);
            assert_eq!(
                model
                    .toasts
                    .iter()
                    .filter(|toast| toast.message == "No active session")
                    .count(),
                5
            );
            model.on_leave_clicked(&event, window, cx);
            model.on_refresh_clicked(&event, window, cx);
            model.on_send_clicked(&event, window, cx);
            model.on_members_refresh_clicked(&event, window, cx);
            model.on_room_admins_refresh_clicked(&event, window, cx);
            assert!(matches!(model.leave_status, LeaveStatus::Idle));

            // "New room" empties the invite field (create mode).
            model.join_form.room_id = "cityg-invite:{}".to_string();
            model.on_generate_room_id(&event, window, cx);
            assert!(model.join_form.room_id.is_empty());
            assert!(
                model
                    .info_message
                    .as_deref()
                    .is_some_and(|info| info.contains("first admin"))
            );
            model.on_join_clicked(&event, window, cx);
        });
    });
    cx.run_until_parked();
}

#[gpui::test]
fn gpui_menu_actions_follow_the_session_state(cx: &mut TestAppContext) {
    let _config = ConfigDir::new();
    let (view, cx) = open_window(cx, None);

    cx.update(|window, app| {
        view.update(app, |model, cx| {
            // No session: the room actions only explain themselves.
            model.on_send_message_action(&SendMessageAction, window, cx);
            model.on_refresh_room_action(&RefreshRoomAction, window, cx);
            model.on_leave_room_action(&LeaveRoomAction, window, cx);
            model.on_copy_room_id_action(&CopyRoomIdAction, window, cx);
            model.on_copy_room_invite_action(&CopyRoomInviteAction, window, cx);
            model.on_focus_composer_action(&FocusComposerAction, window, cx);
            model.on_focus_members_search_action(&FocusMembersSearchAction, window, cx);
            model.on_focus_room_admin_target_action(&FocusRoomAdminTargetAction, window, cx);
            model.on_toggle_ciphertext_action(&ToggleCiphertextAction, window, cx);
            assert!(!model.show_ciphertext);
            assert!(
                model
                    .toasts
                    .iter()
                    .any(|toast| toast.message.contains("Join a room before sending"))
            );
            // Joining with an incomplete form reports the problem.
            model.join_form.alias.clear();
            model.on_join_room_action(&JoinRoomAction, window, cx);
            assert!(model.categorized_error.is_some());
        });
    });

    let session = offline_session(23, "menus");
    cx.update(|window, app| {
        view.update(app, |model, cx| {
            model.install_session(session);
            model.on_join_room_action(&JoinRoomAction, window, cx);
            assert!(
                model
                    .toasts
                    .iter()
                    .any(|toast| toast.message.contains("Leave the current room"))
            );
            model.on_focus_composer_action(&FocusComposerAction, window, cx);
            assert!(model.composer.active);
            model.on_focus_members_search_action(&FocusMembersSearchAction, window, cx);
            assert!(model.members_search.active);
            model.on_focus_room_admin_target_action(&FocusRoomAdminTargetAction, window, cx);
            assert!(model.room_admin_target.active);
            model.on_toggle_ciphertext_action(&ToggleCiphertextAction, window, cx);
            assert!(model.show_ciphertext);
            model.on_copy_room_id_action(&CopyRoomIdAction, window, cx);

            // Text editing actions on the focused field.
            model.room_admin_target.set_value("abcd".to_string());
            model.focus_text_field(NativeTextFieldKind::RoomAdminTarget, window, cx);
            model.on_text_select_all_action(&TextSelectAllAction, window, cx);
            model.on_copy_selection_action(&CopySelectionAction, window, cx);
            assert_eq!(
                cx.read_from_clipboard().and_then(|item| item.text()),
                Some("abcd".to_string())
            );
            model.on_cut_selection_action(&CutSelectionAction, window, cx);
            assert_eq!(model.room_admin_target.value(), "");
            model.on_paste_selection_action(&PasteSelectionAction, window, cx);
            assert_eq!(model.room_admin_target.value(), "abcd");
            model.on_text_home_action(&TextHomeAction, window, cx);
            model.on_text_select_right_action(&TextSelectRightAction, window, cx);
            model.on_text_move_right_action(&TextMoveRightAction, window, cx);
            model.on_text_select_left_action(&TextSelectLeftAction, window, cx);
            model.on_text_move_left_action(&TextMoveLeftAction, window, cx);
            model.on_text_end_action(&TextEndAction, window, cx);
            model.on_text_backspace_action(&TextBackspaceAction, window, cx);
            assert_eq!(model.room_admin_target.value(), "abc");
            model.on_text_home_action(&TextHomeAction, window, cx);
            model.on_text_delete_action(&TextDeleteAction, window, cx);
            assert_eq!(model.room_admin_target.value(), "bc");

            // The room actions run with a session (offline: they fail later).
            model.on_refresh_room_action(&RefreshRoomAction, window, cx);
            assert!(matches!(model.leave_status, LeaveStatus::Refreshing));
            model.on_leave_room_action(&LeaveRoomAction, window, cx);
            model.composer.set_text("hello".to_string());
            model.on_send_message_action(&SendMessageAction, window, cx);
            assert!(matches!(model.send_status, SendStatus::Sending));
        });
    });
    wait_for(cx, &view, "offline failures", |model| {
        matches!(model.leave_status, LeaveStatus::Idle)
            && matches!(model.send_status, SendStatus::Idle)
    });
    view.update(cx, |model, _| {
        assert!(
            model
                .messages
                .iter()
                .any(|message| message.delivery == MessageDelivery::Failed)
        );
    });
}

#[gpui::test]
fn gpui_session_overview_and_sidebar_toggle(cx: &mut TestAppContext) {
    let _config = ConfigDir::new();
    let (view, cx) = open_window(cx, Some(offline_session(24, "layout")));

    cx.update(|window, app| {
        view.update(app, |model, cx| {
            let width = f32::from(window.bounds().size.width);
            assert!(model.resolved_inspector_width(width).is_some());
            assert!(model.resolved_sidebar_width(width).is_some());
            model.on_show_session_overview_action(&ShowSessionOverviewAction, window, cx);
            model.on_toggle_sidebar_action(&ToggleSidebarAction, window, cx);
        });
    });
    cx.run_until_parked();
    cx.update(|window, app| {
        view.update(app, |model, cx| {
            let width = f32::from(window.bounds().size.width);
            assert!(model.resolved_inspector_width(width).is_none());
            assert!(model.resolved_sidebar_width(width).is_none());
            model.on_show_session_overview_action(&ShowSessionOverviewAction, window, cx);
            model.on_toggle_sidebar_action(&ToggleSidebarAction, window, cx);
        });
    });
    cx.run_until_parked();
    cx.update(|window, app| {
        view.update(app, |model, _| {
            let width = f32::from(window.bounds().size.width);
            assert!(model.resolved_inspector_width(width).is_some());
            assert!(model.resolved_sidebar_width(width).is_some());
        });
    });

    // The action reaches the view from a focused text field.
    cx.update(|window, app| {
        view.update(app, |model, cx| model.focus_members_search(window, cx));
    });
    cx.run_until_parked();
    cx.dispatch_action(ShowSessionOverviewAction);
    cx.update(|window, app| {
        view.update(app, |model, _| {
            let width = f32::from(window.bounds().size.width);
            assert!(model.resolved_inspector_width(width).is_none());
        });
    });
}

#[test]
fn global_action_handlers_forward_from_a_secondary_window() {
    let _config = ConfigDir::new();
    let mut cx = TestAppContext::single();
    cx.update(tokio_bridge::init);
    cx.update(app_actions::install_action_handlers);
    let session = offline_session(25, "menus");
    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    view.update(cx, |model, _| model.install_session(session));
    cx.refresh().expect("main window");
    cx.run_until_parked();

    let (_secondary, cx) = cx.add_window_view(|_, _| EmptyView);
    cx.update(|window, _| window.activate_window());
    cx.run_until_parked();
    cx.update(|_, app| {
        let main_active = app
            .active_window()
            .and_then(|window| window.downcast::<AppModel>())
            .is_some();
        assert!(!main_active);
        assert!(app.is_action_available(&CopyRoomIdAction));
    });
}

#[gpui::test]
fn gpui_text_field_mouse_selection(cx: &mut TestAppContext) {
    let _config = ConfigDir::new();
    let (view, cx) = open_window(cx, Some(offline_session(26, "mouse")));
    cx.update(|window, app| {
        view.update(app, |model, cx| {
            model.members_search.set_query("member-lookup".to_string());
            model.on_text_field_mouse_down(
                NativeTextFieldKind::MembersSearch,
                &mouse_down(MouseButton::Left, 2),
                window,
                cx,
            );
            let query = model.members_search.query().to_string();
            assert_eq!(model.members_search.editor.selected_range, 0..query.len());
            assert!(model.members_search.active);

            model.members_search.editor.selected_range = 0..6;
            model.on_text_field_secondary_mouse_down(
                NativeTextFieldKind::MembersSearch,
                &mouse_down(MouseButton::Right, 1),
                window,
                cx,
            );
            assert_eq!(model.members_search.editor.selected_range, 0..6);
            assert!(!model.members_search.editor.is_selecting);

            model.members_search.editor.selected_range = 3..3;
            model.focus_text_field(NativeTextFieldKind::MembersSearch, window, cx);
            model.on_text_select_all_action(&TextSelectAllAction, window, cx);
            assert_eq!(model.members_search.editor.selected_range, 0..query.len());

            model.on_members_search_field_clicked(&click(), window, cx);
            assert!(model.members_search.active);
        });
    });
}

#[gpui::test]
fn gpui_keystrokes_route_to_the_focused_input(cx: &mut TestAppContext) {
    let _config = ConfigDir::new();
    let (view, cx) = open_window(cx, None);

    // Join form: text arrives through the platform input handler of the
    // focused field.
    view.update(cx, |model, _| {
        model.join_form.server.clear();
        model.join_form.alias.clear();
    });
    cx.update(|window, app| {
        view.update(app, |model, cx| {
            model.focus_field_in_window(ActiveField::Server, window, cx);
        });
    });
    cx.run_until_parked();
    cx.simulate_input("http");
    cx.run_until_parked();

    view.update(cx, |model, cx| {
        assert_eq!(model.join_form.server, "http");
        // Tab navigation, submit, escape.
        model.focus_field(ActiveField::Server, cx);
        model.on_keystroke(&key("tab"), cx);
        assert!(matches!(model.join_form.active, Some(ActiveField::Room)));
        model.on_keystroke(&key("shift-tab"), cx);
        assert!(matches!(model.join_form.active, Some(ActiveField::Server)));
        model.on_keystroke(&key("enter"), cx);
        assert!(matches!(model.join_status, JoinStatus::Idle));
        model.on_keystroke(&key("escape"), cx);
        assert!(model.join_form.active.is_none());

        // While joining, keystrokes are ignored.
        model.join_status = JoinStatus::Joining;
        model.focus_field(ActiveField::Alias, cx);
        model.on_keystroke(&key("a->a"), cx);
        assert!(model.join_form.alias.is_empty());
        model.join_status = JoinStatus::Idle;
    });

    view.update(cx, |model, _| model.install_session(offline_session(27, "keys")));
    cx.run_until_parked();

    // Room-admin target field.
    cx.update(|window, app| {
        view.update(app, |model, cx| model.focus_room_admin_target(window, cx));
    });
    cx.run_until_parked();
    cx.simulate_input("a");
    view.update(cx, |model, cx| {
        assert_eq!(model.room_admin_target.value(), "a");
        model.on_keystroke(&key("enter"), cx);
        assert!(matches!(model.room_admin_status, RoomAdminStatus::Error(_)));
        model.on_keystroke(&key("escape"), cx);
        assert!(!model.room_admin_target.active);
    });

    // Members search field.
    cx.update(|window, app| {
        view.update(app, |model, cx| model.focus_members_search(window, cx));
    });
    cx.run_until_parked();
    cx.simulate_input("b");
    view.update(cx, |model, cx| {
        assert_eq!(model.members_search.query(), "b");
        model.on_keystroke(&key("enter"), cx);
        assert!(matches!(model.members_mode, MembersMode::Search { .. }));
        model.on_keystroke(&key("escape"), cx);
        assert!(!model.members_search.active);
    });

    // Composer: enter sends (offline, it fails in the background).
    cx.update(|window, app| {
        view.update(app, |model, cx| model.focus_composer(window, cx));
    });
    cx.run_until_parked();
    cx.simulate_input("hi");
    view.update(cx, |model, cx| {
        assert_eq!(model.composer.text(), "hi");
        model.on_keystroke(&key("enter"), cx);
        assert!(matches!(model.send_status, SendStatus::Sending));
        model.on_keystroke(&key("escape"), cx);
        assert!(!model.composer.active);
    });
    wait_for(cx, &view, "offline send", |model| {
        matches!(model.send_status, SendStatus::Idle)
    });
}

#[gpui::test]
fn gpui_clipboard_shortcuts_edit_the_focused_field(cx: &mut TestAppContext) {
    let _config = ConfigDir::new();
    let session = offline_session(28, "clip");
    let invite = format!(
        "{INVITE_PREFIX}{{\"version\":4,\"server_url\":\"https://edge.example\",\"room_id\":\"{}\",\"invite_seed\":\"{}\"}}",
        "ab".repeat(32),
        "cd".repeat(32)
    );
    let (view, cx) = open_window(cx, None);

    view.update(cx, |model, cx| {
        let paste = key("cmd-v");
        let copy = key("cmd-c");
        let cut = key("cmd-x");

        // Join form: an invite fills the server and the invite field.
        model.join_form.active = Some(ActiveField::Room);
        cx.write_to_clipboard(ClipboardItem::new_string(invite.clone()));
        assert!(matches!(
            model.handle_join_form_clipboard_shortcuts(&paste, cx),
            KeyOutcome::Updated
        ));
        assert_eq!(model.join_form.server, "https://edge.example");
        assert_eq!(model.join_form.room_id, invite);
        assert!(model.join_form.is_ready() || model.join_form.alias.trim().is_empty());

        // A malformed invite is reported.
        cx.write_to_clipboard(ClipboardItem::new_string(format!("{INVITE_PREFIX}{{bad")));
        assert!(matches!(
            model.handle_join_form_clipboard_shortcuts(&paste, cx),
            KeyOutcome::Updated
        ));
        assert!(model.categorized_error.is_some());
        model.clear_error();

        // Plain text is inserted, newlines flattened.
        model.join_form.active = Some(ActiveField::Alias);
        model.join_form.alias = "ab".to_string();
        cx.write_to_clipboard(ClipboardItem::new_string("c\nd".to_string()));
        assert!(matches!(
            model.handle_join_form_clipboard_shortcuts(&paste, cx),
            KeyOutcome::Updated
        ));
        assert!(model.join_form.alias.contains("c d"));
        assert!(matches!(
            model.handle_join_form_clipboard_shortcuts(&key("a"), cx),
            KeyOutcome::None
        ));
        model.join_form.active = None;
        assert!(matches!(
            model.handle_join_form_clipboard_shortcuts(&paste, cx),
            KeyOutcome::None
        ));

        model.install_session(session.clone());

        // Composer.
        model.composer.focus();
        model.composer.set_text("pre".to_string());
        cx.write_to_clipboard(ClipboardItem::new_string("\npost".to_string()));
        assert!(matches!(
            model.handle_composer_clipboard_shortcuts(&paste, cx),
            KeyOutcome::Updated
        ));
        assert_eq!(model.composer.text(), "pre post");
        let text = model.composer.text().to_string();
        model.composer.editor.select_all(&text);
        assert!(matches!(
            model.handle_composer_clipboard_shortcuts(&copy, cx),
            KeyOutcome::Updated
        ));
        assert!(matches!(
            model.handle_composer_clipboard_shortcuts(&cut, cx),
            KeyOutcome::Updated
        ));
        assert!(model.composer.text().is_empty());
        model.composer.blur();
        assert!(matches!(
            model.handle_composer_clipboard_shortcuts(&paste, cx),
            KeyOutcome::None
        ));

        // Members search.
        model.members_search.focus();
        model.members_search.set_query("xy".to_string());
        let query = model.members_search.query().to_string();
        model.members_search.editor.select_all(&query);
        assert!(matches!(
            model.handle_members_search_clipboard_shortcuts(&copy, cx),
            KeyOutcome::Updated
        ));
        assert!(matches!(
            model.handle_members_search_clipboard_shortcuts(&cut, cx),
            KeyOutcome::Updated
        ));
        cx.write_to_clipboard(ClipboardItem::new_string("zz".to_string()));
        assert!(matches!(
            model.handle_members_search_clipboard_shortcuts(&paste, cx),
            KeyOutcome::Updated
        ));
        model.members_search.blur();
        assert!(matches!(
            model.handle_members_search_clipboard_shortcuts(&paste, cx),
            KeyOutcome::None
        ));

        // Room-admin target.
        model.room_admin_target.focus();
        model.room_admin_target.set_value("beef".to_string());
        let value = model.room_admin_target.value().to_string();
        model.room_admin_target.editor.select_all(&value);
        assert!(matches!(
            model.handle_room_admin_target_clipboard_shortcuts(&copy, cx),
            KeyOutcome::Updated
        ));
        assert!(matches!(
            model.handle_room_admin_target_clipboard_shortcuts(&cut, cx),
            KeyOutcome::Updated
        ));
        assert!(matches!(
            model.handle_room_admin_target_clipboard_shortcuts(&paste, cx),
            KeyOutcome::Updated
        ));
        assert_eq!(model.room_admin_target.value(), "beef");
        // Nothing selected: copy and cut do nothing.
        model.room_admin_target.editor.selected_range = 0..0;
        assert!(!model.copy_focused_text(cx));
        assert!(!model.cut_focused_text(cx));
        model.room_admin_target.blur();
        assert!(matches!(
            model.handle_room_admin_target_clipboard_shortcuts(&paste, cx),
            KeyOutcome::None
        ));
        assert!(!model.paste_focused_text(cx));
    });
}

#[gpui::test]
fn gpui_members_search_filters_the_roster(cx: &mut TestAppContext) {
    let _config = ConfigDir::new();
    let session = offline_session(29, "alice");
    let leaf_prefix = hex_encode(&session.leaf_id[..2]);
    let (view, cx) = open_window(cx, Some(session));
    view.update(cx, |model, cx| {
        assert_eq!(model.members.len(), 1);
        model.members_search.set_query("ALI".to_string());
        model.submit_members_search(cx);
        assert_eq!(model.members.len(), 1);
        model.members_search.set_query("zzz".to_string());
        model.submit_members_search(cx);
        assert!(model.members.is_empty());
        model.members_search.set_query(leaf_prefix.clone());
        model.submit_members_search(cx);
        assert_eq!(model.members.len(), 1);
        model.clear_members_search(cx);
        assert!(matches!(model.members_mode, MembersMode::Full));
        assert_eq!(model.members.len(), 1);
        model.members_search.set_query(String::new());
        model.submit_members_search(cx);
        assert!(matches!(model.members_mode, MembersMode::Full));
        assert_eq!(
            model.member_label_for_leaf(&model.members[0].leaf_id).as_deref(),
            model.members[0]
                .alias
                .as_deref()
                .map(|alias| format_alias_display(alias, &model.members[0].leaf_id))
                .as_deref()
        );
    });
    cx.update(|window, app| {
        view.update(app, |model, cx| {
            model.on_members_search_button_clicked(&click(), window, cx);
            model.on_members_search_clear_clicked(&click(), window, cx);
            model.session = None;
            model.rebuild_members();
            assert!(model.members.is_empty());
            model.refresh_members(cx);
            assert!(matches!(model.members_status, MembersStatus::Idle));
        });
    });
}

#[test]
fn message_list_bookkeeping() {
    let _config = ConfigDir::new();
    let session = offline_session(30, "alice");
    let mut model = AppModel::new(CityGConfig::default());
    model.session = Some(session.clone());

    let peer = ChatMessageEntry {
        sender_leaf: Some([0x44; 32]),
        fallback_label: "peer".to_string(),
        plaintext: "later".to_string(),
        ciphertext_hex: "k2".to_string(),
        timestamp_ms: 20,
        delivery: MessageDelivery::Pending,
        pending_id: Some(9),
    };
    let early = ChatMessageEntry {
        plaintext: "earlier".to_string(),
        ciphertext_hex: "k1".to_string(),
        timestamp_ms: 10,
        ..peer.clone()
    };
    let unkeyed = ChatMessageEntry {
        ciphertext_hex: String::new(),
        ..peer.clone()
    };
    assert_eq!(
        model.append_messages(vec![peer.clone(), early, peer.clone(), unkeyed]),
        2
    );
    assert_eq!(model.messages[0].plaintext, "earlier");
    assert!(
        model
            .messages
            .iter()
            .all(|message| message.delivery == MessageDelivery::Sent && message.pending_id.is_none())
    );

    // A pending message confirmed with a key already shown is dropped.
    let pending = model.queue_pending_message(&session, "dup");
    model.confirm_pending_message(pending, peer.clone());
    assert_eq!(model.messages.len(), 2);
    // A confirmation without its placeholder is appended.
    model.confirm_pending_message(
        999,
        ChatMessageEntry {
            ciphertext_hex: "k3".to_string(),
            ..peer.clone()
        },
    );
    assert_eq!(model.messages.len(), 3);
    model.mark_pending_message_failed(12345);

    assert_eq!(model.resolve_sender_label(&peer), "peer");
    model.leaf_alias_index.insert([0x44; 32], "dora".to_string());
    assert!(model.resolve_sender_label(&peer).starts_with("dora ("));

    // Activity and security logs are bounded.
    for index in 0..(MAX_ACTIVITY_EVENTS + 5) {
        model.record_activity(ActivityKind::System, format!("event {index}"));
    }
    assert_eq!(model.activity_events.len(), MAX_ACTIVITY_EVENTS);
    model.acknowledge_security_alerts();
    model.alias_bindings.insert(
        "ghost".to_string(),
        AliasBindingRecord {
            pop_public_key: vec![1],
            leaf_id: [0; 32],
        },
    );
    model.refresh_leaf_alias_index();
    assert!(model.leaf_alias_index.is_empty());
    model.persist_history();
}

#[test]
fn toasts_and_errors() {
    let _config = ConfigDir::new();
    let mut model = AppModel::new(CityGConfig::default());
    let success = Toast::success("ok");
    assert_eq!(success.kind, ToastKind::Success);
    assert_eq!(Toast::error("err").kind, ToastKind::Error);
    assert_eq!(Toast::info("info").kind, ToastKind::Info);
    assert!(!success.is_expired());
    let mut expired = Toast::info("expired");
    expired.created_at = SystemTime::now() - Duration::from_secs(10);
    expired.duration_secs = 1;
    model.toasts.push(expired);
    model.toasts.push(success);
    model.cleanup_expired_toasts();
    assert_eq!(model.toasts.len(), 1);

    model.set_error(&anyhow!("connection reset"), "send", Some(RetryAction::Send));
    assert!(model.last_error.is_some());
    assert!(model.categorized_error.is_some());
    assert_eq!(model.last_retry_action, Some(RetryAction::Send));
    model.clear_error();
    assert!(model.last_error.is_none());
    assert!(model.categorized_error.is_none());
    assert!(model.last_retry_action.is_none());
}

#[test]
fn join_form_requests_and_keystrokes() {
    let invite = format!(
        "{INVITE_PREFIX}{{\"version\":4,\"server_url\":\"https://edge.example\",\"room_id\":\"{}\",\"invite_seed\":\"{}\"}}",
        "ab".repeat(32),
        "cd".repeat(32)
    );
    let mut form = JoinFormState {
        server: " https://edge.example ".to_string(),
        alias: " alice ".to_string(),
        active: Some(ActiveField::Server),
        ..Default::default()
    };
    match form.join_request().expect("create request") {
        JoinRequest::Create { server_url, alias } => {
            assert_eq!(server_url, "https://edge.example");
            assert_eq!(alias, "alice");
        }
        JoinRequest::Invite { .. } => panic!("expected a create request"),
    }
    form.room_id = invite.clone();
    assert!(matches!(
        form.join_request().expect("invite request"),
        JoinRequest::Invite { .. }
    ));
    form.room_id = "00".repeat(32);
    assert!(
        form.join_request()
            .expect_err("bare room ids need an invite")
            .to_string()
            .contains("invite link")
    );
    form.room_id.clear();
    form.server.clear();
    assert!(form.join_request().is_err());
    form.alias.clear();
    assert!(form.join_request().is_err());
    assert!(!form.is_ready());

    let link = parse_join_invite(&invite).expect("parse").expect("link");
    form.apply_invite(&invite, &link).expect("apply");
    assert_eq!(form.server, "https://edge.example");
    form.clear_invite_material();
    assert!(form.room_id.is_empty());
    form.room_id = "kept".to_string();
    form.clear_invite_material();
    assert_eq!(form.room_id, "kept");
    assert!(parse_join_invite("hello").expect("not an invite").is_none());
    assert!(parse_join_invite(&format!("{INVITE_PREFIX}{{}}")).is_err());

    // Keystrokes.
    form.room_id.clear();
    form.server = "https://edge.example".to_string();
    form.alias = "a".to_string();
    form.active = None;
    assert!(matches!(form.handle_keystroke(&key("x")), KeyOutcome::None));
    form.active = Some(ActiveField::Alias);
    assert!(matches!(form.handle_keystroke(&key("tab")), KeyOutcome::Updated));
    assert!(matches!(form.active, Some(ActiveField::Server)));
    assert!(matches!(form.handle_keystroke(&key("shift-tab")), KeyOutcome::Updated));
    assert!(matches!(form.active, Some(ActiveField::Alias)));
    assert_eq!(
        JoinFormState::next_field(ActiveField::Room),
        ActiveField::Alias
    );
    assert_eq!(
        JoinFormState::previous_field(ActiveField::Room),
        ActiveField::Server
    );
    assert!(matches!(form.handle_keystroke(&key("backspace")), KeyOutcome::Updated));
    assert!(matches!(form.handle_keystroke(&key("backspace")), KeyOutcome::None));
    assert!(matches!(form.handle_keystroke(&key("space")), KeyOutcome::Updated));
    assert!(matches!(form.handle_keystroke(&key("x->x")), KeyOutcome::Updated));
    assert_eq!(form.field(ActiveField::Alias), " x");
    assert!(matches!(form.handle_keystroke(&key("ctrl-a")), KeyOutcome::None));
    assert!(matches!(form.handle_keystroke(&key("enter")), KeyOutcome::Submit));
    assert!(matches!(form.handle_keystroke(&key("delete")), KeyOutcome::Updated));
    assert!(matches!(form.handle_keystroke(&key("enter")), KeyOutcome::None));
    assert!(matches!(form.handle_keystroke(&key("escape")), KeyOutcome::Updated));
    assert!(form.active.is_none());
}

#[test]
fn input_helpers() {
    assert!(is_primary_shortcut(&key("cmd-v"), "v"));
    assert!(is_primary_shortcut(&key("ctrl-c"), "c"));
    assert!(!is_primary_shortcut(&key("alt-v"), "v"));
    assert!(!is_primary_shortcut(&key("v"), "v"));
    assert_eq!(sanitize_clipboard_text("one\ntwo\tthree\r"), "one two three ");
    assert_eq!(preferred_join_form_server(""), "");
    assert_eq!(preferred_join_form_server("http://127.0.0.1:8080"), "");
    assert_eq!(
        preferred_join_form_server(" https://cityg.example.workers.dev "),
        "https://cityg.example.workers.dev"
    );

    let mut composer = MessageComposer::default();
    assert!(matches!(composer.handle_keystroke(&key("a")), KeyOutcome::None));
    composer.focus();
    assert!(matches!(composer.handle_keystroke(&key("backspace")), KeyOutcome::None));
    composer.set_text("hi".to_string());
    assert!(matches!(composer.handle_keystroke(&key("backspace")), KeyOutcome::Updated));
    assert!(matches!(composer.handle_keystroke(&key("space")), KeyOutcome::Updated));
    assert_eq!(composer.text(), "h ");
    assert!(matches!(composer.handle_keystroke(&key("delete")), KeyOutcome::Updated));
    assert!(!composer.is_ready());
    composer.set_text("ok".to_string());
    assert!(matches!(composer.handle_keystroke(&key("enter")), KeyOutcome::Submit));
    assert!(matches!(composer.handle_keystroke(&key("ctrl-a")), KeyOutcome::None));
    assert!(matches!(composer.handle_keystroke(&key("escape")), KeyOutcome::Updated));
    assert!(!composer.active);

    let mut search = MembersSearchState::default();
    assert!(matches!(search.handle_keystroke(&key("a")), KeyOutcome::None));
    search.focus();
    search.set_query("ab".to_string());
    assert!(matches!(search.handle_keystroke(&key("backspace")), KeyOutcome::Updated));
    assert!(matches!(search.handle_keystroke(&key("delete")), KeyOutcome::Updated));
    assert!(matches!(search.handle_keystroke(&key("backspace")), KeyOutcome::None));
    assert!(matches!(search.handle_keystroke(&key("enter")), KeyOutcome::Submit));
    assert!(matches!(search.handle_keystroke(&key("x->x")), KeyOutcome::Updated));
    assert!(matches!(search.handle_keystroke(&key("tab")), KeyOutcome::Updated));
    assert!(!search.active);

    let mut target = RoomAdminTargetState::default();
    assert!(matches!(target.handle_keystroke(&key("a->a")), KeyOutcome::None));
    target.focus();
    assert!(matches!(target.handle_keystroke(&key("a->a")), KeyOutcome::Updated));
    assert!(matches!(target.handle_keystroke(&key("backspace")), KeyOutcome::Updated));
    assert!(matches!(target.handle_keystroke(&key("enter")), KeyOutcome::Submit));
    assert!(matches!(target.handle_keystroke(&key("escape")), KeyOutcome::Updated));
    target.clear();
    assert!(target.value().is_empty());

    let mut editor = TextInputEditorState::default();
    let text = "double click";
    editor.selected_range = 3..3;
    assert!(editor.on_mouse_down(text, &mouse_down(MouseButton::Left, 2)));
    assert_eq!(editor.selected_range, 0..text.len());
    editor.selected_range = 0..6;
    assert!(!editor.on_secondary_mouse_down(text, &mouse_down(MouseButton::Right, 1)));
    assert_eq!(editor.selected_range, 0..6);
    editor.selected_range = 4..8;
    assert!(editor.on_secondary_mouse_down(text, &mouse_down(MouseButton::Right, 1)));
    assert_eq!(editor.selected_range, 0..0);
}

#[test]
fn layout_width_rules() {
    assert!(AppModel::available_sidebar_width_for_window(520.0).is_none());
    let compact = AppModel::available_sidebar_width_for_window(620.0).expect("compact");
    assert!((compact - 248.0).abs() < 0.5);
    let wide = AppModel::available_sidebar_width_for_window(1440.0).expect("wide");
    assert!((wide - 300.0).abs() < 0.5);

    assert!(AppModel::available_inspector_width_for_window(720.0, Some(228.0)).is_none());
    let medium =
        AppModel::available_inspector_width_for_window(1000.0, Some(228.0)).expect("medium");
    assert!((medium - 332.0).abs() < 0.5);
    let wide = AppModel::available_inspector_width_for_window(1440.0, Some(228.0)).expect("wide");
    assert!((wide - 460.0).abs() < 0.5);
}

#[test]
fn display_helpers() {
    let leaf = [0xAB; 32];
    assert_eq!(short_leaf_display(&leaf), "abababab…");
    assert!(format_alias_display("bob", &leaf).starts_with("bob ("));
    let member = sample_member(0x11, "", false, false);
    assert_eq!(format_member_label(&member), hex_encode([0x11; 32]));
    assert_eq!(format_regular_fingerprint(None), "Not available");
    assert!(format_regular_fingerprint(Some(&leaf)).starts_with("abab-abab"));
    assert_eq!(fingerprint_full_hex(&leaf).len(), 64);
    assert!(!format_timestamp(1_700_000_000_000).is_empty());
    assert!(current_unix_timestamp_ms() > 0);
    assert!(room_admin_identity_preview(&[1, 2, 3]).contains("0102"));
    assert!(decode_room_admin_target_hex("").is_err());
    assert!(decode_room_admin_target_hex("zz").is_err());
    assert!(decode_room_admin_target_hex("0102").is_err());
    let key_hex = "ab".repeat(cityg_pqc::ML_DSA_87_PUBLIC_KEY_BYTES);
    assert_eq!(
        decode_room_admin_target_hex(&format!(" {key_hex} "))
            .expect("valid key")
            .len(),
        cityg_pqc::ML_DSA_87_PUBLIC_KEY_BYTES
    );
    assert_eq!(hex_encode_prefix(&leaf, 4), "abab…");
    assert_eq!(hex_encode_prefix(&leaf, 64), hex_encode(leaf));
}

#[test]
fn app_model_defaults_without_saved_session() {
    let _config = ConfigDir::new();
    let model = AppModel::new(CityGConfig::default());
    assert!(model.session.is_none());
    assert!(model.join_form.server.is_empty());

    let mut config = CityGConfig::default();
    config.client.default_server_url = "https://cityg.example.workers.dev".to_string();
    let model = AppModel::new(config);
    assert_eq!(model.join_form.server, "https://cityg.example.workers.dev");

    // A corrupt pointer is reported, not fatal.
    let pointer = last_session_pointer_path().expect("pointer path");
    std::fs::create_dir_all(pointer.parent().expect("parent")).expect("dir");
    std::fs::write(&pointer, "{invalid-json").expect("write");
    let model = AppModel::new(CityGConfig::default());
    assert!(model.session.is_none());
    assert!(
        model
            .info_message
            .as_deref()
            .is_some_and(|info| info.contains("could not be restored"))
    );
}
