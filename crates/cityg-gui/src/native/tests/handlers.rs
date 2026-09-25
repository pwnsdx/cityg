//! Completion handlers of the background operations, driven with offline
//! sessions and synthetic outcomes.

use anyhow::anyhow;
use cityg_api_client::ClientError;
use cityg_api_client::cityg_proto::{ApiError, ErrorCode};

use super::*;
use crate::native::session_runtime::{MaintenanceAction, maintenance_action};
use crate::native::websocket::WebSocketEvent;

fn api_error(code: ErrorCode, message: &str) -> anyhow::Error {
    anyhow::Error::from(ClientError::Api(ApiError::new(code, message))).context("request failed")
}

fn roster_entry(leaf: u8, alias: &str, admin: bool) -> RosterEntry {
    RosterEntry {
        member: mref(leaf),
        device_public_key: vec![leaf; 16],
        admin,
        alias: Some(alias.to_string()),
        pending_removal: false,
    }
}

#[gpui::test]
fn gpui_sync_results_update_messages_roster_and_security(cx: &mut TestAppContext) {
    let _config = ConfigDir::new();
    let session = offline_session(1, "alice");
    let room = session.room_id.clone();
    let device = session.pop_public_key.clone();
    let (view, cx) = open_window(cx, Some(session));

    view.update(cx, |model, cx| {
        let mut sync_view = model.session.as_ref().expect("session").view.clone();
        sync_view.epoch += 1;
        sync_view.roster.push(roster_entry(7, "bob", false));
        let mut aliases = BTreeMap::new();
        aliases.insert(mref(7), "bob".to_string());
        let outcome = engine::SyncOutcome {
            messages: vec![engine::IncomingMessage {
                sender: mref(7),
                text: "hi".to_string(),
                signed_timestamp_ms: 42,
                epoch: 2,
                generation: 0,
            }],
            changes: vec![
                engine::RosterChange::Joined(mref(7)),
                engine::RosterChange::Removed(mref(8)),
                engine::RosterChange::Resynced(mref(7)),
                engine::RosterChange::LeaveRequested(mref(7)),
                engine::RosterChange::KeyRotated(mref(7)),
                engine::RosterChange::AdminsChanged,
            ],
            rejected: 2,
            removed: false,
            resynced: true,
            view: sync_view,
            aliases,
        };
        model.fetch_in_flight = true;
        model.handle_sync_result(Ok(outcome), &room, &device, cx);

        assert_eq!(model.members_total, 2);
        assert_eq!(model.messages.len(), 1);
        assert_eq!(model.messages[0].plaintext, "hi");
        assert_eq!(
            model.info_message.as_deref(),
            Some("Received 1 new message(s).")
        );
        for summary in [
            "Joined: bob",
            "Removed: ",
            "Resynced: bob",
            "Leave requested: bob",
            "Device key rotated: bob",
            "Room admins changed",
            "Rejected messages",
            "Moved to a new epoch",
            "Received 1 new message(s)",
        ] {
            assert!(
                model
                    .activity_events
                    .iter()
                    .any(|event| event.summary.contains(summary)),
                "missing activity {summary}"
            );
        }
        // Resyncing is a security-relevant event.
        assert_eq!(model.security_events.len(), 1);
        assert!(model.security_events[0].description.contains("resync"));
        assert_eq!(
            model.member_alias_index.get(&mref(7)).map(String::as_str),
            Some("bob")
        );
        assert!(
            model
                .alias_bindings
                .get("bob")
                .is_some_and(|binding| binding.member == Some(mref(7)))
        );
        assert!(matches!(model.fetch_status, FetchStatus::Idle));

        // The same message again is not duplicated.
        let again = engine::SyncOutcome {
            messages: vec![engine::IncomingMessage {
                sender: mref(7),
                text: "hi".to_string(),
                signed_timestamp_ms: 42,
                epoch: 2,
                generation: 0,
            }],
            view: model.session.as_ref().expect("session").view.clone(),
            ..engine::SyncOutcome::default()
        };
        model.handle_sync_result(Ok(again), &room, &device, cx);
        assert_eq!(model.messages.len(), 1);

        // A different key claiming Bob's alias raises a TOFU alert.
        let mut hijack_view = model.session.as_ref().expect("session").view.clone();
        hijack_view.roster.push(RosterEntry {
            member: mref(9),
            device_public_key: vec![9; 16],
            admin: false,
            alias: None,
            pending_removal: false,
        });
        let mut aliases = BTreeMap::new();
        aliases.insert(mref(9), "bob".to_string());
        let hijack = engine::SyncOutcome {
            view: hijack_view,
            aliases,
            ..engine::SyncOutcome::default()
        };
        model.handle_sync_result(Ok(hijack), &room, &device, cx);
        let alerts = |model: &AppModel| {
            model
                .security_events
                .iter()
                .filter(|event| event.description.contains("TOFU alert"))
                .count()
        };
        assert_eq!(alerts(model), 1);

        // A new key on the same occupancy is a rotation its old key signed:
        // no alert.
        let mut rotated_view = model.session.as_ref().expect("session").view.clone();
        for entry in &mut rotated_view.roster {
            if entry.member == mref(9) {
                entry.device_public_key = vec![10; 16];
            }
        }
        let mut aliases = BTreeMap::new();
        aliases.insert(mref(9), "bob".to_string());
        let rotated = engine::SyncOutcome {
            view: rotated_view,
            aliases,
            ..engine::SyncOutcome::default()
        };
        model.handle_sync_result(Ok(rotated), &room, &device, cx);
        assert_eq!(alerts(model), 1);
        assert!(
            model
                .alias_bindings
                .get("bob")
                .is_some_and(|binding| binding.pop_public_key == vec![10; 16])
        );
    });

    // History and alias bindings were written to disk.
    let session_url = OFFLINE_URL;
    assert_eq!(load_history(session_url, &room).expect("history").len(), 1);
    assert!(
        load_alias_bindings(session_url, &room)
            .expect("aliases")
            .contains_key("bob")
    );
    assert_eq!(load_security_log(session_url, &room).expect("log").len(), 2);
}

#[gpui::test]
fn gpui_sync_errors_and_stale_results(cx: &mut TestAppContext) {
    let _config = ConfigDir::new();
    let session = offline_session(2, "alice");
    let room = session.room_id.clone();
    let device = session.pop_public_key.clone();
    let (view, cx) = open_window(cx, Some(session.clone()));

    view.update(cx, |model, cx| {
        // A result for another session is ignored.
        model.fetch_status = FetchStatus::Refreshing;
        model.handle_sync_result(Ok(engine::SyncOutcome::default()), "other", &device, cx);
        assert!(matches!(model.fetch_status, FetchStatus::Idle));
        assert!(model.session.is_some());

        // A transient failure is reported and retried.
        model.members_status = MembersStatus::Loading("Syncing the roster…".to_string());
        model.fetch_in_flight = true;
        model.handle_sync_result(Err(anyhow!("connection reset")), &room, &device, cx);
        assert!(
            model
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("Failed to sync the room"))
        );
        assert!(matches!(model.members_status, MembersStatus::Error(_)));
        assert!(
            model
                .activity_events
                .iter()
                .any(|event| event.summary == "Room sync failed")
        );

        // Losing the membership clears the session.
        model.handle_sync_result(
            Err(api_error(ErrorCode::Forbidden, "not a member")),
            &room,
            &device,
            cx,
        );
        assert!(model.session.is_none());
        assert!(
            model
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("no longer a member"))
        );
    });

    // A sync that saw this device's removal clears the session too.
    view.update(cx, |model, cx| {
        model.install_session(session.clone());
        let removed = engine::SyncOutcome {
            removed: true,
            ..engine::SyncOutcome::default()
        };
        model.handle_sync_result(Ok(removed), &room, &device, cx);
        assert!(model.session.is_none());
        assert_eq!(
            model.info_message.as_deref(),
            Some("This device was removed from the room.")
        );

        // Without a session, the fetch loop stays idle.
        model.fetch_in_flight = true;
        model.fetch_status = FetchStatus::Refreshing;
        model.ensure_fetch_loop(cx);
        assert!(!model.fetch_in_flight);
        assert!(matches!(model.fetch_status, FetchStatus::Idle));
        model.schedule_fetch(cx, Duration::ZERO);
        assert!(model.fetch_task.is_none());
    });
}

#[gpui::test]
fn gpui_fetch_scheduling_coalesces_requests(cx: &mut TestAppContext) {
    let _config = ConfigDir::new();
    let (view, cx) = open_window(cx, Some(offline_session(3, "alice")));
    view.update(cx, |model, cx| {
        model.schedule_fetch(cx, Duration::ZERO);
        assert!(model.fetch_in_flight);
        assert!(model.fetch_task.is_some());
        assert!(matches!(model.fetch_status, FetchStatus::Refreshing));
        // A second immediate request is remembered, not run concurrently.
        model.schedule_fetch(cx, Duration::ZERO);
        assert!(model.sync_again);
        model.schedule_fetch(cx, Duration::from_secs(5));
        model.ensure_fetch_loop(cx);
        model.reset_fetch_state();
        assert!(!model.fetch_in_flight);
        assert!(!model.sync_again);
        model.ensure_fetch_loop(cx);
        assert!(model.fetch_in_flight);
    });
    // The offline server fails the sync; the failure is recorded.
    wait_for(cx, &view, "failed sync", |model| {
        model
            .activity_events
            .iter()
            .any(|event| event.summary == "Room sync failed")
    });
}

#[gpui::test]
fn gpui_send_join_and_membership_completions(cx: &mut TestAppContext) {
    let _config = ConfigDir::new();
    let session = offline_session(4, "alice");
    let (view, cx) = open_window(cx, Some(session.clone()));

    view.update(cx, |model, cx| {
        // Sending: the pending entry is replaced by the confirmed one.
        let pending = model.queue_pending_message(&session, "first");
        model.on_send_finished(
            Ok(engine::SentOutcome {
                key: "k1".to_string(),
                signed_timestamp_ms: 10,
                seq: 3,
            }),
            pending,
            "first".to_string(),
            cx,
        );
        assert_eq!(model.messages.len(), 1);
        assert_eq!(model.messages[0].delivery, MessageDelivery::Sent);
        assert_eq!(model.info_message.as_deref(), Some("Message sent."));

        // A failed send keeps the text, marked failed, with a retry.
        let pending = model.queue_pending_message(&session, "second");
        model.on_send_finished(Err(anyhow!("timed out")), pending, "second".to_string(), cx);
        assert!(
            model
                .messages
                .iter()
                .any(|message| message.plaintext == "second"
                    && message.delivery == MessageDelivery::Failed)
        );
        assert_eq!(model.last_retry_action, Some(RetryAction::Send));

        // Refresh, expel and admin completions.
        let view_after = model.session.as_ref().expect("session").view.clone();
        model.leave_status = LeaveStatus::Refreshing;
        model.on_refresh_finished(
            Ok(engine::RosterOutcome {
                view: view_after.clone(),
            }),
            cx,
        );
        assert!(matches!(model.leave_status, LeaveStatus::Idle));
        assert!(
            model
                .info_message
                .as_deref()
                .is_some_and(|info| info.starts_with("Keys refreshed"))
        );
        model.on_refresh_finished(Err(anyhow!("boom")), cx);
        assert_eq!(model.last_retry_action, Some(RetryAction::Refresh));

        model.on_member_expel_finished(
            Ok(engine::RosterOutcome {
                view: view_after.clone(),
            }),
            cx,
        );
        assert_eq!(
            model.info_message.as_deref(),
            Some("Member removed from the room.")
        );
        model.on_member_expel_finished(Err(anyhow!("boom")), cx);
        assert!(model.categorized_error.is_some());

        model.on_room_admin_mutation_finished(
            RoomAdminMutationKind::Grant,
            Ok(engine::RosterOutcome {
                view: view_after.clone(),
            }),
            cx,
        );
        assert!(
            model
                .info_message
                .as_deref()
                .is_some_and(|info| info.starts_with("Room admin granted"))
        );
        model.on_room_admin_mutation_finished(
            RoomAdminMutationKind::Revoke,
            Err(api_error(ErrorCode::Forbidden, "not an admin")),
            cx,
        );
        assert!(matches!(
            &model.room_admin_status,
            RoomAdminStatus::Error(message) if message == "Room admin rights required"
        ));

        // A failed join keeps the form with a retry.
        model.on_join_finished(Err(anyhow!("invalid invite link")), cx);
        assert_eq!(model.last_retry_action, Some(RetryAction::Join));

        // A requested leave (other members commit it) clears the session.
        model.on_leave_finished(Err(anyhow!("boom")), cx);
        assert_eq!(model.last_retry_action, Some(RetryAction::Leave));
        assert!(model.session.is_some());
        model.on_leave_finished(Ok(()), cx);
        assert!(model.session.is_none());
        assert_eq!(
            model.info_message.as_deref(),
            Some("Leave requested. The remaining members commit your removal.")
        );

        // A send failing with a lost membership clears the session.
        model.install_session(session.clone());
        let pending = model.queue_pending_message(&session, "third");
        model.on_send_finished(
            Err(api_error(ErrorCode::NotFound, "unknown group")),
            pending,
            "third".to_string(),
            cx,
        );
        assert!(model.session.is_none());
    });
}

#[gpui::test]
fn gpui_leave_cleanup_failure_is_surfaced(cx: &mut TestAppContext) {
    let _config = ConfigDir::new();
    let session = offline_session(5, "alice");
    let blocking = session_file_path(&session.server_url, &session.room_id).expect("path");
    std::fs::create_dir_all(&blocking).expect("block the session file");
    let (view, cx) = open_window(cx, Some(session));
    view.update(cx, |model, cx| {
        model.on_leave_finished(Ok(()), cx);
        assert!(
            model
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("failed to remove session data"))
        );
    });
}

#[gpui::test]
fn gpui_admin_guards_and_revoke_confirmation(cx: &mut TestAppContext) {
    let _config = ConfigDir::new();
    let session = offline_session(6, "alice");
    let (view, cx) = open_window(cx, Some(session.clone()));
    let first = vec![0x44; cityg_pqc::PUBLIC_KEY_BYTES];
    let second = vec![0x55; cityg_pqc::PUBLIC_KEY_BYTES];

    view.update(cx, |model, cx| {
        // Invalid targets are rejected before any request.
        model.room_admin_target.set_value("zz".to_string());
        model.start_room_admin_mutation_from_input(RoomAdminMutationKind::Grant, cx);
        assert!(matches!(model.room_admin_status, RoomAdminStatus::Error(_)));

        // Revoking needs a second click on the same target.
        model.set_room_admin_target(first.clone(), cx);
        model.start_room_admin_mutation_from_input(RoomAdminMutationKind::Revoke, cx);
        assert_eq!(model.room_admin_revoke_confirmation.as_ref(), Some(&first));
        assert!(model.room_admin_revoke_is_staged_for_input());
        assert!(
            model
                .info_message
                .as_deref()
                .is_some_and(|info| info.contains("Revoke staged"))
        );
        // Changing the target cancels the staged revoke.
        model.set_room_admin_target(second.clone(), cx);
        assert!(model.room_admin_revoke_confirmation.is_none());
        assert!(!model.room_admin_revoke_is_staged_for_input());
        model.start_room_admin_mutation_from_input(RoomAdminMutationKind::Revoke, cx);
        model.clear_room_admin_target(cx);
        assert!(model.room_admin_revoke_confirmation.is_none());
        assert!(model.room_admin_target.value().is_empty());

        // The request itself fails offline and is reported.
        model.room_admin_status = RoomAdminStatus::Idle;
        model.start_room_admin_mutation(RoomAdminMutationKind::Grant, second.clone(), cx);
        assert!(matches!(
            model.room_admin_status,
            RoomAdminStatus::Loading(_)
        ));
        // A second mutation while one runs is ignored.
        model.start_room_admin_mutation(RoomAdminMutationKind::Grant, second.clone(), cx);

        // A device without admin rights is locked out of admin actions.
        let mut other = session.pop_public_key.clone();
        other[0] ^= 0xFF;
        model.room_admins = vec![other];
        model.room_admins_loaded = true;
        let locked = model.session.clone().expect("session");
        assert!(model.room_admin_controls_locked(&locked));
        model.start_room_admin_mutation_from_input(RoomAdminMutationKind::Grant, cx);
        assert!(matches!(
            &model.room_admin_status,
            RoomAdminStatus::Error(message) if message.contains("room-admin authority")
        ));
        model.leave_status = LeaveStatus::Idle;
        model.start_member_expulsion(mref(0x11), cx);
        assert!(matches!(model.leave_status, LeaveStatus::Idle));

        // Expelling this device is refused (leave instead).
        model.room_admins = vec![session.pop_public_key.clone()];
        model.start_member_expulsion(session.me(), cx);
        assert!(matches!(model.leave_status, LeaveStatus::Idle));
        assert!(
            model
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("Use Leave room"))
        );
    });
    cx.update(|window, app| {
        view.update(app, |model, cx| {
            // The same guards apply to the confirmation prompt.
            model.prompt_member_expulsion(session.me(), "me".to_string(), window, cx);
            let mut other = session.pop_public_key.clone();
            other[0] ^= 0xFF;
            model.room_admins = vec![other];
            model.prompt_member_expulsion(mref(0x11), "bob".to_string(), window, cx);
            assert!(matches!(model.room_admin_status, RoomAdminStatus::Error(_)));
            model.room_admins = vec![session.pop_public_key.clone()];
            model.prompt_member_expulsion(mref(0x11), "bob".to_string(), window, cx);
            model.leave_status = LeaveStatus::Leaving;
            model.prompt_member_expulsion(mref(0x11), "bob".to_string(), window, cx);
            model.leave_status = LeaveStatus::Idle;
        });
    });
    // Declining the prompt does nothing; accepting it runs the removal,
    // which fails for a device that is not a member.
    assert!(cx.has_pending_prompt());
    cx.simulate_prompt_answer("Cancel");
    cx.run_until_parked();
    view.update(cx, |model, _| {
        assert!(matches!(model.leave_status, LeaveStatus::Idle));
        model.categorized_error = None;
    });
    cx.update(|window, app| {
        view.update(app, |model, cx| {
            model.prompt_member_expulsion(mref(0x11), "bob".to_string(), window, cx);
        });
    });
    cx.simulate_prompt_answer("Expel");
    wait_for(cx, &view, "expel failure", |model| {
        matches!(model.leave_status, LeaveStatus::Idle) && model.categorized_error.is_some()
    });
    view.update(cx, |model, _| {
        assert!(
            model
                .categorized_error
                .as_ref()
                .is_some_and(|error| error.technical_details.contains("no longer a member"))
        );
    });
}

#[gpui::test]
fn gpui_websocket_events_drive_syncs(cx: &mut TestAppContext) {
    let _config = ConfigDir::new();
    let (view, cx) = open_window(cx, Some(offline_session(7, "alice")));
    view.update(cx, |model, cx| {
        model.handle_websocket_event(WebSocketEvent::Connected, cx);
        assert!(model.ws_connected);
        assert!(model.fetch_in_flight);
        model.reset_fetch_state();

        // A head the device already has does not trigger a sync.
        let seq = model.session.as_ref().expect("session").view.log_seq;
        model.handle_websocket_event(WebSocketEvent::Head(seq), cx);
        assert!(!model.fetch_in_flight);
        model.handle_websocket_event(WebSocketEvent::Head(seq + 1), cx);
        assert!(model.fetch_in_flight);
        model.reset_fetch_state();

        model.handle_websocket_event(WebSocketEvent::Resync, cx);
        assert!(model.fetch_in_flight);
        model.handle_websocket_event(WebSocketEvent::Disconnected, cx);
        assert!(!model.ws_connected);
        for summary in [
            "WebSocket connected",
            "WebSocket disconnected",
            "Live updates lagged",
        ] {
            assert!(
                model
                    .activity_events
                    .iter()
                    .any(|event| event.summary.contains(summary))
            );
        }

        // The socket task starts once per session and stops with it.
        model.ensure_websocket_task(cx);
        assert!(model.ws_task.is_some());
        model.ensure_websocket_task(cx);
        model.stop_websocket();
        assert!(model.ws_task.is_none());
        model.session = None;
        model.ensure_websocket_task(cx);
        assert!(!model.ws_autostart_attempted);
        model.start_websocket(cx);
        assert!(model.ws_task.is_none());
    });
}

#[test]
fn websocket_notices_parse() {
    use crate::native::websocket::parse_notice;
    assert_eq!(
        parse_notice(r#"{"type":"head","head_seq":7}"#),
        Some(WebSocketEvent::Head(7))
    );
    assert_eq!(
        parse_notice(r#"{"type":"resync"}"#),
        Some(WebSocketEvent::Resync)
    );
    assert_eq!(parse_notice(r#"{"type":"head"}"#), None);
    assert_eq!(parse_notice(r#"{"type":"other"}"#), None);
    assert_eq!(parse_notice("not json"), None);
}

#[test]
fn maintenance_picks_the_next_action() {
    let mut session = offline_session(8, "alice");
    let now = engine::now_ms();
    session
        .self_update_clock
        .store(now, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(maintenance_action(&session, now), None);

    // Keys older than the FS/PCS window are refreshed.
    assert_eq!(
        maintenance_action(&session, now + engine::SELF_UPDATE_INTERVAL_MS),
        Some(MaintenanceAction::RefreshKeys)
    );

    // Recorded removals of others are committed first.
    session.view.pending_removals = 1;
    session.view.roster.push(RosterEntry {
        pending_removal: true,
        ..roster_entry(9, "carol", false)
    });
    assert_eq!(
        maintenance_action(&session, now),
        Some(MaintenanceAction::CommitPending)
    );
    // Recorded join requests alone are committed too.
    session.view.pending_removals = 0;
    session.view.pending_joins = 2;
    assert_eq!(
        maintenance_action(&session, now),
        Some(MaintenanceAction::CommitPending)
    );

    // A device whose own removal is pending does neither (audit C-03).
    let me = session.me();
    for entry in &mut session.view.roster {
        if entry.member == me {
            entry.pending_removal = true;
        }
    }
    assert!(session.removal_pending());
    assert_eq!(
        maintenance_action(&session, now + engine::SELF_UPDATE_INTERVAL_MS),
        None
    );

    // Previous-epoch keys are erased after the grace window.
    session.view.has_previous_epoch_keys = true;
    session.epoch_started_ms = now;
    assert_eq!(maintenance_action(&session, now + 1), None);
    assert_eq!(
        maintenance_action(&session, now + 10 * 60 * 1000),
        Some(MaintenanceAction::ExpireGrace)
    );
}

#[gpui::test]
fn gpui_maintenance_runs_and_reports(cx: &mut TestAppContext) {
    let _config = ConfigDir::new();
    let session = offline_session(10, "alice");
    let (view, cx) = open_window(cx, Some(session));

    view.update(cx, |model, cx| {
        let current = model.session.as_ref().expect("session").view.clone();
        model.on_maintenance_finished(
            MaintenanceAction::CommitPending,
            Ok(Some(current.clone())),
            cx,
        );
        assert!(
            model
                .activity_events
                .iter()
                .any(|event| event.summary == "Committed the pending leave and join requests")
        );
        model.on_maintenance_finished(MaintenanceAction::CommitPending, Ok(None), cx);
        model.on_maintenance_finished(MaintenanceAction::RefreshKeys, Ok(Some(current)), cx);
        assert!(
            model
                .activity_events
                .iter()
                .any(|event| event.summary == "Refreshed this device's keys")
        );
        model
            .session
            .as_mut()
            .expect("session")
            .view
            .has_previous_epoch_keys = true;
        model.on_maintenance_finished(MaintenanceAction::ExpireGrace, Ok(None), cx);
        assert!(
            !model
                .session
                .as_ref()
                .expect("session")
                .view
                .has_previous_epoch_keys
        );
        model.on_maintenance_finished(MaintenanceAction::RefreshKeys, Err(anyhow!("boom")), cx);
        assert!(model.fetch_in_flight);
        model.reset_fetch_state();

        // A due key refresh runs in the background; offline, it fails.
        model
            .session
            .as_ref()
            .expect("session")
            .self_update_clock
            .store(0, std::sync::atomic::Ordering::SeqCst);
        model.run_maintenance(cx);
        assert!(model.removal_commit_in_flight);
        // Only one maintenance operation runs at a time.
        model.run_maintenance(cx);

        // The maintenance loop follows the session.
        model.ensure_maintenance_task(cx);
        assert!(model.maintenance_task.is_some());
        model.stop_maintenance_task();
        assert!(model.maintenance_task.is_none());
    });
    wait_for(cx, &view, "maintenance failure", |model| {
        !model.removal_commit_in_flight
    });

    // An expired grace window is cleared locally, without the network.
    view.update(cx, |model, cx| {
        let session = model.session.as_mut().expect("session");
        session
            .self_update_clock
            .store(engine::now_ms(), std::sync::atomic::Ordering::SeqCst);
        session.view.has_previous_epoch_keys = true;
        session.epoch_started_ms = 0;
        model.run_maintenance(cx);
    });
    wait_for(cx, &view, "grace expiry", |model| {
        !model.removal_commit_in_flight
            && model
                .session
                .as_ref()
                .is_some_and(|session| !session.view.has_previous_epoch_keys)
    });

    view.update(cx, |model, cx| {
        model.session = None;
        model.ensure_maintenance_task(cx);
        assert!(model.maintenance_task.is_none());
        model.run_maintenance(cx);
    });
}
