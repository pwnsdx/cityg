use super::endpoint_mode::EndpointMode;
use super::*;

impl AppModel {
    pub(super) fn prompt_member_expulsion(
        &mut self,
        target_leaf_id: [u8; 32],
        target_label: String,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if !matches!(self.leave_status, LeaveStatus::Idle) {
            return;
        }
        let Some(session) = self.session.clone() else {
            return;
        };
        if self.room_admin_controls_locked(&session) {
            let message = "This device does not currently hold room-admin authority for this room."
                .to_string();
            self.last_error = Some(message.clone());
            self.room_admin_status = RoomAdminStatus::Error(message.clone());
            self.show_error_toast(message, cx);
            return;
        }
        if session.leaf_id == target_leaf_id {
            let message =
                "Use Leave room to remove this device instead of expelling the local member."
                    .to_string();
            self.last_error = Some(message.clone());
            self.show_error_toast(message, cx);
            return;
        }

        let prompt_message = format!("Expel {target_label} from this room?");
        let prompt_detail = format!(
            "This commits a signed removal: the member's keys stop opening anything from the next epoch on.\nThey will need a new invite to come back.\n\nLeaf: {}",
            hex_encode(target_leaf_id)
        );
        let answer = window.prompt(
            PromptLevel::Critical,
            &prompt_message,
            Some(&prompt_detail),
            &["Expel", "Cancel"],
            cx,
        );
        cx.spawn(async move |this, cx| {
            let Ok(choice) = answer.await else {
                return;
            };
            if choice != 0 {
                return;
            }
            let _ = this.update(cx, |model, cx| {
                model.start_member_expulsion(target_leaf_id, cx);
                cx.notify();
            });
        })
        .detach();
    }

    pub(super) fn start_leave(&mut self, cx: &mut ViewContext<Self>) {
        if !matches!(self.leave_status, LeaveStatus::Idle) {
            return;
        }
        let Some(session) = &self.session else {
            return;
        };

        let member = session.member.clone();
        self.leave_status = LeaveStatus::Leaving;
        self.last_error = None;
        self.info_message = None;
        cx.notify();

        let task = Tokio::spawn_result(cx, async move { engine::leave_room(&member).await });

        cx.spawn(async move |this, cx| {
            let outcome = task.await;
            let _ = this.update(cx, |model, cx| {
                model.on_leave_finished(outcome, cx);
                cx.notify();
            });
        })
        .detach();
    }

    pub(super) fn start_member_expulsion(
        &mut self,
        target_leaf_id: [u8; 32],
        cx: &mut ViewContext<Self>,
    ) {
        if !matches!(self.leave_status, LeaveStatus::Idle) {
            return;
        }
        let Some(session) = self.session.clone() else {
            return;
        };
        if self.room_admin_controls_locked(&session) {
            let message = "This device does not currently hold room-admin authority for this room."
                .to_string();
            self.last_error = Some(message.clone());
            self.room_admin_status = RoomAdminStatus::Error(message.clone());
            self.show_error_toast(message, cx);
            return;
        }
        if session.leaf_id == target_leaf_id {
            let message =
                "Use Leave room to remove this device instead of expelling the local member."
                    .to_string();
            self.last_error = Some(message.clone());
            self.show_error_toast(message, cx);
            return;
        }

        self.leave_status = LeaveStatus::Expelling;
        self.last_error = None;
        self.info_message = None;
        cx.notify();

        let member = session.member.clone();
        let task =
            Tokio::spawn_result(cx, async move { engine::expel(&member, target_leaf_id).await });

        cx.spawn(async move |this, cx| {
            let outcome = task.await;
            let _ = this.update(cx, |model, cx| {
                model.on_member_expel_finished(outcome, cx);
                cx.notify();
            });
        })
        .detach();
    }

    pub(super) fn on_leave_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.start_leave(cx);
    }

    pub(super) fn on_refresh_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.start_pcs_refresh(cx);
    }

    pub(super) fn start_pcs_refresh(&mut self, cx: &mut ViewContext<Self>) {
        if !matches!(self.leave_status, LeaveStatus::Idle) {
            return;
        }
        let Some(session) = &self.session else {
            return;
        };

        let member = session.member.clone();
        self.leave_status = LeaveStatus::Refreshing;
        self.last_error = None;
        self.info_message = None;
        cx.notify();

        let task = Tokio::spawn_result(cx, async move { engine::refresh_keys(&member).await });

        cx.spawn(async move |this, cx| {
            let outcome = task.await;
            let _ = this.update(cx, |model, cx| {
                model.on_refresh_finished(outcome, cx);
                cx.notify();
            });
        })
        .detach();
    }

    pub(super) fn on_refresh_finished(
        &mut self,
        result: anyhow::Result<engine::RosterOutcome>,
        cx: &mut ViewContext<Self>,
    ) {
        self.leave_status = LeaveStatus::Idle;
        match result {
            Ok(outcome) => {
                if let Some(session) = &self.session {
                    session.mark_self_update();
                }
                self.apply_session_view(outcome.view);
                self.clear_error();
                self.info_message = Some(
                    "Keys refreshed: this device re-keyed its leaf and path in a new epoch."
                        .to_string(),
                );
                self.show_success("Keys refreshed", cx);
                self.record_activity(ActivityKind::Sync, "Refreshed this device's keys");
            }
            Err(err) => {
                self.set_error(&err, "refresh", Some(RetryAction::Refresh));
                self.info_message = None;
            }
        }
    }

    pub(super) fn on_leave_finished(
        &mut self,
        result: anyhow::Result<bool>,
        cx: &mut ViewContext<Self>,
    ) {
        self.leave_status = LeaveStatus::Idle;
        match result {
            Ok(vacant) => {
                let (info, toast) = if vacant {
                    ("Left the room. It has no member left.", "Left the room")
                } else {
                    (
                        "Leave requested. The remaining members commit your removal.",
                        "Leave request submitted",
                    )
                };
                if let Err(err) = self.reset_session_state() {
                    let message = format!("Left room, but failed to remove session data: {err}");
                    warn!("{message}");
                    self.last_error = Some(message.clone());
                    self.info_message = None;
                    self.show_error_toast(message, cx);
                } else {
                    self.info_message = Some(info.to_string());
                    self.clear_error();
                    self.show_success(toast, cx);
                }
            }
            Err(err) => {
                self.set_error(&err, "leave", Some(RetryAction::Leave));
                self.info_message = None;
            }
        }
    }

    pub(super) fn on_member_expel_finished(
        &mut self,
        result: anyhow::Result<engine::RosterOutcome>,
        cx: &mut ViewContext<Self>,
    ) {
        self.leave_status = LeaveStatus::Idle;
        match result {
            Ok(outcome) => {
                self.apply_session_view(outcome.view);
                self.clear_error();
                self.info_message = Some("Member removed from the room.".to_string());
                self.show_success("Member expelled", cx);
                self.record_activity(ActivityKind::Roster, "Removed a member");
            }
            Err(err) => {
                self.set_error(&err, "expel", None);
                self.info_message = None;
            }
        }
    }

    pub(super) fn reset_session_state(&mut self) -> Result<()> {
        let removal_result = if let Some(session) = self.session.take() {
            if let Err(err) = remove_security_log(&session.server_url, &session.room_id) {
                warn!("failed to remove security log: {err:?}");
            }
            remove_persisted_session(&session.server_url, &session.room_id)
        } else if let Some(pointer) = read_last_session_pointer()? {
            if let Err(err) = remove_security_log(&pointer.server_url, &pointer.room_id) {
                warn!("failed to remove security log: {err:?}");
            }
            remove_persisted_session(&pointer.server_url, &pointer.room_id)
        } else {
            Ok(())
        };

        self.reset_fetch_state();
        self.join_status = JoinStatus::Idle;
        self.leave_status = LeaveStatus::Idle;
        self.send_status = SendStatus::Idle;
        self.session = None;
        self.endpoint_mode = EndpointMode::Unknown;
        self.endpoint_mode_server_url = None;
        self.endpoint_mode_task = None;
        self.stop_websocket();
        self.stop_maintenance_task();
        self.ws_autostart_attempted = false;
        self.removal_commit_in_flight = false;
        self.alias_bindings.clear();
        self.leaf_alias_index.clear();
        self.members.clear();
        self.members_total = 0;
        self.members_next_offset = None;
        self.members_status = MembersStatus::Idle;
        self.members_mode = MembersMode::Full;
        self.members_search.clear();
        self.members_search.blur();
        self.room_admins.clear();
        self.room_admins_loaded = false;
        self.room_admin_status = RoomAdminStatus::Idle;
        self.room_admin_target.clear();
        self.room_admin_target.blur();
        self.clear_room_admin_revoke_confirmation();
        self.security_events.clear();
        self.security_unread = 0;
        self.security_panel_expanded = false;
        self.activity_events.clear();
        self.messages.clear();
        self.message_keys.clear();
        self.next_pending_message_id = 1;
        self.composer.clear();
        self.composer.blur();
        self.show_ciphertext = false;
        self.join_form.active = Some(ActiveField::Alias);

        removal_result
    }
}
