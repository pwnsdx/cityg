use super::*;

impl AppModel {
    pub(super) fn start_leave(&mut self, cx: &mut ViewContext<Self>) {
        if !matches!(self.leave_status, LeaveStatus::Idle) {
            return;
        }
        let Some(session) = &self.session else {
            return;
        };

        let request = LeaveRequest::from_session(session);
        self.leave_status = LeaveStatus::Leaving;
        self.last_error = None;
        self.info_message = None;
        cx.notify();

        let task = Tokio::spawn_result(cx, async move { perform_leave(request).await });

        cx.spawn(async move |this, cx| {
            let outcome = task.await;
            let _ = this.update(cx, |model, cx| {
                model.on_leave_finished(outcome, cx);
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

        let request = LeaveRequest::from_session(session);
        self.leave_status = LeaveStatus::Refreshing;
        self.last_error = None;
        self.info_message = None;
        cx.notify();

        let task = Tokio::spawn_result(cx, async move { perform_pcs_refresh(request).await });

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
        result: anyhow::Result<()>,
        cx: &mut ViewContext<Self>,
    ) {
        self.leave_status = LeaveStatus::Idle;
        match result {
            Ok(()) => {
                if let Some(session) = &self.session {
                    match load_session_at(&session.server_url, &session.room_id) {
                        Ok(Some(persisted)) => {
                            self.session = Some(persisted);
                            self.bootstrap_session_runtime(cx);
                        }
                        Ok(None) => {
                            warn!("persisted session missing after PCS refresh");
                        }
                        Err(err) => {
                            warn!("failed to reload session after PCS refresh: {err:?}");
                        }
                    }
                }

                self.clear_error();
                self.info_message =
                    Some("PCS refresh submitted. Syncing latest epoch…".to_string());
                self.show_success("PCS refresh submitted", cx);
                self.schedule_epoch_sync(cx, "Syncing latest epoch after PCS refresh…");
            }
            Err(err) => {
                self.set_error(&err, "refresh", Some(RetryAction::Refresh));
                self.info_message = None;
            }
        }
    }

    pub(super) fn on_leave_finished(
        &mut self,
        result: anyhow::Result<()>,
        cx: &mut ViewContext<Self>,
    ) {
        self.leave_status = LeaveStatus::Idle;
        match result {
            Ok(()) => {
                self.reset_fetch_state();
                self.stop_epoch_sync_task();
                self.stop_websocket();
                self.stop_members_refresh_task();
                if let Some(session) = self.session.take() {
                    if let Err(err) = remove_security_log(&session.server_url, &session.room_id) {
                        warn!("failed to remove security log: {err:?}");
                    }
                    match remove_persisted_session(&session.server_url, &session.room_id) {
                        Ok(()) => {
                            self.info_message = Some("Device left the room.".to_string());
                            self.clear_error();
                            self.show_success("Successfully left the room", cx);
                        }
                        Err(err) => {
                            let message =
                                format!("Left room, but failed to remove session data: {err}");
                            warn!("{message}");
                            self.last_error = Some(message.clone());
                            self.info_message = None;
                            self.show_error_toast(message, cx);
                        }
                    }
                } else {
                    self.info_message = Some("Device left the room.".to_string());
                    self.clear_error();
                    self.show_success("Successfully left the room", cx);
                }
                self.messages.clear();
                self.message_keys.clear();
                self.next_pending_message_id = 1;
                self.composer.clear();
                self.composer.blur();
                self.send_status = SendStatus::Idle;
                self.fetch_status = FetchStatus::Idle;
                self.members.clear();
                self.members_status = MembersStatus::Idle;
                self.members_total = 0;
                self.members_next_offset = None;
                self.members_loading_append = false;
                self.alias_bindings.clear();
                self.leaf_alias_index.clear();
                self.members_auto_page = false;
                self.members_mode = MembersMode::Full;
                self.members_search.clear();
                self.members_search.blur();
                self.members_alias_dirty = false;
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
            }
            Err(err) => {
                self.set_error(&err, "leave", Some(RetryAction::Leave));
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
        self.fetch_task = None;
        self.fetch_in_flight = false;
        self.join_status = JoinStatus::Idle;
        self.leave_status = LeaveStatus::Idle;
        self.send_status = SendStatus::Idle;
        self.fetch_status = FetchStatus::Idle;
        self.session = None;
        self.stop_websocket();
        self.stop_epoch_sync_task();
        self.stop_members_refresh_task();
        self.ws_autostart_attempted = false;
        self.restore_epoch_sync_pending = false;
        self.alias_bindings.clear();
        self.leaf_alias_index.clear();
        self.members_auto_page = false;
        self.members_alias_dirty = false;
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
