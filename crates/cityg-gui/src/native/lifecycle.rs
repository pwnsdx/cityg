use super::*;

impl AppModel {
    pub(super) fn start_join(&mut self, cx: &mut ViewContext<Self>) {
        if matches!(self.join_status, JoinStatus::Joining) {
            return;
        }
        if !self.join_form.is_ready() {
            return;
        }

        self.reset_fetch_state();
        self.messages.clear();
        self.message_keys.clear();
        self.join_status = JoinStatus::Joining;
        self.last_error = None;
        self.info_message = None;
        self.composer.blur();
        cx.notify();

        let params = self.join_form.join_params();

        let task = Tokio::spawn_result(cx, async move { perform_join(params).await });

        cx.spawn(async move |this, cx| {
            let outcome = task.await;
            let _ = this.update(cx, |model, cx| {
                model.on_join_finished(outcome, cx);
                cx.notify();
            });
        })
        .detach();
    }

    pub(super) fn start_send(&mut self, cx: &mut ViewContext<Self>) {
        let Some(session_snapshot) = self.session.clone() else {
            return;
        };
        if !self.composer.is_ready() {
            return;
        }
        if matches!(self.send_status, SendStatus::Sending) {
            return;
        }

        let plaintext = self.composer.text.trim().to_string();
        if plaintext.is_empty() {
            return;
        }
        let msg_index: u64 = rng().random();
        let params = match SendParams::from_session(&session_snapshot, plaintext.clone(), msg_index)
        {
            Ok(params) => params,
            Err(err) => {
                if session_snapshot.barrier_state.barrier_recovery_pending {
                    self.info_message = Some(Self::barrier_recovery_wait_message().to_string());
                    self.record_activity_with_detail(
                        ActivityKind::Message,
                        "Message send blocked",
                        Some(err.to_string()),
                    );
                    cx.notify();
                    return;
                }
                self.record_activity_with_detail(
                    ActivityKind::Message,
                    "Message send skipped",
                    Some(err.to_string()),
                );
                self.set_error(&err, "send", Some(RetryAction::Send));
                return;
            }
        };
        let pending_id = self.queue_pending_message(&session_snapshot, &plaintext);

        self.composer.clear();
        self.composer.focus();

        self.send_status = SendStatus::Sending;
        self.last_error = None;
        self.info_message = None;
        cx.notify();

        let task = Tokio::spawn_result(cx, async move { perform_send(params).await });

        cx.spawn(async move |this, cx| {
            let outcome = task.await;
            let _ = this.update(cx, |model, cx| {
                model.on_send_finished(outcome, pending_id, cx);
            });
        })
        .detach();
    }

    pub(super) fn on_join_finished(
        &mut self,
        result: anyhow::Result<AppSession>,
        cx: &mut ViewContext<Self>,
    ) {
        self.join_status = JoinStatus::Idle;
        self.leave_status = LeaveStatus::Idle;
        match result {
            Ok(mut session) => {
                session.last_fetch_timestamp_ms = None;
                let barrier_pending = session.barrier_state.barrier_recovery_pending;
                if let Err(err) = persist_session(&session) {
                    warn!("joined room but failed to persist session: {err:?}");
                    self.last_error =
                        Some(format!("Joined room, but failed to save session: {err}"));
                    self.info_message = None;
                    self.show_error_toast("Joined room, but failed to save session", cx);
                } else {
                    self.last_error = None;
                    self.categorized_error = None;
                    self.info_message = Some(if barrier_pending {
                        Self::barrier_recovery_wait_message().to_string()
                    } else {
                        "Joined room. Session saved locally.".to_string()
                    });
                    self.show_success("Successfully joined room!", cx);
                }
                self.session = Some(session);
                self.hydrate_alias_bindings_from_disk();
                self.load_security_events_from_disk();
                self.activity_events.clear();
                self.record_activity(ActivityKind::System, "Joined room");
                self.messages.clear();
                self.message_keys.clear();
                self.next_pending_message_id = 1;
                self.composer.clear();
                self.composer.blur();
                self.send_status = SendStatus::Idle;
                self.join_form.active = None;
                self.room_admins.clear();
                self.room_admins_loaded = false;
                self.room_admin_status = RoomAdminStatus::Idle;
                self.room_admin_target.clear();
                self.room_admin_target.blur();
                self.clear_room_admin_revoke_confirmation();
                self.ws_autostart_attempted = false;
                self.restore_epoch_sync_pending = false;
                self.reset_fetch_state();
                if !barrier_pending {
                    self.schedule_fetch(cx, Duration::from_millis(0));
                }
                self.refresh_members(cx);
                self.refresh_room_admins(cx);
                self.start_websocket(cx);
                self.schedule_epoch_sync(cx, "Syncing latest epoch after join…");
            }
            Err(err) => {
                self.set_error(&err, "join", Some(RetryAction::Join));
                self.info_message = None;
                self.reset_fetch_state();
            }
        }
    }

    pub(super) fn on_leave_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if !matches!(self.leave_status, LeaveStatus::Idle) {
            return;
        }
        let session = match &self.session {
            Some(session) => session,
            None => return,
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

    pub(super) fn on_send_finished(
        &mut self,
        result: anyhow::Result<ChatMessageEntry>,
        pending_id: u64,
        cx: &mut ViewContext<Self>,
    ) {
        self.send_status = SendStatus::Idle;
        match result {
            Ok(entry) => {
                let ts = entry.timestamp_ms;
                self.confirm_pending_message(pending_id, entry);
                self.info_message = Some("Message sent.".to_string());
                self.show_success("Message sent successfully", cx);
                self.record_activity(ActivityKind::Message, "You sent a message");

                if let Some(session) = self.session.as_mut() {
                    let needs_update = session
                        .last_fetch_timestamp_ms
                        .map(|prev| ts > prev)
                        .unwrap_or(true);
                    if needs_update {
                        session.last_fetch_timestamp_ms = Some(ts);
                        if let Err(err) = persist_session(session) {
                            warn!("failed to persist session after send: {err:?}");
                        }
                    }
                }

                if !self.fetch_in_flight {
                    self.schedule_fetch(cx, Duration::from_millis(500));
                }
            }
            Err(err) => {
                if is_stale_server_session_error(&err) {
                    self.handle_stale_server_session(
                        "Saved session is no longer recognized by the server. Please join again.",
                        cx,
                    );
                    return;
                }
                self.mark_pending_message_failed(pending_id);
                self.record_activity_with_detail(
                    ActivityKind::Message,
                    "Message send failed",
                    Some(err.to_string()),
                );
                self.set_error(&err, "send", Some(RetryAction::Send));
            }
        }
    }
}
