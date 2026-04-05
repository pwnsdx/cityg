use super::*;
use rand::{RngExt, rng};

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
                    self.info_message = Some(Self::barrier_recovery_message_for_session(
                        &session_snapshot,
                    ));
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
                        Self::barrier_recovery_message_for_session(&session)
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
                self.bootstrap_session_runtime(cx);
                self.refresh_members(cx);
                self.schedule_epoch_sync(cx, "Syncing latest epoch after join…");
            }
            Err(err) => {
                self.set_error(&err, "join", Some(RetryAction::Join));
                self.info_message = None;
                self.reset_fetch_state();
            }
        }
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
                        if let Err(err) = persist_replay_progress(
                            &session.server_url,
                            &session.room_id,
                            session.last_fetch_timestamp_ms,
                            &session.msg_replay_state,
                        ) {
                            warn!("failed to persist replay progress after send: {err:?}");
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
