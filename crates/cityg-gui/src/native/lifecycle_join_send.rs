use super::*;

/// Create or join a room, then open (and persist) its session.
pub(super) async fn perform_join(request: JoinRequest) -> Result<AppSession> {
    match request {
        JoinRequest::Create { server_url, alias } => {
            let member =
                engine::create_room(&server_url, &alias, engine::DEFAULT_ROOM_N_MAX).await?;
            open_session(&server_url, &alias, member, None)
        }
        JoinRequest::Invite { link, alias } => {
            let member = engine::join_room(&link, &alias).await?;
            open_session(&link.server_url, &alias, member, None)
        }
    }
}

impl AppModel {
    pub(super) fn start_join(&mut self, cx: &mut ViewContext<Self>) {
        if matches!(self.join_status, JoinStatus::Joining) {
            return;
        }
        let request = match self.join_form.join_request() {
            Ok(request) => request,
            Err(err) => {
                self.set_error(&err, "join", None);
                cx.notify();
                return;
            }
        };

        self.reset_fetch_state();
        self.messages.clear();
        self.message_keys.clear();
        self.join_status = JoinStatus::Joining;
        self.last_error = None;
        self.info_message = Some(match &request {
            JoinRequest::Create { .. } => "Creating a new room…".to_string(),
            JoinRequest::Invite { .. } => "Joining the room…".to_string(),
        });
        self.composer.blur();
        cx.notify();

        let task = Tokio::spawn_result(cx, async move { perform_join(request).await });

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
        let Some(session) = self.session.clone() else {
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
        let pending_id = self.queue_pending_message(&session, &plaintext);

        self.composer.clear();
        self.composer.focus();

        self.send_status = SendStatus::Sending;
        self.last_error = None;
        self.info_message = None;
        cx.notify();

        let member = session.member.clone();
        let text = plaintext.clone();
        let task = Tokio::spawn_result(cx, async move { engine::send_text(&member, &text).await });

        cx.spawn(async move |this, cx| {
            let outcome = task.await;
            let _ = this.update(cx, |model, cx| {
                model.on_send_finished(outcome, pending_id, plaintext, cx);
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
            Ok(session) => {
                self.last_error = None;
                self.categorized_error = None;
                let admin = session.is_admin();
                self.install_session(session);
                self.info_message = Some(if admin && self.members_total <= 1 {
                    "Room created. Copy an invite link to bring others in.".to_string()
                } else {
                    "Joined room. Session saved locally.".to_string()
                });
                self.show_success("Successfully joined room!", cx);
                self.activity_events.clear();
                self.record_activity(ActivityKind::System, "Joined room");
                self.join_form.active = None;
                self.join_form.clear_invite_material();
                self.room_admin_status = RoomAdminStatus::Idle;
                self.room_admin_target.clear();
                self.room_admin_target.blur();
                self.clear_room_admin_revoke_confirmation();
                self.bootstrap_session_runtime(cx);
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
        result: anyhow::Result<engine::SentOutcome>,
        pending_id: u64,
        plaintext: String,
        cx: &mut ViewContext<Self>,
    ) {
        self.send_status = SendStatus::Idle;
        match result {
            Ok(sent) => {
                if let Some(session) = &self.session {
                    let entry = ChatMessageEntry {
                        sender_leaf: Some(session.leaf_id),
                        fallback_label: session.alias.clone(),
                        plaintext,
                        ciphertext_hex: sent.key,
                        timestamp_ms: sent.signed_timestamp_ms,
                        delivery: MessageDelivery::Sent,
                        pending_id: None,
                    };
                    self.confirm_pending_message(pending_id, entry);
                }
                self.persist_history();
                self.info_message = Some("Message sent.".to_string());
                self.show_success("Message sent successfully", cx);
                self.record_activity(ActivityKind::Message, "You sent a message");
            }
            Err(err) => {
                if engine::is_membership_loss(&err) {
                    self.handle_stale_server_session(
                        "This device is no longer a member of the room. Join it again with a new invite.",
                        cx,
                    );
                    return;
                }
                self.mark_pending_message_failed(pending_id);
                self.record_activity_with_detail(
                    ActivityKind::Message,
                    "Message send failed",
                    Some(format!("{err:#}")),
                );
                self.set_error(&err, "send", Some(RetryAction::Send));
            }
        }
    }
}
