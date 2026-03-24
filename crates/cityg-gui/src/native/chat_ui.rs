use super::*;

impl AppModel {
    pub(super) fn render_message_panel(
        &self,
        _session: &AppSession,
        cx: &mut ViewContext<Self>,
    ) -> Div {
        div()
            .flex()
            .flex_col()
            .flex_grow()
            .min_h(px(0.0))
            .h_full()
            .gap(px(14.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .rounded(px(14.0))
            .px(px(16.0))
            .py(px(14.0))
            .bg(rgb(UI_PANEL_BG))
            .child(self.render_message_list())
            .child(self.render_message_composer(cx))
    }

    pub(super) fn render_message_list(&self) -> impl IntoElement {
        let mut list = div()
            .flex()
            .flex_col()
            .flex_grow()
            .min_h(px(0.0))
            .gap(px(8.0))
            .px(px(2.0))
            .py(px(2.0))
            .id("chat-message-list")
            .track_scroll(&self.chat_scroll_handle);
        list = list.overflow_y_scroll().block_mouse_except_scroll();

        if self.messages.is_empty() {
            let empty_text = if self.barrier_recovery_pending() {
                "Joined room. Waiting for barrier recovery before messages can be sent or decrypted."
            } else {
                "No messages yet. Send one to warm up this room."
            };
            return list.child(
                div()
                    .text_size(px(13.0))
                    .text_color(rgb(UI_MUTED_TEXT))
                    .child(empty_text),
            );
        }

        for message in &self.messages {
            let timestamp =
                format_rfc3339_seconds(UNIX_EPOCH + Duration::from_millis(message.timestamp_ms));
            let sender = self.resolve_sender_label(message);
            let (card_bg, card_border, body_color, meta_color, status_line) = match message.delivery
            {
                MessageDelivery::Pending => (
                    rgb(0x1d293b),
                    rgb(0x2d4057),
                    rgb(0xe1e7ff),
                    rgb(0xa2b2d6),
                    Some(("sending...", rgb(UI_ACCENT_TEXT))),
                ),
                MessageDelivery::Failed => (
                    rgb(0x32212c),
                    rgb(0x563342),
                    rgb(0xffd7e3),
                    rgb(0xffafc3),
                    Some(("failed to send", rgb(0xff8ca7))),
                ),
                MessageDelivery::Sent => (
                    rgb(0x171f31),
                    rgb(0x243149),
                    rgb(0xf2f5ff),
                    rgb(0x9eabd2),
                    None,
                ),
            };
            let mut entry = div()
                .flex()
                .flex_col()
                .gap(px(4.0))
                .bg(card_bg)
                .rounded(px(11.0))
                .border(px(1.0))
                .border_color(card_border)
                .px(px(12.0))
                .py(px(10.0))
                .child(
                    div()
                        .flex()
                        .justify_between()
                        .text_size(px(12.0))
                        .text_color(rgb(UI_SUBTLE_TEXT))
                        .child(format!("{} • {}", sender, timestamp)),
                )
                .child(
                    div()
                        .text_size(px(14.0))
                        .text_color(body_color)
                        .child(message.plaintext.clone()),
                )
                .child(div().text_size(px(11.0)).text_color(meta_color).child(
                    if self.show_ciphertext {
                        format!("ciphertext: {}", message.ciphertext_hex)
                    } else {
                        "ciphertext hidden".to_string()
                    },
                ));

            if let Some((label, color)) = status_line {
                entry = entry.child(div().text_size(px(11.0)).text_color(color).child(label));
            }

            list = list.child(entry);
        }

        list
    }

    pub(super) fn on_composer_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.join_form.active = None;
        self.members_search.blur();
        self.room_admin_target.blur();
        self.composer.focus();
        self.last_error = None;
        cx.notify();
    }

    pub(super) fn on_send_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.start_send(cx);
    }

    pub(super) fn on_toggle_ciphertext(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.show_ciphertext = !self.show_ciphertext;
        cx.notify();
    }

    pub(super) fn focus_field(&mut self, field: ActiveField, cx: &mut ViewContext<Self>) {
        self.join_form.active = Some(field);
        self.composer.blur();
        cx.notify();
    }

    pub(super) fn on_join_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.start_join(cx);
    }

    pub(super) fn on_retry_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        match self.last_retry_action {
            Some(RetryAction::Join) => self.start_join(cx),
            Some(RetryAction::Send) => self.start_send(cx),
            Some(RetryAction::Leave) => {
                if let Some(session) = &self.session {
                    let request = LeaveRequest::from_session(session);
                    self.leave_status = LeaveStatus::Leaving;
                    self.clear_error();
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
            }
            Some(RetryAction::Refresh) => self.start_pcs_refresh(cx),
            None => {}
        }
        self.clear_error();
        cx.notify();
    }

    pub(super) fn on_copy_error_details(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if let Some(error) = &self.categorized_error {
            let details = format!(
                "City-G Error Report\n\
                 ==================\n\n\
                 Category: {:?}\n\
                 Error: {}\n\n\
                 Technical Details:\n\
                 {}\n\n\
                 Recovery Suggestion:\n\
                 {}",
                error.category,
                error.user_message,
                error.technical_details,
                error.recovery_suggestion
            );

            cx.write_to_clipboard(ClipboardItem::new_string(details.clone()));
            info!("Error details copied to logs:\n{}", details);
            warn!("Error Report:\n{}", details);
            self.show_success("Error details copied to clipboard", cx);
        }
    }

    pub(super) fn on_copy_regular_fingerprint(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if let Some(session) = &self.session {
            if let Some(bytes) = session.regular_fingerprint {
                let text = fingerprint_full_hex(&bytes);
                cx.write_to_clipboard(ClipboardItem::new_string(text.clone()));
                self.show_success("Regular fingerprint copied", cx);
            } else {
                self.show_error_toast("Regular fingerprint unavailable", cx);
            }
        } else {
            self.show_error_toast("No active session", cx);
        }
    }

    pub(super) fn on_copy_fs_fingerprint(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if let Some(session) = &self.session {
            if let Some(bytes) = session.fs_fingerprint {
                let text = fingerprint_full_hex(&bytes);
                cx.write_to_clipboard(ClipboardItem::new_string(text.clone()));
                self.show_success("FS fingerprint copied", cx);
            } else {
                self.show_error_toast("FS fingerprint unavailable", cx);
            }
        } else {
            self.show_error_toast("No active session", cx);
        }
    }

    pub(super) fn on_copy_room_id(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if let Some(session) = &self.session {
            cx.write_to_clipboard(ClipboardItem::new_string(session.room_id.clone()));
            self.show_success("Room ID copied", cx);
        } else {
            self.show_error_toast("No active session", cx);
        }
    }

    pub(super) fn on_copy_room_identity(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if let Some(session) = &self.session {
            cx.write_to_clipboard(ClipboardItem::new_string(hex_encode(
                &session.pop_public_key,
            )));
            self.show_success("Room identity copied", cx);
        } else {
            self.show_error_toast("No active session", cx);
        }
    }

    pub(super) fn on_copy_room_invite(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if let Some(session) = &self.session {
            match build_join_invite(session) {
                Ok(invite) => {
                    cx.write_to_clipboard(ClipboardItem::new_string(invite));
                    self.show_success("Room invite copied", cx);
                }
                Err(err) => self.show_error_toast(err.to_string(), cx),
            }
        } else {
            self.show_error_toast("No active session", cx);
        }
    }
}
