use super::*;

impl AppModel {
    pub(super) fn focus_composer(&mut self, window: &mut Window, cx: &mut ViewContext<Self>) {
        self.focus_text_field(NativeTextFieldKind::Composer, window, cx);
        self.last_error = None;
    }

    pub(super) fn toggle_ciphertext(&mut self, cx: &mut ViewContext<Self>) {
        self.show_ciphertext = !self.show_ciphertext;
        cx.notify();
    }

    pub(super) fn copy_room_id_to_clipboard(&mut self, cx: &mut ViewContext<Self>) {
        if let Some(session) = &self.session {
            cx.write_to_clipboard(ClipboardItem::new_string(session.room_id.clone()));
            self.show_success("Room ID copied", cx);
        } else {
            self.show_error_toast("No active session", cx);
        }
    }

    pub(super) fn copy_room_identity_to_clipboard(&mut self, cx: &mut ViewContext<Self>) {
        if let Some(session) = &self.session {
            cx.write_to_clipboard(ClipboardItem::new_string(hex_encode(
                &session.pop_public_key,
            )));
            self.show_success("Room identity copied", cx);
        } else {
            self.show_error_toast("No active session", cx);
        }
    }

    /// Create an invite link (admins only) and copy it to the clipboard.
    pub(super) fn copy_room_invite_to_clipboard(&mut self, cx: &mut ViewContext<Self>) {
        let Some(session) = self.session.clone() else {
            self.show_error_toast("No active session", cx);
            return;
        };
        if !session.is_admin() {
            self.show_error_toast("Only room admins can create invite links", cx);
            return;
        }
        let member = session.member.clone();
        let task = Tokio::spawn_result(cx, async move { engine::create_invite(&member).await });
        cx.spawn(async move |this, cx| {
            let outcome = task.await;
            let _ = this.update(cx, |model, cx| {
                match outcome {
                    Ok(link) => {
                        cx.write_to_clipboard(ClipboardItem::new_string(link));
                        model.show_success("Invite link copied (valid 7 days)", cx);
                        model.record_activity(ActivityKind::Roster, "Created an invite link");
                    }
                    Err(err) => model.show_error_toast(format!("{err:#}"), cx),
                }
                cx.notify();
            });
        })
        .detach();
    }

    #[cfg(test)]
    pub(super) fn on_composer_clicked(
        &mut self,
        _: &MouseDownEvent,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.focus_composer(window, cx);
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
        self.toggle_ciphertext(cx);
    }

    #[cfg(test)]
    pub(super) fn focus_field(&mut self, field: ActiveField, cx: &mut ViewContext<Self>) {
        self.join_form.active = Some(field);
        self.composer.blur();
        cx.notify();
    }

    pub(super) fn focus_field_in_window(
        &mut self,
        field: ActiveField,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        let field = match field {
            ActiveField::Server => NativeTextFieldKind::JoinServer,
            ActiveField::Room => NativeTextFieldKind::JoinRoom,
            ActiveField::Alias => NativeTextFieldKind::JoinAlias,
        };
        self.focus_text_field(field, window, cx);
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
            Some(RetryAction::Leave) => self.start_leave(cx),
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
            let text = fingerprint_full_hex(&session.view.transcript_fingerprint);
            cx.write_to_clipboard(ClipboardItem::new_string(text));
            self.show_success("Security code copied", cx);
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
            let text = fingerprint_full_hex(&session.view.roster_hash);
            cx.write_to_clipboard(ClipboardItem::new_string(text));
            self.show_success("Roster hash copied", cx);
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
        self.copy_room_id_to_clipboard(cx);
    }

    pub(super) fn on_copy_room_identity(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.copy_room_identity_to_clipboard(cx);
    }

    pub(super) fn on_copy_room_invite(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.copy_room_invite_to_clipboard(cx);
    }
}
