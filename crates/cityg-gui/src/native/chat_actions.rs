use super::*;

impl AppModel {
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
