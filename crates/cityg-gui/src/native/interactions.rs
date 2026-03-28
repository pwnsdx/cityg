use super::*;

impl AppModel {
    pub(super) fn on_report_issue(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if let Some(error) = &self.categorized_error {
            let report = format!(
                "City-G Error Report\n\
                 ==================\n\n\
                 Category: {:?}\n\
                 Error: {}\n\n\
                 Technical Details:\n\
                 {}\n\n\
                 Recovery Suggestion:\n\
                 {}\n\n\
                 To report this issue:\n\
                 1. Visit: https://github.com/pwnsdx/cityg/issues/new\n\
                 2. Copy the error details above\n\
                 3. Paste them into the issue description",
                error.category,
                error.user_message,
                error.technical_details,
                error.recovery_suggestion
            );

            warn!(
                "===== ERROR REPORT =====\n{}\n========================",
                report
            );
            self.show_info(
                "Error report logged to console - visit GitHub to submit issue",
                cx,
            );
        }
    }

    pub(super) fn on_dismiss_error(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.clear_error();
        cx.notify();
    }

    pub(super) fn on_generate_room_id(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.join_form.room_id = AppModel::random_room_id();
        self.join_form
            .room_editor
            .reset_for_text(&self.join_form.room_id);
        self.join_form.clear_invite_material();
        self.join_form.active = Some(ActiveField::Room);
        self.last_error = None;
        self.info_message = Some("Generated a new room identifier.".to_string());
        cx.notify();
    }

    pub(super) fn on_reset_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        match self.reset_session_state() {
            Ok(()) => {
                self.info_message = Some("Session reset. Local state cleared.".to_string());
                self.last_error = None;
            }
            Err(err) => {
                self.last_error = Some(format!("Failed to reset session: {err}"));
                self.info_message = None;
            }
        }
        cx.notify();
    }

    pub(super) fn handle_stale_server_session(&mut self, reason: &str, cx: &mut ViewContext<Self>) {
        warn!("stale server session detected: {reason}");
        if let Err(err) = self.reset_session_state() {
            warn!("failed to clear stale session state: {err:?}");
        }
        self.last_error = Some(reason.to_string());
        self.info_message = Some(
            "Saved session cleared because server state changed. Rejoin the room to continue."
                .to_string(),
        );
        self.show_error_toast("Session expired on server. Join room again.", cx);
        cx.notify();
    }

    pub(super) fn on_room_admins_refresh_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.refresh_room_admins(cx);
    }

    pub(super) fn on_room_admin_grant_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.start_room_admin_mutation_from_input(RoomAdminMutationKind::Grant, cx);
    }

    pub(super) fn on_room_admin_revoke_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.start_room_admin_mutation_from_input(RoomAdminMutationKind::Revoke, cx);
    }

    pub(super) fn on_room_admin_revoke_cancel_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.clear_room_admin_revoke_confirmation();
        self.room_admin_status = RoomAdminStatus::Idle;
        cx.notify();
    }

    pub(super) fn on_room_admin_target_clear_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.clear_room_admin_target(cx);
    }

    pub(super) fn on_security_log_clear_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.security_events.clear();
        self.persist_security_events_to_disk();
        self.security_unread = 0;
        self.security_panel_expanded = false;
        cx.notify();
    }

    pub(super) fn on_activity_clear_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.activity_events.clear();
        cx.notify();
    }

    pub(super) fn on_security_panel_toggle_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.security_panel_expanded = !self.security_panel_expanded;
        if self.security_panel_expanded {
            self.acknowledge_security_alerts();
        }
        cx.notify();
    }

    pub(super) fn on_security_panel_mark_read_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.acknowledge_security_alerts();
        cx.notify();
    }

    #[cfg(test)]
    pub(super) fn on_keystroke(&mut self, keystroke: &Keystroke, cx: &mut ViewContext<Self>) {
        self.on_keystroke_inner(keystroke, None, cx);
    }

    #[cfg(not(test))]
    pub(super) fn on_window_keystroke(
        &mut self,
        keystroke: &Keystroke,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.on_keystroke_inner(keystroke, Some(window), cx);
    }

    fn on_keystroke_inner(
        &mut self,
        keystroke: &Keystroke,
        mut window: Option<&mut Window>,
        cx: &mut ViewContext<Self>,
    ) {
        if self.session.is_some() {
            if self.room_admin_target.active {
                match self.handle_room_admin_target_clipboard_shortcuts(keystroke, cx) {
                    KeyOutcome::None => {}
                    KeyOutcome::Updated => {
                        cx.notify();
                        return;
                    }
                    KeyOutcome::Submit => {}
                }
                match self.room_admin_target.handle_keystroke(keystroke) {
                    KeyOutcome::None => {}
                    KeyOutcome::Updated => {
                        self.clear_room_admin_revoke_confirmation();
                        if self.room_admin_target.active {
                            cx.notify();
                        } else if let Some(window) = window.as_deref_mut() {
                            self.blur_native_text_input(window, cx);
                        } else {
                            cx.notify();
                        }
                    }
                    KeyOutcome::Submit => {
                        self.start_room_admin_mutation_from_input(RoomAdminMutationKind::Grant, cx)
                    }
                }
                return;
            }
            if self.members_search.active {
                match self.handle_members_search_clipboard_shortcuts(keystroke, cx) {
                    KeyOutcome::None => {}
                    KeyOutcome::Updated => {
                        cx.notify();
                        return;
                    }
                    KeyOutcome::Submit => {}
                }
                match self.members_search.handle_keystroke(keystroke) {
                    KeyOutcome::None => {}
                    KeyOutcome::Updated => {
                        if self.members_search.active {
                            cx.notify();
                        } else if let Some(window) = window.as_deref_mut() {
                            self.blur_native_text_input(window, cx);
                        } else {
                            cx.notify();
                        }
                    }
                    KeyOutcome::Submit => self.submit_members_search(cx),
                }
                return;
            }
            match self.handle_composer_clipboard_shortcuts(keystroke, cx) {
                KeyOutcome::None => {}
                KeyOutcome::Updated => {
                    cx.notify();
                    return;
                }
                KeyOutcome::Submit => {}
            }
            match self.composer.handle_keystroke(keystroke) {
                KeyOutcome::None => {}
                KeyOutcome::Updated => {
                    if self.composer.active {
                        cx.notify();
                    } else if let Some(window) = window.as_deref_mut() {
                        self.blur_native_text_input(window, cx);
                    } else {
                        cx.notify();
                    }
                }
                KeyOutcome::Submit => self.start_send(cx),
            }
            return;
        }
        if matches!(self.join_status, JoinStatus::Joining) {
            return;
        }

        match self.handle_join_form_clipboard_shortcuts(keystroke, cx) {
            KeyOutcome::None => {}
            KeyOutcome::Updated => {
                cx.notify();
                return;
            }
            KeyOutcome::Submit => {}
        }

        match self.join_form.handle_keystroke(keystroke) {
            KeyOutcome::None => {}
            KeyOutcome::Updated => {
                if let Some(window) = window {
                    if let Some(active) = self.join_form.active {
                        self.focus_field_in_window(active, window, cx);
                    } else {
                        self.blur_native_text_input(window, cx);
                    }
                } else {
                    cx.notify();
                }
            }
            KeyOutcome::Submit => self.start_join(cx),
        }
    }
}
