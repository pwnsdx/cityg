use super::*;

impl AppModel {
    pub(super) fn handle_join_form_clipboard_shortcuts(
        &mut self,
        keystroke: &Keystroke,
        cx: &mut ViewContext<Self>,
    ) -> KeyOutcome {
        let Some(active) = self.join_form.active else {
            return KeyOutcome::None;
        };

        if is_primary_shortcut(keystroke, "c") {
            let text = self.join_form.field(active).to_string();
            cx.write_to_clipboard(ClipboardItem::new_string(text));
            return KeyOutcome::Updated;
        }

        if is_primary_shortcut(keystroke, "x") {
            let text = self.join_form.field(active).to_string();
            cx.write_to_clipboard(ClipboardItem::new_string(text));
            self.join_form.field_mut(active).clear();
            return KeyOutcome::Updated;
        }

        if is_primary_shortcut(keystroke, "v") {
            if let Some(text) = cx.read_from_clipboard().and_then(|item| item.text()) {
                if active == ActiveField::Room {
                    match parse_join_invite(&text) {
                        Ok(Some(invite)) => match self.join_form.apply_invite(invite) {
                            Ok(()) => {
                                self.clear_error();
                                self.info_message = Some(
                                    "Invite imported. Choose your alias and join.".to_string(),
                                );
                                return KeyOutcome::Updated;
                            }
                            Err(err) => {
                                self.set_error(&err, "join", Some(RetryAction::Join));
                                return KeyOutcome::Updated;
                            }
                        },
                        Ok(None) => {}
                        Err(err) => {
                            self.set_error(&err, "join", Some(RetryAction::Join));
                            return KeyOutcome::Updated;
                        }
                    }
                }

                let existing = self.join_form.field(active).to_string();
                let updated = apply_join_field_paste(active, &existing, &text);
                if matches!(active, ActiveField::Server | ActiveField::Room) {
                    self.join_form.clear_invite_material();
                }
                *self.join_form.field_mut(active) = updated;
            }
            return KeyOutcome::Updated;
        }

        KeyOutcome::None
    }

    pub(super) fn handle_composer_clipboard_shortcuts(
        &mut self,
        keystroke: &Keystroke,
        cx: &mut ViewContext<Self>,
    ) -> KeyOutcome {
        if !self.composer.active {
            return KeyOutcome::None;
        }

        if is_primary_shortcut(keystroke, "c") {
            cx.write_to_clipboard(ClipboardItem::new_string(self.composer.text().to_string()));
            return KeyOutcome::Updated;
        }

        if is_primary_shortcut(keystroke, "x") {
            cx.write_to_clipboard(ClipboardItem::new_string(self.composer.text().to_string()));
            self.composer.clear();
            return KeyOutcome::Updated;
        }

        if is_primary_shortcut(keystroke, "v") {
            if let Some(text) = cx.read_from_clipboard().and_then(|item| item.text()) {
                let mut updated = self.composer.text().to_string();
                updated.push_str(&sanitize_clipboard_text(&text));
                self.composer.set_text(updated);
            }
            return KeyOutcome::Updated;
        }

        KeyOutcome::None
    }

    pub(super) fn handle_members_search_clipboard_shortcuts(
        &mut self,
        keystroke: &Keystroke,
        cx: &mut ViewContext<Self>,
    ) -> KeyOutcome {
        if !self.members_search.active {
            return KeyOutcome::None;
        }

        if is_primary_shortcut(keystroke, "c") {
            cx.write_to_clipboard(ClipboardItem::new_string(
                self.members_search.query().to_string(),
            ));
            return KeyOutcome::Updated;
        }

        if is_primary_shortcut(keystroke, "x") {
            cx.write_to_clipboard(ClipboardItem::new_string(
                self.members_search.query().to_string(),
            ));
            self.members_search.clear();
            return KeyOutcome::Updated;
        }

        if is_primary_shortcut(keystroke, "v") {
            if let Some(text) = cx.read_from_clipboard().and_then(|item| item.text()) {
                let mut updated = self.members_search.query().to_string();
                updated.push_str(&sanitize_clipboard_text(&text));
                self.members_search.set_query(updated);
            }
            return KeyOutcome::Updated;
        }

        KeyOutcome::None
    }

    pub(super) fn handle_room_admin_target_clipboard_shortcuts(
        &mut self,
        keystroke: &Keystroke,
        cx: &mut ViewContext<Self>,
    ) -> KeyOutcome {
        if !self.room_admin_target.active {
            return KeyOutcome::None;
        }

        if is_primary_shortcut(keystroke, "c") {
            cx.write_to_clipboard(ClipboardItem::new_string(
                self.room_admin_target.value().to_string(),
            ));
            return KeyOutcome::Updated;
        }

        if is_primary_shortcut(keystroke, "x") {
            cx.write_to_clipboard(ClipboardItem::new_string(
                self.room_admin_target.value().to_string(),
            ));
            self.room_admin_target.clear();
            self.clear_room_admin_revoke_confirmation();
            return KeyOutcome::Updated;
        }

        if is_primary_shortcut(keystroke, "v") {
            if let Some(text) = cx.read_from_clipboard().and_then(|item| item.text()) {
                let mut updated = self.room_admin_target.value().to_string();
                updated.push_str(&sanitize_clipboard_text(&text));
                self.room_admin_target.set_value(updated);
                self.clear_room_admin_revoke_confirmation();
            }
            return KeyOutcome::Updated;
        }

        KeyOutcome::None
    }
}
