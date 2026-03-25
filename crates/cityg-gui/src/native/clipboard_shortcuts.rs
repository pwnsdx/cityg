use super::*;

impl AppModel {
    pub(super) fn handle_join_form_clipboard_shortcuts(
        &mut self,
        keystroke: &Keystroke,
        cx: &mut ViewContext<Self>,
    ) -> KeyOutcome {
        if self.join_form.active.is_none() {
            return KeyOutcome::None;
        }

        if is_primary_shortcut(keystroke, "c") {
            return self
                .copy_focused_text(cx)
                .then_some(KeyOutcome::Updated)
                .unwrap_or(KeyOutcome::None);
        }

        if is_primary_shortcut(keystroke, "x") {
            return self
                .cut_focused_text(cx)
                .then_some(KeyOutcome::Updated)
                .unwrap_or(KeyOutcome::None);
        }

        if is_primary_shortcut(keystroke, "v") {
            return self
                .paste_focused_text(cx)
                .then_some(KeyOutcome::Updated)
                .unwrap_or(KeyOutcome::None);
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
            return self
                .copy_focused_text(cx)
                .then_some(KeyOutcome::Updated)
                .unwrap_or(KeyOutcome::None);
        }

        if is_primary_shortcut(keystroke, "x") {
            return self
                .cut_focused_text(cx)
                .then_some(KeyOutcome::Updated)
                .unwrap_or(KeyOutcome::None);
        }

        if is_primary_shortcut(keystroke, "v") {
            return self
                .paste_focused_text(cx)
                .then_some(KeyOutcome::Updated)
                .unwrap_or(KeyOutcome::None);
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
            return self
                .copy_focused_text(cx)
                .then_some(KeyOutcome::Updated)
                .unwrap_or(KeyOutcome::None);
        }

        if is_primary_shortcut(keystroke, "x") {
            return self
                .cut_focused_text(cx)
                .then_some(KeyOutcome::Updated)
                .unwrap_or(KeyOutcome::None);
        }

        if is_primary_shortcut(keystroke, "v") {
            return self
                .paste_focused_text(cx)
                .then_some(KeyOutcome::Updated)
                .unwrap_or(KeyOutcome::None);
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
            return self
                .copy_focused_text(cx)
                .then_some(KeyOutcome::Updated)
                .unwrap_or(KeyOutcome::None);
        }

        if is_primary_shortcut(keystroke, "x") {
            return self
                .cut_focused_text(cx)
                .then_some(KeyOutcome::Updated)
                .unwrap_or(KeyOutcome::None);
        }

        if is_primary_shortcut(keystroke, "v") {
            return self
                .paste_focused_text(cx)
                .then_some(KeyOutcome::Updated)
                .unwrap_or(KeyOutcome::None);
        }

        KeyOutcome::None
    }

    pub(super) fn copy_focused_text(&mut self, cx: &mut ViewContext<Self>) -> bool {
        if let Some(field) = self.focused_text_field() {
            let selected =
                self.with_text_field_mut(field, |text, editor| editor.selected_text(text));
            if let Some(text) = selected {
                cx.write_to_clipboard(ClipboardItem::new_string(text));
                return true;
            }
        }

        false
    }

    pub(super) fn cut_focused_text(&mut self, cx: &mut ViewContext<Self>) -> bool {
        let Some(field) = self.focused_text_field() else {
            return false;
        };
        let selected = self.with_text_field_mut(field, |text, editor| editor.selected_text(text));
        let Some(text) = selected else {
            return false;
        };

        cx.write_to_clipboard(ClipboardItem::new_string(text));
        let updated = self.with_text_field_mut(field, |text, editor| {
            editor.replace_text_in_range(text, None, "")
        });
        if updated {
            self.after_text_field_edit(field);
            cx.notify();
            return true;
        }

        false
    }

    pub(super) fn paste_focused_text(&mut self, cx: &mut ViewContext<Self>) -> bool {
        let Some(text) = cx.read_from_clipboard().and_then(|item| item.text()) else {
            return false;
        };

        let Some(field) = self.focused_text_field() else {
            return false;
        };

        if field == NativeTextFieldKind::JoinRoom {
            match parse_join_invite(&text) {
                Ok(Some(invite)) => match self.join_form.apply_invite(invite) {
                    Ok(()) => {
                        self.clear_error();
                        self.info_message =
                            Some("Invite imported. Choose your alias and join.".to_string());
                        cx.notify();
                        return true;
                    }
                    Err(err) => {
                        self.set_error(&err, "join", Some(RetryAction::Join));
                        cx.notify();
                        return true;
                    }
                },
                Ok(None) => {}
                Err(err) => {
                    self.set_error(&err, "join", Some(RetryAction::Join));
                    cx.notify();
                    return true;
                }
            }
        }

        let sanitized = sanitize_clipboard_text(&text);
        let updated = match field {
            NativeTextFieldKind::JoinRoom if JoinFormState::is_valid_room_id(sanitized.trim()) => {
                self.with_text_field_mut(field, |text, editor| {
                    editor.replace_all(text, sanitized.trim());
                    true
                })
            }
            _ => self.with_text_field_mut(field, |text, editor| {
                editor.replace_text_in_range(text, None, &sanitized)
            }),
        };
        if updated {
            self.after_text_field_edit(field);
            cx.notify();
        }
        updated
    }
}
