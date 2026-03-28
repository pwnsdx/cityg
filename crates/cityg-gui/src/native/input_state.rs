use super::*;

#[derive(Clone, Default)]
pub(super) struct MessageComposer {
    pub(super) text: String,
    pub(super) active: bool,
    pub(super) editor: TextInputEditorState,
}

// Configuration constants have been moved to cityg_config
// These are kept as fallback if needed but should use config from AppModel

impl MessageComposer {
    pub(super) fn clear(&mut self) {
        self.text.clear();
        self.editor.reset();
    }

    pub(super) fn is_ready(&self) -> bool {
        !self.text.trim().is_empty()
    }

    pub(super) fn focus(&mut self) {
        self.active = true;
    }

    pub(super) fn blur(&mut self) {
        self.active = false;
    }

    #[cfg(test)]
    pub(super) fn set_text(&mut self, text: String) {
        self.text = text;
        self.editor.reset_for_text(&self.text);
    }

    #[cfg(test)]
    pub(super) fn text(&self) -> &str {
        self.text.as_str()
    }

    pub(super) fn handle_keystroke(&mut self, ks: &Keystroke) -> KeyOutcome {
        if !self.active {
            return KeyOutcome::None;
        }

        if ks.key == "escape" {
            self.blur();
            return KeyOutcome::Updated;
        }

        if ks.key == "return" || ks.key == "enter" {
            if self.is_ready() {
                return KeyOutcome::Submit;
            }
            return KeyOutcome::None;
        }

        if self.editor.has_native_input() {
            return KeyOutcome::None;
        }

        if ks.key == "backspace" {
            if !self.text.is_empty() {
                self.text.pop();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "delete" {
            if !self.text.is_empty() {
                self.text.clear();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "space" {
            self.text.push(' ');
            return KeyOutcome::Updated;
        }

        if let Some(ch) = ks.key_char.as_ref() {
            if ks.modifiers.control
                || ks.modifiers.alt
                || ks.modifiers.platform
                || ks.modifiers.function
            {
                return KeyOutcome::None;
            }
            if ch.chars().any(|c| c == '\n' || c == '\r' || c == '\t') {
                return KeyOutcome::None;
            }
            self.text.push_str(ch);
            return KeyOutcome::Updated;
        }

        KeyOutcome::None
    }
}

#[derive(Clone, Default)]
pub(super) struct MembersSearchState {
    pub(super) query: String,
    pub(super) active: bool,
    pub(super) editor: TextInputEditorState,
}

impl MembersSearchState {
    #[cfg(test)]
    pub(super) fn focus(&mut self) {
        self.active = true;
    }

    pub(super) fn blur(&mut self) {
        self.active = false;
    }

    pub(super) fn clear(&mut self) {
        self.query.clear();
        self.editor.reset();
    }

    #[cfg(test)]
    pub(super) fn set_query(&mut self, query: String) {
        self.query = query;
        self.editor.reset_for_text(&self.query);
    }

    #[cfg(test)]
    pub(super) fn query(&self) -> &str {
        self.query.as_str()
    }

    pub(super) fn handle_keystroke(&mut self, ks: &Keystroke) -> KeyOutcome {
        if !self.active {
            return KeyOutcome::None;
        }

        if ks.key == "escape" {
            self.blur();
            return KeyOutcome::Updated;
        }

        if ks.key == "tab" {
            self.blur();
            return KeyOutcome::Updated;
        }

        if ks.key == "return" || ks.key == "enter" {
            return KeyOutcome::Submit;
        }

        if self.editor.has_native_input() {
            return KeyOutcome::None;
        }

        if ks.key == "backspace" {
            if !self.query.is_empty() {
                self.query.pop();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "delete" {
            if !self.query.is_empty() {
                self.query.clear();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "space" {
            self.query.push(' ');
            return KeyOutcome::Updated;
        }

        if let Some(ch) = ks.key_char.as_ref() {
            if ks.modifiers.control
                || ks.modifiers.alt
                || ks.modifiers.platform
                || ks.modifiers.function
            {
                return KeyOutcome::None;
            }

            if ch.chars().any(|c| c == '\n' || c == '\r' || c == '\t') {
                return KeyOutcome::None;
            }

            self.query.push_str(ch);
            return KeyOutcome::Updated;
        }

        KeyOutcome::None
    }
}

#[derive(Clone, Default)]
pub(super) struct RoomAdminTargetState {
    pub(super) value: String,
    pub(super) active: bool,
    pub(super) editor: TextInputEditorState,
}

impl RoomAdminTargetState {
    pub(super) fn focus(&mut self) {
        self.active = true;
    }

    pub(super) fn blur(&mut self) {
        self.active = false;
    }

    pub(super) fn clear(&mut self) {
        self.value.clear();
        self.editor.reset();
    }

    pub(super) fn set_value(&mut self, value: String) {
        self.value = value;
        self.editor.reset_for_text(&self.value);
    }

    pub(super) fn value(&self) -> &str {
        self.value.as_str()
    }

    pub(super) fn handle_keystroke(&mut self, ks: &Keystroke) -> KeyOutcome {
        if !self.active {
            return KeyOutcome::None;
        }

        if ks.key == "escape" {
            self.blur();
            return KeyOutcome::Updated;
        }

        if ks.key == "tab" {
            self.blur();
            return KeyOutcome::Updated;
        }

        if ks.key == "return" || ks.key == "enter" {
            return KeyOutcome::Submit;
        }

        if self.editor.has_native_input() {
            return KeyOutcome::None;
        }

        if ks.key == "backspace" {
            if !self.value.is_empty() {
                self.value.pop();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "delete" {
            if !self.value.is_empty() {
                self.value.clear();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "space" {
            self.value.push(' ');
            return KeyOutcome::Updated;
        }

        if let Some(ch) = ks.key_char.as_ref() {
            if ks.modifiers.control
                || ks.modifiers.alt
                || ks.modifiers.platform
                || ks.modifiers.function
            {
                return KeyOutcome::None;
            }

            if ch.chars().any(|c| c == '\n' || c == '\r' || c == '\t') {
                return KeyOutcome::None;
            }

            self.value.push_str(ch);
            return KeyOutcome::Updated;
        }

        KeyOutcome::None
    }
}
