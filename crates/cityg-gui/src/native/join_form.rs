use super::*;

#[derive(Clone, Default)]
pub(super) struct JoinFormState {
    pub(super) server: String,
    pub(super) room_id: String,
    pub(super) alias: String,
    pub(super) active: Option<ActiveField>,
    pub(super) server_editor: TextInputEditorState,
    pub(super) room_editor: TextInputEditorState,
    pub(super) alias_editor: TextInputEditorState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct JoinInvitePayload {
    pub(super) version: u8,
    pub(super) server_url: String,
    pub(super) room_id: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ActiveField {
    Server,
    Room,
    Alias,
}

pub(super) enum KeyOutcome {
    None,
    Updated,
    Submit,
}

const LEGACY_STANDALONE_DEFAULT_SERVER_URL: &str = "http://127.0.0.1:8080";

pub(super) fn is_primary_shortcut(keystroke: &Keystroke, key: &str) -> bool {
    if keystroke.modifiers.alt || keystroke.modifiers.function {
        return false;
    }
    if !(keystroke.modifiers.platform || keystroke.modifiers.control) {
        return false;
    }
    keystroke.key.eq_ignore_ascii_case(key)
}

pub(super) fn sanitize_clipboard_text(raw: &str) -> String {
    raw.chars()
        .map(|c| match c {
            '\r' | '\n' | '\t' => ' ',
            _ => c,
        })
        .collect()
}

pub(super) fn preferred_join_form_server(default_server_url: &str) -> String {
    let trimmed = default_server_url.trim();
    if trimmed.is_empty() || trimmed == LEGACY_STANDALONE_DEFAULT_SERVER_URL {
        return String::new();
    }
    trimmed.to_string()
}

pub(super) fn build_join_invite(session: &AppSession) -> Result<String> {
    let payload = JoinInvitePayload {
        version: 3,
        server_url: session.server_url.clone(),
        room_id: session.room_id.clone(),
    };
    let encoded = serde_json::to_string(&payload).context("failed to encode room invite")?;
    Ok(format!("{JOIN_INVITE_PREFIX}{encoded}"))
}

pub(super) fn parse_join_invite(raw: &str) -> Result<Option<JoinInvitePayload>> {
    let trimmed = raw.trim();
    let Some(payload) = trimmed.strip_prefix(JOIN_INVITE_PREFIX) else {
        return Ok(None);
    };

    let invite: JoinInvitePayload =
        serde_json::from_str(payload).context("invalid City-G invite payload")?;
    if invite.version != 1 && invite.version != 2 && invite.version != 3 {
        return Err(anyhow!(
            "unsupported City-G invite version {}",
            invite.version
        ));
    }
    if invite.server_url.trim().is_empty() {
        return Err(anyhow!(
            "invite worker edge or compatible endpoint URL is missing"
        ));
    }
    if !JoinFormState::is_valid_room_id(invite.room_id.trim()) {
        return Err(anyhow!("invite room ID is not valid"));
    }
    Ok(Some(invite))
}

#[cfg(test)]
pub(super) fn apply_join_field_paste(field: ActiveField, existing: &str, pasted: &str) -> String {
    let sanitized = sanitize_clipboard_text(pasted);
    if field == ActiveField::Room {
        let trimmed = sanitized.trim();
        if JoinFormState::is_valid_room_id(trimmed) {
            return trimmed.to_string();
        }
    }

    let mut updated = existing.to_string();
    updated.push_str(&sanitized);
    updated
}

impl JoinFormState {
    pub(super) fn apply_invite(&mut self, invite: JoinInvitePayload) -> Result<()> {
        self.server = invite.server_url;
        self.room_id = invite.room_id;
        self.server_editor.reset_for_text(&self.server);
        self.room_editor.reset_for_text(&self.room_id);
        Ok(())
    }

    pub(super) fn clear_invite_material(&mut self) {}

    pub(super) fn is_ready(&self) -> bool {
        let server = self.server.trim();
        let room = self.room_id.trim();
        let alias = self.alias.trim();

        !server.is_empty() && !alias.is_empty() && Self::is_valid_room_id(room)
    }

    pub(super) fn is_valid_room_id(room: &str) -> bool {
        room.len() == 64 && room.chars().all(|c| c.is_ascii_hexdigit())
    }

    pub(super) fn field_mut(&mut self, field: ActiveField) -> &mut String {
        match field {
            ActiveField::Server => &mut self.server,
            ActiveField::Room => &mut self.room_id,
            ActiveField::Alias => &mut self.alias,
        }
    }

    #[cfg(test)]
    pub(super) fn field(&self, field: ActiveField) -> &str {
        match field {
            ActiveField::Server => self.server.as_str(),
            ActiveField::Room => self.room_id.as_str(),
            ActiveField::Alias => self.alias.as_str(),
        }
    }

    pub(super) fn next_field(field: ActiveField) -> ActiveField {
        match field {
            ActiveField::Server => ActiveField::Room,
            ActiveField::Room => ActiveField::Alias,
            ActiveField::Alias => ActiveField::Server,
        }
    }

    pub(super) fn previous_field(field: ActiveField) -> ActiveField {
        match field {
            ActiveField::Server => ActiveField::Alias,
            ActiveField::Room => ActiveField::Server,
            ActiveField::Alias => ActiveField::Room,
        }
    }

    pub(super) fn handle_keystroke(&mut self, ks: &Keystroke) -> KeyOutcome {
        let Some(active) = self.active else {
            return KeyOutcome::None;
        };

        if ks.key == "tab" {
            let new_field = if ks.modifiers.shift {
                Self::previous_field(active)
            } else {
                Self::next_field(active)
            };
            if self.active != Some(new_field) {
                self.active = Some(new_field);
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "escape" {
            self.active = None;
            return KeyOutcome::Updated;
        }

        if ks.key == "backspace" {
            let field = self.field_mut(active);
            if !field.is_empty() {
                field.pop();
                return KeyOutcome::Updated;
            }
            return KeyOutcome::None;
        }

        if ks.key == "delete" {
            let field = self.field_mut(active);
            field.clear();
            return KeyOutcome::Updated;
        }

        if ks.key == "return" || ks.key == "enter" {
            if self.is_ready() {
                return KeyOutcome::Submit;
            }
            return KeyOutcome::None;
        }

        if self.editor_for(active).has_native_input() {
            return KeyOutcome::None;
        }

        if ks.key == "space" {
            let field = self.field_mut(active);
            field.push(' ');
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

            let field = self.field_mut(active);
            field.push_str(ch);
            return KeyOutcome::Updated;
        }

        KeyOutcome::None
    }

    pub(super) fn join_params(&self) -> JoinParams {
        JoinParams {
            server_url: self.server.trim().to_string(),
            room_id: self.room_id.trim().to_string(),
            alias: self.alias.trim().to_string(),
        }
    }

    pub(super) fn editor_for(&self, field: ActiveField) -> &TextInputEditorState {
        match field {
            ActiveField::Server => &self.server_editor,
            ActiveField::Room => &self.room_editor,
            ActiveField::Alias => &self.alias_editor,
        }
    }
}
