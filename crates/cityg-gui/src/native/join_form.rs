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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

/// Parse a pasted invite link (`Ok(None)` when the text is not one).
pub(super) fn parse_join_invite(raw: &str) -> Result<Option<InviteLink>> {
    Ok(InviteLink::parse(raw)?)
}

/// What the join form asks for.
#[derive(Clone, Debug)]
pub(super) enum JoinRequest {
    /// Create a new room on `server_url`.
    Create { server_url: String, alias: String },
    /// Join the room of an invite link.
    Invite { link: InviteLink, alias: String },
}

impl JoinFormState {
    pub(super) fn apply_invite(&mut self, raw: &str, link: &InviteLink) -> Result<()> {
        self.server = link.server_url.clone();
        self.room_id = raw.trim().to_string();
        self.server_editor.reset_for_text(&self.server);
        self.room_editor.reset_for_text(&self.room_id);
        Ok(())
    }

    pub(super) fn clear_invite_material(&mut self) {
        if self.room_id.trim().starts_with(INVITE_PREFIX) {
            self.room_id.clear();
            self.room_editor.reset_for_text("");
        }
    }

    pub(super) fn is_ready(&self) -> bool {
        self.join_request().is_ok()
    }

    /// The request the form describes: an empty room field creates a room,
    /// an invite link joins its room.
    pub(super) fn join_request(&self) -> Result<JoinRequest> {
        let alias = self.alias.trim();
        if alias.is_empty() {
            return Err(anyhow!("choose an alias"));
        }
        let room = self.room_id.trim();
        if room.is_empty() {
            let server_url = self.server.trim();
            if server_url.is_empty() {
                return Err(anyhow!("enter the server URL"));
            }
            return Ok(JoinRequest::Create {
                server_url: server_url.to_string(),
                alias: alias.to_string(),
            });
        }
        match InviteLink::parse(room)? {
            Some(link) => Ok(JoinRequest::Invite {
                link,
                alias: alias.to_string(),
            }),
            None => Err(anyhow!(
                "joining an existing room needs an invite link from one of its admins"
            )),
        }
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

    pub(super) fn editor_for(&self, field: ActiveField) -> &TextInputEditorState {
        match field {
            ActiveField::Server => &self.server_editor,
            ActiveField::Room => &self.room_editor,
            ActiveField::Alias => &self.alias_editor,
        }
    }
}
