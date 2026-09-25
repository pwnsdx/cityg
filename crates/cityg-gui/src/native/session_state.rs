use super::*;

impl AppModel {
    /// Make `session` the active session: restore its chat history, aliases
    /// and security log from disk and derive the roster panels from its view.
    pub(super) fn install_session(&mut self, session: AppSession) {
        let history = load_history(&session.server_url, &session.room_id).unwrap_or_else(|err| {
            warn!("failed to load chat history: {err:?}");
            Vec::new()
        });
        let view = session.view.clone();
        self.session = Some(session);
        self.messages.clear();
        self.message_keys.clear();
        self.next_pending_message_id = 1;
        self.append_messages(history);
        self.hydrate_alias_bindings_from_disk();
        self.load_security_events_from_disk();
        self.apply_session_view(view);
        self.fetch_status = FetchStatus::Idle;
        self.send_status = SendStatus::Idle;
        self.composer.clear();
        self.composer.blur();
        self.fetch_task = None;
        self.fetch_in_flight = false;
        self.sync_again = false;
        self.show_ciphertext = false;
        self.ws_autostart_attempted = false;
        self.endpoint_mode_server_url = None;
        self.endpoint_mode = super::endpoint_mode::EndpointMode::Unknown;
    }

    /// Record a new view of the session: roster, admins and members panel.
    pub(super) fn apply_session_view(&mut self, view: SessionView) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        session.apply_view(view.clone());
        self.room_admins = view
            .roster
            .iter()
            .filter(|entry| entry.admin)
            .map(|entry| entry.device_public_key.clone())
            .collect();
        self.room_admins_loaded = true;
        for entry in &view.roster {
            if let Some(alias) = &entry.alias {
                self.leaf_alias_index.insert(entry.leaf_id, alias.clone());
            }
        }
        self.rebuild_members();
    }

    /// Rebuild the members panel from the session roster and the search.
    pub(super) fn rebuild_members(&mut self) {
        let Some(session) = &self.session else {
            self.members.clear();
            self.members_total = 0;
            return;
        };
        let query = match &self.members_mode {
            MembersMode::Search { query } => Some(query.to_lowercase()),
            MembersMode::Full => None,
        };
        self.members = session
            .view
            .roster
            .iter()
            .map(|entry| MemberEntry {
                leaf_id: entry.leaf_id,
                alias: entry
                    .alias
                    .clone()
                    .or_else(|| self.leaf_alias_index.get(&entry.leaf_id).cloned())
                    .or_else(|| (entry.leaf_id == session.leaf_id).then(|| session.alias.clone())),
                pop_public_key: Some(entry.device_public_key.clone()),
                slot: entry.slot,
                admin: entry.admin,
                pending_removal: entry.pending_removal,
            })
            .filter(|member| match &query {
                None => true,
                Some(query) => {
                    member
                        .alias
                        .as_deref()
                        .is_some_and(|alias| alias.to_lowercase().contains(query))
                        || hex_encode(member.leaf_id).starts_with(query.as_str())
                }
            })
            .collect();
        self.members_total = session.view.roster.len() as u64;
        self.members_next_offset = None;
        self.members_status = MembersStatus::Idle;
    }

    pub(super) fn append_messages(&mut self, new_messages: Vec<ChatMessageEntry>) -> usize {
        let mut inserted = 0usize;
        for mut message in new_messages {
            if message.ciphertext_hex.is_empty() {
                continue;
            }
            message.delivery = MessageDelivery::Sent;
            message.pending_id = None;
            let key = MessageKey {
                ciphertext_hex: message.ciphertext_hex.clone(),
                sender_leaf: message.sender_leaf,
            };
            if self.message_keys.insert(key) {
                self.messages.push(message);
                inserted = inserted.saturating_add(1);
            }
        }
        self.messages.sort_by_key(|m| m.timestamp_ms);
        if inserted > 0 {
            self.scroll_chat_to_bottom();
        }
        inserted
    }

    pub(super) fn queue_pending_message(&mut self, session: &AppSession, plaintext: &str) -> u64 {
        let pending_id = self.next_pending_message_id;
        self.next_pending_message_id = self.next_pending_message_id.saturating_add(1);
        self.messages.push(ChatMessageEntry {
            sender_leaf: Some(session.leaf_id),
            fallback_label: session.alias.clone(),
            plaintext: plaintext.to_string(),
            ciphertext_hex: String::new(),
            timestamp_ms: engine::now_ms(),
            delivery: MessageDelivery::Pending,
            pending_id: Some(pending_id),
        });
        self.messages.sort_by_key(|m| m.timestamp_ms);
        self.scroll_chat_to_bottom();
        pending_id
    }

    pub(super) fn confirm_pending_message(&mut self, pending_id: u64, mut entry: ChatMessageEntry) {
        entry.delivery = MessageDelivery::Sent;
        entry.pending_id = None;
        let key = MessageKey {
            ciphertext_hex: entry.ciphertext_hex.clone(),
            sender_leaf: entry.sender_leaf,
        };

        if self.message_keys.insert(key) {
            if let Some(index) = self
                .messages
                .iter()
                .position(|message| message.pending_id == Some(pending_id))
            {
                self.messages[index] = entry;
            } else {
                self.messages.push(entry);
            }
        } else {
            self.messages
                .retain(|message| message.pending_id != Some(pending_id));
        }
        self.messages.sort_by_key(|m| m.timestamp_ms);
        self.scroll_chat_to_bottom();
    }

    pub(super) fn mark_pending_message_failed(&mut self, pending_id: u64) {
        if let Some(message) = self
            .messages
            .iter_mut()
            .find(|message| message.pending_id == Some(pending_id))
        {
            message.delivery = MessageDelivery::Failed;
            message.pending_id = None;
        }
    }

    /// Persist the chat history of the active session.
    pub(super) fn persist_history(&self) {
        if let Some(session) = &self.session
            && let Err(err) = persist_history(&session.server_url, &session.room_id, &self.messages)
        {
            warn!("failed to persist chat history: {err:?}");
        }
    }

    pub(super) fn resolve_sender_label(&self, message: &ChatMessageEntry) -> String {
        if let Some(leaf) = message.sender_leaf
            && let Some(label) = self.member_label_for_leaf(&leaf)
        {
            return label;
        }
        message.fallback_label.clone()
    }

    pub(super) fn member_label_for_leaf(&self, leaf: &[u8; 32]) -> Option<String> {
        if let Some(member) = self.members.iter().find(|member| &member.leaf_id == leaf) {
            return Some(format_member_label(member));
        }
        if let Some(alias) = self.leaf_alias_index.get(leaf) {
            return Some(format_alias_display(alias, leaf));
        }
        None
    }

    /// Check the aliases the delivery service returned against the keys
    /// previously seen for them (trust on first use) and remember them.
    pub(super) fn reconcile_alias_bindings(
        &mut self,
        aliases: &BTreeMap<[u8; 32], String>,
        cx: &mut ViewContext<Self>,
    ) {
        let Some(session) = &self.session else {
            return;
        };
        let server_url = session.server_url.clone();
        let room_id = session.room_id.clone();
        let roster = session.view.roster.clone();

        let mut mismatches = Vec::new();
        let mut refreshed = self.alias_bindings.clone();
        for (leaf, alias) in aliases {
            let Some(entry) = roster.iter().find(|entry| &entry.leaf_id == leaf) else {
                continue;
            };
            if let Some(existing) = self.alias_bindings.get(alias)
                && existing.pop_public_key != entry.device_public_key
            {
                mismatches.push(alias.clone());
            }
            refreshed.insert(
                alias.clone(),
                AliasBindingRecord {
                    pop_public_key: entry.device_public_key.clone(),
                    leaf_id: *leaf,
                },
            );
        }

        for alias in mismatches {
            let message =
                format!("TOFU alert: alias '{alias}' is now claimed by a different device key.");
            self.show_error_toast(message.clone(), cx);
            self.record_security_event(&alias, message, cx);
        }

        let changed = refreshed != self.alias_bindings;
        self.alias_bindings = refreshed;
        self.refresh_leaf_alias_index();
        for (leaf, alias) in aliases {
            self.leaf_alias_index.insert(*leaf, alias.clone());
        }

        if changed
            && let Err(err) = persist_alias_bindings(&server_url, &room_id, &self.alias_bindings)
        {
            warn!("failed to persist alias bindings: {err:?}");
        }
    }

    pub(super) fn hydrate_alias_bindings_from_disk(&mut self) {
        if let Some(session) = &self.session {
            match load_alias_bindings(&session.server_url, &session.room_id) {
                Ok(bindings) => {
                    self.alias_bindings = bindings;
                    self.refresh_leaf_alias_index();
                }
                Err(err) => {
                    warn!("failed to load alias bindings: {err:?}");
                    self.alias_bindings.clear();
                    self.leaf_alias_index.clear();
                }
            }
        } else {
            self.alias_bindings.clear();
            self.leaf_alias_index.clear();
        }
    }

    pub(super) fn load_security_events_from_disk(&mut self) {
        if let Some(session) = &self.session {
            match load_security_log(&session.server_url, &session.room_id) {
                Ok(events) => {
                    self.security_events = events;
                    self.security_unread = 0;
                    self.security_panel_expanded = !self.security_events.is_empty();
                }
                Err(err) => {
                    warn!("failed to load security log: {err:?}");
                    self.security_events.clear();
                    self.security_unread = 0;
                    self.security_panel_expanded = false;
                }
            }
        } else {
            self.security_events.clear();
            self.security_unread = 0;
            self.security_panel_expanded = false;
        }
    }

    pub(super) fn persist_security_events_to_disk(&self) {
        let Some(session) = &self.session else {
            return;
        };
        if let Err(err) =
            persist_security_log(&session.server_url, &session.room_id, &self.security_events)
        {
            warn!("failed to persist security log: {err:?}");
        }
    }

    pub(super) fn record_security_event(
        &mut self,
        alias: &str,
        description: impl Into<String>,
        cx: &mut ViewContext<Self>,
    ) {
        self.security_events.push(SecurityEvent {
            alias: alias.to_string(),
            description: description.into(),
            timestamp_ms: engine::now_ms(),
        });
        if self.security_events.len() > MAX_SECURITY_EVENTS {
            let drain = self.security_events.len() - MAX_SECURITY_EVENTS;
            self.security_events.drain(0..drain);
        }
        self.security_unread = self.security_unread.saturating_add(1);
        self.security_panel_expanded = true;
        self.persist_security_events_to_disk();
        cx.notify();
    }

    pub(super) fn record_activity(&mut self, kind: ActivityKind, summary: impl Into<String>) {
        self.record_activity_with_detail(kind, summary, None);
    }

    pub(super) fn record_activity_with_detail(
        &mut self,
        kind: ActivityKind,
        summary: impl Into<String>,
        detail: Option<String>,
    ) {
        self.activity_events.push(ActivityEvent {
            kind,
            summary: summary.into(),
            detail,
            timestamp_ms: current_unix_timestamp_ms(),
        });
        if self.activity_events.len() > MAX_ACTIVITY_EVENTS {
            let drain = self.activity_events.len() - MAX_ACTIVITY_EVENTS;
            self.activity_events.drain(0..drain);
        }
    }

    pub(super) fn acknowledge_security_alerts(&mut self) {
        if self.security_unread > 0 {
            self.security_unread = 0;
        }
    }

    pub(super) fn refresh_leaf_alias_index(&mut self) {
        self.leaf_alias_index.clear();
        for (alias, record) in &self.alias_bindings {
            if record.leaf_id.iter().all(|&b| b == 0) {
                continue;
            }
            self.leaf_alias_index.insert(record.leaf_id, alias.clone());
        }
    }

    pub(super) fn scroll_chat_to_bottom(&self) {
        self.chat_scroll_handle.scroll_to_bottom();
    }
}
