use super::websocket::{
    MembershipSignal, MembershipSignalKind, WebSocketMessageSignal, WebSocketSyncRequiredSignal,
};
use super::*;

impl AppModel {
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
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.messages.push(ChatMessageEntry {
            sender_leaf: Some(session.leaf_id),
            fallback_label: session.alias.clone(),
            plaintext: plaintext.to_string(),
            ciphertext_hex: String::new(),
            timestamp_ms,
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

    pub(super) fn reconcile_alias_bindings(&mut self, cx: &mut ViewContext<Self>) {
        let Some(session) = &self.session else {
            return;
        };
        let server_url = session.server_url.clone();
        let room_id = session.room_id.clone();

        let mut mismatches = Vec::new();
        let mut refreshed: AHashMap<String, AliasBindingRecord> = AHashMap::new();

        for member in &self.members {
            let Some(alias) = member
                .alias
                .as_ref()
                .map(|alias| alias.trim())
                .filter(|alias| !alias.is_empty())
                .map(|alias| alias.to_string())
            else {
                continue;
            };

            let Some(pop_key) = member.pop_public_key.as_ref().filter(|pk| !pk.is_empty()) else {
                continue;
            };

            if let Some(existing) = self.alias_bindings.get(&alias)
                && existing.pop_public_key != *pop_key
            {
                mismatches.push(alias.clone());
            }

            refreshed.insert(
                alias,
                AliasBindingRecord {
                    pop_public_key: pop_key.clone(),
                    leaf_id: member.leaf_id,
                },
            );
        }

        for alias in mismatches {
            let message = format!("TOFU alert: alias '{alias}' broadcast a new identity key.");
            self.show_error_toast(message.clone(), cx);
            self.record_security_event(&alias, message, cx);
        }

        let changed = refreshed != self.alias_bindings;
        self.alias_bindings = refreshed;
        self.refresh_leaf_alias_index();

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
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.security_events.push(SecurityEvent {
            alias: alias.to_string(),
            description: description.into(),
            timestamp_ms,
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

    pub(super) fn record_websocket_message_activity(&mut self, signal: &WebSocketMessageSignal) {
        let summary = if signal.replayed {
            "Replayed message notification after reconnect"
        } else {
            "New message notification"
        };
        let detail = websocket_activity_detail(signal.sequence, signal.replayed, None);
        self.record_activity_with_detail(ActivityKind::Message, summary, detail);
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

    pub(super) fn record_membership_activity(&mut self, signal: &MembershipSignal) {
        let summary = match (signal.kind, signal.leaf_id, signal.replayed) {
            (Some(MembershipSignalKind::Join), Some(leaf), true) => {
                format!("Replayed roster join: {}", short_leaf_display(&leaf))
            }
            (Some(MembershipSignalKind::Revoke), Some(leaf), true) => {
                format!("Replayed roster revoke: {}", short_leaf_display(&leaf))
            }
            (Some(MembershipSignalKind::Join), Some(leaf), false) => {
                format!("Roster join: {}", short_leaf_display(&leaf))
            }
            (Some(MembershipSignalKind::Revoke), Some(leaf), false) => {
                format!("Roster revoke: {}", short_leaf_display(&leaf))
            }
            (Some(MembershipSignalKind::Join), None, true) => {
                "Replayed roster join detected".to_string()
            }
            (Some(MembershipSignalKind::Revoke), None, true) => {
                "Replayed roster revoke detected".to_string()
            }
            (Some(MembershipSignalKind::Join), None, false) => "Roster join detected".to_string(),
            (Some(MembershipSignalKind::Revoke), None, false) => {
                "Roster revoke detected".to_string()
            }
            (None, Some(leaf), true) => {
                format!("Replayed roster change: {}", short_leaf_display(&leaf))
            }
            (None, Some(leaf), false) => format!("Roster changed: {}", short_leaf_display(&leaf)),
            (None, None, true) => "Replayed roster changed".to_string(),
            (None, None, false) => "Roster changed".to_string(),
        };
        let detail =
            websocket_activity_detail(signal.sequence, signal.replayed, signal.timestamp_ms);
        self.record_activity_with_detail(ActivityKind::Roster, summary, detail);
    }

    pub(super) fn record_websocket_sync_required_activity(
        &mut self,
        signal: &WebSocketSyncRequiredSignal,
    ) {
        let mut detail = Vec::new();
        detail.push(format!(
            "{} messages fell outside the Worker replay window",
            signal.lagged_messages
        ));
        if let Some(retained_from_sequence) = signal.retained_from_sequence {
            detail.push(format!(
                "buffer now retains notifications from sequence {}",
                retained_from_sequence
            ));
        }
        if let Some(reason) = signal.reason.as_deref() {
            detail.push(format!("reason {reason}"));
        }
        if let Some(action) = signal.action.as_deref() {
            detail.push(format!("action {action}"));
        }
        if let Some(reconcile_via) = signal.reconcile_via.as_deref() {
            detail.push(format!("reconcile via {reconcile_via}"));
        }
        if let Some(sequence) = signal.sequence {
            detail.push(format!("sequence {}", sequence));
        }
        if let Some(timestamp_ms) = signal.timestamp_ms {
            detail.push(format!(
                "server timestamp {}",
                format_timestamp(timestamp_ms)
            ));
        }
        self.record_activity_with_detail(
            ActivityKind::Connection,
            "Worker replay window exhausted; HTTP reconciliation required",
            Some(detail.join(", ")),
        );
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

fn websocket_activity_detail(
    sequence: Option<u64>,
    replayed: bool,
    timestamp_ms: Option<u64>,
) -> Option<String> {
    let mut parts = Vec::new();
    if replayed {
        parts.push("replayed after reconnect".to_string());
    }
    if let Some(sequence) = sequence {
        parts.push(format!("sequence {}", sequence));
    }
    if let Some(timestamp_ms) = timestamp_ms {
        parts.push(format!(
            "server timestamp {}",
            format_timestamp(timestamp_ms)
        ));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}
