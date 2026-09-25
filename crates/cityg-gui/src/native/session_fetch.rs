use super::*;

impl AppModel {
    pub(super) fn ensure_fetch_loop(&mut self, cx: &mut ViewContext<Self>) {
        if self.session.is_none() {
            self.reset_fetch_state();
            return;
        }

        if !self.fetch_in_flight && self.fetch_task.is_none() {
            self.schedule_fetch(cx, Duration::from_millis(0));
        }
    }

    pub(super) fn reset_fetch_state(&mut self) {
        self.fetch_in_flight = false;
        self.fetch_status = FetchStatus::Idle;
        self.fetch_task = None;
        self.sync_again = false;
    }

    /// Sync the room log after `delay` (commits, messages, proposals).
    pub(super) fn schedule_fetch(&mut self, cx: &mut ViewContext<Self>, delay: Duration) {
        let Some(session) = self.session.clone() else {
            self.reset_fetch_state();
            return;
        };

        if self.fetch_in_flight {
            if delay.is_zero() {
                self.sync_again = true;
            }
            return;
        }

        self.fetch_in_flight = true;
        if delay.is_zero() {
            self.fetch_status = FetchStatus::Refreshing;
        }

        let member = session.member.clone();
        let expected_room = session.room_id.clone();
        let expected_leaf = session.leaf_id;

        let task = cx.spawn(async move |this, cx| {
            let sync = match Tokio::spawn_result(cx, async move {
                if !delay.is_zero() {
                    sleep(delay).await;
                }
                engine::sync_room(&member).await
            }) {
                Ok(task) => task,
                Err(err) => {
                    let _ = this.update(cx, |model, _| {
                        model.fetch_task = None;
                        model.fetch_in_flight = false;
                        model.fetch_status = FetchStatus::Idle;
                        model.last_error = Some(format!("Failed to schedule room sync: {err}"));
                    });
                    return;
                }
            };

            let outcome = sync.await;

            let _ = this.update(cx, |model, cx| {
                model.fetch_task = None;
                model.fetch_in_flight = false;
                model.handle_sync_result(outcome, &expected_room, expected_leaf, cx);
                cx.notify();
            });
        });

        self.fetch_task = Some(task);
    }

    pub(super) fn handle_sync_result(
        &mut self,
        outcome: anyhow::Result<engine::SyncOutcome>,
        expected_room: &str,
        expected_leaf: [u8; 32],
        cx: &mut ViewContext<Self>,
    ) {
        let matches_session = self
            .session
            .as_ref()
            .is_some_and(|session| session.room_id == expected_room && session.leaf_id == expected_leaf);
        if !matches_session {
            self.fetch_status = FetchStatus::Idle;
            return;
        }

        let delay = match outcome {
            Ok(result) => {
                if result.removed {
                    self.on_removed_from_room(cx);
                    return;
                }
                self.apply_sync_outcome(result, cx);
                self.fetch_status = FetchStatus::Idle;
                if std::mem::take(&mut self.sync_again) {
                    Duration::from_millis(0)
                } else {
                    self.config.client.fetch_poll_interval()
                }
            }
            Err(err) => {
                if engine::is_membership_loss(&err) {
                    self.fetch_status = FetchStatus::Idle;
                    self.handle_stale_server_session(
                        "This device is no longer a member of the room. Join it again with a new invite.",
                        cx,
                    );
                    return;
                }
                self.last_error = Some(format!("Failed to sync the room: {err:#}"));
                if matches!(self.members_status, MembersStatus::Loading(_)) {
                    self.members_status = MembersStatus::Error(format!("Roster sync failed: {err:#}"));
                }
                self.record_activity_with_detail(
                    ActivityKind::Sync,
                    "Room sync failed",
                    Some(format!("{err:#}")),
                );
                self.fetch_status = FetchStatus::Idle;
                self.config.client.fetch_retry_interval()
            }
        };

        if !self.fetch_in_flight {
            self.schedule_fetch(cx, delay);
        }
    }

    /// Apply what a sync observed: roster changes, messages, aliases, view.
    pub(super) fn apply_sync_outcome(
        &mut self,
        result: engine::SyncOutcome,
        cx: &mut ViewContext<Self>,
    ) {
        let engine::SyncOutcome {
            messages,
            changes,
            rejected,
            resynced,
            view,
            aliases,
            ..
        } = result;

        if resynced {
            self.record_security_event(
                "this device",
                "This device could not follow a commit and re-entered its slot (resync).",
                cx,
            );
        }
        for change in &changes {
            let summary = match change {
                engine::RosterChange::Joined(leaf) => {
                    format!("Joined: {}", self.label_for(leaf, &aliases))
                }
                engine::RosterChange::Removed(leaf) => {
                    format!("Removed: {}", self.label_for(leaf, &aliases))
                }
                engine::RosterChange::Resynced(leaf) => {
                    format!("Resynced: {}", self.label_for(leaf, &aliases))
                }
                engine::RosterChange::LeaveRequested(leaf) => {
                    format!("Leave requested: {}", self.label_for(leaf, &aliases))
                }
                engine::RosterChange::AdminsChanged => "Room admins changed".to_string(),
            };
            self.record_activity(ActivityKind::Roster, summary);
        }
        if rejected > 0 {
            self.record_activity_with_detail(
                ActivityKind::Message,
                "Rejected messages",
                Some(format!(
                    "{rejected} envelope(s) failed authentication, came from a removed sender or were replays"
                )),
            );
        }

        let epoch_changed = self
            .session
            .as_ref()
            .is_some_and(|session| session.view.epoch != view.epoch);
        // Aliases name members of the new roster: apply it first.
        self.apply_session_view(view);
        self.reconcile_alias_bindings(&aliases, cx);
        if epoch_changed {
            self.record_activity(ActivityKind::Sync, "Moved to a new epoch");
        }

        if !messages.is_empty() {
            let entries: Vec<ChatMessageEntry> = messages
                .into_iter()
                .map(|message| ChatMessageEntry {
                    sender_leaf: Some(message.sender_leaf),
                    fallback_label: format!("{}✓", hex_encode(&message.sender_leaf[..4])),
                    plaintext: message.text.clone(),
                    ciphertext_hex: message.key(),
                    timestamp_ms: message.signed_timestamp_ms,
                    delivery: MessageDelivery::Sent,
                    pending_id: None,
                })
                .collect();
            let added = self.append_messages(entries);
            if added > 0 {
                self.persist_history();
                self.info_message = Some(format!("Received {added} new message(s)."));
                self.record_activity(
                    ActivityKind::Message,
                    format!("Received {added} new message(s)"),
                );
                self.notify_background_messages(added);
            }
        }
    }

    fn label_for(&self, leaf: &[u8; 32], aliases: &BTreeMap<[u8; 32], String>) -> String {
        aliases
            .get(leaf)
            .map(|alias| format_alias_display(alias, leaf))
            .or_else(|| self.member_label_for_leaf(leaf))
            .unwrap_or_else(|| short_leaf_display(leaf))
    }

    /// The last sync showed this device was removed.
    pub(super) fn on_removed_from_room(&mut self, cx: &mut ViewContext<Self>) {
        self.fetch_status = FetchStatus::Idle;
        let room = self
            .session
            .as_ref()
            .map(|session| session.room_id.clone())
            .unwrap_or_default();
        warn!("this device was removed from room {room}");
        if let Err(err) = self.reset_session_state() {
            warn!("failed to remove session data after removal: {err:?}");
        }
        let message = "This device was removed from the room.".to_string();
        self.info_message = Some(message.clone());
        self.show_error_toast(message, cx);
    }
}
