use super::epoch_sync::perform_epoch_sync;
use super::*;

impl AppModel {
    pub(super) fn ensure_epoch_sync_task(&mut self, _cx: &mut ViewContext<Self>) {
        if self.session.is_none() && self.epoch_sync_task.is_some() {
            self.stop_epoch_sync_task();
        }
    }

    pub(super) fn schedule_epoch_sync(&mut self, cx: &mut ViewContext<Self>, reason: &str) {
        if self.epoch_sync_task.is_some() {
            return;
        }

        let Some(session) = self.session.clone() else {
            return;
        };

        let expected_server = session.server_url.clone();
        let expected_room = session.room_id.clone();
        let expected_leaf = session.leaf_id;
        let reason_text = reason.to_string();

        info!("Scheduling epoch sync: {}", reason_text);

        let sync_task = Tokio::spawn_result(cx, async move { perform_epoch_sync(session).await });

        let task = cx.spawn(async move |this, cx| {
            let outcome = sync_task.await;
            let _ = this.update(cx, |model, cx| {
                model.epoch_sync_task = None;
                model.handle_epoch_sync_result(
                    outcome,
                    &expected_server,
                    &expected_room,
                    expected_leaf,
                    &reason_text,
                    cx,
                );
            });
        });

        self.epoch_sync_task = Some(task);
    }

    pub(super) fn handle_epoch_sync_result(
        &mut self,
        outcome: anyhow::Result<EpochSyncOutcome>,
        expected_server: &str,
        expected_room: &str,
        expected_leaf: [u8; 32],
        reason: &str,
        cx: &mut ViewContext<Self>,
    ) {
        let matches_session = self
            .session
            .as_ref()
            .map(|session| {
                session.server_url == expected_server
                    && session.room_id == expected_room
                    && session.leaf_id == expected_leaf
            })
            .unwrap_or(false);

        if !matches_session {
            return;
        }

        let fetch_after_epoch_sync = std::mem::take(&mut self.fetch_after_epoch_sync);

        match outcome {
            Ok(sync) => {
                let was_pending = self
                    .session
                    .as_ref()
                    .map(|session| session.barrier_state.barrier_recovery_pending)
                    .unwrap_or(false);
                if !sync.changed {
                    if was_pending {
                        self.info_message = Some(Self::barrier_recovery_wait_message().to_string());
                        cx.notify();
                    } else if fetch_after_epoch_sync {
                        self.schedule_fetch(cx, Duration::ZERO);
                    }
                    return;
                }

                let now_pending = sync.session.barrier_state.barrier_recovery_pending;
                self.session = Some(sync.session);
                if let Some(session) = self.session.as_mut()
                    && let Err(err) = persist_session(session)
                {
                    warn!("failed to persist session after epoch sync: {err:?}");
                }

                if was_pending && !now_pending {
                    self.info_message =
                        Some("Barrier recovery completed. Messaging is now available.".to_string());
                    self.record_activity(
                        ActivityKind::Sync,
                        "Barrier recovery completed after epoch sync",
                    );
                } else if now_pending {
                    self.info_message = Some(Self::barrier_recovery_wait_message().to_string());
                    self.record_activity(
                        ActivityKind::Sync,
                        "Epoch sync completed; barrier recovery still pending",
                    );
                } else {
                    self.info_message = Some("Adopted latest epoch head.".to_string());
                    self.record_activity(
                        ActivityKind::Sync,
                        "Adopted latest epoch head after sync",
                    );
                }
                self.reset_fetch_state();
                if !now_pending {
                    self.schedule_fetch(cx, Duration::ZERO);
                }
                self.refresh_members_soft(cx);
                cx.notify();
            }
            Err(err) => {
                if is_stale_server_session_error(&err) {
                    self.handle_stale_server_session(
                        "Saved session is no longer recognized by the server. Please join again.",
                        cx,
                    );
                    return;
                }
                warn!("epoch sync failed ({reason}): {err:?}");
                self.last_error = Some(format!("Failed to sync latest epoch: {err}"));
                self.record_activity_with_detail(
                    ActivityKind::Sync,
                    "Epoch sync failed",
                    Some(err.to_string()),
                );
                cx.notify();
            }
        }
    }

    pub(super) fn stop_epoch_sync_task(&mut self) {
        if self.epoch_sync_task.is_some() {
            info!("Stopping epoch sync task");
            self.epoch_sync_task = None;
        }
    }
}
