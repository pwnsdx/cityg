use super::*;

/// How long the previous epoch's message keys are kept (profile grace
/// window).
const GRACE_WINDOW_MS: u64 = 10 * 60 * 1000;

/// What the maintenance tick should do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MaintenanceAction {
    /// Commit other members' recorded leave requests.
    CommitRemovals,
    /// Re-key this device (forward secrecy / PCS window reached).
    RefreshKeys,
    /// Erase the previous epoch's message keys (grace window over).
    ExpireGrace,
}

/// Pick the maintenance action for `session` at `now_ms`.
pub(super) fn maintenance_action(session: &AppSession, now_ms: u64) -> Option<MaintenanceAction> {
    let me_pending = session.removal_pending();
    if session.view.pending_removals > 0 && !me_pending {
        return Some(MaintenanceAction::CommitRemovals);
    }
    if !me_pending
        && now_ms.saturating_sub(session.last_self_update_ms()) >= engine::SELF_UPDATE_INTERVAL_MS
    {
        return Some(MaintenanceAction::RefreshKeys);
    }
    if session.view.has_previous_epoch_keys
        && now_ms.saturating_sub(session.epoch_started_ms) >= GRACE_WINDOW_MS
    {
        return Some(MaintenanceAction::ExpireGrace);
    }
    None
}

impl AppModel {
    pub(super) fn bootstrap_session_runtime(&mut self, cx: &mut ViewContext<Self>) {
        self.ensure_endpoint_mode_probe(cx);
        self.ensure_fetch_loop(cx);
        self.ensure_websocket_task(cx);
        self.ensure_maintenance_task(cx);
    }

    pub(super) fn ensure_maintenance_task(&mut self, cx: &mut ViewContext<Self>) {
        if self.session.is_none() {
            self.stop_maintenance_task();
            return;
        }
        if self.maintenance_task.is_none() {
            self.start_maintenance_task(cx);
        }
    }

    pub(super) fn start_maintenance_task(&mut self, cx: &mut ViewContext<Self>) {
        let interval = self.config.gui.members_refresh_interval();
        let task = cx.spawn(async move |this, cx| {
            loop {
                let delay = match Tokio::spawn_result(cx, async move {
                    sleep(interval).await;
                    Ok(())
                }) {
                    Ok(task) => task,
                    Err(err) => {
                        warn!("failed to schedule the maintenance tick: {err}");
                        break;
                    }
                };
                if let Err(err) = delay.await {
                    warn!("maintenance tick failed: {err}");
                    break;
                }

                let keep_running = this
                    .update(cx, |model, cx| {
                        if model.session.is_some() {
                            model.run_maintenance(cx);
                            true
                        } else {
                            false
                        }
                    })
                    .unwrap_or(false);

                if !keep_running {
                    info!("Stopping maintenance task (session ended)");
                    break;
                }
            }
        });

        self.maintenance_task = Some(task);
    }

    /// One maintenance tick: commit leave requests of others (audit C-03:
    /// a leaving device never commits its own removal), re-key when the
    /// FS/PCS window elapsed, and erase expired previous-epoch keys.
    pub(super) fn run_maintenance(&mut self, cx: &mut ViewContext<Self>) {
        if self.removal_commit_in_flight || !matches!(self.leave_status, LeaveStatus::Idle) {
            return;
        }
        let Some(session) = self.session.clone() else {
            return;
        };
        let Some(action) = maintenance_action(&session, engine::now_ms()) else {
            return;
        };

        self.removal_commit_in_flight = true;
        let member = session.member.clone();
        let expected_room = session.room_id.clone();
        let task = Tokio::spawn_result(cx, async move {
            match action {
                MaintenanceAction::CommitRemovals => {
                    // Spread concurrent committers to avoid losing the epoch.
                    let jitter = Duration::from_millis(u64::from(rand::random::<u16>() % 1500));
                    sleep(jitter).await;
                    engine::commit_pending(&member).await.map(|outcome| outcome.map(|o| o.view))
                }
                MaintenanceAction::RefreshKeys => {
                    engine::refresh_keys(&member).await.map(|outcome| Some(outcome.view))
                }
                MaintenanceAction::ExpireGrace => {
                    engine::expire_previous_epoch(&member).await.map(|_| None)
                }
            }
        });
        cx.spawn(async move |this, cx| {
            let outcome = task.await;
            let _ = this.update(cx, |model, cx| {
                model.removal_commit_in_flight = false;
                let matches_session = model
                    .session
                    .as_ref()
                    .is_some_and(|session| session.room_id == expected_room);
                if matches_session {
                    model.on_maintenance_finished(action, outcome, cx);
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub(super) fn on_maintenance_finished(
        &mut self,
        action: MaintenanceAction,
        outcome: anyhow::Result<Option<SessionView>>,
        cx: &mut ViewContext<Self>,
    ) {
        match outcome {
            Ok(view) => {
                match action {
                    MaintenanceAction::CommitRemovals if view.is_some() => {
                        self.record_activity(ActivityKind::Roster, "Committed a member's leave request");
                    }
                    MaintenanceAction::RefreshKeys => {
                        if let Some(session) = &self.session {
                            session.mark_self_update();
                        }
                        self.record_activity(ActivityKind::Sync, "Refreshed this device's keys");
                    }
                    MaintenanceAction::ExpireGrace => {
                        if let Some(session) = self.session.as_mut() {
                            session.view.has_previous_epoch_keys = false;
                        }
                    }
                    MaintenanceAction::CommitRemovals => {}
                }
                if let Some(view) = view {
                    self.apply_session_view(view);
                }
            }
            Err(err) => {
                warn!("maintenance {action:?} failed: {err:#}");
                self.schedule_fetch(cx, Duration::from_millis(0));
            }
        }
    }

    pub(super) fn stop_maintenance_task(&mut self) {
        if self.maintenance_task.is_some() {
            info!("Stopping maintenance task");
            self.maintenance_task = None;
        }
    }
}
