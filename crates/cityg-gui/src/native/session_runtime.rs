use super::*;

impl AppModel {
    pub(super) fn bootstrap_session_runtime(&mut self, cx: &mut ViewContext<Self>) {
        self.ensure_endpoint_mode_probe(cx);
        if self.barrier_recovery_pending() {
            self.reset_fetch_state();
        } else {
            self.ensure_fetch_loop(cx);
        }
        self.ensure_websocket_task(cx);
        self.ensure_epoch_sync_task(cx);
        self.ensure_members_refresh_task(cx);
        self.ensure_room_admins_loaded(cx);
    }

    pub(super) fn ensure_members_refresh_task(&mut self, cx: &mut ViewContext<Self>) {
        if self.session.is_none() {
            self.stop_members_refresh_task();
            return;
        }

        if self.members_refresh_task.is_none() {
            self.start_members_refresh_task(cx);
        }
    }

    pub(super) fn ensure_room_admins_loaded(&mut self, cx: &mut ViewContext<Self>) {
        if self.session.is_none() {
            self.room_admins.clear();
            self.room_admins_loaded = false;
            self.room_admin_status = RoomAdminStatus::Idle;
            self.room_admin_target.clear();
            self.room_admin_target.blur();
            self.clear_room_admin_revoke_confirmation();
            return;
        }

        if !self.room_admins_loaded && matches!(self.room_admin_status, RoomAdminStatus::Idle) {
            self.refresh_room_admins(cx);
        }
    }

    pub(super) fn start_members_refresh_task(&mut self, cx: &mut ViewContext<Self>) {
        let interval = self.config.gui.members_refresh_interval();
        let task = cx.spawn(async move |this, cx| {
            loop {
                let delay = match Tokio::spawn_result(cx, async move {
                    sleep(interval).await;
                    Ok(())
                }) {
                    Ok(task) => task,
                    Err(err) => {
                        warn!("failed to schedule members refresh delay: {err}");
                        break;
                    }
                };
                if let Err(err) = delay.await {
                    warn!("members refresh delay task failed: {err}");
                    break;
                }

                let keep_running = this
                    .update(cx, |model, cx| {
                        if model.session.is_some() {
                            model.refresh_members_soft(cx);
                            model.commit_pending_removals_soft(cx);
                            true
                        } else {
                            false
                        }
                    })
                    .unwrap_or(false);

                if !keep_running {
                    info!("Stopping members refresh task (session ended)");
                    break;
                }
            }
        });

        self.members_refresh_task = Some(task);
    }

    /// Commit other members' pending leave requests (audit C-03): a leaving
    /// device never revokes itself, so a remaining member publishes the
    /// removal. Failures are logged and retried on the next tick.
    pub(super) fn commit_pending_removals_soft(&mut self, cx: &mut ViewContext<Self>) {
        if self.removal_commit_in_flight
            || self.epoch_sync_task.is_some()
            || !matches!(self.leave_status, LeaveStatus::Idle)
        {
            return;
        }
        let Some(session) = self.session.clone() else {
            return;
        };
        if session.barrier_state.barrier_recovery_pending
            || !session.barrier_state.current_barrier_full_verified
        {
            return;
        }

        self.removal_commit_in_flight = true;
        let expected_server = session.server_url.clone();
        let expected_room = session.room_id.clone();
        let expected_leaf = session.leaf_id;
        let task = Tokio::spawn_result(
            cx,
            async move { perform_pending_removal_commit(session).await },
        );
        cx.spawn(async move |this, cx| {
            let outcome = task.await;
            let _ = this.update(cx, |model, cx| {
                model.removal_commit_in_flight = false;
                let matches_session = model.session.as_ref().is_some_and(|session| {
                    session.server_url == expected_server
                        && session.room_id == expected_room
                        && session.leaf_id == expected_leaf
                });
                if matches_session {
                    model.on_pending_removal_commit_finished(outcome, cx);
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub(super) fn on_pending_removal_commit_finished(
        &mut self,
        outcome: anyhow::Result<Option<AppSession>>,
        cx: &mut ViewContext<Self>,
    ) {
        match outcome {
            Ok(Some(session)) => {
                self.session = Some(session);
                self.record_activity(ActivityKind::Roster, "Committed a member's leave request");
                self.reset_fetch_state();
                self.bootstrap_session_runtime(cx);
                self.refresh_members(cx);
            }
            Ok(None) => {}
            Err(err) => {
                warn!("committing pending removal proposals failed: {err:#}");
                self.schedule_epoch_sync(cx, "Syncing after a failed removal commit…");
            }
        }
    }

    pub(super) fn stop_members_refresh_task(&mut self) {
        if self.members_refresh_task.is_some() {
            info!("Stopping members refresh task");
            self.members_refresh_task = None;
        }
    }
}
