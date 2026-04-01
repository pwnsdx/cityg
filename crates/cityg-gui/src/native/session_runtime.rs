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

    pub(super) fn stop_members_refresh_task(&mut self) {
        if self.members_refresh_task.is_some() {
            info!("Stopping members refresh task");
            self.members_refresh_task = None;
        }
    }
}
