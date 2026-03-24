use futures::{StreamExt, channel::mpsc as futures_mpsc};

use super::websocket::{WebSocketEvent, run_websocket_worker};
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
    }

    pub(super) fn ensure_epoch_sync_task(&mut self, _cx: &mut ViewContext<Self>) {
        if self.session.is_none() && self.epoch_sync_task.is_some() {
            self.stop_epoch_sync_task();
        }
    }

    pub(super) fn ensure_websocket_task(&mut self, cx: &mut ViewContext<Self>) {
        if self.session.is_none() {
            self.stop_websocket();
            self.ws_autostart_attempted = false;
            self.restore_epoch_sync_pending = false;
            return;
        }

        if self.ws_task.is_none() && !self.ws_autostart_attempted {
            self.ws_autostart_attempted = true;
            self.start_websocket(cx);
        }

        if self.restore_epoch_sync_pending {
            self.restore_epoch_sync_pending = false;
            self.schedule_epoch_sync(cx, "Syncing latest epoch after session restore…");
        }
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

    pub(super) fn schedule_fetch(&mut self, cx: &mut ViewContext<Self>, delay: Duration) {
        let Some(session) = self.session.clone() else {
            self.reset_fetch_state();
            return;
        };

        if self.fetch_in_flight {
            return;
        }

        self.fetch_in_flight = true;
        if delay.is_zero() {
            self.fetch_status = FetchStatus::Refreshing;
        }

        let since = session.last_fetch_timestamp_ms;
        let params = match FetchParams::from_session(&session, since) {
            Ok(params) => params,
            Err(err) => {
                self.fetch_in_flight = false;
                self.fetch_status = FetchStatus::Idle;
                if session.barrier_state.barrier_recovery_pending {
                    self.info_message = Some(Self::barrier_recovery_wait_message().to_string());
                    self.record_activity_with_detail(
                        ActivityKind::Message,
                        "Message fetch deferred",
                        Some(err.to_string()),
                    );
                    return;
                }
                self.last_error = Some(format!("Failed to prepare message fetch: {err}"));
                self.record_activity_with_detail(
                    ActivityKind::Message,
                    "Message fetch skipped",
                    Some(err.to_string()),
                );
                return;
            }
        };
        let expected_weid = session.we_epoch_id;

        let task = cx.spawn(async move |this, cx| {
            let fetch_future = match Tokio::spawn_result(cx, async move {
                if !delay.is_zero() {
                    sleep(delay).await;
                }
                perform_fetch(params).await
            }) {
                Ok(task) => task,
                Err(err) => {
                    let _ = this.update(cx, |model, _| {
                        model.fetch_task = None;
                        model.fetch_in_flight = false;
                        model.fetch_status = FetchStatus::Idle;
                        model.last_error = Some(format!("Failed to schedule message fetch: {err}"));
                    });
                    return;
                }
            };

            let outcome = fetch_future.await;

            let _ = this.update(cx, |model, cx| {
                model.fetch_task = None;
                model.fetch_in_flight = false;
                model.handle_fetch_result(outcome, expected_weid, cx);
            });
        });

        self.fetch_task = Some(task);
    }

    pub(super) fn handle_fetch_result(
        &mut self,
        outcome: anyhow::Result<FetchOutcome>,
        expected_weid: [u8; 32],
        cx: &mut ViewContext<Self>,
    ) {
        let matches_session = self
            .session
            .as_ref()
            .map(|session| session.we_epoch_id == expected_weid)
            .unwrap_or(false);

        if !matches_session {
            self.fetch_status = FetchStatus::Idle;
            return;
        }

        let delay = match outcome {
            Ok(result) => {
                let FetchOutcome {
                    messages,
                    last_timestamp_ms,
                    msg_replay_state,
                } = result;

                if !messages.is_empty() {
                    let added = self.append_messages(messages);
                    if added > 0 {
                        self.info_message = Some(format!("Fetched {added} new message(s)."));
                        self.record_activity(
                            ActivityKind::Message,
                            format!("Fetched {added} new message(s)"),
                        );
                    }
                }

                if let Some(session) = self.session.as_mut() {
                    let mut should_persist = false;
                    if session.msg_replay_state != msg_replay_state {
                        session.msg_replay_state = msg_replay_state;
                        should_persist = true;
                    }
                    if let Some(ts) = last_timestamp_ms {
                        let timestamp_changed = session
                            .last_fetch_timestamp_ms
                            .map(|prev| ts > prev)
                            .unwrap_or(true);
                        if timestamp_changed {
                            session.last_fetch_timestamp_ms = Some(ts);
                            should_persist = true;
                        }
                    }
                    if should_persist && let Err(err) = persist_session(session) {
                        warn!("failed to persist session after fetch update: {err:?}");
                    }
                }

                self.fetch_status = FetchStatus::Idle;
                self.config.client.fetch_poll_interval()
            }
            Err(err) => {
                if is_stale_server_session_error(&err) {
                    self.fetch_status = FetchStatus::Idle;
                    self.handle_stale_server_session(
                        "Saved session is no longer recognized by the server. Please join again.",
                        cx,
                    );
                    return;
                }
                self.last_error = Some(format!("Failed to fetch messages: {err}"));
                self.record_activity_with_detail(
                    ActivityKind::Message,
                    "Message fetch failed",
                    Some(err.to_string()),
                );
                self.fetch_status = FetchStatus::Idle;
                self.config.client.fetch_retry_interval()
            }
        };

        if !self.fetch_in_flight {
            self.schedule_fetch(cx, delay);
        }
    }

    pub(super) fn stop_epoch_sync_task(&mut self) {
        if self.epoch_sync_task.is_some() {
            info!("Stopping epoch sync task");
            self.epoch_sync_task = None;
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

    pub(super) fn start_websocket(&mut self, cx: &mut ViewContext<Self>) {
        self.ws_autostart_attempted = true;
        let Some(session) = &self.session else {
            return;
        };
        let Some(message_token) = configured_client_message_token() else {
            warn!("message auth token is not configured; skipping websocket startup");
            return;
        };

        let ws_url = session
            .server_url
            .replace("http://", "ws://")
            .replace("https://", "wss://");
        let ws_url = format!(
            "{}/v1/ws?gid={}&leaf_id={}",
            ws_url,
            hex_encode(session.gid),
            hex_encode(session.leaf_id)
        );
        let reconnect_delay = self.config.client.websocket_reconnect_delay();

        info!("Starting WebSocket connection to {}", ws_url);

        let this = cx.weak_entity();
        let (event_tx, mut event_rx) = futures_mpsc::unbounded::<WebSocketEvent>();
        let task = cx.spawn(async move |_, cx| {
            let runner = match Tokio::spawn_result(
                cx,
                run_websocket_worker(
                    ws_url.clone(),
                    Some(message_token.clone()),
                    reconnect_delay,
                    event_tx,
                ),
            ) {
                Ok(task) => task,
                Err(err) => {
                    warn!("failed to schedule websocket worker: {err}");
                    return;
                }
            };

            while let Some(event) = event_rx.next().await {
                let _ = this.update(cx, |model, cx| {
                    model.handle_websocket_event(event, cx);
                });
            }

            if let Err(err) = runner.await {
                warn!("websocket worker task failed: {err}");
            }
        });

        self.ws_task = Some(task);
    }

    pub(super) fn handle_websocket_event(
        &mut self,
        event: WebSocketEvent,
        cx: &mut ViewContext<Self>,
    ) {
        match event {
            WebSocketEvent::Connected => {
                self.ws_connected = true;
                self.record_activity(
                    ActivityKind::Connection,
                    "WebSocket connected (live updates enabled)",
                );
                self.schedule_epoch_sync(cx, "Syncing latest epoch after WebSocket reconnect…");
                cx.notify();
            }
            WebSocketEvent::Disconnected => {
                self.ws_connected = false;
                self.record_activity(
                    ActivityKind::Connection,
                    "WebSocket disconnected (falling back to polling)",
                );
                cx.notify();
            }
            WebSocketEvent::Message => {
                self.record_activity(ActivityKind::Message, "New message notification");
                self.fetch_after_epoch_sync = true;
                self.schedule_epoch_sync(cx, "Syncing latest epoch after message notification…");
                cx.notify();
            }
            WebSocketEvent::Membership(signal) => {
                self.record_membership_activity(&signal);
                self.handle_membership_signal(&signal, cx);
            }
        }
    }

    pub(super) fn stop_websocket(&mut self) {
        if self.ws_task.is_some() {
            info!("Stopping WebSocket connection");
            self.ws_task = None;
            self.ws_connected = false;
        }
    }
}
