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
                    self.info_message = Some(Self::barrier_recovery_message_for_session(&session));
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

                if let Some(session) = self.session.as_mut() {
                    let mut updated_session = session.clone();
                    let mut should_persist = false;
                    if updated_session.msg_replay_state != msg_replay_state {
                        updated_session.msg_replay_state = msg_replay_state;
                        should_persist = true;
                    }
                    if let Some(ts) = last_timestamp_ms {
                        let timestamp_changed = updated_session
                            .last_fetch_timestamp_ms
                            .map(|prev| ts > prev)
                            .unwrap_or(true);
                        if timestamp_changed {
                            updated_session.last_fetch_timestamp_ms = Some(ts);
                            should_persist = true;
                        }
                    }
                    if should_persist {
                        if let Err(err) = persist_replay_progress(
                            &updated_session.server_url,
                            &updated_session.room_id,
                            updated_session.last_fetch_timestamp_ms,
                            &updated_session.msg_replay_state,
                        ) {
                            warn!("failed to persist replay progress after fetch update: {err:?}");
                            self.last_error = Some(format!(
                                "Failed to persist replay progress after fetch update: {err}"
                            ));
                            self.record_activity_with_detail(
                                ActivityKind::Message,
                                "Message fetch persistence failed",
                                Some(err.to_string()),
                            );
                            self.fetch_status = FetchStatus::Idle;
                            self.config.client.fetch_retry_interval()
                        } else {
                            *session = updated_session;
                            if !messages.is_empty() {
                                let added = self.append_messages(messages);
                                if added > 0 {
                                    self.info_message =
                                        Some(format!("Fetched {added} new message(s)."));
                                    self.record_activity(
                                        ActivityKind::Message,
                                        format!("Fetched {added} new message(s)"),
                                    );
                                    self.notify_background_messages(added);
                                }
                            }
                            self.fetch_status = FetchStatus::Idle;
                            self.config.client.fetch_poll_interval()
                        }
                    } else {
                        if !messages.is_empty() {
                            let added = self.append_messages(messages);
                            if added > 0 {
                                self.info_message =
                                    Some(format!("Fetched {added} new message(s)."));
                                self.record_activity(
                                    ActivityKind::Message,
                                    format!("Fetched {added} new message(s)"),
                                );
                                self.notify_background_messages(added);
                            }
                        }
                        self.fetch_status = FetchStatus::Idle;
                        self.config.client.fetch_poll_interval()
                    }
                } else {
                    self.fetch_status = FetchStatus::Idle;
                    self.config.client.fetch_poll_interval()
                }
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
}
