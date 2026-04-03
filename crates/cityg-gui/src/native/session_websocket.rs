use futures::{StreamExt, channel::mpsc as futures_mpsc};

use super::websocket::{WebSocketEvent, run_websocket_worker};
use super::*;
use crate::websocket_replay::websocket_room_url;

impl AppModel {
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

    pub(super) fn start_websocket(&mut self, cx: &mut ViewContext<Self>) {
        self.ws_autostart_attempted = true;
        let Some(session) = &self.session else {
            return;
        };
        let Some(message_token) = configured_client_message_token() else {
            warn!("message auth token is not configured; skipping websocket startup");
            return;
        };

        let ws_url = websocket_room_url(&session.server_url, &session.gid, &session.leaf_id);
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
            WebSocketEvent::Message(signal) => {
                self.record_websocket_message_activity(&signal);
                self.fetch_after_epoch_sync = true;
                let reason = if signal.replayed {
                    "Syncing latest epoch after replayed message notification…"
                } else {
                    "Syncing latest epoch after message notification…"
                };
                self.schedule_epoch_sync(cx, reason);
                cx.notify();
            }
            WebSocketEvent::Membership(signal) => {
                self.record_membership_activity(&signal);
                self.handle_membership_signal(&signal, cx);
            }
            WebSocketEvent::SyncRequired(signal) => {
                self.record_websocket_sync_required_activity(&signal);
                self.fetch_after_epoch_sync = true;
                let reason = match signal.reason.as_deref() {
                    Some("replay_window_exhausted") => {
                        "Worker replay window exhausted; reconciling latest room state…"
                    }
                    _ => "WebSocket requested room reconciliation…",
                };
                self.schedule_epoch_sync(cx, reason);
                cx.notify();
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
