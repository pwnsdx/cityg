use futures::{StreamExt, channel::mpsc as futures_mpsc};

use super::websocket::{WebSocketEvent, run_websocket_worker};
use super::*;

impl AppModel {
    pub(super) fn ensure_websocket_task(&mut self, cx: &mut ViewContext<Self>) {
        if self.session.is_none() {
            self.stop_websocket();
            self.ws_autostart_attempted = false;
            return;
        }

        if self.ws_task.is_none() && !self.ws_autostart_attempted {
            self.ws_autostart_attempted = true;
            self.start_websocket(cx);
        }
    }

    pub(super) fn start_websocket(&mut self, cx: &mut ViewContext<Self>) {
        self.ws_autostart_attempted = true;
        let Some(session) = &self.session else {
            return;
        };
        let member = session.member.clone();
        let reconnect_delay = self.config.client.websocket_reconnect_delay();

        let this = cx.weak_entity();
        let (event_tx, mut event_rx) = futures_mpsc::unbounded::<WebSocketEvent>();
        let task = cx.spawn(async move |_, cx| {
            let runner = match Tokio::spawn_result(
                cx,
                run_websocket_worker(member, reconnect_delay, event_tx),
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
                self.schedule_fetch(cx, Duration::from_millis(0));
            }
            WebSocketEvent::Disconnected => {
                self.ws_connected = false;
                self.record_activity(
                    ActivityKind::Connection,
                    "WebSocket disconnected (falling back to polling)",
                );
            }
            WebSocketEvent::Head(head_seq) => {
                let behind = self
                    .session
                    .as_ref()
                    .is_some_and(|session| head_seq > session.view.log_seq);
                if behind {
                    self.schedule_fetch(cx, Duration::from_millis(0));
                }
            }
            WebSocketEvent::Resync => {
                self.record_activity(
                    ActivityKind::Connection,
                    "Live updates lagged; refetching the room log",
                );
                self.schedule_fetch(cx, Duration::from_millis(0));
            }
        }
        cx.notify();
    }

    pub(super) fn stop_websocket(&mut self) {
        if self.ws_task.is_some() {
            info!("Stopping WebSocket connection");
            self.ws_task = None;
            self.ws_connected = false;
        }
    }
}
