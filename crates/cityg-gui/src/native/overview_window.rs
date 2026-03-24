use super::app_actions::ShowSessionOverviewAction;
use super::*;

pub(super) struct SessionOverviewWindow {
    app_model: Entity<AppModel>,
    session: Option<AppSession>,
    window_active: bool,
}

impl SessionOverviewWindow {
    pub(super) fn new(app_model: Entity<AppModel>) -> Self {
        Self {
            app_model,
            session: None,
            window_active: false,
        }
    }

    fn session_row(&self, label: &str, value: &str) -> Div {
        div()
            .flex()
            .flex_col()
            .gap(px(3.0))
            .px(px(10.0))
            .py(px(8.0))
            .rounded(px(10.0))
            .bg(ui_row_fill(self.window_active))
            .child(
                div()
                    .text_size(px(11.0))
                    .text_color(rgb(UI_MUTED_TEXT))
                    .child(label.to_string()),
            )
            .child(
                div()
                    .text_size(px(13.0))
                    .text_color(rgb(UI_PANEL_TEXT))
                    .child(value.to_string()),
            )
    }

    fn render_copyable_row(
        &self,
        label: &str,
        value: &str,
        handler: fn(&mut Self, &MouseDownEvent, &mut Window, &mut ViewContext<Self>),
        cx: &mut ViewContext<Self>,
    ) -> Div {
        div()
            .flex()
            .flex_col()
            .gap(px(4.0))
            .px(px(10.0))
            .py(px(8.0))
            .rounded(px(10.0))
            .bg(ui_row_fill(self.window_active))
            .child(
                div()
                    .text_size(px(11.0))
                    .text_color(rgb(UI_MUTED_TEXT))
                    .child(label.to_string()),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap(px(8.0))
                    .child(
                        div()
                            .flex_grow()
                            .text_size(px(13.0))
                            .text_color(rgb(UI_PANEL_TEXT))
                            .child(value.to_string()),
                    )
                    .child(
                        div()
                            .px(px(10.0))
                            .py(px(6.0))
                            .rounded(px(10.0))
                            .text_size(px(12.0))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(rgb(UI_ACCENT_BUTTON_TEXT))
                            .bg(rgb(UI_ACCENT_TEXT))
                            .cursor(CursorStyle::PointingHand)
                            .child("Copy")
                            .on_mouse_down(MouseButton::Left, cx.listener(handler)),
                    ),
            )
    }

    fn render_fingerprint_row(
        &self,
        label: &str,
        value: String,
        copy_enabled: bool,
        handler: fn(&mut Self, &MouseDownEvent, &mut Window, &mut ViewContext<Self>),
        cx: &mut ViewContext<Self>,
    ) -> Div {
        let mut copy_button = div()
            .px(px(10.0))
            .py(px(6.0))
            .rounded(px(10.0))
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(if copy_enabled {
                rgb(UI_ACCENT_BUTTON_TEXT)
            } else {
                rgb(UI_MUTED_TEXT)
            })
            .bg(if copy_enabled {
                rgb(UI_ACCENT_TEXT)
            } else {
                ui_button_fill(self.window_active)
            })
            .cursor(if copy_enabled {
                CursorStyle::PointingHand
            } else {
                CursorStyle::Arrow
            })
            .child("Copy");

        if copy_enabled {
            copy_button = copy_button.on_mouse_down(MouseButton::Left, cx.listener(handler));
        }

        div()
            .flex()
            .flex_col()
            .gap(px(4.0))
            .px(px(10.0))
            .py(px(8.0))
            .rounded(px(10.0))
            .bg(ui_row_fill(self.window_active))
            .child(
                div()
                    .text_size(px(11.0))
                    .text_color(rgb(UI_MUTED_TEXT))
                    .child(label.to_string()),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap(px(8.0))
                    .child(
                        div()
                            .flex_grow()
                            .text_size(px(13.0))
                            .text_color(rgb(UI_PANEL_TEXT))
                            .child(value),
                    )
                    .child(copy_button),
            )
    }

    fn render_epoch_age_row(&self, session: &AppSession) -> Div {
        let epoch_age_secs = SystemTime::now()
            .duration_since(session.fs_epoch_created_at)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        let rotation_interval = session.fs_epoch_rotation_interval_secs;

        let age_text = if epoch_age_secs < 60 {
            format!("{} seconds", epoch_age_secs)
        } else if epoch_age_secs < 3600 {
            format!("{} minutes", epoch_age_secs / 60)
        } else {
            format!("{:.1} hours", epoch_age_secs as f64 / 3600.0)
        };

        let value_text = format!(
            "Epoch #{} - Age: {} (manual rekey target: {}s)",
            session.fs_ec, age_text, rotation_interval
        );

        self.session_row("Forward Secrecy Epoch", &value_text)
    }

    fn render_overview_panel(&self, session: &AppSession, cx: &mut ViewContext<Self>) -> Div {
        div()
            .flex()
            .flex_col()
            .gap(px(8.0))
            .px(px(12.0))
            .py(px(12.0))
            .rounded(px(14.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .bg(ui_panel_fill(self.window_active))
            .child(
                div()
                    .text_size(px(16.0))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(UI_PANEL_TEXT))
                    .child("Session overview"),
            )
            .child(self.session_row("Server", &session.server_url))
            .child(self.render_copyable_row("Room ID", &session.room_id, Self::on_copy_room_id, cx))
            .child(self.session_row("Alias", &session.alias))
            .child(self.render_copyable_row(
                "Room identity",
                &room_admin_identity_preview(&session.pop_public_key),
                Self::on_copy_room_identity,
                cx,
            ))
            .child(self.session_row("WEID", &hex_encode(session.we_epoch_id)))
            .child(self.session_row("Epoch key", &hex_encode(session.epoch_key)))
            .child(self.session_row("Parent root", &hex_encode(session.parent_root)))
            .child(self.session_row("Join delta", &hex_encode(session.join_delta_root)))
            .child(self.session_row("Revoked since", &hex_encode(session.revoked_since_root)))
            .child(self.session_row("Revoked root", &hex_encode(session.revoked_root)))
            .child(self.render_fingerprint_row(
                "Regular fingerprint",
                format_regular_fingerprint(session.regular_fingerprint.as_ref()),
                session.regular_fingerprint.is_some(),
                Self::on_copy_regular_fingerprint,
                cx,
            ))
            .child(self.render_fingerprint_row(
                "FS fingerprint",
                format_fs_fingerprint(session.fs_fingerprint.as_ref(), session.fs_ec),
                session.fs_fingerprint.is_some(),
                Self::on_copy_fs_fingerprint,
                cx,
            ))
            .child(self.session_row("Proof mode", &session.proof_mode))
            .child(self.session_row("VRF suite", &session.vrf_id))
            .child(self.session_row("Policy", &session.policy_version))
            .child(self.session_row("FS policy", &session.fs_policy_version))
            .child(self.render_epoch_age_row(session))
            .child(self.session_row("KBROAD key (hex)", &hex_encode(&session.kbroad_public)))
    }

    fn on_copy_room_id(&mut self, _: &MouseDownEvent, _: &mut Window, cx: &mut ViewContext<Self>) {
        if let Some(session) = &self.session {
            cx.write_to_clipboard(ClipboardItem::new_string(session.room_id.clone()));
        }
    }

    fn on_copy_room_identity(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if let Some(session) = &self.session {
            cx.write_to_clipboard(ClipboardItem::new_string(hex_encode(
                &session.pop_public_key,
            )));
        }
    }

    fn on_copy_regular_fingerprint(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if let Some(session) = &self.session
            && let Some(bytes) = session.regular_fingerprint
        {
            cx.write_to_clipboard(ClipboardItem::new_string(fingerprint_full_hex(&bytes)));
        }
    }

    fn on_copy_fs_fingerprint(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if let Some(session) = &self.session
            && let Some(bytes) = session.fs_fingerprint
        {
            cx.write_to_clipboard(ClipboardItem::new_string(fingerprint_full_hex(&bytes)));
        }
    }
}

impl Render for SessionOverviewWindow {
    fn render(&mut self, _window: &mut Window, cx: &mut ViewContext<Self>) -> impl IntoElement {
        self.session = self.app_model.read(cx).session.clone();
        let session = self.session.clone();

        let content = if let Some(session) = session {
            div()
                .flex()
                .flex_col()
                .flex_grow()
                .min_h(px(0.0))
                .gap(px(12.0))
                .child(self.render_overview_panel(&session, cx))
        } else {
            div()
                .flex()
                .items_center()
                .justify_center()
                .flex_grow()
                .rounded(px(14.0))
                .border(px(1.0))
                .border_color(rgb(UI_PANEL_BORDER))
                .bg(ui_panel_fill(self.window_active))
                .child(
                    div()
                        .text_size(px(14.0))
                        .text_color(rgb(UI_SUBTLE_TEXT))
                        .child("No active session."),
                )
        };

        div()
            .flex()
            .flex_col()
            .w_full()
            .h_full()
            .px(px(16.0))
            .py(px(16.0))
            .bg(ui_canvas_fill(self.window_active))
            .child(content)
    }
}

impl AppModel {
    pub(super) fn on_show_session_overview_clicked(
        &mut self,
        _: &MouseDownEvent,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.open_session_overview_window(window, cx);
    }

    pub(super) fn on_show_session_overview_action(
        &mut self,
        _: &ShowSessionOverviewAction,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.open_session_overview_window(window, cx);
    }

    fn open_session_overview_window(&mut self, _window: &mut Window, cx: &mut ViewContext<Self>) {
        if self.session.is_none() {
            self.show_info("Join a room to view the session overview.", cx);
            return;
        }

        if let Some(handle) = self.session_overview_window {
            if handle
                .update(cx, |_, window, _| {
                    window.activate_window();
                })
                .is_ok()
            {
                return;
            }
            self.session_overview_window = None;
        }

        let overview_bounds = Bounds::centered(None, size(px(460.0), px(840.0)), cx);
        let window_options = WindowOptions {
            titlebar: Some(TitlebarOptions {
                title: Some("Session Overview".into()),
                appears_transparent: true,
                traffic_light_position: Some(point(px(12.0), px(12.0))),
            }),
            window_decorations: Some(WindowDecorations::Client),
            window_background: WindowBackgroundAppearance::Blurred,
            window_bounds: Some(WindowBounds::Windowed(overview_bounds)),
            ..Default::default()
        };
        let app_model = cx.entity();

        match cx.open_window(window_options, move |window, cx| {
            let entity = cx.new(|_| SessionOverviewWindow::new(app_model.clone()));

            let _ = entity.update(cx, |overview, cx| {
                overview.window_active = window.is_window_active();
                cx.observe_window_activation(window, |overview, window, cx| {
                    overview.window_active = window.is_window_active();
                    cx.notify();
                })
                .detach();
            });

            entity
        }) {
            Ok(handle) => {
                self.session_overview_window = Some(handle.into());
            }
            Err(err) => {
                self.show_error_toast(format!("Failed to open session overview window: {err}"), cx);
            }
        }
    }
}
