use super::*;

impl AppModel {
    pub(super) fn render_workspace_sidebar(
        &self,
        session: &AppSession,
        cx: &mut ViewContext<Self>,
    ) -> Div {
        let members_total = self.members_total.max(self.members.len() as u64);
        let (ws_label, ws_bg, ws_text) = if self.ws_connected {
            ("Live sync", rgb(0x20372a), rgb(UI_SUCCESS_TEXT))
        } else {
            ("Polling", rgb(0x2b3038), rgb(UI_INFO_TEXT))
        };
        let room_preview = if session.room_id.len() > 20 {
            format!(
                "{}…{}",
                &session.room_id[..12],
                &session.room_id[session.room_id.len().saturating_sub(6)..]
            )
        } else {
            session.room_id.clone()
        };
        let button_fill = ui_button_fill(self.window_active);
        let copy_room_hover_fill = ui_hover_fill(self.window_active);
        let copy_invite_hover_fill = ui_hover_fill(self.window_active);
        let mut copy_room_button = div()
            .px(px(10.0))
            .py(px(7.0))
            .rounded(px(11.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .bg(button_fill)
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(UI_PANEL_TEXT))
            .cursor(CursorStyle::PointingHand)
            .hover(move |style| style.bg(copy_room_hover_fill))
            .child("Copy room ID");
        copy_room_button =
            copy_room_button.on_mouse_down(MouseButton::Left, cx.listener(Self::on_copy_room_id));
        let mut copy_invite_button = div()
            .px(px(10.0))
            .py(px(7.0))
            .rounded(px(11.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .bg(button_fill)
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(UI_PANEL_TEXT))
            .cursor(CursorStyle::PointingHand)
            .hover(move |style| style.bg(copy_invite_hover_fill))
            .child("Copy invite");
        copy_invite_button = copy_invite_button
            .on_mouse_down(MouseButton::Left, cx.listener(Self::on_copy_room_invite));

        div()
            .flex()
            .flex_col()
            .gap(px(12.0))
            .px(px(16.0))
            .py(px(16.0))
            .rounded(px(18.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .bg(ui_sidebar_fill(self.window_active))
            .shadow_md()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(6.0))
                    .child(
                        div()
                            .px(px(10.0))
                            .py(px(4.0))
                            .rounded(px(999.0))
                            .bg(ws_bg)
                            .text_size(px(11.0))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(ws_text)
                            .child(ws_label),
                    )
                    .child(
                        div()
                            .text_size(px(18.0))
                            .font_weight(FontWeight::BOLD)
                            .text_color(rgb(UI_PANEL_TEXT))
                            .child("City-G"),
                    )
                    .child(
                        div()
                            .text_size(px(12.0))
                            .text_color(rgb(UI_SUBTLE_TEXT))
                            .child("Secure room workspace"),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(6.0))
                    .px(px(12.0))
                    .py(px(12.0))
                    .rounded(px(16.0))
                    .border(px(1.0))
                    .border_color(rgb(UI_ACCENT_TEXT))
                    .bg(ui_sidebar_selected_fill(self.window_active))
                    .shadow_sm()
                    .child(
                        div()
                            .text_size(px(11.0))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(UI_INFO_TEXT))
                            .child("Current room"),
                    )
                    .child(
                        div()
                            .text_size(px(14.0))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(UI_PANEL_TEXT))
                            .child(format!("#{}", room_preview)),
                    )
                    .child(
                        div()
                            .text_size(px(11.0))
                            .text_color(rgb(UI_SUBTLE_TEXT))
                            .truncate()
                            .child(session.server_url.clone()),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap(px(8.0))
                    .child(copy_room_button)
                    .child(copy_invite_button),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(8.0))
                    .child(
                        div()
                            .text_size(px(11.0))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(UI_MUTED_TEXT))
                            .child("Session"),
                    )
                    .child(
                        div()
                            .px(px(10.0))
                            .py(px(8.0))
                            .rounded(px(12.0))
                            .bg(ui_row_fill(self.window_active))
                            .text_size(px(12.0))
                            .text_color(rgb(UI_PANEL_TEXT))
                            .child(format!("Alias: {}", session.alias)),
                    )
                    .child(
                        div()
                            .px(px(10.0))
                            .py(px(8.0))
                            .rounded(px(12.0))
                            .bg(ui_row_fill(self.window_active))
                            .text_size(px(12.0))
                            .text_color(rgb(UI_PANEL_TEXT))
                            .child(format!("Members: {}/{}", self.members.len(), members_total)),
                    )
                    .child(
                        div()
                            .px(px(10.0))
                            .py(px(8.0))
                            .rounded(px(12.0))
                            .bg(ui_row_fill(self.window_active))
                            .text_size(px(12.0))
                            .text_color(rgb(UI_PANEL_TEXT))
                            .child(if self.show_ciphertext {
                                "Ciphertext mode enabled"
                            } else {
                                "Plaintext mode enabled"
                            }),
                    ),
            )
    }

    pub(super) fn render_chat_header(
        &self,
        session: &AppSession,
        cx: &mut ViewContext<Self>,
    ) -> Div {
        let room_label = if session.room_id.len() > 28 {
            format!(
                "{}…{}",
                &session.room_id[..16],
                &session.room_id[session.room_id.len().saturating_sub(8)..]
            )
        } else {
            session.room_id.clone()
        };
        let ws_state = if self.ws_connected {
            "WebSocket live"
        } else {
            "Polling fallback"
        };
        let fetch_state = match self.fetch_status {
            FetchStatus::Idle => "Idle",
            FetchStatus::Refreshing => "Refreshing",
        };
        let button_fill = ui_button_fill(self.window_active);
        let toggle_hover_fill = ui_hover_fill(self.window_active);
        let overview_hover_fill = ui_hover_fill(self.window_active);
        let status_chip = |label: &str, bg: u32, fg: u32| {
            div()
                .px(px(10.0))
                .py(px(4.0))
                .rounded(px(999.0))
                .bg(rgb(bg))
                .text_size(px(11.0))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(rgb(fg))
                .child(label.to_string())
        };

        let mut toggle_ciphertext = div()
            .px(px(12.0))
            .py(px(8.0))
            .rounded(px(11.0))
            .border(px(1.0))
            .border_color(if self.show_ciphertext {
                rgb(UI_ACCENT_TEXT)
            } else {
                rgb(UI_PANEL_BORDER)
            })
            .bg(if self.show_ciphertext {
                rgba(0x5fb2ffe8)
            } else {
                button_fill
            })
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(if self.show_ciphertext {
                rgb(UI_ACCENT_BUTTON_TEXT)
            } else {
                rgb(UI_PANEL_TEXT)
            })
            .cursor(CursorStyle::PointingHand)
            .hover(move |style| style.bg(toggle_hover_fill))
            .child(if self.show_ciphertext {
                "Hide ciphertext"
            } else {
                "Show ciphertext"
            });
        toggle_ciphertext = toggle_ciphertext
            .on_mouse_down(MouseButton::Left, cx.listener(Self::on_toggle_ciphertext));

        let overview_button = div()
            .px(px(12.0))
            .py(px(8.0))
            .rounded(px(11.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .bg(button_fill)
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(UI_PANEL_TEXT))
            .cursor(CursorStyle::PointingHand)
            .hover(move |style| style.bg(overview_hover_fill))
            .child("Session overview")
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(Self::on_show_session_overview_clicked),
            );

        div()
            .flex()
            .items_center()
            .justify_between()
            .px(px(16.0))
            .py(px(14.0))
            .rounded(px(18.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .bg(ui_toolbar_fill(self.window_active))
            .shadow_sm()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(6.0))
                    .child(
                        div()
                            .text_size(px(11.0))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(UI_MUTED_TEXT))
                            .child("Messages"),
                    )
                    .child(
                        div()
                            .text_size(px(22.0))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(UI_PANEL_TEXT))
                            .child(format!("# {}", room_label)),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .gap(px(8.0))
                            .child(status_chip(
                                ws_state,
                                if self.ws_connected {
                                    0x20372a
                                } else {
                                    0x2b3038
                                },
                                if self.ws_connected {
                                    UI_SUCCESS_TEXT
                                } else {
                                    UI_INFO_TEXT
                                },
                            ))
                            .child(status_chip(
                                fetch_state,
                                if matches!(self.fetch_status, FetchStatus::Refreshing) {
                                    UI_ACCENT_SOFT_FILL
                                } else {
                                    UI_NEUTRAL_ELEVATED_FILL
                                },
                                if matches!(self.fetch_status, FetchStatus::Refreshing) {
                                    UI_ACCENT_TEXT
                                } else {
                                    UI_SUBTLE_TEXT
                                },
                            )),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(8.0))
                    .child(overview_button)
                    .child(toggle_ciphertext),
            )
    }
}
