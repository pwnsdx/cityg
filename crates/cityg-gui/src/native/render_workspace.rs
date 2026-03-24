use super::*;

impl AppModel {
    pub(super) fn render_workspace_sidebar(
        &self,
        session: &AppSession,
        cx: &mut ViewContext<Self>,
    ) -> Div {
        let members_total = self.members_total.max(self.members.len() as u64);
        let ws_state = if self.ws_connected {
            ("Live updates", UI_ACCENT_TEXT)
        } else {
            ("Polling mode", UI_SUBTLE_TEXT)
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
        let mut copy_room_button = div()
            .px(px(10.0))
            .py(px(6.0))
            .rounded(px(10.0))
            .bg(ui_button_fill(self.window_active))
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(UI_PANEL_TEXT))
            .cursor(CursorStyle::PointingHand)
            .child("Copy room ID");
        copy_room_button =
            copy_room_button.on_mouse_down(MouseButton::Left, cx.listener(Self::on_copy_room_id));
        let mut copy_invite_button = div()
            .px(px(10.0))
            .py(px(6.0))
            .rounded(px(10.0))
            .bg(ui_button_fill(self.window_active))
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(UI_PANEL_TEXT))
            .cursor(CursorStyle::PointingHand)
            .child("Copy invite");
        copy_invite_button = copy_invite_button
            .on_mouse_down(MouseButton::Left, cx.listener(Self::on_copy_room_invite));

        div()
            .flex()
            .flex_col()
            .gap(px(12.0))
            .px(px(14.0))
            .py(px(14.0))
            .rounded(px(14.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .bg(ui_sidebar_fill(self.window_active))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(4.0))
                    .child(
                        div()
                            .text_size(px(17.0))
                            .font_weight(FontWeight::BOLD)
                            .text_color(rgb(UI_PANEL_TEXT))
                            .child("City-G"),
                    )
                    .child(
                        div()
                            .text_size(px(12.0))
                            .text_color(rgb(UI_SUBTLE_TEXT))
                            .child("Workspace"),
                    ),
            )
            .child(
                div()
                    .px(px(10.0))
                    .py(px(8.0))
                    .rounded(px(10.0))
                    .bg(ui_row_fill(self.window_active))
                    .child(
                        div()
                            .text_size(px(11.0))
                            .text_color(rgb(UI_MUTED_TEXT))
                            .child("Room"),
                    )
                    .child(
                        div()
                            .text_size(px(13.0))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(UI_PANEL_TEXT))
                            .child(format!("#{}", room_preview)),
                    ),
            )
            .child(
                div()
                    .flex()
                    .gap(px(8.0))
                    .child(copy_room_button)
                    .child(copy_invite_button),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(6.0))
                    .child(
                        div()
                            .text_size(px(12.0))
                            .text_color(rgb(ws_state.1))
                            .child(ws_state.0),
                    )
                    .child(
                        div()
                            .text_size(px(12.0))
                            .text_color(rgb(UI_SUBTLE_TEXT))
                            .child(format!("Alias: {}", session.alias)),
                    )
                    .child(
                        div()
                            .text_size(px(12.0))
                            .text_color(rgb(UI_SUBTLE_TEXT))
                            .child(format!("Members: {}/{}", self.members.len(), members_total)),
                    )
                    .child(
                        div()
                            .text_size(px(11.0))
                            .text_color(rgb(UI_MUTED_TEXT))
                            .child(session.server_url.clone()),
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
        let status_text = format!("{} • {}", ws_state, fetch_state);
        let status_color = if matches!(self.fetch_status, FetchStatus::Refreshing) {
            rgb(UI_ACCENT_TEXT)
        } else {
            rgb(UI_SUBTLE_TEXT)
        };

        let mut toggle_ciphertext = div()
            .px(px(12.0))
            .py(px(7.0))
            .rounded(px(10.0))
            .bg(rgb(UI_ACCENT_TEXT))
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(UI_ACCENT_BUTTON_TEXT))
            .cursor(CursorStyle::PointingHand)
            .child(if self.show_ciphertext {
                "Hide ciphertext"
            } else {
                "Show ciphertext"
            });
        toggle_ciphertext = toggle_ciphertext
            .on_mouse_down(MouseButton::Left, cx.listener(Self::on_toggle_ciphertext));

        div()
            .flex()
            .items_center()
            .justify_between()
            .px(px(16.0))
            .py(px(12.0))
            .rounded(px(14.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .bg(ui_panel_fill(self.window_active))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(4.0))
                    .child(
                        div()
                            .text_size(px(21.0))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(UI_PANEL_TEXT))
                            .child(format!("# {}", room_label)),
                    )
                    .child(
                        div()
                            .text_size(px(12.0))
                            .text_color(status_color)
                            .child(status_text),
                    ),
            )
            .child(toggle_ciphertext)
    }
}
