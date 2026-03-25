use super::*;
use gpui::MaterialVariant;

impl AppModel {
    pub(super) fn render_workspace_sidebar(
        &self,
        session: &AppSession,
        window: &Window,
        cx: &mut ViewContext<Self>,
    ) -> impl IntoElement {
        let members_total = self.members_total.max(self.members.len() as u64);
        let room_preview = if session.room_id.len() > 20 {
            format!(
                "{}…{}",
                &session.room_id[..12],
                &session.room_id[session.room_id.len().saturating_sub(6)..]
            )
        } else {
            session.room_id.clone()
        };
        let transport_label = if self.ws_connected {
            "Live sync"
        } else {
            "Polling fallback"
        };
        let transport_fill = if self.ws_connected {
            rgb(0x20372a)
        } else {
            rgb(0x2b3038)
        };
        let transport_text = if self.ws_connected {
            rgb(UI_SUCCESS_TEXT)
        } else {
            rgb(UI_INFO_TEXT)
        };
        let section_fill = ui_row_fill(self.window_active);
        let hover_fill = ui_hover_fill(self.window_active);

        let mut copy_room_button = div()
            .flex()
            .items_center()
            .justify_between()
            .gap(px(10.0))
            .px(px(10.0))
            .py(px(8.0))
            .rounded(px(11.0))
            .text_size(px(12.0))
            .text_color(rgb(UI_PANEL_TEXT))
            .cursor(CursorStyle::PointingHand)
            .hover(move |style| style.bg(hover_fill))
            .child("Copy room ID")
            .child(
                div()
                    .text_size(px(11.0))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(UI_ACCENT_TEXT))
                    .child("Copy"),
            );
        copy_room_button =
            copy_room_button.on_mouse_down(MouseButton::Left, cx.listener(Self::on_copy_room_id));

        let action_hover_fill = ui_hover_fill(self.window_active);
        let mut copy_invite_button = div()
            .flex()
            .items_center()
            .justify_between()
            .gap(px(10.0))
            .px(px(10.0))
            .py(px(8.0))
            .rounded(px(11.0))
            .text_size(px(12.0))
            .text_color(rgb(UI_PANEL_TEXT))
            .cursor(CursorStyle::PointingHand)
            .hover(move |style| style.bg(action_hover_fill))
            .child("Copy invite")
            .child(
                div()
                    .text_size(px(11.0))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(UI_ACCENT_TEXT))
                    .child("Copy"),
            );
        copy_invite_button = copy_invite_button
            .on_mouse_down(MouseButton::Left, cx.listener(Self::on_copy_room_invite));

        let section_header = |label: &str| {
            div()
                .px(px(10.0))
                .text_size(px(10.0))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(rgb(UI_MUTED_TEXT))
                .child(label.to_string())
        };

        material_surface(
            window,
            MaterialStyle::sidebar().emphasis(MaterialEmphasis::High),
        )
        .flex()
        .flex_col()
        .gap(px(14.0))
        .px(px(10.0))
        .py(px(12.0))
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .px(px(10.0))
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap(px(3.0))
                        .child(
                            div()
                                .text_size(px(17.0))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(UI_PANEL_TEXT))
                                .child("City-G"),
                        )
                        .child(
                            div()
                                .text_size(px(11.0))
                                .text_color(rgb(UI_SUBTLE_TEXT))
                                .child("Secure room workspace"),
                        ),
                )
                .child(
                    div()
                        .px(px(9.0))
                        .py(px(4.0))
                        .rounded(px(999.0))
                        .bg(transport_fill)
                        .text_size(px(11.0))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(transport_text)
                        .child(transport_label),
                ),
        )
        .child(section_header("ROOM"))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(6.0))
                .px(px(10.0))
                .py(px(10.0))
                .rounded(px(14.0))
                .bg(ui_sidebar_selected_fill(self.window_active))
                .child(
                    div()
                        .text_size(px(13.0))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(UI_PANEL_TEXT))
                        .child(format!("# {}", room_preview)),
                )
                .child(
                    div()
                        .text_size(px(11.0))
                        .text_color(rgb(UI_SUBTLE_TEXT))
                        .truncate()
                        .child(session.server_url.clone()),
                ),
        )
        .child(section_header("SESSION"))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(4.0))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .px(px(10.0))
                        .py(px(8.0))
                        .rounded(px(11.0))
                        .bg(section_fill)
                        .child(
                            div()
                                .text_size(px(11.0))
                                .text_color(rgb(UI_MUTED_TEXT))
                                .child("Alias"),
                        )
                        .child(
                            div()
                                .text_size(px(12.0))
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(rgb(UI_PANEL_TEXT))
                                .child(session.alias.clone()),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .px(px(10.0))
                        .py(px(8.0))
                        .rounded(px(11.0))
                        .bg(section_fill)
                        .child(
                            div()
                                .text_size(px(11.0))
                                .text_color(rgb(UI_MUTED_TEXT))
                                .child("Members"),
                        )
                        .child(
                            div()
                                .text_size(px(12.0))
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(rgb(UI_PANEL_TEXT))
                                .child(format!("{}/{}", self.members.len(), members_total)),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .px(px(10.0))
                        .py(px(8.0))
                        .rounded(px(11.0))
                        .bg(section_fill)
                        .child(
                            div()
                                .text_size(px(11.0))
                                .text_color(rgb(UI_MUTED_TEXT))
                                .child("Messages"),
                        )
                        .child(
                            div()
                                .text_size(px(12.0))
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(rgb(UI_PANEL_TEXT))
                                .child(if self.show_ciphertext {
                                    "Ciphertext"
                                } else {
                                    "Plaintext"
                                }),
                        ),
                ),
        )
        .child(section_header("SHARE"))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(2.0))
                .rounded(px(14.0))
                .bg(section_fill)
                .child(copy_room_button)
                .child(copy_invite_button),
        )
    }

    pub(super) fn render_chat_header(
        &self,
        session: &AppSession,
        window: &Window,
        window_width: f32,
        cx: &mut ViewContext<Self>,
    ) -> impl IntoElement {
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
        let sidebar_open = self.resolved_sidebar_width(window_width).is_some();
        let sidebar_available = Self::available_sidebar_width_for_window(window_width).is_some();
        let inspector_open = self.resolved_inspector_width(window_width).is_some();
        let inspector_available = Self::available_inspector_width_for_window(
            window_width,
            self.resolved_sidebar_width(window_width),
        )
        .is_some();
        let toolbar_fill = ui_button_fill(self.window_active);
        let toolbar_hover_fill = ui_hover_fill(self.window_active);
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

        let mut sidebar_button = div()
            .px(px(10.0))
            .py(px(7.0))
            .rounded(px(10.0))
            .bg(if sidebar_open {
                rgba(0x5fb2ffe8)
            } else {
                toolbar_fill
            })
            .border(px(1.0))
            .border_color(if sidebar_open {
                rgb(UI_ACCENT_TEXT)
            } else {
                rgb(UI_PANEL_BORDER)
            })
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(if sidebar_open {
                rgb(UI_ACCENT_BUTTON_TEXT)
            } else if sidebar_available {
                rgb(UI_PANEL_TEXT)
            } else {
                rgb(UI_MUTED_TEXT)
            })
            .cursor(CursorStyle::PointingHand)
            .hover(move |style| style.bg(toolbar_hover_fill))
            .child(if sidebar_open {
                "Hide sidebar"
            } else if sidebar_available {
                "Show sidebar"
            } else {
                "Widen for sidebar"
            });
        sidebar_button = sidebar_button.on_mouse_down(
            MouseButton::Left,
            cx.listener(Self::on_toggle_sidebar_clicked),
        );

        let inspector_hover_fill = ui_hover_fill(self.window_active);
        let mut inspector_button = div()
            .px(px(10.0))
            .py(px(7.0))
            .rounded(px(10.0))
            .bg(if inspector_open {
                rgba(0x5fb2ffe8)
            } else {
                toolbar_fill
            })
            .border(px(1.0))
            .border_color(if inspector_open {
                rgb(UI_ACCENT_TEXT)
            } else {
                rgb(UI_PANEL_BORDER)
            })
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(if inspector_open {
                rgb(UI_ACCENT_BUTTON_TEXT)
            } else if inspector_available {
                rgb(UI_PANEL_TEXT)
            } else {
                rgb(UI_MUTED_TEXT)
            })
            .cursor(CursorStyle::PointingHand)
            .hover(move |style| style.bg(inspector_hover_fill))
            .child(if inspector_open {
                "Hide inspector"
            } else if inspector_available {
                "Show inspector"
            } else {
                "Widen for inspector"
            });
        inspector_button = inspector_button.on_mouse_down(
            MouseButton::Left,
            cx.listener(Self::on_show_session_overview_clicked),
        );

        let ciphertext_hover_fill = ui_hover_fill(self.window_active);
        let mut ciphertext_button = div()
            .px(px(10.0))
            .py(px(7.0))
            .rounded(px(10.0))
            .bg(if self.show_ciphertext {
                rgba(0x5fb2ffe8)
            } else {
                toolbar_fill
            })
            .border(px(1.0))
            .border_color(if self.show_ciphertext {
                rgb(UI_ACCENT_TEXT)
            } else {
                rgb(UI_PANEL_BORDER)
            })
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(if self.show_ciphertext {
                rgb(UI_ACCENT_BUTTON_TEXT)
            } else {
                rgb(UI_PANEL_TEXT)
            })
            .cursor(CursorStyle::PointingHand)
            .hover(move |style| style.bg(ciphertext_hover_fill))
            .child("Ciphertext");
        ciphertext_button = ciphertext_button
            .on_mouse_down(MouseButton::Left, cx.listener(Self::on_toggle_ciphertext));

        let toolbar = material_surface(
            window,
            MaterialStyle::toolbar().emphasis(MaterialEmphasis::High),
        )
        .flex()
        .items_center()
        .justify_between()
        .px(px(16.0))
        .py(px(12.0))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(5.0))
                .child(
                    div()
                        .text_size(px(11.0))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(UI_MUTED_TEXT))
                        .child("Messages"),
                )
                .child(
                    div()
                        .text_size(px(20.0))
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
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(6.0))
                        .px(px(4.0))
                        .py(px(4.0))
                        .rounded(px(14.0))
                        .bg(ui_row_fill(self.window_active))
                        .child(sidebar_button)
                        .child(inspector_button),
                )
                .child(ciphertext_button),
        );

        div()
            .flex()
            .flex_col()
            .gap(px(6.0))
            .child(toolbar)
            .child(
                material_surface(
                    window,
                    MaterialStyle::scroll_edge()
                        .variant(MaterialVariant::Clear)
                        .emphasis(MaterialEmphasis::Low),
                )
                .w_full()
                .h(px(12.0))
                .border(px(0.0)),
            )
    }
}
