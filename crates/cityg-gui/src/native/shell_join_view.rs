use super::*;

impl AppModel {
    pub(super) fn render_join(&self, window: &Window, cx: &mut ViewContext<Self>) -> Div {
        let heading_color = rgb(UI_PANEL_TEXT);
        let subtext_color = rgb(UI_SUBTLE_TEXT);
        let error_color = rgb(UI_ERROR_TEXT);
        let info_color = rgb(UI_SUCCESS_TEXT);
        let join_disabled =
            !self.join_form.is_ready() || matches!(self.join_status, JoinStatus::Joining);

        let form = material_surface(
            window,
            MaterialStyle::overlay()
                .emphasis(MaterialEmphasis::High)
                .tinted(true),
        )
        .flex()
        .flex_col()
        .w(px(520.0))
        .max_w_full()
        .px(px(40.0))
        .py(px(36.0))
        .gap(px(18.0))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(8.0))
                .child(
                    div()
                        .px(px(10.0))
                        .py(px(4.0))
                        .rounded(px(999.0))
                        .bg(rgb(UI_ACCENT_SOFT_FILL))
                        .text_size(px(11.0))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(UI_ACCENT_TEXT))
                        .child("Desktop client"),
                )
                .child(
                    div()
                        .text_size(px(30.0))
                        .font_weight(FontWeight::BOLD)
                        .text_color(heading_color)
                        .child("Join a City-G Room"),
                )
                .child(div().text_size(px(14.0)).text_color(subtext_color).child(
                    "Connect to a City-G endpoint or Worker edge, pick your alias, and request a join ticket.",
                )),
        )
        .child(self.render_field(
            "Server URL",
            &self.join_form.server,
            "https://edge.example.com",
            ActiveField::Server,
            cx,
        ))
        .child(self.render_field(
            "Room ID",
            &self.join_form.room_id,
            "64 hex characters",
            ActiveField::Room,
            cx,
        ))
        .child(
            div()
                .flex()
                .justify_between()
                .items_center()
                .text_size(px(12.0))
                .text_color(subtext_color)
                .child("Paste a City-G invite or enter a 64-character room ID.")
                .child(
                    div()
                        .px(px(12.0))
                        .py(px(7.0))
                        .rounded(px(11.0))
                        .border(px(1.0))
                        .border_color(rgb(UI_PANEL_BORDER))
                        .bg(ui_button_fill(self.window_active))
                        .text_color(rgb(UI_PANEL_TEXT))
                        .cursor(CursorStyle::PointingHand)
                        .text_size(px(12.0))
                        .font_weight(FontWeight::MEDIUM)
                        .hover({
                            let hover_fill = ui_hover_fill(self.window_active);
                            move |style| style.bg(hover_fill)
                        })
                        .child("Generate new ID")
                        .on_mouse_down(MouseButton::Left, cx.listener(Self::on_generate_room_id)),
                ),
        )
        .child(self.render_field(
            "Alias",
            &self.join_form.alias,
            "your name",
            ActiveField::Alias,
            cx,
        ))
        .child({
            let status_text = match self.join_status {
                JoinStatus::Joining => Some("Requesting join ticket...".to_string()),
                JoinStatus::Idle => None,
            };
            let mut status_div = div()
                .flex()
                .gap(px(6.0))
                .items_center()
                .text_size(px(13.0))
                .text_color(subtext_color);
            if let Some(text) = status_text {
                status_div = status_div.child(self.render_spinner()).child(text);
            }
            status_div
        })
        .child({
            let mut button = div()
                .px(px(18.0))
                .py(px(12.0))
                .rounded(px(14.0))
                .border(px(1.0))
                .border_color(if join_disabled {
                    rgb(UI_PANEL_BORDER)
                } else {
                    rgb(UI_ACCENT_TEXT)
                })
                .text_size(px(16.0))
                .font_weight(FontWeight::MEDIUM)
                .text_color(if join_disabled {
                    rgb(UI_MUTED_TEXT)
                } else {
                    rgb(UI_ACCENT_BUTTON_TEXT)
                })
                .bg(if join_disabled {
                    ui_button_fill(self.window_active)
                } else {
                    rgb(UI_ACCENT_TEXT)
                })
                .cursor(if join_disabled {
                    CursorStyle::Arrow
                } else {
                    CursorStyle::PointingHand
                })
                .child(if matches!(self.join_status, JoinStatus::Joining) {
                    "Joining..."
                } else {
                    "Join room"
                });

            if !join_disabled {
                button = button
                    .hover(|style| style.bg(rgb(0x79bdff)))
                    .on_mouse_down(MouseButton::Left, cx.listener(Self::on_join_clicked));
            }
            button
        });

        let mut root = div()
            .flex()
            .flex_col()
            .items_center()
            .gap(px(20.0))
            .child(form);

        if let Some(error_box) = self.render_error_box(cx) {
            root = root.child(error_box);
        } else if let Some(err) = &self.last_error {
            root = root.child(
                div()
                    .text_size(px(13.0))
                    .text_color(error_color)
                    .child(format!("Join failed: {err}")),
            );
        }

        if let Some(info) = &self.info_message {
            root = root.child(
                div()
                    .text_size(px(13.0))
                    .text_color(info_color)
                    .child(info.clone()),
            );
        }

        root
    }

    pub(super) fn render_field(
        &self,
        label: &str,
        value: &str,
        placeholder: &str,
        field: ActiveField,
        cx: &mut ViewContext<Self>,
    ) -> Div {
        let is_active = self.join_form.active == Some(field);
        let border = if is_active {
            rgb(UI_ACCENT_TEXT)
        } else {
            rgb(UI_PANEL_BORDER)
        };
        let background = if is_active {
            ui_input_fill(true)
        } else {
            ui_input_fill(false)
        };
        let text_color = if value.is_empty() {
            rgb(UI_MUTED_TEXT)
        } else {
            rgb(UI_PANEL_TEXT)
        };
        let display = if value.is_empty() {
            placeholder.to_string()
        } else {
            value.to_string()
        };

        div()
            .flex()
            .flex_col()
            .gap(px(6.0))
            .child(
                div()
                    .text_size(px(12.0))
                    .text_color(rgb(UI_SUBTLE_TEXT))
                    .child(label.to_string()),
            )
            .child({
                let handler_field = field;
                div()
                    .px(px(14.0))
                    .py(px(12.0))
                    .rounded(px(14.0))
                    .border(px(1.0))
                    .border_color(border)
                    .bg(background)
                    .text_size(px(16.0))
                    .line_height(px(22.0))
                    .on_mouse_down(MouseButton::Left, {
                        cx.listener(move |this, _, window, cx| {
                            this.focus_field_in_window(handler_field, window, cx);
                        })
                    })
                    .child({
                        let placeholder = display;
                        let field = match handler_field {
                            ActiveField::Server => NativeTextFieldKind::JoinServer,
                            ActiveField::Room => NativeTextFieldKind::JoinRoom,
                            ActiveField::Alias => NativeTextFieldKind::JoinAlias,
                        };
                        div()
                            .text_color(text_color)
                            .child(self.render_native_text_field(cx, field, placeholder))
                    })
            })
    }
}
