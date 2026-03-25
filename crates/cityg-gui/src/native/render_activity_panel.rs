use super::*;

impl AppModel {
    pub(super) fn render_activity_panel(&self, window: &Window, cx: &mut ViewContext<Self>) -> Div {
        let count = self.activity_events.len();
        let title = div()
            .text_size(px(15.0))
            .font_weight(FontWeight::SEMIBOLD)
            .text_color(rgb(UI_PANEL_TEXT))
            .child(format!("Live activity ({count})"));
        let mut header = div().flex().items_center().justify_between().child(title);

        if count > 0 {
            let clear_button = div()
                .px(px(8.0))
                .py(px(4.0))
                .rounded(px(8.0))
                .border(px(1.0))
                .border_color(rgb(UI_PANEL_BORDER))
                .text_size(px(12.0))
                .font_weight(FontWeight::MEDIUM)
                .text_color(rgb(UI_PANEL_TEXT))
                .bg(ui_button_fill(self.window_active))
                .cursor(CursorStyle::PointingHand)
                .hover({
                    let hover_fill = ui_hover_fill(self.window_active);
                    move |style| style.bg(hover_fill)
                })
                .child("Clear")
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(Self::on_activity_clear_clicked),
                );
            header = header.child(clear_button);
        }

        let ws_status = if self.ws_connected {
            "WS live"
        } else {
            "Polling"
        };
        let total_members = self.members_total.max(self.members.len() as u64);
        let metrics = material_surface(
            window,
            MaterialStyle::grouped_controls().emphasis(MaterialEmphasis::Low),
        )
        .flex()
        .flex_wrap()
        .gap(px(8.0))
        .px(px(10.0))
        .py(px(10.0))
        .child(
            div()
                .px(px(8.0))
                .py(px(4.0))
                .rounded(px(999.0))
                .bg(rgb(0x2a2f38))
                .text_size(px(11.0))
                .text_color(rgb(UI_INFO_TEXT))
                .child(ws_status),
        )
        .child(
            div()
                .px(px(8.0))
                .py(px(4.0))
                .rounded(px(999.0))
                .bg(rgb(0x223128))
                .text_size(px(11.0))
                .text_color(rgb(UI_SUCCESS_TEXT))
                .child(format!("messages {}", self.messages.len())),
        )
        .child(
            div()
                .px(px(8.0))
                .py(px(4.0))
                .rounded(px(999.0))
                .bg(rgb(0x352723))
                .text_size(px(11.0))
                .text_color(rgb(UI_WARN_TEXT))
                .child(format!("members {}/{}", self.members.len(), total_members)),
        );

        let mut list = div().flex().flex_col().gap(px(6.0));

        if self.activity_events.is_empty() {
            list = list.child(
                div()
                    .text_size(px(12.0))
                    .text_color(rgb(UI_SUBTLE_TEXT))
                    .child("No live activity yet."),
            );
        } else {
            for event in self.activity_events.iter().rev() {
                let (label, chip_bg, chip_text, card_bg) = match event.kind {
                    ActivityKind::Connection => (
                        "connection",
                        rgb(0x2a313c),
                        rgb(UI_INFO_TEXT),
                        rgb(0x17191d),
                    ),
                    ActivityKind::Roster => {
                        ("roster", rgb(0x43302c), rgb(UI_WARN_TEXT), rgb(0x1b1818))
                    }
                    ActivityKind::Message => (
                        "message",
                        rgb(0x243129),
                        rgb(UI_SUCCESS_TEXT),
                        rgb(0x171a18),
                    ),
                    ActivityKind::Sync => ("sync", rgb(0x283334), rgb(0xb4dcdf), rgb(0x171a1b)),
                    ActivityKind::System => ("system", rgb(0x313239), rgb(0xd6d7dc), rgb(0x18191c)),
                };
                let mut entry = div()
                    .px(px(9.0))
                    .py(px(7.0))
                    .rounded(px(10.0))
                    .bg(card_bg)
                    .border(px(1.0))
                    .border_color(rgb(UI_PANEL_BORDER))
                    .flex()
                    .flex_col()
                    .gap(px(3.0))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .px(px(8.0))
                                    .py(px(2.0))
                                    .rounded(px(999.0))
                                    .bg(chip_bg)
                                    .text_size(px(10.0))
                                    .font_weight(FontWeight::BOLD)
                                    .text_color(chip_text)
                                    .child(label),
                            )
                            .child(
                                div()
                                    .text_size(px(11.0))
                                    .text_color(rgb(UI_SUBTLE_TEXT))
                                    .child(format_timestamp(event.timestamp_ms)),
                            ),
                    )
                    .child(
                        div()
                            .text_size(px(12.0))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(rgb(UI_PANEL_TEXT))
                            .child(event.summary.clone()),
                    );
                if let Some(detail) = event.detail.as_ref().filter(|text| !text.is_empty()) {
                    entry = entry.child(
                        div()
                            .text_size(px(11.0))
                            .text_color(rgb(UI_MUTED_TEXT))
                            .child(detail.clone()),
                    );
                }
                list = list.child(entry);
            }
        }

        material_surface(
            window,
            MaterialStyle::inspector().emphasis(MaterialEmphasis::Medium),
        )
        .flex()
        .flex_col()
        .gap(px(8.0))
        .px(px(14.0))
        .py(px(14.0))
        .child(header)
        .child(metrics)
        .child(list)
    }
}
