use super::*;

impl AppModel {
    pub(super) fn render_activity_panel(&self, cx: &mut ViewContext<Self>) -> Div {
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
                .text_size(px(12.0))
                .font_weight(FontWeight::MEDIUM)
                .text_color(rgb(UI_PANEL_TEXT))
                .bg(rgb(UI_BUTTON_BG))
                .cursor(CursorStyle::PointingHand)
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
        let metrics = div()
            .flex()
            .flex_wrap()
            .gap(px(8.0))
            .child(
                div()
                    .px(px(8.0))
                    .py(px(4.0))
                    .rounded(px(999.0))
                    .bg(rgb(0x213146))
                    .text_size(px(11.0))
                    .text_color(rgb(0x95c7ff))
                    .child(ws_status),
            )
            .child(
                div()
                    .px(px(8.0))
                    .py(px(4.0))
                    .rounded(px(999.0))
                    .bg(rgb(0x21382f))
                    .text_size(px(11.0))
                    .text_color(rgb(0x95f0b6))
                    .child(format!("messages {}", self.messages.len())),
            )
            .child(
                div()
                    .px(px(8.0))
                    .py(px(4.0))
                    .rounded(px(999.0))
                    .bg(rgb(0x39272b))
                    .text_size(px(11.0))
                    .text_color(rgb(0xffbf93))
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
                    ActivityKind::Connection => {
                        ("connection", rgb(0x233553), rgb(0x95c7ff), rgb(0x1f2a3d))
                    }
                    ActivityKind::Roster => ("roster", rgb(0x4b2e2e), rgb(0xffbf93), rgb(0x302428)),
                    ActivityKind::Message => {
                        ("message", rgb(0x244032), rgb(0x95f0b6), rgb(0x1f2f27))
                    }
                    ActivityKind::Sync => ("sync", rgb(0x2a3f46), rgb(0x9fe7f0), rgb(0x212e34)),
                    ActivityKind::System => ("system", rgb(0x373c4a), rgb(0xd0d6ef), rgb(0x262a36)),
                };
                let mut entry = div()
                    .px(px(9.0))
                    .py(px(7.0))
                    .rounded(px(10.0))
                    .bg(card_bg)
                    .border(px(1.0))
                    .border_color(rgb(0x33445d))
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

        div()
            .flex()
            .flex_col()
            .gap(px(8.0))
            .px(px(12.0))
            .py(px(12.0))
            .rounded(px(14.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .bg(rgb(UI_PANEL_BG))
            .child(header)
            .child(metrics)
            .child(list)
    }
}
