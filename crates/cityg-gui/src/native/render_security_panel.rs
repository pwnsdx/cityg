use super::*;

impl AppModel {
    pub(super) fn render_security_panel(&self, cx: &mut ViewContext<Self>) -> Div {
        let count = self.security_events.len();
        let title = div()
            .text_size(px(15.0))
            .font_weight(FontWeight::SEMIBOLD)
            .text_color(rgb(UI_PANEL_TEXT))
            .child(format!("Security alerts ({count})"));
        let mut header = div().flex().items_center().justify_between().child(title);

        let mut actions = div().flex().items_center().gap(px(8.0));
        if self.security_unread > 0 {
            let badge = div()
                .px(px(8.0))
                .py(px(2.0))
                .rounded(px(999.0))
                .bg(rgb(0xff9f68))
                .text_size(px(11.0))
                .font_weight(FontWeight::BOLD)
                .text_color(rgb(UI_ACCENT_BUTTON_TEXT))
                .child(format!("{} new", self.security_unread));
            let ack_button = div()
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
                .child("Mark read")
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(Self::on_security_panel_mark_read_clicked),
                );
            actions = actions.child(badge).child(ack_button);
        }

        let toggle_label = if self.security_panel_expanded {
            "Hide"
        } else {
            "Show"
        };
        let toggle_button = div()
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
            .child(toggle_label)
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(Self::on_security_panel_toggle_clicked),
            );
        actions = actions.child(toggle_button);

        if self.security_panel_expanded && count > 0 {
            let clear_button = div()
                .px(px(8.0))
                .py(px(4.0))
                .rounded(px(8.0))
                .border(px(1.0))
                .border_color(rgb(UI_PANEL_BORDER))
                .text_size(px(12.0))
                .font_weight(FontWeight::MEDIUM)
                .text_color(rgb(UI_PANEL_TEXT))
                .bg(rgb(UI_NEUTRAL_ELEVATED_FILL))
                .cursor(CursorStyle::PointingHand)
                .hover({
                    let hover_fill = ui_hover_fill(self.window_active);
                    move |style| style.bg(hover_fill)
                })
                .child("Clear log")
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(Self::on_security_log_clear_clicked),
                );
            actions = actions.child(clear_button);
        }

        header = header.child(actions);

        let mut list = div().flex().flex_col().gap(px(6.0));

        if !self.security_panel_expanded {
            let summary = if count == 0 {
                "No security alerts recorded."
            } else {
                "Alerts hidden. Click Show to review details."
            };
            list = list.child(
                div()
                    .text_size(px(12.0))
                    .text_color(rgb(UI_SUBTLE_TEXT))
                    .child(summary),
            );
        } else if self.security_events.is_empty() {
            list = list.child(
                div()
                    .text_size(px(12.0))
                    .text_color(rgb(UI_SUBTLE_TEXT))
                    .child("No security alerts recorded."),
            );
        } else {
            for event in self.security_events.iter().rev() {
                let entry = div()
                    .px(px(9.0))
                    .py(px(7.0))
                    .rounded(px(10.0))
                    .bg(rgba(0x241c20ef))
                    .border(px(1.0))
                    .border_color(rgb(0x4b343a))
                    .flex()
                    .flex_col()
                    .gap(px(2.0))
                    .child(
                        div()
                            .text_size(px(12.0))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(rgb(0xffe2e7))
                            .child(format!("{} – {}", event.alias, event.description)),
                    )
                    .child(
                        div()
                            .text_size(px(11.0))
                            .text_color(rgb(0xd8b2bc))
                            .child(format_timestamp(event.timestamp_ms)),
                    );
                list = list.child(entry);
            }
        }

        div()
            .flex()
            .flex_col()
            .gap(px(8.0))
            .px(px(14.0))
            .py(px(14.0))
            .rounded(px(18.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .bg(ui_panel_fill(self.window_active))
            .shadow_sm()
            .child(header)
            .child(list)
    }
}
