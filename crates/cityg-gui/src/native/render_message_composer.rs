use super::*;

impl AppModel {
    pub(super) fn render_message_composer(&self, cx: &mut ViewContext<Self>) -> Div {
        let barrier_pending = self.barrier_recovery_pending();
        let border_color = if self.composer.active {
            rgb(0x72f88e)
        } else {
            rgb(0x2a3148)
        };
        let background = if self.composer.active {
            rgb(0x1b2135)
        } else {
            rgb(0x161b2a)
        };

        let text_color = if self.composer.text.is_empty() {
            rgb(0x5b6584)
        } else {
            rgb(0xf5f7ff)
        };

        let placeholder = if barrier_pending {
            "Waiting for barrier recovery…"
        } else if self.composer.active {
            "Type a message…"
        } else {
            "Click to start typing…"
        };

        let mut row = div().flex().items_center().gap(px(12.0));

        row = row.child(
            div()
                .flex_grow()
                .px(px(14.0))
                .py(px(10.0))
                .rounded(px(12.0))
                .border(px(1.0))
                .border_color(border_color)
                .bg(background)
                .cursor(CursorStyle::IBeam)
                .on_mouse_down(MouseButton::Left, cx.listener(Self::on_composer_clicked))
                .child(div().text_size(px(15.0)).text_color(text_color).child(
                    if self.composer.text.is_empty() {
                        placeholder.to_string()
                    } else {
                        self.composer.text.clone()
                    },
                )),
        );

        let send_disabled = barrier_pending
            || !self.composer.is_ready()
            || matches!(self.send_status, SendStatus::Sending)
            || self.session.is_none();

        let label = match self.send_status {
            SendStatus::Sending => "Sending…",
            SendStatus::Idle if barrier_pending => "Awaiting recovery",
            SendStatus::Idle => "Send",
        };

        let mut button = div()
            .px(px(16.0))
            .py(px(10.0))
            .rounded(px(10.0))
            .text_size(px(15.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(0x0f1118))
            .bg(if send_disabled {
                rgb(0x3a3f57)
            } else {
                rgb(0x72f88e)
            })
            .cursor(if send_disabled {
                CursorStyle::Arrow
            } else {
                CursorStyle::PointingHand
            })
            .child(label);

        if !send_disabled {
            button = button.on_mouse_down(MouseButton::Left, cx.listener(Self::on_send_clicked));
        }

        row.child(button)
    }
}
