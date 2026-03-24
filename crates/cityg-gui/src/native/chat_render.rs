use super::*;

impl AppModel {
    pub(super) fn render_message_panel(
        &self,
        _session: &AppSession,
        cx: &mut ViewContext<Self>,
    ) -> Div {
        div()
            .flex()
            .flex_col()
            .flex_grow()
            .min_h(px(0.0))
            .h_full()
            .gap(px(14.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .rounded(px(14.0))
            .px(px(16.0))
            .py(px(14.0))
            .bg(rgb(UI_PANEL_BG))
            .child(self.render_message_list())
            .child(self.render_message_composer(cx))
    }

    pub(super) fn render_message_list(&self) -> impl IntoElement {
        let mut list = div()
            .flex()
            .flex_col()
            .flex_grow()
            .min_h(px(0.0))
            .gap(px(8.0))
            .px(px(2.0))
            .py(px(2.0))
            .id("chat-message-list")
            .track_scroll(&self.chat_scroll_handle);
        list = list.overflow_y_scroll().block_mouse_except_scroll();

        if self.messages.is_empty() {
            let empty_text = if self.barrier_recovery_pending() {
                "Joined room. Waiting for barrier recovery before messages can be sent or decrypted."
            } else {
                "No messages yet. Send one to warm up this room."
            };
            return list.child(
                div()
                    .text_size(px(13.0))
                    .text_color(rgb(UI_MUTED_TEXT))
                    .child(empty_text),
            );
        }

        for message in &self.messages {
            let timestamp =
                format_rfc3339_seconds(UNIX_EPOCH + Duration::from_millis(message.timestamp_ms));
            let sender = self.resolve_sender_label(message);
            let (card_bg, card_border, body_color, meta_color, status_line) = match message.delivery
            {
                MessageDelivery::Pending => (
                    rgb(0x1d293b),
                    rgb(0x2d4057),
                    rgb(0xe1e7ff),
                    rgb(0xa2b2d6),
                    Some(("sending...", rgb(UI_ACCENT_TEXT))),
                ),
                MessageDelivery::Failed => (
                    rgb(0x32212c),
                    rgb(0x563342),
                    rgb(0xffd7e3),
                    rgb(0xffafc3),
                    Some(("failed to send", rgb(0xff8ca7))),
                ),
                MessageDelivery::Sent => (
                    rgb(0x171f31),
                    rgb(0x243149),
                    rgb(0xf2f5ff),
                    rgb(0x9eabd2),
                    None,
                ),
            };
            let mut entry = div()
                .flex()
                .flex_col()
                .gap(px(4.0))
                .bg(card_bg)
                .rounded(px(11.0))
                .border(px(1.0))
                .border_color(card_border)
                .px(px(12.0))
                .py(px(10.0))
                .child(
                    div()
                        .flex()
                        .justify_between()
                        .text_size(px(12.0))
                        .text_color(rgb(UI_SUBTLE_TEXT))
                        .child(format!("{} • {}", sender, timestamp)),
                )
                .child(
                    div()
                        .text_size(px(14.0))
                        .text_color(body_color)
                        .child(message.plaintext.clone()),
                )
                .child(div().text_size(px(11.0)).text_color(meta_color).child(
                    if self.show_ciphertext {
                        format!("ciphertext: {}", message.ciphertext_hex)
                    } else {
                        "ciphertext hidden".to_string()
                    },
                ));

            if let Some((label, color)) = status_line {
                entry = entry.child(div().text_size(px(11.0)).text_color(color).child(label));
            }

            list = list.child(entry);
        }

        list
    }
}
