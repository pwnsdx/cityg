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
            .bg(ui_panel_fill(self.window_active))
            .child(self.render_message_list())
            .child(self.render_message_composer(cx))
    }

    pub(super) fn render_message_list(&self) -> impl IntoElement {
        let mut sender_labels = AHashMap::new();
        for member in &self.members {
            sender_labels.insert(member.leaf_id, format_member_label(member));
        }
        for (leaf, alias) in &self.leaf_alias_index {
            sender_labels
                .entry(*leaf)
                .or_insert_with(|| format_alias_display(alias, leaf));
        }

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
            let timestamp = format_timestamp(message.timestamp_ms);
            let sender = message
                .sender_leaf
                .and_then(|leaf| sender_labels.get(&leaf).cloned())
                .unwrap_or_else(|| message.fallback_label.clone());
            let (card_bg, card_border, body_color, meta_color, status_line) = match message.delivery
            {
                MessageDelivery::Pending => (
                    rgba(0x191a1de8),
                    rgb(0x303238),
                    rgb(UI_PANEL_TEXT),
                    rgb(UI_SUBTLE_TEXT),
                    Some(("sending...", rgb(UI_ACCENT_TEXT))),
                ),
                MessageDelivery::Failed => (
                    rgba(0x2a1d22e8),
                    rgb(0x5a3740),
                    rgb(0xffdfe6),
                    rgb(0xdab1bb),
                    Some(("failed to send", rgb(UI_ERROR_TEXT))),
                ),
                MessageDelivery::Sent => (
                    rgba(0x131416e2),
                    rgb(UI_PANEL_BORDER),
                    rgb(UI_PANEL_TEXT),
                    rgb(UI_SUBTLE_TEXT),
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
