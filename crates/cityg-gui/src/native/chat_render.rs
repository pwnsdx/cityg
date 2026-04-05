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
            .gap(px(12.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .rounded(px(18.0))
            .px(px(16.0))
            .py(px(16.0))
            .bg(ui_panel_fill(self.window_active))
            .shadow_sm()
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
            let empty_text = if let Some(session) = self.session.as_ref() {
                if session.barrier_state.barrier_recovery_pending {
                    Self::barrier_recovery_message_for_session(session)
                } else {
                    "No messages yet. Send one to warm up this room.".to_string()
                }
            } else {
                "No messages yet. Send one to warm up this room.".to_string()
            };
            return list.child(
                div()
                    .text_size(px(13.0))
                    .text_color(rgb(UI_MUTED_TEXT))
                    .child(empty_text),
            );
        }

        let local_session = self.session.as_ref();

        for message in &self.messages {
            let timestamp = format_timestamp(message.timestamp_ms);
            let sender = message
                .sender_leaf
                .and_then(|leaf| sender_labels.get(&leaf).cloned())
                .unwrap_or_else(|| message.fallback_label.clone());
            let is_self = local_session
                .map(|session| {
                    message.sender_leaf == Some(session.leaf_id)
                        || sender.eq_ignore_ascii_case(session.alias.as_str())
                })
                .unwrap_or(false);
            let display_sender = if is_self { "You" } else { sender.as_str() };
            let (card_bg, card_border, body_color, meta_color, status_line) = match message.delivery
            {
                MessageDelivery::Pending => (
                    if is_self {
                        rgba(0x214467ee)
                    } else {
                        rgba(0x1b232de8)
                    },
                    if is_self {
                        rgb(UI_ACCENT_TEXT)
                    } else {
                        rgb(UI_PANEL_BORDER)
                    },
                    rgb(UI_PANEL_TEXT),
                    rgb(UI_SUBTLE_TEXT),
                    Some(("Sending…", rgb(UI_ACCENT_TEXT))),
                ),
                MessageDelivery::Failed => (
                    rgba(0x332128ee),
                    rgb(0x754550),
                    rgb(0xffdfe6),
                    rgb(0xe1b5bf),
                    Some(("Delivery failed", rgb(UI_ERROR_TEXT))),
                ),
                MessageDelivery::Sent => (
                    if is_self {
                        rgba(0x183656ef)
                    } else {
                        ui_row_fill(self.window_active)
                    },
                    if is_self {
                        rgb(UI_ACCENT_TEXT)
                    } else {
                        rgb(UI_PANEL_BORDER)
                    },
                    rgb(UI_PANEL_TEXT),
                    rgb(UI_SUBTLE_TEXT),
                    None,
                ),
            };
            let mut entry = div()
                .flex()
                .flex_col()
                .gap(px(5.0))
                .bg(card_bg)
                .rounded(px(14.0))
                .border(px(1.0))
                .border_color(card_border)
                .px(px(13.0))
                .py(px(11.0))
                .max_w(gpui::relative(0.86))
                .shadow_sm()
                .child(
                    div()
                        .flex()
                        .justify_between()
                        .text_size(px(12.0))
                        .text_color(rgb(UI_SUBTLE_TEXT))
                        .child(format!("{} • {}", display_sender, timestamp)),
                )
                .child(
                    div()
                        .text_size(px(14.0))
                        .line_height(px(20.0))
                        .text_color(body_color)
                        .child(message.plaintext.clone()),
                );

            if self.show_ciphertext {
                entry = entry.child(
                    div()
                        .text_size(px(11.0))
                        .text_color(meta_color)
                        .child(format!("ciphertext: {}", message.ciphertext_hex)),
                );
            } else {
                entry = entry.child(
                    div()
                        .text_size(px(11.0))
                        .text_color(meta_color)
                        .child("secure payload hidden"),
                );
            }

            if let Some((label, color)) = status_line {
                entry = entry.child(div().text_size(px(11.0)).text_color(color).child(label));
            }

            let mut row = div().flex().w_full();
            if is_self {
                row = row.justify_end();
            } else {
                row = row.justify_start();
            }
            list = list.child(row.child(entry));
        }

        list
    }
}
