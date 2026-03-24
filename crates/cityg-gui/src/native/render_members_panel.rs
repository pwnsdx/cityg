use super::*;

impl AppModel {
    pub(super) fn render_members_panel(&self, cx: &mut ViewContext<Self>) -> Div {
        let count = self.members.len();
        let total = self.members_total.max(count as u64);
        let title_text = match &self.members_mode {
            MembersMode::Full => format!("Members ({count} / {total})"),
            MembersMode::Search { query } => {
                format!("Search \"{}\" ({count} / {total})", query)
            }
        };
        let mut header = div().flex().items_center().justify_between().child(
            div()
                .text_size(px(15.0))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(rgb(UI_PANEL_TEXT))
                .child(title_text),
        );

        let refresh_button = div()
            .px(px(8.0))
            .py(px(5.0))
            .rounded(px(10.0))
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(UI_PANEL_TEXT))
            .bg(ui_button_fill(self.window_active))
            .cursor(CursorStyle::PointingHand)
            .child("Refresh")
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(Self::on_members_refresh_clicked),
            );

        header = header.child(refresh_button);

        if let Some(next_offset) = self.members_next_offset
            && next_offset < total
        {
            let load_more = div()
                .px(px(8.0))
                .py(px(5.0))
                .rounded(px(10.0))
                .text_size(px(12.0))
                .font_weight(FontWeight::MEDIUM)
                .text_color(rgb(UI_PANEL_TEXT))
                .bg(rgb(UI_NEUTRAL_ELEVATED_FILL))
                .cursor(CursorStyle::PointingHand)
                .child("Load more")
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(Self::on_members_load_more_clicked),
                );
            header = header.child(load_more);
        }

        let search_placeholder = "Filter alias or leaf hex";
        let search_active = self.members_search.active;
        let search_border = if search_active {
            rgb(UI_ACCENT_TEXT)
        } else {
            rgb(UI_PANEL_BORDER)
        };
        let search_background = if search_active {
            ui_input_fill(true)
        } else {
            ui_row_fill(self.window_active)
        };
        let search_text_color = if self.members_search.query.is_empty() {
            rgb(UI_MUTED_TEXT)
        } else {
            rgb(UI_PANEL_TEXT)
        };
        let search_display = if self.members_search.query.is_empty() {
            search_placeholder.to_string()
        } else {
            self.members_search.query.clone()
        };

        let search_field = div()
            .flex()
            .items_center()
            .flex_grow()
            .px(px(10.0))
            .py(px(7.0))
            .rounded(px(10.0))
            .border(px(1.0))
            .border_color(search_border)
            .bg(search_background)
            .cursor(CursorStyle::IBeam)
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(Self::on_members_search_field_clicked),
            )
            .child(
                div()
                    .text_size(px(12.0))
                    .text_color(search_text_color)
                    .child(search_display),
            );

        let search_button = div()
            .px(px(8.0))
            .py(px(6.0))
            .rounded(px(10.0))
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(UI_PANEL_TEXT))
            .bg(ui_button_fill(self.window_active))
            .cursor(CursorStyle::PointingHand)
            .child("Search")
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(Self::on_members_search_button_clicked),
            );

        let mut search_row = div().flex().items_center().gap(px(10.0));
        search_row = search_row.child(search_field).child(search_button);

        let has_query = !self.members_search.query.trim().is_empty();
        if has_query || matches!(self.members_mode, MembersMode::Search { .. }) {
            let clear_button = div()
                .px(px(8.0))
                .py(px(6.0))
                .rounded(px(10.0))
                .text_size(px(12.0))
                .font_weight(FontWeight::MEDIUM)
                .text_color(rgb(UI_PANEL_TEXT))
                .bg(rgb(UI_NEUTRAL_ELEVATED_FILL))
                .cursor(CursorStyle::PointingHand)
                .child("Clear")
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(Self::on_members_search_clear_clicked),
                );
            search_row = search_row.child(clear_button);
        }

        let mut list = div().flex().flex_col().gap(px(6.0));

        if self.members.is_empty() {
            list = list.child(
                div()
                    .text_size(px(12.0))
                    .text_color(rgb(UI_SUBTLE_TEXT))
                    .child("No members reported for this root."),
            );
        } else {
            for member in &self.members {
                let primary_label = format_member_label(member);
                let mut entry = div()
                    .px(px(9.0))
                    .py(px(7.0))
                    .rounded(px(10.0))
                    .bg(ui_row_fill(self.window_active))
                    .border(px(1.0))
                    .border_color(rgb(UI_PANEL_BORDER))
                    .flex()
                    .flex_col()
                    .gap(px(3.0))
                    .child(
                        div()
                            .text_size(px(13.0))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(rgb(UI_PANEL_TEXT))
                            .child(primary_label),
                    )
                    .child(
                        div()
                            .text_size(px(11.0))
                            .text_color(rgb(UI_SUBTLE_TEXT))
                            .child(format!("leaf: {}", hex_encode(member.leaf_id))),
                    );

                if let Some(joined) = member.join_timestamp_ms {
                    entry = entry.child(
                        div()
                            .text_size(px(11.0))
                            .text_color(rgb(UI_MUTED_TEXT))
                            .child(format!("joined {}", format_timestamp(joined))),
                    );
                }

                if let Some(last_seen) = member.last_seen_timestamp_ms {
                    entry = entry.child(
                        div()
                            .text_size(px(11.0))
                            .text_color(rgb(UI_MUTED_TEXT))
                            .child(format!("last seen {}", format_timestamp(last_seen))),
                    );
                }

                if let Some(pop_public_key) =
                    member.pop_public_key.as_ref().filter(|pk| !pk.is_empty())
                {
                    let mut identity_row = div().flex().items_center().gap(px(8.0)).child(
                        div()
                            .text_size(px(11.0))
                            .text_color(rgb(UI_MUTED_TEXT))
                            .child(format!(
                                "identity {}",
                                room_admin_identity_preview(pop_public_key)
                            )),
                    );

                    if self.room_admin_membership(pop_public_key.as_slice()) == Some(true) {
                        identity_row = identity_row.child(
                            div()
                                .px(px(8.0))
                                .py(px(2.0))
                                .rounded(px(999.0))
                                .bg(rgb(0x223128))
                                .text_size(px(10.0))
                                .font_weight(FontWeight::BOLD)
                                .text_color(rgb(UI_SUCCESS_TEXT))
                                .child("Room admin"),
                        );
                    }

                    let target_pop_key = pop_public_key.clone();
                    let use_identity_button = div()
                        .px(px(8.0))
                        .py(px(4.0))
                        .rounded(px(8.0))
                        .text_size(px(11.0))
                        .font_weight(FontWeight::MEDIUM)
                        .text_color(rgb(UI_PANEL_TEXT))
                        .bg(ui_button_fill(self.window_active))
                        .cursor(CursorStyle::PointingHand)
                        .child("Use identity")
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(move |this, _, _, cx| {
                                this.set_room_admin_target(target_pop_key.clone(), cx);
                            }),
                        );
                    identity_row = identity_row.child(use_identity_button);

                    entry = entry.child(identity_row);
                }

                list = list.child(entry);
            }
        }

        let status_text = match &self.members_status {
            MembersStatus::Idle => None,
            MembersStatus::Loading(message) => Some(message.clone()),
            MembersStatus::Error(message) => Some(message.clone()),
        };

        let mut root = div()
            .flex()
            .flex_col()
            .gap(px(8.0))
            .px(px(12.0))
            .py(px(12.0))
            .rounded(px(14.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .bg(ui_panel_fill(self.window_active))
            .child(header);
        root = root.child(search_row);
        if let Some(text) = status_text {
            root = root.child(
                div()
                    .text_size(px(12.0))
                    .text_color(rgb(UI_WARN_TEXT))
                    .child(text),
            );
        }
        root.child(list)
    }
}
