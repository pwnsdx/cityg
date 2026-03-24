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

    pub(super) fn render_leave_controls(&self, cx: &mut ViewContext<Self>) -> Div {
        let leaving = matches!(self.leave_status, LeaveStatus::Leaving);
        let refreshing = matches!(self.leave_status, LeaveStatus::Refreshing);
        let barrier_pending = self.barrier_recovery_pending();
        let membership_op_busy = leaving || refreshing || barrier_pending;
        let mut leave_button = div()
            .px(px(12.0))
            .py(px(8.0))
            .rounded(px(12.0))
            .text_size(px(14.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(0xfafafa))
            .bg(if leaving {
                rgb(0x5a4552)
            } else if membership_op_busy {
                rgb(0x4b3f45)
            } else {
                rgb(0xbb4f68)
            })
            .cursor(if membership_op_busy {
                CursorStyle::Arrow
            } else {
                CursorStyle::PointingHand
            })
            .child(if leaving { "Leaving…" } else { "Leave room" });

        if !membership_op_busy {
            leave_button =
                leave_button.on_mouse_down(MouseButton::Left, cx.listener(Self::on_leave_clicked));
        }

        let mut refresh_button = div()
            .px(px(12.0))
            .py(px(8.0))
            .rounded(px(12.0))
            .text_size(px(14.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(0xfafafa))
            .bg(if refreshing {
                rgb(0x42516d)
            } else if membership_op_busy {
                rgb(0x3b4559)
            } else {
                rgb(0x4f79bb)
            })
            .cursor(if membership_op_busy {
                CursorStyle::Arrow
            } else {
                CursorStyle::PointingHand
            })
            .child(if refreshing {
                "Refreshing…"
            } else if barrier_pending {
                "Awaiting recovery"
            } else {
                "PCS refresh"
            });

        if !membership_op_busy {
            refresh_button = refresh_button
                .on_mouse_down(MouseButton::Left, cx.listener(Self::on_refresh_clicked));
        }

        let reset_button = div()
            .px(px(12.0))
            .py(px(8.0))
            .rounded(px(12.0))
            .text_size(px(14.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(UI_PANEL_TEXT))
            .bg(rgb(UI_BUTTON_BG))
            .cursor(CursorStyle::PointingHand)
            .child("Reset session")
            .on_mouse_down(MouseButton::Left, cx.listener(Self::on_reset_clicked));

        div()
            .flex()
            .flex_col()
            .gap(px(8.0))
            .px(px(12.0))
            .py(px(12.0))
            .rounded(px(14.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .bg(rgb(UI_SIDEBAR_BG))
            .child(
                div()
                    .text_size(px(12.0))
                    .text_color(rgb(UI_MUTED_TEXT))
                    .child("Session controls"),
            )
            .child(leave_button)
            .child(refresh_button)
            .child(reset_button)
    }

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
            .bg(rgb(UI_BUTTON_BG))
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
                .bg(rgb(0x32415f))
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
            rgb(0x1b2840)
        } else {
            rgb(UI_ROW_BG)
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
            .bg(rgb(UI_BUTTON_BG))
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
                .bg(rgb(0x3e4b66))
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
                    .bg(rgb(UI_ROW_BG))
                    .border(px(1.0))
                    .border_color(rgb(0x2c3952))
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
                                .bg(rgb(0x224336))
                                .text_size(px(10.0))
                                .font_weight(FontWeight::BOLD)
                                .text_color(rgb(0x9cf5be))
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
                        .bg(rgb(UI_BUTTON_BG))
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
            .bg(rgb(UI_PANEL_BG))
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
                .text_color(rgb(0x0f1118))
                .child(format!("{} new", self.security_unread));
            let ack_button = div()
                .px(px(8.0))
                .py(px(4.0))
                .rounded(px(8.0))
                .text_size(px(12.0))
                .font_weight(FontWeight::MEDIUM)
                .text_color(rgb(UI_PANEL_TEXT))
                .bg(rgb(UI_BUTTON_BG))
                .cursor(CursorStyle::PointingHand)
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
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(UI_PANEL_TEXT))
            .bg(rgb(UI_BUTTON_BG))
            .cursor(CursorStyle::PointingHand)
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
                .text_size(px(12.0))
                .font_weight(FontWeight::MEDIUM)
                .text_color(rgb(UI_PANEL_TEXT))
                .bg(rgb(0x3d4b66))
                .cursor(CursorStyle::PointingHand)
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
                    .bg(rgb(0x2a1f31))
                    .border(px(1.0))
                    .border_color(rgb(0x4b334f))
                    .flex()
                    .flex_col()
                    .gap(px(2.0))
                    .child(
                        div()
                            .text_size(px(12.0))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(rgb(0xffe3ee))
                            .child(format!("{} – {}", event.alias, event.description)),
                    )
                    .child(
                        div()
                            .text_size(px(11.0))
                            .text_color(rgb(0xd3aec2))
                            .child(format_timestamp(event.timestamp_ms)),
                    );
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
            .child(list)
    }

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
