use super::*;

impl AppModel {
    pub(super) fn render_message_composer(&self, cx: &mut ViewContext<Self>) -> Div {
        let barrier_pending = self.barrier_recovery_pending();
        let recovery_issue = self.barrier_recovery_issue();
        let border_color = if self.composer.active {
            rgb(UI_ACCENT_TEXT)
        } else {
            rgb(UI_PANEL_BORDER)
        };
        let background = if self.composer.active {
            ui_input_fill(true)
        } else {
            ui_input_fill(false)
        };

        let text_color = if self.composer.text.is_empty() {
            rgb(UI_MUTED_TEXT)
        } else {
            rgb(UI_PANEL_TEXT)
        };
        let pending_trace_summary = self
            .session
            .as_ref()
            .and_then(|session| session.barrier_state.last_pending_history_trace.as_ref())
            .map(BarrierPendingHistoryTrace::user_summary);

        let placeholder = if let Some(issue) = recovery_issue {
            match issue {
                BarrierRecoveryIssue::ContradictoryAuthenticatedHistory => {
                    "Recovery requires history reconciliation…"
                }
                BarrierRecoveryIssue::InsufficientAuthenticatedHistory
                | BarrierRecoveryIssue::LegacyPendingLocatorMissing => {
                    "Recovery requires authenticated history…"
                }
            }
        } else if barrier_pending {
            "Waiting for barrier recovery…"
        } else if self.composer.active {
            "Type a message…"
        } else {
            "Click to start typing…"
        };
        let button_fill = ui_button_fill(self.window_active);
        let button_hover_fill = ui_hover_fill(self.window_active);

        let mut row = div()
            .flex()
            .items_end()
            .gap(px(12.0))
            .px(px(14.0))
            .py(px(14.0))
            .rounded(px(16.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .bg(ui_toolbar_fill(self.window_active));

        let mut composer_panel = div()
            .flex_grow()
            .flex()
            .flex_col()
            .gap(px(6.0))
            .px(px(14.0))
            .py(px(12.0))
            .rounded(px(14.0))
            .border(px(1.0))
            .border_color(border_color)
            .bg(background)
            .cursor(CursorStyle::IBeam)
            .child(
                div()
                    .text_size(px(11.0))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(UI_MUTED_TEXT))
                    .child("Message"),
            )
            .child(
                div()
                    .text_size(px(15.0))
                    .line_height(px(20.0))
                    .text_color(text_color)
                    .child(self.render_native_text_field(
                        cx,
                        NativeTextFieldKind::Composer,
                        placeholder,
                    )),
            );
        if let Some(summary) = pending_trace_summary {
            composer_panel = composer_panel.child(
                div()
                    .text_size(px(11.0))
                    .text_color(rgb(UI_SUBTLE_TEXT))
                    .child(summary),
            );
        }
        row = row.child(composer_panel);

        let send_disabled = barrier_pending
            || !self.composer.is_ready()
            || matches!(self.send_status, SendStatus::Sending)
            || self.session.is_none();

        let label = match self.send_status {
            SendStatus::Sending => "Sending…",
            SendStatus::Idle if recovery_issue.is_some() => "Recovery required",
            SendStatus::Idle if barrier_pending => "Awaiting recovery",
            SendStatus::Idle => "Send",
        };

        let mut button = div()
            .px(px(16.0))
            .py(px(12.0))
            .rounded(px(13.0))
            .border(px(1.0))
            .border_color(if send_disabled {
                rgb(UI_PANEL_BORDER)
            } else {
                rgb(UI_ACCENT_TEXT)
            })
            .text_size(px(14.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(if send_disabled {
                rgb(UI_MUTED_TEXT)
            } else {
                rgb(UI_ACCENT_BUTTON_TEXT)
            })
            .bg(if send_disabled {
                button_fill
            } else {
                rgb(UI_ACCENT_TEXT)
            })
            .cursor(if send_disabled {
                CursorStyle::Arrow
            } else {
                CursorStyle::PointingHand
            })
            .child(label);

        if !send_disabled {
            button = button
                .hover(move |style| style.bg(rgb(0x78bcff)))
                .on_mouse_down(MouseButton::Left, cx.listener(Self::on_send_clicked));
        } else {
            button = button.hover(move |style| style.bg(button_hover_fill));
        }

        row.child(button)
    }
}
