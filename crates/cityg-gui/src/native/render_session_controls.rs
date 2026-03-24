use super::*;

impl AppModel {
    pub(super) fn render_leave_controls(&self, cx: &mut ViewContext<Self>) -> Div {
        let leaving = matches!(self.leave_status, LeaveStatus::Leaving);
        let expelling = matches!(self.leave_status, LeaveStatus::Expelling);
        let refreshing = matches!(self.leave_status, LeaveStatus::Refreshing);
        let barrier_pending = self.barrier_recovery_pending();
        let membership_op_busy = leaving || expelling || refreshing || barrier_pending;
        let mut leave_button = div()
            .px(px(12.0))
            .py(px(8.0))
            .rounded(px(12.0))
            .text_size(px(14.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(UI_PANEL_TEXT))
            .bg(if leaving {
                rgb(UI_DANGER_MUTED_FILL)
            } else if membership_op_busy {
                rgb(UI_DANGER_MUTED_FILL)
            } else {
                rgb(UI_DANGER_FILL)
            })
            .cursor(if membership_op_busy {
                CursorStyle::Arrow
            } else {
                CursorStyle::PointingHand
            })
            .child(if leaving {
                "Leaving…"
            } else if expelling {
                "Updating roster…"
            } else {
                "Leave room"
            });

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
            .text_color(if membership_op_busy {
                rgb(UI_MUTED_TEXT)
            } else {
                rgb(UI_ACCENT_TEXT)
            })
            .bg(if refreshing {
                rgb(UI_NEUTRAL_ELEVATED_FILL)
            } else if membership_op_busy {
                rgb(UI_DISABLED_FILL)
            } else {
                rgb(UI_NEUTRAL_FILL)
            })
            .cursor(if membership_op_busy {
                CursorStyle::Arrow
            } else {
                CursorStyle::PointingHand
            })
            .child(if refreshing {
                "Refreshing…"
            } else if expelling {
                "Updating roster…"
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
            .bg(ui_button_fill(self.window_active))
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
            .bg(ui_sidebar_fill(self.window_active))
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
}
