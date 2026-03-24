use super::*;

impl AppModel {
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
}
