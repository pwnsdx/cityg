use super::*;

impl AppModel {
    pub(super) fn render_leave_controls(
        &self,
        window: &Window,
        cx: &mut ViewContext<Self>,
    ) -> impl IntoElement {
        let leaving = matches!(self.leave_status, LeaveStatus::Leaving);
        let expelling = matches!(self.leave_status, LeaveStatus::Expelling);
        let refreshing = matches!(self.leave_status, LeaveStatus::Refreshing);
        let barrier_pending = self.barrier_recovery_pending();
        let recovery_required = self.barrier_recovery_issue().is_some();
        let membership_op_busy = leaving || expelling || refreshing || barrier_pending;
        let button_fill = ui_button_fill(self.window_active);
        let refresh_hover_fill = ui_hover_fill(self.window_active);
        let reset_hover_fill = ui_hover_fill(self.window_active);
        let mut leave_button = div()
            .px(px(12.0))
            .py(px(9.0))
            .rounded(px(12.0))
            .border(px(1.0))
            .border_color(if membership_op_busy {
                rgb(UI_DANGER_MUTED_FILL)
            } else {
                rgb(UI_DANGER_FILL)
            })
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
            leave_button = leave_button
                .hover(move |style| style.bg(rgb(0xd06c7b)))
                .on_mouse_down(MouseButton::Left, cx.listener(Self::on_leave_clicked));
        }

        let mut refresh_button = div()
            .px(px(12.0))
            .py(px(9.0))
            .rounded(px(12.0))
            .border(px(1.0))
            .border_color(if membership_op_busy {
                rgb(UI_PANEL_BORDER)
            } else {
                rgb(UI_ACCENT_SOFT_FILL)
            })
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
            } else if recovery_required {
                "Recovery required"
            } else if barrier_pending {
                "Awaiting recovery"
            } else {
                "PCS refresh"
            });

        if !membership_op_busy {
            refresh_button = refresh_button
                .hover(move |style| style.bg(refresh_hover_fill))
                .on_mouse_down(MouseButton::Left, cx.listener(Self::on_refresh_clicked));
        }

        let reset_button = div()
            .px(px(12.0))
            .py(px(9.0))
            .rounded(px(12.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .text_size(px(14.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(UI_PANEL_TEXT))
            .bg(button_fill)
            .cursor(CursorStyle::PointingHand)
            .hover(move |style| style.bg(reset_hover_fill))
            .child("Reset session")
            .on_mouse_down(MouseButton::Left, cx.listener(Self::on_reset_clicked));

        material_surface(
            window,
            MaterialStyle::sidebar().emphasis(MaterialEmphasis::Medium),
        )
        .flex()
        .flex_col()
        .gap(px(8.0))
        .px(px(14.0))
        .py(px(14.0))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(4.0))
                .child(
                    div()
                        .text_size(px(12.0))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(UI_MUTED_TEXT))
                        .child("Room actions"),
                )
                .child(
                    div()
                        .text_size(px(12.0))
                        .text_color(rgb(UI_SUBTLE_TEXT))
                        .child("Leave, refresh forward secrecy, or clear local state."),
                ),
        )
        .child(leave_button)
        .child(refresh_button)
        .child(reset_button)
    }
}
