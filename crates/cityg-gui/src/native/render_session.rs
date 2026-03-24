use super::*;

impl AppModel {
    pub(super) fn render_session(
        &self,
        window: &mut Window,
        session: &AppSession,
        cx: &mut ViewContext<Self>,
    ) -> Div {
        let window_size = window.bounds().size;
        let window_width = f32::from(window_size.width);
        let sidebar_width = if window_width >= 1360.0 {
            248.0
        } else if window_width >= 1100.0 {
            214.0
        } else {
            176.0
        };
        let details_width = if window_width >= 1460.0 {
            392.0
        } else if window_width >= 1180.0 {
            332.0
        } else {
            284.0
        };

        let mut center_column = div()
            .flex()
            .flex_col()
            .flex_grow()
            .min_w(px(280.0))
            .min_h(px(0.0))
            .h_full()
            .gap(px(12.0))
            .child(self.render_chat_header(session, cx))
            .child(self.render_message_panel(session, cx));

        if let Some(info) = &self.info_message {
            center_column = center_column.child(
                div()
                    .text_size(px(13.0))
                    .text_color(rgb(UI_ACCENT_TEXT))
                    .child(info.clone()),
            );
        }

        if let Some(error_box) = self.render_error_box(cx) {
            center_column = center_column.child(error_box);
        } else if let Some(err) = &self.last_error {
            center_column = center_column.child(
                div()
                    .text_size(px(13.0))
                    .text_color(rgb(UI_WARN_TEXT))
                    .child(err.clone()),
            );
        }

        let left_column = div()
            .flex()
            .flex_col()
            .min_w(px(sidebar_width))
            .max_w(px(sidebar_width))
            .min_h(px(0.0))
            .h_full()
            .gap(px(12.0))
            .child(self.render_workspace_sidebar(session, cx))
            .child(self.render_leave_controls(cx));

        let details_scroll = div()
            .flex()
            .flex_col()
            .flex_grow()
            .min_h(px(0.0))
            .h_full()
            .gap(px(12.0))
            .id("session-details-scroll")
            .track_scroll(&self.right_sidebar_scroll_handle)
            .overflow_y_scroll()
            .block_mouse_except_scroll()
            .child(self.render_overview_panel(session, cx))
            .child(self.render_room_admin_panel(session, cx))
            .child(self.render_members_panel(cx))
            .child(self.render_security_panel(cx))
            .child(self.render_activity_panel(cx));

        let right_column = div()
            .flex()
            .flex_col()
            .min_w(px(details_width))
            .max_w(px(details_width))
            .min_h(px(0.0))
            .h_full()
            .child(details_scroll);

        div()
            .flex()
            .w_full()
            .h_full()
            .min_w(px(0.0))
            .min_h(px(420.0))
            .px(px(16.0))
            .py(px(16.0))
            .gap(px(14.0))
            .bg(ui_canvas_fill(self.window_active))
            .child(left_column)
            .child(center_column)
            .child(right_column)
    }
}
