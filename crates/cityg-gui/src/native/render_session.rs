use super::*;

impl AppModel {
    pub(super) fn render_session(
        &mut self,
        window: &mut Window,
        session: &AppSession,
        cx: &mut ViewContext<Self>,
    ) -> Div {
        let window_size = window.bounds().size;
        let window_width = f32::from(window_size.width);
        let sidebar_width = self.resolved_sidebar_width(window_width);
        let inspector_width = self.resolved_inspector_width(window_width);
        let center_min_width = if inspector_width.is_some() {
            360.0
        } else {
            320.0
        };

        let mut center_column = div()
            .flex()
            .flex_col()
            .flex_grow()
            .min_w(px(center_min_width))
            .min_h(px(0.0))
            .h_full()
            .gap(px(12.0))
            .child(self.render_chat_header(session, window_width, cx))
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

        let mut main_columns = div()
            .flex()
            .flex_grow()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .h_full()
            .gap(px(10.0))
            .child(center_column);

        if let Some(inspector_width) = inspector_width {
            main_columns = main_columns
                .child(self.render_inspector_divider(inspector_width, cx))
                .child(self.render_session_inspector(session, inspector_width, cx));
        }

        let mut workspace = div()
            .flex()
            .flex_grow()
            .min_w(px(0.0))
            .min_h(px(0.0))
            .h_full()
            .gap(px(10.0));

        if let Some(sidebar_width) = sidebar_width {
            workspace = workspace
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .min_w(px(sidebar_width))
                        .max_w(px(sidebar_width))
                        .min_h(px(0.0))
                        .h_full()
                        .gap(px(10.0))
                        .child(self.render_workspace_sidebar(session, cx))
                        .child(self.render_leave_controls(cx)),
                )
                .child(self.render_sidebar_divider(sidebar_width, cx));
        }

        workspace = workspace.child(main_columns);

        let root = div()
            .flex()
            .w_full()
            .h_full()
            .min_w(px(0.0))
            .min_h(px(420.0))
            .px(px(12.0))
            .py(px(12.0))
            .bg(ui_canvas_fill(self.window_active))
            .child(workspace);

        root
    }
}
