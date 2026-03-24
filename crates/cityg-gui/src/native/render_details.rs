use super::*;

impl AppModel {
    pub(super) fn session_row(&self, label: &str, value: &str) -> Div {
        div()
            .flex()
            .flex_col()
            .gap(px(3.0))
            .px(px(10.0))
            .py(px(8.0))
            .rounded(px(10.0))
            .bg(rgb(UI_ROW_BG))
            .child(
                div()
                    .text_size(px(11.0))
                    .text_color(rgb(UI_MUTED_TEXT))
                    .child(label.to_string()),
            )
            .child(
                div()
                    .text_size(px(13.0))
                    .text_color(rgb(UI_PANEL_TEXT))
                    .child(value.to_string()),
            )
    }

    pub(super) fn render_copyable_session_row(
        &self,
        label: &str,
        value: &str,
        handler: fn(&mut Self, &MouseDownEvent, &mut Window, &mut ViewContext<Self>),
        cx: &mut ViewContext<Self>,
    ) -> Div {
        div()
            .flex()
            .flex_col()
            .gap(px(4.0))
            .px(px(10.0))
            .py(px(8.0))
            .rounded(px(10.0))
            .bg(rgb(UI_ROW_BG))
            .child(
                div()
                    .text_size(px(11.0))
                    .text_color(rgb(UI_MUTED_TEXT))
                    .child(label.to_string()),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap(px(8.0))
                    .child(
                        div()
                            .flex_grow()
                            .text_size(px(13.0))
                            .text_color(rgb(UI_PANEL_TEXT))
                            .child(value.to_string()),
                    )
                    .child(
                        div()
                            .px(px(10.0))
                            .py(px(6.0))
                            .rounded(px(10.0))
                            .text_size(px(12.0))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(rgb(UI_ACCENT_BUTTON_TEXT))
                            .bg(rgb(UI_ACCENT_TEXT))
                            .cursor(CursorStyle::PointingHand)
                            .child("Copy")
                            .on_mouse_down(MouseButton::Left, cx.listener(handler)),
                    ),
            )
    }

    pub(super) fn render_epoch_age_row(&self, session: &AppSession) -> Div {
        let epoch_age_secs = SystemTime::now()
            .duration_since(session.fs_epoch_created_at)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        let rotation_interval = session.fs_epoch_rotation_interval_secs;

        let age_text = if epoch_age_secs < 60 {
            format!("{} seconds", epoch_age_secs)
        } else if epoch_age_secs < 3600 {
            format!("{} minutes", epoch_age_secs / 60)
        } else {
            format!("{:.1} hours", epoch_age_secs as f64 / 3600.0)
        };

        let value_text = format!(
            "Epoch #{} - Age: {} (manual rekey target: {}s)",
            session.fs_ec, age_text, rotation_interval
        );

        div()
            .flex()
            .flex_col()
            .gap(px(3.0))
            .px(px(10.0))
            .py(px(8.0))
            .rounded(px(10.0))
            .bg(rgb(UI_ROW_BG))
            .child(
                div()
                    .text_size(px(11.0))
                    .text_color(rgb(UI_MUTED_TEXT))
                    .child("Forward Secrecy Epoch"),
            )
            .child(
                div()
                    .text_size(px(13.0))
                    .text_color(rgb(UI_PANEL_TEXT))
                    .child(value_text),
            )
    }

    pub(super) fn render_regular_fingerprint_row(
        &self,
        session: &AppSession,
        cx: &mut ViewContext<Self>,
    ) -> Div {
        self.render_fingerprint_row(
            "Regular fingerprint",
            format_regular_fingerprint(session.regular_fingerprint.as_ref()),
            session.regular_fingerprint.is_some(),
            Self::on_copy_regular_fingerprint,
            cx,
        )
    }

    pub(super) fn render_fs_fingerprint_row(
        &self,
        session: &AppSession,
        cx: &mut ViewContext<Self>,
    ) -> Div {
        self.render_fingerprint_row(
            "FS fingerprint",
            format_fs_fingerprint(session.fs_fingerprint.as_ref(), session.fs_ec),
            session.fs_fingerprint.is_some(),
            Self::on_copy_fs_fingerprint,
            cx,
        )
    }

    pub(super) fn render_fingerprint_row(
        &self,
        label: &str,
        value: String,
        copy_enabled: bool,
        handler: fn(&mut Self, &MouseDownEvent, &mut Window, &mut ViewContext<Self>),
        cx: &mut ViewContext<Self>,
    ) -> Div {
        let mut copy_button = div()
            .px(px(10.0))
            .py(px(6.0))
            .rounded(px(10.0))
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(if copy_enabled {
                rgb(UI_ACCENT_BUTTON_TEXT)
            } else {
                rgb(UI_MUTED_TEXT)
            })
            .bg(if copy_enabled {
                rgb(UI_ACCENT_TEXT)
            } else {
                rgb(UI_BUTTON_BG)
            })
            .cursor(if copy_enabled {
                CursorStyle::PointingHand
            } else {
                CursorStyle::Arrow
            })
            .child("Copy");

        if copy_enabled {
            copy_button = copy_button.on_mouse_down(MouseButton::Left, cx.listener(handler));
        }

        div()
            .flex()
            .flex_col()
            .gap(px(4.0))
            .px(px(10.0))
            .py(px(8.0))
            .rounded(px(10.0))
            .bg(rgb(UI_ROW_BG))
            .child(
                div()
                    .text_size(px(11.0))
                    .text_color(rgb(UI_MUTED_TEXT))
                    .child(label.to_string()),
            )
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap(px(8.0))
                    .child(
                        div()
                            .flex_grow()
                            .text_size(px(13.0))
                            .text_color(rgb(UI_PANEL_TEXT))
                            .child(value),
                    )
                    .child(copy_button),
            )
    }
}
