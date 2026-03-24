use super::*;

impl AppModel {
    pub(super) fn toast_cleanup_delay() -> Duration {
        #[cfg(test)]
        {
            Duration::from_millis(1)
        }
        #[cfg(not(test))]
        {
            Duration::from_secs(8)
        }
    }

    pub(super) fn show_toast(&mut self, toast: Toast, cx: &mut ViewContext<Self>) {
        self.toasts.push(toast);
        cx.notify();

        let cleanup_delay = Self::toast_cleanup_delay();
        let delay = Tokio::spawn_result(cx, async move {
            sleep(cleanup_delay).await;
            Ok(())
        });

        cx.spawn(async move |this, cx| {
            if let Err(err) = delay.await {
                warn!("toast cleanup delay task failed: {err}");
                return;
            }
            let _ = this.update(cx, |model, cx| {
                model.cleanup_expired_toasts();
                cx.notify();
            });
        })
        .detach();
    }

    pub(super) fn show_success(&mut self, message: impl Into<String>, cx: &mut ViewContext<Self>) {
        self.show_toast(Toast::success(message), cx);
    }

    pub(super) fn show_error_toast(
        &mut self,
        message: impl Into<String>,
        cx: &mut ViewContext<Self>,
    ) {
        self.show_toast(Toast::error(message), cx);
    }

    pub(super) fn show_info(&mut self, message: impl Into<String>, cx: &mut ViewContext<Self>) {
        self.show_toast(Toast::info(message), cx);
    }

    pub(super) fn cleanup_expired_toasts(&mut self) {
        self.toasts.retain(|t| !t.is_expired());
    }

    pub(super) fn set_error(
        &mut self,
        err: &anyhow::Error,
        context: &str,
        retry_action: Option<RetryAction>,
    ) {
        let categorized = categorize_error(err, context);
        self.last_error = Some(categorized.user_message.clone());
        self.categorized_error = Some(categorized);
        self.last_retry_action = retry_action;
    }

    pub(super) fn clear_error(&mut self) {
        self.last_error = None;
        self.categorized_error = None;
        self.last_retry_action = None;
    }

    pub(super) fn render_spinner(&self) -> Div {
        div()
            .flex()
            .items_center()
            .gap(px(2.0))
            .child(
                div()
                    .text_size(px(16.0))
                    .text_color(rgb(UI_ACCENT_TEXT))
                    .child("●"),
            )
            .child(
                div()
                    .text_size(px(16.0))
                    .text_color(rgb(0x62d792))
                    .child("●"),
            )
            .child(
                div()
                    .text_size(px(16.0))
                    .text_color(rgb(0x4eb277))
                    .child("●"),
            )
    }

    pub(super) fn render_error_box(&self, cx: &mut ViewContext<Self>) -> Option<Div> {
        let error = self.categorized_error.as_ref()?;

        let (icon, color) = match error.category {
            ErrorCategory::Network => ("⚠", rgb(UI_WARN_TEXT)),
            ErrorCategory::Crypto => ("⚠", rgb(UI_ERROR_TEXT)),
            ErrorCategory::Policy => ("⛔", rgb(0xff9f68)),
            ErrorCategory::Server => ("⚠", rgb(UI_ERROR_TEXT)),
            ErrorCategory::Validation => ("ℹ", rgb(UI_INFO_TEXT)),
        };

        let mut error_box = div()
            .flex()
            .flex_col()
            .gap(px(12.0))
            .px(px(16.0))
            .py(px(14.0))
            .rounded(px(12.0))
            .bg(rgba(0x111214ef))
            .border_1()
            .border_color(color)
            .max_w(px(640.0))
            .child(
                div()
                    .flex()
                    .gap(px(8.0))
                    .items_center()
                    .child(div().text_size(px(18.0)).child(icon))
                    .child(
                        div()
                            .text_size(px(15.0))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(UI_PANEL_TEXT))
                            .child(error.user_message.clone()),
                    ),
            )
            .child(
                div()
                    .text_size(px(13.0))
                    .text_color(rgb(UI_SUBTLE_TEXT))
                    .child(error.recovery_suggestion.clone()),
            );

        let mut action_row = div().flex().flex_wrap().gap(px(8.0)).mt(px(4.0));

        if error.can_retry {
            action_row = action_row.child(
                div()
                    .px(px(14.0))
                    .py(px(8.0))
                    .rounded(px(10.0))
                    .bg(rgb(UI_ACCENT_TEXT))
                    .text_color(rgb(UI_ACCENT_BUTTON_TEXT))
                    .text_size(px(13.0))
                    .font_weight(FontWeight::MEDIUM)
                    .cursor(CursorStyle::PointingHand)
                    .child("Try Again")
                    .on_mouse_down(MouseButton::Left, cx.listener(Self::on_retry_clicked)),
            );
        }

        action_row = action_row
            .child(
                div()
                    .px(px(14.0))
                    .py(px(8.0))
                    .rounded(px(10.0))
                    .bg(ui_button_fill(self.window_active))
                    .text_color(rgb(UI_PANEL_TEXT))
                    .text_size(px(13.0))
                    .cursor(CursorStyle::PointingHand)
                    .child("Copy Details")
                    .on_mouse_down(MouseButton::Left, cx.listener(Self::on_copy_error_details)),
            )
            .child(
                div()
                    .px(px(14.0))
                    .py(px(8.0))
                    .rounded(px(10.0))
                    .bg(ui_button_fill(self.window_active))
                    .text_color(rgb(UI_PANEL_TEXT))
                    .text_size(px(13.0))
                    .cursor(CursorStyle::PointingHand)
                    .child("Report Issue")
                    .on_mouse_down(MouseButton::Left, cx.listener(Self::on_report_issue)),
            )
            .child(
                div()
                    .px(px(14.0))
                    .py(px(8.0))
                    .rounded(px(10.0))
                    .bg(rgb(UI_NEUTRAL_FILL))
                    .text_color(rgb(UI_SUBTLE_TEXT))
                    .text_size(px(13.0))
                    .cursor(CursorStyle::PointingHand)
                    .child("Dismiss")
                    .on_mouse_down(MouseButton::Left, cx.listener(Self::on_dismiss_error)),
            );

        error_box = error_box.child(action_row);
        Some(error_box)
    }

    pub(super) fn render_toasts(&self) -> Option<Div> {
        if self.toasts.is_empty() {
            return None;
        }

        let mut container = div()
            .absolute()
            .top(px(20.0))
            .right(px(20.0))
            .flex()
            .flex_col()
            .gap(px(8.0));

        for toast in &self.toasts {
            if !toast.is_expired() {
                let (icon, bg_color) = match toast.kind {
                    ToastKind::Success => ("✓", rgba(0x1f3427ee)),
                    ToastKind::Error => ("✗", rgba(0x4a252cee)),
                    ToastKind::Info => ("ℹ", rgba(0x22262eee)),
                };

                container = container.child(
                    div()
                        .flex()
                        .gap(px(10.0))
                        .items_center()
                        .px(px(16.0))
                        .py(px(12.0))
                        .rounded(px(10.0))
                        .bg(bg_color)
                        .border_1()
                        .border_color(rgb(UI_PANEL_BORDER))
                        .child(
                            div()
                                .text_size(px(16.0))
                                .text_color(rgb(UI_PANEL_TEXT))
                                .child(icon),
                        )
                        .child(
                            div()
                                .text_size(px(14.0))
                                .text_color(rgb(UI_PANEL_TEXT))
                                .child(toast.message.clone()),
                        ),
                );
            }
        }

        Some(container)
    }
}
