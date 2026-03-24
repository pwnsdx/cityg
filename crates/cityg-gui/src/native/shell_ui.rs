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

    // Toast notification helpers
    pub(super) fn show_toast(&mut self, toast: Toast, cx: &mut ViewContext<Self>) {
        self.toasts.push(toast);
        cx.notify();

        let cleanup_delay = Self::toast_cleanup_delay();
        let delay = Tokio::spawn_result(cx, async move {
            sleep(cleanup_delay).await;
            Ok(())
        });

        // Schedule cleanup of expired toasts
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

    // Set categorized error with automatic retry action tracking
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

    // Render loading spinner with animated appearance
    pub(super) fn render_spinner(&self) -> Div {
        div()
            .flex()
            .items_center()
            .gap(px(2.0))
            .child(
                div()
                    .text_size(px(16.0))
                    .text_color(rgb(0x72f88e))
                    .child("●"),
            )
            .child(
                div()
                    .text_size(px(16.0))
                    .text_color(rgb(0x5fd87f))
                    .child("●"),
            )
            .child(
                div()
                    .text_size(px(16.0))
                    .text_color(rgb(0x4cb86f))
                    .child("●"),
            )
    }

    // Render categorized error box with actions
    pub(super) fn render_error_box(&self, cx: &mut ViewContext<Self>) -> Option<Div> {
        let error = self.categorized_error.as_ref()?;

        let (icon, color) = match error.category {
            ErrorCategory::Network => ("⚠", rgb(0xffa500)),
            ErrorCategory::Crypto => ("⚠", rgb(0xff6b6b)),
            ErrorCategory::Policy => ("⛔", rgb(0xff9f68)),
            ErrorCategory::Server => ("⚠", rgb(0xff6b6b)),
            ErrorCategory::Validation => ("ℹ", rgb(0x72a5f8)),
        };

        let mut error_box = div()
            .flex()
            .flex_col()
            .gap(px(12.0))
            .px(px(16.0))
            .py(px(14.0))
            .rounded(px(12.0))
            .bg(rgb(0x1f1f2e))
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
                            .text_color(rgb(0xf2f4ff))
                            .child(error.user_message.clone()),
                    ),
            )
            .child(
                div()
                    .text_size(px(13.0))
                    .text_color(rgb(0x9aa5d3))
                    .child(error.recovery_suggestion.clone()),
            );

        // Add action buttons row
        let mut action_row = div().flex().flex_wrap().gap(px(8.0)).mt(px(4.0));

        // Primary action: Try Again (if retryable)
        if error.can_retry {
            action_row = action_row.child(
                div()
                    .px(px(14.0))
                    .py(px(8.0))
                    .rounded(px(10.0))
                    .bg(rgb(0x72f88e))
                    .text_color(rgb(0x0f1118))
                    .text_size(px(13.0))
                    .font_weight(FontWeight::MEDIUM)
                    .cursor(CursorStyle::PointingHand)
                    .child("Try Again")
                    .on_mouse_down(MouseButton::Left, cx.listener(Self::on_retry_clicked)),
            );
        }

        // Secondary actions
        action_row = action_row
            .child(
                div()
                    .px(px(14.0))
                    .py(px(8.0))
                    .rounded(px(10.0))
                    .bg(rgb(0x2a3148))
                    .text_color(rgb(0xc8d0e8))
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
                    .bg(rgb(0x2a3148))
                    .text_color(rgb(0xc8d0e8))
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
                    .bg(rgb(0x1f1f2e))
                    .text_color(rgb(0x9aa5d3))
                    .text_size(px(13.0))
                    .cursor(CursorStyle::PointingHand)
                    .child("Dismiss")
                    .on_mouse_down(MouseButton::Left, cx.listener(Self::on_dismiss_error)),
            );

        error_box = error_box.child(action_row);
        Some(error_box)
    }

    // Render toast notifications
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
                    ToastKind::Success => ("✓", rgb(0x2d5f2d)),
                    ToastKind::Error => ("✗", rgb(0x5f2d2d)),
                    ToastKind::Info => ("ℹ", rgb(0x2d3d5f)),
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
                        .border_color(rgb(0x3a3a4f))
                        .child(
                            div()
                                .text_size(px(16.0))
                                .text_color(rgb(0xf2f4ff))
                                .child(icon),
                        )
                        .child(
                            div()
                                .text_size(px(14.0))
                                .text_color(rgb(0xf2f4ff))
                                .child(toast.message.clone()),
                        ),
                );
            }
        }

        Some(container)
    }

    pub(super) fn render_join(&self, cx: &mut ViewContext<Self>) -> Div {
        let heading_color = rgb(0xf2f4ff);
        let subtext_color = rgb(0x9aa5d3);
        let error_color = rgb(0xff6b6b);
        let info_color = rgb(0x72f88e);
        let join_disabled =
            !self.join_form.is_ready() || matches!(self.join_status, JoinStatus::Joining);

        let form = div()
            .flex()
            .flex_col()
            .px(px(40.0))
            .py(px(36.0))
            .gap(px(16.0))
            .rounded(px(18.0))
            .bg(rgb(0x151929))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(4.0))
                    .child(
                        div()
                            .text_size(px(28.0))
                            .font_weight(FontWeight::BOLD)
                            .text_color(heading_color)
                            .child("Join a City-G Room"),
                    )
                    .child(div().text_size(px(14.0)).text_color(subtext_color).child(
                        "Connect to a City-G server, pick your alias, and request a join ticket.",
                    )),
            )
            .child(self.render_field(
                "Server URL",
                &self.join_form.server,
                "https://server.example",
                ActiveField::Server,
                cx,
            ))
            .child(self.render_field(
                "Room ID",
                &self.join_form.room_id,
                "64 hex characters",
                ActiveField::Room,
                cx,
            ))
            .child(
                div()
                    .flex()
                    .justify_between()
                    .items_center()
                    .text_size(px(12.0))
                    .text_color(subtext_color)
                    .child("Paste a City-G invite or enter a 64-character room ID.")
                    .child(
                        div()
                            .px(px(12.0))
                            .py(px(6.0))
                            .rounded(px(10.0))
                            .bg(rgb(0x2a3148))
                            .text_color(rgb(0xf2f4ff))
                            .cursor(CursorStyle::PointingHand)
                            .text_size(px(12.0))
                            .child("Generate new ID")
                            .on_mouse_down(
                                MouseButton::Left,
                                cx.listener(Self::on_generate_room_id),
                            ),
                    ),
            )
            .child(self.render_field(
                "Alias",
                &self.join_form.alias,
                "your name",
                ActiveField::Alias,
                cx,
            ))
            .child({
                let status_text = match self.join_status {
                    JoinStatus::Joining => Some("Requesting join ticket...".to_string()),
                    JoinStatus::Idle => None,
                };
                let mut status_div = div()
                    .flex()
                    .gap(px(6.0))
                    .items_center()
                    .text_size(px(13.0))
                    .text_color(subtext_color);
                if let Some(text) = status_text {
                    status_div = status_div.child(self.render_spinner()).child(text);
                }
                status_div
            })
            .child({
                let mut button = div()
                    .px(px(18.0))
                    .py(px(10.0))
                    .rounded(px(12.0))
                    .text_size(px(16.0))
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(rgb(0x0f1118))
                    .bg(if join_disabled {
                        rgb(0x3a3f57)
                    } else {
                        rgb(0x72f88e)
                    })
                    .cursor(if join_disabled {
                        CursorStyle::Arrow
                    } else {
                        CursorStyle::PointingHand
                    })
                    .child(if matches!(self.join_status, JoinStatus::Joining) {
                        "Joining..."
                    } else {
                        "Join room"
                    });

                if !join_disabled {
                    button =
                        button.on_mouse_down(MouseButton::Left, cx.listener(Self::on_join_clicked));
                }
                button
            });

        let mut root = div()
            .flex()
            .flex_col()
            .items_center()
            .gap(px(20.0))
            .child(form);

        // Show categorized error box if available
        if let Some(error_box) = self.render_error_box(cx) {
            root = root.child(error_box);
        } else if let Some(err) = &self.last_error {
            // Fallback to simple error message if no categorized error
            root = root.child(
                div()
                    .text_size(px(13.0))
                    .text_color(error_color)
                    .child(format!("Join failed: {err}")),
            );
        }

        if let Some(info) = &self.info_message {
            root = root.child(
                div()
                    .text_size(px(13.0))
                    .text_color(info_color)
                    .child(info.clone()),
            );
        }

        root
    }

    pub(super) fn render_field(
        &self,
        label: &str,
        value: &str,
        placeholder: &str,
        field: ActiveField,
        cx: &mut ViewContext<Self>,
    ) -> Div {
        let is_active = self.join_form.active == Some(field);
        let border = if is_active {
            rgb(0x72f88e)
        } else {
            rgb(0x2a3148)
        };
        let background = if is_active {
            rgb(0x1b2135)
        } else {
            rgb(0x161b2a)
        };
        let text_color = if value.is_empty() {
            rgb(0x5b6584)
        } else {
            rgb(0xf5f7ff)
        };
        let display = if value.is_empty() {
            placeholder.to_string()
        } else {
            value.to_string()
        };

        div()
            .flex()
            .flex_col()
            .gap(px(6.0))
            .child(
                div()
                    .text_size(px(12.0))
                    .text_color(rgb(0x9aa5d3))
                    .child(label.to_string()),
            )
            .child({
                let handler_field = field;
                div()
                    .px(px(14.0))
                    .py(px(10.0))
                    .rounded(px(12.0))
                    .border(px(1.0))
                    .border_color(border)
                    .bg(background)
                    .cursor(CursorStyle::IBeam)
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _, _, cx| {
                            this.focus_field(handler_field, cx);
                        }),
                    )
                    .child(
                        div()
                            .text_size(px(16.0))
                            .text_color(text_color)
                            .child(display),
                    )
            })
    }
}

pub(super) const UI_CANVAS_BG: u32 = 0x111522;
pub(super) const UI_SIDEBAR_BG: u32 = 0x151c2f;
pub(super) const UI_PANEL_BG: u32 = 0x171f33;
pub(super) const UI_ROW_BG: u32 = 0x1e2940;
pub(super) const UI_PANEL_BORDER: u32 = 0x2e3d5b;
pub(super) const UI_BUTTON_BG: u32 = 0x2c3956;
pub(super) const UI_PANEL_TEXT: u32 = 0xf2f5ff;
pub(super) const UI_SUBTLE_TEXT: u32 = 0x9eabd2;
pub(super) const UI_MUTED_TEXT: u32 = 0x7180a5;
pub(super) const UI_ACCENT_TEXT: u32 = 0x67f3b8;
pub(super) const UI_ACCENT_BUTTON_TEXT: u32 = 0x122015;
pub(super) const UI_WARN_TEXT: u32 = 0xffb384;
pub(super) const BARRIER_HP_MODE: &str = "barrier-sealed-v1";
