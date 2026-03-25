use super::*;

impl AppModel {
    pub(super) fn render_room_admin_panel(
        &self,
        session: &AppSession,
        cx: &mut ViewContext<Self>,
    ) -> Div {
        let can_list = self.room_admins_loaded;
        let membership = self.room_admin_membership(session.pop_public_key.as_slice());
        let self_is_admin = membership.unwrap_or(false);
        let controls_locked = matches!(membership, Some(false));
        let mutation_busy = matches!(self.room_admin_status, RoomAdminStatus::Loading(_));
        let target_present = !self.room_admin_target.value().trim().is_empty();
        let revoke_staged = self.room_admin_revoke_is_staged_for_input();
        let role_text = match membership {
            Some(true) => "This device currently holds room-admin authority.".to_string(),
            Some(false) => "This device does not currently hold room-admin authority.".to_string(),
            None => "Refresh to load current room-admin state.".to_string(),
        };
        let status_text = match &self.room_admin_status {
            RoomAdminStatus::Idle => None,
            RoomAdminStatus::Loading(message) => Some(message.clone()),
            RoomAdminStatus::Error(message) => Some(message.clone()),
        };
        let access_text = if controls_locked {
            Some(
                "Grant and revoke controls are disabled because this device is not a current room admin."
                    .to_string(),
            )
        } else {
            None
        };
        let revoke_confirmation_text = self.room_admin_revoke_confirmation.as_ref().map(|target| {
            format!(
                "Revoke is staged for {}. Click Confirm revoke to submit, or Cancel revoke to back out.",
                room_admin_identity_preview(target)
            )
        });

        let target_active = self.room_admin_target.active;
        let target_border = if target_active {
            rgb(UI_ACCENT_TEXT)
        } else {
            rgb(UI_PANEL_BORDER)
        };
        let target_background = if target_active {
            ui_input_fill(true)
        } else {
            ui_row_fill(self.window_active)
        };
        let target_text_color = if self.room_admin_target.value().is_empty() {
            rgb(UI_MUTED_TEXT)
        } else {
            rgb(UI_PANEL_TEXT)
        };
        let target_display = if self.room_admin_target.value().is_empty() {
            "Paste target room identity public key (hex)".to_string()
        } else {
            self.room_admin_target.value().to_string()
        };

        let target_field = div()
            .flex()
            .items_center()
            .flex_grow()
            .px(px(10.0))
            .py(px(7.0))
            .rounded(px(10.0))
            .border(px(1.0))
            .border_color(target_border)
            .bg(target_background)
            .cursor(CursorStyle::IBeam)
            .child(
                div()
                    .text_size(px(12.0))
                    .line_height(px(18.0))
                    .text_color(target_text_color)
                    .child(self.render_native_text_field(
                        cx,
                        NativeTextFieldKind::RoomAdminTarget,
                        target_display,
                    )),
            );

        let refresh_button = div()
            .px(px(8.0))
            .py(px(6.0))
            .rounded(px(10.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(UI_PANEL_TEXT))
            .bg(ui_button_fill(self.window_active))
            .cursor(CursorStyle::PointingHand)
            .hover({
                let hover_fill = ui_hover_fill(self.window_active);
                move |style| style.bg(hover_fill)
            })
            .child("Refresh")
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(Self::on_room_admins_refresh_clicked),
            );
        let copy_button = div()
            .px(px(8.0))
            .py(px(6.0))
            .rounded(px(10.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(UI_PANEL_TEXT))
            .bg(ui_button_fill(self.window_active))
            .cursor(CursorStyle::PointingHand)
            .hover({
                let hover_fill = ui_hover_fill(self.window_active);
                move |style| style.bg(hover_fill)
            })
            .child("Copy my identity")
            .on_mouse_down(MouseButton::Left, cx.listener(Self::on_copy_room_identity));
        let grant_enabled = !controls_locked && !mutation_busy && target_present;
        let revoke_enabled = !controls_locked && !mutation_busy && target_present;
        let clear_enabled = !mutation_busy;
        let grant_button = div()
            .px(px(8.0))
            .py(px(6.0))
            .rounded(px(10.0))
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(if grant_enabled {
                rgb(UI_ACCENT_BUTTON_TEXT)
            } else {
                rgb(UI_MUTED_TEXT)
            })
            .bg(if grant_enabled {
                rgb(UI_ACCENT_TEXT)
            } else {
                rgb(UI_DISABLED_FILL)
            })
            .cursor(if grant_enabled {
                CursorStyle::PointingHand
            } else {
                CursorStyle::Arrow
            })
            .child("Grant");
        let grant_button = if grant_enabled {
            grant_button.on_mouse_down(
                MouseButton::Left,
                cx.listener(Self::on_room_admin_grant_clicked),
            )
        } else {
            grant_button
        };
        let revoke_button = div()
            .px(px(8.0))
            .py(px(6.0))
            .rounded(px(10.0))
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(if revoke_enabled {
                rgb(UI_PANEL_TEXT)
            } else {
                rgb(UI_MUTED_TEXT)
            })
            .bg(if revoke_enabled {
                if revoke_staged {
                    rgb(UI_DANGER_FILL)
                } else {
                    rgb(UI_DANGER_MUTED_FILL)
                }
            } else {
                rgb(UI_DISABLED_FILL)
            })
            .cursor(if revoke_enabled {
                CursorStyle::PointingHand
            } else {
                CursorStyle::Arrow
            })
            .child(if revoke_staged {
                "Confirm revoke"
            } else {
                "Revoke"
            });
        let revoke_button = if revoke_enabled {
            revoke_button.on_mouse_down(
                MouseButton::Left,
                cx.listener(Self::on_room_admin_revoke_clicked),
            )
        } else {
            revoke_button
        };
        let clear_button = div()
            .px(px(8.0))
            .py(px(6.0))
            .rounded(px(10.0))
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(if clear_enabled {
                rgb(UI_PANEL_TEXT)
            } else {
                rgb(UI_MUTED_TEXT)
            })
            .bg(if clear_enabled {
                rgb(UI_NEUTRAL_ELEVATED_FILL)
            } else {
                rgb(UI_DISABLED_FILL)
            })
            .cursor(if clear_enabled {
                CursorStyle::PointingHand
            } else {
                CursorStyle::Arrow
            })
            .child("Clear");
        let clear_button = if clear_enabled {
            clear_button.on_mouse_down(
                MouseButton::Left,
                cx.listener(Self::on_room_admin_target_clear_clicked),
            )
        } else {
            clear_button
        };
        let cancel_revoke_button = if revoke_staged {
            Some(
                div()
                    .px(px(8.0))
                    .py(px(6.0))
                    .rounded(px(10.0))
                    .text_size(px(12.0))
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(rgb(UI_PANEL_TEXT))
                    .bg(rgb(UI_NEUTRAL_ELEVATED_FILL))
                    .cursor(CursorStyle::PointingHand)
                    .child("Cancel revoke")
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(Self::on_room_admin_revoke_cancel_clicked),
                    ),
            )
        } else {
            None
        };

        let mut admin_list = div().flex().flex_col().gap(px(6.0));
        if !can_list {
            admin_list = admin_list.child(
                div()
                    .text_size(px(12.0))
                    .text_color(rgb(UI_SUBTLE_TEXT))
                    .child("Current room-admin identities are unavailable until this device refreshes admin state."),
            );
        } else if self.room_admins.is_empty() {
            admin_list = admin_list.child(
                div()
                    .text_size(px(12.0))
                    .text_color(rgb(UI_SUBTLE_TEXT))
                    .child("No room-admin identities reported."),
            );
        } else {
            for admin in &self.room_admins {
                let is_self = admin.as_slice() == session.pop_public_key.as_slice();
                let label = if is_self {
                    format!("{} · this device", room_admin_identity_preview(admin))
                } else {
                    room_admin_identity_preview(admin)
                };
                admin_list = admin_list.child(
                    div()
                        .px(px(9.0))
                        .py(px(7.0))
                        .rounded(px(10.0))
                        .bg(ui_row_fill(self.window_active))
                        .border(px(1.0))
                        .border_color(rgb(UI_PANEL_BORDER))
                        .child(
                            div()
                                .text_size(px(12.0))
                                .text_color(rgb(UI_PANEL_TEXT))
                                .child(label),
                        ),
                );
            }
        }

        let mut root = div()
            .flex()
            .flex_col()
            .gap(px(8.0))
            .px(px(14.0))
            .py(px(14.0))
            .rounded(px(18.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .bg(ui_panel_fill(self.window_active))
            .shadow_sm()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .text_size(px(15.0))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(UI_PANEL_TEXT))
                            .child("Room admins"),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(8.0))
                            .child(refresh_button)
                            .child(copy_button),
                    ),
            )
            .child(
                div()
                    .text_size(px(12.0))
                    .text_color(if self_is_admin {
                        rgb(UI_ACCENT_TEXT)
                    } else {
                        rgb(UI_SUBTLE_TEXT)
                    })
                    .child(role_text),
            )
            .child(target_field);

        if let Some(text) = access_text {
            root = root.child(
                div()
                    .text_size(px(12.0))
                    .text_color(rgb(UI_SUBTLE_TEXT))
                    .child(text),
            );
        }

        if let Some(text) = revoke_confirmation_text {
            root = root.child(
                div()
                    .text_size(px(12.0))
                    .text_color(rgb(UI_WARN_TEXT))
                    .child(text),
            );
        }

        let mut action_row = div()
            .flex()
            .flex_wrap()
            .gap(px(8.0))
            .child(grant_button)
            .child(revoke_button)
            .child(clear_button);
        if let Some(button) = cancel_revoke_button {
            action_row = action_row.child(button);
        }
        root = root.child(action_row);

        if let Some(text) = status_text {
            root = root.child(
                div()
                    .text_size(px(12.0))
                    .text_color(rgb(UI_WARN_TEXT))
                    .child(text),
            );
        }

        root.child(admin_list)
    }
}
