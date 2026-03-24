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
            .bg(rgb(UI_CANVAS_BG))
            .child(left_column)
            .child(center_column)
            .child(right_column)
    }

    pub(super) fn render_overview_panel(
        &self,
        session: &AppSession,
        cx: &mut ViewContext<Self>,
    ) -> Div {
        div()
            .flex()
            .flex_col()
            .gap(px(8.0))
            .px(px(12.0))
            .py(px(12.0))
            .rounded(px(14.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .bg(rgb(UI_PANEL_BG))
            .child(
                div()
                    .text_size(px(16.0))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(UI_PANEL_TEXT))
                    .child("Session overview"),
            )
            .child(self.session_row("Server", &session.server_url))
            .child(self.render_copyable_session_row(
                "Room ID",
                &session.room_id,
                Self::on_copy_room_id,
                cx,
            ))
            .child(self.session_row("Alias", &session.alias))
            .child(self.render_copyable_session_row(
                "Room identity",
                &room_admin_identity_preview(&session.pop_public_key),
                Self::on_copy_room_identity,
                cx,
            ))
            .child(self.session_row("WEID", &hex_encode(session.we_epoch_id)))
            .child(self.session_row("Epoch key", &hex_encode(session.epoch_key)))
            .child(self.session_row("Parent root", &hex_encode(session.parent_root)))
            .child(self.session_row("Join delta", &hex_encode(session.join_delta_root)))
            .child(self.session_row("Revoked since", &hex_encode(session.revoked_since_root)))
            .child(self.session_row("Revoked root", &hex_encode(session.revoked_root)))
            .child(self.render_regular_fingerprint_row(session, cx))
            .child(self.render_fs_fingerprint_row(session, cx))
            .child(self.session_row("Proof mode", &session.proof_mode))
            .child(self.session_row("VRF suite", &session.vrf_id))
            .child(self.session_row("Policy", &session.policy_version))
            .child(self.session_row("FS policy", &session.fs_policy_version))
            .child(self.render_epoch_age_row(session))
            .child(self.session_row("KBROAD key (hex)", &hex_encode(&session.kbroad_public)))
    }

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
            rgb(0x1b2840)
        } else {
            rgb(UI_ROW_BG)
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
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(Self::on_room_admin_target_field_clicked),
            )
            .child(
                div()
                    .text_size(px(12.0))
                    .text_color(target_text_color)
                    .child(target_display),
            );

        let refresh_button = div()
            .px(px(8.0))
            .py(px(6.0))
            .rounded(px(10.0))
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(UI_PANEL_TEXT))
            .bg(rgb(UI_BUTTON_BG))
            .cursor(CursorStyle::PointingHand)
            .child("Refresh")
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(Self::on_room_admins_refresh_clicked),
            );
        let copy_button = div()
            .px(px(8.0))
            .py(px(6.0))
            .rounded(px(10.0))
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(UI_PANEL_TEXT))
            .bg(rgb(UI_BUTTON_BG))
            .cursor(CursorStyle::PointingHand)
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
                rgb(0x3a3f57)
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
                    rgb(0x8a243a)
                } else {
                    rgb(0x6a3443)
                }
            } else {
                rgb(0x3a3f57)
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
                rgb(0x3e4b66)
            } else {
                rgb(0x3a3f57)
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
                    .bg(rgb(0x4c5369))
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
                        .bg(rgb(UI_ROW_BG))
                        .border(px(1.0))
                        .border_color(rgb(0x2c3952))
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
            .px(px(12.0))
            .py(px(12.0))
            .rounded(px(14.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .bg(rgb(UI_PANEL_BG))
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
