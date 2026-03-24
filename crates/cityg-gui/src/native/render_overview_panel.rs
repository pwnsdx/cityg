use super::*;

impl AppModel {
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
            .bg(ui_panel_fill(self.window_active))
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
}
