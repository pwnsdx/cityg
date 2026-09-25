use super::*;

impl AppModel {
    pub(super) fn render_overview_panel(
        &self,
        window: &Window,
        session: &AppSession,
        cx: &mut ViewContext<Self>,
    ) -> impl IntoElement {
        material_surface(
            window,
            MaterialStyle::inspector().emphasis(MaterialEmphasis::Medium),
        )
        .flex()
        .flex_col()
        .gap(px(8.0))
        .px(px(12.0))
        .py(px(12.0))
        .child(
            div()
                .text_size(px(16.0))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(rgb(UI_PANEL_TEXT))
                .child("Session overview"),
        )
        .child(self.session_row("Server", &session.server_url))
        .child(self.session_row("Endpoint", self.endpoint_mode.label()))
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
        .child(self.session_row("Profile", "City-G v0.3 (X-Wing, ML-DSA-65)"))
        .child(self.session_row(
            "Epoch",
            &format!(
                "{} · leaf {} · {} of {} member(s)",
                session.view.epoch,
                session.view.me.leaf,
                session.view.roster.len(),
                session.view.capacity
            ),
        ))
        .child(self.session_row(
            "Role",
            if session.is_admin() {
                "Admin"
            } else {
                "Member"
            },
        ))
        .child(self.render_regular_fingerprint_row(session, cx))
        .child(self.render_fs_fingerprint_row(session, cx))
        .child(self.session_row("Tree hash", &hex_encode(session.view.tree_hash)))
        .child(self.session_row(
            "Pending leave requests",
            &session.view.pending_removals.to_string(),
        ))
        .child(self.render_epoch_age_row(session))
    }
}
