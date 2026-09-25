use super::*;

impl AppModel {
    pub(super) fn room_admin_membership(&self, pop_public_key: &[u8]) -> Option<bool> {
        if !self.room_admins_loaded {
            return None;
        }
        Some(
            self.room_admins
                .iter()
                .any(|admin| admin.as_slice() == pop_public_key),
        )
    }

    pub(super) fn room_admin_controls_locked(&self, session: &AppSession) -> bool {
        matches!(
            self.room_admin_membership(session.pop_public_key.as_slice()),
            Some(false)
        )
    }

    pub(super) fn room_admin_revoke_is_staged_for_input(&self) -> bool {
        let Some(staged) = self.room_admin_revoke_confirmation.as_ref() else {
            return false;
        };
        decode_room_admin_target_hex(self.room_admin_target.value())
            .map(|target| target == *staged)
            .unwrap_or(false)
    }

    pub(super) fn clear_room_admin_revoke_confirmation(&mut self) {
        self.room_admin_revoke_confirmation = None;
    }

    pub(super) fn focus_room_admin_target(
        &mut self,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.focus_text_field(NativeTextFieldKind::RoomAdminTarget, window, cx);
    }

    pub(super) fn clear_room_admin_target(&mut self, cx: &mut ViewContext<Self>) {
        self.room_admin_target.clear();
        self.room_admin_target.blur();
        self.clear_room_admin_revoke_confirmation();
        cx.notify();
    }

    pub(super) fn set_room_admin_target(
        &mut self,
        target_pop_public_key: Vec<u8>,
        cx: &mut ViewContext<Self>,
    ) {
        self.room_admin_target
            .set_value(hex_encode(target_pop_public_key));
        self.clear_room_admin_revoke_confirmation();
        self.room_admin_target.focus();
        self.members_search.blur();
        self.composer.blur();
        self.show_info("Loaded member identity into room-admin target", cx);
    }

    /// Refresh the admin list (a room sync: admins come from the roster).
    pub(super) fn refresh_room_admins(&mut self, cx: &mut ViewContext<Self>) {
        if self.session.is_none() {
            return;
        }
        self.clear_room_admin_revoke_confirmation();
        self.schedule_fetch(cx, Duration::from_millis(0));
        cx.notify();
    }

    pub(super) fn start_room_admin_mutation(
        &mut self,
        kind: RoomAdminMutationKind,
        target_pop_public_key: Vec<u8>,
        cx: &mut ViewContext<Self>,
    ) {
        let Some(session) = self.session.clone() else {
            return;
        };
        if matches!(self.room_admin_status, RoomAdminStatus::Loading(_)) {
            return;
        }
        self.clear_room_admin_revoke_confirmation();
        self.room_admin_status = RoomAdminStatus::Loading(kind.present_progressive().to_string());
        cx.notify();

        let member = session.member.clone();
        let grant = matches!(kind, RoomAdminMutationKind::Grant);
        let task = Tokio::spawn_result(cx, async move {
            engine::set_admin(&member, &target_pop_public_key, grant).await
        });
        cx.spawn(async move |this, cx| {
            let outcome = task.await;
            let _ = this.update(cx, |model, cx| {
                model.on_room_admin_mutation_finished(kind, outcome, cx);
                cx.notify();
            });
        })
        .detach();
    }

    pub(super) fn start_room_admin_mutation_from_input(
        &mut self,
        kind: RoomAdminMutationKind,
        cx: &mut ViewContext<Self>,
    ) {
        let Some(session) = &self.session else {
            return;
        };
        if self.room_admin_controls_locked(session) {
            let message = "This device does not currently hold room-admin authority for this room."
                .to_string();
            self.clear_room_admin_revoke_confirmation();
            self.room_admin_status = RoomAdminStatus::Error(message.clone());
            self.show_error_toast(message, cx);
            cx.notify();
            return;
        }
        let target = match decode_room_admin_target_hex(self.room_admin_target.value()) {
            Ok(target) => target,
            Err(err) => {
                self.clear_room_admin_revoke_confirmation();
                self.room_admin_status =
                    RoomAdminStatus::Error(categorize_error(&err, "room admin").user_message);
                self.show_error_toast(err.to_string(), cx);
                cx.notify();
                return;
            }
        };
        if matches!(kind, RoomAdminMutationKind::Revoke)
            && self.room_admin_revoke_confirmation.as_ref() != Some(&target)
        {
            self.room_admin_revoke_confirmation = Some(target.clone());
            self.room_admin_status = RoomAdminStatus::Idle;
            self.info_message = Some(format!(
                "Revoke staged for {}. Click Revoke again to confirm.",
                room_admin_identity_preview(&target)
            ));
            self.show_info("Revoke staged; click Revoke again to confirm", cx);
            cx.notify();
            return;
        }
        self.start_room_admin_mutation(kind, target, cx);
    }

    pub(super) fn on_room_admin_mutation_finished(
        &mut self,
        kind: RoomAdminMutationKind,
        result: anyhow::Result<engine::RosterOutcome>,
        cx: &mut ViewContext<Self>,
    ) {
        match result {
            Ok(outcome) => {
                self.clear_room_admin_revoke_confirmation();
                self.room_admin_status = RoomAdminStatus::Idle;
                self.apply_session_view(outcome.view);
                let success_message = kind.success_message();
                self.info_message = Some(format!(
                    "{} ({} admins).",
                    success_message,
                    self.room_admins.len()
                ));
                self.show_success(success_message, cx);
                self.record_activity(ActivityKind::Roster, success_message);
            }
            Err(err) => {
                self.clear_room_admin_revoke_confirmation();
                let user_message = categorize_error(&err, "room admin").user_message;
                self.room_admin_status = RoomAdminStatus::Error(user_message.clone());
                self.show_error_toast(user_message, cx);
                warn!("room admin mutation failed: {err:?}");
                cx.notify();
            }
        }
    }
}

/// Admin-set change requested from the room-admin panel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RoomAdminMutationKind {
    Grant,
    Revoke,
}

impl RoomAdminMutationKind {
    pub(super) fn present_progressive(self) -> &'static str {
        match self {
            Self::Grant => "Granting room-admin rights (signed commit)…",
            Self::Revoke => "Revoking room-admin rights (signed commit)…",
        }
    }

    pub(super) fn success_message(self) -> &'static str {
        match self {
            Self::Grant => "Room admin granted",
            Self::Revoke => "Room admin revoked",
        }
    }
}
