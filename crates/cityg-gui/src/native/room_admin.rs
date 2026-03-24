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

    pub(super) fn focus_room_admin_target(&mut self, cx: &mut ViewContext<Self>) {
        self.room_admin_target.focus();
        self.members_search.blur();
        self.composer.blur();
        cx.notify();
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
        self.focus_room_admin_target(cx);
        self.show_info("Loaded member identity into room-admin target", cx);
    }

    pub(super) fn refresh_room_admins(&mut self, cx: &mut ViewContext<Self>) {
        let Some(params) = self
            .session
            .as_ref()
            .map(RoomAdminQueryParams::from_session)
        else {
            return;
        };
        if matches!(self.room_admin_status, RoomAdminStatus::Loading(_)) {
            return;
        }
        self.clear_room_admin_revoke_confirmation();
        self.room_admin_status =
            RoomAdminStatus::Loading("Loading room-admin identities…".to_string());
        cx.notify();

        let task = Tokio::spawn_result(cx, async move { perform_fetch_room_admins(params).await });
        cx.spawn(async move |this, cx| {
            let outcome = task.await;
            let _ = this.update(cx, |model, cx| {
                model.on_room_admins_refreshed(outcome, cx);
                cx.notify();
            });
        })
        .detach();
    }

    pub(super) fn on_room_admins_refreshed(
        &mut self,
        result: anyhow::Result<Vec<Vec<u8>>>,
        cx: &mut ViewContext<Self>,
    ) {
        match result {
            Ok(admins) => {
                self.room_admins = admins;
                self.room_admins_loaded = true;
                self.room_admin_status = RoomAdminStatus::Idle;
                self.clear_room_admin_revoke_confirmation();
                cx.notify();
            }
            Err(err) => {
                self.room_admins.clear();
                self.room_admins_loaded = false;
                self.room_admin_status =
                    RoomAdminStatus::Error(categorize_error(&err, "room admin").user_message);
                self.clear_room_admin_revoke_confirmation();
                warn!("failed to refresh room admins: {err:?}");
                cx.notify();
            }
        }
    }

    pub(super) fn start_room_admin_mutation(
        &mut self,
        kind: RoomAdminMutationKind,
        target_pop_public_key: Vec<u8>,
        cx: &mut ViewContext<Self>,
    ) {
        let Some(query) = self
            .session
            .as_ref()
            .map(RoomAdminQueryParams::from_session)
        else {
            return;
        };
        if matches!(self.room_admin_status, RoomAdminStatus::Loading(_)) {
            return;
        }
        self.clear_room_admin_revoke_confirmation();
        self.room_admin_status = RoomAdminStatus::Loading(kind.present_progressive().to_string());
        cx.notify();

        let params = RoomAdminMutationParams {
            query,
            target_pop_public_key,
            kind,
        };
        let task =
            Tokio::spawn_result(cx, async move { perform_room_admin_mutation(params).await });
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
        result: anyhow::Result<RoomAdminMutationOutcome>,
        cx: &mut ViewContext<Self>,
    ) {
        match result {
            Ok(outcome) => {
                self.clear_room_admin_revoke_confirmation();
                self.room_admin_status = RoomAdminStatus::Idle;
                let success_message = match outcome.status.as_str() {
                    "already_granted" => "Room admin was already granted",
                    "already_revoked" => "Room admin was already revoked",
                    _ => kind.success_message(),
                };
                if let Ok(target) = decode_room_admin_target_hex(self.room_admin_target.value()) {
                    self.apply_room_admin_mutation_locally(kind, outcome.status.as_str(), target);
                } else {
                    self.room_admins_loaded = false;
                }
                self.info_message = Some(format!(
                    "{} ({} admins).",
                    success_message, outcome.admin_count
                ));
                self.show_success(success_message, cx);
                self.refresh_room_admins(cx);
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

    pub(super) fn apply_room_admin_mutation_locally(
        &mut self,
        kind: RoomAdminMutationKind,
        status: &str,
        target_pop_public_key: Vec<u8>,
    ) {
        if !self.room_admins_loaded {
            return;
        }
        let mut admins: BTreeSet<Vec<u8>> = self.room_admins.iter().cloned().collect();
        match (kind, status) {
            (RoomAdminMutationKind::Grant, "granted" | "already_granted") => {
                admins.insert(target_pop_public_key);
            }
            (RoomAdminMutationKind::Revoke, "revoked" | "already_revoked") => {
                admins.remove(&target_pop_public_key);
            }
            _ => {}
        }
        self.room_admins = admins.into_iter().collect();
    }
}
