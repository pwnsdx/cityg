use super::*;

impl AppModel {
    pub(super) fn focus_members_search(&mut self, cx: &mut ViewContext<Self>) {
        self.members_search.focus();
        self.room_admin_target.blur();
        self.composer.blur();
        cx.notify();
    }

    pub(super) fn submit_members_search(&mut self, cx: &mut ViewContext<Self>) {
        let query = self.members_search.query.trim().to_string();
        if query.is_empty() {
            if matches!(self.members_mode, MembersMode::Search { .. }) {
                self.refresh_members(cx);
            } else {
                cx.notify();
            }
            return;
        }

        self.refresh_members_for_mode(
            cx,
            MembersMode::Search {
                query: query.clone(),
            },
            true,
            true,
            format!("Searching for \"{}\"…", query),
        );
    }

    pub(super) fn clear_members_search(&mut self, cx: &mut ViewContext<Self>) {
        self.members_search.clear();
        self.members_search.blur();
        if matches!(self.members_mode, MembersMode::Search { .. }) {
            self.refresh_members(cx);
        } else {
            cx.notify();
        }
    }

    pub(super) fn handle_membership_signal(
        &mut self,
        signal: &MembershipSignal,
        cx: &mut ViewContext<Self>,
    ) {
        let Some(session) = &self.session else {
            return;
        };
        if session.gid != signal.gid {
            return;
        }
        if matches!(self.members_status, MembersStatus::Loading(_)) {
            self.schedule_epoch_sync(cx, "Syncing latest epoch after membership change…");
            return;
        }
        let mode = self.members_mode.clone();
        let message = match &mode {
            MembersMode::Full => "Syncing roster after membership change…".to_string(),
            MembersMode::Search { query } => format!("Updating search for \"{}\"…", query),
        };
        self.refresh_members_for_mode(cx, mode, true, true, message);
        self.schedule_epoch_sync(cx, "Syncing latest epoch after membership change…");
    }

    pub(super) fn refresh_members(&mut self, cx: &mut ViewContext<Self>) {
        self.refresh_members_for_mode(
            cx,
            MembersMode::Full,
            true,
            true,
            "Loading member roster…".to_string(),
        );
    }

    pub(super) fn refresh_members_soft(&mut self, cx: &mut ViewContext<Self>) {
        if matches!(self.members_status, MembersStatus::Loading(_)) {
            return;
        }
        let mode = self.members_mode.clone();
        let message = match &mode {
            MembersMode::Full => "Refreshing member roster…".to_string(),
            MembersMode::Search { query } => format!("Refreshing search for \"{}\"…", query),
        };
        self.refresh_members_for_mode(cx, mode, false, true, message);
    }

    pub(super) fn refresh_members_for_mode(
        &mut self,
        cx: &mut ViewContext<Self>,
        mode: MembersMode,
        reset_state: bool,
        auto_page: bool,
        message: String,
    ) {
        let session = match &self.session {
            Some(session) => session,
            None => return,
        };
        if reset_state {
            self.members.clear();
            self.members_total = 0;
            self.members_next_offset = None;
            self.members_alias_dirty = false;
        }
        if !matches!(mode, MembersMode::Full) {
            self.members_alias_dirty = false;
        }
        self.members_mode = mode.clone();
        self.members_auto_page = auto_page;
        let params =
            MembersParams::from_session(session, 0, self.config.gui.members_page_limit, mode);
        self.start_members_fetch(params, false, message, cx);
    }

    pub(super) fn load_more_members(&mut self, cx: &mut ViewContext<Self>) {
        self.load_more_members_with_mode(cx, false);
    }

    pub(super) fn load_more_members_with_mode(
        &mut self,
        cx: &mut ViewContext<Self>,
        auto_triggered: bool,
    ) {
        if matches!(self.members_status, MembersStatus::Loading(_)) {
            return;
        }
        if !auto_triggered {
            self.members_auto_page = false;
        }
        let session = match &self.session {
            Some(session) => session,
            None => return,
        };
        let next = match self.members_next_offset {
            Some(offset) if offset < self.members_total => offset,
            _ => return,
        };
        let params = MembersParams::from_session(
            session,
            next,
            self.config.gui.members_page_limit,
            self.members_mode.clone(),
        );
        self.start_members_fetch(params, true, "Loading more members…".to_string(), cx);
    }

    pub(super) fn start_members_fetch(
        &mut self,
        params: MembersParams,
        append: bool,
        message: String,
        cx: &mut ViewContext<Self>,
    ) {
        self.members_status = MembersStatus::Loading(message);
        self.members_loading_append = append;
        cx.notify();
        let task = Tokio::spawn_result(cx, async move { perform_fetch_members(params).await });
        cx.spawn(async move |this, cx| {
            let outcome = task.await;
            let _ = this.update(cx, |model, cx| {
                model.on_members_refreshed(outcome, cx);
                cx.notify();
            });
        })
        .detach();
    }

    pub(super) fn on_members_refreshed(
        &mut self,
        result: anyhow::Result<MembersPage>,
        cx: &mut ViewContext<Self>,
    ) {
        match result {
            Ok(mut page) => {
                let mut parent_root_changed = false;
                if let Some(session) = self.session.as_mut()
                    && session.parent_root != page.root
                {
                    session.parent_root = page.root;
                    parent_root_changed = true;
                    if let Err(err) = persist_session(session) {
                        warn!("failed to persist session after members root update: {err:?}");
                    }
                }
                page.members.sort_by(|a, b| {
                    let alias_cmp = a.alias.as_ref().cmp(&b.alias.as_ref());
                    if alias_cmp.is_eq() {
                        a.leaf_id.cmp(&b.leaf_id)
                    } else {
                        alias_cmp
                    }
                });
                if self.members_loading_append {
                    self.members.extend(page.members);
                } else {
                    self.members = page.members;
                    self.members_alias_dirty = matches!(self.members_mode, MembersMode::Full);
                }
                self.members_total = page.total_count;
                self.members_next_offset = if page.next_offset < page.total_count {
                    Some(page.next_offset)
                } else {
                    None
                };
                self.members_status = MembersStatus::Idle;
                self.record_activity(
                    ActivityKind::Roster,
                    format!(
                        "Roster refreshed: {} shown / {} total",
                        self.members.len(),
                        self.members_total
                    ),
                );
                if parent_root_changed {
                    self.schedule_epoch_sync(cx, "Syncing latest epoch after roster root update…");
                }
                if self.members_auto_page {
                    if self.members_next_offset.is_some() {
                        self.load_more_members_with_mode(cx, true);
                        return;
                    } else {
                        self.members_auto_page = false;
                    }
                }
                if self.members_alias_dirty && self.members_next_offset.is_none() {
                    self.members_alias_dirty = false;
                    if matches!(self.members_mode, MembersMode::Full) {
                        self.reconcile_alias_bindings(cx);
                    }
                }
            }
            Err(err) => {
                if is_stale_server_session_error(&err) {
                    self.handle_stale_server_session(
                        "Saved session is no longer recognized by the server. Please join again.",
                        cx,
                    );
                    return;
                }
                let detail = http_error_detail_from_anyhow(&err).unwrap_or_else(|| err.to_string());
                warn!("failed to refresh members: {detail}");
                self.record_activity_with_detail(
                    ActivityKind::Roster,
                    "Roster refresh failed",
                    Some(detail.clone()),
                );
                self.members_status = MembersStatus::Error(detail);
                self.members_auto_page = false;
                self.members_alias_dirty = false;
            }
        }
        self.members_loading_append = false;
    }

    pub(super) fn on_members_refresh_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        let mode = self.members_mode.clone();
        let message = match &mode {
            MembersMode::Full => "Loading member roster…".to_string(),
            MembersMode::Search { query } => format!("Refreshing search for \"{}\"…", query),
        };
        self.refresh_members_for_mode(cx, mode, true, true, message);
    }

    pub(super) fn on_members_load_more_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.load_more_members(cx);
    }

    pub(super) fn on_members_search_field_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.focus_members_search(cx);
    }

    pub(super) fn on_members_search_button_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.submit_members_search(cx);
    }

    pub(super) fn on_members_search_clear_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.clear_members_search(cx);
    }
}
