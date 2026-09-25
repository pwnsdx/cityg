use super::*;

impl AppModel {
    pub(super) fn focus_members_search(&mut self, window: &mut Window, cx: &mut ViewContext<Self>) {
        self.focus_text_field(NativeTextFieldKind::MembersSearch, window, cx);
    }

    /// Filter the members panel by alias or leaf prefix. The roster is the
    /// signed roster of the current epoch, so the search is local.
    pub(super) fn submit_members_search(&mut self, cx: &mut ViewContext<Self>) {
        let query = self.members_search.query.trim().to_string();
        self.members_mode = if query.is_empty() {
            MembersMode::Full
        } else {
            MembersMode::Search { query }
        };
        self.rebuild_members();
        cx.notify();
    }

    pub(super) fn clear_members_search(&mut self, cx: &mut ViewContext<Self>) {
        self.members_search.clear();
        self.members_search.blur();
        self.members_mode = MembersMode::Full;
        self.rebuild_members();
        cx.notify();
    }

    /// Refresh the roster from the delivery service (a room sync).
    pub(super) fn refresh_members(&mut self, cx: &mut ViewContext<Self>) {
        if self.session.is_none() {
            return;
        }
        self.members_status = MembersStatus::Loading("Syncing the roster…".to_string());
        self.schedule_fetch(cx, Duration::from_millis(0));
        cx.notify();
    }

    pub(super) fn on_members_refresh_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.refresh_members(cx);
    }

    pub(super) fn on_members_load_more_clicked(
        &mut self,
        _: &MouseDownEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        // The whole roster is local; there is nothing more to load.
        self.rebuild_members();
        cx.notify();
    }

    #[cfg(test)]
    pub(super) fn on_members_search_field_clicked(
        &mut self,
        _: &MouseDownEvent,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.focus_members_search(window, cx);
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
