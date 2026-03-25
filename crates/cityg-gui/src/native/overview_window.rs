use super::app_actions::{ShowSessionOverviewAction, ToggleSidebarAction};
use super::*;
use gpui::StatefulInteractiveElement;

const SESSION_HORIZONTAL_PADDING: f32 = 24.0;
pub(super) const SESSION_SPLIT_GAP: f32 = 10.0;
const SESSION_SIDEBAR_DIVIDER_WIDTH: f32 = 8.0;
const SESSION_INSPECTOR_DIVIDER_WIDTH: f32 = 8.0;
pub(super) const SESSION_CENTER_MIN_WIDTH: f32 = 320.0;
pub(super) const SESSION_CENTER_MIN_WIDTH_WITH_INSPECTOR: f32 = 360.0;
const SESSION_SIDEBAR_MIN_WIDTH: f32 = 188.0;
const SESSION_SIDEBAR_MAX_WIDTH: f32 = 300.0;
const SESSION_INSPECTOR_MIN_WIDTH: f32 = 312.0;
const SESSION_INSPECTOR_MAX_WIDTH: f32 = 460.0;

impl AppModel {
    fn schedule_session_sidebar_toggle(&mut self, window: &mut Window, cx: &mut ViewContext<Self>) {
        cx.defer_in(window, |model, window, cx| {
            model.toggle_session_sidebar(window, cx);
        });
    }

    fn schedule_session_inspector_toggle(
        &mut self,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        cx.defer_in(window, |model, window, cx| {
            model.toggle_session_inspector(window, cx);
        });
    }

    pub(super) fn available_sidebar_width_for_window(window_width: f32) -> Option<f32> {
        let chrome =
            SESSION_HORIZONTAL_PADDING + (SESSION_SPLIT_GAP * 2.0) + SESSION_SIDEBAR_DIVIDER_WIDTH;
        let max_width =
            (window_width - SESSION_CENTER_MIN_WIDTH - chrome).min(SESSION_SIDEBAR_MAX_WIDTH);
        (max_width >= SESSION_SIDEBAR_MIN_WIDTH).then_some(max_width)
    }

    pub(super) fn resolved_sidebar_width(&self, window_width: f32) -> Option<f32> {
        if !self.sidebar_visible {
            return None;
        }

        Self::available_sidebar_width_for_window(window_width).map(|max_width| {
            self.sidebar_width
                .clamp(SESSION_SIDEBAR_MIN_WIDTH, max_width)
        })
    }

    pub(super) fn available_inspector_width_for_window(
        window_width: f32,
        sidebar_width: Option<f32>,
    ) -> Option<f32> {
        let sidebar_chrome = sidebar_width.map_or(0.0, |width| {
            width + (SESSION_SPLIT_GAP * 2.0) + SESSION_SIDEBAR_DIVIDER_WIDTH
        });
        let chrome = SESSION_HORIZONTAL_PADDING
            + sidebar_chrome
            + (SESSION_SPLIT_GAP * 2.0)
            + SESSION_INSPECTOR_DIVIDER_WIDTH;
        let max_width = (window_width - SESSION_CENTER_MIN_WIDTH_WITH_INSPECTOR - chrome)
            .min(SESSION_INSPECTOR_MAX_WIDTH);
        (max_width >= SESSION_INSPECTOR_MIN_WIDTH).then_some(max_width)
    }

    pub(super) fn resolved_inspector_width(&self, window_width: f32) -> Option<f32> {
        if !self.inspector_visible {
            return None;
        }

        let sidebar_width = self.resolved_sidebar_width(window_width);
        Self::available_inspector_width_for_window(window_width, sidebar_width).map(|max_width| {
            self.inspector_width
                .clamp(SESSION_INSPECTOR_MIN_WIDTH, max_width)
        })
    }

    fn update_sidebar_resize(
        &mut self,
        resize: SidebarResizeState,
        mouse_x: f32,
        window_width: f32,
    ) -> bool {
        let Some(max_width) = Self::available_sidebar_width_for_window(window_width) else {
            return false;
        };

        let updated_width = (resize.start_width + (mouse_x - resize.start_mouse_x))
            .clamp(SESSION_SIDEBAR_MIN_WIDTH, max_width);
        if (self.sidebar_width - updated_width).abs() < 0.5 {
            return false;
        }

        self.sidebar_width = updated_width;
        true
    }

    fn update_inspector_resize(
        &mut self,
        resize: InspectorResizeState,
        mouse_x: f32,
        window_width: f32,
    ) -> bool {
        let sidebar_width = self.resolved_sidebar_width(window_width);
        let Some(max_width) =
            Self::available_inspector_width_for_window(window_width, sidebar_width)
        else {
            return false;
        };

        let updated_width = (resize.start_width + (resize.start_mouse_x - mouse_x))
            .clamp(SESSION_INSPECTOR_MIN_WIDTH, max_width);
        if (self.inspector_width - updated_width).abs() < 0.5 {
            return false;
        }

        self.inspector_width = updated_width;
        true
    }

    pub(super) fn toggle_session_sidebar(
        &mut self,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if self.session.is_none() {
            self.show_info("Join a room to reveal the sidebar.", cx);
            return;
        }

        let window_width = f32::from(window.bounds().size.width);
        if self.resolved_sidebar_width(window_width).is_some() {
            self.sidebar_visible = false;
            self.sidebar_resize = None;
            cx.notify();
            return;
        }

        if Self::available_sidebar_width_for_window(window_width).is_none() {
            self.show_info("Widen the window to reveal the sidebar.", cx);
            return;
        }

        self.sidebar_visible = true;
        self.sidebar_resize = None;
        cx.notify();
    }

    fn toggle_session_inspector(&mut self, window: &mut Window, cx: &mut ViewContext<Self>) {
        if self.session.is_none() {
            self.show_info("Join a room to view the session overview.", cx);
            return;
        }

        let window_width = f32::from(window.bounds().size.width);
        if self.resolved_inspector_width(window_width).is_some() {
            self.inspector_visible = false;
            self.inspector_resize = None;
            cx.notify();
            return;
        }

        let sidebar_width = self.resolved_sidebar_width(window_width);
        if Self::available_inspector_width_for_window(window_width, sidebar_width).is_none() {
            self.show_info("Widen the window to reveal the inspector.", cx);
            return;
        }

        self.inspector_visible = true;
        self.inspector_resize = None;
        cx.notify();
    }

    pub(super) fn render_session_inspector(
        &self,
        session: &AppSession,
        inspector_width: f32,
        cx: &mut ViewContext<Self>,
    ) -> Div {
        let members_total = self.members_total.max(self.members.len() as u64);
        let hide_hover_fill = ui_hover_fill(self.window_active);
        let hide_button = div()
            .px(px(10.0))
            .py(px(6.0))
            .rounded(px(10.0))
            .border(px(1.0))
            .border_color(rgb(UI_PANEL_BORDER))
            .bg(ui_button_fill(self.window_active))
            .text_size(px(12.0))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(UI_PANEL_TEXT))
            .cursor(CursorStyle::PointingHand)
            .hover(move |style| style.bg(hide_hover_fill))
            .child("Hide")
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(Self::on_show_session_overview_clicked),
            );

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

        div()
            .flex()
            .flex_col()
            .min_w(px(inspector_width))
            .max_w(px(inspector_width))
            .min_h(px(0.0))
            .h_full()
            .gap(px(10.0))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .px(px(14.0))
                    .py(px(12.0))
                    .rounded(px(16.0))
                    .border(px(1.0))
                    .border_color(rgb(UI_PANEL_BORDER))
                    .bg(ui_toolbar_fill(self.window_active))
                    .shadow_sm()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap(px(4.0))
                            .child(
                                div()
                                    .text_size(px(14.0))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(rgb(UI_PANEL_TEXT))
                                    .child("Inspector"),
                            )
                            .child(
                                div()
                                    .text_size(px(11.0))
                                    .text_color(rgb(UI_SUBTLE_TEXT))
                                    .child(format!(
                                        "{} · {} members",
                                        session.alias, members_total
                                    )),
                            ),
                    )
                    .child(hide_button),
            )
            .child(details_scroll)
    }

    pub(super) fn render_sidebar_divider(
        &self,
        sidebar_width: f32,
        cx: &mut ViewContext<Self>,
    ) -> impl IntoElement {
        let divider_fill = if self.sidebar_resize.is_some() {
            rgb(UI_ACCENT_TEXT)
        } else {
            rgb(UI_PANEL_BORDER)
        };
        let hover_fill = rgb(UI_ACCENT_SOFT_FILL);
        let entity = cx.entity();

        div()
            .id("session-sidebar-divider")
            .w(px(SESSION_SIDEBAR_DIVIDER_WIDTH))
            .h_full()
            .flex()
            .items_center()
            .justify_center()
            .cursor(CursorStyle::ResizeColumn)
            .hover(move |style| style.bg(hover_fill))
            .on_drag(
                SidebarResizeState {
                    start_mouse_x: 0.0,
                    start_width: sidebar_width,
                },
                move |state: &SidebarResizeState, position, _, cx: &mut App| {
                    let _ = entity.update(cx, |model, cx| {
                        model.sidebar_resize = Some(SidebarResizeState {
                            start_mouse_x: f32::from(position.x),
                            start_width: state.start_width,
                        });
                        cx.notify();
                    });
                    cx.new(|_| EmptyView)
                },
            )
            .on_drag_move(cx.listener(Self::on_sidebar_divider_drag_move))
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(Self::on_sidebar_divider_mouse_up),
            )
            .on_mouse_up_out(
                MouseButton::Left,
                cx.listener(Self::on_sidebar_divider_mouse_up),
            )
            .child(
                div()
                    .w(px(2.0))
                    .h(px(72.0))
                    .rounded(px(999.0))
                    .bg(divider_fill),
            )
    }

    pub(super) fn render_inspector_divider(
        &self,
        inspector_width: f32,
        cx: &mut ViewContext<Self>,
    ) -> impl IntoElement {
        let divider_fill = if self.inspector_resize.is_some() {
            rgb(UI_ACCENT_TEXT)
        } else {
            rgb(UI_PANEL_BORDER)
        };
        let hover_fill = rgb(UI_ACCENT_SOFT_FILL);
        let entity = cx.entity();

        div()
            .id("session-inspector-divider")
            .w(px(SESSION_INSPECTOR_DIVIDER_WIDTH))
            .h_full()
            .flex()
            .items_center()
            .justify_center()
            .cursor(CursorStyle::ResizeColumn)
            .hover(move |style| style.bg(hover_fill))
            .on_drag(
                InspectorResizeState {
                    start_mouse_x: 0.0,
                    start_width: inspector_width,
                },
                move |state: &InspectorResizeState, position, _, cx: &mut App| {
                    let _ = entity.update(cx, |model, cx| {
                        model.inspector_resize = Some(InspectorResizeState {
                            start_mouse_x: f32::from(position.x),
                            start_width: state.start_width,
                        });
                        cx.notify();
                    });
                    cx.new(|_| EmptyView)
                },
            )
            .on_drag_move(cx.listener(Self::on_inspector_divider_drag_move))
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(Self::on_inspector_divider_mouse_up),
            )
            .on_mouse_up_out(
                MouseButton::Left,
                cx.listener(Self::on_inspector_divider_mouse_up),
            )
            .child(
                div()
                    .w(px(2.0))
                    .h(px(72.0))
                    .rounded(px(999.0))
                    .bg(divider_fill),
            )
    }

    pub(super) fn on_toggle_sidebar_clicked(
        &mut self,
        _: &MouseDownEvent,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.schedule_session_sidebar_toggle(window, cx);
    }

    pub(super) fn on_show_session_overview_clicked(
        &mut self,
        _: &MouseDownEvent,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.schedule_session_inspector_toggle(window, cx);
    }

    pub(super) fn on_toggle_sidebar_action(
        &mut self,
        _: &ToggleSidebarAction,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.schedule_session_sidebar_toggle(window, cx);
    }

    pub(super) fn on_show_session_overview_action(
        &mut self,
        _: &ShowSessionOverviewAction,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.schedule_session_inspector_toggle(window, cx);
    }

    pub(super) fn on_sidebar_divider_drag_move(
        &mut self,
        event: &DragMoveEvent<SidebarResizeState>,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        let resize = *event.drag(cx);
        if self.update_sidebar_resize(
            resize,
            f32::from(event.event.position.x),
            f32::from(window.bounds().size.width),
        ) {
            cx.notify();
        }
    }

    pub(super) fn on_inspector_divider_drag_move(
        &mut self,
        event: &DragMoveEvent<InspectorResizeState>,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        let resize = *event.drag(cx);
        if self.update_inspector_resize(
            resize,
            f32::from(event.event.position.x),
            f32::from(window.bounds().size.width),
        ) {
            cx.notify();
        }
    }

    pub(super) fn on_sidebar_divider_mouse_up(
        &mut self,
        _: &MouseUpEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if self.sidebar_resize.take().is_some() {
            cx.notify();
        }
    }

    pub(super) fn on_inspector_divider_mouse_up(
        &mut self,
        _: &MouseUpEvent,
        _: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if self.inspector_resize.take().is_some() {
            cx.notify();
        }
    }
}
