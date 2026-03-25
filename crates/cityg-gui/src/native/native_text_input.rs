#[cfg(all(target_os = "macos", not(test)))]
use std::ffi::c_void;
use std::ops::Range;

use super::*;
use gpui::Point;

use crate::native::app_actions::{
    TextBackspaceAction, TextDeleteAction, TextEndAction, TextHomeAction, TextMoveLeftAction,
    TextMoveRightAction, TextSelectAllAction, TextSelectLeftAction, TextSelectRightAction,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NativeTextFieldKind {
    JoinServer,
    JoinRoom,
    JoinAlias,
    Composer,
    MembersSearch,
    RoomAdminTarget,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeTextContextMenuAction {
    Cut,
    Copy,
    Paste,
    SelectAll,
}

#[derive(Clone, Copy, Debug, Default)]
struct NativeTextContextMenuAvailability {
    cut: bool,
    copy: bool,
    paste: bool,
    select_all: bool,
}

#[cfg(all(target_os = "macos", not(test)))]
type NativeTextContextMenuHost = *mut c_void;

#[cfg(any(test, not(target_os = "macos")))]
type NativeTextContextMenuHost = ();

#[cfg(all(target_os = "macos", not(test)))]
#[allow(unexpected_cfgs)]
mod mac_text_context_menu {
    use super::{NativeTextContextMenuAction, NativeTextContextMenuAvailability};
    use cocoa::{
        appkit::{NSMenu, NSMenuItem},
        base::{NO, YES, id, nil},
        foundation::{NSAutoreleasePool, NSPoint, NSRect, NSString},
    };
    use objc::{
        class,
        declare::ClassDecl,
        msg_send,
        runtime::{Class, Object, Sel},
        sel, sel_impl,
    };
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use std::{cell::Cell, ffi::c_void, sync::Once};

    use super::*;

    const TEXT_CONTEXT_MENU_TARGET_IVAR: &str = "textContextMenuTarget";

    struct TextContextMenuSelection {
        selected_action: Cell<Option<NativeTextContextMenuAction>>,
    }

    pub(super) fn show(
        native_view: NativeTextContextMenuHost,
        position: Point<Pixels>,
        availability: NativeTextContextMenuAvailability,
    ) -> Option<NativeTextContextMenuAction> {
        unsafe {
            let native_view: id = native_view.cast();
            let selection = Box::into_raw(Box::new(TextContextMenuSelection {
                selected_action: Cell::new(None),
            }));
            let target: id = msg_send![context_menu_target_class(), new];
            (*target).set_ivar(TEXT_CONTEXT_MENU_TARGET_IVAR, selection.cast::<c_void>());

            let menu = NSMenu::new(nil).autorelease();
            let _: () = msg_send![menu, setAutoenablesItems: NO];

            add_menu_item(menu, "Cut", sel!(performCut:), availability.cut, target);
            add_menu_item(menu, "Copy", sel!(performCopy:), availability.copy, target);
            add_menu_item(
                menu,
                "Paste",
                sel!(performPaste:),
                availability.paste,
                target,
            );

            let separator = NSMenuItem::separatorItem(nil);
            let _: () = msg_send![menu, addItem: separator];

            add_menu_item(
                menu,
                "Select All",
                sel!(performSelectAll:),
                availability.select_all,
                target,
            );

            let location = ns_view_point(native_view, position);
            let _: bool = msg_send![menu, popUpMenuPositioningItem: nil atLocation: location inView: native_view];

            let selected = (*selection).selected_action.get();
            drop(Box::from_raw(selection));
            let _: () = msg_send![target, release];
            selected
        }
    }

    pub(super) fn host_for_window(window: &Window) -> Option<NativeTextContextMenuHost> {
        unsafe { native_view_for_window(window).map(|native_view| native_view.cast()) }
    }

    unsafe fn native_view_for_window(window: &Window) -> Option<id> {
        let handle = HasWindowHandle::window_handle(window).ok()?;
        match handle.as_raw() {
            RawWindowHandle::AppKit(handle) => Some(handle.ns_view.as_ptr().cast()),
            _ => None,
        }
    }

    unsafe fn ns_view_point(native_view: id, position: Point<Pixels>) -> NSPoint {
        let bounds: NSRect = msg_send![native_view, bounds];
        NSPoint::new(
            f64::from(position.x),
            bounds.size.height - f64::from(position.y),
        )
    }

    unsafe fn add_menu_item(menu: id, title: &str, action: Sel, enabled: bool, target: id) {
        let item = unsafe {
            NSMenuItem::alloc(nil)
                .initWithTitle_action_keyEquivalent_(ns_string(title), action, ns_string(""))
                .autorelease()
        };
        let _: () = msg_send![item, setTarget: target];
        let _: () = msg_send![item, setEnabled: if enabled { YES } else { NO }];
        let _: () = msg_send![menu, addItem: item];
    }

    unsafe fn ns_string(text: &str) -> id {
        unsafe { NSString::alloc(nil).init_str(text).autorelease() }
    }

    fn context_menu_target_class() -> &'static Class {
        const CLASS_NAME: &str = "CityGTextContextMenuTarget";
        static REGISTER: Once = Once::new();

        if let Some(class) = Class::get(CLASS_NAME) {
            return class;
        }

        REGISTER.call_once(|| unsafe {
            let mut decl = ClassDecl::new(CLASS_NAME, class!(NSObject)).unwrap();
            decl.add_ivar::<*mut c_void>(TEXT_CONTEXT_MENU_TARGET_IVAR);
            decl.add_method(
                sel!(performCut:),
                perform_cut as extern "C" fn(&mut Object, Sel, id),
            );
            decl.add_method(
                sel!(performCopy:),
                perform_copy as extern "C" fn(&mut Object, Sel, id),
            );
            decl.add_method(
                sel!(performPaste:),
                perform_paste as extern "C" fn(&mut Object, Sel, id),
            );
            decl.add_method(
                sel!(performSelectAll:),
                perform_select_all as extern "C" fn(&mut Object, Sel, id),
            );
            decl.register();
        });

        Class::get(CLASS_NAME).expect("CityGTextContextMenuTarget should be registered")
    }

    unsafe fn selection(this: &Object) -> &TextContextMenuSelection {
        let raw: *mut c_void = unsafe { *this.get_ivar(TEXT_CONTEXT_MENU_TARGET_IVAR) };
        unsafe { &*(raw.cast::<TextContextMenuSelection>()) }
    }

    extern "C" fn perform_cut(this: &mut Object, _: Sel, _: id) {
        unsafe {
            selection(this)
                .selected_action
                .set(Some(NativeTextContextMenuAction::Cut));
        }
    }

    extern "C" fn perform_copy(this: &mut Object, _: Sel, _: id) {
        unsafe {
            selection(this)
                .selected_action
                .set(Some(NativeTextContextMenuAction::Copy));
        }
    }

    extern "C" fn perform_paste(this: &mut Object, _: Sel, _: id) {
        unsafe {
            selection(this)
                .selected_action
                .set(Some(NativeTextContextMenuAction::Paste));
        }
    }

    extern "C" fn perform_select_all(this: &mut Object, _: Sel, _: id) {
        unsafe {
            selection(this)
                .selected_action
                .set(Some(NativeTextContextMenuAction::SelectAll));
        }
    }
}

#[cfg(all(target_os = "macos", not(test)))]
fn show_native_text_context_menu(
    host: NativeTextContextMenuHost,
    position: Point<Pixels>,
    availability: NativeTextContextMenuAvailability,
) -> Option<NativeTextContextMenuAction> {
    mac_text_context_menu::show(host, position, availability)
}

#[cfg(any(test, not(target_os = "macos")))]
fn show_native_text_context_menu(
    _host: NativeTextContextMenuHost,
    _position: Point<Pixels>,
    _availability: NativeTextContextMenuAvailability,
) -> Option<NativeTextContextMenuAction> {
    None
}

#[cfg(all(target_os = "macos", not(test)))]
fn native_text_context_menu_host(window: &Window) -> Option<NativeTextContextMenuHost> {
    mac_text_context_menu::host_for_window(window)
}

#[cfg(any(test, not(target_os = "macos")))]
fn native_text_context_menu_host(_window: &Window) -> Option<NativeTextContextMenuHost> {
    None
}

#[derive(Clone)]
pub(super) struct TextInputEditorState {
    pub(super) focus_handle: Option<FocusHandle>,
    pub(super) selected_range: Range<usize>,
    pub(super) selection_reversed: bool,
    pub(super) marked_range: Option<Range<usize>>,
    pub(super) last_layout: Option<ShapedLine>,
    pub(super) last_bounds: Option<Bounds<Pixels>>,
    pub(super) is_selecting: bool,
}

impl Default for TextInputEditorState {
    fn default() -> Self {
        Self {
            focus_handle: None,
            selected_range: 0..0,
            selection_reversed: false,
            marked_range: None,
            last_layout: None,
            last_bounds: None,
            is_selecting: false,
        }
    }
}

impl TextInputEditorState {
    pub(super) fn has_native_input(&self) -> bool {
        self.focus_handle.is_some()
    }

    pub(super) fn reset(&mut self) {
        self.selected_range = 0..0;
        self.selection_reversed = false;
        self.marked_range = None;
        self.last_layout = None;
        self.last_bounds = None;
        self.is_selecting = false;
    }

    pub(super) fn reset_for_text(&mut self, text: &str) {
        let end = text.len();
        self.selected_range = end..end;
        self.selection_reversed = false;
        self.marked_range = None;
        self.last_layout = None;
        self.last_bounds = None;
        self.is_selecting = false;
    }

    fn clamp_boundary(text: &str, mut offset: usize) -> usize {
        if offset >= text.len() {
            return text.len();
        }

        while offset > 0 && !text.is_char_boundary(offset) {
            offset -= 1;
        }
        offset
    }

    fn clamp_range(text: &str, range: &Range<usize>) -> Range<usize> {
        let start = Self::clamp_boundary(text, range.start);
        let end = Self::clamp_boundary(text, range.end.max(start));
        start..end
    }

    pub(super) fn clamp_to_text(&mut self, text: &str) {
        self.selected_range = Self::clamp_range(text, &self.selected_range);
        self.marked_range = self
            .marked_range
            .as_ref()
            .map(|range| Self::clamp_range(text, range));
    }

    fn previous_boundary(text: &str, offset: usize) -> usize {
        let offset = Self::clamp_boundary(text, offset);
        if offset == 0 {
            return 0;
        }

        text[..offset]
            .char_indices()
            .last()
            .map(|(idx, _)| idx)
            .unwrap_or(0)
    }

    fn next_boundary(text: &str, offset: usize) -> usize {
        let offset = Self::clamp_boundary(text, offset);
        if offset >= text.len() {
            return text.len();
        }

        let mut chars = text[offset..].char_indices();
        let _ = chars.next();
        chars
            .next()
            .map(|(idx, _)| offset + idx)
            .unwrap_or(text.len())
    }

    fn offset_from_utf16(text: &str, offset: usize) -> usize {
        let mut utf8_offset = 0;
        let mut utf16_count = 0;

        for ch in text.chars() {
            if utf16_count >= offset {
                break;
            }
            utf16_count += ch.len_utf16();
            utf8_offset += ch.len_utf8();
        }

        utf8_offset
    }

    fn offset_to_utf16(text: &str, offset: usize) -> usize {
        let mut utf16_offset = 0;
        let mut utf8_count = 0;

        for ch in text.chars() {
            if utf8_count >= offset {
                break;
            }
            utf8_count += ch.len_utf8();
            utf16_offset += ch.len_utf16();
        }

        utf16_offset
    }

    fn range_to_utf16(text: &str, range: &Range<usize>) -> Range<usize> {
        Self::offset_to_utf16(text, range.start)..Self::offset_to_utf16(text, range.end)
    }

    fn range_from_utf16(text: &str, range_utf16: &Range<usize>) -> Range<usize> {
        Self::offset_from_utf16(text, range_utf16.start)
            ..Self::offset_from_utf16(text, range_utf16.end)
    }

    fn cursor_offset(&self) -> usize {
        if self.selection_reversed {
            self.selected_range.start
        } else {
            self.selected_range.end
        }
    }

    fn move_to(&mut self, offset: usize, text: &str) -> bool {
        let offset = Self::clamp_boundary(text, offset);
        if self.selected_range == (offset..offset) && !self.selection_reversed {
            return false;
        }
        self.selected_range = offset..offset;
        self.selection_reversed = false;
        true
    }

    fn select_to(&mut self, offset: usize, text: &str) -> bool {
        let offset = Self::clamp_boundary(text, offset);
        let before = (self.selected_range.clone(), self.selection_reversed);
        if self.selection_reversed {
            self.selected_range.start = offset;
        } else {
            self.selected_range.end = offset;
        }
        if self.selected_range.end < self.selected_range.start {
            self.selection_reversed = !self.selection_reversed;
            self.selected_range = self.selected_range.end..self.selected_range.start;
        }
        before != (self.selected_range.clone(), self.selection_reversed)
    }

    pub(super) fn select_all(&mut self, text: &str) -> bool {
        self.clamp_to_text(text);
        let before = (self.selected_range.clone(), self.selection_reversed);
        self.selected_range = 0..text.len();
        self.selection_reversed = false;
        before != (self.selected_range.clone(), self.selection_reversed)
    }

    pub(super) fn move_left(&mut self, text: &str) -> bool {
        self.clamp_to_text(text);
        if self.selected_range.is_empty() {
            self.move_to(Self::previous_boundary(text, self.cursor_offset()), text)
        } else {
            self.move_to(self.selected_range.start, text)
        }
    }

    pub(super) fn move_right(&mut self, text: &str) -> bool {
        self.clamp_to_text(text);
        if self.selected_range.is_empty() {
            self.move_to(Self::next_boundary(text, self.cursor_offset()), text)
        } else {
            self.move_to(self.selected_range.end, text)
        }
    }

    pub(super) fn select_left(&mut self, text: &str) -> bool {
        self.clamp_to_text(text);
        self.select_to(Self::previous_boundary(text, self.cursor_offset()), text)
    }

    pub(super) fn select_right(&mut self, text: &str) -> bool {
        self.clamp_to_text(text);
        self.select_to(Self::next_boundary(text, self.cursor_offset()), text)
    }

    pub(super) fn move_home(&mut self, text: &str) -> bool {
        self.move_to(0, text)
    }

    pub(super) fn move_end(&mut self, text: &str) -> bool {
        self.move_to(text.len(), text)
    }

    pub(super) fn backspace(&mut self, text: &mut String) -> bool {
        self.clamp_to_text(text);
        if self.selected_range.is_empty() {
            let next = Self::previous_boundary(text, self.cursor_offset());
            if next == self.cursor_offset() {
                return false;
            }
            self.select_to(next, text);
        }
        self.replace_text_in_range(text, None, "")
    }

    pub(super) fn delete(&mut self, text: &mut String) -> bool {
        self.clamp_to_text(text);
        if self.selected_range.is_empty() {
            let next = Self::next_boundary(text, self.cursor_offset());
            if next == self.cursor_offset() {
                return false;
            }
            self.select_to(next, text);
        }
        self.replace_text_in_range(text, None, "")
    }

    pub(super) fn selected_text(&mut self, text: &str) -> Option<String> {
        self.clamp_to_text(text);
        if self.selected_range.is_empty() {
            None
        } else {
            Some(text[self.selected_range.clone()].to_string())
        }
    }

    pub(super) fn has_selection(&mut self, text: &str) -> bool {
        self.clamp_to_text(text);
        !self.selected_range.is_empty()
    }

    pub(super) fn replace_all(&mut self, text: &mut String, new_text: &str) {
        *text = new_text.to_string();
        self.reset_for_text(text);
    }

    pub(super) fn replace_text_in_range(
        &mut self,
        text: &mut String,
        range_utf16: Option<Range<usize>>,
        new_text: &str,
    ) -> bool {
        self.clamp_to_text(text);
        let range = range_utf16
            .as_ref()
            .map(|range_utf16| Self::range_from_utf16(text, range_utf16))
            .or(self.marked_range.clone())
            .unwrap_or_else(|| self.selected_range.clone());

        if range.is_empty() && new_text.is_empty() {
            return false;
        }

        text.replace_range(range.clone(), new_text);
        let cursor = range.start + new_text.len();
        self.selected_range = cursor..cursor;
        self.selection_reversed = false;
        self.marked_range = None;
        self.last_layout = None;
        true
    }

    pub(super) fn replace_and_mark_text_in_range(
        &mut self,
        text: &mut String,
        range_utf16: Option<Range<usize>>,
        new_text: &str,
        new_selected_range_utf16: Option<Range<usize>>,
    ) {
        self.clamp_to_text(text);
        let range = range_utf16
            .as_ref()
            .map(|range_utf16| Self::range_from_utf16(text, range_utf16))
            .or(self.marked_range.clone())
            .unwrap_or_else(|| self.selected_range.clone());

        text.replace_range(range.clone(), new_text);
        if new_text.is_empty() {
            self.marked_range = None;
        } else {
            self.marked_range = Some(range.start..range.start + new_text.len());
        }
        self.selected_range = new_selected_range_utf16
            .as_ref()
            .map(|range_utf16| Self::range_from_utf16(new_text, range_utf16))
            .map(|new_range| new_range.start + range.start..new_range.end + range.start)
            .unwrap_or_else(|| range.start + new_text.len()..range.start + new_text.len());
        self.selection_reversed = false;
        self.last_layout = None;
    }

    fn index_for_mouse_position(&self, text: &str, position: Point<Pixels>) -> usize {
        if text.is_empty() {
            return 0;
        }

        let (Some(bounds), Some(line)) = (self.last_bounds.as_ref(), self.last_layout.as_ref())
        else {
            return 0;
        };

        if position.y < bounds.top() {
            return 0;
        }
        if position.y > bounds.bottom() {
            return text.len();
        }
        line.closest_index_for_x(position.x - bounds.left())
    }

    pub(super) fn on_mouse_down(&mut self, text: &str, event: &MouseDownEvent) -> bool {
        self.clamp_to_text(text);
        if event.click_count >= 2 {
            self.is_selecting = false;
            return self.select_all(text);
        }

        self.is_selecting = true;
        if event.modifiers.shift {
            self.select_to(self.index_for_mouse_position(text, event.position), text)
        } else {
            self.move_to(self.index_for_mouse_position(text, event.position), text)
        }
    }

    pub(super) fn on_secondary_mouse_down(&mut self, text: &str, event: &MouseDownEvent) -> bool {
        self.clamp_to_text(text);
        self.is_selecting = false;

        let index = self.index_for_mouse_position(text, event.position);
        if !self.selected_range.is_empty()
            && index >= self.selected_range.start
            && index <= self.selected_range.end
        {
            return false;
        }

        self.move_to(index, text)
    }

    pub(super) fn on_mouse_move(&mut self, text: &str, event: &MouseMoveEvent) -> bool {
        if !self.is_selecting {
            return false;
        }
        self.select_to(self.index_for_mouse_position(text, event.position), text)
    }

    pub(super) fn on_mouse_up(&mut self) -> bool {
        let was_selecting = self.is_selecting;
        self.is_selecting = false;
        was_selecting
    }

    pub(super) fn text_for_range(
        &mut self,
        text: &str,
        range_utf16: Range<usize>,
        actual_range: &mut Option<Range<usize>>,
    ) -> Option<String> {
        self.clamp_to_text(text);
        let range = Self::range_from_utf16(text, &range_utf16);
        actual_range.replace(Self::range_to_utf16(text, &range));
        Some(text[range].to_string())
    }

    pub(super) fn selected_text_range(&mut self, text: &str) -> Option<UTF16Selection> {
        self.clamp_to_text(text);
        Some(UTF16Selection {
            range: Self::range_to_utf16(text, &self.selected_range),
            reversed: self.selection_reversed,
        })
    }

    pub(super) fn marked_text_range(&self, text: &str) -> Option<Range<usize>> {
        self.marked_range
            .as_ref()
            .map(|range| Self::range_to_utf16(text, range))
    }

    pub(super) fn bounds_for_range(
        &mut self,
        text: &str,
        range_utf16: Range<usize>,
        bounds: Bounds<Pixels>,
    ) -> Option<Bounds<Pixels>> {
        self.clamp_to_text(text);
        let last_layout = self.last_layout.as_ref()?;
        let range = Self::range_from_utf16(text, &range_utf16);
        Some(Bounds::from_corners(
            point(
                bounds.left() + last_layout.x_for_index(range.start),
                bounds.top(),
            ),
            point(
                bounds.left() + last_layout.x_for_index(range.end),
                bounds.bottom(),
            ),
        ))
    }

    pub(super) fn character_index_for_point(
        &mut self,
        text: &str,
        point: Point<Pixels>,
    ) -> Option<usize> {
        self.clamp_to_text(text);
        let line_point = self.last_bounds?.localize(&point)?;
        let last_layout = self.last_layout.as_ref()?;
        let utf8_index = last_layout.index_for_x(point.x - line_point.x)?;
        Some(Self::offset_to_utf16(text, utf8_index))
    }
}

#[derive(Clone)]
struct NativeTextFieldElement {
    view: Entity<AppModel>,
    field: NativeTextFieldKind,
    placeholder: SharedString,
}

struct NativeTextFieldPrepaint {
    line: ShapedLine,
    cursor: Option<PaintQuad>,
    selection: Option<PaintQuad>,
}

impl IntoElement for NativeTextFieldElement {
    type Element = Self;

    fn into_element(self) -> Self::Element {
        self
    }
}

impl Element for NativeTextFieldElement {
    type RequestLayoutState = ();
    type PrepaintState = NativeTextFieldPrepaint;

    fn id(&self) -> Option<ElementId> {
        None
    }

    fn source_location(&self) -> Option<&'static core::panic::Location<'static>> {
        None
    }

    fn request_layout(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&gpui::InspectorElementId>,
        window: &mut Window,
        cx: &mut App,
    ) -> (LayoutId, Self::RequestLayoutState) {
        let mut style = Style::default();
        style.size.width = relative(1.0).into();
        style.size.height = window.line_height().into();
        (window.request_layout(style, [], cx), ())
    }

    fn prepaint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&gpui::InspectorElementId>,
        bounds: Bounds<Pixels>,
        _request_layout: &mut Self::RequestLayoutState,
        window: &mut Window,
        cx: &mut App,
    ) -> Self::PrepaintState {
        let (content, selected_range, selection_reversed, marked_range) =
            self.view.read(cx).text_field_snapshot(self.field);
        let cursor = if selection_reversed {
            selected_range.start
        } else {
            selected_range.end
        };
        let style = window.text_style();
        let display_text = if content.is_empty() {
            self.placeholder.clone()
        } else {
            SharedString::from(content.clone())
        };
        let text_color = if content.is_empty() {
            style.color.opacity(0.4)
        } else {
            style.color
        };
        let run = TextRun {
            len: display_text.len(),
            font: style.font(),
            color: text_color,
            background_color: None,
            underline: None,
            strikethrough: None,
        };
        let runs = if !content.is_empty() {
            if let Some(marked_range) = marked_range {
                vec![
                    TextRun {
                        len: marked_range.start,
                        ..run.clone()
                    },
                    TextRun {
                        len: marked_range.end - marked_range.start,
                        underline: Some(UnderlineStyle {
                            color: Some(run.color),
                            thickness: px(1.0),
                            wavy: false,
                        }),
                        ..run.clone()
                    },
                    TextRun {
                        len: display_text.len() - marked_range.end,
                        ..run
                    },
                ]
                .into_iter()
                .filter(|run| run.len > 0)
                .collect()
            } else {
                vec![run]
            }
        } else {
            vec![run]
        };

        let font_size = style.font_size.to_pixels(window.rem_size());
        let line = window
            .text_system()
            .shape_line(display_text, font_size, &runs, None);
        let cursor_pos = line.x_for_index(cursor);
        let (selection, cursor) = if selected_range.is_empty() {
            (
                None,
                Some(fill(
                    Bounds::new(
                        point(bounds.left() + cursor_pos, bounds.top()),
                        size(px(2.0), bounds.bottom() - bounds.top()),
                    ),
                    rgb(UI_ACCENT_TEXT),
                )),
            )
        } else {
            (
                Some(fill(
                    Bounds::from_corners(
                        point(
                            bounds.left() + line.x_for_index(selected_range.start),
                            bounds.top(),
                        ),
                        point(
                            bounds.left() + line.x_for_index(selected_range.end),
                            bounds.bottom(),
                        ),
                    ),
                    rgba(0x2c7df045),
                )),
                None,
            )
        };

        NativeTextFieldPrepaint {
            line,
            cursor,
            selection,
        }
    }

    fn paint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&gpui::InspectorElementId>,
        bounds: Bounds<Pixels>,
        _request_layout: &mut Self::RequestLayoutState,
        prepaint: &mut Self::PrepaintState,
        window: &mut Window,
        cx: &mut App,
    ) {
        let focus_handle = self.view.read(cx).focus_handle_for_text_field(self.field);
        if let Some(focus_handle) = focus_handle {
            window.handle_input(
                &focus_handle,
                ElementInputHandler::new(bounds, self.view.clone()),
                cx,
            );

            if let Some(selection) = prepaint.selection.take() {
                window.paint_quad(selection);
            }
            prepaint
                .line
                .paint(bounds.origin, window.line_height(), window, cx)
                .ok();

            if focus_handle.is_focused(window) {
                if let Some(cursor) = prepaint.cursor.take() {
                    window.paint_quad(cursor);
                }
            }
        }

        let line = prepaint.line.clone();
        self.view.update(cx, |view, _cx| {
            view.set_text_field_layout(self.field, line, bounds);
        });
    }
}

impl AppModel {
    pub(super) fn ensure_native_text_input_setup(
        &mut self,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if self.root_focus_handle.is_none() {
            self.root_focus_handle = Some(cx.focus_handle());
        }

        for field in [
            NativeTextFieldKind::JoinServer,
            NativeTextFieldKind::JoinRoom,
            NativeTextFieldKind::JoinAlias,
            NativeTextFieldKind::Composer,
            NativeTextFieldKind::MembersSearch,
            NativeTextFieldKind::RoomAdminTarget,
        ] {
            self.ensure_text_field_handle(field, cx);
        }

        if self.native_text_inputs_bound {
            return;
        }

        for field in [
            NativeTextFieldKind::JoinServer,
            NativeTextFieldKind::JoinRoom,
            NativeTextFieldKind::JoinAlias,
            NativeTextFieldKind::Composer,
            NativeTextFieldKind::MembersSearch,
            NativeTextFieldKind::RoomAdminTarget,
        ] {
            let Some(handle) = self.focus_handle_for_text_field(field) else {
                continue;
            };
            cx.on_focus(&handle, window, move |model, _, cx| {
                model.activate_text_field(field);
                cx.notify();
            })
            .detach();
            cx.on_blur(&handle, window, move |model, _, cx| {
                model.deactivate_text_field(field);
                cx.notify();
            })
            .detach();
        }

        self.native_text_inputs_bound = true;
    }

    fn ensure_text_field_handle(&mut self, field: NativeTextFieldKind, cx: &mut ViewContext<Self>) {
        self.with_text_field_mut(field, |_, editor| {
            if editor.focus_handle.is_none() {
                editor.focus_handle = Some(cx.focus_handle());
            }
        });
    }

    fn activate_text_field(&mut self, field: NativeTextFieldKind) {
        self.join_form.active = None;
        self.members_search.active = false;
        self.room_admin_target.active = false;
        self.composer.active = false;

        match field {
            NativeTextFieldKind::JoinServer => self.join_form.active = Some(ActiveField::Server),
            NativeTextFieldKind::JoinRoom => self.join_form.active = Some(ActiveField::Room),
            NativeTextFieldKind::JoinAlias => self.join_form.active = Some(ActiveField::Alias),
            NativeTextFieldKind::Composer => self.composer.active = true,
            NativeTextFieldKind::MembersSearch => self.members_search.active = true,
            NativeTextFieldKind::RoomAdminTarget => self.room_admin_target.active = true,
        }
    }

    fn deactivate_text_field(&mut self, field: NativeTextFieldKind) {
        match field {
            NativeTextFieldKind::JoinServer
                if self.join_form.active == Some(ActiveField::Server) =>
            {
                self.join_form.active = None;
            }
            NativeTextFieldKind::JoinRoom if self.join_form.active == Some(ActiveField::Room) => {
                self.join_form.active = None;
            }
            NativeTextFieldKind::JoinAlias if self.join_form.active == Some(ActiveField::Alias) => {
                self.join_form.active = None;
            }
            NativeTextFieldKind::Composer => self.composer.active = false,
            NativeTextFieldKind::MembersSearch => self.members_search.active = false,
            NativeTextFieldKind::RoomAdminTarget => self.room_admin_target.active = false,
            _ => {}
        }
    }

    pub(super) fn blur_native_text_input(
        &mut self,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.join_form.active = None;
        self.members_search.active = false;
        self.room_admin_target.active = false;
        self.composer.active = false;
        if let Some(root_focus) = self.root_focus_handle.as_ref() {
            window.focus(root_focus);
        }
        cx.notify();
    }

    pub(super) fn focus_text_field(
        &mut self,
        field: NativeTextFieldKind,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.ensure_native_text_input_setup(window, cx);
        self.activate_text_field(field);
        if let Some(handle) = self.focus_handle_for_text_field(field) {
            window.focus(&handle);
        }
        cx.notify();
    }

    pub(super) fn focus_handle_for_text_field(
        &self,
        field: NativeTextFieldKind,
    ) -> Option<FocusHandle> {
        self.with_text_field(field, |_, editor| editor.focus_handle.clone())
    }

    fn with_text_field<R>(
        &self,
        field: NativeTextFieldKind,
        f: impl FnOnce(&str, &TextInputEditorState) -> R,
    ) -> R {
        match field {
            NativeTextFieldKind::JoinServer => {
                f(&self.join_form.server, &self.join_form.server_editor)
            }
            NativeTextFieldKind::JoinRoom => {
                f(&self.join_form.room_id, &self.join_form.room_editor)
            }
            NativeTextFieldKind::JoinAlias => {
                f(&self.join_form.alias, &self.join_form.alias_editor)
            }
            NativeTextFieldKind::Composer => f(&self.composer.text, &self.composer.editor),
            NativeTextFieldKind::MembersSearch => {
                f(&self.members_search.query, &self.members_search.editor)
            }
            NativeTextFieldKind::RoomAdminTarget => f(
                &self.room_admin_target.value,
                &self.room_admin_target.editor,
            ),
        }
    }

    pub(super) fn with_text_field_mut<R>(
        &mut self,
        field: NativeTextFieldKind,
        f: impl FnOnce(&mut String, &mut TextInputEditorState) -> R,
    ) -> R {
        match field {
            NativeTextFieldKind::JoinServer => f(
                &mut self.join_form.server,
                &mut self.join_form.server_editor,
            ),
            NativeTextFieldKind::JoinRoom => {
                f(&mut self.join_form.room_id, &mut self.join_form.room_editor)
            }
            NativeTextFieldKind::JoinAlias => {
                f(&mut self.join_form.alias, &mut self.join_form.alias_editor)
            }
            NativeTextFieldKind::Composer => f(&mut self.composer.text, &mut self.composer.editor),
            NativeTextFieldKind::MembersSearch => f(
                &mut self.members_search.query,
                &mut self.members_search.editor,
            ),
            NativeTextFieldKind::RoomAdminTarget => f(
                &mut self.room_admin_target.value,
                &mut self.room_admin_target.editor,
            ),
        }
    }

    pub(super) fn after_text_field_edit(&mut self, field: NativeTextFieldKind) {
        match field {
            NativeTextFieldKind::JoinServer | NativeTextFieldKind::JoinRoom => {
                self.join_form.clear_invite_material();
            }
            NativeTextFieldKind::RoomAdminTarget => {
                self.clear_room_admin_revoke_confirmation();
            }
            _ => {}
        }
    }

    pub(super) fn focused_text_field(&self) -> Option<NativeTextFieldKind> {
        if let Some(active) = self.join_form.active {
            return Some(match active {
                ActiveField::Server => NativeTextFieldKind::JoinServer,
                ActiveField::Room => NativeTextFieldKind::JoinRoom,
                ActiveField::Alias => NativeTextFieldKind::JoinAlias,
            });
        }

        if self.room_admin_target.active {
            return Some(NativeTextFieldKind::RoomAdminTarget);
        }

        if self.members_search.active {
            return Some(NativeTextFieldKind::MembersSearch);
        }

        if self.composer.active {
            return Some(NativeTextFieldKind::Composer);
        }

        None
    }

    pub(super) fn text_field_snapshot(
        &self,
        field: NativeTextFieldKind,
    ) -> (String, Range<usize>, bool, Option<Range<usize>>) {
        self.with_text_field(field, |text, editor| {
            let selected_range = TextInputEditorState::clamp_range(text, &editor.selected_range);
            let marked_range = editor
                .marked_range
                .as_ref()
                .map(|range| TextInputEditorState::clamp_range(text, range));
            (
                text.to_string(),
                selected_range,
                editor.selection_reversed,
                marked_range,
            )
        })
    }

    fn set_text_field_layout(
        &mut self,
        field: NativeTextFieldKind,
        line: ShapedLine,
        bounds: Bounds<Pixels>,
    ) {
        self.with_text_field_mut(field, |_, editor| {
            editor.last_layout = Some(line);
            editor.last_bounds = Some(bounds);
        });
    }

    pub(super) fn render_native_text_field(
        &self,
        cx: &mut ViewContext<Self>,
        field: NativeTextFieldKind,
        placeholder: impl Into<SharedString>,
    ) -> Div {
        let mut content = div()
            .w_full()
            .key_context("cityg-text-input")
            .cursor(CursorStyle::IBeam)
            .on_mouse_down(MouseButton::Left, {
                let field = field;
                cx.listener(move |this, event, window, cx| {
                    this.on_text_field_mouse_down(field, event, window, cx);
                })
            })
            .on_mouse_down(MouseButton::Right, {
                let field = field;
                cx.listener(move |this, event, window, cx| {
                    this.on_text_field_secondary_mouse_down(field, event, window, cx);
                })
            })
            .on_mouse_move({
                let field = field;
                cx.listener(move |this, event, window, cx| {
                    this.on_text_field_mouse_move(field, event, window, cx);
                })
            })
            .on_mouse_up(MouseButton::Left, {
                let field = field;
                cx.listener(move |this, event, window, cx| {
                    this.on_text_field_mouse_up(field, event, window, cx);
                })
            })
            .on_mouse_up_out(MouseButton::Left, {
                let field = field;
                cx.listener(move |this, event, window, cx| {
                    this.on_text_field_mouse_up(field, event, window, cx);
                })
            })
            .child(NativeTextFieldElement {
                view: cx.entity(),
                field,
                placeholder: placeholder.into(),
            });

        if let Some(handle) = self.focus_handle_for_text_field(field) {
            content = content.track_focus(&handle);
        }

        content
    }

    pub(super) fn on_text_field_mouse_down(
        &mut self,
        field: NativeTextFieldKind,
        event: &MouseDownEvent,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.focus_text_field(field, window, cx);
        self.with_text_field_mut(field, |text, editor| {
            editor.on_mouse_down(text, event);
        });
        cx.notify();
    }

    pub(super) fn on_text_field_secondary_mouse_down(
        &mut self,
        field: NativeTextFieldKind,
        event: &MouseDownEvent,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.focus_text_field(field, window, cx);
        let updated = self.with_text_field_mut(field, |text, editor| {
            editor.on_secondary_mouse_down(text, event)
        });
        let availability = self.text_context_menu_availability_for_field(field, cx);
        if updated {
            cx.notify();
        }

        let menu_host = native_text_context_menu_host(window);
        let view = cx.entity();
        let position = event.position;
        cx.spawn(async move |_, cx| {
            let Some(menu_host) = menu_host else {
                return;
            };
            let Some(action) = show_native_text_context_menu(menu_host, position, availability)
            else {
                return;
            };
            let _ = view.update(cx, |model, cx| {
                model.activate_text_field(field);
                model.perform_text_context_menu_action(action, cx);
            });
        })
        .detach();
    }

    pub(super) fn on_text_field_mouse_move(
        &mut self,
        field: NativeTextFieldKind,
        event: &MouseMoveEvent,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        let updated =
            self.with_text_field_mut(field, |text, editor| editor.on_mouse_move(text, event));
        if updated {
            cx.notify();
        }
    }

    pub(super) fn on_text_field_mouse_up(
        &mut self,
        field: NativeTextFieldKind,
        _: &MouseUpEvent,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        let updated = self.with_text_field_mut(field, |_, editor| editor.on_mouse_up());
        if updated {
            cx.notify();
        }
    }

    fn edit_focused_text(
        &mut self,
        cx: &mut ViewContext<Self>,
        edit: impl FnOnce(&mut String, &mut TextInputEditorState) -> bool,
        affects_text: bool,
    ) -> bool {
        let Some(field) = self.focused_text_field() else {
            return false;
        };

        let updated = self.with_text_field_mut(field, edit);
        if updated {
            if affects_text {
                self.after_text_field_edit(field);
            }
            cx.notify();
        }
        updated
    }

    fn text_context_menu_availability_for_field(
        &mut self,
        field: NativeTextFieldKind,
        cx: &mut ViewContext<Self>,
    ) -> NativeTextContextMenuAvailability {
        let (has_selection, has_text) = self.with_text_field_mut(field, |text, editor| {
            (editor.has_selection(text), !text.is_empty())
        });
        NativeTextContextMenuAvailability {
            cut: has_selection,
            copy: has_selection,
            paste: cx
                .read_from_clipboard()
                .and_then(|item| item.text())
                .is_some(),
            select_all: has_text,
        }
    }

    fn perform_text_context_menu_action(
        &mut self,
        action: NativeTextContextMenuAction,
        cx: &mut ViewContext<Self>,
    ) {
        match action {
            NativeTextContextMenuAction::Cut => {
                let _ = self.cut_focused_text(cx);
            }
            NativeTextContextMenuAction::Copy => {
                let _ = self.copy_focused_text(cx);
            }
            NativeTextContextMenuAction::Paste => {
                let _ = self.paste_focused_text(cx);
            }
            NativeTextContextMenuAction::SelectAll => {
                let _ = self.edit_focused_text(cx, |text, editor| editor.select_all(text), false);
            }
        }
    }

    pub(super) fn on_text_backspace_action(
        &mut self,
        _: &TextBackspaceAction,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        let _ = self.edit_focused_text(cx, |text, editor| editor.backspace(text), true);
    }

    pub(super) fn on_text_delete_action(
        &mut self,
        _: &TextDeleteAction,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        let _ = self.edit_focused_text(cx, |text, editor| editor.delete(text), true);
    }

    pub(super) fn on_text_move_left_action(
        &mut self,
        _: &TextMoveLeftAction,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        let _ = self.edit_focused_text(cx, |text, editor| editor.move_left(text), false);
    }

    pub(super) fn on_text_move_right_action(
        &mut self,
        _: &TextMoveRightAction,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        let _ = self.edit_focused_text(cx, |text, editor| editor.move_right(text), false);
    }

    pub(super) fn on_text_select_left_action(
        &mut self,
        _: &TextSelectLeftAction,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        let _ = self.edit_focused_text(cx, |text, editor| editor.select_left(text), false);
    }

    pub(super) fn on_text_select_right_action(
        &mut self,
        _: &TextSelectRightAction,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        let _ = self.edit_focused_text(cx, |text, editor| editor.select_right(text), false);
    }

    pub(super) fn on_text_select_all_action(
        &mut self,
        _: &TextSelectAllAction,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        let _ = self.edit_focused_text(cx, |text, editor| editor.select_all(text), false);
    }

    pub(super) fn on_text_home_action(
        &mut self,
        _: &TextHomeAction,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        let _ = self.edit_focused_text(cx, |text, editor| editor.move_home(text), false);
    }

    pub(super) fn on_text_end_action(
        &mut self,
        _: &TextEndAction,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        let _ = self.edit_focused_text(cx, |text, editor| editor.move_end(text), false);
    }
}

impl EntityInputHandler for AppModel {
    fn text_for_range(
        &mut self,
        range_utf16: Range<usize>,
        adjusted_range: &mut Option<Range<usize>>,
        _window: &mut Window,
        _cx: &mut ViewContext<Self>,
    ) -> Option<String> {
        let field = self.focused_text_field()?;
        self.with_text_field_mut(field, |text, editor| {
            editor.text_for_range(text, range_utf16, adjusted_range)
        })
    }

    fn selected_text_range(
        &mut self,
        _ignore_disabled_input: bool,
        _window: &mut Window,
        _cx: &mut ViewContext<Self>,
    ) -> Option<UTF16Selection> {
        let field = self.focused_text_field()?;
        self.with_text_field_mut(field, |text, editor| editor.selected_text_range(text))
    }

    fn marked_text_range(
        &self,
        _window: &mut Window,
        _cx: &mut ViewContext<Self>,
    ) -> Option<Range<usize>> {
        let field = self.focused_text_field()?;
        self.with_text_field(field, |text, editor| editor.marked_text_range(text))
    }

    fn unmark_text(&mut self, _window: &mut Window, _cx: &mut ViewContext<Self>) {
        if let Some(field) = self.focused_text_field() {
            self.with_text_field_mut(field, |_, editor| {
                editor.marked_range = None;
            });
        }
    }

    fn replace_text_in_range(
        &mut self,
        range_utf16: Option<Range<usize>>,
        new_text: &str,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        let Some(field) = self.focused_text_field() else {
            return;
        };
        let inserted = sanitize_clipboard_text(new_text);
        let updated = self.with_text_field_mut(field, |text, editor| {
            editor.replace_text_in_range(text, range_utf16, &inserted)
        });
        if updated {
            self.after_text_field_edit(field);
            cx.notify();
        }
    }

    fn replace_and_mark_text_in_range(
        &mut self,
        range_utf16: Option<Range<usize>>,
        new_text: &str,
        new_selected_range: Option<Range<usize>>,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        let Some(field) = self.focused_text_field() else {
            return;
        };
        let inserted = sanitize_clipboard_text(new_text);
        self.with_text_field_mut(field, |text, editor| {
            editor.replace_and_mark_text_in_range(text, range_utf16, &inserted, new_selected_range);
        });
        self.after_text_field_edit(field);
        cx.notify();
    }

    fn bounds_for_range(
        &mut self,
        range_utf16: Range<usize>,
        element_bounds: Bounds<Pixels>,
        _window: &mut Window,
        _cx: &mut ViewContext<Self>,
    ) -> Option<Bounds<Pixels>> {
        let field = self.focused_text_field()?;
        self.with_text_field_mut(field, |text, editor| {
            editor.bounds_for_range(text, range_utf16, element_bounds)
        })
    }

    fn character_index_for_point(
        &mut self,
        point: Point<Pixels>,
        _window: &mut Window,
        _cx: &mut ViewContext<Self>,
    ) -> Option<usize> {
        let field = self.focused_text_field()?;
        self.with_text_field_mut(field, |text, editor| {
            editor.character_index_for_point(text, point)
        })
    }
}
