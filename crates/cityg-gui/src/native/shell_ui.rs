use gpui::rgba;

pub(super) const UI_PANEL_BORDER: u32 = 0x2e3d5b;
pub(super) const UI_PANEL_TEXT: u32 = 0xf2f5ff;
pub(super) const UI_SUBTLE_TEXT: u32 = 0x9eabd2;
pub(super) const UI_MUTED_TEXT: u32 = 0x7180a5;
pub(super) const UI_ACCENT_TEXT: u32 = 0x67f3b8;
pub(super) const UI_ACCENT_BUTTON_TEXT: u32 = 0x122015;
pub(super) const UI_WARN_TEXT: u32 = 0xffb384;
pub(super) const BARRIER_HP_MODE: &str = "barrier-sealed-v1";

pub(super) fn ui_canvas_fill(window_active: bool) -> gpui::Rgba {
    if window_active {
        rgba(0x111522d9)
    } else {
        rgba(0x141a28c9)
    }
}

pub(super) fn ui_sidebar_fill(window_active: bool) -> gpui::Rgba {
    if window_active {
        rgba(0x151c2fe8)
    } else {
        rgba(0x182033d4)
    }
}

pub(super) fn ui_panel_fill(window_active: bool) -> gpui::Rgba {
    if window_active {
        rgba(0x171f33e3)
    } else {
        rgba(0x1b2438d1)
    }
}

pub(super) fn ui_row_fill(window_active: bool) -> gpui::Rgba {
    if window_active {
        rgba(0x1e2940db)
    } else {
        rgba(0x232d43c8)
    }
}

pub(super) fn ui_button_fill(window_active: bool) -> gpui::Rgba {
    if window_active {
        rgba(0x2c3956e6)
    } else {
        rgba(0x33405ccf)
    }
}

pub(super) fn ui_input_fill(focused: bool) -> gpui::Rgba {
    if focused {
        rgba(0x1b2840f0)
    } else {
        rgba(0x182234d9)
    }
}

pub(super) fn ui_sheet_fill(window_active: bool) -> gpui::Rgba {
    if window_active {
        rgba(0x151929ea)
    } else {
        rgba(0x1a2030d2)
    }
}
