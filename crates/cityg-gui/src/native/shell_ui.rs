use gpui::rgba;

pub(super) const UI_PANEL_BORDER: u32 = 0x26282d;
pub(super) const UI_PANEL_TEXT: u32 = 0xf5f5f7;
pub(super) const UI_SUBTLE_TEXT: u32 = 0xb2b5bc;
pub(super) const UI_MUTED_TEXT: u32 = 0x7d8189;
pub(super) const UI_ACCENT_TEXT: u32 = 0x70efad;
pub(super) const UI_ACCENT_BUTTON_TEXT: u32 = 0x08100c;
pub(super) const UI_WARN_TEXT: u32 = 0xffb384;
pub(super) const UI_INFO_TEXT: u32 = 0xaebad0;
pub(super) const UI_ERROR_TEXT: u32 = 0xffa7b3;
pub(super) const UI_SUCCESS_TEXT: u32 = 0xa8f1c0;
pub(super) const UI_NEUTRAL_FILL: u32 = 0x23252a;
pub(super) const UI_NEUTRAL_ELEVATED_FILL: u32 = 0x2b2d33;
pub(super) const UI_DISABLED_FILL: u32 = 0x2a2c31;
pub(super) const UI_DANGER_FILL: u32 = 0xb14e62;
pub(super) const UI_DANGER_MUTED_FILL: u32 = 0x4b363d;
pub(super) const BARRIER_HP_MODE: &str = "barrier-sealed-v1";

pub(super) fn ui_canvas_fill(window_active: bool) -> gpui::Rgba {
    if window_active {
        rgba(0x050506d2)
    } else {
        rgba(0x0a0b0dc2)
    }
}

pub(super) fn ui_sidebar_fill(window_active: bool) -> gpui::Rgba {
    if window_active {
        rgba(0x0b0c0ef0)
    } else {
        rgba(0x111215dc)
    }
}

pub(super) fn ui_panel_fill(window_active: bool) -> gpui::Rgba {
    if window_active {
        rgba(0x101114e7)
    } else {
        rgba(0x17181cd5)
    }
}

pub(super) fn ui_row_fill(window_active: bool) -> gpui::Rgba {
    if window_active {
        rgba(0x18191ce0)
    } else {
        rgba(0x1d1e22cc)
    }
}

pub(super) fn ui_button_fill(window_active: bool) -> gpui::Rgba {
    if window_active {
        rgba(0x202227ea)
    } else {
        rgba(0x282a30d2)
    }
}

pub(super) fn ui_input_fill(focused: bool) -> gpui::Rgba {
    if focused {
        rgba(0x101216f3)
    } else {
        rgba(0x0d0e11e8)
    }
}

pub(super) fn ui_sheet_fill(window_active: bool) -> gpui::Rgba {
    if window_active {
        rgba(0x090a0cf1)
    } else {
        rgba(0x101114dc)
    }
}
