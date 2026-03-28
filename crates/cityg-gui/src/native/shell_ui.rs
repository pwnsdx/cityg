use gpui::rgba;

pub(super) const UI_PANEL_BORDER: u32 = 0x303640;
pub(super) const UI_PANEL_TEXT: u32 = 0xf6f8fc;
pub(super) const UI_SUBTLE_TEXT: u32 = 0xc4cbd6;
pub(super) const UI_MUTED_TEXT: u32 = 0x8f98a5;
pub(super) const UI_ACCENT_TEXT: u32 = 0x5fb2ff;
pub(super) const UI_ACCENT_BUTTON_TEXT: u32 = 0x041320;
pub(super) const UI_WARN_TEXT: u32 = 0xffc47a;
pub(super) const UI_INFO_TEXT: u32 = 0xbfd9ff;
pub(super) const UI_ERROR_TEXT: u32 = 0xffa7b1;
pub(super) const UI_SUCCESS_TEXT: u32 = 0xa7e6bd;
pub(super) const UI_NEUTRAL_FILL: u32 = 0x1e242b;
pub(super) const UI_NEUTRAL_ELEVATED_FILL: u32 = 0x252d37;
pub(super) const UI_DISABLED_FILL: u32 = 0x1a2026;
pub(super) const UI_DANGER_FILL: u32 = 0xcf6274;
pub(super) const UI_DANGER_MUTED_FILL: u32 = 0x553943;
pub(super) const UI_ACCENT_SOFT_FILL: u32 = 0x173656;
pub(super) const BARRIER_HP_MODE: &str = "barrier-sealed-v1";

pub(super) fn ui_canvas_fill(window_active: bool) -> gpui::Rgba {
    if window_active {
        rgba(0x0a0f16ea)
    } else {
        rgba(0x10161ed6)
    }
}

#[allow(dead_code)]
pub(super) fn ui_sidebar_fill(window_active: bool) -> gpui::Rgba {
    if window_active {
        rgba(0x0c1118f3)
    } else {
        rgba(0x141a22e4)
    }
}

pub(super) fn ui_panel_fill(window_active: bool) -> gpui::Rgba {
    if window_active {
        rgba(0x121823e8)
    } else {
        rgba(0x171e28da)
    }
}

pub(super) fn ui_row_fill(window_active: bool) -> gpui::Rgba {
    if window_active {
        rgba(0x18202ae4)
    } else {
        rgba(0x1e2630d3)
    }
}

pub(super) fn ui_button_fill(window_active: bool) -> gpui::Rgba {
    if window_active {
        rgba(0x222a34ef)
    } else {
        rgba(0x2a323ddc)
    }
}

pub(super) fn ui_input_fill(focused: bool) -> gpui::Rgba {
    if focused {
        rgba(0x121925f6)
    } else {
        rgba(0x101620ee)
    }
}

#[allow(dead_code)]
pub(super) fn ui_sheet_fill(window_active: bool) -> gpui::Rgba {
    if window_active {
        rgba(0x0f141cf4)
    } else {
        rgba(0x161c24e3)
    }
}

pub(super) fn ui_toolbar_fill(window_active: bool) -> gpui::Rgba {
    if window_active {
        rgba(0x111823f1)
    } else {
        rgba(0x181f2ade)
    }
}

pub(super) fn ui_hover_fill(window_active: bool) -> gpui::Rgba {
    if window_active {
        rgba(0x2c3542f0)
    } else {
        rgba(0x333c49db)
    }
}

pub(super) fn ui_sidebar_selected_fill(window_active: bool) -> gpui::Rgba {
    if window_active {
        rgba(0x1a3d63e8)
    } else {
        rgba(0x23405bd8)
    }
}
