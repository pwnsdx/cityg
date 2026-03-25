use super::*;
#[cfg(not(test))]
use gpui::{KeyBinding, Menu, MenuItem, OsAction, SystemMenuType};

gpui::actions!(
    cityg_gui_native,
    [
        ShowAbout,
        RevealConfigDirectory,
        JoinRoomAction,
        SendMessageAction,
        RefreshRoomAction,
        LeaveRoomAction,
        FocusComposerAction,
        FocusMembersSearchAction,
        FocusRoomAdminTargetAction,
        CopyRoomIdAction,
        CopyRoomInviteAction,
        ShowSessionOverviewAction,
        ToggleCiphertextAction,
        CopySelectionAction,
        CutSelectionAction,
        PasteSelectionAction,
        TextBackspaceAction,
        TextDeleteAction,
        TextMoveLeftAction,
        TextMoveRightAction,
        TextSelectLeftAction,
        TextSelectRightAction,
        TextSelectAllAction,
        TextHomeAction,
        TextEndAction,
        ShowEmojiPaletteAction,
        MinimizeWindowAction,
        ZoomWindowAction,
        QuitAppAction,
        HideAppAction,
        HideOtherAppsAction
    ]
);

pub(super) fn install_action_handlers(app: &mut App) {
    app.on_action(|_: &QuitAppAction, app| app.quit());
    app.on_action(|_: &HideAppAction, app| app.hide());
    app.on_action(|_: &HideOtherAppsAction, app| app.hide_other_apps());
    app.on_action(|_: &ShowAbout, _| {});
    app.on_action(|_: &RevealConfigDirectory, _| {});
    app.on_action(|_: &JoinRoomAction, _| {});
    app.on_action(|_: &SendMessageAction, _| {});
    app.on_action(|_: &RefreshRoomAction, _| {});
    app.on_action(|_: &LeaveRoomAction, _| {});
    app.on_action(|_: &FocusComposerAction, _| {});
    app.on_action(|_: &FocusMembersSearchAction, _| {});
    app.on_action(|_: &FocusRoomAdminTargetAction, _| {});
    app.on_action(|_: &CopyRoomIdAction, _| {});
    app.on_action(|_: &CopyRoomInviteAction, _| {});
    app.on_action(|_: &ShowSessionOverviewAction, _| {});
    app.on_action(|_: &ToggleCiphertextAction, _| {});
    app.on_action(|_: &CopySelectionAction, _| {});
    app.on_action(|_: &CutSelectionAction, _| {});
    app.on_action(|_: &PasteSelectionAction, _| {});
    app.on_action(|_: &TextBackspaceAction, _| {});
    app.on_action(|_: &TextDeleteAction, _| {});
    app.on_action(|_: &TextMoveLeftAction, _| {});
    app.on_action(|_: &TextMoveRightAction, _| {});
    app.on_action(|_: &TextSelectLeftAction, _| {});
    app.on_action(|_: &TextSelectRightAction, _| {});
    app.on_action(|_: &TextSelectAllAction, _| {});
    app.on_action(|_: &TextHomeAction, _| {});
    app.on_action(|_: &TextEndAction, _| {});
    app.on_action(|_: &ShowEmojiPaletteAction, _| {});
    app.on_action(|_: &MinimizeWindowAction, _| {});
    app.on_action(|_: &ZoomWindowAction, _| {});
}

#[cfg(not(test))]
pub(super) fn install_native_app_shell(app: &mut App) {
    install_action_handlers(app);

    app.bind_keys([
        KeyBinding::new("cmd-q", QuitAppAction, None),
        KeyBinding::new("cmd-h", HideAppAction, None),
        KeyBinding::new("alt-cmd-h", HideOtherAppsAction, None),
        KeyBinding::new("shift-cmd-o", ShowSessionOverviewAction, None),
        KeyBinding::new("cmd-,", RevealConfigDirectory, Some("cityg-root")),
        KeyBinding::new("cmd-j", JoinRoomAction, Some("cityg-root")),
        KeyBinding::new("cmd-enter", SendMessageAction, Some("cityg-root")),
        KeyBinding::new("cmd-r", RefreshRoomAction, Some("cityg-root")),
        KeyBinding::new("shift-cmd-l", LeaveRoomAction, Some("cityg-root")),
        KeyBinding::new("shift-cmd-m", FocusComposerAction, Some("cityg-root")),
        KeyBinding::new("shift-cmd-f", FocusMembersSearchAction, Some("cityg-root")),
        KeyBinding::new(
            "shift-cmd-a",
            FocusRoomAdminTargetAction,
            Some("cityg-root"),
        ),
        KeyBinding::new("shift-cmd-y", ToggleCiphertextAction, Some("cityg-root")),
        KeyBinding::new("ctrl-cmd-space", ShowEmojiPaletteAction, Some("cityg-root")),
        KeyBinding::new("cmd-m", MinimizeWindowAction, Some("cityg-root")),
        KeyBinding::new("backspace", TextBackspaceAction, Some("cityg-text-input")),
        KeyBinding::new("delete", TextDeleteAction, Some("cityg-text-input")),
        KeyBinding::new("left", TextMoveLeftAction, Some("cityg-text-input")),
        KeyBinding::new("right", TextMoveRightAction, Some("cityg-text-input")),
        KeyBinding::new("shift-left", TextSelectLeftAction, Some("cityg-text-input")),
        KeyBinding::new(
            "shift-right",
            TextSelectRightAction,
            Some("cityg-text-input"),
        ),
        KeyBinding::new("cmd-a", TextSelectAllAction, Some("cityg-text-input")),
        KeyBinding::new("cmd-left", TextHomeAction, Some("cityg-text-input")),
        KeyBinding::new("cmd-right", TextEndAction, Some("cityg-text-input")),
    ]);

    app.set_menus(vec![
        Menu {
            name: "City-G".into(),
            items: vec![
                MenuItem::action("About City-G", ShowAbout),
                MenuItem::action("Show Config Folder", RevealConfigDirectory),
                MenuItem::separator(),
                MenuItem::os_submenu("Services", SystemMenuType::Services),
                MenuItem::separator(),
                MenuItem::action("Hide City-G", HideAppAction),
                MenuItem::action("Hide Others", HideOtherAppsAction),
                MenuItem::separator(),
                MenuItem::action("Quit City-G", QuitAppAction),
            ],
        },
        Menu {
            name: "Edit".into(),
            items: vec![
                MenuItem::os_action("Cut", CutSelectionAction, OsAction::Cut),
                MenuItem::os_action("Copy", CopySelectionAction, OsAction::Copy),
                MenuItem::os_action("Paste", PasteSelectionAction, OsAction::Paste),
                MenuItem::separator(),
                MenuItem::action("Emoji & Symbols", ShowEmojiPaletteAction),
            ],
        },
        Menu {
            name: "Room".into(),
            items: vec![
                MenuItem::action("Join Room", JoinRoomAction),
                MenuItem::action("Send Message", SendMessageAction),
                MenuItem::action("PCS Refresh", RefreshRoomAction),
                MenuItem::action("Leave Room", LeaveRoomAction),
                MenuItem::separator(),
                MenuItem::action("Copy Room ID", CopyRoomIdAction),
                MenuItem::action("Copy Invite", CopyRoomInviteAction),
            ],
        },
        Menu {
            name: "View".into(),
            items: vec![
                MenuItem::action("Focus Composer", FocusComposerAction),
                MenuItem::action("Focus Member Search", FocusMembersSearchAction),
                MenuItem::action("Focus Room Admin Target", FocusRoomAdminTargetAction),
                MenuItem::separator(),
                MenuItem::action("Show Session Overview", ShowSessionOverviewAction),
                MenuItem::separator(),
                MenuItem::action("Toggle Ciphertext", ToggleCiphertextAction),
            ],
        },
        Menu {
            name: "Window".into(),
            items: vec![
                MenuItem::action("Minimize", MinimizeWindowAction),
                MenuItem::action("Zoom", ZoomWindowAction),
                MenuItem::separator(),
                MenuItem::action("Show Session Overview", ShowSessionOverviewAction),
            ],
        },
    ]);

    app.set_dock_menu(vec![
        MenuItem::action("Join Room", JoinRoomAction),
        MenuItem::action("Show Session Overview", ShowSessionOverviewAction),
        MenuItem::action("PCS Refresh", RefreshRoomAction),
        MenuItem::separator(),
        MenuItem::action("Show Config Folder", RevealConfigDirectory),
    ]);
}

impl AppModel {
    pub(super) fn on_show_about_action(
        &mut self,
        _: &ShowAbout,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        let config_path = session_dir()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| "Unavailable".to_string());
        let detail = format!(
            "Version {}\nNative shell with blurred materials, split-view workspace, Dock actions, and background notifications.\nConfig folder: {}",
            env!("CARGO_PKG_VERSION"),
            config_path
        );
        let prompt = window.prompt(
            PromptLevel::Info,
            "About City-G",
            Some(&detail),
            &["OK"],
            cx,
        );
        cx.spawn(async move |_, _| {
            let _ = prompt.await;
        })
        .detach();
    }

    pub(super) fn on_reveal_config_directory_action(
        &mut self,
        _: &RevealConfigDirectory,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        match reveal_gui_config_directory() {
            Ok(path) => {
                self.info_message = Some(format!("Opened config folder at {}", path.display()));
                self.show_success("Config folder revealed", cx);
            }
            Err(err) => self.show_error_toast(format!("Failed to open config folder: {err}"), cx),
        }
    }

    pub(super) fn on_join_room_action(
        &mut self,
        _: &JoinRoomAction,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if self.session.is_some() {
            self.show_info("Leave the current room before joining another one.", cx);
            return;
        }
        self.start_join(cx);
    }

    pub(super) fn on_send_message_action(
        &mut self,
        _: &SendMessageAction,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if self.session.is_none() {
            self.show_info("Join a room before sending messages.", cx);
            return;
        }
        self.start_send(cx);
    }

    pub(super) fn on_refresh_room_action(
        &mut self,
        _: &RefreshRoomAction,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if self.session.is_none() {
            self.show_info("Join a room before requesting PCS refresh.", cx);
            return;
        }
        self.start_pcs_refresh(cx);
    }

    pub(super) fn on_leave_room_action(
        &mut self,
        _: &LeaveRoomAction,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if self.session.is_none() {
            self.show_info("No active room to leave.", cx);
            return;
        }
        self.start_leave(cx);
    }

    pub(super) fn on_focus_composer_action(
        &mut self,
        _: &FocusComposerAction,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if self.session.is_some() {
            self.focus_composer(window, cx);
        }
    }

    pub(super) fn on_focus_members_search_action(
        &mut self,
        _: &FocusMembersSearchAction,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if self.session.is_some() {
            self.focus_members_search(window, cx);
        }
    }

    pub(super) fn on_focus_room_admin_target_action(
        &mut self,
        _: &FocusRoomAdminTargetAction,
        window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if self.session.is_some() {
            self.focus_room_admin_target(window, cx);
        }
    }

    pub(super) fn on_copy_room_id_action(
        &mut self,
        _: &CopyRoomIdAction,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.copy_room_id_to_clipboard(cx);
    }

    pub(super) fn on_copy_room_invite_action(
        &mut self,
        _: &CopyRoomInviteAction,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        self.copy_room_invite_to_clipboard(cx);
    }

    pub(super) fn on_toggle_ciphertext_action(
        &mut self,
        _: &ToggleCiphertextAction,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if self.session.is_some() {
            self.toggle_ciphertext(cx);
        }
    }

    pub(super) fn on_copy_selection_action(
        &mut self,
        _: &CopySelectionAction,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        let _ = self.copy_focused_text(cx);
    }

    pub(super) fn on_cut_selection_action(
        &mut self,
        _: &CutSelectionAction,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        let _ = self.cut_focused_text(cx);
    }

    pub(super) fn on_paste_selection_action(
        &mut self,
        _: &PasteSelectionAction,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        let _ = self.paste_focused_text(cx);
    }

    pub(super) fn on_show_emoji_palette_action(
        &mut self,
        _: &ShowEmojiPaletteAction,
        window: &mut Window,
        _cx: &mut ViewContext<Self>,
    ) {
        window.show_character_palette();
    }

    pub(super) fn on_minimize_window_action(
        &mut self,
        _: &MinimizeWindowAction,
        window: &mut Window,
        _cx: &mut ViewContext<Self>,
    ) {
        window.minimize_window();
    }

    pub(super) fn on_zoom_window_action(
        &mut self,
        _: &ZoomWindowAction,
        window: &mut Window,
        _cx: &mut ViewContext<Self>,
    ) {
        window.zoom_window();
    }
}

#[cfg(target_os = "macos")]
fn reveal_gui_config_directory() -> Result<std::path::PathBuf> {
    let path = session_dir()?;
    std::fs::create_dir_all(&path)?;
    let status = std::process::Command::new("open").arg(&path).status()?;
    if !status.success() {
        return Err(anyhow!("open returned status {}", status));
    }
    Ok(path)
}

#[cfg(not(target_os = "macos"))]
fn reveal_gui_config_directory() -> Result<std::path::PathBuf> {
    let path = session_dir()?;
    std::fs::create_dir_all(&path)?;
    Ok(path)
}
