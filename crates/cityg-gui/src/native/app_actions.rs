use super::*;

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
        QuitAppAction,
        HideAppAction,
        HideOtherAppsAction
    ]
);

#[cfg(not(test))]
pub(super) fn install_native_app_shell(app: &mut App) {
    app.on_action(|_: &QuitAppAction, app| app.quit());
    app.on_action(|_: &HideAppAction, app| app.hide());
    app.on_action(|_: &HideOtherAppsAction, app| app.hide_other_apps());

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
            "Version {}\nGPUI shell with native menus, shortcuts, blur, and background notifications.\nConfig folder: {}",
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
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if self.session.is_some() {
            self.focus_composer(cx);
        }
    }

    pub(super) fn on_focus_members_search_action(
        &mut self,
        _: &FocusMembersSearchAction,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if self.session.is_some() {
            self.focus_members_search(cx);
        }
    }

    pub(super) fn on_focus_room_admin_target_action(
        &mut self,
        _: &FocusRoomAdminTargetAction,
        _window: &mut Window,
        cx: &mut ViewContext<Self>,
    ) {
        if self.session.is_some() {
            self.focus_room_admin_target(cx);
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
