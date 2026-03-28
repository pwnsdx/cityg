use super::*;

#[cfg(not(test))]
pub(super) fn run_native_app() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .without_time()
        .init();

    // Load configuration
    let config = match CityGConfig::load() {
        Ok(config) => {
            if let Err(e) = config.validate() {
                eprintln!("Configuration validation failed: {}", e);
                eprintln!("Please check your configuration and try again.");
                std::process::exit(1);
            }
            info!("Configuration loaded successfully");
            config
        }
        Err(e) => {
            warn!("Failed to load configuration: {}, using defaults", e);
            CityGConfig::default()
        }
    };

    Application::new().run(move |app: &mut App| {
        info!("Starting City-G GUI");
        tokio_bridge::init(app);
        app_actions::install_native_app_shell(app);

        let window_options = WindowOptions {
            titlebar: Some(TitlebarOptions {
                title: Some("City-G".into()),
                appears_transparent: true,
                traffic_light_position: Some(point(px(12.0), px(12.0))),
            }),
            window_decorations: Some(WindowDecorations::Client),
            window_background: WindowBackgroundAppearance::Blurred,
            window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
                None,
                size(
                    px(config.gui.default_window_width),
                    px(config.gui.default_window_height),
                ),
                app,
            ))),
            ..Default::default()
        };

        let config_clone = config.clone();
        let window_result = app.open_window(window_options, |window, cx| {
            let entity = cx.new(|_| AppModel::new(config_clone));
            let weak = entity.downgrade();

            cx.observe_keystrokes(move |event, window, cx| {
                if let Some(view) = weak.upgrade() {
                    view.update(cx, |model, cx| {
                        model.on_window_keystroke(&event.keystroke, window, cx);
                    });
                }
            })
            .detach();

            entity.update(cx, |model, cx| {
                model.window_active = window.is_window_active();
                model.bootstrap_session_runtime(cx);
                cx.observe_window_activation(window, |model, window, cx| {
                    model.window_active = window.is_window_active();
                    cx.notify();
                })
                .detach();
            });

            entity
        });

        if let Err(e) = window_result {
            eprintln!("Failed to open application window: {}", e);
            eprintln!("Please check your display settings and try again.");
            std::process::exit(1);
        }

        app.activate(true);
    });
}

impl AppModel {
    pub(super) fn barrier_recovery_pending(&self) -> bool {
        self.session
            .as_ref()
            .map(|session| session.barrier_state.barrier_recovery_pending)
            .unwrap_or(false)
    }

    pub(super) fn barrier_recovery_issue(&self) -> Option<BarrierRecoveryIssue> {
        self.session
            .as_ref()
            .and_then(|session| session.barrier_state.barrier_recovery_issue)
    }

    pub(super) fn barrier_recovery_wait_message() -> &'static str {
        "Joined room. Waiting for barrier recovery before messaging."
    }

    pub(super) fn barrier_recovery_message_for_session(session: &AppSession) -> &'static str {
        session
            .barrier_state
            .barrier_recovery_issue
            .map(BarrierRecoveryIssue::user_message)
            .unwrap_or_else(Self::barrier_recovery_wait_message)
    }

    pub(super) fn new(config: CityGConfig) -> Self {
        let mut model = Self {
            config: config.clone(),
            join_form: JoinFormState {
                server: config.client.default_server_url.clone(),
                room_id: AppModel::random_room_id(),
                alias: String::new(),
                active: Some(ActiveField::Alias),
                ..Default::default()
            },
            join_status: JoinStatus::Idle,
            leave_status: LeaveStatus::Idle,
            session: None,
            last_error: None,
            categorized_error: None,
            info_message: None,
            toasts: Vec::new(),
            messages: Vec::new(),
            message_keys: HashSet::new(),
            next_pending_message_id: 1,
            fetch_status: FetchStatus::Idle,
            send_status: SendStatus::Idle,
            composer: MessageComposer::default(),
            fetch_task: None,
            fetch_in_flight: false,
            fetch_after_epoch_sync: false,
            show_ciphertext: false,
            members: Vec::new(),
            members_status: MembersStatus::Idle,
            members_total: 0,
            members_next_offset: None,
            members_loading_append: false,
            members_auto_page: false,
            members_alias_dirty: false,
            members_mode: MembersMode::default(),
            members_search: MembersSearchState::default(),
            members_refresh_task: None,
            alias_bindings: AHashMap::new(),
            leaf_alias_index: AHashMap::new(),
            room_admins: Vec::new(),
            room_admins_loaded: false,
            room_admin_status: RoomAdminStatus::Idle,
            room_admin_target: RoomAdminTargetState::default(),
            room_admin_revoke_confirmation: None,
            epoch_sync_task: None,
            ws_task: None,
            ws_connected: false,
            ws_autostart_attempted: false,
            window_active: false,
            restore_epoch_sync_pending: false,
            last_retry_action: None,
            security_events: Vec::new(),
            security_unread: 0,
            security_panel_expanded: false,
            activity_events: Vec::new(),
            chat_scroll_handle: ScrollHandle::new(),
            right_sidebar_scroll_handle: ScrollHandle::new(),
            sidebar_visible: true,
            sidebar_width: 228.0,
            sidebar_resize: None,
            inspector_visible: true,
            inspector_width: 360.0,
            inspector_resize: None,
            root_focus_handle: None,
            native_text_inputs_bound: false,
        };

        match load_last_session() {
            Ok(Some(saved)) => {
                model.join_form.server = saved.server_url.clone();
                model.join_form.room_id = saved.room_id.clone();
                model.join_form.alias = saved.alias.clone();
                model
                    .join_form
                    .server_editor
                    .reset_for_text(&model.join_form.server);
                model
                    .join_form
                    .room_editor
                    .reset_for_text(&model.join_form.room_id);
                model
                    .join_form
                    .alias_editor
                    .reset_for_text(&model.join_form.alias);
                model.join_form.active = None;
                model.session = Some(saved);
                model.hydrate_alias_bindings_from_disk();
                model.load_security_events_from_disk();
                model.info_message = Some("Restored saved session.".to_string());
                model.fetch_status = FetchStatus::Idle;
                model.send_status = SendStatus::Idle;
                model.messages.clear();
                model.message_keys.clear();
                model.composer.clear();
                model.composer.blur();
                model.fetch_task = None;
                model.fetch_in_flight = false;
                model.fetch_after_epoch_sync = false;
                model.show_ciphertext = false;
                model.restore_epoch_sync_pending = true;
            }
            Ok(None) => {}
            Err(err) => {
                warn!("failed to load saved session: {err:?}");
            }
        }

        model
    }
}

impl Render for AppModel {
    fn render(&mut self, window: &mut Window, cx: &mut ViewContext<Self>) -> impl IntoElement {
        self.ensure_native_text_input_setup(window, cx);
        let background = ui_canvas_fill(self.window_active);
        let has_session = self.session.is_some();
        let body: Div = if let Some(session) = self.session.clone() {
            self.render_session(window, &session, cx)
        } else {
            self.render_join(window, cx)
        };

        let mut root = div()
            .key_context("cityg-root")
            .flex()
            .flex_col()
            .w_full()
            .h_full()
            .bg(background)
            .on_action(cx.listener(Self::on_show_about_action))
            .on_action(cx.listener(Self::on_reveal_config_directory_action))
            .on_action(cx.listener(Self::on_join_room_action))
            .on_action(cx.listener(Self::on_send_message_action))
            .on_action(cx.listener(Self::on_refresh_room_action))
            .on_action(cx.listener(Self::on_leave_room_action))
            .on_action(cx.listener(Self::on_focus_composer_action))
            .on_action(cx.listener(Self::on_focus_members_search_action))
            .on_action(cx.listener(Self::on_focus_room_admin_target_action))
            .on_action(cx.listener(Self::on_copy_room_id_action))
            .on_action(cx.listener(Self::on_copy_room_invite_action))
            .on_action(cx.listener(Self::on_toggle_sidebar_action))
            .on_action(cx.listener(Self::on_show_session_overview_action))
            .on_action(cx.listener(Self::on_toggle_ciphertext_action))
            .on_action(cx.listener(Self::on_copy_selection_action))
            .on_action(cx.listener(Self::on_cut_selection_action))
            .on_action(cx.listener(Self::on_paste_selection_action))
            .on_action(cx.listener(Self::on_text_backspace_action))
            .on_action(cx.listener(Self::on_text_delete_action))
            .on_action(cx.listener(Self::on_text_move_left_action))
            .on_action(cx.listener(Self::on_text_move_right_action))
            .on_action(cx.listener(Self::on_text_select_left_action))
            .on_action(cx.listener(Self::on_text_select_right_action))
            .on_action(cx.listener(Self::on_text_select_all_action))
            .on_action(cx.listener(Self::on_text_home_action))
            .on_action(cx.listener(Self::on_text_end_action))
            .on_action(cx.listener(Self::on_show_emoji_palette_action))
            .on_action(cx.listener(Self::on_minimize_window_action))
            .on_action(cx.listener(Self::on_zoom_window_action));

        if let Some(root_focus_handle) = self.root_focus_handle.as_ref() {
            root = root.track_focus(root_focus_handle);
        }

        if has_session {
            root = root.child(body);
        } else {
            root = root.items_center().justify_center().child(body);
        }

        // Add toast notifications overlay
        if let Some(toasts) = self.render_toasts() {
            root = root.child(toasts);
        }

        root
    }
}

impl AppModel {
    pub(super) fn random_room_id() -> String {
        let mut bytes = [0u8; 32];
        rng().fill(&mut bytes);
        hex_encode(bytes)
    }
}
