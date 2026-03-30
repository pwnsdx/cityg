use super::*;

#[gpui::test]
fn gpui_session_overview_action_toggles_inline_inspector(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let session = build_test_session(
        0x1234,
        "http://127.0.0.1:9",
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        "alice",
    )
    .expect("build test session");

    let (view, cx) = cx.add_window_view(move |window, _| {
        window.resize(size(px(1280.0), px(760.0)));
        let mut model = AppModel::new(CityGConfig::default());
        model.session = Some(session);
        model
    });

    cx.update(|window, app| {
        view.update(app, |model, view_cx| {
            let window_width = f32::from(window.bounds().size.width);
            assert!(model.resolved_inspector_width(window_width).is_some());

            model.on_show_session_overview_action(&ShowSessionOverviewAction, window, view_cx);
        });
    });
    cx.run_until_parked();
    cx.update(|window, app| {
        view.update(app, |model, _| {
            let window_width = f32::from(window.bounds().size.width);
            assert!(model.resolved_inspector_width(window_width).is_none());
        });
    });
    cx.update(|window, app| {
        view.update(app, |model, view_cx| {
            model.on_show_session_overview_action(&ShowSessionOverviewAction, window, view_cx);
        });
    });
    cx.run_until_parked();
    cx.update(|window, app| {
        view.update(app, |model, _| {
            let window_width = f32::from(window.bounds().size.width);
            assert!(model.resolved_inspector_width(window_width).is_some());
        });
    });
}

#[gpui::test]
fn gpui_toggle_sidebar_action_toggles_inline_sidebar(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let session = build_test_session(
        0x2233,
        "http://127.0.0.1:9",
        "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
        "sidebar",
    )
    .expect("build test session");

    let (view, cx) = cx.add_window_view(move |window, _| {
        window.resize(size(px(1280.0), px(760.0)));
        let mut model = AppModel::new(CityGConfig::default());
        model.session = Some(session);
        model
    });

    cx.update(|window, app| {
        view.update(app, |model, view_cx| {
            let window_width = f32::from(window.bounds().size.width);
            assert!(model.resolved_sidebar_width(window_width).is_some());

            model.on_toggle_sidebar_action(&ToggleSidebarAction, window, view_cx);
        });
    });
    cx.run_until_parked();
    cx.update(|window, app| {
        view.update(app, |model, _| {
            let window_width = f32::from(window.bounds().size.width);
            assert!(model.resolved_sidebar_width(window_width).is_none());
        });
    });
    cx.update(|window, app| {
        view.update(app, |model, view_cx| {
            model.on_toggle_sidebar_action(&ToggleSidebarAction, window, view_cx);
        });
    });
    cx.run_until_parked();
    cx.update(|window, app| {
        view.update(app, |model, _| {
            let window_width = f32::from(window.bounds().size.width);
            assert!(model.resolved_sidebar_width(window_width).is_some());
        });
    });
}

#[gpui::test]
fn gpui_dispatch_toggle_inspector_action_from_focused_search_field(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let session = build_test_session(
        0x7788,
        "http://127.0.0.1:9",
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "focus",
    )
    .expect("build test session");

    let (view, cx) = cx.add_window_view(move |window, _| {
        window.resize(size(px(1280.0), px(760.0)));
        let mut model = AppModel::new(CityGConfig::default());
        model.session = Some(session);
        model
    });

    cx.update(|window, app| {
        view.update(app, |model, view_cx| {
            model.focus_members_search(window, view_cx);
        });
    });
    cx.run_until_parked();

    cx.dispatch_action(ShowSessionOverviewAction);

    cx.update(|window, app| {
        view.update(app, |model, _| {
            let window_width = f32::from(window.bounds().size.width);
            assert!(model.resolved_inspector_width(window_width).is_none());
        });
    });
}

#[gpui::test]
fn gpui_double_click_members_search_selects_all_text(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let session = build_test_session(
        0x3344,
        "http://127.0.0.1:9",
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "search",
    )
    .expect("build test session");

    let (view, cx) = cx.add_window_view(move |window, _| {
        window.resize(size(px(1280.0), px(760.0)));
        let mut model = AppModel::new(CityGConfig::default());
        model.session = Some(session);
        model.members_search.set_query("member-lookup".to_string());
        model
    });

    cx.update(|window, app| {
        view.update(app, |model, view_cx| {
            model.on_text_field_mouse_down(
                NativeTextFieldKind::MembersSearch,
                &test_mouse_down_event_with_click_count(2),
                window,
                view_cx,
            );

            let query = model.members_search.query().to_string();
            assert_eq!(model.members_search.editor.selected_range, 0..query.len());
            assert!(model.members_search.active);
        });
    });
}

#[gpui::test]
fn gpui_secondary_click_members_search_preserves_selection_and_focuses(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let session = build_test_session(
        0x4455,
        "http://127.0.0.1:9",
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        "search-secondary",
    )
    .expect("build test session");

    let (view, cx) = cx.add_window_view(move |window, _| {
        window.resize(size(px(1280.0), px(760.0)));
        let mut model = AppModel::new(CityGConfig::default());
        model.session = Some(session);
        model.members_search.set_query("member-lookup".to_string());
        model.members_search.editor.selected_range = 0..6;
        model
    });

    cx.update(|window, app| {
        view.update(app, |model, view_cx| {
            model.on_text_field_secondary_mouse_down(
                NativeTextFieldKind::MembersSearch,
                &test_mouse_down_event_with_button(MouseButton::Right),
                window,
                view_cx,
            );

            assert_eq!(model.members_search.editor.selected_range, 0..6);
            assert!(model.members_search.active);
            assert!(!model.members_search.editor.is_selecting);
        });
    });
}

#[gpui::test]
fn gpui_text_select_all_action_selects_focused_members_search_text(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let session = build_test_session(
        0x5566,
        "http://127.0.0.1:9",
        "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
        "search-select-all",
    )
    .expect("build test session");

    let (view, cx) = cx.add_window_view(move |window, _| {
        window.resize(size(px(1280.0), px(760.0)));
        let mut model = AppModel::new(CityGConfig::default());
        model.session = Some(session);
        model.members_search.set_query("member-lookup".to_string());
        model.members_search.editor.selected_range = 3..3;
        model
    });

    cx.update(|window, app| {
        view.update(app, |model, view_cx| {
            model.focus_text_field(NativeTextFieldKind::MembersSearch, window, view_cx);
            model.on_text_select_all_action(&TextSelectAllAction, window, view_cx);

            let query = model.members_search.query().to_string();
            assert_eq!(model.members_search.editor.selected_range, 0..query.len());
            assert!(model.members_search.active);
        });
    });
}

#[gpui::test]
fn gpui_pending_barrier_recovery_surfaces_guidance_instead_of_errors(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let mut session = build_test_session(
        0xBADA55,
        "http://127.0.0.1:9",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "pending",
    )
    .expect("build test session");
    session.barrier_state.barrier_recovery_pending = true;
    session.last_fetch_timestamp_ms = None;

    cx.update(|_, app| {
        view.update(app, |model, view_cx| {
            model.on_join_finished(Ok(session.clone()), view_cx);
            assert_eq!(
                model.info_message.as_deref(),
                Some(AppModel::barrier_recovery_wait_message())
            );
            assert!(
                !model.fetch_in_flight,
                "fetch should stay deferred while pending"
            );
            assert!(
                model.last_error.is_none(),
                "pending recovery is expected state"
            );

            model.composer.set_text("hello".to_string());
            model.start_send(view_cx);
            assert!(matches!(model.send_status, SendStatus::Idle));
            assert_eq!(
                model.info_message.as_deref(),
                Some(AppModel::barrier_recovery_wait_message())
            );
            assert!(
                model.last_error.is_none(),
                "blocked send should not become an error"
            );
        });
    });
}

#[gpui::test]
fn gpui_pending_barrier_recovery_defers_fetch_without_setting_error(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let mut session = build_test_session(
        0xBADA56,
        "http://127.0.0.1:9",
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "pending-fetch",
    )
    .expect("build test session");
    session.barrier_state.barrier_recovery_pending = true;

    cx.update(|_, app| {
        view.update(app, |model, view_cx| {
            model.session = Some(session.clone());
            model.schedule_fetch(view_cx, Duration::ZERO);
            assert!(matches!(model.fetch_status, FetchStatus::Idle));
            assert!(
                !model.fetch_in_flight,
                "fetch should not be scheduled while pending"
            );
            assert_eq!(
                model.info_message.as_deref(),
                Some(AppModel::barrier_recovery_wait_message())
            );
            assert!(
                model.last_error.is_none(),
                "deferred fetch should not set an error"
            );
        });
    });
}
