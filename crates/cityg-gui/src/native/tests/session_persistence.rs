use super::*;

#[test]
fn session_encryption_key_prefers_env_passphrase() -> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let _restore = EnvVarRestore {
        original: std::env::var(SESSION_PASSPHRASE_ENV).ok(),
    };

    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    unsafe { std::env::set_var(SESSION_PASSPHRASE_ENV, "cityg-test-passphrase") };

    let temp_dir = TempDir::new()?;
    let session_path = temp_dir
        .path()
        .join("cityg")
        .join("gui")
        .join("session.json");
    let (key, source) = session_encryption_key(&session_path)?;

    assert_eq!(source.as_str(), SessionKeySource::EnvPassphrase.as_str());
    assert_eq!(
        key,
        blake3::derive_key(SESSION_KEY_DERIVE_CONTEXT, b"cityg-test-passphrase")
    );
    assert!(
        !session_local_key_path(&session_path)?.exists(),
        "env-derived key path must not create local key file"
    );
    Ok(())
}

#[test]
fn session_encryption_key_uses_local_key_file_when_env_missing()
-> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let _restore = EnvVarRestore {
        original: std::env::var(SESSION_PASSPHRASE_ENV).ok(),
    };

    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    unsafe { std::env::remove_var(SESSION_PASSPHRASE_ENV) };

    let temp_dir = TempDir::new()?;
    let session_path = temp_dir
        .path()
        .join("cityg")
        .join("gui")
        .join("session.json");

    let (first_key, first_source) = session_encryption_key(&session_path)?;
    assert_eq!(
        first_source.as_str(),
        SessionKeySource::LocalKeyFile.as_str(),
        "missing env passphrase should use local key file"
    );
    let key_path = session_local_key_path(&session_path)?;
    assert!(key_path.exists(), "local key file should be created");
    assert_eq!(fs::read(&key_path)?.len(), 32, "local key must be 32 bytes");

    let (second_key, second_source) = session_encryption_key(&session_path)?;
    assert_eq!(
        second_source.as_str(),
        SessionKeySource::LocalKeyFile.as_str()
    );
    assert_eq!(
        first_key, second_key,
        "local key should be stable across reads"
    );
    Ok(())
}

#[test]
fn load_or_create_local_session_key_rejects_invalid_file_len()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let session_path = temp_dir
        .path()
        .join("cityg")
        .join("gui")
        .join("session.json");
    let key_path = session_local_key_path(&session_path)?;
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&key_path, vec![0xAB; 31])?;

    let err = load_or_create_local_session_key(&session_path)
        .expect_err("invalid key length should fail");
    assert!(
        err.to_string()
            .contains("session local key must be 32 bytes"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn read_last_session_pointer_missing_invalid_and_valid() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));

    assert!(
        read_last_session_pointer()?.is_none(),
        "missing pointer => None"
    );

    let pointer_path = last_session_pointer_path()?;
    if let Some(parent) = pointer_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&pointer_path, b"{not-json")?;
    assert!(
        read_last_session_pointer().is_err(),
        "invalid pointer JSON should error"
    );

    let pointer = LastSessionPointer {
        server_url: "http://127.0.0.1:8080".to_string(),
        room_id: "room-a".to_string(),
    };
    fs::write(&pointer_path, serde_json::to_vec(&pointer)?)?;
    let loaded = read_last_session_pointer()?
        .ok_or_else(|| anyhow!("expected valid pointer to be loaded"))?;
    assert_eq!(loaded.server_url, pointer.server_url);
    assert_eq!(loaded.room_id, pointer.room_id);
    Ok(())
}

#[test]
fn session_dir_respects_cityg_gui_config_dir_env() -> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let _config_guard = set_config_dir_override_for_tests(None);

    let original = std::env::var("CITYG_GUI_CONFIG_DIR").ok();
    let override_root = TempDir::new()?;
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    unsafe {
        std::env::set_var(
            "CITYG_GUI_CONFIG_DIR",
            override_root.path().to_string_lossy().to_string(),
        )
    };

    let resolved = session_dir()?;
    assert_eq!(
        resolved,
        override_root.path().join("cityg").join("gui"),
        "session dir should respect CITYG_GUI_CONFIG_DIR override"
    );

    match original {
        Some(value) => {
            // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
            unsafe { std::env::set_var("CITYG_GUI_CONFIG_DIR", value) };
        }
        None => {
            // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
            unsafe { std::env::remove_var("CITYG_GUI_CONFIG_DIR") };
        }
    }
    Ok(())
}

#[test]
fn session_dir_falls_back_to_user_config_directory() -> Result<(), Box<dyn std::error::Error>> {
    let _env_lock = ENV_VAR_LOCK
        .lock()
        .map_err(|_| anyhow!("env var lock poisoned"))?;
    let _config_guard = set_config_dir_override_for_tests(None);

    let original = std::env::var("CITYG_GUI_CONFIG_DIR").ok();
    // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
    unsafe { std::env::remove_var("CITYG_GUI_CONFIG_DIR") };

    let resolved = session_dir()?;
    assert!(
        resolved.ends_with("cityg/gui"),
        "fallback session dir should include cityg/gui suffix: {}",
        resolved.display()
    );

    match original {
        Some(value) => {
            // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
            unsafe { std::env::set_var("CITYG_GUI_CONFIG_DIR", value) };
        }
        None => {
            // SAFETY: tests serialize env mutation with ENV_VAR_LOCK.
            unsafe { std::env::remove_var("CITYG_GUI_CONFIG_DIR") };
        }
    }
    Ok(())
}

#[test]
fn load_last_session_removes_dangling_pointer() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));

    let pointer = LastSessionPointer {
        server_url: "http://127.0.0.1:8080".to_string(),
        room_id: "missing-room".to_string(),
    };
    let pointer_path = last_session_pointer_path()?;
    if let Some(parent) = pointer_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&pointer_path, serde_json::to_vec(&pointer)?)?;

    let session = load_last_session()?;
    assert!(
        session.is_none(),
        "dangling pointer should return no session"
    );
    assert!(
        !pointer_path.exists(),
        "dangling pointer should be removed automatically"
    );
    Ok(())
}

#[test]
fn load_last_session_invalid_pointer_json_errors() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));

    let pointer_path = last_session_pointer_path()?;
    if let Some(parent) = pointer_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&pointer_path, b"not-json")?;
    assert!(
        load_last_session().is_err(),
        "invalid pointer JSON should produce an error"
    );
    Ok(())
}

#[test]
fn remove_persisted_session_keeps_unrelated_pointer() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));

    let pointer = LastSessionPointer {
        server_url: "http://127.0.0.1:8080".to_string(),
        room_id: "room-a".to_string(),
    };
    let pointer_path = last_session_pointer_path()?;
    if let Some(parent) = pointer_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&pointer_path, serde_json::to_vec(&pointer)?)?;

    remove_persisted_session("http://127.0.0.1:8080", "room-b")?;
    assert!(
        pointer_path.exists(),
        "pointer should remain when removing unrelated session"
    );
    let loaded = read_last_session_pointer()?
        .ok_or_else(|| anyhow!("expected pointer to remain present"))?;
    assert_eq!(loaded.server_url, pointer.server_url);
    assert_eq!(loaded.room_id, pointer.room_id);
    Ok(())
}

#[test]
fn reload_join_finalization_session_rejects_other_identity_snapshot()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));

    let alice = build_test_session(
        0xA11C,
        "http://127.0.0.1:18080",
        "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface",
        "alice",
    )?;
    let mut bob = build_test_session(
        0xB0B0,
        "http://127.0.0.1:18080",
        "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface",
        "bob",
    )?;
    bob.gid = [0xB0; 32];
    bob.leaf_id = [0x0B; 32];

    persist_session(&alice)?;

    let err = match reload_join_finalization_session(
        &bob,
        anyhow!("join finalization failed"),
        "complete join barrier finalization",
    ) {
        Ok(_) => {
            return Err(anyhow!(
                "mismatched persisted identity must not be treated as a finalized session"
            )
            .into());
        }
        Err(err) => err,
    };
    let text = format!("{err:#}");
    assert!(text.contains("complete join barrier finalization"));
    assert!(text.contains("join finalization failed"));
    Ok(())
}

#[test]
fn reset_session_state_uses_pointer_and_handles_security_log_remove_error()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));

    let pointer = LastSessionPointer {
        server_url: "http://127.0.0.1:8080".to_string(),
        room_id: "room-reset".to_string(),
    };
    let pointer_path = last_session_pointer_path()?;
    if let Some(parent) = pointer_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&pointer_path, serde_json::to_vec(&pointer)?)?;

    let log_path = security_log_file_path(&pointer.server_url, &pointer.room_id)?;
    fs::create_dir_all(&log_path)?;

    let mut model = AppModel::new(CityGConfig::default());
    model.reset_session_state()?;
    assert!(model.session.is_none());
    assert!(model.members.is_empty());
    assert!(model.security_events.is_empty());
    Ok(())
}

#[test]
fn reset_session_state_without_session_or_pointer_is_ok() -> Result<(), Box<dyn std::error::Error>>
{
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));
    let mut model = AppModel::new(CityGConfig::default());
    model.reset_session_state()?;
    assert!(model.session.is_none());
    Ok(())
}

#[test]
fn alias_bindings_persist_load_legacy_and_cleanup() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));
    let server = "http://127.0.0.1:8080";
    let room = "room-alias";

    let mut bindings = AHashMap::new();
    bindings.insert(
        "alice".to_string(),
        AliasBindingRecord {
            pop_public_key: vec![0x01, 0x02, 0x03],
            leaf_id: [0xAA; 32],
        },
    );
    persist_alias_bindings(server, room, &bindings)?;

    let loaded = load_alias_bindings(server, room)?;
    let alice = loaded
        .get("alice")
        .ok_or_else(|| anyhow!("alice binding missing"))?;
    assert_eq!(alice.pop_public_key, vec![0x01, 0x02, 0x03]);
    assert_eq!(alice.leaf_id, [0xAA; 32]);

    let roster_path = roster_file_path(server, room)?;
    let legacy: AHashMap<String, String> = [("bob".to_string(), "0a0b".to_string())]
        .into_iter()
        .collect();
    fs::write(&roster_path, serde_json::to_vec(&legacy)?)?;
    let legacy_loaded = load_alias_bindings(server, room)?;
    let bob = legacy_loaded
        .get("bob")
        .ok_or_else(|| anyhow!("legacy bob binding missing"))?;
    assert_eq!(bob.pop_public_key, vec![0x0A, 0x0B]);
    assert_eq!(bob.leaf_id, [0u8; 32], "legacy format has zero leaf id");

    let invalid_store = PersistedAliasStore {
        version: ALIAS_STORE_VERSION,
        bindings: [
            (
                "bad_pop".to_string(),
                PersistedAliasBinding {
                    pop_public_key_hex: "zzzz".to_string(),
                    leaf_id_hex: hex_encode([0x11; 32]),
                },
            ),
            (
                "bad_leaf".to_string(),
                PersistedAliasBinding {
                    pop_public_key_hex: "aa".to_string(),
                    leaf_id_hex: "not-hex".to_string(),
                },
            ),
            (
                "empty_pop".to_string(),
                PersistedAliasBinding {
                    pop_public_key_hex: String::new(),
                    leaf_id_hex: hex_encode([0x22; 32]),
                },
            ),
        ]
        .into_iter()
        .collect(),
    };
    fs::write(&roster_path, serde_json::to_vec(&invalid_store)?)?;
    let invalid_loaded = load_alias_bindings(server, room)?;
    assert!(
        !invalid_loaded.contains_key("bad_pop"),
        "invalid pop key entry should be skipped"
    );
    let bad_leaf = invalid_loaded
        .get("bad_leaf")
        .ok_or_else(|| anyhow!("bad_leaf binding should remain with zeroed leaf id"))?;
    assert_eq!(bad_leaf.pop_public_key, vec![0xAA]);
    assert_eq!(bad_leaf.leaf_id, [0u8; 32]);
    assert!(
        !invalid_loaded.contains_key("empty_pop"),
        "entries with empty pop keys should be skipped"
    );

    persist_alias_bindings(server, room, &AHashMap::new())?;
    assert!(
        !roster_path.exists(),
        "empty bindings should remove roster file"
    );
    Ok(())
}

#[test]
fn load_alias_bindings_invalid_json_errors() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));
    let server = "http://127.0.0.1:8080";
    let room = "room-alias-invalid";
    let roster_path = roster_file_path(server, room)?;
    if let Some(parent) = roster_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&roster_path, b"not-json")?;
    assert!(
        load_alias_bindings(server, room).is_err(),
        "invalid alias store JSON should error"
    );
    Ok(())
}

#[test]
fn security_log_persist_load_and_remove() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base.clone()));
    let server = "http://127.0.0.1:8080";
    let room = "room-sec";

    assert!(
        load_security_log(server, room)?.is_empty(),
        "missing security log should return empty vec"
    );

    let events = vec![
        SecurityEvent {
            alias: "alice".to_string(),
            description: "joined".to_string(),
            timestamp_ms: 1,
        },
        SecurityEvent {
            alias: "bob".to_string(),
            description: "revoked".to_string(),
            timestamp_ms: 2,
        },
    ];
    persist_security_log(server, room, &events)?;
    let loaded = load_security_log(server, room)?;
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded[0].alias, "alice");
    assert_eq!(loaded[1].description, "revoked");

    let log_path = security_log_file_path(server, room)?;
    assert!(
        log_path.exists(),
        "security log file should exist after persist"
    );

    persist_security_log(server, room, &[])?;
    assert!(!log_path.exists(), "empty security log should remove file");

    persist_security_log(server, room, &events)?;
    remove_security_log(server, room)?;
    assert!(!log_path.exists(), "remove_security_log should delete file");
    Ok(())
}

#[test]
fn load_security_events_from_disk_handles_invalid_and_missing_session()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));
    let mut model = AppModel::new(CityGConfig::default());

    let session = build_test_session(
        0x5151,
        "http://127.0.0.1:18080",
        "feedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeed",
        "security",
    )?;
    let log_path = security_log_file_path(&session.server_url, &session.room_id)?;
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&log_path, b"not-json")?;

    model.session = Some(session);
    model.security_events = vec![SecurityEvent {
        alias: "seed".to_string(),
        description: "stale".to_string(),
        timestamp_ms: 1,
    }];
    model.security_unread = 7;
    model.security_panel_expanded = true;
    model.load_security_events_from_disk();
    assert!(model.security_events.is_empty());
    assert_eq!(model.security_unread, 0);
    assert!(!model.security_panel_expanded);

    model.session = None;
    model.security_events = vec![SecurityEvent {
        alias: "seed".to_string(),
        description: "stale".to_string(),
        timestamp_ms: 2,
    }];
    model.security_unread = 3;
    model.security_panel_expanded = true;
    model.load_security_events_from_disk();
    assert!(model.security_events.is_empty());
    assert_eq!(model.security_unread, 0);
    assert!(!model.security_panel_expanded);
    Ok(())
}

#[test]
fn hydrate_alias_bindings_from_disk_handles_invalid_and_missing_session()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));
    let mut model = AppModel::new(CityGConfig::default());

    let session = build_test_session(
        0x5152,
        "http://127.0.0.1:18080",
        "deafdeafdeafdeafdeafdeafdeafdeafdeafdeafdeafdeafdeafdeafdeafdeaf",
        "aliases",
    )?;
    let bindings_path = roster_file_path(&session.server_url, &session.room_id)?;
    if let Some(parent) = bindings_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&bindings_path, b"not-json")?;

    model.session = Some(session);
    model.alias_bindings.insert(
        "seed".to_string(),
        AliasBindingRecord {
            pop_public_key: vec![0xAA],
            leaf_id: [0x11; 32],
        },
    );
    model
        .leaf_alias_index
        .insert([0x11; 32], "seed".to_string());
    model.hydrate_alias_bindings_from_disk();
    assert!(model.alias_bindings.is_empty());
    assert!(model.leaf_alias_index.is_empty());

    model.session = None;
    model.alias_bindings.insert(
        "stale".to_string(),
        AliasBindingRecord {
            pop_public_key: vec![0xBB],
            leaf_id: [0x22; 32],
        },
    );
    model
        .leaf_alias_index
        .insert([0x22; 32], "stale".to_string());
    model.hydrate_alias_bindings_from_disk();
    assert!(model.alias_bindings.is_empty());
    assert!(model.leaf_alias_index.is_empty());
    Ok(())
}

#[gpui::test]
fn gpui_reconcile_alias_bindings_covers_mismatch_and_early_return(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base = temp_dir.path().join("cityg").join("gui");
    let _override_guard = set_config_dir_override_for_tests(Some(base));
    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let session = build_test_session(
        0xABCD,
        "http://127.0.0.1:18080",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "sab",
    )
    .expect("build session");

    view.update(cx, |model, view_cx| {
        model.session = None;
        model.alias_bindings.insert(
            "keep".to_string(),
            AliasBindingRecord {
                pop_public_key: vec![0x01],
                leaf_id: [0x01; 32],
            },
        );
        model.reconcile_alias_bindings(view_cx);
        assert!(
            model.alias_bindings.contains_key("keep"),
            "early return without session should keep existing bindings"
        );
    });

    view.update(cx, |model, view_cx| {
        model.session = Some(session.clone());
        model.alias_bindings.insert(
            "sab".to_string(),
            AliasBindingRecord {
                pop_public_key: vec![0xAA],
                leaf_id: [0x10; 32],
            },
        );
        model.members = vec![
            MemberEntry {
                leaf_id: [0x20; 32],
                alias: Some("sab".to_string()),
                pop_public_key: Some(vec![0xBB]),
                join_timestamp_ms: Some(1),
                last_seen_timestamp_ms: Some(2),
            },
            MemberEntry {
                leaf_id: [0x21; 32],
                alias: None,
                pop_public_key: Some(vec![0xCC]),
                join_timestamp_ms: None,
                last_seen_timestamp_ms: None,
            },
            MemberEntry {
                leaf_id: [0x22; 32],
                alias: Some(String::new()),
                pop_public_key: Some(vec![0xDD]),
                join_timestamp_ms: None,
                last_seen_timestamp_ms: None,
            },
            MemberEntry {
                leaf_id: [0x23; 32],
                alias: Some("dock".to_string()),
                pop_public_key: None,
                join_timestamp_ms: None,
                last_seen_timestamp_ms: None,
            },
        ];

        model.reconcile_alias_bindings(view_cx);

        let updated = model.alias_bindings.get("sab").expect("alias updated");
        assert_eq!(updated.pop_public_key, vec![0xBB]);
        assert_eq!(updated.leaf_id, [0x20; 32]);
        assert_eq!(
            model.leaf_alias_index.get(&[0x20; 32]).map(String::as_str),
            Some("sab")
        );
        assert_eq!(model.security_events.len(), 1);
        assert!(
            model.security_events[0].description.contains("TOFU alert"),
            "TOFU mismatch should record a security event"
        );
        assert!(
            !model.toasts.is_empty(),
            "TOFU mismatch should show a toast"
        );
    });
}

#[gpui::test]
fn gpui_reconcile_alias_bindings_handles_persist_failure(cx: &mut TestAppContext) {
    cx.update(tokio_bridge::init);
    let temp_dir = TempDir::new().expect("create temp dir");
    let base_file = temp_dir.path().join("not-a-directory");
    fs::write(&base_file, b"blocking dir").expect("create blocking file");
    let _override_guard = set_config_dir_override_for_tests(Some(base_file));
    let (view, cx) = cx.add_window_view(|_, _| AppModel::new(CityGConfig::default()));
    let session = build_test_session(
        0xABCE,
        "http://127.0.0.1:18080",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "dock",
    )
    .expect("build session");

    view.update(cx, |model, view_cx| {
        model.session = Some(session.clone());
        model.members = vec![MemberEntry {
            leaf_id: [0x42; 32],
            alias: Some("dock".to_string()),
            pop_public_key: Some(vec![0x42]),
            join_timestamp_ms: None,
            last_seen_timestamp_ms: None,
        }];
        model.reconcile_alias_bindings(view_cx);
        assert!(
            model.alias_bindings.contains_key("dock"),
            "binding should still update when disk persistence fails"
        );
    });
}

#[test]
fn decode_persisted_session_rejects_bad_envelope_metadata() -> Result<(), Box<dyn std::error::Error>>
{
    let temp_dir = TempDir::new()?;
    let session_path = temp_dir
        .path()
        .join("cityg")
        .join("gui")
        .join("session.json");

    let bad_version = EncryptedSessionEnvelope {
        version: ENCRYPTED_SESSION_ENVELOPE_VERSION + 1,
        alg: ENCRYPTED_SESSION_ALG.to_string(),
        key_source: SessionKeySource::LocalKeyFile.as_str().to_string(),
        nonce_hex: "000102030405060708090a0b".to_string(),
        ciphertext_hex: "00".to_string(),
    };
    let err = match decode_persisted_session(&serde_json::to_vec(&bad_version)?, &session_path) {
        Ok(_) => return Err(anyhow!("unsupported envelope version should fail").into()),
        Err(err) => err,
    };
    assert!(
        err.to_string()
            .contains("unsupported encrypted session envelope version"),
        "unexpected error: {err}"
    );

    let bad_alg = EncryptedSessionEnvelope {
        version: ENCRYPTED_SESSION_ENVELOPE_VERSION,
        alg: "aes-gcm".to_string(),
        key_source: SessionKeySource::LocalKeyFile.as_str().to_string(),
        nonce_hex: "000102030405060708090a0b".to_string(),
        ciphertext_hex: "00".to_string(),
    };
    let err = match decode_persisted_session(&serde_json::to_vec(&bad_alg)?, &session_path) {
        Ok(_) => return Err(anyhow!("unsupported envelope algorithm should fail").into()),
        Err(err) => err,
    };
    assert!(
        err.to_string()
            .contains("unsupported encrypted session algorithm"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn decode_persisted_session_rejects_bad_nonce_and_ciphertext_hex()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let session_path = temp_dir
        .path()
        .join("cityg")
        .join("gui")
        .join("session.json");

    let bad_nonce = EncryptedSessionEnvelope {
        version: ENCRYPTED_SESSION_ENVELOPE_VERSION,
        alg: ENCRYPTED_SESSION_ALG.to_string(),
        key_source: SessionKeySource::LocalKeyFile.as_str().to_string(),
        nonce_hex: "000102".to_string(),
        ciphertext_hex: "00".to_string(),
    };
    let err = match decode_persisted_session(&serde_json::to_vec(&bad_nonce)?, &session_path) {
        Ok(_) => return Err(anyhow!("invalid nonce length should fail").into()),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("nonce must be 12 bytes"),
        "unexpected error: {err}"
    );

    let bad_ciphertext = EncryptedSessionEnvelope {
        version: ENCRYPTED_SESSION_ENVELOPE_VERSION,
        alg: ENCRYPTED_SESSION_ALG.to_string(),
        key_source: SessionKeySource::LocalKeyFile.as_str().to_string(),
        nonce_hex: "000102030405060708090a0b".to_string(),
        ciphertext_hex: "zzzz".to_string(),
    };
    let err = match decode_persisted_session(&serde_json::to_vec(&bad_ciphertext)?, &session_path) {
        Ok(_) => return Err(anyhow!("invalid ciphertext hex should fail").into()),
        Err(err) => err,
    };
    assert!(
        err.to_string()
            .contains("encrypted session envelope ciphertext is not valid hex"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn decode_persisted_session_accepts_payload_when_key_source_label_mismatches()
-> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let session_path = temp_dir
        .path()
        .join("cityg")
        .join("gui")
        .join("session.json");
    if let Some(parent) = session_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let session = build_test_session(
        0xDA7A,
        "https://example.invalid",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "mismatch",
    )?;
    let persisted = PersistedSession::from_session(&session);
    let encrypted = encrypt_persisted_session(&persisted, &session_path)?;
    let mut envelope: EncryptedSessionEnvelope = serde_json::from_slice(&encrypted)?;
    envelope.key_source = SessionKeySource::EnvPassphrase.as_str().to_string();

    let decoded = decode_persisted_session(&serde_json::to_vec(&envelope)?, &session_path)?;
    assert_eq!(decoded.room_id, session.room_id);
    assert_eq!(decoded.server_url, session.server_url);
    Ok(())
}

#[test]
fn decode_hex_helpers_validate_shape() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(decode_hex32("gid", &hex_encode([0xAB; 32]))?, [0xAB; 32]);
    assert_eq!(decode_hex_vec("vec", "0a0b")?, vec![0x0A, 0x0B]);
    assert_eq!(decode_hex_vec("empty", "")?, Vec::<u8>::new());
    assert!(decode_hex32("gid", "zz").is_err());
    assert!(decode_hex32("gid", "aa").is_err());
    assert!(decode_hex_vec("vec", "gg").is_err());
    Ok(())
}
