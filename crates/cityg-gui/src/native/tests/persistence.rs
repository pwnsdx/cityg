//! Encrypted session files, chat history, alias bindings and security logs.

use std::fs;
use std::sync::atomic::Ordering;

use super::*;

fn history_entry(text: &str, key: &str, delivery: MessageDelivery) -> ChatMessageEntry {
    ChatMessageEntry {
        sender_leaf: Some([0x21; 32]),
        fallback_label: "peer".to_string(),
        plaintext: text.to_string(),
        ciphertext_hex: key.to_string(),
        timestamp_ms: 5,
        delivery,
        pending_id: None,
    }
}

#[test]
fn sessions_are_saved_encrypted_and_restored() {
    let _config = ConfigDir::new();
    let member = offline_member(40);
    let gid = member.gid();
    let leaf = *member.session().my_leaf_id();
    let session = open_session(OFFLINE_URL, "alice", member, Some(1234)).expect("open");
    assert_eq!(session.room_id, hex_encode(gid));
    assert_eq!(session.last_self_update_ms(), 1234);

    // The file is an encrypted envelope: no secret appears in clear.
    let path = session_file_path(OFFLINE_URL, &session.room_id).expect("path");
    let raw = fs::read(&path).expect("session file");
    let text = String::from_utf8_lossy(&raw);
    assert!(text.contains(ENCRYPTED_SESSION_ALG));
    assert!(!text.contains("identity_secret_key_hex"));
    assert!(!text.contains("alice"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o077, 0);
    }

    // The last-session pointer names it; restoring gives the same member.
    let pointer = read_last_session_pointer()
        .expect("pointer")
        .expect("pointer present");
    assert_eq!(pointer.room_id, session.room_id);
    let restored = load_last_session().expect("load").expect("restored");
    assert_eq!(restored.leaf_id, leaf);
    assert_eq!(restored.alias, "alice");
    assert_eq!(restored.last_self_update_ms(), 1234);
    assert_eq!(restored.view.epoch, session.view.epoch);

    // A self-update moves the clock the sink writes.
    session.mark_self_update();
    let persisted_clock = session.self_update_clock.load(Ordering::SeqCst);
    assert!(persisted_clock > 1234);
    let reopened = load_session_at(OFFLINE_URL, &session.room_id)
        .expect("load")
        .expect("session");
    // The clock is written with the next state save.
    assert!(reopened.last_self_update_ms() >= 1234);

    // The app starts on the restored session.
    let model = AppModel::new(CityGConfig::default());
    let active = model.session.as_ref().expect("active session");
    assert_eq!(active.room_id, session.room_id);
    assert_eq!(model.join_form.alias, "alice");
    assert_eq!(model.join_form.server, OFFLINE_URL);
    assert!(model.join_form.room_id.is_empty());
    assert!(model.join_form.active.is_none());
    assert_eq!(model.info_message.as_deref(), Some("Restored saved session."));
    assert!(model.fetch_task.is_none());

    // Removing it deletes every file and the pointer.
    remove_persisted_session(OFFLINE_URL, &session.room_id).expect("remove");
    assert!(!path.exists());
    assert!(read_last_session_pointer().expect("pointer").is_none());
    assert!(load_last_session().expect("load").is_none());
    assert!(
        load_session_at(OFFLINE_URL, &session.room_id)
            .expect("load")
            .is_none()
    );
    // Removing a session that is not the pointed one keeps the pointer.
    let other = open_session(OFFLINE_URL, "bob", offline_member(41), None).expect("open");
    remove_persisted_session(OFFLINE_URL, &"00".repeat(32)).expect("remove other");
    assert_eq!(
        read_last_session_pointer()
            .expect("pointer")
            .expect("kept")
            .room_id,
        other.room_id
    );
}

#[test]
fn damaged_session_files_are_refused() {
    let _config = ConfigDir::new();
    let session = open_session(OFFLINE_URL, "alice", offline_member(42), None).expect("open");
    let path = session_file_path(OFFLINE_URL, &session.room_id).expect("path");
    let rewrite = |mutate: &dyn Fn(&mut PersistedSession)| {
        let data = fs::read(&path).expect("read");
        let mut persisted = decode_persisted_session(&data, &path).expect("decode");
        mutate(&mut persisted);
        let data = encrypt_persisted_session(&persisted, &path).expect("encrypt");
        write_file_atomic(&path, &data).expect("write");
    };

    // Plaintext files are refused.
    let original = fs::read(&path).expect("read");
    fs::write(&path, b"{\"version\":2}").expect("write");
    assert!(load_last_session().is_err());
    fs::write(&path, &original).expect("restore");
    assert!(load_last_session().expect("load").is_some());

    // Tampered ciphertext does not decrypt.
    let mut envelope: serde_json::Value = serde_json::from_slice(&original).expect("json");
    let ciphertext = envelope["ciphertext_hex"].as_str().expect("hex").to_string();
    let flipped = format!(
        "{}{}",
        if ciphertext.starts_with('0') { "1" } else { "0" },
        &ciphertext[1..]
    );
    envelope["ciphertext_hex"] = serde_json::Value::String(flipped);
    fs::write(&path, serde_json::to_vec(&envelope).expect("json")).expect("write");
    assert!(load_last_session().is_err());
    for (field, value) in [
        ("version", serde_json::json!(99)),
        ("alg", serde_json::json!("rot13")),
        ("nonce_hex", serde_json::json!("00")),
        ("nonce_hex", serde_json::json!("zz")),
        ("ciphertext_hex", serde_json::json!("zz")),
    ] {
        let mut broken: serde_json::Value = serde_json::from_slice(&original).expect("json");
        broken[field] = value;
        fs::write(&path, serde_json::to_vec(&broken).expect("json")).expect("write");
        assert!(load_last_session().is_err(), "{field} accepted");
    }
    fs::write(&path, &original).expect("restore");

    // Old formats, foreign rooms and bad secrets are refused.
    rewrite(&|persisted| persisted.version = 1);
    assert!(
        load_last_session()
            .err()
            .is_some_and(|error| format!("{error:#}").contains("join the room again"))
    );
    fs::write(&path, &original).expect("restore");
    rewrite(&|persisted| persisted.room_id = "11".repeat(32));
    assert!(load_session_at(OFFLINE_URL, &session.room_id).is_err());
    fs::write(&path, &original).expect("restore");
    rewrite(&|persisted| persisted.identity_secret_key_hex = "00".to_string());
    assert!(load_last_session().is_err());
    fs::write(&path, &original).expect("restore");
    rewrite(&|persisted| persisted.member_state_hex = "zz".to_string());
    assert!(load_last_session().is_err());
    fs::write(&path, &original).expect("restore");
    let other_identity = hex_encode(identity(43).secret_key_bytes());
    rewrite(&|persisted| persisted.identity_secret_key_hex = other_identity.clone());
    assert!(load_last_session().is_err());

    // A damaged file does not stop the app: it asks to join again.
    let model = AppModel::new(CityGConfig::default());
    assert!(model.session.is_none());
    assert!(
        model
            .info_message
            .as_deref()
            .is_some_and(|info| info.contains("could not be restored"))
    );
}

#[test]
fn a_passphrase_from_the_environment_keys_the_files() {
    let _config = ConfigDir::new();
    let path = session_file_path(OFFLINE_URL, &"22".repeat(32)).expect("path");
    fs::create_dir_all(path.parent().expect("parent")).expect("dir");
    let history = PersistedHistory {
        version: HISTORY_VERSION,
        messages: Vec::new(),
    };
    let local = encrypt_persisted_history(&history, &path).expect("local key");
    assert!(decode_persisted_history(&local, &path).is_ok());
    assert!(session_local_key_path(&path).expect("key path").exists());

    // SAFETY: the config-dir guard serializes the tests of this process
    // that touch the environment.
    unsafe { std::env::set_var(SESSION_PASSPHRASE_ENV, "correct horse") };
    let keyed = encrypt_persisted_history(&history, &path);
    let decoded_local = decode_persisted_history(&local, &path);
    // SAFETY: as above.
    unsafe { std::env::remove_var(SESSION_PASSPHRASE_ENV) };
    let keyed = keyed.expect("passphrase key");
    assert!(String::from_utf8_lossy(&keyed).contains("env-passphrase"));
    // A file keyed with the local key does not open with the passphrase.
    assert!(decoded_local.is_err());
    assert!(decode_persisted_history(&keyed, &path).is_err());

    // The local key file must hold exactly 32 bytes.
    fs::write(session_local_key_path(&path).expect("key path"), b"short").expect("write");
    assert!(load_or_create_local_session_key(&path).is_err());
    assert!(session_local_key_path(std::path::Path::new("/")).is_err());
    assert_eq!(session_key_hash("a", "b").expect("hash").len(), 64);
    assert_ne!(
        session_key_hash("a", "b").expect("hash"),
        session_key_hash("a\0b", "").expect("hash")
    );
    assert_eq!(SessionKeySource::EnvPassphrase.as_str(), "env-passphrase");
}

#[test]
fn chat_history_keeps_the_newest_sent_messages() {
    let _config = ConfigDir::new();
    let room = "33".repeat(32);
    assert!(load_history(OFFLINE_URL, &room).expect("empty").is_empty());

    let mut messages: Vec<ChatMessageEntry> = (0..(MAX_PERSISTED_MESSAGES + 3))
        .map(|index| history_entry(&format!("m{index}"), &format!("k{index}"), MessageDelivery::Sent))
        .collect();
    messages.push(history_entry("pending", "", MessageDelivery::Pending));
    messages.push(history_entry("failed", "", MessageDelivery::Failed));
    persist_history(OFFLINE_URL, &room, &messages).expect("persist");

    let loaded = load_history(OFFLINE_URL, &room).expect("load");
    assert!(loaded.len() <= MAX_PERSISTED_MESSAGES);
    assert!(loaded.iter().all(|message| message.delivery == MessageDelivery::Sent));
    assert!(loaded.iter().any(|message| message.plaintext == "m502"));
    assert!(!loaded.iter().any(|message| message.plaintext == "m0"));
    assert_eq!(loaded[0].sender_leaf, Some([0x21; 32]));

    // Entries without a sender round-trip; other versions are refused.
    persist_history(
        OFFLINE_URL,
        &room,
        &[ChatMessageEntry {
            sender_leaf: None,
            ..history_entry("anon", "k", MessageDelivery::Sent)
        }],
    )
    .expect("persist");
    assert_eq!(
        load_history(OFFLINE_URL, &room).expect("load")[0].sender_leaf,
        None
    );
    let path = history_file_path(OFFLINE_URL, &room).expect("path");
    let data = encrypt_persisted_history(
        &PersistedHistory {
            version: HISTORY_VERSION + 1,
            messages: Vec::new(),
        },
        &path,
    )
    .expect("encrypt");
    write_file_atomic(&path, &data).expect("write");
    assert!(load_history(OFFLINE_URL, &room).is_err());
}

#[test]
fn alias_bindings_and_security_logs_round_trip() {
    let _config = ConfigDir::new();
    let room = "44".repeat(32);
    assert!(load_alias_bindings(OFFLINE_URL, &room).expect("empty").is_empty());

    let mut bindings = AHashMap::new();
    bindings.insert(
        "bob".to_string(),
        AliasBindingRecord {
            pop_public_key: vec![1, 2, 3],
            leaf_id: [0x55; 32],
        },
    );
    persist_alias_bindings(OFFLINE_URL, &room, &bindings).expect("persist");
    let loaded = load_alias_bindings(OFFLINE_URL, &room).expect("load");
    assert!(loaded.get("bob") == bindings.get("bob"));

    // The legacy map format and damaged entries are tolerated.
    let path = roster_file_path(OFFLINE_URL, &room).expect("path");
    fs::write(&path, br#"{"carol":"0a0b","dave":"zz","eve":""}"#).expect("write");
    let legacy = load_alias_bindings(OFFLINE_URL, &room).expect("legacy");
    assert_eq!(legacy.len(), 1);
    assert_eq!(legacy["carol"].leaf_id, [0; 32]);
    fs::write(
        &path,
        br#"{"version":2,"bindings":{"frank":{"pop_public_key_hex":"0a","leaf_id_hex":"zz"}}}"#,
    )
    .expect("write");
    let damaged = load_alias_bindings(OFFLINE_URL, &room).expect("damaged leaf");
    assert_eq!(damaged["frank"].leaf_id, [0; 32]);
    fs::write(&path, b"[]").expect("write");
    assert!(load_alias_bindings(OFFLINE_URL, &room).is_err());
    persist_alias_bindings(OFFLINE_URL, &room, &AHashMap::new()).expect("clear");
    assert!(!path.exists());
    persist_alias_bindings(OFFLINE_URL, &room, &AHashMap::new()).expect("clear again");

    // Security log.
    assert!(load_security_log(OFFLINE_URL, &room).expect("empty").is_empty());
    let events = vec![SecurityEvent {
        alias: "bob".to_string(),
        description: "TOFU alert".to_string(),
        timestamp_ms: 9,
    }];
    persist_security_log(OFFLINE_URL, &room, &events).expect("persist");
    let loaded = load_security_log(OFFLINE_URL, &room).expect("load");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].description, "TOFU alert");
    remove_security_log(OFFLINE_URL, &room).expect("remove");
    assert!(load_security_log(OFFLINE_URL, &room).expect("gone").is_empty());
    remove_security_log(OFFLINE_URL, &room).expect("remove again");
    persist_security_log(OFFLINE_URL, &room, &events).expect("persist");
    persist_security_log(OFFLINE_URL, &room, &[]).expect("clear");
    let log_path = security_log_file_path(OFFLINE_URL, &room).expect("path");
    assert!(!log_path.exists());
    fs::write(&log_path, b"not json").expect("write");
    assert!(load_security_log(OFFLINE_URL, &room).is_err());
}

#[test]
fn file_helpers() {
    let config = ConfigDir::new();
    let target = config.dir.path().join("file.bin");
    write_file_atomic(&target, b"one").expect("write");
    write_file_atomic(&target, b"two").expect("overwrite");
    assert_eq!(fs::read(&target).expect("read"), b"two");
    assert!(write_file_atomic(std::path::Path::new("/"), b"x").is_err());
    assert!(
        write_file_atomic(&config.dir.path().join("missing").join("file"), b"x").is_err()
    );

    assert_eq!(decode_hex32("x", &"ab".repeat(32)).expect("hex32"), [0xAB; 32]);
    assert!(decode_hex32("x", "abcd").is_err());
    assert!(decode_hex_vec("x", "zz").is_err());
    assert!(session_dir().is_ok());
}

#[test]
fn the_state_sink_rewrites_the_session_file() {
    let _config = ConfigDir::new();
    let member = offline_member(44);
    let context = SessionFileContext::for_member(OFFLINE_URL, "alice", &member);
    let sink = context.sink();
    let exported = member.export().expect("export");
    sink(&exported).expect("sink write");
    let path = session_file_path(OFFLINE_URL, &context.room_id).expect("path");
    assert!(path.exists());
    context.last_self_update_ms.store(77, Ordering::SeqCst);
    sink(&exported).expect("sink write");
    let restored = load_last_session().expect("load").expect("session");
    assert_eq!(restored.last_self_update_ms(), 77);

    // A write that cannot happen is reported to the member driver.
    fs::remove_file(&path).expect("remove");
    fs::create_dir_all(&path).expect("block");
    assert!(sink(&exported).is_err());
}
