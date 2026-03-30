use super::*;

#[test]
fn encrypt_decrypt_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let key = [42u8; 32];
    let plaintext = b"Hello, City-G! This is a test message.";

    let ciphertext = encrypt_message(plaintext, &key)?;
    let decrypted = decrypt_message(&ciphertext, &key)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn payload_envelope_v2_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let gid = [0x11u8; 32];
    let we_epoch_id = [0x22u8; 32];
    let xk_hash = [0x23u8; 32];
    let epoch_key = [0x33u8; 32];
    let k_barrier = [0x44u8; 32];
    let sender_leaf = [0x45u8; 32];
    let context = MessageCryptoContext {
        gid: &gid,
        we_epoch_id: &we_epoch_id,
        xk_hash: &xk_hash,
        fs_ec: 9,
        barrier_version: 5,
        sender_leaf: &sender_leaf,
        epoch_key: &epoch_key,
        k_barrier: &k_barrier,
    };
    let plaintext = b"payload-v2-roundtrip";
    let envelope = encrypt_message_v2(plaintext, &context, 7)?;
    let decrypted = decrypt_message_v2(&envelope, &context)?;
    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn payload_envelope_v2_roundtrip_exposes_msg_index() -> Result<(), Box<dyn std::error::Error>> {
    let gid = [0x71u8; 32];
    let we_epoch_id = [0x72u8; 32];
    let xk_hash = [0x73u8; 32];
    let epoch_key = [0x74u8; 32];
    let k_barrier = [0x75u8; 32];
    let sender_leaf = [0x76u8; 32];
    let context = MessageCryptoContext {
        gid: &gid,
        we_epoch_id: &we_epoch_id,
        xk_hash: &xk_hash,
        fs_ec: 5,
        barrier_version: 2,
        sender_leaf: &sender_leaf,
        epoch_key: &epoch_key,
        k_barrier: &k_barrier,
    };
    let envelope = encrypt_message_v2(b"payload-v2-index", &context, 42)?;
    let (msg_index, decrypted) = decrypt_message_v2_with_index(&envelope, &context)?;
    assert_eq!(msg_index, 42);
    assert_eq!(decrypted, b"payload-v2-index");
    Ok(())
}

#[test]
fn payload_envelope_v2_context_mismatch_fails() -> Result<(), Box<dyn std::error::Error>> {
    let gid = [0x51u8; 32];
    let we_epoch_id = [0x52u8; 32];
    let xk_hash = [0x53u8; 32];
    let epoch_key = [0x53u8; 32];
    let k_barrier = [0x54u8; 32];
    let sender_leaf = [0x55u8; 32];
    let good_context = MessageCryptoContext {
        gid: &gid,
        we_epoch_id: &we_epoch_id,
        xk_hash: &xk_hash,
        fs_ec: 12,
        barrier_version: 4,
        sender_leaf: &sender_leaf,
        epoch_key: &epoch_key,
        k_barrier: &k_barrier,
    };
    let bad_context = MessageCryptoContext {
        barrier_version: 5,
        ..good_context
    };
    let envelope = encrypt_message_v2(b"context-bound", &good_context, 1)?;
    assert!(
        decrypt_message_v2(&envelope, &bad_context).is_err(),
        "barrier_version mismatch must fail decryption"
    );
    Ok(())
}

#[test]
fn payload_envelope_v2_msg_index_changes_ciphertext() -> Result<(), Box<dyn std::error::Error>> {
    let gid = [0x61u8; 32];
    let we_epoch_id = [0x62u8; 32];
    let xk_hash = [0x63u8; 32];
    let epoch_key = [0x63u8; 32];
    let k_barrier = [0x64u8; 32];
    let sender_leaf = [0x65u8; 32];
    let context = MessageCryptoContext {
        gid: &gid,
        we_epoch_id: &we_epoch_id,
        xk_hash: &xk_hash,
        fs_ec: 3,
        barrier_version: 1,
        sender_leaf: &sender_leaf,
        epoch_key: &epoch_key,
        k_barrier: &k_barrier,
    };
    let payload_a = encrypt_message_v2(b"same-plaintext", &context, 1)?;
    let payload_b = encrypt_message_v2(b"same-plaintext", &context, 2)?;
    assert_ne!(payload_a, payload_b, "msg_index must influence ciphertext");
    Ok(())
}

#[test]
fn payload_envelope_v2_sender_scope_changes_ciphertext() -> Result<(), Box<dyn std::error::Error>> {
    let gid = [0x81u8; 32];
    let we_epoch_id = [0x82u8; 32];
    let xk_hash = [0x83u8; 32];
    let epoch_key = [0x84u8; 32];
    let k_barrier = [0x85u8; 32];
    let sender_leaf_a = [0x86u8; 32];
    let sender_leaf_b = [0x87u8; 32];
    let context_a = MessageCryptoContext {
        gid: &gid,
        we_epoch_id: &we_epoch_id,
        xk_hash: &xk_hash,
        fs_ec: 7,
        barrier_version: 3,
        sender_leaf: &sender_leaf_a,
        epoch_key: &epoch_key,
        k_barrier: &k_barrier,
    };
    let context_b = MessageCryptoContext {
        sender_leaf: &sender_leaf_b,
        ..context_a
    };
    let payload_a = encrypt_message_v2(b"same-plaintext", &context_a, 11)?;
    let payload_b = encrypt_message_v2(b"same-plaintext", &context_b, 11)?;
    assert_ne!(payload_a, payload_b, "sender scope must affect ciphertext");
    assert!(
        decrypt_message_v2(&payload_a, &context_b).is_err(),
        "wrong sender scope must fail decryption"
    );
    Ok(())
}

#[test]
fn msg_replay_state_tracks_multiple_tuples_and_caps_window()
-> Result<(), Box<dyn std::error::Error>> {
    let mut replay = MsgReplayState::default();
    let tuple_a = [0xA1; 32];
    let context_id = [0xC1; 32];
    replay.ensure_tuple(tuple_a, context_id);
    for msg_index in 0..(MAX_MSGS_PER_REPLAY_TUPLE as u64 + 8) {
        replay.record(tuple_a, context_id, msg_index);
    }
    assert_eq!(replay.len(tuple_a), MAX_MSGS_PER_REPLAY_TUPLE);
    assert!(
        !replay.contains(tuple_a, 0),
        "oldest indices should be evicted"
    );
    assert!(replay.contains(tuple_a, MAX_MSGS_PER_REPLAY_TUPLE as u64 + 7));

    let tuple_b = [0xB2; 32];
    replay.ensure_tuple(tuple_b, context_id);
    assert!(
        replay.contains(tuple_a, MAX_MSGS_PER_REPLAY_TUPLE as u64 + 7),
        "adding a second tuple must preserve the first tuple window"
    );
    assert_eq!(replay.len(tuple_b), 0);
    replay.record(tuple_b, context_id, 99);
    assert!(replay.contains(tuple_b, 99));
    Ok(())
}

#[test]
fn msg_replay_state_ignores_duplicate_indices() -> Result<(), Box<dyn std::error::Error>> {
    let mut replay = MsgReplayState::default();
    let tuple = [0x42; 32];
    let context_id = [0x43; 32];
    replay.ensure_tuple(tuple, context_id);
    replay.record(tuple, context_id, 7);
    replay.record(tuple, context_id, 7);
    replay.record(tuple, context_id, 7);
    assert_eq!(
        replay.len(tuple),
        1,
        "duplicate indices must not grow replay state"
    );
    assert!(replay.contains(tuple, 7));
    Ok(())
}

#[test]
fn msg_replay_state_allows_reuse_after_window_eviction() -> Result<(), Box<dyn std::error::Error>> {
    let mut replay = MsgReplayState::default();
    let tuple = [0x55; 32];
    let context_id = [0x56; 32];
    replay.ensure_tuple(tuple, context_id);
    for msg_index in 0..=(MAX_MSGS_PER_REPLAY_TUPLE as u64) {
        replay.record(tuple, context_id, msg_index);
    }
    assert!(
        !replay.contains(tuple, 0),
        "oldest index must be evicted once window is exceeded"
    );
    replay.record(tuple, context_id, 0);
    assert!(
        replay.contains(tuple, 0),
        "evicted index can be re-seen by design outside replay window"
    );
    Ok(())
}

#[test]
fn derive_msg_replay_tuple_tag_changes_with_tuple_inputs() -> Result<(), Box<dyn std::error::Error>>
{
    let gid = [0x31u8; 32];
    let we_epoch_id = [0x32u8; 32];
    let xk_hash = [0x33u8; 32];
    let epoch_key = [0x34u8; 32];
    let k_barrier = [0x35u8; 32];
    let sender_leaf_a = [0x36u8; 32];
    let sender_leaf_b = [0x37u8; 32];
    let context_a = MessageCryptoContext {
        gid: &gid,
        we_epoch_id: &we_epoch_id,
        xk_hash: &xk_hash,
        fs_ec: 8,
        barrier_version: 1,
        sender_leaf: &sender_leaf_a,
        epoch_key: &epoch_key,
        k_barrier: &k_barrier,
    };
    let context_b = MessageCryptoContext {
        sender_leaf: &sender_leaf_b,
        ..context_a
    };
    let tag_a = derive_msg_replay_tuple_tag(&context_a)?;
    let tag_b = derive_msg_replay_tuple_tag(&context_b)?;
    assert_ne!(tag_a, tag_b, "sender scope must affect replay tuple tag");
    Ok(())
}

#[test]
fn encrypt_produces_different_ciphertexts() -> Result<(), Box<dyn std::error::Error>> {
    let key = [42u8; 32];
    let plaintext = b"Same message, different ciphertext";

    let ciphertext1 = encrypt_message(plaintext, &key)?;
    let ciphertext2 = encrypt_message(plaintext, &key)?;

    assert_ne!(ciphertext1, ciphertext2);

    let decrypted1 = decrypt_message(&ciphertext1, &key)?;
    let decrypted2 = decrypt_message(&ciphertext2, &key)?;
    assert_eq!(decrypted1, plaintext);
    assert_eq!(decrypted2, plaintext);
    Ok(())
}

#[test]
fn decrypt_with_wrong_key_fails() -> Result<(), Box<dyn std::error::Error>> {
    let correct_key = [42u8; 32];
    let wrong_key = [99u8; 32];
    let plaintext = b"Secret message";

    let ciphertext = encrypt_message(plaintext, &correct_key)?;
    let result = decrypt_message(&ciphertext, &wrong_key);

    assert!(result.is_err(), "Decryption should fail with wrong key");
    let err = match result {
        Err(e) => e,
        Ok(_) => return Err("expected error".into()),
    };
    assert!(
        err.to_string().contains("decryption failed"),
        "Error message should indicate decryption failure"
    );
    Ok(())
}

#[test]
fn decrypt_tampered_ciphertext_fails() -> Result<(), Box<dyn std::error::Error>> {
    let key = [42u8; 32];
    let plaintext = b"Authenticated message";

    let mut ciphertext = encrypt_message(plaintext, &key)?;
    if ciphertext.len() > 20 {
        ciphertext[20] ^= 0x01;
    }

    let result = decrypt_message(&ciphertext, &key);

    assert!(result.is_err(), "Decryption should fail for tampered data");
    let err = match result {
        Err(e) => e,
        Ok(_) => return Err("expected error".into()),
    };
    assert!(
        err.to_string().contains("decryption failed"),
        "Error message should indicate decryption failure"
    );
    Ok(())
}

#[test]
fn decrypt_short_ciphertext_fails() -> Result<(), Box<dyn std::error::Error>> {
    let key = [42u8; 32];
    let short_data = b"short";

    let result = decrypt_message(short_data, &key);

    assert!(result.is_err(), "Decryption should fail for short data");
    let err = match result {
        Err(e) => e,
        Ok(_) => return Err("expected error".into()),
    };
    assert!(
        err.to_string().contains("too short"),
        "Error should mention data is too short"
    );
    Ok(())
}

#[test]
fn encrypt_empty_message() -> Result<(), Box<dyn std::error::Error>> {
    let key = [42u8; 32];
    let plaintext = b"";

    let ciphertext = encrypt_message(plaintext, &key)?;
    let decrypted = decrypt_message(&ciphertext, &key)?;

    assert_eq!(decrypted, plaintext);
    assert_eq!(decrypted.len(), 0);
    Ok(())
}

#[test]
fn encrypt_large_message() -> Result<(), Box<dyn std::error::Error>> {
    let key = [42u8; 32];
    let plaintext = vec![b'A'; 10_000];

    let ciphertext = encrypt_message(&plaintext, &key)?;
    let decrypted = decrypt_message(&ciphertext, &key)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn ciphertext_format_validation() -> Result<(), Box<dyn std::error::Error>> {
    let key = [42u8; 32];
    let plaintext = b"Test message";

    let ciphertext = encrypt_message(plaintext, &key)?;

    assert!(
        ciphertext.len() >= 28,
        "Ciphertext should be at least 28 bytes (nonce + tag)"
    );
    assert_eq!(
        ciphertext.len(),
        12 + plaintext.len() + 16,
        "Ciphertext size should be nonce + plaintext + tag"
    );
    Ok(())
}

#[test]
fn multiple_keys_independence() -> Result<(), Box<dyn std::error::Error>> {
    let key1 = [1u8; 32];
    let key2 = [2u8; 32];
    let plaintext = b"Multi-key test";

    let ciphertext1 = encrypt_message(plaintext, &key1)?;
    let ciphertext2 = encrypt_message(plaintext, &key2)?;

    assert_ne!(ciphertext1, ciphertext2);
    assert!(decrypt_message(&ciphertext1, &key1).is_ok());
    assert!(decrypt_message(&ciphertext2, &key2).is_ok());
    assert!(decrypt_message(&ciphertext1, &key2).is_err());
    assert!(decrypt_message(&ciphertext2, &key1).is_err());
    Ok(())
}
