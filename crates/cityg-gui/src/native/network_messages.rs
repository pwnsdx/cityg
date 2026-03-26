use std::time::{SystemTime, UNIX_EPOCH};

use pqcrypto_dilithium::dilithium3::{
    public_key_bytes as ml_dsa_public_key_bytes, signature_bytes as ml_dsa_signature_bytes,
};

use crate::message_crypto::{
    MessageCryptoContext, decrypt_message_v2_with_index, derive_msg_replay_context_id,
    derive_msg_replay_tuple_tag, encrypt_message_v2,
};

use super::*;

pub(super) async fn perform_send(params: SendParams) -> Result<ChatMessageEntry> {
    let SendParams {
        server_url,
        gid,
        we_epoch_id,
        xk_hash,
        epoch_key,
        fs_ec,
        barrier_version,
        k_barrier,
        msg_index,
        leaf_id,
        alias,
        plaintext,
        pop_secret_key,
        pop_public_key,
    } = params;

    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let signature = sign_message(
        &leaf_id,
        timestamp_ms,
        plaintext.as_bytes(),
        &pop_secret_key,
    )
    .context("failed to sign message")?;

    let authenticated_msg = encode_authenticated_message(
        timestamp_ms,
        plaintext.as_bytes(),
        &pop_public_key,
        &signature,
    );

    let ciphertext = encrypt_message_v2(
        &authenticated_msg,
        &MessageCryptoContext {
            gid: &gid,
            we_epoch_id: &we_epoch_id,
            xk_hash: &xk_hash,
            fs_ec,
            barrier_version,
            sender_leaf: &leaf_id,
            epoch_key: &epoch_key,
            k_barrier: &k_barrier,
        },
        msg_index,
    )
    .context("failed to encrypt message")?;

    let client = new_api_client(&server_url);
    client
        .send_message(&we_epoch_id, &ciphertext, Some(&leaf_id))
        .await
        .context("failed to send message")?;

    Ok(ChatMessageEntry {
        sender_leaf: Some(leaf_id),
        fallback_label: alias,
        plaintext,
        ciphertext_hex: hex_encode(&ciphertext),
        timestamp_ms,
        delivery: MessageDelivery::Sent,
        pending_id: None,
    })
}

pub(super) async fn perform_fetch(params: FetchParams) -> Result<FetchOutcome> {
    let FetchParams {
        server_url,
        gid,
        we_epoch_id,
        xk_hash,
        epoch_key,
        fs_ec,
        barrier_version,
        k_barrier,
        n_max,
        mut msg_replay_state,
        leaf_id,
        since,
    } = params;

    let client = new_api_client(&server_url);
    let response = client
        .fetch_messages(&we_epoch_id, &leaf_id)
        .await
        .context("failed to fetch messages")?;

    let replay_context_id = derive_msg_replay_context_id(&MessageCryptoContext {
        gid: &gid,
        we_epoch_id: &we_epoch_id,
        xk_hash: &xk_hash,
        fs_ec,
        barrier_version,
        sender_leaf: &leaf_id,
        epoch_key: &epoch_key,
        k_barrier: &k_barrier,
    })
    .context("derive fs/msg/replay/context")?;
    msg_replay_state.prune_to_context(replay_context_id, usize::try_from(n_max).unwrap_or(usize::MAX));

    let mut messages = Vec::new();
    let mut max_timestamp = since.unwrap_or(0);
    for message in response.messages {
        if let Some(threshold) = since
            && message.timestamp_ms <= threshold
        {
            continue;
        }

        if message.sender.len() != 32 {
            tracing::warn!(
                "sender field is not 32 bytes (got {}), skipping message",
                message.sender.len()
            );
            continue;
        }
        let leaf_id: [u8; 32] = message.sender[..32].try_into()?;
        let replay_context = MessageCryptoContext {
            gid: &gid,
            we_epoch_id: &we_epoch_id,
            xk_hash: &xk_hash,
            fs_ec,
            barrier_version,
            sender_leaf: &leaf_id,
            epoch_key: &epoch_key,
            k_barrier: &k_barrier,
        };
        let replay_tuple_tag =
            derive_msg_replay_tuple_tag(&replay_context).context("derive fs/msg/replay/tuple")?;
        msg_replay_state.ensure_tuple(replay_tuple_tag, replay_context_id);

        let (msg_index, authenticated_msg) =
            match decrypt_message_v2_with_index(&message.ciphertext, &replay_context) {
                Ok(outcome) => outcome,
                Err(e) => {
                    tracing::warn!("failed to decrypt message: {}", e);
                    continue;
                }
            };
        if msg_replay_state.contains(replay_tuple_tag, msg_index) {
            tracing::warn!("dropping replayed msg_index={msg_index}");
            continue;
        }

        const MLDSA65_PUBKEY_SIZE: usize = ml_dsa_public_key_bytes();
        const MLDSA65_SIG_SIZE: usize = ml_dsa_signature_bytes();
        const MIN_MSG_SIZE: usize =
            MESSAGE_PREFIX.len() + 8 + 4 + 4 + MLDSA65_PUBKEY_SIZE + 4 + MLDSA65_SIG_SIZE;

        if authenticated_msg.len() < MIN_MSG_SIZE {
            tracing::warn!(
                "message too small for authenticated format: {} bytes < {} bytes minimum",
                authenticated_msg.len(),
                MIN_MSG_SIZE
            );
            continue;
        }

        let envelope = match decode_authenticated_message(&authenticated_msg) {
            Ok(env) => env,
            Err(err) => {
                tracing::warn!("failed to decode authenticated message: {err}");
                continue;
            }
        };

        if envelope.public_key.len() != MLDSA65_PUBKEY_SIZE {
            tracing::warn!(
                "unexpected public key length: {} (expected {})",
                envelope.public_key.len(),
                MLDSA65_PUBKEY_SIZE
            );
            continue;
        }
        if envelope.signature.len() != MLDSA65_SIG_SIZE {
            tracing::warn!(
                "unexpected signature length: {} (expected {})",
                envelope.signature.len(),
                MLDSA65_SIG_SIZE
            );
            continue;
        }
        if let Err(err) = verify_sender_leaf_binding(&gid, &leaf_id, envelope.public_key) {
            tracing::warn!(
                "sender leaf binding failed for message from {}: {}",
                hex_encode(&leaf_id[..4]),
                err
            );
            continue;
        }

        match verify_message_signature(
            &leaf_id,
            envelope.timestamp_ms,
            envelope.plaintext,
            envelope.signature,
            envelope.public_key,
        ) {
            Ok(()) => {
                let sender_display = format!("{}✓", hex_encode(&leaf_id[..4]));
                let plaintext = String::from_utf8_lossy(envelope.plaintext).into_owned();

                if message.timestamp_ms > max_timestamp {
                    max_timestamp = message.timestamp_ms;
                }
                msg_replay_state.record(replay_tuple_tag, replay_context_id, msg_index);

                tracing::info!("message from {}: verification=verified", sender_display);

                messages.push(ChatMessageEntry {
                    sender_leaf: Some(leaf_id),
                    fallback_label: sender_display,
                    plaintext,
                    ciphertext_hex: hex_encode(&message.ciphertext),
                    timestamp_ms: message.timestamp_ms,
                    delivery: MessageDelivery::Sent,
                    pending_id: None,
                });
            }
            Err(e) => {
                tracing::warn!(
                    "signature verification failed for message from {}: {}",
                    hex_encode(&leaf_id[..4]),
                    e
                );
                continue;
            }
        }
    }

    let last_timestamp_ms = if messages.is_empty() {
        since
    } else {
        Some(max_timestamp)
    };

    Ok(FetchOutcome {
        messages,
        last_timestamp_ms,
        msg_replay_state,
    })
}
