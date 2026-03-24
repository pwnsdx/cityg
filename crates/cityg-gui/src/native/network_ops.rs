use std::time::{SystemTime, UNIX_EPOCH};

use pqcrypto_dilithium::dilithium3::{
    public_key_bytes as ml_dsa_public_key_bytes, signature_bytes as ml_dsa_signature_bytes,
};

use crate::message_crypto::{
    MessageCryptoContext, decrypt_message_v2_with_index, derive_msg_replay_tuple_tag,
    encrypt_message_v2,
};

use super::*;

pub(super) async fn perform_fetch_members(params: MembersParams) -> Result<MembersPage> {
    let client = new_api_client(&params.server_url);
    let (raw_members, root, total_count, next_offset) = match &params.mode {
        MembersMode::Full => {
            // Always resolve the first page against latest server root to avoid
            // sticking to an old-but-still-valid parent_root after missed events.
            let response = if params.offset == 0 {
                client
                    .members_with_range(&params.gid, None, Some(params.offset), Some(params.limit))
                    .await?
            } else {
                match client
                    .members_with_range(
                        &params.gid,
                        Some(&params.parent_root),
                        Some(params.offset),
                        Some(params.limit),
                    )
                    .await
                {
                    Ok(response) => response,
                    Err(ApiClientError::HttpStatus { status, .. }) if status.as_u16() == 404 => {
                        info!(
                            "members root {} not found for gid {}; retrying with latest root",
                            hex_encode(params.parent_root),
                            hex_encode(params.gid)
                        );
                        client
                            .members_with_range(
                                &params.gid,
                                None,
                                Some(params.offset),
                                Some(params.limit),
                            )
                            .await?
                    }
                    Err(err) => return Err(err.into()),
                }
            };
            (
                response.members,
                response.root,
                response.total_count,
                response.next_offset,
            )
        }
        MembersMode::Search { query } => {
            // Same latest-root bootstrap for search mode first page.
            let response = if params.offset == 0 {
                client
                    .search_members(
                        &params.gid,
                        query,
                        None,
                        Some(params.offset),
                        Some(params.limit),
                    )
                    .await?
            } else {
                match client
                    .search_members(
                        &params.gid,
                        query,
                        Some(&params.parent_root),
                        Some(params.offset),
                        Some(params.limit),
                    )
                    .await
                {
                    Ok(response) => response,
                    Err(ApiClientError::HttpStatus { status, .. }) if status.as_u16() == 404 => {
                        info!(
                            "search root {} not found for gid {}; retrying with latest root",
                            hex_encode(params.parent_root),
                            hex_encode(params.gid)
                        );
                        client
                            .search_members(
                                &params.gid,
                                query,
                                None,
                                Some(params.offset),
                                Some(params.limit),
                            )
                            .await?
                    }
                    Err(err) => return Err(err.into()),
                }
            };
            (
                response.members,
                response.root,
                response.total_count,
                response.next_offset,
            )
        }
    };
    let root: [u8; 32] = root
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("members root must be 32 bytes"))?;
    if params.offset == 0 {
        verify_members_root_consistency(&client, &params.gid, &root)
            .await
            .context("failed to verify member roster root")?;
    }
    let mut members = Vec::with_capacity(raw_members.len());
    for entry in raw_members {
        let leaf_id = parse_member_leaf_id(entry.leaf_id.as_slice())?;
        let alias = entry.alias.filter(|alias| !alias.trim().is_empty());
        let pop_public_key = entry.pop_public_key.filter(|pk| !pk.is_empty());
        members.push(MemberEntry {
            leaf_id,
            alias,
            pop_public_key,
            join_timestamp_ms: entry.join_date,
            last_seen_timestamp_ms: entry.last_seen,
        });
    }
    Ok(MembersPage {
        members,
        root,
        total_count,
        next_offset,
    })
}

pub(super) async fn perform_fetch_room_admins(
    params: RoomAdminQueryParams,
) -> Result<Vec<Vec<u8>>> {
    let client = new_api_client(&params.server_url);
    let admin_proof = build_room_admin_listing_proof(
        &params.room_id,
        &params.pop_public_key,
        &params.pop_secret_key,
    )
    .context("build room admin listing proof")?;
    let response = client
        .list_room_admins(&params.room_id, admin_proof)
        .await
        .context("list room admins")?;
    Ok(response.admin_pop_public_keys)
}

pub(super) async fn perform_room_admin_mutation(
    params: RoomAdminMutationParams,
) -> Result<RoomAdminMutationOutcome> {
    let client = new_api_client(&params.query.server_url);
    let admin_proof = build_room_admin_target_proof(
        params.kind.operation(),
        &params.query.room_id,
        &params.target_pop_public_key,
        &params.query.pop_public_key,
        &params.query.pop_secret_key,
    )
    .with_context(|| {
        format!(
            "build {} room admin proof",
            match params.kind {
                RoomAdminMutationKind::Grant => "grant",
                RoomAdminMutationKind::Revoke => "revoke",
            }
        )
    })?;
    let response = match params.kind {
        RoomAdminMutationKind::Grant => client
            .grant_room_admin(
                &params.query.room_id,
                &params.target_pop_public_key,
                admin_proof,
            )
            .await
            .context("grant room admin")?,
        RoomAdminMutationKind::Revoke => client
            .revoke_room_admin(
                &params.query.room_id,
                &params.target_pop_public_key,
                admin_proof,
            )
            .await
            .context("revoke room admin")?,
    };
    Ok(RoomAdminMutationOutcome {
        status: response.status,
        admin_count: response.admin_count,
    })
}

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
        msg_sign_secret_key,
        msg_sign_public_key,
    } = params;

    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Sign the message with ML-DSA-65
    let signature = sign_message(
        &leaf_id,
        timestamp_ms,
        plaintext.as_bytes(),
        &msg_sign_secret_key,
    )
    .context("failed to sign message")?;

    let authenticated_msg = encode_authenticated_message(
        timestamp_ms,
        plaintext.as_bytes(),
        &msg_sign_public_key,
        &signature,
    );

    // Encrypt the authenticated message
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

    // Send with leaf_id as sender identifier
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
        mut msg_replay_state,
        leaf_id,
        since,
    } = params;

    let client = new_api_client(&server_url);
    let response = client
        .fetch_messages(&we_epoch_id, &leaf_id)
        .await
        .context("failed to fetch messages")?;

    let mut messages = Vec::new();
    let mut max_timestamp = since.unwrap_or(0);
    for message in response.messages {
        if let Some(threshold) = since
            && message.timestamp_ms <= threshold
        {
            continue;
        }

        // Extract leaf_id from sender field (must be 32 bytes)
        if message.sender.len() != 32 {
            tracing::warn!(
                "sender field is not 32 bytes (got {}), skipping message",
                message.sender.len()
            );
            continue;
        }
        // Safe conversion: we verified length == 32 above
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
        msg_replay_state.ensure_tuple(replay_tuple_tag);

        // Decrypt using ChaCha20-Poly1305
        let (msg_index, authenticated_msg) =
            match decrypt_message_v2_with_index(&message.ciphertext, &replay_context) {
                Ok(outcome) => outcome,
                Err(e) => {
                    // Skip messages that fail decryption (might be from different epoch, sender, or corrupted)
                    tracing::warn!("failed to decrypt message: {}", e);
                    continue;
                }
            };
        if msg_replay_state.contains(replay_tuple_tag, msg_index) {
            tracing::warn!("dropping replayed msg_index={msg_index}");
            continue;
        }

        // Parse authenticated message format: plaintext || pub_key_len (4) || pub_key || signature
        // ML-DSA-65: public key is 1952 bytes, signature is 3293 bytes
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
            continue; // Skip messages that don't meet minimum size
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

        // Verify signature
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
                msg_replay_state.record(replay_tuple_tag, msg_index);

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
                // Skip messages with invalid signatures
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
