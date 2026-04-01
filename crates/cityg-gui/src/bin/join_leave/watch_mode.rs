use super::*;

pub(super) async fn run_watch_mode(params: WatchModeParams<'_>) -> Result<()> {
    let WatchModeParams {
        server_url,
        room_id,
        alias_base,
        count,
        leave_order,
        verbose,
        message_burst,
        session_artifact_dir,
    } = params;
    println!(
        "watch mode: server={server_url} room={room_id} alias_base={alias_base} count={count}"
    );
    let mut sessions = Vec::with_capacity(count);

    let first_alias = alias_for(alias_base, count, 0);
    println!("joining alias={first_alias}");
    let first_session = perform_join(server_url, room_id, &first_alias).await?;
    println!("join ok: weid={}", hex::encode(first_session.we_epoch_id));
    log_fingerprints(&first_session);
    maybe_write_session_artifact(session_artifact_dir, "joined", &first_alias, &first_session)?;
    let message_token = configured_client_message_token()
        .ok_or_else(|| anyhow!("message auth token is not configured"))?;
    let ws_url = websocket_url(server_url, &first_session.gid, &first_session.leaf_id);
    let notification_cursor = WebSocketReplayCursor::default();
    let (mut event_rx, ws_handle) =
        spawn_notification_listener(&ws_url, Some(&message_token), notification_cursor).await?;
    sessions.push(first_session);

    for i in 1..count {
        let alias = alias_for(alias_base, count, i);
        println!("joining alias={alias}");
        let session = perform_join(server_url, room_id, &alias).await?;
        println!("join ok: weid={}", hex::encode(session.we_epoch_id));
        log_fingerprints(&session);
        maybe_write_session_artifact(session_artifact_dir, "joined", &alias, &session)?;
        expect_membership_event(
            &mut event_rx,
            &session.gid,
            &session.leaf_id,
            "join",
            format!("alias {alias} join"),
        )
        .await?;
        sessions.push(session);
    }

    let effective_message_burst_count = message_burst.count.max(1);
    send_message_burst(
        &mut sessions,
        effective_message_burst_count,
        message_burst.interval,
        Some(&mut event_rx),
    )
    .await?;
    for (idx, session) in sessions.iter().enumerate() {
        maybe_write_session_artifact(
            session_artifact_dir,
            "post-burst",
            &alias_for(alias_base, sessions.len(), idx),
            session,
        )?;
    }

    let default_order: Vec<usize> = (1..=sessions.len()).collect();
    let order = leave_order.as_ref().unwrap_or(&default_order);
    for idx in order {
        if *idx == 0 || *idx > sessions.len() {
            return Err(anyhow!("leave order index {idx} invalid"));
        }
        let session = &sessions[*idx - 1];
        maybe_write_session_artifact(
            session_artifact_dir,
            "pre-leave",
            &alias_for(alias_base, sessions.len(), *idx - 1),
            session,
        )?;
        println!(
            "leaving alias={} weid={}",
            alias_for(alias_base, sessions.len(), *idx - 1),
            hex::encode(session.we_epoch_id)
        );
        perform_leave(session, verbose).await?;
        expect_membership_event(
            &mut event_rx,
            &session.gid,
            &session.leaf_id,
            "revoke",
            format!(
                "alias {} leave",
                alias_for(alias_base, sessions.len(), *idx - 1)
            ),
        )
        .await?;
    }

    println!("watch scenario completed successfully");
    ws_handle.abort();
    let _ = ws_handle.await;
    Ok(())
}

pub(super) async fn send_text_message(session: &mut Session, plaintext: &str) -> Result<()> {
    let client = new_api_client(&session.server_url);
    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let signature = sign_message(
        &session.leaf_id,
        timestamp_ms,
        plaintext.as_bytes(),
        DilithiumSecretKeyTrait::as_bytes(session.pop_secret.as_ref()),
    )?;
    let authenticated = encode_authenticated_message(
        timestamp_ms,
        plaintext.as_bytes(),
        &session.pop_public_key,
        &signature,
    );
    let msg_index: u64 = rng().random();
    let ciphertext = encrypt_message_v2(
        &authenticated,
        &MessageCryptoContext {
            gid: &session.gid,
            we_epoch_id: &session.we_epoch_id,
            xk_hash: &session.xk_hash,
            fs_ec: session.fs_ec,
            barrier_version: session.barrier_version,
            sender_leaf: &session.leaf_id,
            epoch_key: &session.epoch_key,
            k_barrier: &session.k_barrier,
        },
        msg_index,
    )?;
    client
        .send_message(&session.we_epoch_id, &ciphertext, Some(&session.leaf_id))
        .await?;
    Ok(())
}

pub(super) async fn send_dummy_message(session: &mut Session) -> Result<()> {
    let plaintext = format!("join_leave-message-{}", hex::encode(&session.leaf_id[..4]));
    send_text_message(session, plaintext.as_str()).await
}

#[cfg(test)]
pub(super) async fn fetch_and_decrypt_messages(session: &mut Session) -> Result<Vec<String>> {
    let client = new_api_client(&session.server_url);
    let response = client
        .fetch_messages(&session.we_epoch_id, &session.leaf_id)
        .await?;

    let mut plaintexts = Vec::new();
    for message in response.messages {
        let sender_leaf: [u8; 32] = match message.sender.as_slice().try_into() {
            Ok(leaf) => leaf,
            Err(_) => continue,
        };
        let replay_context = MessageCryptoContext {
            gid: &session.gid,
            we_epoch_id: &session.we_epoch_id,
            xk_hash: &session.xk_hash,
            fs_ec: session.fs_ec,
            barrier_version: session.barrier_version,
            sender_leaf: &sender_leaf,
            epoch_key: &session.epoch_key,
            k_barrier: &session.k_barrier,
        };
        let replay_tuple_tag =
            derive_msg_replay_tuple_tag(&replay_context).context("derive fs/msg/replay/tuple")?;
        let replay_context_id = derive_msg_replay_context_id(&replay_context)
            .context("derive fs/msg/replay/context")?;
        session
            .msg_replay_state
            .ensure_tuple(replay_tuple_tag, replay_context_id);
        let (msg_index, authenticated) =
            match decrypt_message_v2_with_index(&message.ciphertext, &replay_context) {
                Ok(outcome) => outcome,
                Err(_) => continue,
            };
        if session
            .msg_replay_state
            .contains(replay_tuple_tag, msg_index)
        {
            continue;
        }
        let envelope = match decode_authenticated_message(&authenticated) {
            Ok(envelope) => envelope,
            Err(_) => continue,
        };
        if verify_sender_leaf_binding(&session.gid, &sender_leaf, envelope.public_key).is_err() {
            continue;
        }
        if verify_message_signature(
            &sender_leaf,
            envelope.timestamp_ms,
            envelope.plaintext,
            envelope.signature,
            envelope.public_key,
        )
        .is_err()
        {
            continue;
        }
        session
            .msg_replay_state
            .record(replay_tuple_tag, replay_context_id, msg_index);
        plaintexts.push(String::from_utf8_lossy(envelope.plaintext).into_owned());
    }
    Ok(plaintexts)
}

pub(super) async fn send_message_burst(
    sessions: &mut [Session],
    message_burst_count: usize,
    message_burst_interval: Duration,
    mut event_rx: Option<&mut mpsc::Receiver<Notification>>,
) -> Result<()> {
    if sessions.is_empty() || message_burst_count == 0 {
        return Ok(());
    }

    for idx in 0..message_burst_count {
        let session = &mut sessions[idx % sessions.len()];
        println!(
            "sending dummy message {}/{} via {}",
            idx + 1,
            message_burst_count,
            hex::encode(session.we_epoch_id)
        );
        send_dummy_message(session).await?;
        if let Some(rx) = event_rx.as_deref_mut() {
            expect_message_event(
                rx,
                &session.we_epoch_id,
                false,
                format!("dummy message delivery {}", idx + 1),
            )
            .await?;
        }
        if message_burst_interval > Duration::ZERO && idx + 1 < message_burst_count {
            sleep(message_burst_interval).await;
        }
    }

    Ok(())
}
