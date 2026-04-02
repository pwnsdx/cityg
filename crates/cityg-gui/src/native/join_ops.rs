use super::*;
use cityg_client::join_bundle::{
    JoinEpochBundleInputs, build_join_epoch_bundle, parse_accepted_bundle_runtime_state,
};
use cityg_client::join_runtime::generate_join_runtime_material;

const JOIN_IDENTITY_RETRY_MAX_ATTEMPTS: u32 = 8;

fn generate_room_identity() -> RoomIdentity {
    let (pop_public_key, pop_secret_key) = cityg_api_client::generate_room_admin_keypair();
    RoomIdentity {
        pop_public_key,
        pop_secret_key,
    }
}

fn rotate_room_identity(server_url: &str, room_id: &str) -> Result<RoomIdentity> {
    let identity = generate_room_identity();
    persist_room_identity(server_url, room_id, &identity)?;
    Ok(identity)
}

pub(super) async fn perform_join(params: JoinParams) -> Result<AppSession> {
    let JoinParams {
        server_url,
        room_id,
        alias,
    } = params;

    if server_url.is_empty() {
        return Err(anyhow!(
            "worker edge or compatible endpoint URL must not be empty"
        ));
    }
    if room_id.is_empty() {
        return Err(anyhow!("room id must not be empty"));
    }
    if alias.is_empty() {
        return Err(anyhow!("alias must not be empty"));
    }

    let mut room_identity = load_or_create_room_identity(&server_url, &room_id)
        .context("load or create persistent room identity")?;

    let mut generated_kbroad_public: Option<Vec<u8>> = None;
    let mut bootstrap_attempted = false;
    let mut retry_attempt = 0u32;

    let client = new_api_client(&server_url);
    let ticket = loop {
        let pop_public_key = room_identity.pop_public_key.clone();
        let pop_secret_key = room_identity.pop_secret_key.clone();
        let identity_binding = Some(cityg_api_client::build_identity_binding(
            &alias,
            &pop_public_key,
            &pop_secret_key,
        )?);
        match client.join_ticket(&room_id, &alias, identity_binding).await {
            Ok(ticket) => break ticket,
            Err(ApiClientError::HttpStatus {
                status,
                message,
                freeze_code,
                freeze_reason,
                ..
            }) => {
                if status.is_server_error()
                    && message.contains("kbroad key missing")
                    && !bootstrap_attempted
                {
                    bootstrap_attempted = true;
                    generated_kbroad_public = Some(
                        client
                            .bootstrap_room_for_join(
                                &room_id,
                                &pop_public_key,
                                &pop_secret_key,
                                generated_kbroad_public.take(),
                            )
                            .await
                            .map_err(anyhow::Error::from)
                            .context("failed to bootstrap room KBROAD key")?,
                    );
                    continue;
                }

                if status.is_server_error()
                    && message.contains("cover leaf index already allocated")
                    && retry_attempt < JOIN_IDENTITY_RETRY_MAX_ATTEMPTS
                {
                    retry_attempt = retry_attempt.saturating_add(1);
                    room_identity = rotate_room_identity(&server_url, &room_id)
                        .context("regenerate room identity after cover leaf collision")?;
                    warn!(
                        attempt = retry_attempt,
                        "join identity collided on cover leaf index; regenerating identity"
                    );
                    continue;
                }

                if should_retry_ticket_http_error(status.as_u16(), &message, freeze_code)
                    && retry_attempt < TICKET_RETRY_MAX_ATTEMPTS
                {
                    let delay = ticket_retry_delay(retry_attempt);
                    retry_attempt = retry_attempt.saturating_add(1);
                    warn!(
                        attempt = retry_attempt,
                        delay_ms = delay.as_millis() as u64,
                        status = status.as_u16(),
                        message = %message,
                        "join_ticket race/concurrency rejection; retrying"
                    );
                    sleep(delay).await;
                    continue;
                }

                let detail = describe_http_failure(
                    status.as_str(),
                    &message,
                    freeze_code,
                    freeze_reason.as_deref(),
                );
                return Err(anyhow!(detail));
            }
            Err(err) => return Err(err.into()),
        }
    };
    let (mut session, requires_bootstrap_finalize) = {
        let prepared_runtime =
            cityg_api_client::prepare_runtime_join_ticket(&ticket).map_err(anyhow::Error::from)?;

        let witness_bytes = if let Some(witness_bytes) = prepared_runtime.witness_bytes.clone() {
            witness_bytes
        } else {
            return Err(anyhow!("server did not include canonical witness"));
        };

        let mut header_map = BTreeMap::new();
        header_map.insert(hdr::HDR_KBROAD_ALG, Value::Text("ml-kem-768".to_string()));
        header_map.insert(
            hdr::HDR_KBROAD_PUB,
            Value::Bytes(prepared_runtime.kbroad_public.clone()),
        );
        let join_runtime = generate_join_runtime_material()?;
        header_map.insert(
            hdr::HDR_BARRIER_LEAF_PK,
            Value::Bytes(join_runtime.barrier_leaf_public_key.clone()),
        );

        let mut fs_state = join_runtime.forward_state;
        let pop_secret = Box::new(
            dilithium5::SecretKey::from_bytes(&room_identity.pop_secret_key)
                .context("invalid POP key")?,
        );

        let (msg_sign_public_key, msg_sign_secret_key) =
            cityg_client::message_auth::generate_message_signing_keypair();
        let vrf_secret_key = join_runtime.vrf_secret_key;
        let vrf_public_key = join_runtime.vrf_public_key;

        let prepared_orchestration = prepared_runtime.prepare_barrier_orchestration(
            room_identity.pop_public_key.as_slice(),
            pop_secret.as_ref(),
            vrf_secret_key.as_slice(),
            vrf_public_key.as_slice(),
        );
        let prepared_parts = prepared_orchestration.parts.clone();
        let prepared_params = prepared_orchestration.params.clone();

        let build_join_bundle = |fs_state: &mut ForwardSecrecyState,
                                 disable_autonomic_evolve: bool|
         -> Result<ClientEpochBundle> {
            build_join_epoch_bundle(JoinEpochBundleInputs {
                header: header_map.clone(),
                parts: prepared_parts.clone(),
                params: prepared_params.clone(),
                fs_state,
                witness_bytes: Some(&witness_bytes),
                disable_autonomic_evolve,
            })
            .context("failed to build join anchor")
        };

        let pristine_fs_state = fs_state.clone();
        let mut bundle = build_join_bundle(&mut fs_state, false)?;

        let capss_witness_bytes = encode_capss_witness(&bundle.capss_witness)?;

        if prepared_runtime.parent_root == [0u8; 32]
            && !prepared_runtime.bootstrap_public.is_empty()
        {
            return Err(anyhow!(
                "server requires bootstrap signer for first join; GUI bootstrap signer support is not configured"
            ));
        }

        match client.accept_epoch_bundle(&bundle).await {
            Ok(_) => {}
            Err(ApiClientError::HttpStatus {
                freeze_code,
                freeze_reason,
                ..
            }) if cityg_api_client::is_fs_forward_jump_group_http_error(
                freeze_code,
                freeze_reason.as_deref(),
            ) =>
            {
                fs_state = pristine_fs_state;
                bundle = build_join_bundle(&mut fs_state, true)?;
                client
                    .accept_epoch_bundle(&bundle)
                    .await
                    .context("server rejected join bundle after stale-group retry")?;
            }
            Err(err) => return Err(err).context("server rejected join bundle"),
        }
        let forward_state = fs_state;
        let accepted_bundle = parse_accepted_bundle_runtime_state(
            &bundle,
            prepared_runtime.fs_policy_version.as_str(),
            prepared_runtime.fs_epoch_base_ts,
        )?;
        let accepted_fs_dev_prev_commit = accepted_bundle
            .fs_dev_prev_commit
            .ok_or_else(|| anyhow!("accepted join bundle missing fs_dev commit"))?;
        let regular_fingerprint = Some(accepted_bundle.seed_ctx_hash);
        let fs_fingerprint = accepted_bundle.fs_fingerprint;
        let requires_bootstrap_finalize =
            prepared_runtime.barrier_version == 0 && prepared_runtime.parent_root == [0u8; 32];
        let session = AppSession {
            server_url,
            room_id,
            alias,
            gid: prepared_runtime.gid,
            cat: prepared_runtime.cat,
            leaf_id: prepared_runtime.leaf_id,
            parent_root: prepared_runtime.parent_root,
            join_delta_root: prepared_runtime.join_delta_root,
            revoked_since_root: prepared_runtime.revoked_since_root,
            revoked_root: prepared_runtime.revoked_root,
            regular_fingerprint,
            fs_fingerprint,
            tswe_salt_hash: prepared_runtime.tswe_salt_hash,
            pox_r_commit: prepared_runtime.pox_r_commit,
            we_epoch_id: bundle.we_epoch_id,
            xk_hash: bundle.hp_binding.xk_hash,
            epoch_key: bundle.epoch_key,
            forward_state,
            fs_ec: accepted_bundle.fs_ec,
            fs_epoch_commit: accepted_bundle.fs_epoch_commit,
            fs_dev_prev_commit: accepted_fs_dev_prev_commit,
            fs_epoch_created_at: SystemTime::now(),
            fs_epoch_rotation_interval_secs: 300,
            pop_public_key: room_identity.pop_public_key.clone(),
            pop_secret_key: room_identity.pop_secret_key.clone(),
            msg_sign_public_key,
            msg_sign_secret_key,
            vrf_secret_key,
            vrf_public_key,
            kbroad_public: prepared_runtime.kbroad_public.clone(),
            bootstrap_public: prepared_runtime.bootstrap_public.clone(),
            proof_mode: prepared_runtime.proof_mode.clone(),
            vrf_id: prepared_runtime.vrf_id.clone(),
            policy_version: prepared_runtime.policy_version.clone(),
            msphf_crs_id: prepared_runtime.msphf_crs_id.clone(),
            msphf_params_id: prepared_runtime.msphf_params_id.clone(),
            fs_policy_version: accepted_bundle.fs_policy_version,
            fs_epoch_base_ts: accepted_bundle.fs_epoch_base_ts,
            fs_forward_leap_policy: FsForwardLeapPolicy {
                h: prepared_runtime.fs_forward_leap_policy.h,
                checkpoint_interval: prepared_runtime.fs_forward_leap_policy.checkpoint_interval,
                slack_anchor: prepared_runtime.fs_forward_leap_policy.slack_anchor,
                slack_first_device: prepared_runtime.fs_forward_leap_policy.slack_first_device,
                slack_device: prepared_runtime.fs_forward_leap_policy.slack_device,
            },
            last_accepted_ec: prepared_runtime.last_accepted_ec.max(accepted_bundle.fs_ec),
            last_fetch_timestamp_ms: None,
            msg_replay_state: MsgReplayState::default(),
            capss_witness: capss_witness_bytes,
            barrier_state: BarrierSecretState {
                barrier_initialized: true,
                barrier_version: prepared_runtime.barrier_version,
                barrier_roots_hash: compute_revocation_roots_hash(
                    &prepared_runtime.revoked_since_root,
                    &prepared_runtime.revoked_root,
                )?,
                current_history_view_id: prepared_runtime.current_history_view_id,
                current_history_commitment: prepared_runtime.current_history_commitment,
                current_history_authority_extension: prepared_runtime
                    .current_history_authority_extension,
                current_global_history_attestation_bytes: prepared_runtime
                    .current_global_history_attestation_bytes,
                current_public_tree: None,
                bootstrap_history_commitment: prepared_runtime.current_history_commitment,
                bootstrap_predecessor_kem_tree_hash_after: prepared_runtime
                    .current_predecessor_kem_tree_hash_after,
                bootstrap_join_records: prepared_runtime.current_join_records,
                bootstrap_revoked_leaf_indices: prepared_runtime.current_revoked_leaf_indices,
                bootstrap_join_finalize_auth_token: prepared_runtime.join_finalize_auth_token,
                k_barrier: Zeroizing::new([0u8; 32]),
                kem_tree_hash_after: prepared_runtime.kem_tree_hash_after,
                bootstrap_current_barrier_update: prepared_runtime.current_barrier_update,
                max_barrier_update_bytes: prepared_runtime.max_barrier_update_bytes,
                n_max: prepared_runtime.barrier_n_max,
                cover_leaf_index: prepared_runtime.cover_leaf_index,
                dk_leaf: Zeroizing::new(join_runtime.barrier_leaf_secret_key),
                pkhash_leaf: join_runtime.barrier_leaf_pkhash,
                barrier_recovery_pending: true,
                current_barrier_full_verified: false,
                ..BarrierSecretState::default()
            },
        };

        (session, requires_bootstrap_finalize)
    };

    if requires_bootstrap_finalize {
        session = match finalize_bootstrapped_room_join(session.clone()).await {
            Ok(finalized) => finalized,
            Err(err) => {
                warn!("initial room setup after bootstrap join failed: {err:#}");
                reload_join_finalization_session(&session, err, "complete initial room setup")?
            }
        };
    } else if session.barrier_state.barrier_recovery_pending {
        session = match finalize_pending_join(session.clone()).await {
            Ok(finalized) => finalized,
            Err(err) => {
                warn!("post-join barrier finalization failed: {err:#}");
                reload_join_finalization_session(
                    &session,
                    err,
                    "complete join barrier finalization",
                )?
            }
        };
    }

    Ok(session)
}
