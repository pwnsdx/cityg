use super::*;
use cityg_client::barrier_orchestration::{
    BarrierOrchestrationInputs, prepare_barrier_orchestration,
};
use cityg_client::join_bundle::{JoinEpochBundleInputs, build_join_epoch_bundle};

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
                    let provisioning_public = if let Some(public) = generated_kbroad_public.as_ref()
                    {
                        public.clone()
                    } else {
                        let public = generate_kbroad_keypair().0;
                        generated_kbroad_public = Some(public.clone());
                        public
                    };
                    let admin_proof = build_room_admin_proof(
                        RoomAdminOperation::Bootstrap,
                        &room_id,
                        &provisioning_public,
                        &pop_public_key,
                        &pop_secret_key,
                    )
                    .context("build room bootstrap admin proof")?;

                    match client
                        .bootstrap_room_as_admin(&room_id, &provisioning_public, admin_proof)
                        .await
                    {
                        Ok(_) => continue,
                        Err(ApiClientError::HttpStatus {
                            status: bootstrap_status,
                            message: bootstrap_message,
                            ..
                        }) if bootstrap_status.is_server_error()
                            && bootstrap_message.contains("kbroad key already registered") =>
                        {
                            continue;
                        }
                        Err(err) => {
                            return Err(anyhow!("failed to bootstrap room KBROAD key: {}", err));
                        }
                    }
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
        let cityg_api_client::PreparedRuntimeJoinTicket {
            gid,
            cat,
            parent_root,
            join_delta_root,
            revoked_since_root,
            revoked_root,
            tswe_salt_hash,
            leaf_id,
            pox_r_commit,
            kbroad_public,
            bootstrap_public,
            witness_bytes,
            srx_inputs,
            msphf_crs_id,
            msphf_params_id,
            proof_mode,
            vrf_id,
            policy_version,
            fs_policy_version,
            fs_epoch_base_ts,
            fs_forward_leap_policy,
            barrier_version,
            current_history_view_id,
            current_history_commitment,
            current_history_authority_extension,
            current_global_history_attestation_bytes,
            join_finalize_auth_token,
            barrier_n_max,
            cover_leaf_index,
            max_barrier_update_bytes,
            kem_tree_hash_after,
            current_predecessor_kem_tree_hash_after,
            current_join_records,
            current_revoked_leaf_indices,
            current_barrier_update,
            last_accepted_ec,
        } = cityg_api_client::prepare_runtime_join_ticket(&ticket).map_err(anyhow::Error::from)?;

        let witness_bytes = if let Some(witness_bytes) = witness_bytes {
            witness_bytes
        } else {
            return Err(anyhow!("server did not include canonical witness"));
        };

        let mut header_map = BTreeMap::new();
        header_map.insert(hdr::HDR_KBROAD_ALG, Value::Text("ml-kem-768".to_string()));
        header_map.insert(hdr::HDR_KBROAD_PUB, Value::Bytes(kbroad_public.clone()));
        let (barrier_leaf_ek_bytes, barrier_leaf_dk_bytes, barrier_pkhash_leaf) =
            cityg_client::barrier_crypto::generate_barrier_leaf_keypair()?;
        header_map.insert(
            hdr::HDR_BARRIER_LEAF_PK,
            Value::Bytes(barrier_leaf_ek_bytes.clone()),
        );

        let mut k_fs = [0u8; 32];
        rand::rng().fill(&mut k_fs);
        let mut fs_state = ForwardSecrecyState::new(k_fs);
        let pop_secret = Box::new(
            dilithium5::SecretKey::from_bytes(&room_identity.pop_secret_key)
                .context("invalid POP key")?,
        );

        let (msg_sign_public_key, msg_sign_secret_key) =
            cityg_client::message_auth::generate_message_signing_keypair();

        let (vrf_secret_key, vrf_public_key) =
            generate_vrf_keys().context("generate runtime VRF keypair")?;

        let prepared_orchestration = prepare_barrier_orchestration(BarrierOrchestrationInputs {
            gid: &gid,
            cat: &cat,
            tswe_salt_hash: &tswe_salt_hash,
            parent_root: &parent_root,
            join_delta_root: &join_delta_root,
            revoked_since_root: &revoked_since_root,
            revoked_root: &revoked_root,
            pox_r_commit: &pox_r_commit,
            msphf_crs_id: msphf_crs_id.as_str(),
            msphf_params_id: msphf_params_id.as_str(),
            srx: Some(srx_inputs.into_srx_inputs()),
            pop_public_key: room_identity.pop_public_key.as_slice(),
            pop_secret_key: pop_secret.as_ref(),
            proof_mode: proof_mode.as_str(),
            vrf_id: vrf_id.as_str(),
            policy_version: policy_version.as_str(),
            vrf_secret_key: vrf_secret_key.as_slice(),
            vrf_public_key: vrf_public_key.as_slice(),
            fs_policy_version: fs_policy_version.as_str(),
            fs_epoch_base_ts,
            barrier_version,
            fs_join: FsJoinInputs::default(),
        });

        let build_join_bundle = |fs_state: &mut ForwardSecrecyState,
                                 disable_autonomic_evolve: bool|
         -> Result<ClientEpochBundle> {
            build_join_epoch_bundle(JoinEpochBundleInputs {
                header: header_map.clone(),
                parts: prepared_orchestration.parts.clone(),
                params: prepared_orchestration.params.clone(),
                fs_state,
                witness_bytes: Some(&witness_bytes),
                disable_autonomic_evolve,
            })
            .context("failed to build join anchor")
        };

        let pristine_fs_state = fs_state.clone();
        let mut bundle = build_join_bundle(&mut fs_state, false)?;

        let capss_witness_bytes = encode_capss_witness(&bundle.capss_witness)?;

        if parent_root == [0u8; 32] && !bootstrap_public.is_empty() {
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
        let fs_ec: u64 = bundle
            .header_map
            .get(&hdr::HDR_FS_EC)
            .and_then(Value::as_integer)
            .ok_or_else(|| anyhow!("join bundle missing fs_ec"))?
            .try_into()
            .map_err(|_| anyhow!("fs_ec out of range"))?;
        let fs_epoch_commit: [u8; 32] = bundle
            .header_map
            .get(&hdr::HDR_FS_EPOCH_COMMIT)
            .and_then(Value::as_bytes)
            .map(|bytes| bytes.as_slice())
            .ok_or_else(|| anyhow!("join bundle missing fs_epoch_commit"))?
            .try_into()
            .map_err(|_| anyhow!("fs_epoch_commit length"))?;
        let fs_dev_prev_commit: [u8; 32] = bundle
            .header_map
            .get(&hdr::HDR_FS_DEV_COMMIT)
            .or_else(|| bundle.header_map.get(&hdr::HDR_FS_DEV_PREV_COMMIT))
            .and_then(Value::as_bytes)
            .map(|bytes| bytes.as_slice())
            .ok_or_else(|| anyhow!("join bundle missing fs_dev commit"))?
            .try_into()
            .map_err(|_| anyhow!("fs_dev commit length"))?;
        let regular_fingerprint = Some(bundle.hp_binding.seed_ctx_hash);
        let fs_fingerprint = compute_fs_fingerprint_from_header(&bundle.header_map).or_else(|| {
            derive_fs_fingerprint_from_fields(
                fs_policy_version.as_str(),
                fs_ec,
                &fs_epoch_commit,
                fs_epoch_base_ts,
            )
        });
        let requires_bootstrap_finalize = barrier_version == 0 && parent_root == [0u8; 32];
        let session = AppSession {
            server_url,
            room_id,
            alias,
            gid,
            cat,
            leaf_id,
            parent_root,
            join_delta_root,
            revoked_since_root,
            revoked_root,
            regular_fingerprint,
            fs_fingerprint,
            tswe_salt_hash,
            pox_r_commit,
            we_epoch_id: bundle.we_epoch_id,
            xk_hash: bundle.hp_binding.xk_hash,
            epoch_key: bundle.epoch_key,
            forward_state,
            fs_ec,
            fs_epoch_commit,
            fs_dev_prev_commit,
            fs_epoch_created_at: SystemTime::now(),
            fs_epoch_rotation_interval_secs: 300,
            pop_public_key: room_identity.pop_public_key.clone(),
            pop_secret_key: room_identity.pop_secret_key.clone(),
            msg_sign_public_key,
            msg_sign_secret_key,
            vrf_secret_key,
            vrf_public_key,
            kbroad_public,
            bootstrap_public,
            proof_mode,
            vrf_id,
            policy_version,
            msphf_crs_id,
            msphf_params_id,
            fs_policy_version,
            fs_epoch_base_ts,
            fs_forward_leap_policy: FsForwardLeapPolicy {
                h: fs_forward_leap_policy.h,
                checkpoint_interval: fs_forward_leap_policy.checkpoint_interval,
                slack_anchor: fs_forward_leap_policy.slack_anchor,
                slack_first_device: fs_forward_leap_policy.slack_first_device,
                slack_device: fs_forward_leap_policy.slack_device,
            },
            last_accepted_ec: last_accepted_ec.max(fs_ec),
            last_fetch_timestamp_ms: None,
            msg_replay_state: MsgReplayState::default(),
            capss_witness: capss_witness_bytes,
            barrier_state: BarrierSecretState {
                barrier_initialized: true,
                barrier_version,
                barrier_roots_hash: compute_revocation_roots_hash(
                    &revoked_since_root,
                    &revoked_root,
                )?,
                current_history_view_id,
                current_history_commitment,
                current_history_authority_extension,
                current_global_history_attestation_bytes,
                current_public_tree: None,
                bootstrap_history_commitment: current_history_commitment,
                bootstrap_predecessor_kem_tree_hash_after: current_predecessor_kem_tree_hash_after,
                bootstrap_join_records: current_join_records,
                bootstrap_revoked_leaf_indices: current_revoked_leaf_indices,
                bootstrap_join_finalize_auth_token: join_finalize_auth_token,
                k_barrier: Zeroizing::new([0u8; 32]),
                kem_tree_hash_after,
                bootstrap_current_barrier_update: current_barrier_update,
                max_barrier_update_bytes,
                n_max: barrier_n_max,
                cover_leaf_index,
                dk_leaf: Zeroizing::new(barrier_leaf_dk_bytes),
                pkhash_leaf: barrier_pkhash_leaf,
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
