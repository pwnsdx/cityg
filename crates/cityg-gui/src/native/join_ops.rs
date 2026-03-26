use super::*;

fn is_fs_forward_jump_group_http_error(
    freeze_code: Option<u32>,
    freeze_reason: Option<&str>,
) -> bool {
    freeze_code == Some(9476) || freeze_reason == Some("fs_forward_jump_group")
}

pub(super) async fn perform_join(params: JoinParams) -> Result<AppSession> {
    let JoinParams {
        server_url,
        room_id,
        alias,
    } = params;

    if server_url.is_empty() {
        return Err(anyhow!("server URL must not be empty"));
    }
    if room_id.is_empty() {
        return Err(anyhow!("room id must not be empty"));
    }
    if alias.is_empty() {
        return Err(anyhow!("alias must not be empty"));
    }

    let room_identity = load_or_create_room_identity(&server_url, &room_id)
        .context("load or create persistent room identity")?;
    let pop_public_key = room_identity.pop_public_key.clone();
    let pop_secret_key = room_identity.pop_secret_key.clone();
    let identity_binding = Some(build_identity_binding(
        &alias,
        &pop_public_key,
        &pop_secret_key,
    )?);

    let mut generated_kbroad_public: Option<Vec<u8>> = None;
    let mut bootstrap_attempted = false;
    let mut retry_attempt = 0u32;

    let client = new_api_client(&server_url);
    let ticket = loop {
        match client
            .join_ticket(&room_id, &alias, identity_binding.clone())
            .await
        {
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

    let gid = bytes32("gid", &ticket.gid)?;
    let cat = bytes32("cat", &ticket.cat)?;
    let parent_root = bytes32("parent_root", &ticket.parent_root)?;
    let revoked_root = bytes32("revoked_root", &ticket.revoked_root)?;
    let revoked_since_root = bytes32("revoked_since_root", &ticket.revoked_since_root)?;
    let tswe_salt_hash = bytes32("tswe_salt_hash", &ticket.tswe_salt_hash)?;
    let join_delta_root = bytes32("join_delta_root", &ticket.join_delta_root)?;
    let leaf_id = bytes32("leaf_id", &ticket.leaf_id)?;
    let pox_r_commit = bytes32("pox_r_commit", &ticket.pox_r_commit)?;
    let kbroad_public = if ticket.kbroad_public.is_empty() {
        return Err(anyhow!("server returned empty KBROAD public key"));
    } else {
        ticket.kbroad_public.clone()
    };
    let bootstrap_public = ticket.bootstrap_public.clone();

    let witness_bytes = if ticket.witness_cbor.is_empty() {
        return Err(anyhow!("server did not include canonical witness"));
    } else {
        ticket.witness_cbor
    };

    let srx_inputs = SrxInputsOwned::from_cbor(&ticket.srx_cbor)
        .context("unable to decode SRX bundle from server")?
        .into_srx_inputs();

    let mut header_map = BTreeMap::new();
    header_map.insert(hdr::HDR_KBROAD_ALG, Value::Text("ml-kem-768".to_string()));
    header_map.insert(hdr::HDR_KBROAD_PUB, Value::Bytes(kbroad_public.clone()));
    let (barrier_leaf_ek, barrier_leaf_dk) = kyber768::keypair();
    let barrier_leaf_ek_bytes = KemPublicKey::as_bytes(&barrier_leaf_ek).to_vec();
    let barrier_leaf_dk_bytes = KemSecretKey::as_bytes(&barrier_leaf_dk).to_vec();
    let barrier_pkhash_leaf = compute_barrier_pkhash(barrier_leaf_ek_bytes.as_slice())?;
    header_map.insert(
        hdr::HDR_BARRIER_LEAF_PK,
        Value::Bytes(barrier_leaf_ek_bytes.clone()),
    );

    let mut k_fs = [0u8; 32];
    rand::rng().fill(&mut k_fs);
    let mut fs_state = ForwardSecrecyState::new(k_fs);
    let pop_secret =
        Box::new(dilithium5::SecretKey::from_bytes(&pop_secret_key).context("invalid POP key")?);

    // Room-scoped PoP identity was loaded or created above.

    // Generate ML-DSA-65 (Dilithium3) keys for message authentication
    let (msg_sign_pk, msg_sign_sk) = dilithium3::keypair();
    let msg_sign_public_key = msg_sign_pk.as_bytes().to_vec();
    let msg_sign_secret_key = msg_sign_sk.as_bytes().to_vec();

    let (vrf_secret_key, vrf_public_key) =
        generate_vrf_keys().context("generate runtime VRF keypair")?;

    let msphf_crs_id = if ticket.msphf_crs_id.is_empty() {
        "rlwe-merkle/v1".to_string()
    } else {
        ticket.msphf_crs_id
    };
    let msphf_params_id = if ticket.msphf_params_id.is_empty() {
        "rlwe-params/mock".to_string()
    } else {
        ticket.msphf_params_id
    };
    let proof_mode = if ticket.proof_mode.is_empty() {
        "lin+zkvrf".to_string()
    } else {
        ticket.proof_mode
    };
    let vrf_id = if ticket.vrf_id.is_empty() {
        "lb-vrf/v1".to_string()
    } else {
        ticket.vrf_id
    };
    let policy_version = if ticket.policy_version.is_empty() {
        "0".to_string()
    } else {
        ticket.policy_version
    };
    let fs_policy_version = if ticket.fs_policy_version.is_empty() {
        "7".to_string()
    } else {
        ticket.fs_policy_version
    };
    let fs_epoch_base_ts = ticket.fs_epoch_base_ts;
    let kem_tree_hash_after = bytes32("kem_tree_hash_after", &ticket.kem_tree_hash_after)?;
    let current_predecessor_kem_tree_hash_after =
        if ticket.current_predecessor_kem_tree_hash_after.is_empty() {
            [0u8; 32]
        } else {
            bytes32(
                "current_predecessor_kem_tree_hash_after",
                &ticket.current_predecessor_kem_tree_hash_after,
            )?
        };
    let current_history_commitment = ticket
        .current_history_commitment
        .clone()
        .map(|commitment| -> Result<HistoryCommitment> {
            let history_view_id = bytes32("current_history_view_id", &commitment.history_view_id)?;
            let expected_view_id =
                bytes32("current_history_view_id", &ticket.current_history_view_id)?;
            if history_view_id != expected_view_id {
                return Err(anyhow!(
                    "join ticket current_history_commitment.history_view_id mismatch"
                ));
            }
            Ok(HistoryCommitment {
                history_view_id,
                history_commitment_id: bytes32(
                    "current_history_commitment_id",
                    &commitment.history_commitment_id,
                )?,
                prev_history_commitment_id: bytes32(
                    "current_history_commitment.prev_history_commitment_id",
                    &commitment.prev_history_commitment_id,
                )?,
                history_seq: commitment.history_seq,
            })
        })
        .transpose()?;
    let join_finalize_auth_token =
        bytes32("join_finalize_auth_token", &ticket.join_finalize_auth_token)?;
    let barrier_n_max = validate_barrier_n_max(if ticket.n_max == 0 {
        DEFAULT_BARRIER_N_MAX
    } else {
        ticket.n_max
    })?;
    if ticket.cover_leaf_index >= barrier_n_max {
        return Err(anyhow!(
            "cover_leaf_index out of range for barrier tree: {} >= {}",
            ticket.cover_leaf_index,
            barrier_n_max
        ));
    }

    let params = OrchestrationParams {
        msphf_crs_id: msphf_crs_id.as_str(),
        params_id: msphf_params_id.as_str(),
        srx: Some(srx_inputs),
        srx_mode: SrxMode::Complete,
        pop_keys: Some(PopKeypair {
            algorithm: "ML-DSA-65",
            public_key: pop_public_key.as_slice(),
            secret_key: pop_secret.as_ref(),
        }),
        leaf_id_mode: LeafIdMode::PerGroup,
        proof_mode: proof_mode.as_str(),
        vrf_id: vrf_id.as_str(),
        policy_version: policy_version.as_str(),
        vrf_secret_key: Some(vrf_secret_key.as_slice()),
        vrf_public_key: Some(vrf_public_key.as_slice()),
        fs_policy_version: fs_policy_version.as_str(),
        fs_epoch_base_ts,
        barrier_version: ticket.barrier_version,
        fs_join: FsJoinInputs::default(),
        fs_merge: FsMergeInputs::default(),
    };

    let parts = AnchorInstanceParts {
        gid: &gid,
        cat: &cat,
        tswe_salt_hash: &tswe_salt_hash,
        parent_root: &parent_root,
        join_delta_root: &join_delta_root,
        revoked_since_prev_root: &revoked_since_root,
        revoked_root: &revoked_root,
        pox_r_commit: Some(&pox_r_commit),
    };

    let build_join_bundle = |fs_state: &mut ForwardSecrecyState,
                             disable_autonomic_evolve: bool|
     -> Result<ClientEpochBundle> {
        if disable_autonomic_evolve {
            CityGClient::generate_epoch_without_evolve(
                header_map.clone(),
                parts.clone(),
                params.clone(),
                fs_state,
                Some(&witness_bytes),
            )
        } else {
            CityGClient::generate_epoch(
                header_map.clone(),
                parts.clone(),
                params.clone(),
                fs_state,
                Some(&witness_bytes),
            )
        }
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
        }) if is_fs_forward_jump_group_http_error(freeze_code, freeze_reason.as_deref()) => {
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
    let mut session = AppSession {
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
        pop_public_key,
        pop_secret_key,
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
        last_fetch_timestamp_ms: None,
        msg_replay_state: MsgReplayState::default(),
        capss_witness: capss_witness_bytes,
        barrier_state: BarrierSecretState {
            barrier_initialized: true,
            barrier_version: ticket.barrier_version,
            barrier_roots_hash: compute_revocation_roots_hash(&revoked_since_root, &revoked_root)?,
            current_history_view_id: bytes32(
                "current_history_view_id",
                &ticket.current_history_view_id,
            )?,
            bootstrap_history_commitment: current_history_commitment,
            bootstrap_predecessor_kem_tree_hash_after: current_predecessor_kem_tree_hash_after,
            bootstrap_join_records: ticket
                .current_join_records
                .iter()
                .map(|record| BarrierJoinRecord {
                    device_pk: record.device_pk.clone(),
                    leaf_index: record.leaf_index,
                    ek_leaf: record.ek_leaf.clone(),
                })
                .collect(),
            bootstrap_revoked_leaf_indices: ticket.current_revoked_leaf_indices.clone(),
            bootstrap_join_finalize_auth_token: join_finalize_auth_token,
            k_barrier: Zeroizing::new([0u8; 32]),
            kem_tree_hash_after,
            bootstrap_current_barrier_update: ticket.current_barrier_update.clone(),
            max_barrier_update_bytes: ticket.max_barrier_update_bytes.max(1),
            n_max: barrier_n_max,
            cover_leaf_index: ticket.cover_leaf_index,
            dk_leaf: Zeroizing::new(barrier_leaf_dk_bytes),
            pkhash_leaf: barrier_pkhash_leaf,
            barrier_recovery_pending: true,
            current_barrier_full_verified: false,
            ..BarrierSecretState::default()
        },
    };

    if ticket.barrier_version == 0 && parent_root == [0u8; 32] {
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
