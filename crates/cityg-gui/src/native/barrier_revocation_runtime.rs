use std::{future::Future, pin::Pin};

use super::epoch_sync::perform_epoch_sync;
use super::*;
use crate::barrier_shared::{to_core_history_commitment, to_core_join_snapshot_records};
use cityg_client::barrier_merge_bundle::{
    BarrierMergeBundleInputs as CoreBarrierMergeBundleInputs,
    build_barrier_merge_bundle as build_barrier_merge_bundle_core,
};
use cityg_client::barrier_snapshot_prepare::{
    BarrierSnapshotArtifactsInput as CoreBarrierSnapshotArtifactsInput,
    BarrierSnapshotTicketFields as CoreBarrierSnapshotTicketFields,
    derive_barrier_snapshot_ticket_fields as derive_barrier_snapshot_ticket_fields_core,
    derive_barrier_snapshot_witness_selection as derive_barrier_snapshot_witness_selection_core,
    prepare_barrier_snapshot_artifacts as prepare_barrier_snapshot_artifacts_core,
};

pub(super) fn is_fs_forward_jump_group_http_error(
    freeze_code: Option<u32>,
    freeze_reason: Option<&str>,
) -> bool {
    freeze_code == Some(9476) || freeze_reason == Some("fs_forward_jump_group")
}

pub(super) fn publish_revocation_merge_from_ticket(
    request: LeaveRequest,
    ticket: MergeTicket,
    operation_label: &'static str,
    revocation_target_leaf_id: Option<[u8; 32]>,
) -> Pin<Box<dyn Future<Output = Result<PublishedBarrierMerge>> + Send>> {
    Box::pin(publish_revocation_merge_from_ticket_inner(
        request,
        ticket,
        operation_label,
        revocation_target_leaf_id,
    ))
}

async fn publish_revocation_merge_from_ticket_inner(
    request: LeaveRequest,
    ticket: MergeTicket,
    operation_label: &'static str,
    revocation_target_leaf_id: Option<[u8; 32]>,
) -> Result<PublishedBarrierMerge> {
    let persist_request = request.clone();
    let LeaveRequest {
        server_url,
        room_id,
        gid,
        leaf_id,
        barrier_version: local_barrier_version,
        kem_tree_hash_after: local_kem_tree_hash_after,
        current_history_commitment: local_current_history_commitment,
        current_history_authority_extension: local_current_history_authority_extension,
        forward_state,
        pop_public_key,
        pop_secret_key,
        vrf_secret_key,
        vrf_public_key,
        fs_ec,
        fs_epoch_commit,
        fs_dev_prev_commit,
        max_barrier_update_bytes: stored_max_barrier_update_bytes,
        barrier_recovery_pending,
        current_barrier_full_verified,
        ..
    } = request;

    ensure_full_barrier_verification_for_origin(
        barrier_recovery_pending,
        current_barrier_full_verified,
    )?;

    let MergeTicket {
        we_epoch_id: _,
        parities: raw_parities,
        witness_cbor,
        srx_cbor,
        proof_mode,
        vrf_id,
        policy_version,
        cat,
        parent_root,
        join_delta_root,
        revoked_since_root,
        revoked_root,
        tswe_salt_hash,
        pox_r_commit,
        kbroad_public,
        msphf_crs_id,
        msphf_params_id,
        fs_policy_version,
        fs_epoch_base_ts,
        fs_forward_leap_policy,
        last_accepted_ec,
        kbroad_generation: _,
        barrier_version,
        cover_leaf_index: revoked_cover_leaf_index,
        kem_tree_hash_after,
        current_history_commitment: ticket_history_commitment,
        history_authority_extension: ticket_history_authority_extension,
        history_authority,
        current_global_history_attestation_bytes,
        merge_ticket_artifact_bytes,
        deployment_profile_manifest_bytes,
        n_max,
        max_barrier_update_bytes,
        ..
    } = ticket;

    ensure_supported_attested_current_state_extension(
        operation_label,
        ticket_history_authority_extension,
        current_global_history_attestation_bytes.as_slice(),
    )?;

    ensure_non_regressing_authenticated_current_state(
        local_barrier_version,
        &local_kem_tree_hash_after,
        local_current_history_commitment.as_ref(),
        local_current_history_authority_extension,
        barrier_version,
        &bytes32("kem_tree_hash_after", &kem_tree_hash_after)?,
        &ticket_history_commitment,
        ticket_history_authority_extension,
        operation_label,
    )?;

    let srx_inputs = if srx_cbor.is_empty() {
        return Err(anyhow!(
            "{operation_label} merge ticket missing SRX payload"
        ));
    } else {
        SrxInputsOwned::from_cbor(&srx_cbor)
            .context("unable to decode SRX bundle from server")?
            .into_srx_inputs()
    };

    let client = new_api_client(&server_url);
    let mut header = BTreeMap::new();
    header.insert(hdr::HDR_KBROAD_ALG, Value::Text("ml-kem-768".to_string()));
    header.insert(hdr::HDR_KBROAD_PUB, Value::Bytes(kbroad_public.clone()));

    let pop_secret =
        Box::new(dilithium5::SecretKey::from_bytes(&pop_secret_key).context("invalid POP key")?);

    let witness_bytes = if witness_cbor.is_empty() {
        None
    } else {
        Some(witness_cbor.as_slice())
    };

    let parities = hydrate_parities(&raw_parities, fs_ec, fs_epoch_commit, fs_dev_prev_commit);
    let CoreBarrierSnapshotTicketFields {
        cat: cat_arr,
        pox_r_commit: pox_r_commit_arr,
        pivot,
        parent_root: parent_root_arr,
        join_delta_root: join_delta_root_arr,
        revoked_since_root: revoked_since_root_arr,
        revoked_root: revoked_root_arr,
        tswe_salt_hash: tswe_salt_hash_arr,
        revocation_roots_hash,
        committed_revocation_roots_hash,
    } = derive_barrier_snapshot_ticket_fields_core(
        &parities,
        &cat,
        &pox_r_commit,
        &parent_root,
        &join_delta_root,
        &revoked_since_root,
        &revoked_root,
        &tswe_salt_hash,
    )?;
    let snapshot_hash = bytes32("kem_tree_hash_after", &kem_tree_hash_after)?;
    let barrier_tree_response = client
        .barrier_fetch_public_tree(&room_id, &snapshot_hash)
        .await
        .context("fetch barrier public tree snapshot")?;
    let barrier_tree_snapshot = barrier_tree_response.tree;
    let barrier_n_max = validate_barrier_n_max(if n_max == 0 {
        DEFAULT_BARRIER_N_MAX
    } else {
        n_max
    })?;
    if revoked_cover_leaf_index >= barrier_n_max {
        return Err(anyhow!(
            "cover_leaf_index out of range for barrier tree: {revoked_cover_leaf_index} >= {barrier_n_max}"
        ));
    }
    if barrier_tree_snapshot.n_max != barrier_n_max {
        return Err(anyhow!(
            "barrier tree snapshot n_max mismatch: expected {barrier_n_max}, got {}",
            barrier_tree_snapshot.n_max
        ));
    }
    validate_barrier_tree_snapshot_auth(&snapshot_hash, barrier_n_max, &barrier_tree_snapshot)?;
    let join_resolution = client
        .barrier_resolve_joins_since(&room_id, barrier_version)
        .await
        .context("resolve barrier joins since previous version")?;
    let revoked_resolution = client
        .barrier_resolve_revoked_leaves(&room_id, &committed_revocation_roots_hash)
        .await
        .context("resolve committed barrier revoked leaf indices")?;
    let revoked_cover_leaf_index = u32::try_from(revoked_cover_leaf_index)
        .map_err(|_| anyhow!("cover_leaf_index out of range for barrier tree"))?;
    let post_revoked_witness_selection = derive_barrier_snapshot_witness_selection_core(
        0,
        u64::from(revoked_cover_leaf_index),
        revoked_resolution.leaf_indices.as_slice(),
        revocation_roots_hash,
        committed_revocation_roots_hash,
    )?;
    let ticket_max_barrier_update_bytes = max_barrier_update_bytes.max(1);
    if stored_max_barrier_update_bytes != 0
        && stored_max_barrier_update_bytes != ticket_max_barrier_update_bytes
    {
        return Err(anyhow!(
            "max_barrier_update_bytes mismatch: local={} server={}",
            stored_max_barrier_update_bytes,
            ticket_max_barrier_update_bytes
        ));
    }
    let updater_leaf = u64::from(revoked_cover_leaf_index);
    let ticket_history_commitment_core = to_core_history_commitment(&ticket_history_commitment);
    let snapshot_history_commitment_core =
        to_core_history_commitment(&barrier_tree_response.history_commitment);
    let joins_history_commitment_core =
        to_core_history_commitment(&join_resolution.history_commitment);
    let revoked_history_commitment_core =
        to_core_history_commitment(&revoked_resolution.history_commitment);
    let join_records_core = to_core_join_snapshot_records(join_resolution.records.as_slice());
    let prepared_snapshot =
        prepare_barrier_snapshot_artifacts_core(CoreBarrierSnapshotArtifactsInput {
            header,
            gid: &gid,
            leaf_id: &leaf_id,
            updater_leaf,
            barrier_version,
            barrier_update_reason: 0,
            barrier_n_max,
            max_barrier_update_bytes: ticket_max_barrier_update_bytes,
            ticket_history_commitment: &ticket_history_commitment_core,
            snapshot_history_commitment: &snapshot_history_commitment_core,
            joins_history_commitment: &joins_history_commitment_core,
            revoked_history_commitment: &revoked_history_commitment_core,
            current_global_history_attestation_bytes: current_global_history_attestation_bytes
                .as_slice(),
            snapshot_pk_entries: barrier_tree_snapshot.pk_entries.as_slice(),
            join_records: join_records_core.as_slice(),
            witness_revoked_leaf_indices: post_revoked_witness_selection
                .witness_revoked_leaf_indices
                .as_slice(),
            revocation_roots_hash,
            pop_secret_key: pop_secret_key.as_slice(),
        })?;
    let mut header = prepared_snapshot.header;
    let barrier_update =
        BarrierUpdateBuildResult::from_core(barrier_n_max, prepared_snapshot.barrier_update);
    let next_barrier_version = barrier_version.saturating_add(1);
    if !current_global_history_attestation_bytes.is_empty() {
        let history_authority = history_authority.as_ref().ok_or_else(|| {
            anyhow!(
                "{operation_label} merge ticket missing history_authority descriptor for full verification witness"
            )
        })?;
        let history_authority_extension = ticket_history_authority_extension.ok_or_else(|| {
            anyhow!(
                "{operation_label} merge ticket missing history_authority_extension for full verification witness"
            )
        })?;
        let full_verification_witness = client
            .barrier_issue_full_verification_witness(
                &room_id,
                &leaf_id,
                Some(&revocation_target_leaf_id.unwrap_or(leaf_id)),
                merge_ticket_artifact_bytes.as_slice(),
                0,
                barrier_update.raw_update.as_slice(),
                barrier_n_max,
                &ticket_history_commitment,
                history_authority_extension,
                history_authority,
                current_global_history_attestation_bytes.as_slice(),
                barrier_version,
                &snapshot_hash,
                barrier_version,
                join_resolution.records.as_slice(),
                &revocation_roots_hash,
                post_revoked_witness_selection
                    .witness_revoked_leaf_indices
                    .as_slice(),
                deployment_profile_manifest_bytes.as_slice(),
            )
            .await
            .context("issue full verification witness for leave/expel merge")?;
        header.insert(
            hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS,
            Value::Bytes(full_verification_witness),
        );
    }
    let mut pending_barrier_state = BarrierPendingState {
        barrier_version: next_barrier_version,
        we_epoch_id: [0u8; 32],
        fs_ec,
        next_forward_fs_ec: 0,
        next_forward_fs_dev_commit: [0u8; 32],
        next_forward_last_weid: [0u8; 32],
        revocation_roots_hash,
        kem_tree_hash_after: barrier_update.kem_tree_hash_after,
        k_barrier_new: barrier_update.k_barrier_new.clone(),
        k_fs_after_pcs: None,
        barrier_update_reason: Some(0),
        barrier_update_digest: barrier_update.barrier_update_digest,
        on_path_key_material: barrier_update.on_path_key_material.clone(),
        activation_source: Some(BarrierPendingActivationSource {
            barrier_version,
            barrier_roots_hash: committed_revocation_roots_hash,
            kem_tree_hash_after: snapshot_hash,
            current_history_commitment: Some(ticket_history_commitment),
            current_history_authority_extension: ticket_history_authority_extension,
            current_global_history_attestation_bytes: current_global_history_attestation_bytes
                .clone(),
            fs_ec,
            fs_dev_prev_commit,
        }),
    };

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
        barrier_version: next_barrier_version,
        fs_join: FsJoinInputs {
            fs_ec,
            fs_epoch_commit,
            fs_dev_prev_commit,
        },
        fs_merge: FsMergeInputs::default(),
    };

    let parts = AnchorInstanceParts {
        gid: &gid,
        cat: cat_arr.as_slice(),
        tswe_salt_hash: tswe_salt_hash_arr.as_slice(),
        parent_root: parent_root_arr.as_slice(),
        join_delta_root: join_delta_root_arr.as_slice(),
        revoked_since_prev_root: revoked_since_root_arr.as_slice(),
        revoked_root: revoked_root_arr.as_slice(),
        pox_r_commit: Some(pox_r_commit_arr.as_slice()),
    };

    let built = build_barrier_merge_bundle_core(CoreBarrierMergeBundleInputs {
        header,
        parts,
        params,
        forward_state,
        parities: &parities,
        witness_bytes,
        pivot: &pivot,
        gid: &gid,
        cat: &cat_arr,
        parent_root: &parent_root_arr,
        current_k_fs: None,
        next_barrier_version,
        barrier_key: &barrier_update.k_barrier_new,
        barrier_update_reason: 1,
        disable_autonomic_evolve: false,
    })
    .with_context(|| format!("failed to build {operation_label} merge bundle"))?;

    let next_forward = built.forward_state_after.snapshot();
    pending_barrier_state.we_epoch_id = built.bundle.we_epoch_id;
    pending_barrier_state.fs_ec = built.observed_fs_ec;
    pending_barrier_state.next_forward_fs_ec = next_forward.fs_ec;
    pending_barrier_state.next_forward_fs_dev_commit = next_forward.fs_dev_commit;
    pending_barrier_state.next_forward_last_weid = next_forward.last_weid;
    let bundle = built.bundle;
    let forward_state = built.forward_state_after;

    persist_pending_barrier_state_before_publish(&persist_request, pending_barrier_state.clone())?;

    match client.refresh_pivot(&bundle).await {
        Ok(_) => {}
        Err(ApiClientError::HttpStatus {
            status, message, ..
        }) if is_refresh_pivot_conflict(status.as_u16(), &message) => {
            debug!(status = status.as_u16(), "refresh pivot skipped: {message}");
        }
        Err(err) => return Err(err).context("refresh pivot parity"),
    }

    client
        .accept_epoch_bundle(&bundle)
        .await
        .with_context(|| format!("server rejected {operation_label} merge bundle"))?;

    Ok(PublishedBarrierMerge {
        bundle,
        pending_barrier_state,
        pre_publish_barrier_version: barrier_version,
        pre_publish_barrier_roots_hash: committed_revocation_roots_hash,
        pre_publish_kem_tree_hash_after: snapshot_hash,
        pre_publish_current_history_commitment: ticket_history_commitment,
        pre_publish_current_history_authority_extension: ticket_history_authority_extension,
        pre_publish_current_global_history_attestation_bytes:
            current_global_history_attestation_bytes,
        forward_state_after: forward_state,
        fs_forward_leap_policy: FsForwardLeapPolicy {
            h: fs_forward_leap_policy.h,
            checkpoint_interval: fs_forward_leap_policy.checkpoint_interval,
            slack_anchor: fs_forward_leap_policy.slack_anchor,
            slack_first_device: fs_forward_leap_policy.slack_first_device,
            slack_device: fs_forward_leap_policy.slack_device,
        },
        last_accepted_ec,
        current_public_tree: barrier_update.snapshot_post.clone(),
    })
}

pub(super) fn perform_leave(
    request: LeaveRequest,
) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
    Box::pin(perform_leave_inner(request))
}

async fn perform_leave_inner(request: LeaveRequest) -> Result<()> {
    ensure_full_barrier_verification_for_origin(
        request.barrier_recovery_pending,
        request.current_barrier_full_verified,
    )?;

    let client = new_api_client(&request.server_url);
    let room_id = request.room_id.clone();
    let leaf_id = request.leaf_id;
    let mut retry_attempt = 0u32;
    let ticket = loop {
        match client.merge_ticket(&room_id, &leaf_id).await {
            Ok(ticket) => break ticket,
            Err(err) => {
                if let ApiClientError::HttpStatus {
                    status,
                    message,
                    freeze_code,
                    ..
                } = &err
                    && should_retry_ticket_http_error(status.as_u16(), message, *freeze_code)
                    && retry_attempt < TICKET_RETRY_MAX_ATTEMPTS
                {
                    let delay = ticket_retry_delay(retry_attempt);
                    retry_attempt = retry_attempt.saturating_add(1);
                    warn!(
                        attempt = retry_attempt,
                        delay_ms = delay.as_millis() as u64,
                        status = status.as_u16(),
                        message = %message,
                        "merge_ticket race/concurrency rejection; retrying"
                    );
                    sleep(delay).await;
                    continue;
                }

                return Err(err).context("failed to obtain leave merge ticket");
            }
        }
    };

    let leave_leaf_id = request.leaf_id;
    publish_revocation_merge_from_ticket(request, ticket, "leave", Some(leave_leaf_id)).await?;
    Ok(())
}

pub(super) fn perform_room_admin_expel(
    session: AppSession,
    target_leaf_id: [u8; 32],
) -> Pin<Box<dyn Future<Output = Result<AppSession>> + Send>> {
    Box::pin(perform_room_admin_expel_inner(session, target_leaf_id))
}

async fn perform_room_admin_expel_inner(
    session: AppSession,
    target_leaf_id: [u8; 32],
) -> Result<AppSession> {
    if session.leaf_id == target_leaf_id {
        return Err(anyhow!(
            "cannot expel the local device; use Leave room for controlled self-revocation"
        ));
    }

    let request = LeaveRequest::from_session(&session);
    ensure_full_barrier_verification_for_origin(
        request.barrier_recovery_pending,
        request.current_barrier_full_verified,
    )?;
    let client = new_api_client(&request.server_url);
    let room_id = request.room_id.clone();
    let author_leaf_id = request.leaf_id;
    let admin_proof = build_room_admin_leaf_pair_proof(
        RoomAdminOperation::ExpelMember,
        &room_id,
        &author_leaf_id,
        &target_leaf_id,
        &request.pop_public_key,
        &request.pop_secret_key,
    )
    .context("build expel member room admin proof")?;

    let mut retry_attempt = 0u32;
    let ticket = loop {
        match client
            .expel_member_ticket(
                &room_id,
                &author_leaf_id,
                &target_leaf_id,
                admin_proof.clone(),
            )
            .await
        {
            Ok(ticket) => break ticket,
            Err(err) => {
                if let ApiClientError::HttpStatus {
                    status,
                    message,
                    freeze_code,
                    ..
                } = &err
                    && should_retry_ticket_http_error(status.as_u16(), message, *freeze_code)
                    && retry_attempt < TICKET_RETRY_MAX_ATTEMPTS
                {
                    let delay = ticket_retry_delay(retry_attempt);
                    retry_attempt = retry_attempt.saturating_add(1);
                    warn!(
                        attempt = retry_attempt,
                        delay_ms = delay.as_millis() as u64,
                        status = status.as_u16(),
                        message = %message,
                        "expel_member_ticket race/concurrency rejection; retrying"
                    );
                    sleep(delay).await;
                    continue;
                }

                return Err(err).context("failed to obtain expel merge ticket");
            }
        }
    };

    let published =
        publish_revocation_merge_from_ticket(request, ticket, "expel", Some(target_leaf_id))
            .await?;
    let mut updated = session.clone();
    match apply_local_published_barrier_merge(&mut updated, published) {
        Ok(()) => {
            persist_activated_joined_session(&updated)
                .context("persist room session after expel")?;
            Ok(updated)
        }
        Err(local_err) => {
            warn!(
                "local activation of expel merge failed; falling back to epoch sync: {local_err:#}"
            );
            let persisted = load_session_at(&session.server_url, &session.room_id)?
                .ok_or_else(|| anyhow!("persisted session missing after expel merge publish"))?;
            let mut sync = perform_epoch_sync(persisted)
                .await
                .context("sync room after expel merge")?;
            if sync.session.barrier_state.barrier_recovery_pending {
                return Err(anyhow!("barrier recovery still pending after expel merge"));
            }
            sync.session.barrier_state.pending = None;
            persist_activated_joined_session(&sync.session)
                .context("persist room session after expel merge sync")?;
            Ok(sync.session)
        }
    }
}
