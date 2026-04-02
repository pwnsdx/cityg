use std::{future::Future, pin::Pin};

use super::barrier_merge_publish_runtime::{
    BarrierMergePublishInputs, BarrierMergePublishPolicy, publish_barrier_merge,
};
use super::barrier_merge_snapshot_runtime::{
    BarrierSnapshotRuntimeRequest, prepare_barrier_snapshot_runtime,
};
use super::epoch_sync::perform_epoch_sync;
use super::*;
use cityg_client::barrier_orchestration::{
    BarrierOrchestrationInputs, prepare_barrier_orchestration,
};

pub(super) fn is_fs_forward_jump_group_http_error(
    freeze_code: Option<u32>,
    freeze_reason: Option<&str>,
) -> bool {
    freeze_code == Some(9476) || freeze_reason == Some("fs_forward_jump_group")
}

fn revocation_build_bundle_context(operation_label: &'static str) -> &'static str {
    match operation_label {
        "leave" => "failed to build leave merge bundle",
        "expel" => "failed to build expel merge bundle",
        _ => "failed to build revocation merge bundle",
    }
}

fn revocation_accept_bundle_context(operation_label: &'static str) -> &'static str {
    match operation_label {
        "leave" => "server rejected leave merge bundle",
        "expel" => "server rejected expel merge bundle",
        _ => "server rejected revocation merge bundle",
    }
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
    let prepared_runtime = ticket
        .prepare_runtime(
            fs_ec,
            fs_epoch_commit,
            fs_dev_prev_commit,
            stored_max_barrier_update_bytes,
        )
        .map_err(anyhow::Error::from)?;

    let MergeTicket {
        we_epoch_id: _,
        parities: _,
        witness_cbor: _,
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
        n_max: _,
        max_barrier_update_bytes: _,
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

    let witness_bytes = prepared_runtime.witness_bytes;
    let parities = prepared_runtime.parities;
    let snapshot_hash = prepared_runtime.snapshot_hash;
    let barrier_n_max = prepared_runtime.barrier_n_max;
    let ticket_max_barrier_update_bytes = prepared_runtime.max_barrier_update_bytes;
    let snapshot = prepare_barrier_snapshot_runtime(
        BarrierSnapshotRuntimeRequest {
            client: &client,
            room_id: &room_id,
            gid: &gid,
            leaf_id: &leaf_id,
            barrier_version,
            cover_leaf_index: revoked_cover_leaf_index,
            snapshot_hash,
            barrier_n_max,
            max_barrier_update_bytes: ticket_max_barrier_update_bytes,
            header,
            parities: &parities,
            cat: &cat,
            pox_r_commit: &pox_r_commit,
            parent_root: &parent_root,
            join_delta_root: &join_delta_root,
            revoked_since_root: &revoked_since_root,
            revoked_root: &revoked_root,
            tswe_salt_hash: &tswe_salt_hash,
            ticket_history_commitment: &ticket_history_commitment,
            ticket_history_authority_extension,
            history_authority: history_authority.clone(),
            current_global_history_attestation_bytes: current_global_history_attestation_bytes
                .as_slice(),
            merge_ticket_artifact_bytes: merge_ticket_artifact_bytes.as_slice(),
            deployment_profile_manifest_bytes: deployment_profile_manifest_bytes.as_slice(),
            pop_secret_key: pop_secret_key.as_slice(),
            full_verification_target_leaf_id: Some(revocation_target_leaf_id.unwrap_or(leaf_id)),
        },
        0,
        operation_label,
    )
    .await?;
    let super::barrier_merge_snapshot_runtime::PreparedBarrierMergeSnapshot {
        header,
        cat_arr,
        parent_root_arr,
        join_delta_root_arr,
        revoked_since_root_arr,
        revoked_root_arr,
        tswe_salt_hash_arr,
        pox_r_commit_arr,
        pivot,
        snapshot_hash,
        committed_revocation_roots_hash,
        revocation_roots_hash,
        barrier_update,
    } = snapshot;
    let next_barrier_version = barrier_version.saturating_add(1);
    let prepared_orchestration = prepare_barrier_orchestration(BarrierOrchestrationInputs {
        gid: &gid,
        cat: &cat_arr,
        tswe_salt_hash: &tswe_salt_hash_arr,
        parent_root: &parent_root_arr,
        join_delta_root: &join_delta_root_arr,
        revoked_since_root: &revoked_since_root_arr,
        revoked_root: &revoked_root_arr,
        pox_r_commit: &pox_r_commit_arr,
        msphf_crs_id: msphf_crs_id.as_str(),
        msphf_params_id: msphf_params_id.as_str(),
        srx: Some(srx_inputs),
        pop_public_key: pop_public_key.as_slice(),
        pop_secret_key: pop_secret.as_ref(),
        proof_mode: proof_mode.as_str(),
        vrf_id: vrf_id.as_str(),
        policy_version: policy_version.as_str(),
        vrf_secret_key: vrf_secret_key.as_slice(),
        vrf_public_key: vrf_public_key.as_slice(),
        fs_policy_version: fs_policy_version.as_str(),
        fs_epoch_base_ts,
        barrier_version: next_barrier_version,
        fs_join: FsJoinInputs {
            fs_ec,
            fs_epoch_commit,
            fs_dev_prev_commit,
        },
    });

    publish_barrier_merge(BarrierMergePublishInputs {
        policy: BarrierMergePublishPolicy {
            pending_barrier_update_reason: 0,
            build_barrier_update_reason: 1,
            current_k_fs: None,
            build_bundle_context: revocation_build_bundle_context(operation_label),
            accept_bundle_context: revocation_accept_bundle_context(operation_label),
            retry_on_fs_forward_jump_group: false,
            trigger_before_publish_join_finalize_fault: false,
        },
        client: &client,
        persist_request: &persist_request,
        gid: &gid,
        barrier_version,
        next_barrier_version,
        fs_ec,
        fs_dev_prev_commit,
        header,
        cat_arr,
        parent_root_arr,
        params: prepared_orchestration.params,
        parts: prepared_orchestration.parts,
        parities: &parities,
        witness_bytes: witness_bytes.as_deref(),
        pivot: &pivot,
        snapshot_hash,
        committed_revocation_roots_hash,
        revocation_roots_hash,
        ticket_history_commitment,
        ticket_history_authority_extension,
        current_global_history_attestation_bytes,
        barrier_update,
        forward_state,
        fs_forward_leap_policy: FsForwardLeapPolicy {
            h: fs_forward_leap_policy.h,
            checkpoint_interval: fs_forward_leap_policy.checkpoint_interval,
            slack_anchor: fs_forward_leap_policy.slack_anchor,
            slack_first_device: fs_forward_leap_policy.slack_first_device,
            slack_device: fs_forward_leap_policy.slack_device,
        },
        last_accepted_ec,
    })
    .await
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
    let ticket = client
        .merge_ticket_with_retry(&room_id, &leaf_id)
        .await
        .context("failed to obtain leave merge ticket")?;

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

    let ticket = client
        .expel_member_ticket_with_retry(
            &room_id,
            &author_leaf_id,
            &target_leaf_id,
            admin_proof.clone(),
        )
        .await
        .context("failed to obtain expel merge ticket")?;

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
