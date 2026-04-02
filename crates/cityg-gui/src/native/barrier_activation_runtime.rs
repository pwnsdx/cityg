use super::*;
use cityg_api_client::to_core_history_commitment;
use cityg_client::barrier_activation::{
    ClientVisibleBarrierActivationInput,
    bundle_authored_by_local_device as bundle_authored_by_local_device_core,
    extract_barrier_update_digest as extract_barrier_update_digest_core,
    validate_client_visible_activation_guards as validate_client_visible_activation_guards_core,
};
use cityg_client::barrier_pending::{
    PendingBarrierHistoryInput as CorePendingBarrierHistoryInput,
    PendingBarrierHistoryResolution as CorePendingBarrierHistoryResolution,
    PendingBarrierLookupStatus as CorePendingBarrierLookupStatus,
    PendingBarrierRecoveryReason as CorePendingBarrierRecoveryReason,
    resolve_pending_barrier_history,
};

fn map_pending_barrier_recovery_reason(
    reason: CorePendingBarrierRecoveryReason,
) -> BarrierRecoveryIssue {
    match reason {
        CorePendingBarrierRecoveryReason::InsufficientAuthenticatedHistory => {
            BarrierRecoveryIssue::InsufficientAuthenticatedHistory
        }
        CorePendingBarrierRecoveryReason::ContradictoryAuthenticatedHistory => {
            BarrierRecoveryIssue::ContradictoryAuthenticatedHistory
        }
        CorePendingBarrierRecoveryReason::LegacyPendingLocatorMissing => {
            BarrierRecoveryIssue::LegacyPendingLocatorMissing
        }
    }
}

pub(super) fn extract_barrier_update_digest(
    header: &BTreeMap<u64, Value>,
) -> Result<Option<[u8; 32]>> {
    extract_barrier_update_digest_core(header)
}

pub(super) fn validate_client_visible_activation_guards(
    session: &AppSession,
    header_map: &BTreeMap<u64, Value>,
) -> Result<()> {
    let current_history_commitment = session
        .barrier_state
        .current_history_commitment
        .as_ref()
        .map(to_core_history_commitment);

    validate_client_visible_activation_guards_core(
        ClientVisibleBarrierActivationInput {
            gid: &session.gid,
            local_pop_public_key: session.pop_public_key.as_slice(),
            local_current_history_commitment: current_history_commitment.as_ref(),
            local_current_history_view_id: session.barrier_state.current_history_view_id,
            local_current_history_authority_extension_present: session
                .barrier_state
                .current_history_authority_extension
                .is_some(),
            local_current_global_history_attestation_bytes: session
                .barrier_state
                .current_global_history_attestation_bytes
                .as_slice(),
            local_n_max: session.barrier_state.n_max,
            local_max_barrier_update_bytes: session.barrier_state.max_barrier_update_bytes,
            local_fs_policy_version: session.fs_policy_version.as_str(),
            local_fs_epoch_base_ts: session.fs_epoch_base_ts,
            local_last_accepted_ec: session.last_accepted_ec,
            local_fs_ec: session.fs_ec,
            local_fs_dev_prev_commit: session.fs_dev_prev_commit,
            fs_forward_leap_h: session.fs_forward_leap_policy.h,
            fs_forward_leap_checkpoint_interval: session.fs_forward_leap_policy.checkpoint_interval,
            fs_forward_leap_slack_anchor: session.fs_forward_leap_policy.slack_anchor,
            fs_forward_leap_slack_first_device: session.fs_forward_leap_policy.slack_first_device,
            fs_forward_leap_slack_device: session.fs_forward_leap_policy.slack_device,
        },
        header_map,
    )
}

pub(super) fn bundle_authored_by_local_device(
    session: &AppSession,
    header: &BTreeMap<u64, Value>,
) -> bool {
    bundle_authored_by_local_device_core(session.pop_public_key.as_slice(), header)
}

pub(super) async fn apply_pending_barrier_activation_from_history(
    client: &CitygApiClient,
    session: &mut AppSession,
    current_barrier_version: u64,
) -> Result<PendingBarrierHistoryOutcome> {
    let Some(pending) = session.barrier_state.pending.clone() else {
        return Ok(PendingBarrierHistoryOutcome::Unchanged);
    };

    let lookup_resolution = if pending.we_epoch_id == [0u8; 32] {
        resolve_pending_barrier_history(CorePendingBarrierHistoryInput {
            current_barrier_version,
            pending_barrier_version: pending.barrier_version,
            pending_we_epoch_id: pending.we_epoch_id,
            status: CorePendingBarrierLookupStatus::Pending,
            accepted_barrier_version: None,
            accepted_fs_ec: None,
            accepted_reason: None,
            accepted_digest: None,
        })?
    } else {
        match client
            .barrier_lookup_merge_acceptance(
                &session.room_id,
                pending.barrier_version,
                &pending.barrier_update_digest,
                &pending.we_epoch_id,
            )
            .await
        {
            Ok(lookup) => {
                let status = match lookup.status {
                    MergeAcceptanceStatus::Pending => CorePendingBarrierLookupStatus::Pending,
                    MergeAcceptanceStatus::Accepted => CorePendingBarrierLookupStatus::Accepted,
                    MergeAcceptanceStatus::Superseded => CorePendingBarrierLookupStatus::Superseded,
                    MergeAcceptanceStatus::FinalRejected => {
                        CorePendingBarrierLookupStatus::FinalRejected
                    }
                };
                resolve_pending_barrier_history(CorePendingBarrierHistoryInput {
                    current_barrier_version,
                    pending_barrier_version: pending.barrier_version,
                    pending_we_epoch_id: pending.we_epoch_id,
                    status,
                    accepted_barrier_version: lookup.accepted_barrier_version,
                    accepted_fs_ec: lookup.accepted_fs_ec,
                    accepted_reason: lookup.accepted_reason,
                    accepted_digest: lookup.accepted_digest,
                })?
            }
            Err(ApiClientError::HttpStatus { status, .. }) if status.as_u16() == 404 => {
                resolve_pending_barrier_history(CorePendingBarrierHistoryInput {
                    current_barrier_version,
                    pending_barrier_version: pending.barrier_version,
                    pending_we_epoch_id: pending.we_epoch_id,
                    status: CorePendingBarrierLookupStatus::NotFound,
                    accepted_barrier_version: None,
                    accepted_fs_ec: None,
                    accepted_reason: None,
                    accepted_digest: None,
                })?
            }
            Err(err) => {
                return Err(anyhow!(
                    "pending barrier activation history lookup failed (960.9): {err}"
                ));
            }
        }
    };

    match lookup_resolution {
        CorePendingBarrierHistoryResolution::Unchanged => {
            Ok(PendingBarrierHistoryOutcome::Unchanged)
        }
        CorePendingBarrierHistoryResolution::Discard => {
            session.barrier_state.pending = None;
            session.barrier_state.barrier_recovery_issue = None;
            Ok(PendingBarrierHistoryOutcome::Discarded)
        }
        CorePendingBarrierHistoryResolution::RecoveryRequired(reason) => {
            let issue = map_pending_barrier_recovery_reason(reason);
            if matches!(
                reason,
                CorePendingBarrierRecoveryReason::LegacyPendingLocatorMissing
            ) {
                warn!(
                    code = BARRIER_CODE_SNAPSHOT_AUTH_FAILURE,
                    pending_barrier_version = pending.barrier_version,
                    current_barrier_version,
                    "pending barrier state predates pending we_epoch_id persistence; entering recovery-required state after newer barrier version observed"
                );
            }
            Ok(mark_barrier_recovery_required(session, issue))
        }
        CorePendingBarrierHistoryResolution::Activate {
            we_epoch_id,
            observation,
        } => {
            let activation_source = pending
                .activation_source
                .clone()
                .unwrap_or_else(|| capture_barrier_pending_activation_source(session));
            if apply_pending_barrier_activation_with_source(
                session,
                &activation_source,
                observation.observed_barrier_version,
                observation.observed_fs_ec,
                observation.observed_barrier_update_reason,
                observation.accepted_digest,
            )? {
                Ok(PendingBarrierHistoryOutcome::Activated(we_epoch_id))
            } else {
                Ok(mark_barrier_recovery_required(
                    session,
                    BarrierRecoveryIssue::ContradictoryAuthenticatedHistory,
                ))
            }
        }
    }
}
