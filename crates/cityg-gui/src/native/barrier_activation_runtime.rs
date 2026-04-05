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

fn trace_from_pending_history_resolution(
    pending: &BarrierPendingState,
    current_barrier_version: u64,
    lookup_status: BarrierPendingLookupTraceStatus,
    accepted_barrier_version: Option<u64>,
    accepted_fs_ec: Option<u64>,
    accepted_reason: Option<u64>,
    accepted_digest: Option<[u8; 32]>,
    resolution: CorePendingBarrierHistoryResolution,
    detail: Option<String>,
) -> BarrierPendingHistoryTrace {
    let (decision, recovery_issue) = match resolution {
        CorePendingBarrierHistoryResolution::Unchanged => {
            (BarrierPendingTraceDecision::Unchanged, None)
        }
        CorePendingBarrierHistoryResolution::Activate { .. } => {
            (BarrierPendingTraceDecision::Activated, None)
        }
        CorePendingBarrierHistoryResolution::Discard => {
            (BarrierPendingTraceDecision::Discarded, None)
        }
        CorePendingBarrierHistoryResolution::RecoveryRequired(reason) => (
            BarrierPendingTraceDecision::RecoveryRequired,
            Some(map_pending_barrier_recovery_reason(reason)),
        ),
    };

    BarrierPendingHistoryTrace {
        pending_barrier_version: pending.barrier_version,
        pending_we_epoch_id: pending.we_epoch_id,
        current_barrier_version,
        lookup_status,
        accepted_barrier_version,
        accepted_fs_ec,
        accepted_reason,
        accepted_digest,
        decision,
        recovery_issue,
        detail,
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

    let (
        core_lookup_status,
        trace_lookup_status,
        accepted_barrier_version,
        accepted_fs_ec,
        accepted_reason,
        accepted_digest,
    ) = if pending.we_epoch_id == [0u8; 32] {
        (
            CorePendingBarrierLookupStatus::Pending,
            BarrierPendingLookupTraceStatus::LegacyLocatorUnavailable,
            None,
            None,
            None,
            None,
        )
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
                let (core_status, trace_status) = match lookup.status {
                    MergeAcceptanceStatus::Pending => (
                        CorePendingBarrierLookupStatus::Pending,
                        BarrierPendingLookupTraceStatus::Pending,
                    ),
                    MergeAcceptanceStatus::Accepted => (
                        CorePendingBarrierLookupStatus::Accepted,
                        BarrierPendingLookupTraceStatus::Accepted,
                    ),
                    MergeAcceptanceStatus::Superseded => (
                        CorePendingBarrierLookupStatus::Superseded,
                        BarrierPendingLookupTraceStatus::Superseded,
                    ),
                    MergeAcceptanceStatus::FinalRejected => (
                        CorePendingBarrierLookupStatus::FinalRejected,
                        BarrierPendingLookupTraceStatus::FinalRejected,
                    ),
                };
                (
                    core_status,
                    trace_status,
                    lookup.accepted_barrier_version,
                    lookup.accepted_fs_ec,
                    lookup.accepted_reason,
                    lookup.accepted_digest,
                )
            }
            Err(ApiClientError::HttpStatus { status, .. }) if status.as_u16() == 404 => (
                CorePendingBarrierLookupStatus::NotFound,
                BarrierPendingLookupTraceStatus::NotFound,
                None,
                None,
                None,
                None,
            ),
            Err(err) => {
                warn!(
                    pending_barrier_version = pending.barrier_version,
                    current_barrier_version,
                    pending_we_epoch_id = %hex_encode(pending.we_epoch_id),
                    pending_barrier_update_digest = %hex_encode(pending.barrier_update_digest),
                    "pending barrier activation history lookup failed before authenticated resolution: {err}"
                );
                record_pending_history_trace(
                    session,
                    BarrierPendingHistoryTrace {
                        pending_barrier_version: pending.barrier_version,
                        pending_we_epoch_id: pending.we_epoch_id,
                        current_barrier_version,
                        lookup_status: BarrierPendingLookupTraceStatus::TransportError,
                        accepted_barrier_version: None,
                        accepted_fs_ec: None,
                        accepted_reason: None,
                        accepted_digest: None,
                        decision: BarrierPendingTraceDecision::LookupFailed,
                        recovery_issue: None,
                        detail: Some(err.to_string()),
                    },
                );
                return Err(anyhow!(
                    "pending barrier activation history lookup failed for barrier_version={} we_epoch_id={} digest={} (960.9): {err}",
                    pending.barrier_version,
                    hex_encode(pending.we_epoch_id),
                    hex_encode(pending.barrier_update_digest),
                ));
            }
        }
    };

    let lookup_resolution = resolve_pending_barrier_history(CorePendingBarrierHistoryInput {
        current_barrier_version,
        pending_barrier_version: pending.barrier_version,
        pending_we_epoch_id: pending.we_epoch_id,
        status: core_lookup_status,
        accepted_barrier_version,
        accepted_fs_ec,
        accepted_reason,
        accepted_digest,
    })?;

    record_pending_history_trace(
        session,
        trace_from_pending_history_resolution(
            &pending,
            current_barrier_version,
            trace_lookup_status,
            accepted_barrier_version,
            accepted_fs_ec,
            accepted_reason,
            accepted_digest,
            lookup_resolution,
            None,
        ),
    );
    if let Some(trace) = session.barrier_state.last_pending_history_trace.as_ref() {
        info!(
            pending_barrier_version = trace.pending_barrier_version,
            current_barrier_version = trace.current_barrier_version,
            lookup_status = ?trace.lookup_status,
            decision = ?trace.decision,
            recovery_issue = ?trace.recovery_issue,
            "resolved pending barrier history state"
        );
    }

    match lookup_resolution {
        CorePendingBarrierHistoryResolution::Unchanged => {
            Ok(PendingBarrierHistoryOutcome::Unchanged)
        }
        CorePendingBarrierHistoryResolution::Discard => {
            discard_pending_barrier_state(session);
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
                record_pending_history_trace(
                    session,
                    BarrierPendingHistoryTrace {
                        pending_barrier_version: pending.barrier_version,
                        pending_we_epoch_id: pending.we_epoch_id,
                        current_barrier_version,
                        lookup_status: trace_lookup_status,
                        accepted_barrier_version,
                        accepted_fs_ec,
                        accepted_reason,
                        accepted_digest,
                        decision: BarrierPendingTraceDecision::RecoveryRequired,
                        recovery_issue: Some(
                            BarrierRecoveryIssue::ContradictoryAuthenticatedHistory,
                        ),
                        detail: Some(
                            "accepted merge contradicted the locally persisted pending activation source"
                                .to_string(),
                        ),
                    },
                );
                Ok(mark_barrier_recovery_required(
                    session,
                    BarrierRecoveryIssue::ContradictoryAuthenticatedHistory,
                ))
            }
        }
    }
}
