use std::{collections::BTreeMap, convert::TryInto, fs, path::Path};

#[cfg(test)]
use cityg_runtime::StoredBundle;
#[cfg(test)]
use cityg_runtime::ensure_leaf_member_for_epoch as runtime_ensure_leaf_member_for_epoch;
use cityg_runtime::{
    AcceptedRoomEpoch, AppliedBundleIndexes, BundleIndexUpdate, EpochScope, PreparedAcceptedBundle,
    RoomAcceptEpochError, RoomAuthorizationError, RoomBundleMaterializationError,
    RoomRetentionPolicy, RoomServiceError, apply_bundle_indexes, lane_state_path,
    materialize_replayed_bundle as runtime_materialize_replayed_bundle,
};
use cityg_runtime::{
    commit_prepared_accepted_bundle as runtime_commit_prepared_accepted_bundle,
    ensure_leaf_member_for_room as runtime_ensure_leaf_member_for_room,
};

use cityg_api_schema::pb::AcceptEpochResponse;
use cityg_client::{CityGError as ClientError, ClientEpochBundle, GroupMembership};
use cityg_server::ServerOutcome;
use msphf_core::{MsphfError, merkle::canonical_set_root};
use msphf_orchestrator::AcceptanceError;

use crate::{
    ApiError, ApiState, MESSAGE_PRUNE_INTERVAL_MS, MembershipEventKind, current_timestamp_ms,
    maybe_record_api_concurrency_error,
};

pub(crate) async fn apply_bundle(
    state: &ApiState,
    bundle: &ClientEpochBundle,
) -> Result<AcceptEpochResponse, ApiError> {
    let gid: [u8; 32] = bundle
        .gid()
        .try_into()
        .map_err(|_| ApiError::server_message("invalid gid length in bundle"))?;
    let started = std::time::Instant::now();

    let prepared = {
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        match crate::runtime_prepare_accepted_bundle(&mut guard, bundle) {
            Ok(prepared) => prepared,
            Err(err) => {
                drop(guard);
                let mapped = map_room_accept_error(state, err, None, None).await;
                maybe_record_api_concurrency_error("accept_epoch", &mapped);
                metrics::counter!("cityg_accept_epoch_total", "result" => "error").increment(1);
                metrics::histogram!("cityg_accept_epoch_duration_seconds", "result" => "error")
                    .record(started.elapsed().as_secs_f64());
                return Err(mapped);
            }
        }
    };

    let accepted = match commit_accepted_bundle(state, bundle, prepared, true).await {
        Ok(accepted) => accepted,
        Err(mapped) => {
            maybe_record_api_concurrency_error("accept_epoch", &mapped);
            metrics::counter!("cityg_accept_epoch_total", "result" => "error").increment(1);
            metrics::histogram!("cityg_accept_epoch_duration_seconds", "result" => "error")
                .record(started.elapsed().as_secs_f64());
            return Err(mapped);
        }
    };

    state.clear_merge_ticket_cache_for_gid(gid).await;
    metrics::counter!("cityg_accept_epoch_total", "result" => "ok").increment(1);
    metrics::histogram!("cityg_accept_epoch_duration_seconds", "result" => "ok")
        .record(started.elapsed().as_secs_f64());
    Ok(accept_response_from(&accepted.outcome))
}

#[cfg(test)]
pub(crate) async fn store_bundle_bytes(state: &ApiState, weid: [u8; 32], bytes: Vec<u8>) {
    let now_ms = current_timestamp_ms();
    let mut room_state = state.room_state.write().await;
    room_state.store_bundle(
        weid,
        StoredBundle {
            bytes,
            stored_at_ms: now_ms,
        },
        now_ms,
        state.message_retention,
        MESSAGE_PRUNE_INTERVAL_MS,
    );
}

fn load_journal_entries(path: &Path) -> anyhow::Result<Vec<Vec<u8>>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    let mut cursor = bytes.as_slice();
    let mut entries = Vec::new();
    while cursor.len() >= 4 {
        let (len_bytes, rest) = cursor.split_at(4);
        let len = u32::from_le_bytes(
            len_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid journal entry length"))?,
        ) as usize;
        if rest.len() < len {
            break;
        }
        let (entry, remainder) = rest.split_at(len);
        entries.push(entry.to_vec());
        cursor = remainder;
    }
    Ok(entries)
}

pub(crate) async fn commit_accepted_bundle(
    state: &ApiState,
    bundle: &ClientEpochBundle,
    prepared: PreparedAcceptedBundle,
    broadcast: bool,
) -> Result<AcceptedRoomEpoch, ApiError> {
    let timestamp_ms = current_timestamp_ms();
    let accepted = {
        let mut room_state = state.room_state.write().await;
        runtime_commit_prepared_accepted_bundle(
            &mut room_state,
            bundle,
            prepared,
            timestamp_ms,
            RoomRetentionPolicy {
                retention: state.message_retention,
                prune_interval_ms: MESSAGE_PRUNE_INTERVAL_MS,
            },
        )
        .map_err(|err| map_bundle_index_error(err, "failed to compute membership delta"))?
    };
    apply_bundle_side_effects(state, &accepted.applied, broadcast).await;
    Ok(accepted)
}

async fn rehydrate_bundle_indexes(
    state: &ApiState,
    bundle: &ClientEpochBundle,
    weid: [u8; 32],
    bytes: Vec<u8>,
    membership_root: [u8; 32],
) -> Result<(), ApiError> {
    let timestamp_ms = current_timestamp_ms();
    let applied = {
        let mut room_state = state.room_state.write().await;
        apply_bundle_indexes(
            &mut room_state,
            bundle,
            BundleIndexUpdate {
                we_epoch_id: weid,
                bytes,
                membership_root,
                timestamp_ms,
            },
            RoomRetentionPolicy {
                retention: state.message_retention,
                prune_interval_ms: MESSAGE_PRUNE_INTERVAL_MS,
            },
        )
        .map_err(|err| {
            map_bundle_index_error(err, "failed to compute membership delta during replay")
        })?
    };
    apply_bundle_side_effects(state, &applied, false).await;
    Ok(())
}

pub(crate) async fn rehydrate_persisted_bundle_indexes(
    state: &ApiState,
    cfg: &cityg_config::CityGConfig,
    lane_count: usize,
) -> anyhow::Result<()> {
    let Some(base_path) = cfg.server.state_path.as_ref() else {
        return Ok(());
    };

    let mut memberships: BTreeMap<[u8; 32], GroupMembership> = BTreeMap::new();
    for lane_index in 0..lane_count.max(1) {
        let journal_path = lane_state_path(base_path, lane_index, lane_count.max(1));
        let entries = load_journal_entries(&journal_path)?;
        for entry in entries {
            let bundle = ClientEpochBundle::from_cbor(&entry).map_err(|err| {
                anyhow::anyhow!("failed to decode replayed journal bundle: {err}")
            })?;
            let gid: [u8; 32] = bundle
                .gid()
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid gid length in replayed journal bundle"))?;
            let delta = bundle.membership_delta().map_err(|err| {
                anyhow::anyhow!("failed to compute replayed membership delta: {err}")
            })?;
            let membership = memberships.entry(gid).or_default();
            membership
                .apply_delta_checked(&delta)
                .map_err(|err| anyhow::anyhow!("failed to replay membership delta: {err}"))?;
            let leaves: Vec<[u8; 32]> = membership.members().copied().collect();
            let membership_root = canonical_set_root(&leaves)
                .map_err(|_| anyhow::anyhow!("failed to compute replayed membership root"))?;
            let bytes = {
                let lane = state.server_for_gid(&gid);
                let mut guard = lane.write().await;
                runtime_materialize_replayed_bundle(&mut guard, &bundle, membership_root)
                    .map_err(|err| anyhow::anyhow!(err.to_string()))?
            };
            rehydrate_bundle_indexes(state, &bundle, bundle.we_epoch_id, bytes, membership_root)
                .await?;
        }
    }

    Ok(())
}

fn map_bundle_index_error(err: RoomServiceError, context: &str) -> ApiError {
    match err {
        RoomServiceError::InvalidGidLength => {
            ApiError::server_message("invalid gid length in bundle")
        }
        RoomServiceError::MembershipDelta(message) => {
            ApiError::server_message(format!("{context}: {message}"))
        }
    }
}

fn map_bundle_materialization_error(err: RoomBundleMaterializationError) -> ApiError {
    ApiError::server_message(err.to_string())
}

pub(crate) async fn map_room_accept_error(
    state: &ApiState,
    err: RoomAcceptEpochError,
    error_label: Option<&'static str>,
    failed_index: Option<u32>,
) -> ApiError {
    match err {
        RoomAcceptEpochError::Client(err) => {
            map_accept_error(state, err, error_label, failed_index).await
        }
        RoomAcceptEpochError::Materialization(err) => map_bundle_materialization_error(err),
        RoomAcceptEpochError::Service(err) => {
            map_bundle_index_error(err, "failed to compute membership delta")
        }
    }
}

async fn apply_bundle_side_effects(
    state: &ApiState,
    applied: &AppliedBundleIndexes,
    broadcast: bool,
) {
    if !applied.revoked.is_empty() {
        let mut alias_guard = state.alias_registry.write().await;
        alias_guard.remove_revoked_slice(applied.revoked.as_slice());
    }
    if !broadcast {
        return;
    }
    for leaf in &applied.joined {
        state.broadcast_membership(
            applied.gid,
            *leaf,
            MembershipEventKind::Join,
            applied.timestamp_ms,
        );
    }
    for leaf in &applied.revoked {
        state.broadcast_membership(
            applied.gid,
            *leaf,
            MembershipEventKind::Revoke,
            applied.timestamp_ms,
        );
    }
}

#[cfg(test)]
pub(crate) async fn ensure_leaf_member_for_epoch(
    state: &ApiState,
    we_epoch_id: &[u8; 32],
    leaf_id: [u8; 32],
) -> Result<EpochScope, ApiError> {
    let scope = state
        .epoch_scope_for_weid(we_epoch_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let lane = state.server_for_gid(&scope.gid);
    let guard = lane.read().await;
    let room_state = state.room_state.read().await;
    runtime_ensure_leaf_member_for_epoch(&guard, &room_state, we_epoch_id, leaf_id).map_err(|err| {
        match err {
            RoomAuthorizationError::NotFound => ApiError::NotFound,
            RoomAuthorizationError::Unauthorized => {
                ApiError::Unauthorized("leaf is not a member for epoch")
            }
        }
    })
}

pub(crate) async fn ensure_leaf_member_for_room(
    state: &ApiState,
    gid: &[u8; 32],
    leaf_id: [u8; 32],
) -> Result<(), ApiError> {
    let lane = state.server_for_gid(gid);
    let guard = lane.read().await;
    runtime_ensure_leaf_member_for_room(&guard, gid, leaf_id).map_err(|err| match err {
        RoomAuthorizationError::NotFound => ApiError::NotFound,
        RoomAuthorizationError::Unauthorized => {
            ApiError::Unauthorized("leaf is not a member for room")
        }
    })
}

fn accept_response_from(outcome: &ServerOutcome) -> AcceptEpochResponse {
    AcceptEpochResponse {
        we_epoch_id: outcome.we_epoch_id.to_vec(),
        wid: outcome.wid.to_vec(),
        parent_root: outcome.parent_root.to_vec(),
        new_root: outcome.new_root.to_vec(),
    }
}

pub(crate) async fn map_accept_error(
    state: &ApiState,
    err: ClientError,
    error_label: Option<&'static str>,
    failed_index: Option<u32>,
) -> ApiError {
    match err {
        ClientError::InvalidInput(message) => {
            tracing::debug!(%message, "accept_epoch invalid bundle input");
            ApiError::InvalidRequest("invalid bundle components")
        }
        ClientError::Acceptance(AcceptanceError::Freeze(freeze)) => {
            state.record_freeze(freeze).await;
            ApiError::server_with_freeze_context(
                format!("acceptance error: {}", freeze.reason),
                freeze,
                error_label,
                failed_index,
            )
        }
        ClientError::Acceptance(AcceptanceError::Msphf(MsphfError::InvalidInput(message))) => {
            tracing::debug!(%message, "accept_epoch invalid msphf bundle input");
            ApiError::InvalidRequest("invalid bundle components")
        }
        ClientError::Acceptance(other) => ApiError::server_message_with_context(
            format!("acceptance error: {other:?}"),
            error_label,
            failed_index,
        ),
        other => {
            ApiError::server_message_with_context(other.to_string(), error_label, failed_index)
        }
    }
}
