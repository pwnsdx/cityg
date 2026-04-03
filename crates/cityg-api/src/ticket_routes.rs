use std::time::SystemTime;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderValue},
    response::Response,
};
use prost::Message;

use cityg_api_schema::{
    API_PROFILE_VERSION, encode_bootstrap_room_response, encode_prepared_join_ticket_response,
    encode_prepared_merge_ticket_response,
    prepare_join_ticket_request as schema_prepare_join_ticket_request,
    validate_bootstrap_room_request as schema_validate_bootstrap_room_request,
    validate_merge_ticket_request as schema_validate_merge_ticket_request,
};
use cityg_client::CityGError as ClientError;
use cityg_runtime::{
    bootstrap_room_with_admin as runtime_bootstrap_room_with_admin,
    prepare_join_ticket as runtime_prepare_join_ticket,
    prepare_merge_ticket as runtime_prepare_merge_ticket,
};
use cityg_server::{
    BARRIER_LEAF_CAPACITY_EXHAUSTED_ERR, BARRIER_LEAF_CAPACITY_REFUSAL_THRESHOLD_REACHED_ERR,
    MergeTicketIntent as ServerMergeTicketIntent,
};
use tracing::warn;

use crate::{
    ApiError, ApiState, BootstrapRoomRequest, JoinTicketRequest, MESSAGE_AUTH_HEADER,
    MergeTicketCacheKey, MergeTicketIntent, MergeTicketRequest, configured_message_auth_token,
    current_timestamp_ms, enforce_expensive_rate_limit, enforce_message_auth_header,
    fingerprint_rate_limit_parts, join_ticket_rate_limit_key,
    map_join_ticket_request_preparation_error, map_merge_ticket_request_validation_error,
    map_room_admin_request_validation_error, map_room_ticket_preparation_error,
    protobuf_response_bytes, verify_room_admin_proof,
};

pub(crate) async fn join_ticket(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let _permit = state.join_ticket_limiter.try_acquire()?;
    let request = JoinTicketRequest::decode(body)?;
    if request.room_id.is_empty() {
        return Err(ApiError::InvalidRequest("room_id must be provided"));
    }
    enforce_expensive_rate_limit(&state, "join_ticket", join_ticket_rate_limit_key(&request))
        .await?;
    let request = schema_prepare_join_ticket_request(request)
        .map_err(map_join_ticket_request_preparation_error)?;

    let (prepared, leaf_capacity, warning_percent) = {
        let lane = state.server_for_gid(&request.gid);
        let mut guard = lane.write().await;
        match runtime_prepare_join_ticket(
            &mut guard,
            &request.gid,
            request.requested_leaf_id,
            SystemTime::now(),
            state.fs_epoch_period_seconds,
            API_PROFILE_VERSION,
        ) {
            Ok(prepared) => {
                let leaf_capacity = guard.barrier_leaf_capacity(&request.gid);
                let warning_percent = guard.barrier_leaf_capacity_warning_percent();
                (prepared, leaf_capacity, warning_percent)
            }
            Err(err) => {
                metrics::counter!("cityg_join_ticket_total", "result" => "error").increment(1);
                if matches!(
                    err.client_error(),
                    Some(ClientError::InvalidInput(
                        BARRIER_LEAF_CAPACITY_REFUSAL_THRESHOLD_REACHED_ERR
                    ))
                ) {
                    metrics::counter!(
                        "cityg_join_ticket_capacity_total",
                        "state" => "refused"
                    )
                    .increment(1);
                } else if matches!(
                    err.client_error(),
                    Some(ClientError::InvalidInput(
                        BARRIER_LEAF_CAPACITY_EXHAUSTED_ERR
                    ))
                ) {
                    metrics::counter!(
                        "cityg_join_ticket_capacity_total",
                        "state" => "exhausted"
                    )
                    .increment(1);
                }
                return Err(map_room_ticket_preparation_error("join_ticket", err));
            }
        }
    };
    let ticket_leaf_id = prepared.bundle.leaf_id;

    if let Some(binding) = request.confirmed_binding.as_ref() {
        state
            .register_alias(
                &binding.alias,
                ticket_leaf_id,
                binding.pop_public_key.clone(),
            )
            .await?;
    }
    if let Some(capacity) = leaf_capacity
        && capacity.utilization_percent() >= u64::from(warning_percent)
    {
        warn!(
            room_id = %request.room_id,
            n_max = capacity.n_max,
            active_leaf_count = capacity.active_leaf_count,
            revoked_leaf_count = capacity.revoked_leaf_count,
            pending_join_ticket_count = capacity.pending_join_ticket_count,
            reserved_cover_leaf_count = capacity.reserved_cover_leaf_count,
            remaining_cover_leaf_slots = capacity.remaining_cover_leaf_slots,
            utilization_percent = capacity.utilization_percent(),
            warning_percent,
            "barrier leaf capacity high during join ticket issuance"
        );
        metrics::counter!("cityg_join_ticket_capacity_total", "state" => "warning").increment(1);
    }
    metrics::counter!("cityg_join_ticket_total", "result" => "ok").increment(1);
    Ok(protobuf_response_bytes(
        encode_prepared_join_ticket_response(prepared, request.confirmed_binding),
    ))
}

pub(crate) async fn bootstrap_room(
    State(state): State<ApiState>,
    _headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request = schema_validate_bootstrap_room_request(BootstrapRoomRequest::decode(body)?)
        .map_err(map_room_admin_request_validation_error)?;
    let initial_room_admin_pop_key = verify_room_admin_proof(
        &request.admin_proof,
        "bootstrap_room_v1",
        &request.room_id,
        &request.kbroad_public,
    )?;

    {
        let lane = state.server_for_gid(&request.gid);
        let mut guard = lane.write().await;
        runtime_bootstrap_room_with_admin(
            &mut guard,
            &request.gid,
            request.kbroad_public,
            initial_room_admin_pop_key,
        )
        .map_err(|err| match err {
            ClientError::InvalidInput(message) => ApiError::InvalidRequest(message),
            other => ApiError::from(other),
        })?;
    }

    Ok(protobuf_response_bytes(encode_bootstrap_room_response(
        "registered",
    )))
}

pub(crate) async fn merge_ticket(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let request = schema_validate_merge_ticket_request(MergeTicketRequest::decode(body)?)
        .map_err(map_merge_ticket_request_validation_error)?;
    enforce_expensive_rate_limit(
        &state,
        "merge_ticket",
        fingerprint_rate_limit_parts(&[
            headers
                .get(MESSAGE_AUTH_HEADER)
                .map(HeaderValue::as_bytes)
                .unwrap_or_default(),
            &request.gid,
            &request.leaf_id,
        ]),
    )
    .await?;
    let cache_key = MergeTicketCacheKey {
        gid: request.gid,
        leaf_id: request.leaf_id,
        intent: request.intent_value,
    };
    let now_ms = current_timestamp_ms();
    if request.intent == MergeTicketIntent::Leave
        && let Some(cached) = state.coalesced_merge_ticket_lookup(cache_key, now_ms).await
    {
        metrics::counter!(
            "cityg_merge_ticket_coalesced_total",
            "intent" => "leave"
        )
        .increment(1);
        metrics::counter!("cityg_merge_ticket_total", "result" => "ok").increment(1);
        return Ok(protobuf_response_bytes(cached));
    }

    let prepared = {
        let lane = state.server_for_gid(&request.gid);
        let mut guard = lane.write().await;
        let server_intent = match request.intent {
            MergeTicketIntent::Leave => ServerMergeTicketIntent::Leave,
            MergeTicketIntent::Refresh => ServerMergeTicketIntent::Refresh,
        };
        match runtime_prepare_merge_ticket(
            &mut guard,
            &request.gid,
            &request.leaf_id,
            server_intent,
            API_PROFILE_VERSION,
        ) {
            Ok(prepared) => prepared,
            Err(err) => {
                metrics::counter!("cityg_merge_ticket_total", "result" => "error").increment(1);
                let endpoint = match request.intent {
                    MergeTicketIntent::Leave => "merge_ticket",
                    MergeTicketIntent::Refresh => "merge_ticket_refresh",
                };
                return Err(map_room_ticket_preparation_error(endpoint, err));
            }
        }
    };

    let response_bytes = encode_prepared_merge_ticket_response(prepared);
    if request.intent == MergeTicketIntent::Leave {
        state
            .coalesced_merge_ticket_store(cache_key, response_bytes.clone(), now_ms)
            .await;
    }
    metrics::counter!("cityg_merge_ticket_total", "result" => "ok").increment(1);
    Ok(protobuf_response_bytes(response_bytes))
}
