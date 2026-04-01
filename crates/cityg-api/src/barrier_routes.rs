use axum::{body::Bytes, extract::State, http::HeaderMap, response::Response};
use prost::Message;

use cityg_api_schema::{
    API_PROFILE_VERSION, FetchPublicTreeRequestDecodeError,
    FullVerificationWitnessRequestDecodeError, LookupMergeAcceptanceRequestDecodeError,
    MAX_BARRIER_HELPER_PAGE_ENTRIES, ResolveRevokedLeavesRequestDecodeError,
    decode_barrier_fetch_public_tree_request as schema_decode_barrier_fetch_public_tree_request,
    decode_barrier_lookup_merge_acceptance_request as schema_decode_barrier_lookup_merge_acceptance_request,
    decode_barrier_resolve_revoked_leaves_request as schema_decode_barrier_resolve_revoked_leaves_request,
    decode_full_verification_witness_request as schema_decode_full_verification_witness_request,
    encode_full_verification_witness_response, encode_prepared_barrier_public_tree_response,
    encode_prepared_merge_acceptance_lookup_response, encode_prepared_resolved_joins_response,
    encode_prepared_resolved_revoked_leaves_response,
};
use cityg_runtime::{
    prepare_barrier_public_tree as runtime_prepare_barrier_public_tree,
    prepare_full_verification_witness as runtime_prepare_full_verification_witness,
    prepare_merge_acceptance_lookup as runtime_prepare_merge_acceptance_lookup,
    prepare_resolved_joins as runtime_prepare_resolved_joins,
    prepare_resolved_revoked_leaves as runtime_prepare_resolved_revoked_leaves,
};

use crate::{
    ApiError, ApiState, BarrierFetchPublicTreeRequest, BarrierIssueFullVerificationWitnessRequest,
    BarrierLookupMergeAcceptanceRequest, BarrierResolveJoinsSinceRequest,
    BarrierResolveRevokedLeavesRequest, configured_message_auth_token,
    enforce_expensive_rate_limit, enforce_message_auth_header,
    map_full_verification_witness_preparation_error, map_room_barrier_helper_preparation_error,
    message_scoped_rate_limit_key, parse_gid, protobuf_response_bytes,
};

pub(crate) async fn barrier_issue_full_verification_witness(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let request = BarrierIssueFullVerificationWitnessRequest::decode(body)?;
    if request.room_id.is_empty() {
        return Err(ApiError::InvalidRequest("room_id must be provided"));
    }
    let gid = parse_gid(&request.room_id)?;
    enforce_expensive_rate_limit(
        &state,
        "barrier_issue_full_verification_witness",
        message_scoped_rate_limit_key(&headers, &gid),
    )
    .await?;
    let witness_request =
        schema_decode_full_verification_witness_request(request).map_err(|error| match error {
            FullVerificationWitnessRequestDecodeError::InvalidAuthorLeafId
            | FullVerificationWitnessRequestDecodeError::MissingCurrentGlobalHistoryAttestation
            | FullVerificationWitnessRequestDecodeError::MissingDeploymentProfileManifest
            | FullVerificationWitnessRequestDecodeError::MissingMergeTicketArtifact
            | FullVerificationWitnessRequestDecodeError::InvalidBarrierUpdateReason
            | FullVerificationWitnessRequestDecodeError::InvalidRevocationRootsHash
            | FullVerificationWitnessRequestDecodeError::InvalidRevocationTargetLeafId
            | FullVerificationWitnessRequestDecodeError::HistoryCommitment(_) => {
                ApiError::InvalidRequest(error.api_message())
            }
        })?;
    let witness = {
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        runtime_prepare_full_verification_witness(
            &mut guard,
            &gid,
            witness_request,
            API_PROFILE_VERSION,
        )
        .map_err(|err| {
            map_full_verification_witness_preparation_error(
                "barrier_issue_full_verification_witness",
                err,
            )
        })?
    };

    Ok(protobuf_response_bytes(
        encode_full_verification_witness_response(witness),
    ))
}

pub(crate) async fn barrier_resolve_revoked_leaves(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let request = BarrierResolveRevokedLeavesRequest::decode(body)?;
    if request.room_id.is_empty() {
        return Err(ApiError::InvalidRequest("room_id must be provided"));
    }
    let gid = parse_gid(&request.room_id)?;
    enforce_expensive_rate_limit(
        &state,
        "barrier_resolve_revoked_leaves",
        message_scoped_rate_limit_key(&headers, &gid),
    )
    .await?;
    let request = schema_decode_barrier_resolve_revoked_leaves_request(request).map_err(
        |error: ResolveRevokedLeavesRequestDecodeError| {
            ApiError::InvalidRequest(error.api_message())
        },
    )?;

    let prepared = {
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        runtime_prepare_resolved_revoked_leaves(
            &mut guard,
            &gid,
            &request.revocation_roots_hash,
            request.page_offset,
            request.max_entries,
            MAX_BARRIER_HELPER_PAGE_ENTRIES,
            API_PROFILE_VERSION,
        )
        .map_err(|err| {
            map_room_barrier_helper_preparation_error("barrier_resolve_revoked_leaves", err)
        })?
    };
    Ok(protobuf_response_bytes(
        encode_prepared_resolved_revoked_leaves_response(prepared),
    ))
}

pub(crate) async fn barrier_resolve_joins_since(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let request = BarrierResolveJoinsSinceRequest::decode(body)?;
    if request.room_id.is_empty() {
        return Err(ApiError::InvalidRequest("room_id must be provided"));
    }
    let gid = parse_gid(&request.room_id)?;
    enforce_expensive_rate_limit(
        &state,
        "barrier_resolve_joins_since",
        message_scoped_rate_limit_key(&headers, &gid),
    )
    .await?;

    let prepared = {
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        runtime_prepare_resolved_joins(
            &mut guard,
            &gid,
            request.prev_barrier_version,
            request.page_offset,
            request.max_entries,
            MAX_BARRIER_HELPER_PAGE_ENTRIES,
            API_PROFILE_VERSION,
        )
        .map_err(|err| {
            map_room_barrier_helper_preparation_error("barrier_resolve_joins_since", err)
        })?
    };
    Ok(protobuf_response_bytes(
        encode_prepared_resolved_joins_response(prepared),
    ))
}

pub(crate) async fn barrier_fetch_public_tree(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let request = BarrierFetchPublicTreeRequest::decode(body)?;
    if request.room_id.is_empty() {
        return Err(ApiError::InvalidRequest("room_id must be provided"));
    }
    let gid = parse_gid(&request.room_id)?;
    enforce_expensive_rate_limit(
        &state,
        "barrier_fetch_public_tree",
        message_scoped_rate_limit_key(&headers, &gid),
    )
    .await?;
    let request = schema_decode_barrier_fetch_public_tree_request(request).map_err(
        |error: FetchPublicTreeRequestDecodeError| ApiError::InvalidRequest(error.api_message()),
    )?;

    let prepared = {
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        runtime_prepare_barrier_public_tree(
            &mut guard,
            &gid,
            &request.kem_tree_hash_after,
            request.entry_offset,
            request.max_entries,
            MAX_BARRIER_HELPER_PAGE_ENTRIES,
            API_PROFILE_VERSION,
        )
        .map_err(|err| {
            map_room_barrier_helper_preparation_error("barrier_fetch_public_tree", err)
        })?
    };
    Ok(protobuf_response_bytes(
        encode_prepared_barrier_public_tree_response(prepared),
    ))
}

pub(crate) async fn barrier_lookup_merge_acceptance(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let request = BarrierLookupMergeAcceptanceRequest::decode(body)?;
    if request.room_id.is_empty() {
        return Err(ApiError::InvalidRequest("room_id must be provided"));
    }
    let gid = parse_gid(&request.room_id)?;
    enforce_expensive_rate_limit(
        &state,
        "barrier_lookup_merge_acceptance",
        message_scoped_rate_limit_key(&headers, request.pending_we_epoch_id.as_slice()),
    )
    .await?;
    let request = schema_decode_barrier_lookup_merge_acceptance_request(request).map_err(
        |error: LookupMergeAcceptanceRequestDecodeError| {
            ApiError::InvalidRequest(error.api_message())
        },
    )?;

    let prepared = {
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        runtime_prepare_merge_acceptance_lookup(
            &mut guard,
            &gid,
            request.pending_barrier_version,
            &request.pending_barrier_update_digest,
            &request.pending_we_epoch_id,
            API_PROFILE_VERSION,
        )
        .map_err(|err| {
            map_room_barrier_helper_preparation_error("barrier_lookup_merge_acceptance", err)
        })?
    };
    Ok(protobuf_response_bytes(
        encode_prepared_merge_acceptance_lookup_response(prepared),
    ))
}
