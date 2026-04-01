use axum::{body::Bytes, extract::State, http::HeaderMap, response::Response};
use prost::Message;

use cityg_api_schema::{
    API_PROFILE_VERSION, encode_list_room_admins_response, encode_prepared_merge_ticket_response,
    encode_room_admin_mutation_response, encode_rotate_room_kbroad_response,
    validate_expel_member_ticket_request as schema_validate_expel_member_ticket_request,
    validate_list_room_admins_request as schema_validate_list_room_admins_request,
    validate_room_admin_mutation_request as schema_validate_room_admin_mutation_request,
    validate_rotate_room_kbroad_request as schema_validate_rotate_room_kbroad_request,
};
use cityg_client::CityGError as ClientError;
use cityg_runtime::{
    grant_room_admin as runtime_grant_room_admin, list_room_admins as runtime_list_room_admins,
    prepare_expel_member_ticket as runtime_prepare_expel_member_ticket,
    revoke_room_admin as runtime_revoke_room_admin,
    rotate_room_kbroad as runtime_rotate_room_kbroad,
};

use crate::{
    ApiError, ApiState, ExpelMemberTicketRequest, ListRoomAdminsRequest, RoomAdminMutationRequest,
    RotateRoomKbroadRequest, encode_room_admin_leaf_pair_payload, enforce_expensive_rate_limit,
    fingerprint_rate_limit_parts, map_expel_member_ticket_request_validation_error,
    map_room_admin_request_validation_error, map_room_ticket_preparation_error,
    protobuf_response_bytes, room_admin_proof_replay_key, verify_room_admin_proof,
    verify_room_admin_proof_payload,
};

pub(crate) async fn rotate_room_kbroad(
    State(state): State<ApiState>,
    _headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request =
        schema_validate_rotate_room_kbroad_request(RotateRoomKbroadRequest::decode(body)?)
            .map_err(map_room_admin_request_validation_error)?;
    let replay_key = room_admin_proof_replay_key(&request.admin_proof)?;
    let kbroad_generation = {
        let lane = state.server_for_gid(&request.gid);
        let mut guard = lane.write().await;
        let actor_pop_key = verify_room_admin_proof(
            &request.admin_proof,
            "rotate_room_kbroad_v1",
            &request.room_id,
            &request.kbroad_public,
        )?;
        runtime_rotate_room_kbroad(
            &mut guard,
            &request.gid,
            request.kbroad_public,
            &actor_pop_key,
            replay_key,
        )
        .map_err(|err| match err {
            ClientError::InvalidInput(message) => ApiError::InvalidRequest(message),
            other => ApiError::from(other),
        })?
    };

    Ok(protobuf_response_bytes(encode_rotate_room_kbroad_response(
        "rotated",
        kbroad_generation,
    )))
}

pub(crate) async fn grant_room_admin(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request =
        schema_validate_room_admin_mutation_request(RoomAdminMutationRequest::decode(body)?)
            .map_err(map_room_admin_request_validation_error)?;
    let replay_key = room_admin_proof_replay_key(&request.admin_proof)?;
    let actor_pop_key = verify_room_admin_proof_payload(
        &request.admin_proof,
        "grant_room_admin_v1",
        &request.room_id,
        &request.target_pop_public_key,
    )?;
    let (granted, admin_count) = {
        let lane = state.server_for_gid(&request.gid);
        let mut guard = lane.write().await;
        runtime_grant_room_admin(
            &mut guard,
            &request.gid,
            &actor_pop_key,
            request.target_pop_public_key,
            replay_key,
        )
        .map_err(|err| match err {
            ClientError::InvalidInput(message) => ApiError::InvalidRequest(message),
            other => ApiError::from(other),
        })?
    };

    Ok(protobuf_response_bytes(
        encode_room_admin_mutation_response(
            if granted {
                "granted"
            } else {
                "already_granted"
            },
            admin_count,
        ),
    ))
}

pub(crate) async fn revoke_room_admin(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request =
        schema_validate_room_admin_mutation_request(RoomAdminMutationRequest::decode(body)?)
            .map_err(map_room_admin_request_validation_error)?;
    let replay_key = room_admin_proof_replay_key(&request.admin_proof)?;
    let actor_pop_key = verify_room_admin_proof_payload(
        &request.admin_proof,
        "revoke_room_admin_v1",
        &request.room_id,
        &request.target_pop_public_key,
    )?;
    let (revoked, admin_count) = {
        let lane = state.server_for_gid(&request.gid);
        let mut guard = lane.write().await;
        runtime_revoke_room_admin(
            &mut guard,
            &request.gid,
            &actor_pop_key,
            &request.target_pop_public_key,
            replay_key,
        )
        .map_err(|err| match err {
            ClientError::InvalidInput(message) => ApiError::InvalidRequest(message),
            other => ApiError::from(other),
        })?
    };

    Ok(protobuf_response_bytes(
        encode_room_admin_mutation_response(
            if revoked {
                "revoked"
            } else {
                "already_revoked"
            },
            admin_count,
        ),
    ))
}

pub(crate) async fn list_room_admins(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request = schema_validate_list_room_admins_request(ListRoomAdminsRequest::decode(body)?)
        .map_err(map_room_admin_request_validation_error)?;
    let actor_pop_key = verify_room_admin_proof_payload(
        &request.admin_proof,
        "list_room_admins_v1",
        &request.room_id,
        &[],
    )?;
    let admin_pop_public_keys = {
        let lane = state.server_for_gid(&request.gid);
        let guard = lane.read().await;
        runtime_list_room_admins(&guard, &request.gid, &actor_pop_key).map_err(|err| match err {
            ClientError::InvalidInput(message) => ApiError::InvalidRequest(message),
            other => ApiError::from(other),
        })?
    };

    Ok(protobuf_response_bytes(encode_list_room_admins_response(
        admin_pop_public_keys,
    )))
}

pub(crate) async fn expel_member_ticket(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request =
        schema_validate_expel_member_ticket_request(ExpelMemberTicketRequest::decode(body)?)
            .map_err(map_expel_member_ticket_request_validation_error)?;
    let payload =
        encode_room_admin_leaf_pair_payload(&request.author_leaf_id, &request.target_leaf_id)?;
    let replay_key = room_admin_proof_replay_key(&request.admin_proof)?;
    let actor_pop_key = verify_room_admin_proof_payload(
        &request.admin_proof,
        "expel_room_member_v1",
        &request.room_id,
        &payload,
    )?;
    enforce_expensive_rate_limit(
        &state,
        "expel_member_ticket",
        fingerprint_rate_limit_parts(&[
            &request.gid,
            &request.author_leaf_id,
            &request.target_leaf_id,
            actor_pop_key.as_slice(),
        ]),
    )
    .await?;

    let prepared = {
        let lane = state.server_for_gid(&request.gid);
        let mut guard = lane.write().await;
        runtime_prepare_expel_member_ticket(
            &mut guard,
            &request.gid,
            &actor_pop_key,
            &request.author_leaf_id,
            &request.target_leaf_id,
            replay_key,
            API_PROFILE_VERSION,
        )
        .map_err(|err| map_room_ticket_preparation_error("expel_member_ticket", err))?
    };

    Ok(protobuf_response_bytes(
        encode_prepared_merge_ticket_response(prepared),
    ))
}
