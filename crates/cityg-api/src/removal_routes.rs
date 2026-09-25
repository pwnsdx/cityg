//! Signed removal proposals (audit C-03): a member leaves by submitting a
//! proposal that another member commits with a LEAVE merge ticket.

use axum::{body::Bytes, extract::State, http::HeaderMap, response::Response};
use prost::Message;

use cityg_api_schema::{
    RemoveProposalRequestValidationError,
    validate_pending_remove_proposals_request as schema_validate_pending_remove_proposals_request,
    validate_submit_remove_proposal_request as schema_validate_submit_remove_proposal_request,
};
use cityg_client::CityGError as ClientError;
use cityg_runtime::{
    pending_remove_proposals as runtime_pending_remove_proposals,
    submit_remove_proposal as runtime_submit_remove_proposal,
};

use crate::{
    ApiError, ApiState, MESSAGE_AUTH_HEADER, PendingRemoveProposalsRequest,
    PendingRemoveProposalsResponse, SubmitRemoveProposalRequest, SubmitRemoveProposalResponse,
    configured_message_auth_token, enforce_expensive_rate_limit, enforce_message_auth_header,
    fingerprint_rate_limit_parts, protobuf_response,
};

pub(crate) fn map_remove_proposal_request_validation_error(
    err: RemoveProposalRequestValidationError,
) -> ApiError {
    match err {
        RemoveProposalRequestValidationError::MissingRoomId => {
            ApiError::InvalidRequest("room_id must be provided")
        }
        RemoveProposalRequestValidationError::InvalidRoomIdEncoding => {
            ApiError::InvalidRequest("room_id must be 64 hex characters")
        }
        RemoveProposalRequestValidationError::InvalidRoomIdLength => {
            ApiError::InvalidRequest("room_id must be 32 bytes")
        }
        RemoveProposalRequestValidationError::MissingProposal => {
            ApiError::InvalidRequest("signed_proposal must be provided")
        }
        RemoveProposalRequestValidationError::ProposalTooLarge { .. } => {
            ApiError::InvalidRequest("signed_proposal is too large")
        }
    }
}

pub(crate) async fn submit_remove_proposal(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let request =
        schema_validate_submit_remove_proposal_request(SubmitRemoveProposalRequest::decode(body)?)
            .map_err(map_remove_proposal_request_validation_error)?;
    enforce_expensive_rate_limit(
        &state,
        "remove_proposal",
        fingerprint_rate_limit_parts(&[
            headers
                .get(MESSAGE_AUTH_HEADER)
                .map(|value| value.as_bytes())
                .unwrap_or_default(),
            &request.gid,
            &request.signed_proposal,
        ]),
    )
    .await?;
    let submission = {
        let lane = state.server_for_gid(&request.gid);
        let mut guard = lane.write().await;
        runtime_submit_remove_proposal(&mut guard, &request.gid, &request.signed_proposal).map_err(
            |err| match err {
                ClientError::InvalidInput(message) => ApiError::InvalidRequest(message),
                other => ApiError::from(other),
            },
        )?
    };
    metrics::counter!("cityg_remove_proposal_total", "result" => "ok").increment(1);
    Ok(protobuf_response(&SubmitRemoveProposalResponse {
        status: submission.status().to_string(),
    }))
}

pub(crate) async fn pending_remove_proposals(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let request = schema_validate_pending_remove_proposals_request(
        PendingRemoveProposalsRequest::decode(body)?,
    )
    .map_err(map_remove_proposal_request_validation_error)?;
    let signed_proposals = {
        let lane = state.server_for_gid(&request.gid);
        let mut guard = lane.write().await;
        runtime_pending_remove_proposals(&mut guard, &request.gid)
    };
    Ok(protobuf_response(&PendingRemoveProposalsResponse {
        signed_proposals,
    }))
}
