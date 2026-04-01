use axum::{body::Bytes, extract::State, http::HeaderMap, response::Response};
use prost::Message;

use cityg_api_schema::validate_get_bundle_request as schema_validate_get_bundle_request;

use crate::{
    ApiError, ApiState, GetBundleRequest, GetBundleResponse, MESSAGE_PRUNE_INTERVAL_MS,
    configured_message_auth_token, current_timestamp_ms, enforce_expensive_rate_limit,
    enforce_message_auth_header, map_get_bundle_request_validation_error,
    message_scoped_rate_limit_key, protobuf_response,
};

pub(crate) async fn get_bundle(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let request = schema_validate_get_bundle_request(GetBundleRequest::decode(body)?)
        .map_err(map_get_bundle_request_validation_error)?;
    enforce_expensive_rate_limit(
        &state,
        "get_bundle",
        message_scoped_rate_limit_key(&headers, &request.we_epoch_id),
    )
    .await?;

    let now_ms = current_timestamp_ms();
    let bundle = {
        let mut room_state = state.room_state.write().await;
        cityg_runtime::fetch_room_bundle(
            &mut room_state,
            &request.we_epoch_id,
            now_ms,
            state.message_retention,
            MESSAGE_PRUNE_INTERVAL_MS,
        )
    };
    let bytes = bundle.ok_or(ApiError::NotFound)?.bytes;

    let reply = GetBundleResponse { bundle_cbor: bytes };

    Ok(protobuf_response(&reply))
}
