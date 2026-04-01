use axum::{body::Bytes, extract::State, response::Response};
use prost::Message;

use crate::{
    AcceptEpochRequest, ApiError, ApiState, accept_epoch_rate_limit_key, apply_bundle,
    enforce_expensive_rate_limit, map_bundle_cbor_request_decode_error, protobuf_response,
    schema_decode_bundle_cbor_request,
};

pub(crate) async fn accept_epoch(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let _permit = state.accept_epoch_limiter.try_acquire()?;
    let request = AcceptEpochRequest::decode(body)?;
    let bundle = schema_decode_bundle_cbor_request(&request.bundle_cbor, false)
        .map_err(map_bundle_cbor_request_decode_error)?;
    enforce_expensive_rate_limit(&state, "accept_epoch", accept_epoch_rate_limit_key(&bundle))
        .await?;

    let response = apply_bundle(&state, &bundle).await?;
    Ok(protobuf_response(&response))
}
