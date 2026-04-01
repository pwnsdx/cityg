use axum::{body::Bytes, extract::State, http::HeaderMap, response::Response};
use prost::Message;

use cityg_client::{CityGError as ClientError, ClientEpochBundle};
use cityg_runtime::{
    classify_refresh_pivot_conflict, refresh_room_pivot as runtime_refresh_room_pivot,
    seed_room_window_head as runtime_seed_room_window_head,
};

use crate::{
    ApiError, ApiState, configured_message_auth_token, configured_window_admin_token,
    enforce_expensive_rate_limit, enforce_message_auth_header, enforce_window_config_auth,
    map_bundle_cbor_request_decode_error, message_scoped_rate_limit_key, protobuf_response,
    schema_decode_bundle_cbor_request,
};
use crate::{RefreshPivotRequest, RefreshPivotResponse};
#[cfg(any(debug_assertions, feature = "debug-api"))]
use crate::{SeedHeadRequest, SeedHeadResponse};

#[cfg(any(debug_assertions, feature = "debug-api"))]
pub(crate) async fn seed_window_head(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_window_config_auth(&headers, configured_window_admin_token().as_deref())?;
    let request = SeedHeadRequest::decode(body)?;
    if request.bundle_cbor.is_empty() {
        return Err(ApiError::InvalidRequest("bundle_cbor must be provided"));
    }

    let bundle = match ClientEpochBundle::from_cbor(&request.bundle_cbor) {
        Ok(bundle) => bundle,
        Err(ClientError::InvalidInput(_)) => {
            return Err(ApiError::InvalidRequest("invalid bundle encoding"));
        }
        Err(err) => return Err(ApiError::server_message(err.to_string())),
    };

    {
        let gid: [u8; 32] = bundle
            .gid()
            .try_into()
            .map_err(|_| ApiError::InvalidRequest("bundle gid must be 32 bytes"))?;
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        runtime_seed_room_window_head(&mut guard, &bundle).map_err(|err| match err {
            cityg_runtime::RoomWindowSeedError::InvalidGidLength => {
                ApiError::InvalidRequest("bundle gid must be 32 bytes")
            }
            cityg_runtime::RoomWindowSeedError::ComputeWindowId(message)
            | cityg_runtime::RoomWindowSeedError::AcceptHead(message) => {
                ApiError::server_message(message)
            }
        })?;
    }

    let reply = SeedHeadResponse {};
    Ok(protobuf_response(&reply))
}

pub(crate) async fn refresh_pivot(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let request = RefreshPivotRequest::decode(body)?;
    let bundle = schema_decode_bundle_cbor_request(&request.bundle_cbor, true)
        .map_err(map_bundle_cbor_request_decode_error)?;
    let gid: [u8; 32] = bundle
        .gid()
        .try_into()
        .map_err(|_| ApiError::InvalidRequest("bundle gid must be 32 bytes"))?;
    enforce_expensive_rate_limit(
        &state,
        "refresh_pivot",
        message_scoped_rate_limit_key(&headers, &gid),
    )
    .await?;

    {
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        runtime_refresh_room_pivot(&mut guard, &bundle).map_err(|err| match err {
            ClientError::InvalidInput(
                "pivot parity missing for refresh"
                | "pivot head missing"
                | "refresh payload diverges from stored parity",
            ) => {
                if let Some(reason) = classify_refresh_pivot_conflict(&err.to_string()) {
                    metrics::counter!(
                        "cityg_refresh_pivot_conflict_total",
                        "reason" => reason.to_string()
                    )
                    .increment(1);
                }
                ApiError::conflict(err.to_string())
            }
            other => ApiError::server_message(other.to_string()),
        })?;
    }

    let reply = RefreshPivotResponse {};
    Ok(protobuf_response(&reply))
}
