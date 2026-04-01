use std::time::Duration;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};
use bytes::BytesMut;
use cityg_api_schema::{
    encode_telemetry_snapshot_response, encode_window_snapshot_response,
    pb::{
        ConfigureWindowRequest, ConfigureWindowResponse, GetTelemetryRequest, GetWindowRequest,
        HealthResponse,
    },
};
use prost::Message;
use tracing::error;

use cityg_runtime::{
    apply_room_window_limit_update as runtime_apply_room_window_limit_update,
    parse_room_window_limit_update as runtime_parse_room_window_limit_update,
    snapshot_room_telemetry as runtime_snapshot_room_telemetry,
    snapshot_room_window as runtime_snapshot_room_window,
};

use crate::{
    ApiError, ApiState, configured_message_auth_token, configured_window_admin_token,
    enforce_expensive_rate_limit, enforce_message_auth_header, enforce_window_config_auth,
    message_scoped_rate_limit_key,
};

pub(crate) async fn health_legacy_with_state(State(_state): State<ApiState>) -> Response {
    let reply = HealthResponse {
        status: "ok".to_string(),
    };
    protobuf_response(&reply)
}

pub(crate) async fn health_liveness(State(_state): State<ApiState>) -> Response {
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "alive": true
        })),
    )
        .into_response()
}

pub(crate) async fn health_readiness(State(_state): State<ApiState>) -> Response {
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "ready": true
        })),
    )
        .into_response()
}

pub(crate) async fn health_detailed(State(_state): State<ApiState>) -> Response {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "status": "healthy",
            "timestamp": timestamp,
            "version": env!("CARGO_PKG_VERSION"),
            "checks": [
                {
                    "name": "system",
                    "status": "healthy",
                    "message": "Service is running"
                }
            ]
        })),
    )
        .into_response()
}

pub(crate) async fn get_window(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let _ = GetWindowRequest::decode(body)?;
    enforce_expensive_rate_limit(
        &state,
        "get_window",
        message_scoped_rate_limit_key(&headers, b"window"),
    )
    .await?;
    let mut snapshot = Vec::new();
    for lane in state.all_server_lanes() {
        let guard = lane.read().await;
        snapshot.extend(runtime_snapshot_room_window(&guard));
    }

    Ok(protobuf_response_bytes(encode_window_snapshot_response(
        snapshot,
    )))
}

pub(crate) async fn get_telemetry(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let _ = GetTelemetryRequest::decode(body)?;
    enforce_expensive_rate_limit(
        &state,
        "get_telemetry",
        message_scoped_rate_limit_key(&headers, b"telemetry"),
    )
    .await?;
    let mut report = Vec::new();
    for lane in state.all_server_lanes() {
        let guard = lane.read().await;
        report.extend(runtime_snapshot_room_telemetry(&guard));
    }

    let freeze_stats = state.freeze_stats().await;
    Ok(protobuf_response_bytes(encode_telemetry_snapshot_response(
        report,
        freeze_stats,
    )))
}

pub(crate) async fn configure_window(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_window_config_auth(&headers, configured_window_admin_token().as_deref())?;
    let request = ConfigureWindowRequest::decode(body)?;
    let update = runtime_parse_room_window_limit_update(request.h_max, request.ttl_ms)
        .map_err(|err| ApiError::InvalidRequest(err.api_message()))?;

    let (effective_h, effective_ttl) = {
        let mut effective: Option<(usize, Duration)> = None;
        for lane in state.all_server_lanes() {
            let mut guard = lane.write().await;
            let applied = runtime_apply_room_window_limit_update(&mut guard, update);
            if effective.is_none() {
                effective = Some((applied.h_max, applied.ttl));
            }
        }
        effective.unwrap_or((0, Duration::from_secs(0)))
    };

    let ttl_ms = effective_ttl.as_millis().min(u128::from(u32::MAX)) as u32;

    let reply = ConfigureWindowResponse {
        h_max: effective_h as u32,
        ttl_ms,
    };
    Ok(protobuf_response(&reply))
}

pub(crate) fn protobuf_response<M: Message>(message: &M) -> Response {
    let mut buf = BytesMut::new();
    buf.reserve(message.encoded_len());

    if let Err(e) = message.encode(&mut buf) {
        error!("failed to encode protobuf response: {}", e);
        return ApiError::server_message("Failed to encode response").into_response();
    }

    let mut response = Response::new(buf.freeze().into());
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-protobuf"),
    );
    response
}

pub(crate) fn protobuf_response_bytes(payload: Vec<u8>) -> Response {
    let mut response = Response::new(payload.into());
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-protobuf"),
    );
    response
}
