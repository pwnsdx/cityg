use std::time::Duration;

use axum::http::HeaderMap;
use hex::FromHex;
use tracing::warn;

use crate::{
    ACCEPT_EPOCH_MAX_IN_FLIGHT_ENV, ALLOW_INSECURE_ADMIN_ENV, ApiError,
    DEFAULT_ACCEPT_EPOCH_MAX_IN_FLIGHT, DEFAULT_EXPENSIVE_RATE_LIMIT_BURST,
    DEFAULT_EXPENSIVE_RATE_LIMIT_MAX_KEYS, DEFAULT_EXPENSIVE_RATE_LIMIT_WINDOW_SECS,
    DEFAULT_GROUP_LANES, DEFAULT_JOIN_TICKET_MAX_IN_FLIGHT, EXPENSIVE_RATE_LIMIT_BURST_ENV,
    EXPENSIVE_RATE_LIMIT_MAX_KEYS_ENV, EXPENSIVE_RATE_LIMIT_WINDOW_SECS_ENV, GROUP_LANES_ENV,
    JOIN_TICKET_MAX_IN_FLIGHT_ENV, MESSAGE_AUTH_HEADER, MESSAGE_AUTH_TOKEN_ENV,
    ROOMS_ADMIN_TOKEN_ENV, WINDOW_CONFIG_ADMIN_HEADER, WINDOW_CONFIG_ADMIN_TOKEN_ENV,
    WS_MAX_LAG_DEFAULT, WS_MAX_LAG_ENV,
};

pub(crate) fn parse_gid(room_id: &str) -> Result<[u8; 32], ApiError> {
    let bytes = Vec::from_hex(room_id)
        .map_err(|_| ApiError::InvalidRequest("room_id must be 64 hex characters"))?;
    if bytes.len() != 32 {
        return Err(ApiError::InvalidRequest("room_id must be 32 bytes"));
    }
    let mut gid = [0u8; 32];
    gid.copy_from_slice(&bytes);
    Ok(gid)
}

pub(crate) fn parse_hex_32(label: &'static str, value: &str) -> Result<[u8; 32], ApiError> {
    let bytes = Vec::from_hex(value).map_err(|_| ApiError::InvalidRequest(label))?;
    if bytes.len() != 32 {
        return Err(ApiError::InvalidRequest(label));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(crate) fn configured_window_admin_token() -> Option<String> {
    std::env::var(WINDOW_CONFIG_ADMIN_TOKEN_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn configured_rooms_admin_token() -> Option<String> {
    std::env::var(ROOMS_ADMIN_TOKEN_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(configured_window_admin_token)
}

pub(crate) fn configured_message_auth_token() -> Option<String> {
    std::env::var(MESSAGE_AUTH_TOKEN_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn parse_bool_env(raw: Option<String>) -> bool {
    raw.map(|value| value.trim().to_ascii_lowercase())
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

pub(crate) fn allow_insecure_admin() -> bool {
    parse_bool_env(std::env::var(ALLOW_INSECURE_ADMIN_ENV).ok())
}

pub(crate) fn warn_if_admin_auth_is_open() {
    if !allow_insecure_admin() {
        return;
    }
    if configured_rooms_admin_token().is_none() {
        warn!(
            "{}=true with no {} or {} configured; insecure admin bypass is ignored and room admin endpoints remain unavailable",
            ALLOW_INSECURE_ADMIN_ENV, ROOMS_ADMIN_TOKEN_ENV, WINDOW_CONFIG_ADMIN_TOKEN_ENV
        );
    }
    if configured_window_admin_token().is_none() {
        warn!(
            "{}=true with no {} configured; insecure admin bypass is ignored and window admin endpoints remain unavailable",
            ALLOW_INSECURE_ADMIN_ENV, WINDOW_CONFIG_ADMIN_TOKEN_ENV
        );
    }
}

pub(crate) fn enforce_admin_token_with_policy(
    headers: &HeaderMap,
    expected_token: Option<&str>,
    allow_insecure: bool,
) -> Result<(), ApiError> {
    let Some(expected_token) = expected_token else {
        if allow_insecure {
            warn!(
                "{}=true was set without an admin token; refusing unauthenticated admin access",
                ALLOW_INSECURE_ADMIN_ENV
            );
        }
        return Err(ApiError::Unauthorized("admin token is not configured"));
    };
    let provided = headers
        .get(WINDOW_CONFIG_ADMIN_HEADER)
        .and_then(|value| value.to_str().ok());
    if provided == Some(expected_token) {
        Ok(())
    } else {
        Err(ApiError::Unauthorized("missing or invalid admin token"))
    }
}

pub(crate) fn enforce_admin_token(
    headers: &HeaderMap,
    expected_token: Option<&str>,
) -> Result<(), ApiError> {
    enforce_admin_token_with_policy(headers, expected_token, allow_insecure_admin())
}

pub(crate) fn enforce_window_config_auth(
    headers: &HeaderMap,
    expected_token: Option<&str>,
) -> Result<(), ApiError> {
    enforce_admin_token(headers, expected_token)
}

pub(crate) fn enforce_message_auth_header(
    headers: &HeaderMap,
    expected_token: Option<&str>,
) -> Result<(), ApiError> {
    let Some(expected_token) = expected_token else {
        return Err(ApiError::Unauthorized(
            "message auth token is not configured",
        ));
    };
    let provided = headers
        .get(MESSAGE_AUTH_HEADER)
        .and_then(|value| value.to_str().ok());
    if provided == Some(expected_token) {
        Ok(())
    } else {
        Err(ApiError::Unauthorized(
            "missing or invalid message auth token",
        ))
    }
}

pub(crate) fn enforce_message_auth_query(
    provided: Option<&str>,
    expected_token: Option<&str>,
) -> Result<(), ApiError> {
    let Some(expected_token) = expected_token else {
        return Err(ApiError::Unauthorized(
            "message auth token is not configured",
        ));
    };
    if provided == Some(expected_token) {
        Ok(())
    } else {
        Err(ApiError::Unauthorized(
            "missing or invalid message auth token",
        ))
    }
}

pub(crate) fn enforce_message_auth_websocket(
    headers: &HeaderMap,
    expected_token: Option<&str>,
) -> Result<(), ApiError> {
    enforce_message_auth_query(
        headers
            .get(MESSAGE_AUTH_HEADER)
            .and_then(|value| value.to_str().ok()),
        expected_token,
    )
}

pub(crate) fn parse_ws_max_lag(raw: Option<&str>) -> u64 {
    raw.and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(WS_MAX_LAG_DEFAULT)
}

pub(crate) fn configured_accept_epoch_max_in_flight() -> usize {
    std::env::var(ACCEPT_EPOCH_MAX_IN_FLIGHT_ENV)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_ACCEPT_EPOCH_MAX_IN_FLIGHT)
}

pub(crate) fn configured_join_ticket_max_in_flight() -> usize {
    std::env::var(JOIN_TICKET_MAX_IN_FLIGHT_ENV)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_JOIN_TICKET_MAX_IN_FLIGHT)
}

pub(crate) fn configured_expensive_rate_limit_burst() -> u32 {
    std::env::var(EXPENSIVE_RATE_LIMIT_BURST_ENV)
        .ok()
        .and_then(|raw| raw.parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_EXPENSIVE_RATE_LIMIT_BURST)
}

pub(crate) fn configured_expensive_rate_limit_window() -> Duration {
    std::env::var(EXPENSIVE_RATE_LIMIT_WINDOW_SECS_ENV)
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_EXPENSIVE_RATE_LIMIT_WINDOW_SECS))
}

pub(crate) fn configured_expensive_rate_limit_max_keys() -> usize {
    std::env::var(EXPENSIVE_RATE_LIMIT_MAX_KEYS_ENV)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_EXPENSIVE_RATE_LIMIT_MAX_KEYS)
}

pub(crate) fn configured_ws_max_lag() -> u64 {
    let raw = std::env::var(WS_MAX_LAG_ENV).ok();
    parse_ws_max_lag(raw.as_deref())
}

pub(crate) fn configured_group_lane_count() -> usize {
    std::env::var(GROUP_LANES_ENV)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_GROUP_LANES)
}
