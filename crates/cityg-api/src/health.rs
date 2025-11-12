// Health check types and handlers
//
// Note: These types are defined here for reusability, but the actual health
// endpoints are implemented directly in lib.rs for simplicity. This module
// provides the foundation for more sophisticated health checking in the future.

#![allow(dead_code)]

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug)]
pub struct HealthResponse {
    pub status: HealthStatus,
    pub timestamp: u64,
    pub version: String,
    pub uptime_seconds: u64,
    pub checks: Vec<HealthCheck>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HealthCheck {
    pub name: String,
    pub status: HealthStatus,
    pub message: Option<String>,
    pub latency_ms: Option<u64>,
}

#[derive(Clone)]
pub struct HealthState {
    pub start_time: std::time::Instant,
}

impl HealthState {
    pub fn new() -> Self {
        Self {
            start_time: std::time::Instant::now(),
        }
    }
}

impl Default for HealthState {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn health_check_handler(State(health_state): State<HealthState>) -> Response {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let uptime_seconds = health_state.start_time.elapsed().as_secs();

    let checks = vec![HealthCheck {
        name: "system".to_string(),
        status: HealthStatus::Healthy,
        message: Some("Service is running".to_string()),
        latency_ms: None,
    }];

    // Determine overall status
    let overall_status = if checks.iter().any(|c| c.status == HealthStatus::Unhealthy) {
        HealthStatus::Unhealthy
    } else if checks.iter().any(|c| c.status == HealthStatus::Degraded) {
        HealthStatus::Degraded
    } else {
        HealthStatus::Healthy
    };

    let response = HealthResponse {
        status: overall_status,
        timestamp,
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds,
        checks,
    };

    let status_code = match overall_status {
        HealthStatus::Healthy => StatusCode::OK,
        HealthStatus::Degraded => StatusCode::OK,
        HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };

    (status_code, Json(response)).into_response()
}

pub async fn readiness_check_handler(State(_health_state): State<HealthState>) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ready": true
        })),
    )
        .into_response()
}

pub async fn liveness_check_handler() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "alive": true
        })),
    )
        .into_response()
}
