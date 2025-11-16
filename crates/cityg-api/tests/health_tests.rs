use axum::{extract::State, http::StatusCode};
use cityg_api::health::{
    HealthState, HealthStatus, health_check_handler, liveness_check_handler,
    readiness_check_handler,
};

#[tokio::test]
async fn test_health_check_handler_returns_healthy() {
    let state = HealthState::new();
    let response = health_check_handler(State(state)).await;

    // Should return 200 OK for healthy status
    let (parts, _body) = response.into_parts();
    assert_eq!(parts.status, StatusCode::OK);
}

#[tokio::test]
async fn test_liveness_check_handler() {
    let response = liveness_check_handler().await;
    let (parts, _body) = response.into_parts();
    assert_eq!(parts.status, StatusCode::OK);
}

#[tokio::test]
async fn test_readiness_check_handler() {
    let state = HealthState::new();
    let response = readiness_check_handler(State(state)).await;
    let (parts, _body) = response.into_parts();
    assert_eq!(parts.status, StatusCode::OK);
}

#[test]
fn test_health_state_new() {
    let state = HealthState::new();
    // Should be able to create new health state
    let elapsed = state.start_time.elapsed();
    assert!(elapsed.as_secs() < 1);
}

#[test]
fn test_health_state_default() {
    let state = HealthState::default();
    let elapsed = state.start_time.elapsed();
    assert!(elapsed.as_secs() < 1);
}

#[test]
fn test_health_status_serialization() -> Result<(), Box<dyn std::error::Error>> {
    use serde_json;

    let healthy = HealthStatus::Healthy;
    let json = serde_json::to_string(&healthy)?;
    assert_eq!(json, "\"healthy\"");

    let degraded = HealthStatus::Degraded;
    let json = serde_json::to_string(&degraded)?;
    assert_eq!(json, "\"degraded\"");

    let unhealthy = HealthStatus::Unhealthy;
    let json = serde_json::to_string(&unhealthy)?;
    assert_eq!(json, "\"unhealthy\"");

    Ok(())
}
