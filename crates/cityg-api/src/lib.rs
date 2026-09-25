#![forbid(unsafe_code)]

//! Native HTTP server of the City-G v0.2 delivery service.
//!
//! It serves the delivery-service API (`/v2/groups/*` and the `/v2/ws`
//! log-head notifications, see [`routes`]), health checks and Prometheus
//! metrics. The server relays and orders protocol objects; it never holds a
//! group secret.

pub mod health;
mod middleware;
pub mod routes;

use std::net::SocketAddr;

use axum::{Router, middleware as axum_middleware, routing::get};
use cityg_config::CityGConfig;
use cityg_runtime::{NativeRoomStore, ServiceConfig};
use metrics_exporter_prometheus::PrometheusHandle;
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

pub use middleware::metric_path;

/// Load the configuration (file and environment) and serve it.
pub async fn run() -> anyhow::Result<()> {
    let config = CityGConfig::load()
        .map_err(|error| anyhow::anyhow!("failed to load configuration: {error}"))?;
    config
        .validate()
        .map_err(|error| anyhow::anyhow!("configuration validation failed: {error}"))?;
    let addr = config.server.address.parse().map_err(|error| {
        anyhow::anyhow!(
            "failed to parse server address '{}': {error}",
            config.server.address
        )
    })?;
    run_with_config(addr, config).await
}

/// Serve the default configuration on `addr`.
pub async fn run_with_addr(addr: SocketAddr) -> anyhow::Result<()> {
    run_with_config(addr, CityGConfig::default()).await
}

/// The application: health checks, metrics and the delivery-service routes.
pub fn app(config: &CityGConfig, metrics: Option<PrometheusHandle>) -> anyhow::Result<Router> {
    let store = NativeRoomStore::for_state_path(config.server.state_path.as_deref())?;
    let state = routes::ServiceState::new(
        ServiceConfig::from_config(config),
        store,
        config.server.websocket_capacity,
    );
    let with_metrics = metrics.is_some();
    let metrics_route = match metrics {
        Some(handle) => get(move || {
            let handle = handle.clone();
            async move { handle.render() }
        }),
        None => get(|| async { "metrics not available" }),
    };
    let mut app = Router::new()
        .merge(health::router())
        .route("/metrics", metrics_route)
        .merge(routes::router(state))
        .layer(axum_middleware::from_fn(
            middleware::request_tracing_middleware,
        ));
    if with_metrics {
        app = app.layer(axum_middleware::from_fn(middleware::metrics_middleware));
    }
    Ok(app)
}

/// Serve `config` on `addr`.
pub async fn run_with_config(addr: SocketAddr, config: CityGConfig) -> anyhow::Result<()> {
    init_logging()?;
    let metrics = match middleware::init_metrics_exporter() {
        Ok(handle) => Some(handle),
        Err(error) => {
            warn!("metrics exporter disabled: {error}");
            None
        }
    };
    let app = app(&config, metrics)?;
    match &config.server.state_path {
        Some(path) => info!("rooms are journaled under {}", path.display()),
        None => warn!("no state path configured: rooms live in memory only"),
    }
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("listening on {addr} (metrics at /metrics, health at /health/detailed)");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Human-readable logs, or JSON with `LOG_FORMAT=json`.
fn init_logging() -> anyhow::Result<()> {
    let env_filter = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new("info"))?;
    let json = std::env::var("LOG_FORMAT").is_ok_and(|value| value.eq_ignore_ascii_case("json"));
    // A subscriber may already be installed (tests): keep it.
    if json {
        let _ = tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().json())
            .try_init();
    } else {
        let _ = tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer())
            .try_init();
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::*;

    async fn get_status(app: &Router, path: &str) -> (StatusCode, String) {
        let response = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test]
    async fn the_app_serves_health_metrics_and_the_api() {
        let config = CityGConfig::default();
        let metrics = middleware::init_metrics_exporter().ok();
        let app = app(&config, metrics).unwrap();
        for path in [
            "/health",
            "/health/live",
            "/health/ready",
            "/health/detailed",
        ] {
            assert_eq!(get_status(&app, path).await.0, StatusCode::OK, "{path}");
        }
        let (status, body) = get_status(&app, "/health/detailed").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"status\":\"healthy\""));
        assert_eq!(get_status(&app, "/metrics").await.0, StatusCode::OK);
        assert_eq!(get_status(&app, "/nope").await.0, StatusCode::NOT_FOUND);
        // The API is POST-only; a malformed body is a 400.
        let response = app
            .clone()
            .oneshot(
                Request::post("/v2/groups/info")
                    .body(Body::from(vec![0xFF, 0xFF]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let bare = app_without_metrics();
        assert_eq!(
            get_status(&bare, "/metrics").await.1,
            "metrics not available"
        );
    }

    fn app_without_metrics() -> Router {
        app(&CityGConfig::default(), None).unwrap()
    }

    #[test]
    fn logging_initializes_twice() {
        init_logging().unwrap();
        init_logging().unwrap();
    }
}
