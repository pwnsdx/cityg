use axum::{extract::Request, middleware::Next, response::Response};
use metrics::{counter, histogram};
use std::sync::OnceLock;
use std::time::Instant;

static METRICS_HANDLE: OnceLock<metrics_exporter_prometheus::PrometheusHandle> = OnceLock::new();

/// Middleware that records request metrics
pub async fn metrics_middleware(request: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = request.method().clone();
    let path = request.uri().path().to_string();

    // Increment request counter
    counter!("http_requests_total", "method" => method.to_string(), "path" => path.clone())
        .increment(1);

    // Process request
    let response = next.run(request).await;

    // Record metrics
    let latency = start.elapsed();
    let status = response.status().as_u16().to_string();

    // Record latency histogram
    histogram!(
        "http_request_duration_seconds",
        "method" => method.to_string(),
        "path" => path.clone(),
        "status" => status.clone()
    )
    .record(latency.as_secs_f64());

    // Increment status counter
    counter!(
        "http_responses_total",
        "method" => method.to_string(),
        "path" => path,
        "status" => status
    )
    .increment(1);

    response
}

/// Initialize metrics exporter
/// Uses a singleton pattern to ensure the global recorder is only installed once
pub fn init_metrics_exporter() -> anyhow::Result<metrics_exporter_prometheus::PrometheusHandle> {
    // Try to get existing handle first
    if let Some(handle) = METRICS_HANDLE.get() {
        return Ok(handle.clone());
    }

    // Try to install the recorder and store the handle
    let builder = metrics_exporter_prometheus::PrometheusBuilder::new();
    match builder.install_recorder() {
        Ok(handle) => {
            // Try to store it in the OnceLock (may fail if another thread beat us to it)
            let _ = METRICS_HANDLE.set(handle.clone());
            Ok(handle)
        }
        Err(e) => {
            // If we get here, the recorder was already installed by another call
            // Check if we have a handle stored
            if let Some(handle) = METRICS_HANDLE.get() {
                Ok(handle.clone())
            } else {
                Err(anyhow::anyhow!("Failed to install metrics recorder: {}", e))
            }
        }
    }
}
