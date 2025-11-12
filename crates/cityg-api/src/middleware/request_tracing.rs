use axum::{
    extract::Request,
    http::{HeaderMap, HeaderValue},
    middleware::Next,
    response::Response,
};
use std::time::Instant;
use tracing::{Instrument, info, info_span};
use uuid::Uuid;

/// HTTP header name for request ID
pub const X_REQUEST_ID: &str = "x-request-id";

/// Middleware that adds request tracing with correlation IDs
pub async fn request_tracing_middleware(mut request: Request, next: Next) -> Response {
    let start = Instant::now();

    // Extract or generate request ID
    let request_id = request
        .headers()
        .get(X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(Uuid::new_v4);

    // Add request ID to request extensions for use in handlers
    request.extensions_mut().insert(RequestId(request_id));

    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path().to_string();

    // Create a span for this request
    let span = info_span!(
        "http_request",
        method = %method,
        path = %path,
        request_id = %request_id,
    );

    // Process the request within the span
    async move {
        info!("request started");
        let response = next.run(request).await;
        let latency_ms = start.elapsed().as_millis();
        let status = response.status();

        info!(
            status = %status,
            latency_ms = %latency_ms,
            "request completed"
        );

        // Add request ID to response headers
        let (mut parts, body) = response.into_parts();
        parts.headers.insert(
            X_REQUEST_ID,
            HeaderValue::from_str(&request_id.to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("invalid")),
        );

        Response::from_parts(parts, body)
    }
    .instrument(span)
    .await
}

/// Request ID extracted from headers or generated
#[derive(Clone, Copy, Debug)]
pub struct RequestId(pub Uuid);

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Extract request ID from request extensions
#[allow(dead_code)]
pub fn get_request_id(headers: &HeaderMap) -> Option<RequestId> {
    headers
        .get(X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .map(RequestId)
}
