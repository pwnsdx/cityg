use axum::{
    extract::Request,
    http::{HeaderMap, HeaderValue},
    middleware::Next,
    response::Response,
};
use std::time::Instant;
use tracing::{Instrument, info, info_span, warn};
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
        let request_id_text = request_id.to_string();
        if let Ok(request_id_header) = HeaderValue::from_str(&request_id_text) {
            parts.headers.insert(X_REQUEST_ID, request_id_header);
        } else {
            warn!(
                request_id = %request_id,
                "failed to encode request id header"
            );
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, middleware, routing::get};
    use std::net::SocketAddr;
    use tokio::net::TcpListener;
    use tokio::time::{Duration, sleep};
    use uuid::Uuid;

    async fn send_health_request(
        addr: SocketAddr,
        request_id: Option<String>,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/health");
        let mut last_connect_err = None;

        for _ in 0..20 {
            let mut request = client.get(&url);
            if let Some(value) = &request_id {
                request = request.header(X_REQUEST_ID, value);
            }

            match request.send().await {
                Ok(response) => return Ok(response),
                Err(err) if err.is_connect() => {
                    last_connect_err = Some(err);
                    sleep(Duration::from_millis(20)).await;
                }
                Err(err) => return Err(err),
            }
        }

        Err(last_connect_err.expect("at least one connect error should be recorded"))
    }

    #[test]
    fn get_request_id_accepts_valid_uuid_header() {
        let id = Uuid::new_v4();
        let mut headers = HeaderMap::new();
        let value = HeaderValue::from_str(&id.to_string()).expect("valid header value");
        headers.insert(X_REQUEST_ID, value);

        let parsed = get_request_id(&headers).expect("request id should parse");
        assert_eq!(parsed.0, id);
        assert_eq!(parsed.to_string(), id.to_string());
    }

    #[test]
    fn get_request_id_rejects_invalid_header_values() {
        let mut headers = HeaderMap::new();
        headers.insert(X_REQUEST_ID, HeaderValue::from_static("not-a-uuid"));
        assert!(get_request_id(&headers).is_none());
    }

    #[tokio::test]
    async fn middleware_propagates_valid_request_id() {
        let app = Router::new()
            .route("/health", get(|| async { "ok" }))
            .layer(middleware::from_fn(request_tracing_middleware));

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr: SocketAddr = listener.local_addr().expect("listener addr");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let id = Uuid::new_v4();
        let response = send_health_request(addr, Some(id.to_string()))
            .await
            .expect("request should succeed");
        assert!(response.status().is_success());
        let echoed = response
            .headers()
            .get(X_REQUEST_ID)
            .expect("response should include request id")
            .to_str()
            .expect("request id header should be utf8");
        assert_eq!(echoed, id.to_string());
        handle.abort();
    }

    #[tokio::test]
    async fn middleware_generates_request_id_for_invalid_input() {
        let app = Router::new()
            .route("/health", get(|| async { "ok" }))
            .layer(middleware::from_fn(request_tracing_middleware));

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr: SocketAddr = listener.local_addr().expect("listener addr");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let response = send_health_request(addr, Some("definitely-not-a-uuid".to_string()))
            .await
            .expect("request should succeed");
        assert!(response.status().is_success());
        let generated = response
            .headers()
            .get(X_REQUEST_ID)
            .expect("response should include generated request id")
            .to_str()
            .expect("request id header should be utf8");
        assert!(Uuid::parse_str(generated).is_ok());
        handle.abort();
    }
}
