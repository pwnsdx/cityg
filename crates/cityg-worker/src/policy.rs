//! Edge routing decisions of the Worker, independent of the Cloudflare
//! runtime: which paths go to a room object, health replies, the route
//! policy manifest and the service limits.

use cityg_config::CityGConfig;
use cityg_proto::Route;
use cityg_runtime::ServiceConfig;
use serde_json::{Value, json};

/// Path of the route policy manifest.
pub const POLICY_ROUTE: &str = "/__cloudflare/policy";
/// Path of the log-head WebSocket.
pub const WEBSOCKET_PATH: &str = "/v2/ws";
/// Health paths answered by the Worker itself.
pub const HEALTH_ROUTES: [&str; 5] = [
    "/healthz",
    "/health",
    "/health/live",
    "/health/ready",
    "/health/detailed",
];

/// Whether `path` is served by the Durable Object of a room.
#[must_use]
pub fn is_room_path(path: &str) -> bool {
    path == WEBSOCKET_PATH || Route::from_path(path).is_some()
}

/// Whether `path` belongs to the removed v0.1.4 API.
#[must_use]
pub fn is_legacy_path(path: &str) -> bool {
    path.starts_with("/v1/") || path.starts_with("/v2/barrier/")
}

/// Name of the Durable Object serving the room `gid`.
#[must_use]
pub fn durable_object_name(gid: &[u8; 32]) -> String {
    format!("v2-{}", hex::encode(gid))
}

/// Reply of a health path.
#[derive(Clone, Debug, PartialEq)]
pub enum EdgeReply {
    Text(&'static str),
    Json(Value),
}

/// The reply to a `GET` of `path`, when the Worker answers it itself.
#[must_use]
pub fn edge_reply(path: &str, now_secs: u64) -> Option<EdgeReply> {
    let healthy = || {
        json!({
            "status": "healthy",
            "timestamp": now_secs,
            "version": env!("CARGO_PKG_VERSION"),
            "checks": [{
                "name": "worker-edge",
                "status": "healthy",
                "message": "Cloudflare Worker entrypoint is responsive"
            }]
        })
    };
    match path {
        "/healthz" => Some(EdgeReply::Text("ok")),
        "/health" | "/health/detailed" => Some(EdgeReply::Json(healthy())),
        "/health/live" => Some(EdgeReply::Json(json!({ "alive": true }))),
        "/health/ready" => Some(EdgeReply::Json(json!({ "ready": true }))),
        _ => None,
    }
}

/// The route policy manifest: which routes the edge answers, which run in
/// a room Durable Object and which stay native-only.
#[must_use]
pub fn route_policy_manifest() -> Value {
    let entry = |path: &str, methods: &[&str], note: &str| json!({ "path": path, "methods": methods, "note": note });
    let mut room_routes = vec![entry(
        WEBSOCKET_PATH,
        &["GET"],
        "Log-head notifications of a room, served by its Durable Object",
    )];
    room_routes.extend(Route::ALL.iter().map(|route| {
        entry(
            route.path(),
            &["POST"],
            "Delivery-service request executed by the room's Durable Object",
        )
    }));
    json!({
        "profile": cityg_proto::API_PROFILE_VERSION,
        "edge_only_routes": HEALTH_ROUTES
            .iter()
            .map(|path| entry(path, &["GET"], "Answered by the Worker entrypoint"))
            .collect::<Vec<_>>(),
        "room_durable_object_routes": room_routes,
        "unsupported_native_routes": [entry(
            "/metrics",
            &["GET"],
            "Prometheus metrics stay native-only; the Worker relies on logs and analytics",
        )],
        "internal_worker_routes": [entry(POLICY_ROUTE, &["GET"], "This manifest")],
    })
}

/// Service limits from the optional `CityGConfig` JSON of the Worker (its
/// `[server]` section); the defaults without one.
pub fn service_config_from_json(json: Option<&str>) -> Result<ServiceConfig, String> {
    let Some(json) = json.filter(|json| !json.trim().is_empty()) else {
        return Ok(ServiceConfig::default());
    };
    let config: CityGConfig =
        serde_json::from_str(json).map_err(|error| format!("invalid Worker config: {error}"))?;
    config
        .validate()
        .map_err(|error| format!("invalid Worker config: {error}"))?;
    Ok(ServiceConfig::from_config(&config))
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn room_paths_and_legacy_paths() {
        assert!(is_room_path("/v2/ws"));
        assert!(is_room_path("/v2/groups/commit"));
        assert!(!is_room_path("/v2/groups/nope"));
        assert!(!is_room_path("/health"));
        assert!(is_legacy_path("/v1/accept_epoch"));
        assert!(is_legacy_path("/v2/barrier/resolve_join_occupancies_since"));
        assert!(!is_legacy_path("/v2/groups/commit"));
        assert_eq!(
            durable_object_name(&[0xAB; 32]),
            format!("v2-{}", "ab".repeat(32))
        );
    }

    #[test]
    fn health_replies() {
        assert_eq!(edge_reply("/healthz", 1), Some(EdgeReply::Text("ok")));
        for path in HEALTH_ROUTES {
            assert!(edge_reply(path, 1).is_some(), "{path}");
        }
        let Some(EdgeReply::Json(detailed)) = edge_reply("/health/detailed", 42) else {
            panic!("expected a JSON reply");
        };
        assert_eq!(detailed["status"], "healthy");
        assert_eq!(detailed["timestamp"], 42);
        assert_eq!(edge_reply("/metrics", 1), None);
    }

    #[test]
    fn the_manifest_lists_every_route() {
        let manifest = route_policy_manifest();
        let room_routes = manifest["room_durable_object_routes"]
            .as_array()
            .map(Vec::len)
            .unwrap_or_default();
        assert_eq!(room_routes, Route::ALL.len() + 1);
        assert!(manifest["unsupported_native_routes"].is_array());
        assert_eq!(
            manifest["edge_only_routes"].as_array().map(Vec::len),
            Some(5)
        );
        assert_eq!(manifest["internal_worker_routes"][0]["path"], POLICY_ROUTE);
    }

    #[test]
    fn service_limits_come_from_the_worker_config() {
        assert_eq!(service_config_from_json(None), Ok(ServiceConfig::default()));
        assert_eq!(
            service_config_from_json(Some("  ")),
            Ok(ServiceConfig::default())
        );
        let mut config = CityGConfig::default();
        config.server.max_group_size = 16;
        let json = serde_json::to_string(&config).unwrap_or_default();
        let service = service_config_from_json(Some(&json));
        assert_eq!(service.map(|service| service.room.max_n_max), Ok(16));
        assert!(service_config_from_json(Some("{")).is_err());
        config.server.max_group_size = 0;
        let json = serde_json::to_string(&config).unwrap_or_default();
        assert!(service_config_from_json(Some(&json)).is_err());
    }
}
