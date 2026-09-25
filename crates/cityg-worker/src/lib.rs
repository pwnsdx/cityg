#![forbid(unsafe_code)]

//! Cloudflare Worker transport of the City-G v0.2 delivery service.
//!
//! The Worker routes each `/v2/groups/*` request and each `/v2/ws`
//! subscription to the Durable Object of its room, named `v2-<gid hex>`.
//! The object serves the request with [`WorkerRoomHost`] (the handlers of
//! the native server, over the object's SQLite storage) and pushes log-head
//! notices to the room's hibernatable WebSockets. Health checks and the
//! route policy manifest are answered at the edge.

#[cfg(feature = "cloudflare")]
mod cloudflare;
mod host;
mod policy;
mod storage;

pub use host::{DoRoomStore, DoRoomStoreError, WorkerRoomHost};
pub use policy::{
    EdgeReply, HEALTH_ROUTES, POLICY_ROUTE, WEBSOCKET_PATH, durable_object_name, edge_reply,
    is_legacy_path, is_room_path, route_policy_manifest, service_config_from_json,
};
pub use storage::{DurableObjectStorage, MemoryDurableObjectStorage};

/// Durable Object namespace binding of the rooms.
pub const ROOM_NAMESPACE_BINDING: &str = "CITYG_ROOM";
/// Optional Worker variable with a serialized `CityGConfig`; its `[server]`
/// limits apply to every room.
pub const WORKER_CONFIG_JSON_ENV: &str = "CITYG_WORKER_CONFIG_JSON";

#[cfg(feature = "cloudflare")]
pub use cloudflare::CloudflareSqlDurableObjectStorage;

#[cfg(feature = "cloudflare")]
use worker::wasm_bindgen;
#[cfg(feature = "cloudflare")]
use worker::{
    DurableObject, Env, Request, Response, Result as WorkerResult, State, WebSocket,
    WebSocketIncomingMessage, durable_object, event,
};

#[cfg(feature = "cloudflare")]
#[event(fetch, respond_with_errors)]
pub async fn worker_fetch(req: Request, env: Env, _ctx: worker::Context) -> WorkerResult<Response> {
    cloudflare::fetch(req, env).await
}

/// The Durable Object class of the rooms (binding [`ROOM_NAMESPACE_BINDING`]).
#[cfg(feature = "cloudflare")]
#[durable_object]
pub struct CityGRoomDurableObject {
    inner: cloudflare::RoomObject,
}

#[cfg(feature = "cloudflare")]
impl DurableObject for CityGRoomDurableObject {
    fn new(state: State, env: Env) -> Self {
        Self {
            inner: cloudflare::RoomObject::new(state, env),
        }
    }

    async fn fetch(&self, req: Request) -> WorkerResult<Response> {
        self.inner.fetch(req).await
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> WorkerResult<()> {
        self.inner.websocket_message(ws, message).await
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        code: usize,
        reason: String,
        was_clean: bool,
    ) -> WorkerResult<()> {
        self.inner
            .websocket_close(ws, code, reason, was_clean)
            .await
    }

    async fn websocket_error(&self, ws: WebSocket, error: worker::Error) -> WorkerResult<()> {
        self.inner.websocket_error(ws, error).await
    }
}
