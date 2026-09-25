//! Cloudflare glue of the v0.2 routes: the Worker forwards `/v2/...`
//! requests to the Durable Object `v2-<gid hex>`, which serves them with
//! [`WorkerRoomHost`].

use std::cell::RefCell;

use cityg_proto::{AUTHORIZATION_HEADER, ApiError, ErrorCode, Route, parse_bearer, request_gid};
use cityg_runtime::v2::ServiceConfig;
use rand_core::OsRng;
use worker::{Env, Method, Request, Response, Result, State, WebSocketPair};

use crate::WorkerRoomHost;
use crate::cloudflare::{CLOUDFLARE_ROOM_NAMESPACE_BINDING, CloudflareSqlDurableObjectStorage};

/// Path of the v2 log-head WebSocket.
pub const V2_WEBSOCKET_PATH: &str = "/v2/ws";
const V2_TAG: &str = "v2";

/// Whether `path` belongs to the v2 API.
#[must_use]
pub fn is_v2_path(path: &str) -> bool {
    path == V2_WEBSOCKET_PATH || path.starts_with("/v2/groups/")
}

fn now_ms() -> u64 {
    worker::Date::now().as_millis()
}

fn error_response(error: &ApiError) -> Result<Response> {
    let mut response = Response::from_bytes(error.to_body())?.with_status(error.code.status());
    response
        .headers_mut()
        .set("content-type", "application/x-protobuf")?;
    Ok(response)
}

fn object_name(gid: &[u8; 32]) -> String {
    format!("v2-{}", hex::encode(gid))
}

fn query_param(req: &Request, name: &str) -> Result<Option<String>> {
    Ok(req
        .url()?
        .query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned()))
}

fn hex32(value: Option<String>) -> Option<[u8; 32]> {
    hex::decode(value?).ok()?.try_into().ok()
}

/// Worker side: route a v2 request to its room's Durable Object.
pub async fn forward_v2(req: Request, env: &Env) -> Result<Response> {
    let gid = if req.path() == V2_WEBSOCKET_PATH {
        match hex32(query_param(&req, "gid")?) {
            Some(gid) => gid,
            None => return error_response(&ApiError::new(ErrorCode::BadRequest, "gid is hex")),
        }
    } else {
        if req.method() != Method::Post {
            return error_response(&ApiError::new(ErrorCode::BadRequest, "v2 routes are POST"));
        }
        let body = req.clone()?.bytes().await?;
        match request_gid(&body) {
            Ok(gid) => gid,
            Err(error) => return error_response(&error),
        }
    };
    let namespace = env.durable_object(CLOUDFLARE_ROOM_NAMESPACE_BINDING)?;
    let stub = namespace.id_from_name(&object_name(&gid))?.get_stub()?;
    stub.fetch_with_request(req).await
}

/// Durable Object side: the v2 room of this object.
#[derive(Default)]
pub struct V2Room {
    host: RefCell<Option<WorkerRoomHost<CloudflareSqlDurableObjectStorage>>>,
}

impl V2Room {
    fn with_host<T>(
        &self,
        state: &State,
        run: impl FnOnce(&mut WorkerRoomHost<CloudflareSqlDurableObjectStorage>) -> T,
    ) -> Result<T> {
        let mut host = self.host.borrow_mut();
        if host.is_none() {
            let storage = CloudflareSqlDurableObjectStorage::new(state.storage().sql())
                .map_err(|error| worker::Error::from(error.to_string()))?;
            *host = Some(WorkerRoomHost::new(storage, ServiceConfig::default()));
        }
        let host = host
            .as_mut()
            .ok_or_else(|| worker::Error::from("v2 room host unavailable"))?;
        Ok(run(host))
    }

    /// Serve a v2 request.
    pub async fn fetch(&self, state: &State, mut req: Request) -> Result<Response> {
        if req.path() == V2_WEBSOCKET_PATH {
            return self.subscribe(state, &req);
        }
        let Some(route) = Route::from_path(&req.path()) else {
            return error_response(&ApiError::new(ErrorCode::NotFound, "unknown route"));
        };
        let bearer = req
            .headers()
            .get(AUTHORIZATION_HEADER)?
            .and_then(|value| parse_bearer(&value));
        let body = req.bytes().await?;
        let outcome = self.with_host(state, |host| {
            host.handle(route, &body, bearer.as_ref(), now_ms(), &mut OsRng)
        })?;
        match outcome {
            Ok(handled) => {
                if let Some(head) = handled.new_head
                    && let Ok(gid) = request_gid(&body)
                {
                    broadcast_head(state, &gid, head);
                }
                let mut response = Response::from_bytes(handled.body)?;
                response
                    .headers_mut()
                    .set("content-type", "application/x-protobuf")?;
                Ok(response)
            }
            Err(error) => error_response(&error),
        }
    }

    fn subscribe(&self, state: &State, req: &Request) -> Result<Response> {
        let (Some(gid), Some(token)) = (
            hex32(query_param(req, "gid")?),
            hex32(query_param(req, "token")?),
        ) else {
            return error_response(&ApiError::new(
                ErrorCode::BadRequest,
                "gid and token are hex",
            ));
        };
        let head = self.with_host(state, |host| {
            host.check_subscription(&gid, &token, now_ms())
        })?;
        let head = match head {
            Ok(head) => head,
            Err(error) => return error_response(&error),
        };
        let pair = WebSocketPair::new()?;
        state.accept_websocket_with_tags(&pair.server, &[V2_TAG]);
        pair.server.send_with_str(head_notice(&gid, head))?;
        Response::from_websocket(pair.client)
    }
}

fn head_notice(gid: &[u8; 32], head: u64) -> String {
    serde_json::json!({
        "type": "head",
        "gid": hex::encode(gid),
        "head_seq": head,
    })
    .to_string()
}

fn broadcast_head(state: &State, gid: &[u8; 32], head: u64) {
    let notice = head_notice(gid, head);
    for socket in state.get_websockets_with_tag(V2_TAG) {
        // A closed socket is dropped by the runtime; nothing to do here.
        let _ = socket.send_with_str(notice.as_str());
    }
}
