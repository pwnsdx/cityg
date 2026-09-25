//! Delivery-service routes of the City-G v0.2 profile (`/v2/groups/*` and
//! the `/v2/ws` log-head notifications).
//!
//! Requests are protobuf bodies (see `cityg-proto`). Each room is locked on
//! its own; the handler runs on the blocking pool because verifying a
//! commit (ML-DSA-87 signature, update path, tree hashes) is CPU work. The
//! journal record of a request is written before the reply; if that fails
//! the in-memory room is dropped and reloaded from storage on next use.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    Router,
    body::Bytes,
    extract::{
        DefaultBodyLimit, Query, State, WebSocketUpgrade,
        ws::{Message as WsMessage, WebSocket},
    },
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header::CONTENT_TYPE},
    response::Response,
    routing::{get, post},
};
use cityg_core::hash::Digest;
use cityg_proto::{
    AUTHORIZATION_HEADER, ApiError, ErrorCode, MAX_REQUEST_BYTES, Route, parse_bearer, request_gid,
};
use cityg_runtime::{
    NativeRoomStore, ServiceConfig, SessionRegistry, create_room, handle_room_request,
    persist_record,
};
use cityg_server::{Room, RoomStore, restore_room};
use futures::{SinkExt, StreamExt};
use rand_core::OsRng;
use serde::Deserialize;
use tokio::sync::broadcast;
use tracing::warn;

type RoomSlot = Arc<Mutex<Option<Room>>>;

struct Inner {
    config: ServiceConfig,
    rooms: Mutex<HashMap<Digest, RoomSlot>>,
    store: Mutex<NativeRoomStore>,
    sessions: Mutex<SessionRegistry>,
    heads: broadcast::Sender<(Digest, u64)>,
}

/// Shared state of the delivery-service routes.
#[derive(Clone)]
pub struct ServiceState {
    inner: Arc<Inner>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, ApiError> {
    mutex
        .lock()
        .map_err(|_| ApiError::new(ErrorCode::Internal, "state lock poisoned"))
}

impl ServiceState {
    /// New state over `store`.
    #[must_use]
    pub fn new(
        config: ServiceConfig,
        store: NativeRoomStore,
        notification_capacity: usize,
    ) -> Self {
        let (heads, _) = broadcast::channel(notification_capacity.max(16));
        Self {
            inner: Arc::new(Inner {
                config,
                rooms: Mutex::new(HashMap::new()),
                store: Mutex::new(store),
                sessions: Mutex::new(SessionRegistry::new()),
                heads,
            }),
        }
    }

    fn slot(&self, gid: &Digest) -> Result<RoomSlot, ApiError> {
        Ok(lock(&self.inner.rooms)?
            .entry(*gid)
            .or_insert_with(|| Arc::new(Mutex::new(None)))
            .clone())
    }

    fn load(&self, gid: &Digest) -> Result<Option<Room>, ApiError> {
        let stored = lock(&self.inner.store)?
            .load(gid)
            .map_err(|error| ApiError::new(ErrorCode::Internal, error.to_string()))?;
        stored
            .map(|stored| {
                restore_room(&stored, self.inner.config.room)
                    .map_err(|error| ApiError::new(ErrorCode::Internal, error.to_string()))
            })
            .transpose()
    }

    /// Run one request; returns the protobuf response body.
    pub fn dispatch(
        &self,
        route: Route,
        body: &[u8],
        bearer: Option<&[u8; 32]>,
        now_ms: u64,
    ) -> Result<Vec<u8>, ApiError> {
        let gid = request_gid(body)?;
        let slot = self.slot(&gid)?;
        let mut room = lock(&slot)?;
        if room.is_none() {
            *room = self.load(&gid)?;
        }
        let config = &self.inner.config;
        let handled = match (route, room.as_mut()) {
            (Route::CreateGroup, None) => {
                let (created, handled) = create_room(body, config, now_ms)?;
                *room = Some(created);
                handled
            }
            (_, None) => return Err(ApiError::new(ErrorCode::NotFound, "group not found")),
            (_, Some(existing)) => {
                let mut sessions = lock(&self.inner.sessions)?;
                handle_room_request(
                    route,
                    body,
                    existing,
                    &mut sessions,
                    bearer,
                    config,
                    now_ms,
                    &mut OsRng,
                )?
            }
        };
        if let (Some(record), Some(current)) = (&handled.record, room.as_ref()) {
            let persisted = persist_record(
                &mut *lock(&self.inner.store)?,
                current,
                record,
                config.compact_every,
            );
            if let Err(error) = persisted {
                // Memory is ahead of storage: forget it and reload later.
                *room = None;
                return Err(error);
            }
        }
        if let Some(head) = handled.new_head {
            let _ = self.inner.heads.send((gid, head));
        }
        Ok(handled.body)
    }

    /// Check a member token for `gid`; returns the room's log head.
    fn check_subscription(&self, gid: &Digest, token: &[u8; 32]) -> Result<u64, ApiError> {
        let slot = self.slot(gid)?;
        let mut room = lock(&slot)?;
        if room.is_none() {
            *room = self.load(gid)?;
        }
        let room = room
            .as_ref()
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "group not found"))?;
        lock(&self.inner.sessions)?.check(Some(token), room, now_ms())?;
        Ok(room.head_seq())
    }
}

fn protobuf(body: Vec<u8>) -> Response {
    let mut response = Response::new(body.into());
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-protobuf"),
    );
    response
}

fn error_response(error: &ApiError) -> Response {
    let status =
        StatusCode::from_u16(error.code.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = protobuf(error.to_body());
    *response.status_mut() = status;
    response
}

async fn handle(
    State(state): State<ServiceState>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(route) = Route::from_path(uri.path()) else {
        return error_response(&ApiError::new(ErrorCode::NotFound, "unknown route"));
    };
    let bearer = headers
        .get(AUTHORIZATION_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_bearer);
    let joined = tokio::task::spawn_blocking(move || {
        state.dispatch(route, &body, bearer.as_ref(), now_ms())
    })
    .await;
    match joined {
        Ok(Ok(body)) => protobuf(body),
        Ok(Err(error)) => error_response(&error),
        Err(_) => error_response(&ApiError::new(ErrorCode::Internal, "handler failed")),
    }
}

#[derive(Deserialize)]
struct SubscriptionQuery {
    gid: String,
    token: String,
}

fn parse_hex32(value: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(value).ok()?;
    bytes.try_into().ok()
}

async fn websocket(
    ws: WebSocketUpgrade,
    State(state): State<ServiceState>,
    Query(query): Query<SubscriptionQuery>,
) -> Response {
    let (Some(gid), Some(token)) = (parse_hex32(&query.gid), parse_hex32(&query.token)) else {
        return error_response(&ApiError::new(
            ErrorCode::BadRequest,
            "gid and token are hex",
        ));
    };
    let checked = {
        let state = state.clone();
        tokio::task::spawn_blocking(move || state.check_subscription(&gid, &token)).await
    };
    match checked {
        Ok(Ok(head)) => ws.on_upgrade(move |socket| subscription(socket, state, gid, head)),
        Ok(Err(error)) => error_response(&error),
        Err(_) => error_response(&ApiError::new(ErrorCode::Internal, "handler failed")),
    }
}

fn head_notice(gid: &Digest, head: u64) -> WsMessage {
    WsMessage::Text(
        serde_json::json!({
            "type": "head",
            "gid": hex::encode(gid),
            "head_seq": head,
        })
        .to_string()
        .into(),
    )
}

async fn subscription(socket: WebSocket, state: ServiceState, gid: Digest, head: u64) {
    let (mut sender, mut receiver) = socket.split();
    let mut heads = state.inner.heads.subscribe();
    if sender.send(head_notice(&gid, head)).await.is_err() {
        return;
    }
    let period = Duration::from_secs(30);
    let mut ping = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    loop {
        tokio::select! {
            notice = heads.recv() => match notice {
                Ok((room, head)) if room == gid => {
                    if sender.send(head_notice(&gid, head)).await.is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    // The client refetches the log; tell it to resync.
                    warn!("log-head subscription lagged by {skipped} notices");
                    let resync = WsMessage::Text(
                        serde_json::json!({"type": "resync", "gid": hex::encode(gid)})
                            .to_string()
                            .into(),
                    );
                    if sender.send(resync).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            incoming = receiver.next() => match incoming {
                Some(Ok(WsMessage::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(_)) => {}
            },
            _ = ping.tick() => {
                if sender.send(WsMessage::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
            }
        }
    }
}

/// The delivery-service router.
pub fn router(state: ServiceState) -> Router {
    let mut router = Router::new();
    for route in Route::ALL {
        router = router.route(route.path(), post(handle));
    }
    router
        .route("/v2/ws", get(websocket))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(state)
}
