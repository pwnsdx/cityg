//! Cloudflare glue: the Worker entrypoint forwards room requests to the
//! Durable Object `v2-<gid hex>`, which serves them with
//! [`WorkerRoomHost`] over its SQLite storage and notifies the room's
//! WebSockets of new log heads.

use std::cell::RefCell;

use cityg_proto::{AUTHORIZATION_HEADER, ApiError, ErrorCode, Route, parse_bearer, request_gid};
use cityg_runtime::ServiceConfig;
use rand_core::OsRng;
use worker::{
    Env, Method, Request, Response, Result, SqlStorage, SqlStorageValue, State, WebSocket,
    WebSocketIncomingMessage, WebSocketPair, WebSocketRequestResponsePair,
};

use crate::policy::{
    EdgeReply, POLICY_ROUTE, WEBSOCKET_PATH, durable_object_name, edge_reply, is_legacy_path,
    is_room_path, route_policy_manifest, service_config_from_json,
};
use crate::{DurableObjectStorage, ROOM_NAMESPACE_BINDING, WORKER_CONFIG_JSON_ENV, WorkerRoomHost};

const ROOM_STATE_TABLE: &str = "cityg_room_state";
const WEBSOCKET_TAG: &str = "v2";
const PING_REQUEST: &str = "ping";
const PING_RESPONSE: &str = "pong";

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

/// Worker entrypoint.
pub async fn fetch(req: Request, env: Env) -> Result<Response> {
    let path = req.path();
    if req.method() == Method::Get
        && let Some(reply) = edge_reply(&path, now_ms() / 1000)
    {
        return match reply {
            EdgeReply::Text(text) => Response::ok(text),
            EdgeReply::Json(value) => Response::from_json(&value),
        };
    }
    if path == POLICY_ROUTE {
        return if req.method() == Method::Get {
            Response::from_json(&route_policy_manifest())
        } else {
            Response::error("method not allowed", 405)
        };
    }
    if is_room_path(&path) {
        return forward(req, &env).await;
    }
    if is_legacy_path(&path) {
        return error_response(&ApiError::new(
            ErrorCode::Gone,
            "the v0.1.4 API was removed; use a City-G v0.2 client",
        ));
    }
    error_response(&ApiError::new(ErrorCode::NotFound, "unknown route"))
}

/// Route a room request to its Durable Object.
async fn forward(req: Request, env: &Env) -> Result<Response> {
    let gid = if req.path() == WEBSOCKET_PATH {
        match hex32(query_param(&req, "gid")?) {
            Some(gid) => gid,
            None => return error_response(&ApiError::new(ErrorCode::BadRequest, "gid is hex")),
        }
    } else {
        if req.method() != Method::Post {
            return error_response(&ApiError::new(
                ErrorCode::BadRequest,
                "delivery-service routes are POST",
            ));
        }
        let body = req.clone()?.bytes().await?;
        match request_gid(&body) {
            Ok(gid) => gid,
            Err(error) => return error_response(&error),
        }
    };
    let namespace = env.durable_object(ROOM_NAMESPACE_BINDING)?;
    let stub = namespace
        .id_from_name(&durable_object_name(&gid))?
        .get_stub()?;
    stub.fetch_with_request(req).await
}

/// SQLite storage of a Durable Object as a key-value store.
pub struct CloudflareSqlDurableObjectStorage {
    sql: SqlStorage,
}

impl CloudflareSqlDurableObjectStorage {
    pub fn new(sql: SqlStorage) -> Result<Self> {
        sql.exec(
            &format!(
                "CREATE TABLE IF NOT EXISTS {ROOM_STATE_TABLE} (
                    key TEXT PRIMARY KEY NOT NULL,
                    value BLOB NOT NULL
                ) WITHOUT ROWID"
            ),
            None,
        )?;
        Ok(Self { sql })
    }
}

impl DurableObjectStorage for CloudflareSqlDurableObjectStorage {
    type Error = worker::Error;

    fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, Self::Error> {
        let mut rows = self
            .sql
            .exec(
                &format!("SELECT value FROM {ROOM_STATE_TABLE} WHERE key = ? LIMIT 1"),
                vec![key.into()],
            )?
            .raw();
        match rows.next() {
            Some(Ok(row)) => match row.as_slice() {
                [SqlStorageValue::Blob(buffer)] => Ok(Some(buffer.clone())),
                _ => Err(worker::Error::from(
                    "unexpected durable object value row shape",
                )),
            },
            Some(Err(error)) => Err(error),
            None => Ok(None),
        }
    }

    fn put_bytes(&mut self, key: &str, value: Vec<u8>) -> Result<(), Self::Error> {
        self.sql.exec(
            &format!(
                "INSERT INTO {ROOM_STATE_TABLE} (key, value)
                 VALUES (?, ?)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value"
            ),
            vec![key.into(), value.into()],
        )?;
        Ok(())
    }

    fn delete_bytes(&mut self, key: &str) -> Result<(), Self::Error> {
        self.sql.exec(
            &format!("DELETE FROM {ROOM_STATE_TABLE} WHERE key = ?"),
            vec![key.into()],
        )?;
        Ok(())
    }

    fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Self::Error> {
        // Escape LIKE wildcards: keys are hex and '/', but stay exact.
        let pattern = prefix
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let rows = self
            .sql
            .exec(
                &format!(
                    "SELECT key, value FROM {ROOM_STATE_TABLE}
                     WHERE key LIKE ? ESCAPE '\\'
                     ORDER BY key ASC"
                ),
                vec![format!("{pattern}%").into()],
            )?
            .raw();
        let mut entries = Vec::new();
        for row in rows {
            match row?.as_slice() {
                // LIKE ignores ASCII case: keep exact prefix matches only.
                [SqlStorageValue::String(key), SqlStorageValue::Blob(buffer)] => {
                    if key.starts_with(prefix) {
                        entries.push((key.clone(), buffer.clone()));
                    }
                }
                _ => {
                    return Err(worker::Error::from(
                        "unexpected durable object key/value row shape",
                    ));
                }
            }
        }
        Ok(entries)
    }
}

type Host = WorkerRoomHost<CloudflareSqlDurableObjectStorage>;

/// The Durable Object of one room.
pub struct RoomObject {
    state: State,
    env: Env,
    host: RefCell<Option<Host>>,
}

impl RoomObject {
    #[must_use]
    pub fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            host: RefCell::new(None),
        }
    }

    fn config(&self) -> std::result::Result<ServiceConfig, String> {
        let json = self
            .env
            .var(WORKER_CONFIG_JSON_ENV)
            .ok()
            .map(|value| value.to_string());
        service_config_from_json(json.as_deref())
    }

    fn with_host<T>(&self, run: impl FnOnce(&mut Host) -> T) -> Result<T> {
        let mut host = self.host.borrow_mut();
        if host.is_none() {
            let config = self.config().map_err(worker::Error::from)?;
            let storage = CloudflareSqlDurableObjectStorage::new(self.state.storage().sql())?;
            *host = Some(WorkerRoomHost::new(storage, config));
        }
        let host = host
            .as_mut()
            .ok_or_else(|| worker::Error::from("room host unavailable"))?;
        Ok(run(host))
    }

    fn ensure_ping_auto_response(&self) {
        if self.state.get_websocket_auto_response().is_some() {
            return;
        }
        if let Ok(pair) = WebSocketRequestResponsePair::new(PING_REQUEST, PING_RESPONSE) {
            self.state.set_websocket_auto_response(&pair);
        }
    }

    /// Serve a room request.
    pub async fn fetch(&self, mut req: Request) -> Result<Response> {
        self.ensure_ping_auto_response();
        if req.path() == WEBSOCKET_PATH {
            return self.subscribe(&req);
        }
        let Some(route) = Route::from_path(&req.path()) else {
            return error_response(&ApiError::new(ErrorCode::NotFound, "unknown route"));
        };
        let bearer = req
            .headers()
            .get(AUTHORIZATION_HEADER)?
            .and_then(|value| parse_bearer(&value));
        let body = req.bytes().await?;
        let outcome = match self
            .with_host(|host| host.handle(route, &body, bearer.as_ref(), now_ms(), &mut OsRng))
        {
            Ok(outcome) => outcome,
            Err(error) => {
                return error_response(&ApiError::new(ErrorCode::Internal, error.to_string()));
            }
        };
        match outcome {
            Ok(handled) => {
                if let Some(head) = handled.new_head
                    && let Ok(gid) = request_gid(&body)
                {
                    self.broadcast_head(&gid, head);
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

    fn subscribe(&self, req: &Request) -> Result<Response> {
        let (Some(gid), Some(token)) = (
            hex32(query_param(req, "gid")?),
            hex32(query_param(req, "token")?),
        ) else {
            return error_response(&ApiError::new(
                ErrorCode::BadRequest,
                "gid and token are hex",
            ));
        };
        let head = match self.with_host(|host| host.check_subscription(&gid, &token, now_ms())) {
            Ok(Ok(head)) => head,
            Ok(Err(error)) => return error_response(&error),
            Err(error) => {
                return error_response(&ApiError::new(ErrorCode::Internal, error.to_string()));
            }
        };
        let pair = WebSocketPair::new()?;
        self.state
            .accept_websocket_with_tags(&pair.server, &[WEBSOCKET_TAG]);
        pair.server.send_with_str(head_notice(&gid, head))?;
        Response::from_websocket(pair.client)
    }

    fn broadcast_head(&self, gid: &[u8; 32], head: u64) {
        let notice = head_notice(gid, head);
        for socket in self.state.get_websockets_with_tag(WEBSOCKET_TAG) {
            // A closed socket is dropped by the runtime.
            let _ = socket.send_with_str(notice.as_str());
        }
    }

    /// Clients send nothing but pings (answered by the auto-response).
    pub async fn websocket_message(
        &self,
        _ws: WebSocket,
        _message: WebSocketIncomingMessage,
    ) -> Result<()> {
        Ok(())
    }

    pub async fn websocket_close(
        &self,
        ws: WebSocket,
        code: usize,
        reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        let _ = ws.close(u16::try_from(code).ok(), Some(reason.as_str()));
        Ok(())
    }

    pub async fn websocket_error(&self, ws: WebSocket, _error: worker::Error) -> Result<()> {
        let _ = ws.close(Some(1011), Some("websocket error"));
        Ok(())
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
