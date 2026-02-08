mod pb {
    include!(concat!(env!("OUT_DIR"), "/cityg.api.v1.rs"));
}

pub mod health;
mod middleware;

use std::{
    collections::{BTreeMap, HashSet},
    convert::TryInto,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use ahash::AHashMap;

use axum::{
    Router,
    body::Bytes,
    extract::ws::{Message as WsMessage, WebSocket},
    extract::{State, WebSocketUpgrade},
    http::{HeaderValue, StatusCode, header::CONTENT_TYPE},
    middleware as axum_middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bytes::BytesMut;
use ciborium::ser::into_writer;
use futures::{SinkExt, StreamExt};
use hex::FromHex;
use pb::{
    AcceptEpochRequest, AcceptEpochResponse, BootstrapRoomRequest, BootstrapRoomResponse,
    ChatMessage, ConfigureWindowRequest, ConfigureWindowResponse, FetchMessagesRequest,
    FetchMessagesResponse, FreezeStat, GetBundleRequest, GetBundleResponse, GetTelemetryRequest,
    GetTelemetryResponse, GetWindowRequest, GetWindowResponse, HealthResponse, IdentityBinding,
    JoinTicketRequest, JoinTicketResponse, Member, MembersRequest, MembersResponse,
    MergeTicketRequest, MergeTicketResponse, RefreshPivotRequest, RefreshPivotResponse,
    SeedHeadRequest, SeedHeadResponse, SendMessageRequest, SendMessageResponse, TelemetryEntry,
    WindowEntry, WindowHead,
};
use prost::Message;
use thiserror::Error;
use tokio::sync::{RwLock, broadcast};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use cityg_client::{CityGError as ClientError, ClientEpochBundle};
use cityg_server::{CityGServer, MergeTicketBundle, ServerConfig, ServerOutcome};
use msphf_core::params::{RLWE_CRS_ID_DEFAULT, RLWE_PARAMS_ID_MOCK};
use msphf_orchestrator::{AcceptanceError, mhw::FreezeError};
use msphf_orchestrator::{
    AcceptanceOptions, BootstrapPolicy, DEFAULT_PROOF_MODE, DEFAULT_VRF_ID, FsPolicyConfig,
    LeafIdMode, PivotParity, compute_leaf_id,
};
use pqcrypto_kyber::kyber768::public_key_bytes as ml_kem_public_key_bytes;
use serde::Serialize;
use serde_bytes::ByteBuf;
use serde_json::to_vec as to_json_vec;

#[derive(Clone, Debug)]
struct AliasBinding {
    leaf_id: [u8; 32],
    pop_public_key: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
struct MemberMetadata {
    join_timestamp_ms: u64,
    last_seen_timestamp_ms: u64,
}

#[derive(Clone, Debug)]
enum BroadcastNotification {
    Message(MessageNotification),
    Membership(MembershipNotification),
}

/// Per-alias rate limiter for TOFU registration.
///
/// Tracks the number of registration attempts per alias within a sliding
/// window.  Prevents alias squatting by rejecting bursts that exceed the
/// configured threshold.
#[derive(Clone)]
struct AliasRateLimiter {
    /// (alias -> list of attempt timestamps)
    attempts: Arc<RwLock<AHashMap<String, Vec<Instant>>>>,
    /// Maximum number of registration attempts per alias within `window`.
    burst: u32,
    /// Sliding window duration.
    window: Duration,
    /// Maximum number of alias buckets to retain at once.
    max_aliases: usize,
}

impl AliasRateLimiter {
    fn new(burst: u32, window: Duration) -> Self {
        Self::with_max_aliases(burst, window, ALIAS_RATE_LIMIT_MAX_BUCKETS)
    }

    fn with_max_aliases(burst: u32, window: Duration, max_aliases: usize) -> Self {
        Self {
            attempts: Arc::new(RwLock::new(AHashMap::new())),
            burst,
            window,
            max_aliases: max_aliases.max(1),
        }
    }

    /// Returns `true` if the attempt is allowed (under the rate limit).
    async fn check_and_record(&self, alias: &str) -> bool {
        let now = Instant::now();
        let mut guard = self.attempts.write().await;

        // Prune all stale alias buckets first so one-off alias spam does not
        // accumulate unbounded state in memory.
        let window = self.window;
        guard.retain(|_, entries| {
            entries.retain(|ts| now.duration_since(*ts) <= window);
            !entries.is_empty()
        });

        if !guard.contains_key(alias) && guard.len() >= self.max_aliases {
            let evict_key = guard
                .iter()
                .filter_map(|(candidate, entries)| {
                    entries.last().copied().map(|ts| (candidate.clone(), ts))
                })
                .min_by_key(|(_, ts)| *ts)
                .map(|(candidate, _)| candidate);
            if let Some(evict_key) = evict_key {
                guard.remove(&evict_key);
            }
        }

        let entries = guard.entry(alias.to_string()).or_default();
        if entries.len() >= self.burst as usize {
            return false;
        }
        entries.push(now);
        true
    }
}

/// Default alias TOFU rate limit: 10 attempts per alias per 60 seconds.
const ALIAS_RATE_LIMIT_BURST: u32 = 10;
const ALIAS_RATE_LIMIT_WINDOW_SECS: u64 = 60;
const ALIAS_RATE_LIMIT_MAX_BUCKETS: usize = 100_000;

#[derive(Clone)]
struct ApiState {
    server: Arc<RwLock<CityGServer>>,
    messages: Arc<RwLock<AHashMap<[u8; 32], Vec<StoredMessage>>>>,
    bundles: Arc<RwLock<AHashMap<[u8; 32], Vec<u8>>>>,
    message_retention: Duration,
    fs_epoch_period_seconds: u64,
    freeze_counts: Arc<RwLock<BTreeMap<(u32, String), u64>>>,
    // Alias registry: alias -> (leaf_id, pop_pk) for TOFU
    alias_registry: Arc<RwLock<AHashMap<String, AliasBinding>>>,
    member_metadata: Arc<RwLock<AHashMap<[u8; 32], MemberMetadata>>>,
    weid_to_leaf: Arc<RwLock<AHashMap<[u8; 32], [u8; 32]>>>,
    // Broadcast channel for WebSocket notifications
    notification_tx: broadcast::Sender<BroadcastNotification>,
    alias_rate_limiter: AliasRateLimiter,
}

#[derive(Clone, Debug)]
struct MessageNotification {
    we_epoch_id: [u8; 32],
    timestamp_ms: u64,
}

#[derive(Clone, Copy, Debug)]
enum MembershipEventKind {
    Join,
    Revoke,
}

#[derive(Clone, Debug)]
struct MembershipNotification {
    gid: [u8; 32],
    leaf_id: [u8; 32],
    event: MembershipEventKind,
    timestamp_ms: u64,
}

impl ApiState {
    async fn record_freeze(&self, freeze: FreezeError) {
        let mut guard = self.freeze_counts.write().await;
        let key = (freeze.code, freeze.reason.to_string());
        *guard.entry(key).or_insert(0) += 1;
    }

    async fn freeze_stats(&self) -> Vec<(u32, String, u64)> {
        let guard = self.freeze_counts.read().await;
        guard
            .iter()
            .map(|((code, reason), count)| (*code, reason.clone(), *count))
            .collect()
    }

    /// Register an alias binding using Trust-On-First-Use (TOFU) semantics.
    /// Returns Ok(true) if this is a new binding, Ok(false) if it matches an existing binding.
    /// Returns Err if the alias is already bound to a different public key
    /// or if the per-alias rate limit is exceeded.
    async fn register_alias(
        &self,
        alias: &str,
        leaf_id: [u8; 32],
        pop_public_key: Vec<u8>,
    ) -> Result<bool, ApiError> {
        if !self.alias_rate_limiter.check_and_record(alias).await {
            warn!(alias = alias, "alias registration rate-limited");
            return Err(ApiError::RateLimited);
        }

        let mut guard = self.alias_registry.write().await;

        if let Some(existing) = guard.get_mut(alias) {
            // TOFU: First binding wins
            if existing.pop_public_key == pop_public_key {
                if existing.leaf_id != leaf_id {
                    existing.leaf_id = leaf_id;
                    info!(
                        "Alias '{}' verified: updated leaf binding to {}",
                        alias,
                        hex::encode(leaf_id)
                    );
                } else {
                    info!("Alias '{}' verified: matches existing binding", alias);
                }
                return Ok(false);
            } else {
                // Different device trying to use same alias - TOFU violation
                error!(
                    "TOFU violation: Alias '{}' already bound to different public key",
                    alias
                );
                return Err(ApiError::InvalidRequest(
                    "alias already bound to a different identity",
                ));
            }
        }

        // New alias, register it
        let binding = AliasBinding {
            leaf_id,
            pop_public_key: pop_public_key.clone(),
        };
        guard.insert(alias.to_string(), binding);
        info!("Alias '{}' registered with new binding", alias);
        Ok(true)
    }

    async fn record_member_join(
        &self,
        leaf_id: [u8; 32],
        we_epoch_id: [u8; 32],
        timestamp_ms: u64,
    ) {
        {
            let mut metadata = self.member_metadata.write().await;
            metadata.insert(
                leaf_id,
                MemberMetadata {
                    join_timestamp_ms: timestamp_ms,
                    last_seen_timestamp_ms: timestamp_ms,
                },
            );
        }

        {
            let mut map = self.weid_to_leaf.write().await;
            map.retain(|_, existing| *existing != leaf_id);
            map.insert(we_epoch_id, leaf_id);
        }
    }

    async fn record_member_revocations(&self, leaves: &[[u8; 32]]) {
        if leaves.is_empty() {
            return;
        }
        let revoked: HashSet<[u8; 32]> = leaves.iter().copied().collect();
        {
            let mut metadata = self.member_metadata.write().await;
            for leaf in &revoked {
                metadata.remove(leaf);
            }
        }
        {
            let mut map = self.weid_to_leaf.write().await;
            map.retain(|_, existing| !revoked.contains(existing));
        }
    }

    async fn touch_member_for_weid(&self, we_epoch_id: &[u8; 32], timestamp_ms: u64) {
        let leaf = {
            let map = self.weid_to_leaf.read().await;
            map.get(we_epoch_id).copied()
        };
        if let Some(leaf_id) = leaf {
            let mut metadata = self.member_metadata.write().await;
            if let Some(entry) = metadata.get_mut(&leaf_id) {
                entry.last_seen_timestamp_ms = timestamp_ms;
            }
        }
    }

    fn broadcast_message(&self, notification: MessageNotification) {
        let _ = self
            .notification_tx
            .send(BroadcastNotification::Message(notification));
    }

    fn broadcast_membership(
        &self,
        gid: [u8; 32],
        leaf_id: [u8; 32],
        event: MembershipEventKind,
        timestamp_ms: u64,
    ) {
        let notification = MembershipNotification {
            gid,
            leaf_id,
            event,
            timestamp_ms,
        };
        let _ = self
            .notification_tx
            .send(BroadcastNotification::Membership(notification));
    }
}

#[derive(Clone)]
struct StoredMessage {
    we_epoch_id: [u8; 32],
    ciphertext: Vec<u8>,
    sender: Vec<u8>,
    timestamp_ms: u64,
}

const DEFAULT_FS_MESSAGE_RETENTION_SECS: u64 = 600;

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn message_retention_from_config(config: &cityg_config::CityGConfig) -> Duration {
    Duration::from_secs(DEFAULT_FS_MESSAGE_RETENTION_SECS.max(config.protocol.fs_policy.h_seconds))
}

fn prune_expired_messages(
    store: &mut AHashMap<[u8; 32], Vec<StoredMessage>>,
    now_ms: u64,
    retention: Duration,
) {
    let retention_ms_u128 = retention.as_millis().min(u128::from(u64::MAX));
    let retention_ms = retention_ms_u128 as u64;
    let cutoff = now_ms.saturating_sub(retention_ms);

    store.retain(|_, messages| {
        messages.retain(|msg| msg.timestamp_ms >= cutoff);
        !messages.is_empty()
    });
}

#[derive(Debug, Error)]
enum ApiError {
    #[error("failed to decode protobuf payload: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    #[error("server error: {message}")]
    Server {
        message: String,
        freeze: Option<FreezeError>,
        error_label: Option<&'static str>,
        failed_index: Option<u32>,
    },
    #[error("resource not found")]
    NotFound,
    #[error("rate limited")]
    RateLimited,
}

impl ApiError {
    fn server_message(message: impl Into<String>) -> Self {
        Self::server_with_context(message.into(), None, None, None)
    }

    fn server_with_freeze(message: impl Into<String>, freeze: FreezeError) -> Self {
        Self::server_with_context(message.into(), Some(freeze), None, None)
    }

    fn server_message_with_context(
        message: impl Into<String>,
        error_label: Option<&'static str>,
        failed_index: Option<u32>,
    ) -> Self {
        Self::server_with_context(message.into(), None, error_label, failed_index)
    }

    fn server_with_freeze_context(
        message: impl Into<String>,
        freeze: FreezeError,
        error_label: Option<&'static str>,
        failed_index: Option<u32>,
    ) -> Self {
        Self::server_with_context(message.into(), Some(freeze), error_label, failed_index)
    }

    fn server_with_context(
        message: String,
        freeze: Option<FreezeError>,
        error_label: Option<&'static str>,
        failed_index: Option<u32>,
    ) -> Self {
        ApiError::Server {
            message,
            freeze,
            error_label,
            failed_index,
        }
    }
}

impl From<ClientError> for ApiError {
    fn from(err: ClientError) -> Self {
        match err {
            ClientError::Acceptance(inner) => match inner {
                AcceptanceError::Freeze(freeze) => ApiError::server_with_freeze(
                    format!("acceptance error: {}", freeze.reason),
                    freeze,
                ),
                other => ApiError::server_message(format!("acceptance error: {other:?}")),
            },
            other => ApiError::server_message(other.to_string()),
        }
    }
}

#[derive(Serialize)]
struct ErrorResponse<'a> {
    message: &'a str,
    freeze_code: Option<u32>,
    freeze_reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed_index: Option<u32>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message, freeze, error_label, failed_index) = match self {
            ApiError::Decode(err) => (StatusCode::BAD_REQUEST, err.to_string(), None, None, None),
            ApiError::InvalidRequest(msg) => {
                (StatusCode::BAD_REQUEST, msg.to_string(), None, None, None)
            }
            ApiError::NotFound => (
                StatusCode::NOT_FOUND,
                "resource not found".to_string(),
                None,
                None,
                None,
            ),
            ApiError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate limited".to_string(),
                None,
                None,
                None,
            ),
            ApiError::Server {
                message,
                freeze,
                error_label,
                failed_index,
            } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                message,
                freeze,
                error_label,
                failed_index,
            ),
        };
        let freeze_code = freeze.map(|f| f.code);
        let freeze_reason = freeze.map(|f| f.reason);
        error!(status = %status, message = %message, freeze_code = ?freeze_code, freeze_reason = ?freeze_reason, "request failed");
        let body = ErrorResponse {
            message: &message,
            freeze_code,
            freeze_reason,
            error: error_label,
            failed_index,
        };
        // Handle serialization error gracefully with a fallback error message
        let payload = to_json_vec(&body).unwrap_or_else(|e| {
            error!("failed to serialize error body: {}", e);
            // Fallback to a simple JSON error message
            r#"{"message":"Internal server error"}"#.as_bytes().to_vec()
        });
        let mut response = (status, payload).into_response();
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        response
    }
}

fn parse_gid(room_id: &str) -> Result<[u8; 32], ApiError> {
    let bytes = Vec::from_hex(room_id)
        .map_err(|_| ApiError::InvalidRequest("room_id must be 64 hex characters"))?;
    if bytes.len() != 32 {
        return Err(ApiError::InvalidRequest("room_id must be 32 bytes"));
    }
    let mut gid = [0u8; 32];
    gid.copy_from_slice(&bytes);
    Ok(gid)
}

/// Verifies an identity binding signature.
/// The signature should be over CBOR([alias, pop_public_key])
fn verify_identity_binding(binding: &IdentityBinding) -> Result<(), ApiError> {
    use pqcrypto_dilithium::dilithium5;
    use pqcrypto_traits::sign::{
        DetachedSignature as DetachedSignatureTrait, PublicKey as PublicKeyTrait,
    };
    use serde_bytes::ByteBuf;

    // Validate inputs
    if binding.pop_public_key.len() != dilithium5::public_key_bytes() {
        return Err(ApiError::InvalidRequest("invalid pop_public_key length"));
    }
    if binding.signature.len() != dilithium5::signature_bytes() {
        return Err(ApiError::InvalidRequest("invalid signature length"));
    }
    if binding.alias.is_empty() {
        return Err(ApiError::InvalidRequest("alias cannot be empty"));
    }

    // Reconstruct the signed message: CBOR([alias, pop_public_key])
    let message_data = (
        ByteBuf::from(binding.alias.as_bytes().to_vec()),
        ByteBuf::from(binding.pop_public_key.clone()),
    );
    let mut message = Vec::new();
    ciborium::ser::into_writer(&message_data, &mut message)
        .map_err(|_| ApiError::InvalidRequest("failed to encode message for verification"))?;

    // Parse public key and signature using trait methods
    let public_key = <dilithium5::PublicKey as PublicKeyTrait>::from_bytes(&binding.pop_public_key)
        .map_err(|_| ApiError::InvalidRequest("invalid pop_public_key"))?;
    let signature =
        <dilithium5::DetachedSignature as DetachedSignatureTrait>::from_bytes(&binding.signature)
            .map_err(|_| ApiError::InvalidRequest("invalid signature"))?;

    // Verify signature
    dilithium5::verify_detached_signature(&signature, &message, &public_key)
        .map_err(|_| ApiError::InvalidRequest("signature verification failed"))?;

    Ok(())
}

async fn accept_epoch(State(state): State<ApiState>, body: Bytes) -> Result<Response, ApiError> {
    let request = AcceptEpochRequest::decode(body)?;
    let bundle = match ClientEpochBundle::from_cbor(&request.bundle_cbor) {
        Ok(bundle) => bundle,
        Err(ClientError::InvalidInput(_)) => {
            return Err(ApiError::InvalidRequest("invalid bundle encoding"));
        }
        Err(err) => return Err(ApiError::from(err)),
    };

    let response = apply_bundle(&state, &bundle).await?;
    Ok(protobuf_response(&response))
}

async fn apply_bundle(
    state: &ApiState,
    bundle: &ClientEpochBundle,
) -> Result<AcceptEpochResponse, ApiError> {
    let mut weid = [0u8; 32];
    weid.copy_from_slice(&bundle.we_epoch_id);

    let outcome = {
        let mut guard = state.server.write().await;
        match guard.accept_epoch(bundle) {
            Ok(outcome) => outcome,
            Err(err) => {
                drop(guard);
                return Err(map_accept_error(state, err, None, None).await);
            }
        }
    };

    let sanitized_bundle = bundle
        .to_cbor()
        .map_err(|err| ApiError::server_message(format!("failed to sanitize bundle: {err}")))?;
    persist_bundle(state, bundle, weid, sanitized_bundle).await?;
    Ok(accept_response_from(&outcome))
}

async fn store_bundle_bytes(state: &ApiState, weid: [u8; 32], bytes: Vec<u8>) {
    let mut guard = state.bundles.write().await;
    guard.insert(weid, bytes);
}

async fn persist_bundle(
    state: &ApiState,
    bundle: &ClientEpochBundle,
    weid: [u8; 32],
    bytes: Vec<u8>,
) -> Result<(), ApiError> {
    record_membership_updates(state, bundle, weid).await?;
    store_bundle_bytes(state, weid, bytes).await;
    Ok(())
}

async fn record_membership_updates(
    state: &ApiState,
    bundle: &ClientEpochBundle,
    weid: [u8; 32],
) -> Result<(), ApiError> {
    let delta = bundle.membership_delta().map_err(|err| {
        ApiError::server_message(format!("failed to compute membership delta: {err}"))
    })?;
    let gid: [u8; 32] = bundle
        .gid()
        .try_into()
        .map_err(|_| ApiError::server_message("invalid gid length in bundle"))?;

    let timestamp_ms = current_timestamp_ms();
    for leaf in &delta.joined {
        state.record_member_join(*leaf, weid, timestamp_ms).await;
        state.broadcast_membership(gid, *leaf, MembershipEventKind::Join, timestamp_ms);
    }
    if !delta.revoked.is_empty() {
        state.record_member_revocations(&delta.revoked).await;
        for leaf in &delta.revoked {
            state.broadcast_membership(gid, *leaf, MembershipEventKind::Revoke, timestamp_ms);
        }
    }
    Ok(())
}

fn accept_response_from(outcome: &ServerOutcome) -> AcceptEpochResponse {
    AcceptEpochResponse {
        we_epoch_id: outcome.we_epoch_id.to_vec(),
        wid: outcome.wid.to_vec(),
        parent_root: outcome.parent_root.to_vec(),
        new_root: outcome.new_root.to_vec(),
    }
}

async fn map_accept_error(
    state: &ApiState,
    err: ClientError,
    error_label: Option<&'static str>,
    failed_index: Option<u32>,
) -> ApiError {
    match err {
        ClientError::InvalidInput(_) => ApiError::InvalidRequest("invalid bundle components"),
        ClientError::Acceptance(AcceptanceError::Freeze(freeze)) => {
            state.record_freeze(freeze).await;
            ApiError::server_with_freeze_context(
                format!("acceptance error: {}", freeze.reason),
                freeze,
                error_label,
                failed_index,
            )
        }
        ClientError::Acceptance(other) => ApiError::server_message_with_context(
            format!("acceptance error: {other:?}"),
            error_label,
            failed_index,
        ),
        other => {
            ApiError::server_message_with_context(other.to_string(), error_label, failed_index)
        }
    }
}

const MEMBERS_DEFAULT_PAGE_SIZE: u32 = 256;
const MEMBERS_MAX_PAGE_SIZE: u32 = 2000;

async fn members(State(state): State<ApiState>, body: Bytes) -> Result<Response, ApiError> {
    let request = MembersRequest::decode(body)?;
    if request.gid.is_empty() {
        return Err(ApiError::InvalidRequest("gid must be provided"));
    }
    let gid = request.gid;
    let offset = request.offset.unwrap_or(0);
    let limit = request
        .limit
        .unwrap_or(MEMBERS_DEFAULT_PAGE_SIZE)
        .clamp(1, MEMBERS_MAX_PAGE_SIZE);

    let (members, root) = {
        let guard = state.server.read().await;
        if request.parent_root.is_empty() {
            let latest_root = guard.latest_parent_root(&gid).ok_or(ApiError::NotFound)?;
            let list = guard
                .members_for_root(&gid, &latest_root)
                .unwrap_or_default();
            (list, latest_root)
        } else {
            if request.parent_root.len() != 32 {
                return Err(ApiError::InvalidRequest("parent_root must be 32 bytes"));
            }
            let mut root = [0u8; 32];
            root.copy_from_slice(&request.parent_root);
            let list = guard
                .members_for_root(&gid, &root)
                .ok_or(ApiError::NotFound)?;
            (list, root)
        }
    };

    let total_count = members.len() as u64;
    let start = offset.min(total_count) as usize;
    let end = (start as u64 + u64::from(limit)).min(total_count) as usize;
    let next_offset = if end as u64 >= total_count {
        total_count
    } else {
        end as u64
    };

    let slice = &members[start..end];

    let alias_lookup = {
        let registry = state.alias_registry.read().await;
        let mut map: AHashMap<[u8; 32], (String, Vec<u8>)> = AHashMap::new();
        for (alias, binding) in registry.iter() {
            map.insert(
                binding.leaf_id,
                (alias.clone(), binding.pop_public_key.clone()),
            );
        }
        map
    };
    let metadata = state.member_metadata.read().await;

    let reply = MembersResponse {
        members: slice
            .iter()
            .map(|leaf| {
                let alias_info = alias_lookup.get(leaf);
                let metadata_entry = metadata.get(leaf);

                Member {
                    leaf_id: leaf.to_vec(),
                    alias: alias_info.map(|(alias, _)| alias.clone()),
                    pop_public_key: alias_info.map(|(_, pk)| pk.clone()),
                    join_date: metadata_entry.map(|entry| entry.join_timestamp_ms),
                    last_seen: metadata_entry.map(|entry| entry.last_seen_timestamp_ms),
                }
            })
            .collect(),
        root: root.to_vec(),
        total_count,
        next_offset,
    };

    Ok(protobuf_response(&reply))
}

async fn search_members(State(state): State<ApiState>, body: Bytes) -> Result<Response, ApiError> {
    let request = pb::SearchMembersRequest::decode(body)?;
    if request.gid.is_empty() {
        return Err(ApiError::InvalidRequest("gid must be provided"));
    }
    if request.query.is_empty() {
        return Err(ApiError::InvalidRequest("query must be provided"));
    }
    let gid = request.gid;
    let query = request.query.to_lowercase();
    let offset = request.offset.unwrap_or(0);
    let limit = request
        .limit
        .unwrap_or(MEMBERS_DEFAULT_PAGE_SIZE)
        .clamp(1, MEMBERS_MAX_PAGE_SIZE);

    let (members, root) = {
        let guard = state.server.read().await;
        if request.parent_root.is_empty() {
            let latest_root = guard.latest_parent_root(&gid).ok_or(ApiError::NotFound)?;
            let list = guard
                .members_for_root(&gid, &latest_root)
                .unwrap_or_default();
            (list, latest_root)
        } else {
            if request.parent_root.len() != 32 {
                return Err(ApiError::InvalidRequest("parent_root must be 32 bytes"));
            }
            let mut root = [0u8; 32];
            root.copy_from_slice(&request.parent_root);
            let list = guard
                .members_for_root(&gid, &root)
                .ok_or(ApiError::NotFound)?;
            (list, root)
        }
    };

    // Get alias registry for filtering
    let alias_lookup = {
        let registry = state.alias_registry.read().await;
        let mut map: AHashMap<[u8; 32], (String, Vec<u8>)> = AHashMap::new();
        for (alias, binding) in registry.iter() {
            map.insert(
                binding.leaf_id,
                (alias.clone(), binding.pop_public_key.clone()),
            );
        }
        map
    };
    let metadata = state.member_metadata.read().await;

    // Filter members by query (alias or leaf_id hex)
    let filtered_members: Vec<[u8; 32]> = members
        .iter()
        .filter(|leaf| {
            // Check if leaf_id hex matches query
            let hex = hex::encode(leaf);
            if hex.contains(&query) {
                return true;
            }

            // Check if alias matches query
            for (leaf_id, (alias, _)) in alias_lookup.iter() {
                if leaf_id == *leaf && alias.to_lowercase().contains(&query) {
                    return true;
                }
            }

            false
        })
        .copied()
        .collect();

    let total_count = filtered_members.len() as u64;
    let start = offset.min(total_count) as usize;
    let end = (start as u64 + u64::from(limit)).min(total_count) as usize;
    let next_offset = if end as u64 >= total_count {
        total_count
    } else {
        end as u64
    };

    let slice = &filtered_members[start..end];

    let reply = pb::SearchMembersResponse {
        members: slice
            .iter()
            .map(|leaf| {
                let alias_info = alias_lookup.get(leaf);
                let metadata_entry = metadata.get(leaf);

                Member {
                    leaf_id: leaf.to_vec(),
                    alias: alias_info.map(|(alias, _)| alias.clone()),
                    pop_public_key: alias_info.map(|(_, pk)| pk.clone()),
                    join_date: metadata_entry.map(|entry| entry.join_timestamp_ms),
                    last_seen: metadata_entry.map(|entry| entry.last_seen_timestamp_ms),
                }
            })
            .collect(),
        root: root.to_vec(),
        total_count,
        next_offset,
    };

    Ok(protobuf_response(&reply))
}

async fn join_ticket(State(state): State<ApiState>, body: Bytes) -> Result<Response, ApiError> {
    let request = JoinTicketRequest::decode(body)?;
    if request.room_id.is_empty() {
        return Err(ApiError::InvalidRequest("room_id must be provided"));
    }
    let gid = parse_gid(&request.room_id)?;

    // Verify identity binding if provided; persist TOFU alias only after ticket succeeds.
    let mut requested_leaf_id: Option<[u8; 32]> = None;
    let confirmed_binding = if let Some(binding) = &request.identity_binding {
        // Verify the signature
        verify_identity_binding(binding)?;

        // Bind the join ticket leaf to the provided PoP public key.
        let computed_leaf = compute_leaf_id(
            LeafIdMode::PerGroup,
            &gid,
            "ML-DSA-65",
            &binding.pop_public_key,
        )
        .map_err(|e| ApiError::server_message(format!("failed to compute leaf_id: {}", e)))?;
        requested_leaf_id = Some(computed_leaf);

        Some(binding.clone())
    } else {
        None
    };

    let (ticket, policy_version, fs_policy_version, fs_epoch_base_ts, bootstrap_public) = {
        let mut guard = state.server.write().await;
        let bundle = guard
            .build_join_ticket_with_leaf(&gid, requested_leaf_id)
            .map_err(ApiError::from)?;
        let policy_version = guard.context().policy_version().to_string();
        let fs_policy_version = guard
            .context()
            .fs_policy_version()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "fs-policy-v1".to_string());
        let fs_epoch_base_ts = match guard.context().fs_base_ts() {
            Some(base_ts) => base_ts,
            None => {
                let base_ts =
                    aligned_fs_epoch_base_ts(SystemTime::now(), state.fs_epoch_period_seconds);
                guard.context_mut().set_fs_base_ts(Some(base_ts));
                base_ts
            }
        };
        let bootstrap_public = guard
            .context()
            .bootstrap_public_key()
            .map(|key| key.to_vec())
            .unwrap_or_default();
        (
            bundle,
            policy_version,
            fs_policy_version,
            fs_epoch_base_ts,
            bootstrap_public,
        )
    };

    if let Some(binding) = confirmed_binding.as_ref() {
        state
            .register_alias(
                &binding.alias,
                ticket.leaf_id,
                binding.pop_public_key.clone(),
            )
            .await?;
    }

    let response = JoinTicketResponse {
        gid: ticket.gid.to_vec(),
        cat: ticket.cat.to_vec(),
        parent_root: ticket.parent_root.to_vec(),
        revoked_root: ticket.revoked_root.to_vec(),
        revoked_since_root: ticket.revoked_since_root.to_vec(),
        tswe_salt_hash: ticket.tswe_salt_hash.to_vec(),
        join_delta_root: ticket.join_delta_root.to_vec(),
        leaf_id: ticket.leaf_id.to_vec(),
        pox_r_commit: ticket.pox_r_commit.to_vec(),
        witness_cbor: ticket.witness_cbor,
        srx_cbor: ticket.srx_cbor,
        msphf_crs_id: RLWE_CRS_ID_DEFAULT.to_string(),
        msphf_params_id: RLWE_PARAMS_ID_MOCK.to_string(),
        proof_mode: DEFAULT_PROOF_MODE.to_string(),
        vrf_id: DEFAULT_VRF_ID.to_string(),
        policy_version,
        fs_policy_version,
        fs_epoch_base_ts,
        kbroad_public: ticket.kbroad_public,
        bootstrap_public,
        confirmed_binding: confirmed_binding.clone(),
    };

    Ok(protobuf_response(&response))
}

async fn bootstrap_room(State(state): State<ApiState>, body: Bytes) -> Result<Response, ApiError> {
    let request = BootstrapRoomRequest::decode(body)?;
    if request.room_id.is_empty() {
        return Err(ApiError::InvalidRequest("room_id must be provided"));
    }
    if request.kbroad_public.is_empty() {
        return Err(ApiError::InvalidRequest("kbroad_public must be provided"));
    }

    if request.kbroad_public.len() != ml_kem_public_key_bytes() {
        return Err(ApiError::InvalidRequest(
            "kbroad_public has unexpected length",
        ));
    }

    let gid = parse_gid(&request.room_id)?;

    {
        let mut guard = state.server.write().await;
        guard
            .register_group(&gid, request.kbroad_public)
            .map_err(ApiError::from)?;
    }

    let response = BootstrapRoomResponse {
        status: "registered".to_string(),
    };

    Ok(protobuf_response(&response))
}

async fn merge_ticket(State(state): State<ApiState>, body: Bytes) -> Result<Response, ApiError> {
    let request = MergeTicketRequest::decode(body)?;
    if request.room_id.is_empty() {
        return Err(ApiError::InvalidRequest("room_id must be provided"));
    }
    if request.leaf_id.len() != 32 {
        return Err(ApiError::InvalidRequest("leaf_id must be 32 bytes"));
    }

    let gid = parse_gid(&request.room_id)?;
    let mut leaf_id = [0u8; 32];
    leaf_id.copy_from_slice(&request.leaf_id);

    let bundle = {
        let mut guard = state.server.write().await;
        guard
            .build_merge_ticket(&gid, &leaf_id)
            .map_err(ApiError::from)?
    };

    let MergeTicketBundle {
        gid: _,
        cat,
        parent_root,
        leaf_id: _,
        pivot_we_epoch_id,
        parities,
        witness_cbor,
        srx_cbor,
        join_delta_root,
        revoked_since_root,
        revoked_root,
        tswe_salt_hash,
        pox_r_commit,
        proof_mode,
        vrf_id,
        policy_version,
        msphf_crs_id,
        msphf_params_id,
        fs_policy_version,
        fs_epoch_base_ts,
        kbroad_public,
    } = bundle;

    let pivot_parity_cbor = parities
        .iter()
        .map(pivot_parity_to_cbor)
        .collect::<Result<Vec<_>, _>>()?;

    let response = MergeTicketResponse {
        we_epoch_id: pivot_we_epoch_id.to_vec(),
        pivot_parity_cbor,
        witness_cbor,
        proof_mode,
        vrf_id,
        policy_version,
        kbroad_public,
        cat: cat.to_vec(),
        parent_root: parent_root.to_vec(),
        join_delta_root: join_delta_root.to_vec(),
        revoked_since_root: revoked_since_root.to_vec(),
        revoked_root: revoked_root.to_vec(),
        tswe_salt_hash: tswe_salt_hash.to_vec(),
        pox_r_commit: pox_r_commit.to_vec(),
        srx_cbor,
        msphf_crs_id,
        msphf_params_id,
        fs_policy_version,
        fs_epoch_base_ts,
    };

    Ok(protobuf_response(&response))
}

async fn send_message(State(state): State<ApiState>, body: Bytes) -> Result<Response, ApiError> {
    let request = SendMessageRequest::decode(body)?;
    if request.we_epoch_id.len() != 32 {
        return Err(ApiError::InvalidRequest("we_epoch_id must be 32 bytes"));
    }

    let mut weid = [0u8; 32];
    weid.copy_from_slice(&request.we_epoch_id);
    let ciphertext = request.ciphertext;
    if ciphertext.is_empty() {
        return Err(ApiError::InvalidRequest("ciphertext must be provided"));
    }

    let sender = request.sender;
    let timestamp_ms = current_timestamp_ms();

    let stored = StoredMessage {
        we_epoch_id: weid,
        ciphertext,
        sender,
        timestamp_ms,
    };

    {
        let mut guard = state.messages.write().await;
        guard.entry(weid).or_default().push(stored);
        prune_expired_messages(&mut guard, timestamp_ms, state.message_retention);
    }

    // Broadcast notification to WebSocket clients
    let notification = MessageNotification {
        we_epoch_id: weid,
        timestamp_ms,
    };
    state.broadcast_message(notification);

    state.touch_member_for_weid(&weid, timestamp_ms).await;

    let reply = SendMessageResponse {
        status: "stored".to_string(),
    };
    Ok(protobuf_response(&reply))
}

async fn fetch_messages(State(state): State<ApiState>, body: Bytes) -> Result<Response, ApiError> {
    let request = FetchMessagesRequest::decode(body)?;
    if request.we_epoch_id.len() != 32 {
        return Err(ApiError::InvalidRequest("we_epoch_id must be 32 bytes"));
    }
    let mut weid = [0u8; 32];
    weid.copy_from_slice(&request.we_epoch_id);

    let messages = {
        let mut guard = state.messages.write().await;
        prune_expired_messages(&mut guard, current_timestamp_ms(), state.message_retention);
        guard.get(&weid).cloned().unwrap_or_default()
    };

    let reply = FetchMessagesResponse {
        messages: messages
            .into_iter()
            .map(|msg| ChatMessage {
                ciphertext: msg.ciphertext,
                we_epoch_id: msg.we_epoch_id.to_vec(),
                sender: msg.sender,
                timestamp_ms: msg.timestamp_ms,
            })
            .collect(),
    };

    Ok(protobuf_response(&reply))
}

async fn websocket_handler(ws: WebSocketUpgrade, State(state): State<ApiState>) -> Response {
    ws.on_upgrade(|socket| handle_websocket(socket, state))
}

async fn handle_websocket(socket: WebSocket, state: ApiState) {
    let (mut sender, mut receiver) = socket.split();

    // Subscribe to server notifications
    let mut rx = state.notification_tx.subscribe();

    debug!("WebSocket client connected");

    // Track connection health for auto-reconnect signaling
    let connection_healthy = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let conn_healthy_clone = connection_healthy.clone();

    // Spawn a task to handle incoming messages from the client (ping/pong)
    let mut recv_task = tokio::spawn(async move {
        let mut last_pong = Instant::now();
        let pong_timeout = Duration::from_secs(60);

        while let Some(result) = receiver.next().await {
            match result {
                Ok(WsMessage::Close(_)) => {
                    debug!("WebSocket client sent close message");
                    conn_healthy_clone.store(false, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
                Ok(WsMessage::Ping(_)) => {
                    debug!("WebSocket received ping");
                    last_pong = Instant::now();
                }
                Ok(WsMessage::Pong(_)) => {
                    debug!("WebSocket received pong");
                    last_pong = Instant::now();
                }
                Ok(_) => {
                    // Ignore other message types from client
                }
                Err(e) => {
                    warn!("WebSocket receive error: {}", e);
                    conn_healthy_clone.store(false, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
            }

            // Check for pong timeout
            if last_pong.elapsed() > pong_timeout {
                warn!("WebSocket pong timeout, considering connection unhealthy");
                conn_healthy_clone.store(false, std::sync::atomic::Ordering::Relaxed);
                break;
            }
        }
    });

    // Main task: forward message notifications to the WebSocket client
    let mut send_task = tokio::spawn(async move {
        let ping_interval = Duration::from_secs(30);
        let mut last_ping = Instant::now();

        loop {
            // Check connection health
            if !connection_healthy.load(std::sync::atomic::Ordering::Relaxed) {
                debug!("WebSocket connection marked unhealthy, closing send loop");
                break;
            }

            tokio::select! {
                // Wait for message notifications
                result = rx.recv() => {
                    match result {
                        Ok(notification) => {
                            let payload = match notification {
                                BroadcastNotification::Message(msg) => serde_json::json!({
                                    "type": "message",
                                    "we_epoch_id": hex::encode(msg.we_epoch_id),
                                    "timestamp_ms": msg.timestamp_ms,
                                    "connection_healthy": true
                                }),
                                BroadcastNotification::Membership(event) => {
                                    let kind = match event.event {
                                        MembershipEventKind::Join => "join",
                                        MembershipEventKind::Revoke => "revoke",
                                    };
                                    serde_json::json!({
                                        "type": "membership",
                                        "gid": hex::encode(event.gid),
                                        "leaf_id": hex::encode(event.leaf_id),
                                        "event": kind,
                                        "timestamp_ms": event.timestamp_ms
                                    })
                                }
                            };

                            let text = match serde_json::to_string(&payload) {
                                Ok(t) => t,
                                Err(e) => {
                                    error!("Failed to serialize notification: {}", e);
                                    continue;
                                }
                            };

                            if let Err(e) = sender.send(WsMessage::Text(text)).await {
                                warn!("Failed to send WebSocket message: {}", e);
                                connection_healthy.store(false, std::sync::atomic::Ordering::Relaxed);
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("WebSocket client lagged by {} messages", n);
                            // Send lag notification to client
                            let lag_notification = serde_json::json!({
                                "type": "lag",
                                "lagged_messages": n,
                                "recommendation": "consider reconnecting"
                            });
                            if let Ok(text) = serde_json::to_string(&lag_notification) {
                                let _ = sender.send(WsMessage::Text(text)).await;
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            info!("Message broadcast channel closed");
                            break;
                        }
                    }
                }

                // Send periodic ping to keep connection alive
                _ = tokio::time::sleep(ping_interval) => {
                    if last_ping.elapsed() >= ping_interval {
                        if let Err(e) = sender.send(WsMessage::Ping(vec![])).await {
                            warn!("Failed to send ping: {}", e);
                            connection_healthy.store(false, std::sync::atomic::Ordering::Relaxed);
                            break;
                        }
                        last_ping = Instant::now();
                    }
                }
            }
        }
    });

    // Wait for either task to complete
    tokio::select! {
        _ = &mut send_task => {
            debug!("WebSocket send task completed");
            recv_task.abort();
        }
        _ = &mut recv_task => {
            debug!("WebSocket receive task completed");
            send_task.abort();
        }
    }

    info!("WebSocket client disconnected");
}

async fn get_bundle(State(state): State<ApiState>, body: Bytes) -> Result<Response, ApiError> {
    let request = GetBundleRequest::decode(body)?;
    if request.we_epoch_id.len() != 32 {
        return Err(ApiError::InvalidRequest("we_epoch_id must be 32 bytes"));
    }
    let mut weid = [0u8; 32];
    weid.copy_from_slice(&request.we_epoch_id);

    let bytes = {
        let guard = state.bundles.read().await;
        guard.get(&weid).cloned().ok_or(ApiError::NotFound)?
    };

    let reply = GetBundleResponse { bundle_cbor: bytes };

    Ok(protobuf_response(&reply))
}

async fn health_legacy_with_state(State(_state): State<ApiState>) -> Response {
    let reply = HealthResponse {
        status: "ok".to_string(),
    };
    protobuf_response(&reply)
}

async fn health_liveness(State(_state): State<ApiState>) -> Response {
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "alive": true
        })),
    )
        .into_response()
}

async fn health_readiness(State(_state): State<ApiState>) -> Response {
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "ready": true
        })),
    )
        .into_response()
}

async fn health_detailed(State(_state): State<ApiState>) -> Response {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "status": "healthy",
            "timestamp": timestamp,
            "version": env!("CARGO_PKG_VERSION"),
            "checks": [
                {
                    "name": "system",
                    "status": "healthy",
                    "message": "Service is running"
                }
            ]
        })),
    )
        .into_response()
}

async fn get_window(State(state): State<ApiState>, body: Bytes) -> Result<Response, ApiError> {
    let _ = GetWindowRequest::decode(body)?;
    let snapshot = {
        let guard = state.server.read().await;
        let now = guard.context().current_time();
        guard
            .context()
            .mh_window
            .snapshot()
            .into_iter()
            .map(|(wid, heads)| WindowEntry {
                wid,
                heads: heads
                    .into_iter()
                    .map(|record| {
                        let age_ms = now
                            .duration_since(record.accept_time())
                            .as_millis()
                            .min(u64::MAX as u128) as u64;
                        WindowHead {
                            we_epoch_id: record.we_epoch_id.to_vec(),
                            msphf_hp_commit: record.msphf_hp_commit.to_vec(),
                            seed_ctx_hash: record.seed_ctx_hash.to_vec(),
                            rho_commit: record.rho_commit.to_vec(),
                            seed_commit: record.seed_commit.to_vec(),
                            xk_hash: record.xk_hash.to_vec(),
                            accept_seq: record.accept_seq,
                            age_ms,
                        }
                    })
                    .collect(),
            })
            .collect::<Vec<_>>()
    };

    let reply = GetWindowResponse { entries: snapshot };
    Ok(protobuf_response(&reply))
}

async fn get_telemetry(State(state): State<ApiState>, body: Bytes) -> Result<Response, ApiError> {
    let _ = GetTelemetryRequest::decode(body)?;
    let report = {
        let guard = state.server.read().await;
        guard.context().telemetry_report()
    };

    let entries = report
        .into_iter()
        .map(|(key, counters)| TelemetryEntry {
            gid: key.gid.to_vec(),
            parent_root: key.parent_root.to_vec(),
            head_attempts: counters.head_attempts,
            head_insertions: counters.head_insertions,
            freeze_window_full: counters.freeze_window_full,
            freeze_rho_replay: counters.freeze_rho_replay,
            last_active_heads: counters.last_active_heads as u64,
        })
        .collect();

    let freeze_stats = state
        .freeze_stats()
        .await
        .into_iter()
        .map(|(code, reason, count)| FreezeStat {
            code,
            reason,
            count,
        })
        .collect();

    let reply = GetTelemetryResponse {
        entries,
        freeze_stats,
    };
    Ok(protobuf_response(&reply))
}

fn pivot_parity_to_cbor(parity: &PivotParity) -> Result<Vec<u8>, ApiError> {
    #[derive(Serialize)]
    struct PivotParitySerializable {
        gid: ByteBuf,
        cat: ByteBuf,
        parent_root: ByteBuf,
        we_epoch_id: ByteBuf,
        rho_commit: ByteBuf,
        seed_ctx_hash: ByteBuf,
        seed_commit: ByteBuf,
        hp_commit: ByteBuf,
        xk_hash: ByteBuf,
        join_delta_root: ByteBuf,
        revoked_since_root: ByteBuf,
        revoked_root: ByteBuf,
        accept_seq: u64,
        crs_id: ByteBuf,
        params_id: ByteBuf,
        policy_version: String,
        proof_mode: String,
        vrf_id: String,
        vrf_proof: ByteBuf,
        vrf_public: ByteBuf,
        mask_a: ByteBuf,
        mask_b: ByteBuf,
        fs_capss: ByteBuf,
        proofs_commit: ByteBuf,
        srx_commit: Option<ByteBuf>,
        is_join: bool,
        hp_envelope: ByteBuf,
        fs_epoch_commit: Option<ByteBuf>,
        fs_ec: Option<u64>,
        fs_dev_commit: Option<ByteBuf>,
    }

    let serializable = PivotParitySerializable {
        gid: ByteBuf::from(parity.gid.clone()),
        cat: ByteBuf::from(parity.cat.clone()),
        parent_root: ByteBuf::from(parity.parent_root.to_vec()),
        we_epoch_id: ByteBuf::from(parity.we_epoch_id.to_vec()),
        rho_commit: ByteBuf::from(parity.rho_commit.to_vec()),
        seed_ctx_hash: ByteBuf::from(parity.seed_ctx_hash.to_vec()),
        seed_commit: ByteBuf::from(parity.seed_commit.to_vec()),
        hp_commit: ByteBuf::from(parity.hp_commit.to_vec()),
        xk_hash: ByteBuf::from(parity.xk_hash.to_vec()),
        join_delta_root: ByteBuf::from(parity.join_delta_root.to_vec()),
        revoked_since_root: ByteBuf::from(parity.revoked_since_root.to_vec()),
        revoked_root: ByteBuf::from(parity.revoked_root.to_vec()),
        accept_seq: parity.accept_seq,
        crs_id: ByteBuf::from(parity.crs_id.clone()),
        params_id: ByteBuf::from(parity.params_id.clone()),
        policy_version: parity.policy_version.clone(),
        proof_mode: parity.proof_mode.clone(),
        vrf_id: parity.vrf_id.clone(),
        vrf_proof: ByteBuf::from(parity.vrf_proof.clone()),
        vrf_public: ByteBuf::from(parity.vrf_public.clone()),
        mask_a: ByteBuf::from(parity.mask_a.to_vec()),
        mask_b: ByteBuf::from(parity.mask_b.to_vec()),
        fs_capss: ByteBuf::from(parity.fs_capss.clone()),
        proofs_commit: ByteBuf::from(parity.proofs_commit.to_vec()),
        srx_commit: parity
            .srx_commit
            .map(|commit| ByteBuf::from(commit.to_vec())),
        is_join: parity.is_join,
        hp_envelope: ByteBuf::from(parity.hp_envelope.as_ref().to_vec()),
        fs_epoch_commit: parity
            .fs_epoch_commit
            .map(|commit| ByteBuf::from(commit.to_vec())),
        fs_ec: parity.fs_ec,
        fs_dev_commit: parity
            .fs_dev_commit
            .map(|commit| ByteBuf::from(commit.to_vec())),
    };

    let mut buf = Vec::new();
    into_writer(&serializable, &mut buf)
        .map_err(|_| ApiError::server_message("failed to encode pivot parity"))?;
    Ok(buf)
}

async fn configure_window(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request = ConfigureWindowRequest::decode(body)?;
    let h_max = request
        .h_max
        .map(|value| {
            if value == 0 {
                Err(ApiError::InvalidRequest("h_max must be at least 1"))
            } else if value > 1024 {
                Err(ApiError::InvalidRequest("h_max too large"))
            } else {
                Ok(value as usize)
            }
        })
        .transpose()?;
    let ttl = request
        .ttl_ms
        .map(|value| {
            if value == 0 {
                Err(ApiError::InvalidRequest("ttl_ms must be positive"))
            } else {
                Ok(Duration::from_millis(u64::from(value)))
            }
        })
        .transpose()?;

    let (effective_h, effective_ttl) = {
        let mut guard = state.server.write().await;
        guard.update_window_limits(h_max, ttl);
        guard.window_limits()
    };

    let ttl_ms = effective_ttl.as_millis().min(u128::from(u32::MAX)) as u32;

    let reply = ConfigureWindowResponse {
        h_max: effective_h as u32,
        ttl_ms,
    };
    Ok(protobuf_response(&reply))
}

fn protobuf_response<M: Message>(message: &M) -> Response {
    let mut buf = BytesMut::new();
    buf.reserve(message.encoded_len());

    // Handle encoding error gracefully
    if let Err(e) = message.encode(&mut buf) {
        error!("failed to encode protobuf response: {}", e);
        return ApiError::server_message("Failed to encode response").into_response();
    }

    let mut response = Response::new(buf.freeze().into());
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-protobuf"),
    );
    response
}

pub async fn run() -> anyhow::Result<()> {
    use cityg_config::CityGConfig;

    // Load configuration
    let config =
        CityGConfig::load().map_err(|e| anyhow::anyhow!("failed to load configuration: {}", e))?;

    // Validate configuration
    config
        .validate()
        .map_err(|e| anyhow::anyhow!("configuration validation failed: {}", e))?;

    tracing::info!("Configuration loaded successfully");
    tracing::info!("Server will bind to: {}", config.server.address);

    let addr = config.server.address.parse().map_err(|e| {
        anyhow::anyhow!(
            "failed to parse server address '{}': {}",
            config.server.address,
            e
        )
    })?;

    run_with_config(addr, config).await
}

pub async fn run_with_addr(addr: SocketAddr) -> anyhow::Result<()> {
    use cityg_config::CityGConfig;
    let config = CityGConfig::default();
    run_with_config(addr, config).await
}

fn server_from_config(cfg: &cityg_config::CityGConfig) -> CityGServer {
    let mut server_cfg = ServerConfig::new();
    server_cfg.h_max = Some(cfg.protocol.max_concurrent_heads);
    server_cfg.window_ttl = Some(Duration::from_secs(cfg.server.window_ttl_secs));

    let mut acceptance = AcceptanceOptions {
        srx_max_bytes: cfg.protocol.default_srx_max_bytes,
        fs_policy_config: fs_policy_from_settings(&cfg.protocol.fs_policy),
        ..AcceptanceOptions::default()
    };

    if cfg.server.seed_demo_room {
        acceptance.bootstrap_policy = BootstrapPolicy::CaMlDsa {
            public_key: cityg_client::demo::bootstrap_public().to_vec(),
        };
        let mut registry = BTreeMap::new();
        registry.insert(
            cityg_client::demo::DEMO_GID.to_vec(),
            cityg_client::demo::kbroad_public().to_vec(),
        );
        acceptance.kbroad_registry = Some(registry);
    }

    server_cfg.acceptance_options = Some(acceptance);

    let mut server = CityGServer::new(server_cfg);
    let version = cfg.protocol.fs_policy_version.clone();
    {
        let ctx = server.context_mut();
        ctx.set_allowed_fs_policy_version(Some(version.clone()));
        ctx.set_fs_policy_version(Some(version));
    }
    server
}

fn aligned_fs_epoch_base_ts(now: SystemTime, period_seconds: u64) -> u64 {
    let period = period_seconds.max(1);
    let now_secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    now_secs - (now_secs % period)
}

fn fs_policy_from_settings(settings: &cityg_config::FsPolicySettings) -> FsPolicyConfig {
    FsPolicyConfig {
        h_seconds: settings.h_seconds,
        checkpoint_interval_seconds: settings.checkpoint_interval_seconds,
        checkpoint_head_threshold: settings.checkpoint_head_threshold,
        slack_anchor: settings.slack_anchor,
        slack_first_device: settings.slack_first_device,
        slack_device: settings.slack_device,
    }
}

pub async fn run_with_config(
    addr: SocketAddr,
    config: cityg_config::CityGConfig,
) -> anyhow::Result<()> {
    // Initialize structured logging based on environment
    init_logging()?;

    // Initialize metrics exporter
    let prometheus_handle = match middleware::init_metrics_exporter() {
        Ok(handle) => Some(handle),
        Err(err) => {
            warn!("metrics exporter disabled: {}", err);
            None
        }
    };

    let server = server_from_config(&config);
    let message_retention = message_retention_from_config(&config);
    info!(
        "message retention window set to {}s",
        message_retention.as_secs()
    );
    // Create broadcast channel for WebSocket notifications (capacity from config)
    let (notification_tx, _) = broadcast::channel(config.server.websocket_capacity);

    let state = ApiState {
        server: Arc::new(RwLock::new(server)),
        messages: Arc::new(RwLock::new(AHashMap::new())),
        bundles: Arc::new(RwLock::new(AHashMap::new())),
        message_retention,
        fs_epoch_period_seconds: config.protocol.fs_policy.h_seconds.max(1),
        freeze_counts: Arc::new(RwLock::new(BTreeMap::new())),
        alias_registry: Arc::new(RwLock::new(AHashMap::new())),
        member_metadata: Arc::new(RwLock::new(AHashMap::new())),
        weid_to_leaf: Arc::new(RwLock::new(AHashMap::new())),
        notification_tx,
        alias_rate_limiter: AliasRateLimiter::new(
            ALIAS_RATE_LIMIT_BURST,
            Duration::from_secs(ALIAS_RATE_LIMIT_WINDOW_SECS),
        ),
    };

    // Build router with all routes
    let mut router_with_state = Router::new()
        .route("/health", get(health_legacy_with_state))
        .route("/health/live", get(health_liveness))
        .route("/health/ready", get(health_readiness))
        .route("/health/detailed", get(health_detailed))
        .route("/v1/ws", get(websocket_handler))
        .route("/v1/accept_epoch", post(accept_epoch))
        .route("/v1/members", post(members))
        .route("/v1/members/search", post(search_members))
        .route("/v1/send_message", post(send_message))
        .route("/v1/messages", post(fetch_messages))
        .route("/v1/window", post(get_window))
        .route("/v1/telemetry", post(get_telemetry))
        .route("/v1/config/window", post(configure_window))
        .route("/v1/bundle", post(get_bundle))
        .route("/v1/rooms/bootstrap", post(bootstrap_room))
        .route("/v1/rooms/join_ticket", post(join_ticket))
        .route("/v1/rooms/merge_ticket", post(merge_ticket))
        .route("/v1/pivot/refresh", post(refresh_pivot));

    #[cfg(any(debug_assertions, feature = "debug-api"))]
    {
        router_with_state =
            router_with_state.route("/v1/debug/window/seed", post(seed_window_head));
    }

    let metrics_handle = prometheus_handle.clone();
    if let Some(handle) = metrics_handle {
        let handle_clone = handle.clone();
        router_with_state = router_with_state.route(
            "/metrics",
            get(move || {
                let handle = handle_clone.clone();
                async move { handle.render() }
            }),
        );
    } else {
        router_with_state =
            router_with_state.route("/metrics", get(|| async { "metrics not available" }));
    }

    let mut app: Router = router_with_state
        .with_state(state)
        .layer(axum_middleware::from_fn(
            middleware::request_tracing_middleware,
        ));

    if prometheus_handle.is_some() {
        app = app.layer(axum_middleware::from_fn(middleware::metrics_middleware));
    }

    info!("listening on {addr}");
    info!("metrics available at http://{}/metrics", addr);
    info!("health check at http://{}/health/detailed", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Initialize logging based on environment variables
fn init_logging() -> anyhow::Result<()> {
    let env_filter = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new("info"))?;

    // Check if JSON logging is requested
    let use_json = std::env::var("LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    if use_json {
        // JSON structured logging for production
        // Ignore error if subscriber is already initialized (e.g., in tests)
        let _ = tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().json())
            .try_init();
    } else {
        // Human-readable logging for development
        // Ignore error if subscriber is already initialized (e.g., in tests)
        let _ = tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer())
            .try_init();
    }

    Ok(())
}

#[cfg(any(debug_assertions, feature = "debug-api"))]
async fn seed_window_head(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Response, ApiError> {
    use msphf_core::hash::h_l;
    use msphf_orchestrator::mhw::HeadRecord;
    use serde::Serialize;

    #[derive(Serialize)]
    struct WindowInputs<'a> {
        #[serde(with = "serde_bytes")]
        gid: &'a [u8],
        #[serde(with = "serde_bytes")]
        parent_root: &'a [u8; 32],
        #[serde(with = "serde_bytes")]
        seed_ctx_hash: &'a [u8; 32],
    }

    let request = SeedHeadRequest::decode(body)?;
    if request.bundle_cbor.is_empty() {
        return Err(ApiError::InvalidRequest("bundle_cbor must be provided"));
    }

    let bundle = match ClientEpochBundle::from_cbor(&request.bundle_cbor) {
        Ok(bundle) => bundle,
        Err(ClientError::InvalidInput(_)) => {
            return Err(ApiError::InvalidRequest("invalid bundle encoding"));
        }
        Err(err) => return Err(ApiError::server_message(err.to_string())),
    };

    let wid = h_l(
        "mhw/window",
        &WindowInputs {
            gid: bundle.gid(),
            parent_root: &bundle.anchor.parent_root,
            seed_ctx_hash: &bundle.hp_binding.seed_ctx_hash,
        },
    )
    .map_err(|err| ApiError::server_message(err.to_string()))?;

    {
        let mut guard = state.server.write().await;
        let accept_time = guard.context_mut().next_accept_instant();
        let record = HeadRecord::new(
            bundle.we_epoch_id,
            bundle.hp_binding.hp_commit,
            bundle.hp_binding.seed_ctx_hash,
            bundle.hp_binding.rho_commit,
            bundle.hp_binding.seed_commit,
            bundle.hp_binding.xk_hash,
            bundle.anchor.join_delta_root,
            bundle.anchor.revoked_since_prev_root,
            bundle.anchor.revoked_root,
            0,
            accept_time,
        );
        guard
            .context_mut()
            .mh_window
            .accept_head(&wid, record, accept_time)
            .map_err(|err| ApiError::server_message(err.reason.to_string()))?;
    }

    let reply = SeedHeadResponse {};
    Ok(protobuf_response(&reply))
}

async fn refresh_pivot(State(state): State<ApiState>, body: Bytes) -> Result<Response, ApiError> {
    let request = RefreshPivotRequest::decode(body)?;
    if request.bundle_cbor.is_empty() {
        return Err(ApiError::InvalidRequest("bundle_cbor must be provided"));
    }

    let bundle = match ClientEpochBundle::from_cbor(&request.bundle_cbor) {
        Ok(bundle) => bundle,
        Err(ClientError::InvalidInput(_)) => {
            return Err(ApiError::InvalidRequest("invalid bundle encoding"));
        }
        Err(err) => return Err(ApiError::server_message(err.to_string())),
    };

    {
        let mut guard = state.server.write().await;
        guard
            .refresh_pivot(&bundle)
            .map_err(|err| ApiError::server_message(err.to_string()))?;
    }

    let reply = RefreshPivotResponse {};
    Ok(protobuf_response(&reply))
}
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::routing::get;
    use cityg_client::demo::{DEMO_GID, demo_bundle};
    use cityg_config::CityGConfig;
    use futures::{SinkExt, StreamExt};
    use msphf_core::MsphfError;
    use pqcrypto_dilithium::dilithium5;
    use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
    use prost::Message;
    use serde_bytes::ByteBuf;
    use serde_json::Value;

    fn test_api_state() -> ApiState {
        let mut cfg = CityGConfig::default();
        cfg.server.seed_demo_room = true;
        ApiState {
            server: Arc::new(RwLock::new(server_from_config(&cfg))),
            messages: Arc::new(RwLock::new(AHashMap::new())),
            bundles: Arc::new(RwLock::new(AHashMap::new())),
            message_retention: Duration::from_secs(DEFAULT_FS_MESSAGE_RETENTION_SECS),
            fs_epoch_period_seconds: cfg.protocol.fs_policy.h_seconds.max(1),
            freeze_counts: Arc::new(RwLock::new(BTreeMap::new())),
            alias_registry: Arc::new(RwLock::new(AHashMap::new())),
            member_metadata: Arc::new(RwLock::new(AHashMap::new())),
            weid_to_leaf: Arc::new(RwLock::new(AHashMap::new())),
            notification_tx: broadcast::channel(8).0,
            alias_rate_limiter: AliasRateLimiter::new(
                ALIAS_RATE_LIMIT_BURST,
                Duration::from_secs(ALIAS_RATE_LIMIT_WINDOW_SECS),
            ),
        }
    }

    async fn decode_proto_response<T>(response: Response) -> T
    where
        T: Message + Default,
    {
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        T::decode(body).expect("decode protobuf response")
    }

    fn encode_proto_request<T>(message: &T) -> Bytes
    where
        T: Message,
    {
        let mut body = Vec::new();
        message.encode(&mut body).expect("encode protobuf request");
        Bytes::from(body)
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_identity_binding_creation_and_verification() {
        // Generate a keypair
        let (pop_pk, pop_sk) = dilithium5::keypair();
        let pop_public_key = pop_pk.as_bytes().to_vec();
        let alias = "alice".to_string();

        // Create the message to sign: CBOR([alias, pop_public_key])
        let message_data = (
            ByteBuf::from(alias.as_bytes().to_vec()),
            ByteBuf::from(pop_public_key.clone()),
        );
        let mut message = Vec::new();
        ciborium::ser::into_writer(&message_data, &mut message)
            .expect("encode identity binding message");

        // Sign the message
        let signature = dilithium5::detached_sign(&message, &pop_sk);

        // Create the identity binding
        let binding = IdentityBinding {
            alias: alias.clone(),
            pop_public_key: pop_public_key.clone(),
            signature: signature.as_bytes().to_vec(),
        };

        // Verify it
        let result = verify_identity_binding(&binding);
        assert!(
            result.is_ok(),
            "Identity binding verification should succeed"
        );
    }

    #[test]
    fn test_identity_binding_wrong_signature() {
        // Generate a keypair
        let (pop_pk, pop_sk) = dilithium5::keypair();
        let pop_public_key = pop_pk.as_bytes().to_vec();
        let alias = "alice".to_string();

        // Sign the wrong message
        let wrong_message = b"wrong message";
        let signature = dilithium5::detached_sign(wrong_message, &pop_sk);

        // Create the identity binding with wrong signature
        let binding = IdentityBinding {
            alias: alias.clone(),
            pop_public_key: pop_public_key.clone(),
            signature: signature.as_bytes().to_vec(),
        };

        // Verify it should fail
        let result = verify_identity_binding(&binding);
        assert!(
            result.is_err(),
            "Identity binding with wrong signature should fail"
        );
    }

    #[tokio::test]
    async fn register_alias_tofu_paths_cover_match_update_and_conflict() {
        let state = test_api_state();
        let alias = "alice";
        let leaf_a = [0x11; 32];
        let leaf_b = [0x22; 32];
        let key_a = vec![0xAA; 8];
        let key_b = vec![0xBB; 8];

        assert!(
            state
                .register_alias(alias, leaf_a, key_a.clone())
                .await
                .expect("new alias registration"),
            "first registration should mark alias as new"
        );

        assert!(
            !state
                .register_alias(alias, leaf_a, key_a.clone())
                .await
                .expect("matching alias registration"),
            "same alias/key/leaf should be treated as existing binding"
        );

        assert!(
            !state
                .register_alias(alias, leaf_b, key_a.clone())
                .await
                .expect("leaf update for matching key"),
            "same alias/key with new leaf should update in-place"
        );

        let err = state
            .register_alias(alias, leaf_b, key_b)
            .await
            .expect_err("different key must violate TOFU");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("alias already bound to a different identity")
        ));
    }

    #[tokio::test]
    async fn record_member_revocations_prunes_metadata_and_weid_map() {
        let state = test_api_state();
        let leaf_a = [0xA1; 32];
        let leaf_b = [0xB2; 32];
        let weid_a = [0x01; 32];
        let weid_b = [0x02; 32];

        state.record_member_join(leaf_a, weid_a, 100).await;
        state.record_member_join(leaf_b, weid_b, 200).await;

        state.record_member_revocations(&[]).await;
        assert_eq!(state.member_metadata.read().await.len(), 2);
        assert_eq!(state.weid_to_leaf.read().await.len(), 2);

        state.record_member_revocations(&[leaf_a]).await;
        let metadata = state.member_metadata.read().await;
        let weid_map = state.weid_to_leaf.read().await;
        assert!(!metadata.contains_key(&leaf_a));
        assert!(metadata.contains_key(&leaf_b));
        assert!(!weid_map.values().any(|leaf| leaf == &leaf_a));
        assert!(weid_map.values().any(|leaf| leaf == &leaf_b));
    }

    #[tokio::test]
    async fn register_alias_updates_leaf_binding() {
        let state = ApiState {
            server: Arc::new(RwLock::new(server_from_config(&CityGConfig::default()))),
            messages: Arc::new(RwLock::new(AHashMap::new())),
            bundles: Arc::new(RwLock::new(AHashMap::new())),
            message_retention: Duration::from_secs(DEFAULT_FS_MESSAGE_RETENTION_SECS),
            fs_epoch_period_seconds: CityGConfig::default().protocol.fs_policy.h_seconds.max(1),
            freeze_counts: Arc::new(RwLock::new(BTreeMap::new())),
            alias_registry: Arc::new(RwLock::new(AHashMap::new())),
            member_metadata: Arc::new(RwLock::new(AHashMap::new())),
            weid_to_leaf: Arc::new(RwLock::new(AHashMap::new())),
            notification_tx: broadcast::channel(4).0,
            alias_rate_limiter: AliasRateLimiter::new(100, Duration::from_secs(60)),
        };

        let alias = "alice";
        let pop_public_key = vec![0xAA; 8];
        let initial_leaf = [0x11; 32];
        let assigned_leaf = [0x22; 32];

        // First registration reserves the alias.
        state
            .register_alias(alias, initial_leaf, pop_public_key.clone())
            .await
            .expect("initial alias registration");

        // Second registration with the confirmed leaf updates the binding.
        state
            .register_alias(alias, assigned_leaf, pop_public_key.clone())
            .await
            .expect("alias update");

        let registry = state.alias_registry.read().await;
        let binding = registry.get(alias).expect("binding present");
        assert_eq!(
            binding.leaf_id, assigned_leaf,
            "alias binding should track the server-issued leaf id"
        );
        assert_eq!(
            binding.pop_public_key, pop_public_key,
            "alias binding must retain the original pop key"
        );
    }

    #[tokio::test]
    async fn join_ticket_failure_does_not_persist_alias_binding() {
        let cfg = CityGConfig::default();
        let state = ApiState {
            server: Arc::new(RwLock::new(server_from_config(&cfg))),
            messages: Arc::new(RwLock::new(AHashMap::new())),
            bundles: Arc::new(RwLock::new(AHashMap::new())),
            message_retention: Duration::from_secs(DEFAULT_FS_MESSAGE_RETENTION_SECS),
            fs_epoch_period_seconds: cfg.protocol.fs_policy.h_seconds.max(1),
            freeze_counts: Arc::new(RwLock::new(BTreeMap::new())),
            alias_registry: Arc::new(RwLock::new(AHashMap::new())),
            member_metadata: Arc::new(RwLock::new(AHashMap::new())),
            weid_to_leaf: Arc::new(RwLock::new(AHashMap::new())),
            notification_tx: broadcast::channel(4).0,
            alias_rate_limiter: AliasRateLimiter::new(100, Duration::from_secs(60)),
        };

        let (pop_pk, pop_sk) = dilithium5::keypair();
        let alias = "alice".to_string();
        let pop_public_key = pop_pk.as_bytes().to_vec();
        let message_data = (
            ByteBuf::from(alias.as_bytes().to_vec()),
            ByteBuf::from(pop_public_key.clone()),
        );
        let mut message = Vec::new();
        ciborium::ser::into_writer(&message_data, &mut message)
            .expect("encode identity binding message");
        let signature = dilithium5::detached_sign(&message, &pop_sk);

        let request = JoinTicketRequest {
            room_id: "ab".repeat(32),
            alias: alias.clone(),
            identity_binding: Some(IdentityBinding {
                alias: alias.clone(),
                pop_public_key,
                signature: signature.as_bytes().to_vec(),
            }),
        };
        let mut body = Vec::new();
        request.encode(&mut body).expect("encode join request");
        let response = join_ticket(State(state.clone()), Bytes::from(body)).await;
        assert!(response.is_err(), "join_ticket should fail without KBROAD");

        let registry = state.alias_registry.read().await;
        assert!(
            !registry.contains_key(&alias),
            "failed join_ticket must not persist TOFU alias binding"
        );
    }

    #[tokio::test]
    async fn burst_step_error_response_includes_index() {
        let freeze = FreezeError {
            code: 9449,
            reason: "fs_burst_non_monotone_ec",
        };
        let response = ApiError::server_with_freeze_context(
            "acceptance error: fs_burst_non_monotone_ec",
            freeze,
            Some("burst_step_failed"),
            Some(3),
        )
        .into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(response.into_body(), 1024)
            .await
            .expect("body bytes");
        let json: Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(json["error"], "burst_step_failed");
        assert_eq!(json["failed_index"], 3);
        assert_eq!(json["freeze_code"], 9449);
        assert_eq!(json["freeze_reason"], "fs_burst_non_monotone_ec");
    }

    #[tokio::test]
    async fn map_accept_error_covers_invalid_input_and_non_freeze_acceptance() {
        let state = test_api_state();

        let invalid = map_accept_error(
            &state,
            ClientError::InvalidInput("bad bundle"),
            Some("batch_step"),
            Some(9),
        )
        .await;
        assert!(matches!(
            invalid,
            ApiError::InvalidRequest("invalid bundle components")
        ));

        let acceptance = map_accept_error(
            &state,
            ClientError::Acceptance(AcceptanceError::Msphf(MsphfError::invalid_input(
                "hp mismatch",
            ))),
            Some("batch_step"),
            Some(2),
        )
        .await;
        let response = acceptance.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let json: Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(json["error"], "batch_step");
        assert_eq!(json["failed_index"], 2);
    }

    #[tokio::test]
    async fn bootstrap_room_validates_requests_and_registers_group() {
        let state = test_api_state();

        let encode = |request: BootstrapRoomRequest| -> Bytes {
            let mut body = Vec::new();
            request.encode(&mut body).expect("encode bootstrap request");
            Bytes::from(body)
        };

        let err = bootstrap_room(
            State(state.clone()),
            encode(BootstrapRoomRequest {
                room_id: String::new(),
                kbroad_public: vec![0x11; ml_kem_public_key_bytes()],
            }),
        )
        .await
        .expect_err("missing room id must fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("room_id must be provided")
        ));

        let err = bootstrap_room(
            State(state.clone()),
            encode(BootstrapRoomRequest {
                room_id: hex::encode([0x44u8; 32]),
                kbroad_public: Vec::new(),
            }),
        )
        .await
        .expect_err("missing kbroad key must fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("kbroad_public must be provided")
        ));

        let err = bootstrap_room(
            State(state.clone()),
            encode(BootstrapRoomRequest {
                room_id: hex::encode([0x55u8; 32]),
                kbroad_public: vec![0x11; ml_kem_public_key_bytes() - 1],
            }),
        )
        .await
        .expect_err("wrong kbroad key length must fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("kbroad_public has unexpected length")
        ));

        let response = bootstrap_room(
            State(state),
            encode(BootstrapRoomRequest {
                room_id: hex::encode([0x66u8; 32]),
                kbroad_public: vec![0x33; ml_kem_public_key_bytes()],
            }),
        )
        .await
        .expect("valid bootstrap should succeed");
        let decoded: BootstrapRoomResponse = decode_proto_response(response).await;
        assert_eq!(decoded.status, "registered");
    }

    #[tokio::test]
    async fn search_members_filters_by_alias_or_leaf_hex_and_validates_inputs() {
        let state = test_api_state();
        let alice = demo_bundle("alice").expect("alice demo bundle");
        let bob = demo_bundle("bob").expect("bob demo bundle");

        let (root, tagged_leaf) = {
            let mut guard = state.server.write().await;
            guard.accept_epoch(&alice).expect("accept alice");
            guard.accept_epoch(&bob).expect("accept bob");
            let root = guard
                .latest_parent_root(DEMO_GID.as_ref())
                .expect("latest root");
            let members = guard
                .members_for_root(DEMO_GID.as_ref(), &root)
                .expect("members for root");
            (root, members[0])
        };

        state
            .register_alias("special-user", tagged_leaf, vec![0xAB; 8])
            .await
            .expect("register alias for search");

        let mut body = Vec::new();
        pb::SearchMembersRequest {
            gid: DEMO_GID.to_vec(),
            query: "special".to_string(),
            parent_root: Vec::new(),
            offset: Some(0),
            limit: Some(10),
        }
        .encode(&mut body)
        .expect("encode alias query request");
        let response = search_members(State(state.clone()), Bytes::from(body))
            .await
            .expect("alias query should succeed");
        let decoded: pb::SearchMembersResponse = decode_proto_response(response).await;
        assert_eq!(decoded.total_count, 1);
        assert_eq!(decoded.members.len(), 1);
        assert_eq!(
            decoded.members[0].alias.as_deref(),
            Some("special-user"),
            "alias query should return aliased member"
        );

        let leaf_prefix = hex::encode(tagged_leaf);
        let mut body = Vec::new();
        pb::SearchMembersRequest {
            gid: DEMO_GID.to_vec(),
            query: leaf_prefix[..12].to_string(),
            parent_root: root.to_vec(),
            offset: Some(0),
            limit: Some(10),
        }
        .encode(&mut body)
        .expect("encode leaf query request");
        let response = search_members(State(state.clone()), Bytes::from(body))
            .await
            .expect("leaf query should succeed");
        let decoded: pb::SearchMembersResponse = decode_proto_response(response).await;
        assert!(
            decoded.total_count >= 1,
            "leaf hex search should return at least one match"
        );

        let mut body = Vec::new();
        pb::SearchMembersRequest {
            gid: DEMO_GID.to_vec(),
            query: String::new(),
            parent_root: Vec::new(),
            offset: Some(0),
            limit: Some(10),
        }
        .encode(&mut body)
        .expect("encode missing query request");
        let err = search_members(State(state.clone()), Bytes::from(body))
            .await
            .expect_err("empty query should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("query must be provided")
        ));

        let mut body = Vec::new();
        pb::SearchMembersRequest {
            gid: DEMO_GID.to_vec(),
            query: "x".to_string(),
            parent_root: vec![0x01],
            offset: Some(0),
            limit: Some(10),
        }
        .encode(&mut body)
        .expect("encode invalid parent root request");
        let err = search_members(State(state), Bytes::from(body))
            .await
            .expect_err("bad parent root should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("parent_root must be 32 bytes")
        ));
    }

    #[tokio::test]
    async fn merge_ticket_validates_inputs_and_returns_ticket_payload() {
        let state = test_api_state();
        let alice = demo_bundle("alice").expect("alice demo bundle");

        let leaf_id = {
            let mut guard = state.server.write().await;
            guard.accept_epoch(&alice).expect("accept alice");
            let root = guard
                .latest_parent_root(DEMO_GID.as_ref())
                .expect("latest root");
            guard
                .members_for_root(DEMO_GID.as_ref(), &root)
                .expect("members for root")[0]
        };

        let mut body = Vec::new();
        MergeTicketRequest {
            room_id: String::new(),
            leaf_id: leaf_id.to_vec(),
        }
        .encode(&mut body)
        .expect("encode missing room id request");
        let err = merge_ticket(State(state.clone()), Bytes::from(body))
            .await
            .expect_err("empty room id should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("room_id must be provided")
        ));

        let mut body = Vec::new();
        MergeTicketRequest {
            room_id: hex::encode(DEMO_GID),
            leaf_id: vec![0x01; 31],
        }
        .encode(&mut body)
        .expect("encode bad leaf request");
        let err = merge_ticket(State(state.clone()), Bytes::from(body))
            .await
            .expect_err("invalid leaf length should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("leaf_id must be 32 bytes")
        ));

        let mut body = Vec::new();
        MergeTicketRequest {
            room_id: hex::encode(DEMO_GID),
            leaf_id: leaf_id.to_vec(),
        }
        .encode(&mut body)
        .expect("encode valid merge request");
        let response = merge_ticket(State(state), Bytes::from(body))
            .await
            .expect("valid merge ticket request");
        let decoded: MergeTicketResponse = decode_proto_response(response).await;
        assert_eq!(decoded.we_epoch_id.len(), 32);
        assert_eq!(decoded.parent_root.len(), 32);
        assert!(
            !decoded.pivot_parity_cbor.is_empty(),
            "merge ticket should include at least one pivot parity"
        );
    }

    #[test]
    fn identity_binding_validation_rejects_invalid_field_shapes() {
        let mut binding = IdentityBinding {
            alias: "alice".to_string(),
            pop_public_key: vec![0u8; dilithium5::public_key_bytes().saturating_sub(1)],
            signature: vec![0u8; dilithium5::signature_bytes()],
        };
        assert!(matches!(
            verify_identity_binding(&binding),
            Err(ApiError::InvalidRequest("invalid pop_public_key length"))
        ));

        binding.pop_public_key = vec![0u8; dilithium5::public_key_bytes()];
        binding.signature = vec![0u8; dilithium5::signature_bytes().saturating_sub(1)];
        assert!(matches!(
            verify_identity_binding(&binding),
            Err(ApiError::InvalidRequest("invalid signature length"))
        ));

        binding.signature = vec![0u8; dilithium5::signature_bytes()];
        binding.alias.clear();
        assert!(matches!(
            verify_identity_binding(&binding),
            Err(ApiError::InvalidRequest("alias cannot be empty"))
        ));
    }

    #[test]
    fn client_error_conversion_covers_freeze_acceptance_and_io_paths() {
        let freeze = FreezeError {
            code: 9412,
            reason: "rho_replay",
        };
        let converted: ApiError = ClientError::Acceptance(AcceptanceError::Freeze(freeze)).into();
        match converted {
            ApiError::Server {
                message,
                freeze: Some(inner),
                ..
            } => {
                assert!(message.contains("acceptance error"));
                assert_eq!(inner.code, 9412);
                assert_eq!(inner.reason, "rho_replay");
            }
            other => panic!("expected frozen server error, got {other:?}"),
        }

        let converted: ApiError =
            ClientError::Acceptance(AcceptanceError::Msphf(MsphfError::invalid_input("bad")))
                .into();
        assert!(matches!(converted, ApiError::Server { .. }));

        let converted: ApiError = ClientError::Io(std::io::Error::other("disk")).into();
        match converted {
            ApiError::Server { message, .. } => assert!(message.contains("io error")),
            other => panic!("expected server error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn join_ticket_success_persists_confirmed_alias_binding() {
        let state = test_api_state();

        let (pop_pk, pop_sk) = dilithium5::keypair();
        let alias = "alice-joined".to_string();
        let pop_public_key = pop_pk.as_bytes().to_vec();
        let message_data = (
            ByteBuf::from(alias.as_bytes().to_vec()),
            ByteBuf::from(pop_public_key.clone()),
        );
        let mut message = Vec::new();
        ciborium::ser::into_writer(&message_data, &mut message)
            .expect("encode identity binding message");
        let signature = dilithium5::detached_sign(&message, &pop_sk);

        let before = state.server.read().await.context().fs_base_ts();
        assert!(before.is_none(), "fs base ts should start unset");

        let response = join_ticket(
            State(state.clone()),
            encode_proto_request(&JoinTicketRequest {
                room_id: hex::encode(DEMO_GID),
                alias: alias.clone(),
                identity_binding: Some(IdentityBinding {
                    alias: alias.clone(),
                    pop_public_key: pop_public_key.clone(),
                    signature: signature.as_bytes().to_vec(),
                }),
            }),
        )
        .await
        .expect("join ticket with valid binding should succeed");
        let decoded: JoinTicketResponse = decode_proto_response(response).await;
        assert_eq!(decoded.gid.len(), 32);
        assert_eq!(decoded.leaf_id.len(), 32);
        let gid: [u8; 32] = decoded.gid.as_slice().try_into().expect("join ticket gid");
        let expected_leaf =
            compute_leaf_id(LeafIdMode::PerGroup, &gid, "ML-DSA-65", &pop_public_key)
                .expect("compute leaf from binding pop key");
        assert_eq!(decoded.leaf_id, expected_leaf.to_vec());

        let registry = state.alias_registry.read().await;
        let binding = registry.get(&alias).expect("alias must be persisted");
        assert_eq!(binding.leaf_id, decoded.leaf_id.as_slice());
        drop(registry);

        let response = join_ticket(
            State(state.clone()),
            encode_proto_request(&JoinTicketRequest {
                room_id: hex::encode(DEMO_GID),
                alias: "without-binding".to_string(),
                identity_binding: None,
            }),
        )
        .await
        .expect("join ticket without binding should still succeed");
        let decoded_second: JoinTicketResponse = decode_proto_response(response).await;
        assert_eq!(decoded_second.fs_epoch_base_ts, decoded.fs_epoch_base_ts);
    }

    #[tokio::test]
    async fn members_handler_covers_validation_notfound_and_alias_metadata() {
        let state = test_api_state();
        let alice = demo_bundle("alice").expect("alice demo bundle");
        let (root, leaf) = {
            let mut guard = state.server.write().await;
            guard.accept_epoch(&alice).expect("accept alice");
            let root = guard
                .latest_parent_root(DEMO_GID.as_ref())
                .expect("latest root");
            let leaf = guard
                .members_for_root(DEMO_GID.as_ref(), &root)
                .expect("members for root")[0];
            (root, leaf)
        };
        state
            .register_alias("member-alias", leaf, vec![0x55; 8])
            .await
            .expect("register member alias");
        state.record_member_join(leaf, [0x88; 32], 777).await;

        let err = members(
            State(state.clone()),
            encode_proto_request(&MembersRequest {
                gid: Vec::new(),
                parent_root: Vec::new(),
                offset: Some(0),
                limit: Some(10),
            }),
        )
        .await
        .expect_err("missing gid should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("gid must be provided")
        ));

        let err = members(
            State(state.clone()),
            encode_proto_request(&MembersRequest {
                gid: DEMO_GID.to_vec(),
                parent_root: vec![0x01],
                offset: Some(0),
                limit: Some(10),
            }),
        )
        .await
        .expect_err("invalid parent root length should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("parent_root must be 32 bytes")
        ));

        let err = members(
            State(state.clone()),
            encode_proto_request(&MembersRequest {
                gid: DEMO_GID.to_vec(),
                parent_root: vec![0x99; 32],
                offset: Some(0),
                limit: Some(10),
            }),
        )
        .await
        .expect_err("unknown parent root should fail");
        assert!(matches!(err, ApiError::NotFound));

        let response = members(
            State(state.clone()),
            encode_proto_request(&MembersRequest {
                gid: DEMO_GID.to_vec(),
                parent_root: root.to_vec(),
                offset: Some(0),
                limit: Some(10),
            }),
        )
        .await
        .expect("members request should succeed");
        let decoded: MembersResponse = decode_proto_response(response).await;
        let returned = decoded
            .members
            .iter()
            .find(|member| member.leaf_id == leaf)
            .expect("returned members should include accepted leaf");
        assert_eq!(returned.alias.as_deref(), Some("member-alias"));
        assert_eq!(returned.join_date, Some(777));
        assert_eq!(returned.last_seen, Some(777));
    }

    #[tokio::test]
    async fn send_and_fetch_messages_cover_validation_touch_and_roundtrip() {
        let state = test_api_state();
        let weid = [0x77; 32];
        let leaf = [0x44; 32];
        state.record_member_join(leaf, weid, 100).await;

        let err = send_message(
            State(state.clone()),
            encode_proto_request(&SendMessageRequest {
                we_epoch_id: vec![0x01; 31],
                ciphertext: vec![0xAA],
                sender: vec![0x01; 32],
            }),
        )
        .await
        .expect_err("invalid weid length should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("we_epoch_id must be 32 bytes")
        ));

        let err = send_message(
            State(state.clone()),
            encode_proto_request(&SendMessageRequest {
                we_epoch_id: weid.to_vec(),
                ciphertext: Vec::new(),
                sender: vec![0x02; 32],
            }),
        )
        .await
        .expect_err("empty ciphertext should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("ciphertext must be provided")
        ));

        let response = send_message(
            State(state.clone()),
            encode_proto_request(&SendMessageRequest {
                we_epoch_id: weid.to_vec(),
                ciphertext: b"hello".to_vec(),
                sender: vec![0x03; 32],
            }),
        )
        .await
        .expect("valid send should succeed");
        let decoded: SendMessageResponse = decode_proto_response(response).await;
        assert_eq!(decoded.status, "stored");

        let metadata = state.member_metadata.read().await;
        let member = metadata.get(&leaf).expect("member metadata");
        assert!(
            member.last_seen_timestamp_ms >= 100,
            "send path should touch member last-seen timestamp"
        );
        drop(metadata);

        let err = fetch_messages(
            State(state.clone()),
            encode_proto_request(&FetchMessagesRequest {
                we_epoch_id: vec![0x01; 31],
            }),
        )
        .await
        .expect_err("invalid fetch weid length should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("we_epoch_id must be 32 bytes")
        ));

        let response = fetch_messages(
            State(state.clone()),
            encode_proto_request(&FetchMessagesRequest {
                we_epoch_id: weid.to_vec(),
            }),
        )
        .await
        .expect("fetch should succeed");
        let decoded: FetchMessagesResponse = decode_proto_response(response).await;
        assert_eq!(decoded.messages.len(), 1);
        assert_eq!(decoded.messages[0].ciphertext, b"hello");
    }

    #[tokio::test]
    async fn get_bundle_refresh_pivot_and_health_handlers_cover_core_paths() {
        let state = test_api_state();

        let err = get_bundle(
            State(state.clone()),
            encode_proto_request(&GetBundleRequest {
                we_epoch_id: vec![0x01; 31],
            }),
        )
        .await
        .expect_err("invalid bundle key length should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("we_epoch_id must be 32 bytes")
        ));

        let err = get_bundle(
            State(state.clone()),
            encode_proto_request(&GetBundleRequest {
                we_epoch_id: vec![0x02; 32],
            }),
        )
        .await
        .expect_err("unknown bundle should fail");
        assert!(matches!(err, ApiError::NotFound));

        let weid = [0x23; 32];
        store_bundle_bytes(&state, weid, vec![0xAA, 0xBB]).await;
        let response = get_bundle(
            State(state.clone()),
            encode_proto_request(&GetBundleRequest {
                we_epoch_id: weid.to_vec(),
            }),
        )
        .await
        .expect("stored bundle should be returned");
        let decoded: GetBundleResponse = decode_proto_response(response).await;
        assert_eq!(decoded.bundle_cbor, vec![0xAA, 0xBB]);

        let err = refresh_pivot(
            State(state.clone()),
            encode_proto_request(&RefreshPivotRequest {
                bundle_cbor: Vec::new(),
            }),
        )
        .await
        .expect_err("empty refresh payload should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("bundle_cbor must be provided")
        ));

        let err = refresh_pivot(
            State(state.clone()),
            encode_proto_request(&RefreshPivotRequest {
                bundle_cbor: vec![0x01, 0x02],
            }),
        )
        .await
        .expect_err("invalid cbor payload should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("invalid bundle encoding")
        ));

        let live_body = to_bytes(
            health_liveness(State(state.clone())).await.into_body(),
            usize::MAX,
        )
        .await
        .expect("health live body");
        let live: Value = serde_json::from_slice(&live_body).expect("health live json");
        assert_eq!(live["alive"], true);

        let ready_body = to_bytes(
            health_readiness(State(state.clone())).await.into_body(),
            usize::MAX,
        )
        .await
        .expect("health ready body");
        let ready: Value = serde_json::from_slice(&ready_body).expect("health ready json");
        assert_eq!(ready["ready"], true);

        let detailed_body = to_bytes(
            health_detailed(State(state.clone())).await.into_body(),
            usize::MAX,
        )
        .await
        .expect("health detailed body");
        let detailed: Value = serde_json::from_slice(&detailed_body).expect("health detailed json");
        assert_eq!(detailed["status"], "healthy");

        let legacy: HealthResponse =
            decode_proto_response(health_legacy_with_state(State(state)).await).await;
        assert_eq!(legacy.status, "ok");
    }

    #[tokio::test]
    async fn websocket_handler_streams_message_and_membership_notifications() {
        let state = test_api_state();
        let app = Router::new()
            .route("/v1/ws", get(websocket_handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral listener");
        let addr = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve websocket test app");
        });

        let url = format!("ws://{addr}/v1/ws");
        let (mut socket, _) = tokio_tungstenite::connect_async(url)
            .await
            .expect("connect websocket");

        state.broadcast_message(MessageNotification {
            we_epoch_id: [0xA5; 32],
            timestamp_ms: 101,
        });
        let first = tokio::time::timeout(std::time::Duration::from_secs(2), socket.next())
            .await
            .expect("wait for message notification")
            .expect("message notification frame")
            .expect("message notification payload");
        let first_text = match first {
            tokio_tungstenite::tungstenite::Message::Text(text) => text,
            other => panic!("expected text notification frame, got {other:?}"),
        };
        let first_json: Value =
            serde_json::from_str(&first_text).expect("decode message notification JSON");
        assert_eq!(first_json["type"], "message");
        assert_eq!(first_json["timestamp_ms"], 101);

        state.broadcast_membership(DEMO_GID, [0xB6; 32], MembershipEventKind::Join, 202);
        let second = tokio::time::timeout(std::time::Duration::from_secs(2), socket.next())
            .await
            .expect("wait for membership notification")
            .expect("membership notification frame")
            .expect("membership notification payload");
        let second_text = match second {
            tokio_tungstenite::tungstenite::Message::Text(text) => text,
            other => panic!("expected text membership frame, got {other:?}"),
        };
        let second_json: Value =
            serde_json::from_str(&second_text).expect("decode membership notification JSON");
        assert_eq!(second_json["type"], "membership");
        assert_eq!(second_json["event"], "join");
        assert_eq!(second_json["timestamp_ms"], 202);

        socket
            .send(tokio_tungstenite::tungstenite::Message::Ping(vec![1, 2, 3]))
            .await
            .expect("send ping");
        socket
            .send(tokio_tungstenite::tungstenite::Message::Close(None))
            .await
            .expect("send close");

        server.abort();
    }

    #[test]
    fn prune_expired_messages_removes_old_entries_and_empty_buckets() {
        let mut store: AHashMap<[u8; 32], Vec<StoredMessage>> = AHashMap::new();
        let weid_a = [0xAA; 32];
        let weid_b = [0xBB; 32];

        store.insert(
            weid_a,
            vec![
                StoredMessage {
                    we_epoch_id: weid_a,
                    ciphertext: vec![1],
                    sender: vec![],
                    timestamp_ms: 1_000,
                },
                StoredMessage {
                    we_epoch_id: weid_a,
                    ciphertext: vec![2],
                    sender: vec![],
                    timestamp_ms: 9_500,
                },
                StoredMessage {
                    we_epoch_id: weid_a,
                    ciphertext: vec![3],
                    sender: vec![],
                    timestamp_ms: 10_000,
                },
            ],
        );
        store.insert(
            weid_b,
            vec![StoredMessage {
                we_epoch_id: weid_b,
                ciphertext: vec![4],
                sender: vec![],
                timestamp_ms: 500,
            }],
        );

        prune_expired_messages(&mut store, 10_000, Duration::from_secs(1));

        let retained = store.get(&weid_a).expect("weid_a should exist");
        assert_eq!(retained.len(), 2, "old message should be pruned");
        assert!(
            retained.iter().all(|m| m.timestamp_ms >= 9_000),
            "all retained messages should be inside the retention window"
        );
        assert!(
            !store.contains_key(&weid_b),
            "empty per-epoch buckets should be removed"
        );
    }

    #[test]
    fn prune_expired_messages_zero_retention_keeps_only_current_timestamp() {
        let mut store: AHashMap<[u8; 32], Vec<StoredMessage>> = AHashMap::new();
        let weid = [0xCC; 32];
        let now_ms: u64 = 42_000;

        store.insert(
            weid,
            vec![
                StoredMessage {
                    we_epoch_id: weid,
                    ciphertext: vec![1],
                    sender: vec![],
                    timestamp_ms: now_ms.saturating_sub(1),
                },
                StoredMessage {
                    we_epoch_id: weid,
                    ciphertext: vec![2],
                    sender: vec![],
                    timestamp_ms: now_ms,
                },
            ],
        );

        prune_expired_messages(&mut store, now_ms, Duration::from_secs(0));

        let retained = store.get(&weid).expect("weid should exist");
        assert_eq!(retained.len(), 1, "only exact-now message should remain");
        assert_eq!(retained[0].timestamp_ms, now_ms);
    }

    #[test]
    fn aligned_fs_epoch_base_ts_rounds_down_to_period() {
        let now = UNIX_EPOCH + Duration::from_secs(1_001);
        assert_eq!(aligned_fs_epoch_base_ts(now, 300), 900);
    }

    #[test]
    fn server_from_config_leaves_fs_base_ts_unset() {
        let config = CityGConfig::default();
        let server = server_from_config(&config);
        assert!(
            server.context().fs_base_ts().is_none(),
            "server should not pre-seed fs base timestamp before first accepted/join ticket flow"
        );
    }

    #[tokio::test]
    async fn alias_rate_limiter_allows_burst_then_rejects() {
        let burst = 3u32;
        let limiter = AliasRateLimiter::new(burst, Duration::from_secs(60));
        let alias = "squatter";

        for i in 0..burst {
            assert!(
                limiter.check_and_record(alias).await,
                "attempt {i} within burst should be allowed"
            );
        }
        assert!(
            !limiter.check_and_record(alias).await,
            "attempt past burst should be rejected"
        );

        // Different alias should still be allowed
        assert!(
            limiter.check_and_record("other-alias").await,
            "different alias should have independent budget"
        );
    }

    #[tokio::test]
    async fn alias_rate_limiter_rejects_produces_429() {
        let state = ApiState {
            server: Arc::new(RwLock::new(server_from_config(&CityGConfig::default()))),
            messages: Arc::new(RwLock::new(AHashMap::new())),
            bundles: Arc::new(RwLock::new(AHashMap::new())),
            message_retention: Duration::from_secs(DEFAULT_FS_MESSAGE_RETENTION_SECS),
            fs_epoch_period_seconds: CityGConfig::default().protocol.fs_policy.h_seconds.max(1),
            freeze_counts: Arc::new(RwLock::new(BTreeMap::new())),
            alias_registry: Arc::new(RwLock::new(AHashMap::new())),
            member_metadata: Arc::new(RwLock::new(AHashMap::new())),
            weid_to_leaf: Arc::new(RwLock::new(AHashMap::new())),
            notification_tx: broadcast::channel(4).0,
            // Burst of 1 so the second attempt triggers rate limit
            alias_rate_limiter: AliasRateLimiter::new(1, Duration::from_secs(60)),
        };
        let leaf = [0x01u8; 32];
        let key = vec![0xAB; 8];

        let result1 = state.register_alias("rate-test", leaf, key.clone()).await;
        assert!(result1.is_ok(), "first call should succeed");

        let result2 = state.register_alias("rate-test", leaf, key).await;
        assert!(
            matches!(result2, Err(ApiError::RateLimited)),
            "second call should be rate-limited, got: {result2:?}"
        );
    }

    #[tokio::test]
    async fn alias_rate_limiter_prunes_stale_alias_buckets() {
        let limiter = AliasRateLimiter::new(10, Duration::from_millis(1));
        assert!(limiter.check_and_record("old-alias").await);
        tokio::time::sleep(Duration::from_millis(5)).await;

        assert!(limiter.check_and_record("new-alias").await);

        let guard = limiter.attempts.read().await;
        assert!(
            !guard.contains_key("old-alias"),
            "stale alias bucket should be removed during global prune"
        );
        assert!(
            guard.contains_key("new-alias"),
            "active alias bucket should remain"
        );
    }

    #[tokio::test]
    async fn alias_rate_limiter_caps_bucket_count_with_eviction() {
        let limiter = AliasRateLimiter::with_max_aliases(10, Duration::from_secs(60), 2);
        assert!(limiter.check_and_record("alias-a").await);
        tokio::time::sleep(Duration::from_millis(2)).await;
        assert!(limiter.check_and_record("alias-b").await);
        tokio::time::sleep(Duration::from_millis(2)).await;
        assert!(limiter.check_and_record("alias-c").await);

        let guard = limiter.attempts.read().await;
        assert_eq!(guard.len(), 2, "bucket map must remain capped");
        assert!(
            !guard.contains_key("alias-a"),
            "oldest bucket should be evicted once cap is reached"
        );
        assert!(guard.contains_key("alias-b"));
        assert!(guard.contains_key("alias-c"));
    }
}
