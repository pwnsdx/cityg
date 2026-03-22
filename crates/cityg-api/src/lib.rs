#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

#[allow(dead_code)]
mod pb {
    include!(concat!(env!("OUT_DIR"), "/cityg.api.v1.rs"));
}

pub mod health;
mod middleware;

use std::{
    collections::{BTreeMap, HashSet},
    convert::TryInto,
    hash::{Hash, Hasher},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use ahash::{AHashMap, AHasher};

use axum::{
    Router,
    body::Bytes,
    extract::ws::{Message as WsMessage, WebSocket},
    extract::{DefaultBodyLimit, Query, State, WebSocketUpgrade},
    http::{HeaderMap, HeaderValue, StatusCode, header::CONTENT_TYPE},
    middleware as axum_middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bytes::BytesMut;
use ciborium::ser::into_writer;
use futures::{SinkExt, StreamExt};
use hex::FromHex;
use pb::{
    AcceptEpochRequest, AcceptEpochResponse, BarrierFetchPublicTreeRequest,
    BarrierFetchPublicTreeResponse, BarrierJoinLeafRecord, BarrierResolveJoinsSinceRequest,
    BarrierResolveJoinsSinceResponse, BarrierResolveRevokedLeavesRequest,
    BarrierResolveRevokedLeavesResponse, BootstrapRoomRequest, BootstrapRoomResponse, ChatMessage,
    ConfigureWindowRequest, ConfigureWindowResponse, FetchMessagesRequest, FetchMessagesResponse,
    FreezeStat, GetBundleRequest, GetBundleResponse, GetTelemetryRequest, GetTelemetryResponse,
    GetWindowRequest, GetWindowResponse, HealthResponse, IdentityBinding, JoinTicketRequest,
    JoinTicketResponse, Member, MembersRequest, MembersResponse, MergeTicketIntent,
    MergeTicketRequest, MergeTicketResponse, RefreshPivotRequest, RefreshPivotResponse,
    RotateRoomKbroadRequest, RotateRoomKbroadResponse, SendMessageRequest, SendMessageResponse,
    TelemetryEntry, WindowEntry, WindowHead,
};
#[cfg(any(debug_assertions, feature = "debug-api"))]
use pb::{SeedHeadRequest, SeedHeadResponse};
use prost::Message;
use thiserror::Error;
use tokio::sync::{RwLock, broadcast};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};
use unicode_normalization::UnicodeNormalization;

use cityg_client::{CityGError as ClientError, ClientEpochBundle};
use cityg_server::{
    BarrierJoinLeafRecord as ServerBarrierJoinLeafRecord, CityGServer, MergeTicketBundle,
    ServerConfig, ServerOutcome,
};
use msphf_core::{
    MsphfError,
    params::{RLWE_CRS_ID_DEFAULT, RLWE_PARAMS_ID_MOCK},
};
use msphf_orchestrator::{AcceptanceError, mhw::FreezeError};
use msphf_orchestrator::{
    AcceptanceOptions, BootstrapPolicy, DEFAULT_PROOF_MODE, DEFAULT_VRF_ID, FsPolicyConfig,
    LeafIdMode, PivotParity, compute_leaf_id, hdr,
};
use pqcrypto_kyber::kyber768::public_key_bytes as ml_kem_public_key_bytes;
use serde::{Deserialize, Serialize};
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
const API_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const WINDOW_CONFIG_ADMIN_HEADER: &str = "x-cityg-admin-token";
const WINDOW_CONFIG_ADMIN_TOKEN_ENV: &str = "CITYG_SERVER_WINDOW_ADMIN_TOKEN";
const ROOMS_ADMIN_TOKEN_ENV: &str = "CITYG_SERVER_ROOMS_ADMIN_TOKEN";
const ALLOW_INSECURE_ADMIN_ENV: &str = "CITYG_SERVER_ALLOW_INSECURE_ADMIN";
const MESSAGE_AUTH_HEADER: &str = "x-cityg-message-token";
const MESSAGE_AUTH_TOKEN_ENV: &str = "CITYG_SERVER_MESSAGE_AUTH_TOKEN";
const MESSAGE_PRUNE_INTERVAL_MS: u64 = 1_000;
const WS_MAX_LAG_ENV: &str = "CITYG_SERVER_WS_MAX_LAG";
const WS_MAX_LAG_DEFAULT: u64 = 256;
const API_PROFILE_VERSION: &str = "v0.1.4";
const GROUP_LANES_ENV: &str = "CITYG_SERVER_GROUP_LANES";
const DEFAULT_GROUP_LANES: usize = 4;
const MERGE_COALESCE_TTL_MS: u64 = 2_000;
const MERGE_COALESCE_MAX_ENTRIES: usize = 8_192;

#[derive(Clone)]
struct ApiState {
    // Compatibility handle for tests and single-lane deployments.
    server: Arc<RwLock<CityGServer>>,
    // Execution lanes keyed by gid hash; write-heavy gid-scoped operations
    // are routed to one lane to reduce cross-group lock contention.
    server_lanes: Arc<Vec<Arc<RwLock<CityGServer>>>>,
    messages: Arc<RwLock<AHashMap<[u8; 32], Vec<StoredMessage>>>>,
    bundles: Arc<RwLock<AHashMap<[u8; 32], Vec<u8>>>>,
    message_retention: Duration,
    fs_epoch_period_seconds: u64,
    freeze_counts: Arc<RwLock<BTreeMap<(u32, String), u64>>>,
    // Alias registry: alias -> (leaf_id, pop_pk) for TOFU
    alias_registry: Arc<RwLock<AHashMap<String, AliasBinding>>>,
    member_metadata: Arc<RwLock<AHashMap<[u8; 32], MemberMetadata>>>,
    weid_to_leaf: Arc<RwLock<AHashMap<[u8; 32], [u8; 32]>>>,
    epoch_scopes: Arc<RwLock<AHashMap<[u8; 32], EpochScope>>>,
    // Broadcast channel for WebSocket notifications
    notification_tx: broadcast::Sender<BroadcastNotification>,
    alias_rate_limiter: AliasRateLimiter,
    message_prune_due_ms: Arc<AtomicU64>,
    merge_ticket_cache: Arc<RwLock<AHashMap<MergeTicketCacheKey, MergeTicketCacheEntry>>>,
}

#[derive(Clone, Debug)]
struct MessageNotification {
    gid: [u8; 32],
    we_epoch_id: [u8; 32],
    timestamp_ms: u64,
}

#[derive(Clone, Copy, Debug)]
struct EpochScope {
    gid: [u8; 32],
    membership_root: [u8; 32],
}

#[derive(Clone, Deserialize)]
struct WebSocketSubscriptionQuery {
    gid: String,
    leaf_id: String,
    token: Option<String>,
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct MergeTicketCacheKey {
    gid: [u8; 32],
    leaf_id: [u8; 32],
    intent: i32,
}

#[derive(Clone, Debug)]
struct MergeTicketCacheEntry {
    created_at_ms: u64,
    response_bytes: Vec<u8>,
}

impl ApiState {
    fn lane_index_for_gid_bytes(&self, gid: &[u8]) -> usize {
        if self.server_lanes.is_empty() {
            return 0;
        }
        let mut hasher = AHasher::default();
        hasher.write(gid);
        (hasher.finish() as usize) % self.server_lanes.len()
    }

    fn server_for_gid_bytes(&self, gid: &[u8]) -> Arc<RwLock<CityGServer>> {
        if self.server_lanes.is_empty() {
            return self.server.clone();
        }
        self.server_lanes[self.lane_index_for_gid_bytes(gid)].clone()
    }

    fn server_for_gid(&self, gid: &[u8; 32]) -> Arc<RwLock<CityGServer>> {
        self.server_for_gid_bytes(gid)
    }

    fn all_server_lanes(&self) -> Vec<Arc<RwLock<CityGServer>>> {
        if self.server_lanes.is_empty() {
            return vec![self.server.clone()];
        }
        self.server_lanes.iter().cloned().collect()
    }

    async fn clear_merge_ticket_cache_for_gid(&self, gid: [u8; 32]) {
        let mut guard = self.merge_ticket_cache.write().await;
        guard.retain(|key, _| key.gid != gid);
    }

    async fn coalesced_merge_ticket_lookup(
        &self,
        key: MergeTicketCacheKey,
        now_ms: u64,
    ) -> Option<Vec<u8>> {
        let mut guard = self.merge_ticket_cache.write().await;
        guard
            .retain(|_, entry| now_ms.saturating_sub(entry.created_at_ms) <= MERGE_COALESCE_TTL_MS);
        guard.get(&key).map(|entry| entry.response_bytes.clone())
    }

    async fn coalesced_merge_ticket_store(
        &self,
        key: MergeTicketCacheKey,
        response_bytes: Vec<u8>,
        now_ms: u64,
    ) {
        let mut guard = self.merge_ticket_cache.write().await;
        guard
            .retain(|_, entry| now_ms.saturating_sub(entry.created_at_ms) <= MERGE_COALESCE_TTL_MS);
        if !guard.contains_key(&key) && guard.len() >= MERGE_COALESCE_MAX_ENTRIES {
            let evict = guard
                .iter()
                .min_by_key(|(_, entry)| entry.created_at_ms)
                .map(|(candidate, _)| *candidate);
            if let Some(evict) = evict {
                guard.remove(&evict);
            }
        }
        guard.insert(
            key,
            MergeTicketCacheEntry {
                created_at_ms: now_ms,
                response_bytes,
            },
        );
    }

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
        let normalized_alias: String = alias.nfc().collect();

        if !self
            .alias_rate_limiter
            .check_and_record(normalized_alias.as_str())
            .await
        {
            warn!(alias = normalized_alias, "alias registration rate-limited");
            return Err(ApiError::RateLimited);
        }

        let mut guard = self.alias_registry.write().await;

        if let Some(existing) = guard.get_mut(normalized_alias.as_str()) {
            // TOFU: First binding wins
            if existing.pop_public_key == pop_public_key {
                if existing.leaf_id != leaf_id {
                    existing.leaf_id = leaf_id;
                    info!(
                        "Alias '{}' verified: updated leaf binding to {}",
                        normalized_alias,
                        hex::encode(leaf_id)
                    );
                } else {
                    info!(
                        "Alias '{}' verified: matches existing binding",
                        normalized_alias
                    );
                }
                return Ok(false);
            } else {
                // Different device trying to use same alias - TOFU violation
                error!(
                    "TOFU violation: Alias '{}' already bound to different public key",
                    normalized_alias
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
        guard.insert(normalized_alias.clone(), binding);
        info!("Alias '{}' registered with new binding", normalized_alias);
        Ok(true)
    }

    async fn record_member_join(
        &self,
        leaf_id: [u8; 32],
        we_epoch_id: [u8; 32],
        timestamp_ms: u64,
    ) {
        // Keep metadata and reverse index updates in one critical section.
        let mut metadata = self.member_metadata.write().await;
        let mut map = self.weid_to_leaf.write().await;
        metadata.insert(
            leaf_id,
            MemberMetadata {
                join_timestamp_ms: timestamp_ms,
                last_seen_timestamp_ms: timestamp_ms,
            },
        );
        map.retain(|_, existing| *existing != leaf_id);
        map.insert(we_epoch_id, leaf_id);
    }

    async fn record_member_revocations(&self, leaves: &[[u8; 32]]) {
        if leaves.is_empty() {
            return;
        }
        let revoked: HashSet<[u8; 32]> = leaves.iter().copied().collect();
        let mut metadata = self.member_metadata.write().await;
        let mut map = self.weid_to_leaf.write().await;
        for leaf in &revoked {
            metadata.remove(leaf);
        }
        map.retain(|_, existing| !revoked.contains(existing));
    }

    async fn record_epoch_scope(&self, we_epoch_id: [u8; 32], scope: EpochScope) {
        let mut scopes = self.epoch_scopes.write().await;
        scopes.insert(we_epoch_id, scope);
    }

    async fn epoch_scope_for_weid(&self, we_epoch_id: &[u8; 32]) -> Option<EpochScope> {
        let scopes = self.epoch_scopes.read().await;
        scopes.get(we_epoch_id).copied()
    }

    async fn touch_member(&self, leaf_id: [u8; 32], timestamp_ms: u64) {
        let mut metadata = self.member_metadata.write().await;
        if let Some(entry) = metadata.get_mut(&leaf_id) {
            entry.last_seen_timestamp_ms = timestamp_ms;
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

fn should_prune_messages(prune_due_ms: &AtomicU64, now_ms: u64) -> bool {
    let due = prune_due_ms.load(Ordering::Relaxed);
    if now_ms < due {
        return false;
    }
    prune_due_ms
        .compare_exchange(
            due,
            now_ms.saturating_add(MESSAGE_PRUNE_INTERVAL_MS),
            Ordering::Relaxed,
            Ordering::Relaxed,
        )
        .is_ok()
}

fn maybe_prune_expired_messages(
    state: &ApiState,
    store: &mut AHashMap<[u8; 32], Vec<StoredMessage>>,
    now_ms: u64,
) {
    if should_prune_messages(state.message_prune_due_ms.as_ref(), now_ms) {
        prune_expired_messages(store, now_ms, state.message_retention);
    }
}

#[derive(Debug, Error)]
enum ApiError {
    #[error("failed to decode protobuf payload: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    #[error("conflict: {0}")]
    Conflict(String),
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
    #[error("unauthorized: {0}")]
    Unauthorized(&'static str),
}

impl ApiError {
    fn server_message(message: impl Into<String>) -> Self {
        Self::server_with_context(message.into(), None, None, None)
    }

    fn conflict(message: impl Into<String>) -> Self {
        ApiError::Conflict(message.into())
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
            ApiError::Conflict(message) => (StatusCode::CONFLICT, message, None, None, None),
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
            ApiError::Unauthorized(msg) => {
                (StatusCode::UNAUTHORIZED, msg.to_string(), None, None, None)
            }
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
        if status.is_server_error() {
            error!(status = %status, message = %message, freeze_code = ?freeze_code, freeze_reason = ?freeze_reason, "request failed");
        } else if status == StatusCode::CONFLICT {
            if let Some(reason) = classify_refresh_pivot_conflict(&message) {
                info!(
                    status = %status,
                    message = %message,
                    conflict_reason = reason,
                    freeze_code = ?freeze_code,
                    freeze_reason = ?freeze_reason,
                    "request conflict"
                );
            } else {
                warn!(status = %status, message = %message, freeze_code = ?freeze_code, freeze_reason = ?freeze_reason, "request failed");
            }
        } else {
            warn!(status = %status, message = %message, freeze_code = ?freeze_code, freeze_reason = ?freeze_reason, "request failed");
        }
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

fn parse_hex_32(label: &'static str, value: &str) -> Result<[u8; 32], ApiError> {
    let bytes = Vec::from_hex(value).map_err(|_| ApiError::InvalidRequest(label))?;
    if bytes.len() != 32 {
        return Err(ApiError::InvalidRequest(label));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn configured_window_admin_token() -> Option<String> {
    std::env::var(WINDOW_CONFIG_ADMIN_TOKEN_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn configured_rooms_admin_token() -> Option<String> {
    std::env::var(ROOMS_ADMIN_TOKEN_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(configured_window_admin_token)
}

fn configured_message_auth_token() -> Option<String> {
    std::env::var(MESSAGE_AUTH_TOKEN_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn parse_bool_env(raw: Option<String>) -> bool {
    raw.map(|value| value.trim().to_ascii_lowercase())
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn allow_insecure_admin() -> bool {
    parse_bool_env(std::env::var(ALLOW_INSECURE_ADMIN_ENV).ok())
}

fn warn_if_admin_auth_is_open() {
    if !allow_insecure_admin() {
        return;
    }
    if configured_rooms_admin_token().is_none() {
        warn!(
            "{}=true with no {} or {} configured; room admin endpoints are unauthenticated",
            ALLOW_INSECURE_ADMIN_ENV, ROOMS_ADMIN_TOKEN_ENV, WINDOW_CONFIG_ADMIN_TOKEN_ENV
        );
    }
    if configured_window_admin_token().is_none() {
        warn!(
            "{}=true with no {} configured; window admin endpoints are unauthenticated",
            ALLOW_INSECURE_ADMIN_ENV, WINDOW_CONFIG_ADMIN_TOKEN_ENV
        );
    }
}

fn enforce_admin_token_with_policy(
    headers: &HeaderMap,
    expected_token: Option<&str>,
    allow_insecure: bool,
) -> Result<(), ApiError> {
    let Some(expected_token) = expected_token else {
        if allow_insecure {
            return Ok(());
        }
        return Err(ApiError::Unauthorized("admin token is not configured"));
    };
    let provided = headers
        .get(WINDOW_CONFIG_ADMIN_HEADER)
        .and_then(|value| value.to_str().ok());
    if provided == Some(expected_token) {
        Ok(())
    } else {
        Err(ApiError::Unauthorized("missing or invalid admin token"))
    }
}

fn enforce_admin_token(headers: &HeaderMap, expected_token: Option<&str>) -> Result<(), ApiError> {
    enforce_admin_token_with_policy(headers, expected_token, allow_insecure_admin())
}

fn enforce_window_config_auth(
    headers: &HeaderMap,
    expected_token: Option<&str>,
) -> Result<(), ApiError> {
    enforce_admin_token(headers, expected_token)
}

fn enforce_room_admin_auth(
    headers: &HeaderMap,
    expected_token: Option<&str>,
) -> Result<(), ApiError> {
    enforce_admin_token(headers, expected_token)
}

fn enforce_message_auth_header(
    headers: &HeaderMap,
    expected_token: Option<&str>,
) -> Result<(), ApiError> {
    let Some(expected_token) = expected_token else {
        return Err(ApiError::Unauthorized(
            "message auth token is not configured",
        ));
    };
    let provided = headers
        .get(MESSAGE_AUTH_HEADER)
        .and_then(|value| value.to_str().ok());
    if provided == Some(expected_token) {
        Ok(())
    } else {
        Err(ApiError::Unauthorized(
            "missing or invalid message auth token",
        ))
    }
}

fn enforce_message_auth_query(
    provided: Option<&str>,
    expected_token: Option<&str>,
) -> Result<(), ApiError> {
    let Some(expected_token) = expected_token else {
        return Err(ApiError::Unauthorized(
            "message auth token is not configured",
        ));
    };
    if provided == Some(expected_token) {
        Ok(())
    } else {
        Err(ApiError::Unauthorized(
            "missing or invalid message auth token",
        ))
    }
}

fn parse_ws_max_lag(raw: Option<&str>) -> u64 {
    raw.and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(WS_MAX_LAG_DEFAULT)
}

fn configured_ws_max_lag() -> u64 {
    let raw = std::env::var(WS_MAX_LAG_ENV).ok();
    parse_ws_max_lag(raw.as_deref())
}

fn configured_group_lane_count() -> usize {
    std::env::var(GROUP_LANES_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_GROUP_LANES)
}

fn should_disconnect_for_lag(lagged_messages: u64, max_lag: u64) -> bool {
    lagged_messages > max_lag
}

fn classify_concurrency_pressure(
    message: &str,
    freeze_reason: Option<&'static str>,
) -> Option<&'static str> {
    let lowered = message.to_ascii_lowercase();
    let freeze_lowered = freeze_reason.unwrap_or_default().to_ascii_lowercase();
    if lowered.contains("window full")
        || freeze_lowered.contains("window_full")
        || freeze_lowered.contains("mhw/window")
    {
        return Some("window_full");
    }
    if lowered.contains("mh_heads_invalid") || freeze_lowered.contains("mh_heads_invalid") {
        return Some("mh_heads_invalid");
    }
    if lowered.contains("barrier_version") || lowered.contains("barrier version") {
        return Some("barrier_version");
    }
    if lowered.contains("barrier update required on revocation change") {
        return Some("revocation_change");
    }
    None
}

fn classify_refresh_pivot_conflict(message: &str) -> Option<&'static str> {
    let reason = message.strip_prefix("invalid input: ").unwrap_or(message);
    match reason {
        "pivot parity missing for refresh" => Some("pivot_parity_missing"),
        "pivot head missing" => Some("pivot_head_missing"),
        "refresh payload diverges from stored parity" => Some("payload_diverges"),
        _ => None,
    }
}

fn record_concurrency_pressure(endpoint: &'static str, reason: &'static str) {
    metrics::counter!(
        "cityg_concurrency_pressure_total",
        "endpoint" => endpoint.to_string(),
        "reason" => reason.to_string()
    )
    .increment(1);
}

fn maybe_record_api_concurrency_error(endpoint: &'static str, err: &ApiError) {
    if let ApiError::Server {
        message, freeze, ..
    } = err
        && let Some(reason) = classify_concurrency_pressure(message, freeze.map(|f| f.reason))
    {
        record_concurrency_pressure(endpoint, reason);
    }
}

fn maybe_record_client_concurrency_error(endpoint: &'static str, err: &ClientError) {
    match err {
        ClientError::InvalidInput(message) => {
            if let Some(reason) = classify_concurrency_pressure(message, None) {
                record_concurrency_pressure(endpoint, reason);
            }
        }
        ClientError::Acceptance(AcceptanceError::Freeze(freeze)) => {
            if let Some(reason) = classify_concurrency_pressure(freeze.reason, Some(freeze.reason))
            {
                record_concurrency_pressure(endpoint, reason);
            }
        }
        ClientError::Acceptance(inner) => {
            let message = format!("{inner:?}");
            if let Some(reason) = classify_concurrency_pressure(&message, None) {
                record_concurrency_pressure(endpoint, reason);
            }
        }
        _ => {}
    }
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
    let gid: [u8; 32] = bundle
        .gid()
        .try_into()
        .map_err(|_| ApiError::server_message("invalid gid length in bundle"))?;
    let mut weid = [0u8; 32];
    weid.copy_from_slice(&bundle.we_epoch_id);
    let started = Instant::now();

    let (outcome, sanitized_bundle) = {
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        let outcome = match guard.accept_epoch(bundle) {
            Ok(outcome) => outcome,
            Err(err) => {
                drop(guard);
                let mapped = map_accept_error(state, err, None, None).await;
                maybe_record_api_concurrency_error("accept_epoch", &mapped);
                metrics::counter!(
                    "cityg_accept_epoch_total",
                    "result" => "error".to_string()
                )
                .increment(1);
                metrics::histogram!(
                    "cityg_accept_epoch_duration_seconds",
                    "result" => "error".to_string()
                )
                .record(started.elapsed().as_secs_f64());
                return Err(mapped);
            }
        };
        let sanitized_bundle = materialize_stored_bundle(&mut guard, bundle, &outcome)?;
        (outcome, sanitized_bundle)
    };

    persist_bundle(state, bundle, weid, sanitized_bundle, outcome.new_root).await?;
    state.clear_merge_ticket_cache_for_gid(gid).await;
    metrics::counter!(
        "cityg_accept_epoch_total",
        "result" => "ok".to_string()
    )
    .increment(1);
    metrics::histogram!(
        "cityg_accept_epoch_duration_seconds",
        "result" => "ok".to_string()
    )
    .record(started.elapsed().as_secs_f64());
    Ok(accept_response_from(&outcome))
}

fn materialize_stored_bundle(
    server: &mut CityGServer,
    bundle: &ClientEpochBundle,
    outcome: &ServerOutcome,
) -> Result<Vec<u8>, ApiError> {
    let mut stored = bundle.clone();
    if !stored.header_map.contains_key(&hdr::HDR_HP_BYTES)
        && is_merge_bundle_header(&stored.header_map)
    {
        let parity = [outcome.new_root, outcome.parent_root]
            .into_iter()
            .find_map(|root| {
                server
                    .context_mut()
                    .pivot_parities_for(bundle.gid(), &root)
                    .into_iter()
                    .find(|parity| {
                        parity.we_epoch_id == outcome.we_epoch_id && !parity.hp_envelope.is_empty()
                    })
            })
            .ok_or_else(|| {
                ApiError::server_message(
                    "accepted merge parity missing hp envelope for stored bundle",
                )
            })?;
        let envelope: ciborium::value::Value =
            ciborium::de::from_reader(parity.hp_envelope.as_ref()).map_err(|_| {
                ApiError::server_message(
                    "accepted merge parity hp envelope malformed for stored bundle",
                )
            })?;
        stored.header_map.insert(hdr::HDR_HP_BYTES, envelope);
    }
    stored
        .to_cbor()
        .map_err(|err| ApiError::server_message(format!("failed to sanitize bundle: {err}")))
}

fn is_merge_bundle_header(header: &BTreeMap<u64, ciborium::value::Value>) -> bool {
    header.contains_key(&hdr::HDR_BARRIER_UPDATE)
        || header.contains_key(&hdr::HDR_BARRIER_UPDATE_REASON)
        || [
            hdr::HDR_MH_HEADS,
            hdr::HDR_ROLLUP_PIVOT_WEID,
            hdr::HDR_ROLLUP_PROVENANCE_COMMIT,
            hdr::HDR_ROLLUP_EPOCH_REPLAY,
            hdr::HDR_ROLLUP_VCK_COMMIT,
            hdr::HDR_MERGE_DELEGATION_SIG,
            hdr::HDR_KBROAD_REPLAY,
            hdr::HDR_ROLLUP_FS_MODE,
            hdr::HDR_FS_EVOLUTION_BOUNDARY,
            hdr::HDR_FS_PURGE_TIMES,
            hdr::HDR_FS_CHECKPOINT_EC,
        ]
        .into_iter()
        .any(|key| header.contains_key(&key))
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
    membership_root: [u8; 32],
) -> Result<(), ApiError> {
    let gid: [u8; 32] = bundle
        .gid()
        .try_into()
        .map_err(|_| ApiError::server_message("invalid gid length in bundle"))?;
    state
        .record_epoch_scope(
            weid,
            EpochScope {
                gid,
                membership_root,
            },
        )
        .await;
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

async fn ensure_leaf_member_for_epoch(
    state: &ApiState,
    we_epoch_id: &[u8; 32],
    leaf_id: [u8; 32],
) -> Result<EpochScope, ApiError> {
    let scope = state
        .epoch_scope_for_weid(we_epoch_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let members = {
        let lane = state.server_for_gid(&scope.gid);
        let guard = lane.read().await;
        guard
            .members_for_root(&scope.gid, &scope.membership_root)
            .ok_or(ApiError::NotFound)?
    };
    if members.iter().any(|member| member == &leaf_id) {
        Ok(scope)
    } else {
        Err(ApiError::Unauthorized("leaf is not a member for epoch"))
    }
}

async fn ensure_leaf_member_for_room(
    state: &ApiState,
    gid: &[u8; 32],
    leaf_id: [u8; 32],
) -> Result<(), ApiError> {
    let members = {
        let lane = state.server_for_gid(gid);
        let guard = lane.read().await;
        let latest_root = guard.latest_parent_root(gid).ok_or(ApiError::NotFound)?;
        guard
            .members_for_root(gid, &latest_root)
            .ok_or(ApiError::NotFound)?
    };
    if members.iter().any(|member| member == &leaf_id) {
        Ok(())
    } else {
        Err(ApiError::Unauthorized("leaf is not a member for room"))
    }
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
        ClientError::InvalidInput(message) => {
            tracing::debug!(%message, "accept_epoch invalid bundle input");
            ApiError::InvalidRequest("invalid bundle components")
        }
        ClientError::Acceptance(AcceptanceError::Freeze(freeze)) => {
            state.record_freeze(freeze).await;
            ApiError::server_with_freeze_context(
                format!("acceptance error: {}", freeze.reason),
                freeze,
                error_label,
                failed_index,
            )
        }
        ClientError::Acceptance(AcceptanceError::Msphf(MsphfError::InvalidInput(message))) => {
            tracing::debug!(%message, "accept_epoch invalid msphf bundle input");
            ApiError::InvalidRequest("invalid bundle components")
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

async fn members(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
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
    let lane = state.server_for_gid_bytes(&gid);

    let (members, root) = {
        let guard = lane.read().await;
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

async fn search_members(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
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
    let lane = state.server_for_gid_bytes(&gid);

    let (members, root) = {
        let guard = lane.read().await;
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
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        let bundle = match guard.build_join_ticket_with_leaf(&gid, requested_leaf_id) {
            Ok(bundle) => bundle,
            Err(err) => {
                maybe_record_client_concurrency_error("join_ticket", &err);
                metrics::counter!("cityg_join_ticket_total", "result" => "error".to_string())
                    .increment(1);
                return Err(ApiError::from(err));
            }
        };
        let policy_version = guard.context().policy_version().to_string();
        let fs_policy_version = guard
            .context()
            .fs_policy_version()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "7".to_string());
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
        kbroad_generation: ticket.kbroad_generation,
        barrier_version: ticket.barrier_version,
        profile_version: API_PROFILE_VERSION.to_string(),
        cover_leaf_index: ticket.cover_leaf_index,
        kem_tree_hash_after: ticket.kem_tree_hash_after.to_vec(),
        n_max: ticket.n_max,
        max_barrier_update_bytes: ticket.max_barrier_update_bytes,
    };

    metrics::counter!("cityg_join_ticket_total", "result" => "ok".to_string()).increment(1);
    Ok(protobuf_response(&response))
}

async fn bootstrap_room(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_room_admin_auth(&headers, configured_rooms_admin_token().as_deref())?;
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
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        guard
            .register_group(&gid, request.kbroad_public)
            .map_err(|err| match err {
                ClientError::InvalidInput(message) => ApiError::InvalidRequest(message),
                other => ApiError::from(other),
            })?;
    }

    let response = BootstrapRoomResponse {
        status: "registered".to_string(),
    };

    Ok(protobuf_response(&response))
}

async fn rotate_room_kbroad(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_room_admin_auth(&headers, configured_rooms_admin_token().as_deref())?;
    let request = RotateRoomKbroadRequest::decode(body)?;
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
    let kbroad_generation = {
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        guard
            .rotate_group_kbroad(&gid, request.kbroad_public)
            .map_err(|err| match err {
                ClientError::InvalidInput(message) => ApiError::InvalidRequest(message),
                other => ApiError::from(other),
            })?
    };

    let response = RotateRoomKbroadResponse {
        status: "rotated".to_string(),
        kbroad_generation,
    };
    Ok(protobuf_response(&response))
}

async fn merge_ticket(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
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
    let intent = MergeTicketIntent::try_from(request.intent)
        .map_err(|_| ApiError::InvalidRequest("merge ticket intent is invalid"))?;
    let cache_key = MergeTicketCacheKey {
        gid,
        leaf_id,
        intent: request.intent,
    };
    let now_ms = current_timestamp_ms();
    if intent == MergeTicketIntent::Leave
        && let Some(cached) = state.coalesced_merge_ticket_lookup(cache_key, now_ms).await
    {
        metrics::counter!(
            "cityg_merge_ticket_coalesced_total",
            "intent" => "leave".to_string()
        )
        .increment(1);
        metrics::counter!("cityg_merge_ticket_total", "result" => "ok".to_string()).increment(1);
        return Ok(protobuf_response_bytes(cached));
    }

    let bundle = {
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        match intent {
            MergeTicketIntent::Leave => {
                guard.build_merge_ticket(&gid, &leaf_id).map_err(|err| {
                    maybe_record_client_concurrency_error("merge_ticket", &err);
                    metrics::counter!("cityg_merge_ticket_total", "result" => "error".to_string())
                        .increment(1);
                    ApiError::from(err)
                })?
            }
            MergeTicketIntent::Refresh => guard
                .build_merge_ticket_for_refresh(&gid, &leaf_id)
                .map_err(|err| {
                    maybe_record_client_concurrency_error("merge_ticket_refresh", &err);
                    metrics::counter!("cityg_merge_ticket_total", "result" => "error".to_string())
                        .increment(1);
                    ApiError::from(err)
                })?,
        }
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
        kbroad_generation,
        barrier_version,
        cover_leaf_index,
        kem_tree_hash_after,
        n_max,
        max_barrier_update_bytes,
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
        kbroad_generation,
        barrier_version,
        profile_version: API_PROFILE_VERSION.to_string(),
        cover_leaf_index,
        kem_tree_hash_after: kem_tree_hash_after.to_vec(),
        n_max,
        max_barrier_update_bytes,
    };

    let mut response_bytes = Vec::new();
    response
        .encode(&mut response_bytes)
        .map_err(|err| ApiError::server_message(format!("failed to encode merge ticket: {err}")))?;
    if intent == MergeTicketIntent::Leave {
        state
            .coalesced_merge_ticket_store(cache_key, response_bytes.clone(), now_ms)
            .await;
    }
    metrics::counter!("cityg_merge_ticket_total", "result" => "ok".to_string()).increment(1);
    Ok(protobuf_response_bytes(response_bytes))
}

async fn barrier_resolve_revoked_leaves(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let request = BarrierResolveRevokedLeavesRequest::decode(body)?;
    if request.room_id.is_empty() {
        return Err(ApiError::InvalidRequest("room_id must be provided"));
    }
    if request.revocation_roots_hash.len() != 32 {
        return Err(ApiError::InvalidRequest(
            "revocation_roots_hash must be 32 bytes",
        ));
    }
    let gid = parse_gid(&request.room_id)?;
    let mut revocation_roots_hash = [0u8; 32];
    revocation_roots_hash.copy_from_slice(&request.revocation_roots_hash);

    let leaf_indices = {
        let lane = state.server_for_gid(&gid);
        let guard = lane.read().await;
        guard
            .resolve_revoked_leaf_indices(&gid, &revocation_roots_hash)
            .map_err(ApiError::from)?
    };

    let response = BarrierResolveRevokedLeavesResponse { leaf_indices };
    Ok(protobuf_response(&response))
}

async fn barrier_resolve_joins_since(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let request = BarrierResolveJoinsSinceRequest::decode(body)?;
    if request.room_id.is_empty() {
        return Err(ApiError::InvalidRequest("room_id must be provided"));
    }
    let gid = parse_gid(&request.room_id)?;

    let records = {
        let lane = state.server_for_gid(&gid);
        let guard = lane.read().await;
        guard
            .resolve_joins_since(&gid, request.prev_barrier_version)
            .map_err(ApiError::from)?
    };

    let response = BarrierResolveJoinsSinceResponse {
        records: records
            .into_iter()
            .map(
                |ServerBarrierJoinLeafRecord {
                     device_pk,
                     leaf_index,
                     ek_leaf,
                 }| BarrierJoinLeafRecord {
                    device_pk,
                    leaf_index,
                    ek_leaf,
                },
            )
            .collect(),
    };
    Ok(protobuf_response(&response))
}

async fn barrier_fetch_public_tree(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let request = BarrierFetchPublicTreeRequest::decode(body)?;
    if request.room_id.is_empty() {
        return Err(ApiError::InvalidRequest("room_id must be provided"));
    }
    if request.kem_tree_hash_after.len() != 32 {
        return Err(ApiError::InvalidRequest(
            "kem_tree_hash_after must be 32 bytes",
        ));
    }
    let gid = parse_gid(&request.room_id)?;
    let mut kem_tree_hash_after = [0u8; 32];
    kem_tree_hash_after.copy_from_slice(&request.kem_tree_hash_after);

    let snapshot = {
        let lane = state.server_for_gid(&gid);
        let guard = lane.read().await;
        guard
            .fetch_barrier_public_tree(&gid, &kem_tree_hash_after)
            .map_err(ApiError::from)?
    };

    let response = BarrierFetchPublicTreeResponse {
        n_max: snapshot.n_max,
        kem_tree_hash_after: snapshot.kem_tree_hash_after.to_vec(),
        pk_entries: snapshot.pk_entries,
    };
    Ok(protobuf_response(&response))
}

async fn send_message(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
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
    if sender.len() != 32 {
        return Err(ApiError::InvalidRequest("sender must be 32 bytes"));
    }
    let mut sender_leaf = [0u8; 32];
    sender_leaf.copy_from_slice(&sender);
    let scope = ensure_leaf_member_for_epoch(&state, &weid, sender_leaf).await?;
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
        maybe_prune_expired_messages(&state, &mut guard, timestamp_ms);
    }

    // Broadcast notification to WebSocket clients
    let notification = MessageNotification {
        gid: scope.gid,
        we_epoch_id: weid,
        timestamp_ms,
    };
    state.broadcast_message(notification);

    state.touch_member(sender_leaf, timestamp_ms).await;

    let reply = SendMessageResponse {
        status: "stored".to_string(),
    };
    Ok(protobuf_response(&reply))
}

async fn fetch_messages(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let request = FetchMessagesRequest::decode(body)?;
    if request.we_epoch_id.len() != 32 {
        return Err(ApiError::InvalidRequest("we_epoch_id must be 32 bytes"));
    }
    if request.leaf_id.len() != 32 {
        return Err(ApiError::InvalidRequest("leaf_id must be 32 bytes"));
    }
    let mut weid = [0u8; 32];
    weid.copy_from_slice(&request.we_epoch_id);
    let mut leaf_id = [0u8; 32];
    leaf_id.copy_from_slice(&request.leaf_id);
    ensure_leaf_member_for_epoch(&state, &weid, leaf_id).await?;

    let now_ms = current_timestamp_ms();
    let messages = {
        let mut guard = state.messages.write().await;
        maybe_prune_expired_messages(&state, &mut guard, now_ms);
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

async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<ApiState>,
    Query(query): Query<WebSocketSubscriptionQuery>,
) -> Result<Response, ApiError> {
    enforce_message_auth_query(
        query.token.as_deref(),
        configured_message_auth_token().as_deref(),
    )?;
    let gid = parse_gid(&query.gid)?;
    let leaf_id = parse_hex_32("leaf_id must be 64 hex characters", &query.leaf_id)?;
    ensure_leaf_member_for_room(&state, &gid, leaf_id).await?;
    Ok(ws.on_upgrade(move |socket| handle_websocket(socket, state, gid)))
}

async fn handle_websocket(socket: WebSocket, state: ApiState, subscribed_gid: [u8; 32]) {
    let (mut sender, mut receiver) = socket.split();

    // Subscribe to server notifications
    let mut rx = state.notification_tx.subscribe();
    let max_lag = configured_ws_max_lag();

    debug!(
        "WebSocket client connected for gid {}",
        hex::encode(subscribed_gid)
    );

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
                                BroadcastNotification::Message(msg) => {
                                    if msg.gid != subscribed_gid {
                                        continue;
                                    }
                                    serde_json::json!({
                                        "type": "message",
                                        "gid": hex::encode(msg.gid),
                                        "we_epoch_id": hex::encode(msg.we_epoch_id),
                                        "timestamp_ms": msg.timestamp_ms,
                                        "connection_healthy": true
                                    })
                                }
                                BroadcastNotification::Membership(event) => {
                                    if event.gid != subscribed_gid {
                                        continue;
                                    }
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

                            if let Err(e) = sender.send(WsMessage::Text(text.into())).await {
                                warn!("Failed to send WebSocket message: {}", e);
                                connection_healthy.store(false, std::sync::atomic::Ordering::Relaxed);
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!(
                                "WebSocket client lagged by {} messages (max allowed: {})",
                                n, max_lag
                            );
                            if should_disconnect_for_lag(n, max_lag) {
                                let disconnect_notification = serde_json::json!({
                                    "type": "lag_disconnect",
                                    "lagged_messages": n,
                                    "max_lag": max_lag,
                                });
                                if let Ok(text) = serde_json::to_string(&disconnect_notification) {
                                    let _ = sender.send(WsMessage::Text(text.into())).await;
                                }
                                warn!(
                                    "WebSocket client exceeded lag threshold; disconnecting"
                                );
                                connection_healthy
                                    .store(false, std::sync::atomic::Ordering::Relaxed);
                                break;
                            }
                            // Send lag notification to client
                            let lag_notification = serde_json::json!({
                                "type": "lag",
                                "lagged_messages": n,
                                "recommendation": "consider reconnecting"
                            });
                            if let Ok(text) = serde_json::to_string(&lag_notification) {
                                let _ = sender.send(WsMessage::Text(text.into())).await;
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
                        if let Err(e) = sender.send(WsMessage::Ping(vec![].into())).await {
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

async fn get_bundle(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
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

async fn get_window(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let _ = GetWindowRequest::decode(body)?;
    let mut snapshot: Vec<WindowEntry> = Vec::new();
    for lane in state.all_server_lanes() {
        let guard = lane.read().await;
        let now = guard.context().current_time();
        snapshot.extend(
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
                            let age_ms =
                                now.duration_since(record.accept_time())
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
                }),
        );
    }

    let reply = GetWindowResponse { entries: snapshot };
    Ok(protobuf_response(&reply))
}

async fn get_telemetry(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let _ = GetTelemetryRequest::decode(body)?;
    let mut report = Vec::new();
    for lane in state.all_server_lanes() {
        let guard = lane.read().await;
        report.extend(guard.context().telemetry_report());
    }

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
        srx_root_sw: Option<ByteBuf>,
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
        srx_root_sw: parity.srx_root_sw.map(|root| ByteBuf::from(root.to_vec())),
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
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_window_config_auth(&headers, configured_window_admin_token().as_deref())?;
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
        let mut effective: Option<(usize, Duration)> = None;
        for lane in state.all_server_lanes() {
            let mut guard = lane.write().await;
            guard.update_window_limits(h_max, ttl);
            if effective.is_none() {
                effective = Some(guard.window_limits());
            }
        }
        effective.unwrap_or((0, Duration::from_secs(0)))
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

fn protobuf_response_bytes(payload: Vec<u8>) -> Response {
    let mut response = Response::new(payload.into());
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
    server_cfg.state_path = cfg.server.state_path.clone();

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

fn lane_state_path(base: &Path, lane_index: usize, lane_count: usize) -> PathBuf {
    if lane_count <= 1 {
        return base.to_path_buf();
    }

    let stem = base
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("cityg-server");
    let lane_stem = format!("{stem}.lane-{lane_index:02}");
    match base.extension().and_then(|ext| ext.to_str()) {
        Some(ext) if !ext.is_empty() => base.with_file_name(format!("{lane_stem}.{ext}")),
        _ => base.with_file_name(lane_stem),
    }
}

fn server_from_config_for_lane(
    cfg: &cityg_config::CityGConfig,
    lane_index: usize,
    lane_count: usize,
) -> CityGServer {
    if lane_count <= 1 || cfg.server.state_path.is_none() {
        return server_from_config(cfg);
    }

    let mut lane_cfg = cfg.clone();
    lane_cfg.server.state_path = cfg
        .server
        .state_path
        .as_ref()
        .map(|path| lane_state_path(path, lane_index, lane_count));
    server_from_config(&lane_cfg)
}

fn aligned_fs_epoch_base_ts(now: SystemTime, period_seconds: u64) -> u64 {
    let period = period_seconds.max(1);
    let now_secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    now_secs - (now_secs % period)
}

fn fs_policy_from_settings(settings: &cityg_config::FsPolicySettings) -> FsPolicyConfig {
    FsPolicyConfig {
        h: settings.h_seconds,
        checkpoint_interval: settings.checkpoint_interval_seconds,
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
    warn_if_admin_auth_is_open();

    // Initialize metrics exporter
    let prometheus_handle = match middleware::init_metrics_exporter() {
        Ok(handle) => Some(handle),
        Err(err) => {
            warn!("metrics exporter disabled: {}", err);
            None
        }
    };

    let lane_count = configured_group_lane_count().max(1);
    let server_lanes_vec: Vec<Arc<RwLock<CityGServer>>> = (0..lane_count)
        .map(|lane_index| {
            Arc::new(RwLock::new(server_from_config_for_lane(
                &config, lane_index, lane_count,
            )))
        })
        .collect();
    let server = server_lanes_vec.first().cloned().unwrap_or_else(|| {
        Arc::new(RwLock::new(server_from_config_for_lane(
            &config, 0, lane_count,
        )))
    });
    let server_lanes = Arc::new(server_lanes_vec);
    let message_retention = message_retention_from_config(&config);
    info!(
        "message retention window set to {}s (group execution lanes: {})",
        message_retention.as_secs(),
        lane_count
    );
    // Create broadcast channel for WebSocket notifications (capacity from config)
    let (notification_tx, _) = broadcast::channel(config.server.websocket_capacity);

    let state = ApiState {
        server,
        server_lanes,
        messages: Arc::new(RwLock::new(AHashMap::new())),
        bundles: Arc::new(RwLock::new(AHashMap::new())),
        message_retention,
        fs_epoch_period_seconds: config.protocol.fs_policy.h_seconds.max(1),
        freeze_counts: Arc::new(RwLock::new(BTreeMap::new())),
        alias_registry: Arc::new(RwLock::new(AHashMap::new())),
        member_metadata: Arc::new(RwLock::new(AHashMap::new())),
        weid_to_leaf: Arc::new(RwLock::new(AHashMap::new())),
        epoch_scopes: Arc::new(RwLock::new(AHashMap::new())),
        notification_tx,
        alias_rate_limiter: AliasRateLimiter::new(
            ALIAS_RATE_LIMIT_BURST,
            Duration::from_secs(ALIAS_RATE_LIMIT_WINDOW_SECS),
        ),
        message_prune_due_ms: Arc::new(AtomicU64::new(0)),
        merge_ticket_cache: Arc::new(RwLock::new(AHashMap::new())),
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
        .route("/v1/rooms/rotate_kbroad", post(rotate_room_kbroad))
        .route("/v1/rooms/join_ticket", post(join_ticket))
        .route("/v1/rooms/merge_ticket", post(merge_ticket))
        .route(
            "/v1/barrier/resolve_revoked_leaves",
            post(barrier_resolve_revoked_leaves),
        )
        .route(
            "/v1/barrier/resolve_joins_since",
            post(barrier_resolve_joins_since),
        )
        .route(
            "/v1/barrier/fetch_public_tree",
            post(barrier_fetch_public_tree),
        )
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
        .layer(DefaultBodyLimit::max(API_MAX_BODY_BYTES))
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
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_window_config_auth(&headers, configured_window_admin_token().as_deref())?;
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
        let gid: [u8; 32] = bundle
            .gid()
            .try_into()
            .map_err(|_| ApiError::InvalidRequest("bundle gid must be 32 bytes"))?;
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
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

async fn refresh_pivot(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
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
        let gid: [u8; 32] = bundle
            .gid()
            .try_into()
            .map_err(|_| ApiError::InvalidRequest("bundle gid must be 32 bytes"))?;
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        guard.refresh_pivot(&bundle).map_err(|err| match err {
            ClientError::InvalidInput(
                "pivot parity missing for refresh"
                | "pivot head missing"
                | "refresh payload diverges from stored parity",
            ) => {
                if let Some(reason) = classify_refresh_pivot_conflict(&err.to_string()) {
                    metrics::counter!(
                        "cityg_refresh_pivot_conflict_total",
                        "reason" => reason.to_string()
                    )
                    .increment(1);
                }
                ApiError::conflict(err.to_string())
            }
            other => ApiError::server_message(other.to_string()),
        })?;
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
    use cityg_client::witness::SrxInputsOwned;
    use cityg_config::CityGConfig;
    use futures::{SinkExt, StreamExt};
    use msphf_core::MsphfError;
    use msphf_core::merkle::canonical_set_root;
    use msphf_orchestrator::hdr;
    use pqcrypto_dilithium::dilithium5;
    use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
    use prost::Message;
    use serde_bytes::ByteBuf;
    use serde_json::Value;
    use std::sync::{Mutex, Once, OnceLock};

    fn test_api_state_with_lanes(lane_count: usize) -> ApiState {
        let mut cfg = CityGConfig::default();
        cfg.server.seed_demo_room = true;
        let lanes: Vec<Arc<RwLock<CityGServer>>> = (0..lane_count.max(1))
            .map(|_| Arc::new(RwLock::new(server_from_config(&cfg))))
            .collect();
        let server = lanes
            .first()
            .cloned()
            .expect("test lane set must contain at least one lane");
        ApiState {
            server: server.clone(),
            server_lanes: Arc::new(lanes),
            messages: Arc::new(RwLock::new(AHashMap::new())),
            bundles: Arc::new(RwLock::new(AHashMap::new())),
            message_retention: Duration::from_secs(DEFAULT_FS_MESSAGE_RETENTION_SECS),
            fs_epoch_period_seconds: cfg.protocol.fs_policy.h_seconds.max(1),
            freeze_counts: Arc::new(RwLock::new(BTreeMap::new())),
            alias_registry: Arc::new(RwLock::new(AHashMap::new())),
            member_metadata: Arc::new(RwLock::new(AHashMap::new())),
            weid_to_leaf: Arc::new(RwLock::new(AHashMap::new())),
            epoch_scopes: Arc::new(RwLock::new(AHashMap::new())),
            notification_tx: broadcast::channel(8).0,
            alias_rate_limiter: AliasRateLimiter::new(
                ALIAS_RATE_LIMIT_BURST,
                Duration::from_secs(ALIAS_RATE_LIMIT_WINDOW_SECS),
            ),
            message_prune_due_ms: Arc::new(AtomicU64::new(0)),
            merge_ticket_cache: Arc::new(RwLock::new(AHashMap::new())),
        }
    }

    fn test_api_state() -> ApiState {
        test_api_state_with_lanes(1)
    }

    fn empty_test_api_state() -> ApiState {
        let cfg = CityGConfig::default();
        let server = Arc::new(RwLock::new(server_from_config(&cfg)));
        ApiState {
            server: server.clone(),
            server_lanes: Arc::new(vec![server]),
            messages: Arc::new(RwLock::new(AHashMap::new())),
            bundles: Arc::new(RwLock::new(AHashMap::new())),
            message_retention: Duration::from_secs(DEFAULT_FS_MESSAGE_RETENTION_SECS),
            fs_epoch_period_seconds: cfg.protocol.fs_policy.h_seconds.max(1),
            freeze_counts: Arc::new(RwLock::new(BTreeMap::new())),
            alias_registry: Arc::new(RwLock::new(AHashMap::new())),
            member_metadata: Arc::new(RwLock::new(AHashMap::new())),
            weid_to_leaf: Arc::new(RwLock::new(AHashMap::new())),
            epoch_scopes: Arc::new(RwLock::new(AHashMap::new())),
            notification_tx: broadcast::channel(4).0,
            alias_rate_limiter: AliasRateLimiter::new(100, Duration::from_secs(60)),
            message_prune_due_ms: Arc::new(AtomicU64::new(0)),
            merge_ticket_cache: Arc::new(RwLock::new(AHashMap::new())),
        }
    }

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock poisoned")
    }

    fn ensure_test_admin_tokens() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| unsafe {
            std::env::set_var(WINDOW_CONFIG_ADMIN_TOKEN_ENV, "window-test-token");
            std::env::set_var(ROOMS_ADMIN_TOKEN_ENV, "room-test-token");
            std::env::set_var(MESSAGE_AUTH_TOKEN_ENV, "message-test-token");
            std::env::remove_var(ALLOW_INSECURE_ADMIN_ENV);
        });
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

    fn room_admin_headers() -> HeaderMap {
        ensure_test_admin_tokens();
        let mut headers = HeaderMap::new();
        if let Some(token) = configured_rooms_admin_token() {
            let token = HeaderValue::from_str(token.as_str()).expect("valid room admin token");
            headers.insert(WINDOW_CONFIG_ADMIN_HEADER, token);
        }
        headers
    }

    fn window_admin_headers() -> HeaderMap {
        ensure_test_admin_tokens();
        let mut headers = HeaderMap::new();
        if let Some(token) = configured_window_admin_token() {
            let token = HeaderValue::from_str(token.as_str()).expect("valid window admin token");
            headers.insert(WINDOW_CONFIG_ADMIN_HEADER, token);
        }
        headers
    }

    fn message_auth_headers() -> HeaderMap {
        ensure_test_admin_tokens();
        let mut headers = HeaderMap::new();
        if let Some(token) = configured_message_auth_token() {
            let token = HeaderValue::from_str(token.as_str()).expect("valid message auth token");
            headers.insert(MESSAGE_AUTH_HEADER, token);
        }
        headers
    }

    #[test]
    fn window_config_auth_accepts_matching_header_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            WINDOW_CONFIG_ADMIN_HEADER,
            HeaderValue::from_static("top-secret"),
        );
        assert!(enforce_window_config_auth(&headers, Some("top-secret")).is_ok());
    }

    #[test]
    fn window_config_auth_rejects_missing_or_wrong_token() {
        let empty_headers = HeaderMap::new();
        let missing = enforce_window_config_auth(&empty_headers, Some("top-secret"));
        assert!(matches!(
            missing,
            Err(ApiError::Unauthorized("missing or invalid admin token"))
        ));

        let mut headers = HeaderMap::new();
        headers.insert(
            WINDOW_CONFIG_ADMIN_HEADER,
            HeaderValue::from_static("wrong"),
        );
        let wrong = enforce_window_config_auth(&headers, Some("top-secret"));
        assert!(matches!(
            wrong,
            Err(ApiError::Unauthorized("missing or invalid admin token"))
        ));

        assert!(matches!(
            enforce_window_config_auth(&empty_headers, None),
            Err(ApiError::Unauthorized("admin token is not configured"))
        ));
    }

    #[test]
    fn classify_concurrency_pressure_maps_expected_signals() {
        assert_eq!(
            classify_concurrency_pressure("window full for gid", None),
            Some("window_full")
        );
        assert_eq!(
            classify_concurrency_pressure("invalid input: barrier_version mismatch", None),
            Some("barrier_version")
        );
        assert_eq!(
            classify_concurrency_pressure("mh_heads_invalid", Some("mh_heads_invalid")),
            Some("mh_heads_invalid")
        );
        assert_eq!(
            classify_concurrency_pressure("barrier update required on revocation change", None),
            Some("revocation_change")
        );
        assert_eq!(classify_concurrency_pressure("random failure", None), None);
    }

    #[test]
    fn configured_group_lane_count_uses_env_or_default() {
        let _guard = env_lock();
        unsafe {
            std::env::remove_var(GROUP_LANES_ENV);
        }
        assert_eq!(configured_group_lane_count(), DEFAULT_GROUP_LANES);

        unsafe {
            std::env::set_var(GROUP_LANES_ENV, "7");
        }
        assert_eq!(configured_group_lane_count(), 7);

        unsafe {
            std::env::set_var(GROUP_LANES_ENV, "0");
        }
        assert_eq!(configured_group_lane_count(), DEFAULT_GROUP_LANES);

        unsafe {
            std::env::set_var(GROUP_LANES_ENV, "not-a-number");
        }
        assert_eq!(configured_group_lane_count(), DEFAULT_GROUP_LANES);

        unsafe {
            std::env::remove_var(GROUP_LANES_ENV);
        }
    }

    #[tokio::test]
    async fn server_lane_helpers_fallback_when_lane_set_is_empty() {
        let cfg = CityGConfig::default();
        let server = Arc::new(RwLock::new(server_from_config(&cfg)));
        let state = ApiState {
            server: server.clone(),
            server_lanes: Arc::new(Vec::new()),
            messages: Arc::new(RwLock::new(AHashMap::new())),
            bundles: Arc::new(RwLock::new(AHashMap::new())),
            message_retention: Duration::from_secs(DEFAULT_FS_MESSAGE_RETENTION_SECS),
            fs_epoch_period_seconds: cfg.protocol.fs_policy.h_seconds.max(1),
            freeze_counts: Arc::new(RwLock::new(BTreeMap::new())),
            alias_registry: Arc::new(RwLock::new(AHashMap::new())),
            member_metadata: Arc::new(RwLock::new(AHashMap::new())),
            weid_to_leaf: Arc::new(RwLock::new(AHashMap::new())),
            epoch_scopes: Arc::new(RwLock::new(AHashMap::new())),
            notification_tx: broadcast::channel(4).0,
            alias_rate_limiter: AliasRateLimiter::new(100, Duration::from_secs(60)),
            message_prune_due_ms: Arc::new(AtomicU64::new(0)),
            merge_ticket_cache: Arc::new(RwLock::new(AHashMap::new())),
        };

        let gid = [0x44; 32];
        let routed = state.server_for_gid(&gid);
        assert!(
            Arc::ptr_eq(&routed, &server),
            "empty lane set should fallback to primary server"
        );
        let lanes = state.all_server_lanes();
        assert_eq!(lanes.len(), 1);
        assert!(Arc::ptr_eq(&lanes[0], &server));
    }

    #[tokio::test]
    async fn coalesced_merge_ticket_lookup_prunes_stale_entries() {
        let state = test_api_state();
        let key = MergeTicketCacheKey {
            gid: [0x11; 32],
            leaf_id: [0x22; 32],
            intent: MergeTicketIntent::Leave as i32,
        };
        let now_ms: u64 = 50_000;
        {
            let mut guard = state.merge_ticket_cache.write().await;
            guard.insert(
                key,
                MergeTicketCacheEntry {
                    created_at_ms: now_ms.saturating_sub(MERGE_COALESCE_TTL_MS + 1),
                    response_bytes: vec![1, 2, 3],
                },
            );
        }
        assert!(
            state
                .coalesced_merge_ticket_lookup(key, now_ms)
                .await
                .is_none(),
            "stale coalesced merge ticket entry should be pruned on lookup"
        );
        assert!(state.merge_ticket_cache.read().await.is_empty());
    }

    #[test]
    fn admin_auth_policy_supports_explicit_insecure_override() {
        let empty_headers = HeaderMap::new();
        assert!(enforce_admin_token_with_policy(&empty_headers, None, true).is_ok());
        assert!(matches!(
            enforce_admin_token_with_policy(&empty_headers, None, false),
            Err(ApiError::Unauthorized("admin token is not configured"))
        ));
    }

    #[test]
    fn room_admin_auth_accepts_matching_header_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            WINDOW_CONFIG_ADMIN_HEADER,
            HeaderValue::from_static("room-secret"),
        );
        assert!(enforce_room_admin_auth(&headers, Some("room-secret")).is_ok());
    }

    #[test]
    fn room_admin_auth_rejects_missing_or_wrong_token() {
        let empty_headers = HeaderMap::new();
        let missing = enforce_room_admin_auth(&empty_headers, Some("room-secret"));
        assert!(matches!(
            missing,
            Err(ApiError::Unauthorized("missing or invalid admin token"))
        ));

        let mut headers = HeaderMap::new();
        headers.insert(
            WINDOW_CONFIG_ADMIN_HEADER,
            HeaderValue::from_static("wrong"),
        );
        let wrong = enforce_room_admin_auth(&headers, Some("room-secret"));
        assert!(matches!(
            wrong,
            Err(ApiError::Unauthorized("missing or invalid admin token"))
        ));

        assert!(matches!(
            enforce_room_admin_auth(&empty_headers, None),
            Err(ApiError::Unauthorized("admin token is not configured"))
        ));
    }

    #[test]
    fn message_auth_rejects_missing_wrong_or_unconfigured_tokens() {
        let mut headers = HeaderMap::new();
        headers.insert(MESSAGE_AUTH_HEADER, HeaderValue::from_static("wrong"));
        assert!(matches!(
            enforce_message_auth_header(&headers, Some("msg-secret")),
            Err(ApiError::Unauthorized(
                "missing or invalid message auth token"
            ))
        ));

        let empty_headers = HeaderMap::new();
        assert!(matches!(
            enforce_message_auth_header(&empty_headers, Some("msg-secret")),
            Err(ApiError::Unauthorized(
                "missing or invalid message auth token"
            ))
        ));
        assert!(matches!(
            enforce_message_auth_query(None, None),
            Err(ApiError::Unauthorized(
                "message auth token is not configured"
            ))
        ));
    }

    #[test]
    fn message_auth_helpers_cover_header_and_query_error_paths() {
        let empty_headers = HeaderMap::new();
        assert!(matches!(
            enforce_message_auth_header(&empty_headers, None),
            Err(ApiError::Unauthorized(
                "message auth token is not configured"
            ))
        ));
        assert!(matches!(
            enforce_message_auth_query(Some("wrong"), Some("msg-secret")),
            Err(ApiError::Unauthorized(
                "missing or invalid message auth token"
            ))
        ));
    }

    #[tokio::test]
    async fn sensitive_endpoints_require_message_auth_header() {
        ensure_test_admin_tokens();
        let state = empty_test_api_state();
        let empty_headers = HeaderMap::new();

        let members_err = members(State(state.clone()), empty_headers.clone(), Bytes::new())
            .await
            .expect_err("members should require message auth");
        assert!(matches!(
            members_err,
            ApiError::Unauthorized("missing or invalid message auth token")
        ));

        let search_err = search_members(State(state.clone()), empty_headers.clone(), Bytes::new())
            .await
            .expect_err("member search should require message auth");
        assert!(matches!(
            search_err,
            ApiError::Unauthorized("missing or invalid message auth token")
        ));

        let merge_err = merge_ticket(State(state.clone()), empty_headers.clone(), Bytes::new())
            .await
            .expect_err("merge ticket should require message auth");
        assert!(matches!(
            merge_err,
            ApiError::Unauthorized("missing or invalid message auth token")
        ));

        let revoked_err = barrier_resolve_revoked_leaves(
            State(state.clone()),
            empty_headers.clone(),
            Bytes::new(),
        )
        .await
        .expect_err("revoked leaves should require message auth");
        assert!(matches!(
            revoked_err,
            ApiError::Unauthorized("missing or invalid message auth token")
        ));

        let joins_err =
            barrier_resolve_joins_since(State(state.clone()), empty_headers.clone(), Bytes::new())
                .await
                .expect_err("joins-since should require message auth");
        assert!(matches!(
            joins_err,
            ApiError::Unauthorized("missing or invalid message auth token")
        ));

        let tree_err =
            barrier_fetch_public_tree(State(state.clone()), empty_headers.clone(), Bytes::new())
                .await
                .expect_err("public tree should require message auth");
        assert!(matches!(
            tree_err,
            ApiError::Unauthorized("missing or invalid message auth token")
        ));

        let bundle_err = get_bundle(State(state.clone()), empty_headers.clone(), Bytes::new())
            .await
            .expect_err("bundle fetch should require message auth");
        assert!(matches!(
            bundle_err,
            ApiError::Unauthorized("missing or invalid message auth token")
        ));

        let window_err = get_window(State(state.clone()), empty_headers.clone(), Bytes::new())
            .await
            .expect_err("window snapshot should require message auth");
        assert!(matches!(
            window_err,
            ApiError::Unauthorized("missing or invalid message auth token")
        ));

        let telemetry_err =
            get_telemetry(State(state.clone()), empty_headers.clone(), Bytes::new())
                .await
                .expect_err("telemetry should require message auth");
        assert!(matches!(
            telemetry_err,
            ApiError::Unauthorized("missing or invalid message auth token")
        ));

        let pivot_err = refresh_pivot(State(state), empty_headers, Bytes::new())
            .await
            .expect_err("pivot refresh should require message auth");
        assert!(matches!(
            pivot_err,
            ApiError::Unauthorized("missing or invalid message auth token")
        ));
    }

    #[cfg(any(debug_assertions, feature = "debug-api"))]
    #[tokio::test]
    async fn debug_window_seed_requires_window_admin_auth() {
        ensure_test_admin_tokens();
        let state = empty_test_api_state();
        let err = seed_window_head(State(state), HeaderMap::new(), Bytes::new())
            .await
            .expect_err("debug window seed should require admin auth");
        assert!(matches!(
            err,
            ApiError::Unauthorized("missing or invalid admin token")
        ));
    }

    #[tokio::test]
    async fn api_error_rate_limit_and_unauthorized_map_to_expected_http_responses() {
        let rate_limited = ApiError::RateLimited.into_response();
        assert_eq!(rate_limited.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = to_bytes(rate_limited.into_body(), usize::MAX)
            .await
            .expect("rate limited body bytes");
        let json: Value = serde_json::from_slice(&body).expect("rate limited json");
        assert_eq!(json["message"], "rate limited");

        let unauthorized = ApiError::Unauthorized("missing token").into_response();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(unauthorized.into_body(), usize::MAX)
            .await
            .expect("unauthorized body bytes");
        let json: Value = serde_json::from_slice(&body).expect("unauthorized json");
        assert_eq!(json["message"], "missing token");
    }

    #[tokio::test]
    async fn api_error_helpers_cover_decode_notfound_and_context_payload() {
        let decode_err = GetBundleRequest::decode(Bytes::from_static(b"\xFF"))
            .expect_err("invalid protobuf should yield decode error");
        let decode = ApiError::Decode(decode_err).into_response();
        assert_eq!(decode.status(), StatusCode::BAD_REQUEST);

        let not_found = ApiError::NotFound.into_response();
        assert_eq!(not_found.status(), StatusCode::NOT_FOUND);

        let contextual = ApiError::server_message_with_context(
            "batch failed",
            Some("batch_step_failed"),
            Some(4),
        )
        .into_response();
        assert_eq!(contextual.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(contextual.into_body(), usize::MAX)
            .await
            .expect("contextual body bytes");
        let json: Value = serde_json::from_slice(&body).expect("contextual error json");
        assert_eq!(json["message"], "batch failed");
        assert_eq!(json["error"], "batch_step_failed");
        assert_eq!(json["failed_index"], 4);
    }

    #[test]
    fn parse_ws_max_lag_uses_default_on_invalid_input() {
        assert_eq!(parse_ws_max_lag(None), WS_MAX_LAG_DEFAULT);
        assert_eq!(parse_ws_max_lag(Some("0")), WS_MAX_LAG_DEFAULT);
        assert_eq!(parse_ws_max_lag(Some("not-a-number")), WS_MAX_LAG_DEFAULT);
        assert_eq!(parse_ws_max_lag(Some("512")), 512);
    }

    #[test]
    fn should_disconnect_for_lag_respects_threshold() {
        assert!(!should_disconnect_for_lag(10, 10));
        assert!(!should_disconnect_for_lag(9, 10));
        assert!(should_disconnect_for_lag(11, 10));
    }

    #[test]
    fn parse_bool_env_accepts_truthy_values() {
        assert!(parse_bool_env(Some("1".to_string())));
        assert!(parse_bool_env(Some("true".to_string())));
        assert!(parse_bool_env(Some("YES".to_string())));
        assert!(!parse_bool_env(Some("0".to_string())));
        assert!(!parse_bool_env(Some("false".to_string())));
        assert!(!parse_bool_env(None));
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
        assert!(result.is_ok());
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
        assert!(result.is_err());
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
                .expect("new alias registration")
        );

        assert!(
            !state
                .register_alias(alias, leaf_a, key_a.clone())
                .await
                .expect("matching alias registration")
        );

        assert!(
            !state
                .register_alias(alias, leaf_b, key_a.clone())
                .await
                .expect("leaf update for matching key")
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
    async fn register_alias_normalizes_unicode_to_nfc() {
        let state = test_api_state();
        let alias_nfc = "Café";
        let alias_nfd = "Cafe\u{301}";
        assert_ne!(alias_nfc, alias_nfd);

        let leaf = [0x4A; 32];
        let pop_key = vec![0x9C; 8];
        assert!(
            state
                .register_alias(alias_nfd, leaf, pop_key.clone())
                .await
                .expect("first registration should succeed")
        );
        assert!(
            !state
                .register_alias(alias_nfc, leaf, pop_key)
                .await
                .expect("normalized alias should match existing binding")
        );

        let registry = state.alias_registry.read().await;
        assert_eq!(registry.len(), 1, "equivalent aliases must coalesce");
        assert!(
            registry.contains_key(alias_nfc),
            "stored alias should use NFC canonical form"
        );
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
        let server = Arc::new(RwLock::new(server_from_config(&CityGConfig::default())));
        let state = ApiState {
            server: server.clone(),
            server_lanes: Arc::new(vec![server]),
            messages: Arc::new(RwLock::new(AHashMap::new())),
            bundles: Arc::new(RwLock::new(AHashMap::new())),
            message_retention: Duration::from_secs(DEFAULT_FS_MESSAGE_RETENTION_SECS),
            fs_epoch_period_seconds: CityGConfig::default().protocol.fs_policy.h_seconds.max(1),
            freeze_counts: Arc::new(RwLock::new(BTreeMap::new())),
            alias_registry: Arc::new(RwLock::new(AHashMap::new())),
            member_metadata: Arc::new(RwLock::new(AHashMap::new())),
            weid_to_leaf: Arc::new(RwLock::new(AHashMap::new())),
            epoch_scopes: Arc::new(RwLock::new(AHashMap::new())),
            notification_tx: broadcast::channel(4).0,
            alias_rate_limiter: AliasRateLimiter::new(100, Duration::from_secs(60)),
            message_prune_due_ms: Arc::new(AtomicU64::new(0)),
            merge_ticket_cache: Arc::new(RwLock::new(AHashMap::new())),
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
        assert_eq!(binding.leaf_id, assigned_leaf);
        assert_eq!(
            binding.pop_public_key, pop_public_key,
            "alias binding must retain the original pop key"
        );
    }

    #[tokio::test]
    async fn join_ticket_failure_does_not_persist_alias_binding() {
        let cfg = CityGConfig::default();
        let server = Arc::new(RwLock::new(server_from_config(&cfg)));
        let state = ApiState {
            server: server.clone(),
            server_lanes: Arc::new(vec![server]),
            messages: Arc::new(RwLock::new(AHashMap::new())),
            bundles: Arc::new(RwLock::new(AHashMap::new())),
            message_retention: Duration::from_secs(DEFAULT_FS_MESSAGE_RETENTION_SECS),
            fs_epoch_period_seconds: cfg.protocol.fs_policy.h_seconds.max(1),
            freeze_counts: Arc::new(RwLock::new(BTreeMap::new())),
            alias_registry: Arc::new(RwLock::new(AHashMap::new())),
            member_metadata: Arc::new(RwLock::new(AHashMap::new())),
            weid_to_leaf: Arc::new(RwLock::new(AHashMap::new())),
            epoch_scopes: Arc::new(RwLock::new(AHashMap::new())),
            notification_tx: broadcast::channel(4).0,
            alias_rate_limiter: AliasRateLimiter::new(100, Duration::from_secs(60)),
            message_prune_due_ms: Arc::new(AtomicU64::new(0)),
            merge_ticket_cache: Arc::new(RwLock::new(AHashMap::new())),
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
        assert!(matches!(
            acceptance,
            ApiError::InvalidRequest("invalid bundle components")
        ));

        let acceptance_other = map_accept_error(
            &state,
            ClientError::Acceptance(AcceptanceError::Msphf(MsphfError::serialization(
                "broken proof",
            ))),
            Some("batch_step"),
            Some(5),
        )
        .await;
        assert!(matches!(
            acceptance_other,
            ApiError::Server {
                error_label: Some("batch_step"),
                failed_index: Some(5),
                ..
            }
        ));

        let io_error = map_accept_error(
            &state,
            ClientError::Io(std::io::Error::other("disk error")),
            Some("batch_step"),
            Some(6),
        )
        .await;
        assert!(matches!(
            io_error,
            ApiError::Server {
                error_label: Some("batch_step"),
                failed_index: Some(6),
                ..
            }
        ));
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
            room_admin_headers(),
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
            room_admin_headers(),
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
            room_admin_headers(),
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
            room_admin_headers(),
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
    async fn bootstrap_room_maps_duplicate_group_to_invalid_request() {
        let state = test_api_state();
        let gid = [0x77u8; 32];
        let kbroad_public = vec![0x44; ml_kem_public_key_bytes()];
        let encode = |request: BootstrapRoomRequest| -> Bytes {
            let mut body = Vec::new();
            request.encode(&mut body).expect("encode bootstrap request");
            Bytes::from(body)
        };

        bootstrap_room(
            State(state.clone()),
            room_admin_headers(),
            encode(BootstrapRoomRequest {
                room_id: hex::encode(gid),
                kbroad_public: kbroad_public.clone(),
            }),
        )
        .await
        .expect("initial bootstrap should succeed");

        let err = bootstrap_room(
            State(state),
            room_admin_headers(),
            encode(BootstrapRoomRequest {
                room_id: hex::encode(gid),
                kbroad_public,
            }),
        )
        .await
        .expect_err("duplicate bootstrap should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("kbroad key already registered")
        ));
    }

    #[tokio::test]
    async fn rotate_room_kbroad_validates_requests_and_updates_generation() {
        let state = test_api_state();
        let headers = room_admin_headers();
        let encode = |request: RotateRoomKbroadRequest| -> Bytes {
            let mut body = Vec::new();
            request.encode(&mut body).expect("encode rotate request");
            Bytes::from(body)
        };

        let err = rotate_room_kbroad(
            State(state.clone()),
            headers.clone(),
            encode(RotateRoomKbroadRequest {
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

        let err = rotate_room_kbroad(
            State(state.clone()),
            headers.clone(),
            encode(RotateRoomKbroadRequest {
                room_id: hex::encode(DEMO_GID),
                kbroad_public: vec![0x11; ml_kem_public_key_bytes() - 1],
            }),
        )
        .await
        .expect_err("invalid key length must fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("kbroad_public has unexpected length")
        ));

        let mut rotated = cityg_client::demo::kbroad_public().to_vec();
        rotated[0] ^= 0x3C;
        let response = rotate_room_kbroad(
            State(state.clone()),
            headers.clone(),
            encode(RotateRoomKbroadRequest {
                room_id: hex::encode(DEMO_GID),
                kbroad_public: rotated.clone(),
            }),
        )
        .await
        .expect("rotation should succeed");
        let decoded: RotateRoomKbroadResponse = decode_proto_response(response).await;
        assert_eq!(decoded.status, "rotated");
        assert_eq!(decoded.kbroad_generation, 1);

        let response = join_ticket(
            State(state),
            encode_proto_request(&JoinTicketRequest {
                room_id: hex::encode(DEMO_GID),
                alias: "post-rotate".to_string(),
                identity_binding: None,
            }),
        )
        .await
        .expect("join ticket should include updated generation");
        let decoded: JoinTicketResponse = decode_proto_response(response).await;
        assert_eq!(decoded.kbroad_generation, 1);
        assert_eq!(decoded.kbroad_public, rotated);
        assert_eq!(decoded.kem_tree_hash_after.len(), 32);
        assert!(decoded.n_max.is_power_of_two());
        assert!(decoded.max_barrier_update_bytes > 0);
    }

    #[tokio::test]
    async fn rotate_room_kbroad_maps_server_invalid_input_paths() {
        let state = test_api_state();
        let headers = room_admin_headers();
        let encode = |request: RotateRoomKbroadRequest| -> Bytes {
            let mut body = Vec::new();
            request.encode(&mut body).expect("encode rotate request");
            Bytes::from(body)
        };

        let missing_gid = [0xEEu8; 32];
        let missing_err = rotate_room_kbroad(
            State(state.clone()),
            headers.clone(),
            encode(RotateRoomKbroadRequest {
                room_id: hex::encode(missing_gid),
                kbroad_public: vec![0x22; ml_kem_public_key_bytes()],
            }),
        )
        .await
        .expect_err("missing room should fail");
        assert!(matches!(
            missing_err,
            ApiError::InvalidRequest("kbroad key missing")
        ));

        let unchanged_err = rotate_room_kbroad(
            State(state),
            headers,
            encode(RotateRoomKbroadRequest {
                room_id: hex::encode(DEMO_GID),
                kbroad_public: cityg_client::demo::kbroad_public().to_vec(),
            }),
        )
        .await
        .expect_err("unchanged key should fail");
        assert!(matches!(
            unchanged_err,
            ApiError::InvalidRequest("kbroad key unchanged")
        ));
    }

    #[tokio::test]
    async fn search_members_filters_by_alias_or_leaf_hex_and_validates_inputs() {
        let state = test_api_state();
        let headers = message_auth_headers();
        let alice = demo_bundle("alice").expect("alice demo bundle");
        let bob = demo_bundle("bob").expect("bob demo bundle");

        let (root, tagged_leaf, second_leaf) = {
            let mut guard = state.server.write().await;
            guard.accept_epoch(&alice).expect("accept alice");
            guard.accept_epoch(&bob).expect("accept bob");
            let root = guard
                .latest_parent_root(DEMO_GID.as_ref())
                .expect("latest root");
            let members = guard
                .members_for_root(DEMO_GID.as_ref(), &root)
                .expect("members for root");
            (root, members[0], members[1])
        };

        state
            .register_alias("special-user", tagged_leaf, vec![0xAB; 8])
            .await
            .expect("register alias for search");
        state
            .register_alias("special-two", second_leaf, vec![0xBC; 8])
            .await
            .expect("register second alias for search");

        let mut body = Vec::new();
        pb::SearchMembersRequest {
            gid: DEMO_GID.to_vec(),
            query: "special-user".to_string(),
            parent_root: Vec::new(),
            offset: Some(0),
            limit: Some(10),
        }
        .encode(&mut body)
        .expect("encode alias query request");
        let response = search_members(State(state.clone()), headers.clone(), Bytes::from(body))
            .await
            .expect("alias query should succeed");
        let decoded: pb::SearchMembersResponse = decode_proto_response(response).await;
        assert_eq!(decoded.total_count, 1);
        assert_eq!(decoded.members.len(), 1);
        assert_eq!(decoded.members[0].alias.as_deref(), Some("special-user"));

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
        let response = search_members(State(state.clone()), headers.clone(), Bytes::from(body))
            .await
            .expect("leaf query should succeed");
        let decoded: pb::SearchMembersResponse = decode_proto_response(response).await;
        assert!(decoded.total_count >= 1);

        let mut body = Vec::new();
        pb::SearchMembersRequest {
            gid: DEMO_GID.to_vec(),
            query: "special".to_string(),
            parent_root: root.to_vec(),
            offset: Some(0),
            limit: Some(1),
        }
        .encode(&mut body)
        .expect("encode paged alias query request");
        let response = search_members(State(state.clone()), headers.clone(), Bytes::from(body))
            .await
            .expect("paged alias query should succeed");
        let decoded: pb::SearchMembersResponse = decode_proto_response(response).await;
        assert_eq!(decoded.total_count, 2);
        assert_eq!(decoded.next_offset, 1);

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
        let err = search_members(State(state.clone()), headers.clone(), Bytes::from(body))
            .await
            .expect_err("empty query should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("query must be provided")
        ));

        let mut body = Vec::new();
        pb::SearchMembersRequest {
            gid: Vec::new(),
            query: "special".to_string(),
            parent_root: Vec::new(),
            offset: Some(0),
            limit: Some(10),
        }
        .encode(&mut body)
        .expect("encode missing gid request");
        let err = search_members(State(state.clone()), headers.clone(), Bytes::from(body))
            .await
            .expect_err("missing gid should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("gid must be provided")
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
        let err = search_members(State(state), headers, Bytes::from(body))
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
        let headers = message_auth_headers();
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
            intent: MergeTicketIntent::Leave as i32,
        }
        .encode(&mut body)
        .expect("encode missing room id request");
        let err = merge_ticket(State(state.clone()), headers.clone(), Bytes::from(body))
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
            intent: MergeTicketIntent::Leave as i32,
        }
        .encode(&mut body)
        .expect("encode bad leaf request");
        let err = merge_ticket(State(state.clone()), headers.clone(), Bytes::from(body))
            .await
            .expect_err("invalid leaf length should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("leaf_id must be 32 bytes")
        ));

        let mut body = Vec::new();
        MergeTicketRequest {
            room_id: "not-hex-room-id".to_string(),
            leaf_id: leaf_id.to_vec(),
            intent: MergeTicketIntent::Leave as i32,
        }
        .encode(&mut body)
        .expect("encode invalid room-id merge request");
        let err = merge_ticket(State(state.clone()), headers.clone(), Bytes::from(body))
            .await
            .expect_err("invalid room id format should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("room_id must be 64 hex characters")
        ));

        let mut body = Vec::new();
        MergeTicketRequest {
            room_id: hex::encode([0xEE; 32]),
            leaf_id: leaf_id.to_vec(),
            intent: MergeTicketIntent::Leave as i32,
        }
        .encode(&mut body)
        .expect("encode unknown room merge request");
        let err = merge_ticket(State(state.clone()), headers.clone(), Bytes::from(body))
            .await
            .expect_err("unknown room should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest(_) | ApiError::NotFound | ApiError::Server { .. }
        ));

        let mut body = Vec::new();
        MergeTicketRequest {
            room_id: hex::encode(DEMO_GID),
            leaf_id: leaf_id.to_vec(),
            intent: i32::MAX,
        }
        .encode(&mut body)
        .expect("encode invalid intent request");
        let err = merge_ticket(State(state.clone()), headers.clone(), Bytes::from(body))
            .await
            .expect_err("invalid intent should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("merge ticket intent is invalid")
        ));

        let mut body = Vec::new();
        MergeTicketRequest {
            room_id: hex::encode(DEMO_GID),
            leaf_id: leaf_id.to_vec(),
            intent: MergeTicketIntent::Leave as i32,
        }
        .encode(&mut body)
        .expect("encode valid merge request");
        let response = merge_ticket(State(state), headers.clone(), Bytes::from(body))
            .await
            .expect("valid merge ticket request");
        let decoded: MergeTicketResponse = decode_proto_response(response).await;
        assert_eq!(decoded.we_epoch_id.len(), 32);
        assert_eq!(decoded.parent_root.len(), 32);
        assert!(!decoded.pivot_parity_cbor.is_empty(),);
        assert_eq!(decoded.join_delta_root, vec![0u8; 32]);
        let expected_revoked_root = canonical_set_root(&[leaf_id]).expect("canonical revoked root");
        assert_eq!(decoded.revoked_since_root, expected_revoked_root.to_vec());
        assert_eq!(decoded.revoked_root, expected_revoked_root.to_vec());
        assert_eq!(decoded.kem_tree_hash_after.len(), 32);
        assert!(decoded.n_max.is_power_of_two());
        assert!(decoded.max_barrier_update_bytes > 0);
        let expected_cover_leaf_index = u64::from(u32::from_be_bytes(
            leaf_id[28..32].try_into().expect("leaf suffix"),
        )) % decoded.n_max.max(1);
        assert_eq!(decoded.cover_leaf_index, expected_cover_leaf_index);

        let srx = SrxInputsOwned::from_cbor(&decoded.srx_cbor).expect("decode merge srx payload");
        assert!(srx.join_leaf_ids.is_empty());
        assert_eq!(srx.since_leaf_ids, vec![leaf_id]);

        let state = test_api_state();
        {
            let mut guard = state.server.write().await;
            guard.accept_epoch(&alice).expect("accept alice");
        }
        let mut refresh_body = Vec::new();
        MergeTicketRequest {
            room_id: hex::encode(DEMO_GID),
            leaf_id: leaf_id.to_vec(),
            intent: MergeTicketIntent::Refresh as i32,
        }
        .encode(&mut refresh_body)
        .expect("encode refresh merge request");
        let refresh_response = merge_ticket(State(state), headers, Bytes::from(refresh_body))
            .await
            .expect("refresh merge ticket request");
        let refresh_decoded: MergeTicketResponse = decode_proto_response(refresh_response).await;
        assert_eq!(refresh_decoded.srx_cbor, Vec::<u8>::new());
        assert_eq!(refresh_decoded.join_delta_root, vec![0u8; 32]);
        assert_eq!(
            refresh_decoded.revoked_since_root,
            refresh_decoded.revoked_root
        );
    }

    #[tokio::test]
    async fn merge_ticket_coalesces_duplicate_leave_requests() {
        let state = test_api_state();
        let headers = message_auth_headers();
        let alice = demo_bundle("alice").expect("alice demo bundle");
        let leaf_id = {
            let lane = state.server_for_gid(&DEMO_GID);
            let mut guard = lane.write().await;
            guard.accept_epoch(&alice).expect("accept alice");
            let root = guard
                .latest_parent_root(DEMO_GID.as_ref())
                .expect("latest root");
            guard
                .members_for_root(DEMO_GID.as_ref(), &root)
                .expect("members for root")[0]
        };

        let request = MergeTicketRequest {
            room_id: hex::encode(DEMO_GID),
            leaf_id: leaf_id.to_vec(),
            intent: MergeTicketIntent::Leave as i32,
        };
        let response_a = merge_ticket(
            State(state.clone()),
            headers.clone(),
            encode_proto_request(&request),
        )
        .await
        .expect("first leave merge ticket");
        let response_b = merge_ticket(
            State(state.clone()),
            headers,
            encode_proto_request(&request),
        )
        .await
        .expect("second leave merge ticket should be coalesced");
        let bytes_a = to_bytes(response_a.into_body(), usize::MAX)
            .await
            .expect("first response bytes");
        let bytes_b = to_bytes(response_b.into_body(), usize::MAX)
            .await
            .expect("second response bytes");
        assert_eq!(
            bytes_a, bytes_b,
            "duplicate leave requests should reuse cached merge ticket response"
        );
        assert_eq!(state.merge_ticket_cache.read().await.len(), 1);
    }

    #[tokio::test]
    async fn high_contention_join_ticket_requests_across_groups_converge() {
        ensure_test_admin_tokens();
        let state = test_api_state_with_lanes(4);
        let mut room_ids = vec![hex::encode(DEMO_GID)];
        for seed in [0x11u8, 0x22u8, 0x33u8] {
            let gid = [seed; 32];
            let request = BootstrapRoomRequest {
                room_id: hex::encode(gid),
                kbroad_public: vec![seed; ml_kem_public_key_bytes()],
            };
            bootstrap_room(
                State(state.clone()),
                room_admin_headers(),
                encode_proto_request(&request),
            )
            .await
            .expect("bootstrap extra room for contention test");
            room_ids.push(hex::encode(gid));
        }

        let task_count = 48usize;
        let iterations = 6usize;
        let mut tasks = Vec::new();
        for task_idx in 0..task_count {
            let state = state.clone();
            let room_id = room_ids[task_idx % room_ids.len()].clone();
            tasks.push(tokio::spawn(async move {
                for iter in 0..iterations {
                    let request = JoinTicketRequest {
                        room_id: room_id.clone(),
                        alias: format!("stress-{task_idx}-{iter}"),
                        identity_binding: None,
                    };
                    let response =
                        join_ticket(State(state.clone()), encode_proto_request(&request))
                            .await
                            .map_err(|err| format!("join_ticket failed: {err}"))?;
                    let decoded: JoinTicketResponse = decode_proto_response(response).await;
                    if decoded.profile_version != API_PROFILE_VERSION {
                        return Err(format!(
                            "unexpected profile version: {}",
                            decoded.profile_version
                        ));
                    }
                }
                Ok::<(), String>(())
            }));
        }

        for task in tasks {
            let result = task.await.expect("join contention task must complete");
            assert!(
                result.is_ok(),
                "join contention task failed: {}",
                result.err().unwrap_or_default()
            );
        }
    }

    #[tokio::test]
    async fn high_contention_merge_refresh_and_leave_requests_converge() {
        let state = test_api_state_with_lanes(4);
        let headers = message_auth_headers();
        let alice = demo_bundle("alice").expect("alice demo bundle");
        let leaf_id = {
            let lane = state.server_for_gid(&DEMO_GID);
            let mut guard = lane.write().await;
            guard.accept_epoch(&alice).expect("accept alice");
            let root = guard
                .latest_parent_root(DEMO_GID.as_ref())
                .expect("latest root");
            guard
                .members_for_root(DEMO_GID.as_ref(), &root)
                .expect("members for root")[0]
        };

        let task_count = 40usize;
        let mut tasks = Vec::new();
        for idx in 0..task_count {
            let state = state.clone();
            let headers = headers.clone();
            let room_id = hex::encode(DEMO_GID);
            let leaf = leaf_id.to_vec();
            tasks.push(tokio::spawn(async move {
                let intent = if idx % 2 == 0 {
                    MergeTicketIntent::Leave as i32
                } else {
                    MergeTicketIntent::Refresh as i32
                };
                let request = MergeTicketRequest {
                    room_id,
                    leaf_id: leaf,
                    intent,
                };
                let response = merge_ticket(State(state), headers, encode_proto_request(&request))
                    .await
                    .map_err(|err| format!("merge_ticket failed: {err}"))?;
                let decoded: MergeTicketResponse = decode_proto_response(response).await;
                if decoded.profile_version != API_PROFILE_VERSION {
                    return Err(format!(
                        "unexpected merge profile version: {}",
                        decoded.profile_version
                    ));
                }
                Ok::<MergeTicketResponse, String>(decoded)
            }));
        }

        let mut leave_barrier_versions = Vec::new();
        for task in tasks {
            let result = task.await.expect("merge contention task must complete");
            let decoded =
                result.unwrap_or_else(|err| panic!("merge contention task failed: {err}"));
            if decoded.srx_cbor.is_empty() {
                // refresh intent
                continue;
            }
            leave_barrier_versions.push(decoded.barrier_version);
        }
        assert!(
            !leave_barrier_versions.is_empty(),
            "leave intents should be represented in contention run"
        );
        let first = leave_barrier_versions[0];
        assert!(
            leave_barrier_versions
                .iter()
                .all(|version| *version == first),
            "coalesced leave tickets should converge to one barrier version"
        );
    }

    #[tokio::test]
    async fn barrier_resolve_joins_since_returns_join_records() {
        let state = test_api_state();
        let headers = message_auth_headers();
        let alice = demo_bundle("alice").expect("alice demo bundle");

        let mut bad_body = Vec::new();
        BarrierResolveJoinsSinceRequest {
            room_id: String::new(),
            prev_barrier_version: 0,
        }
        .encode(&mut bad_body)
        .expect("encode bad joins-since request");
        let err = barrier_resolve_joins_since(
            State(state.clone()),
            headers.clone(),
            Bytes::from(bad_body),
        )
        .await
        .expect_err("joins-since missing room id should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("room_id must be provided")
        ));

        {
            let mut guard = state.server.write().await;
            guard.accept_epoch(&alice).expect("accept alice");
        }

        let mut body = Vec::new();
        BarrierResolveJoinsSinceRequest {
            room_id: hex::encode(DEMO_GID),
            prev_barrier_version: 0,
        }
        .encode(&mut body)
        .expect("encode joins-since request");
        let response = barrier_resolve_joins_since(State(state), headers, Bytes::from(body))
            .await
            .expect("joins-since request should succeed");
        let decoded: BarrierResolveJoinsSinceResponse = decode_proto_response(response).await;
        assert!(
            !decoded.records.is_empty(),
            "joins-since should return records"
        );
        let first = &decoded.records[0];
        assert!(first.leaf_index > 0);
        assert!(!first.device_pk.is_empty());
        assert!(
            first.ek_leaf.is_empty() || first.ek_leaf.len() == ml_kem_public_key_bytes(),
            "ek_leaf should be absent or ML-KEM-768 size"
        );
    }

    #[tokio::test]
    async fn barrier_tree_and_revoked_leaves_endpoints_validate_inputs() {
        let state = test_api_state();
        let headers = message_auth_headers();
        let alice = demo_bundle("alice").expect("alice demo bundle");

        let (revocation_roots_hash, kem_tree_hash_after, n_max) = {
            let mut guard = state.server.write().await;
            guard.accept_epoch(&alice).expect("accept alice");
            (
                guard
                    .barrier_roots_hash(DEMO_GID.as_ref())
                    .expect("barrier roots hash"),
                guard
                    .barrier_kem_tree_hash_after(DEMO_GID.as_ref())
                    .expect("barrier tree hash"),
                guard
                    .barrier_n_max(DEMO_GID.as_ref())
                    .expect("barrier n_max"),
            )
        };

        let mut bad_revoked_body = Vec::new();
        BarrierResolveRevokedLeavesRequest {
            room_id: String::new(),
            revocation_roots_hash: revocation_roots_hash.to_vec(),
        }
        .encode(&mut bad_revoked_body)
        .expect("encode missing room revoked request");
        let err = barrier_resolve_revoked_leaves(
            State(state.clone()),
            headers.clone(),
            Bytes::from(bad_revoked_body),
        )
        .await
        .expect_err("missing room_id should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("room_id must be provided")
        ));

        let mut bad_revoked_room = Vec::new();
        BarrierResolveRevokedLeavesRequest {
            room_id: "bad-room-id".to_string(),
            revocation_roots_hash: revocation_roots_hash.to_vec(),
        }
        .encode(&mut bad_revoked_room)
        .expect("encode invalid room revoked request");
        let err = barrier_resolve_revoked_leaves(
            State(state.clone()),
            headers.clone(),
            Bytes::from(bad_revoked_room),
        )
        .await
        .expect_err("invalid room_id should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("room_id must be 64 hex characters")
        ));

        let mut bad_revoked_hash = Vec::new();
        BarrierResolveRevokedLeavesRequest {
            room_id: hex::encode(DEMO_GID),
            revocation_roots_hash: vec![0xAB; 31],
        }
        .encode(&mut bad_revoked_hash)
        .expect("encode short hash revoked request");
        let err = barrier_resolve_revoked_leaves(
            State(state.clone()),
            headers.clone(),
            Bytes::from(bad_revoked_hash),
        )
        .await
        .expect_err("short revocation_roots_hash should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("revocation_roots_hash must be 32 bytes")
        ));

        let mut revoked_body = Vec::new();
        BarrierResolveRevokedLeavesRequest {
            room_id: hex::encode(DEMO_GID),
            revocation_roots_hash: revocation_roots_hash.to_vec(),
        }
        .encode(&mut revoked_body)
        .expect("encode revoked leaves request");
        let revoked_response = barrier_resolve_revoked_leaves(
            State(state.clone()),
            headers.clone(),
            Bytes::from(revoked_body),
        )
        .await
        .expect("revoked leaves request should succeed");
        let revoked_decoded: BarrierResolveRevokedLeavesResponse =
            decode_proto_response(revoked_response).await;
        assert!(revoked_decoded.leaf_indices.is_empty());

        let mut bad_tree_body = Vec::new();
        BarrierFetchPublicTreeRequest {
            room_id: String::new(),
            kem_tree_hash_after: kem_tree_hash_after.to_vec(),
        }
        .encode(&mut bad_tree_body)
        .expect("encode missing room tree request");
        let err = barrier_fetch_public_tree(
            State(state.clone()),
            headers.clone(),
            Bytes::from(bad_tree_body),
        )
        .await
        .expect_err("missing room tree request should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("room_id must be provided")
        ));

        let mut bad_tree_hash = Vec::new();
        BarrierFetchPublicTreeRequest {
            room_id: hex::encode(DEMO_GID),
            kem_tree_hash_after: vec![0xCD; 31],
        }
        .encode(&mut bad_tree_hash)
        .expect("encode short hash tree request");
        let err = barrier_fetch_public_tree(
            State(state.clone()),
            headers.clone(),
            Bytes::from(bad_tree_hash),
        )
        .await
        .expect_err("short tree hash should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("kem_tree_hash_after must be 32 bytes")
        ));

        let mut tree_body = Vec::new();
        BarrierFetchPublicTreeRequest {
            room_id: hex::encode(DEMO_GID),
            kem_tree_hash_after: kem_tree_hash_after.to_vec(),
        }
        .encode(&mut tree_body)
        .expect("encode barrier tree request");
        let tree_response = barrier_fetch_public_tree(
            State(state.clone()),
            headers.clone(),
            Bytes::from(tree_body),
        )
        .await
        .expect("barrier tree request should succeed");
        let tree_decoded: BarrierFetchPublicTreeResponse =
            decode_proto_response(tree_response).await;
        assert_eq!(tree_decoded.n_max, n_max);
        assert_eq!(
            tree_decoded.kem_tree_hash_after,
            kem_tree_hash_after.to_vec()
        );
        assert_eq!(
            tree_decoded.pk_entries.len() as u64,
            n_max.saturating_mul(2).saturating_sub(1)
        );

        let mut bad_tree_body = Vec::new();
        BarrierFetchPublicTreeRequest {
            room_id: hex::encode(DEMO_GID),
            kem_tree_hash_after: vec![0xFF; 32],
        }
        .encode(&mut bad_tree_body)
        .expect("encode bad barrier tree request");
        let err = barrier_fetch_public_tree(State(state), headers, Bytes::from(bad_tree_body))
            .await
            .expect_err("mismatched tree hash must fail");
        assert!(matches!(
            err,
            ApiError::Server {
                freeze: Some(freeze),
                ..
            } if freeze.code == msphf_orchestrator::FREEZE_BARRIER_TREE_SNAPSHOT_AUTH_FAILURE.code
                && freeze.reason
                    == msphf_orchestrator::FREEZE_BARRIER_TREE_SNAPSHOT_AUTH_FAILURE.reason
        ));
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
            _ => panic!("expected frozen server error"),
        }

        let converted: ApiError =
            ClientError::Acceptance(AcceptanceError::Msphf(MsphfError::invalid_input("bad")))
                .into();
        assert!(matches!(converted, ApiError::Server { .. }));

        let converted: ApiError = ClientError::Io(std::io::Error::other("disk")).into();
        match converted {
            ApiError::Server { message, .. } => assert!(message.contains("io error")),
            _ => panic!("expected server error"),
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
        let headers = message_auth_headers();
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
            headers.clone(),
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
            headers.clone(),
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
            headers.clone(),
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
            headers,
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
        let bundle = demo_bundle("alice").expect("alice bundle");
        apply_bundle(&state, &bundle)
            .await
            .expect("accept bundle should seed epoch scope");
        let mut weid = [0u8; 32];
        weid.copy_from_slice(&bundle.we_epoch_id);
        let leaf = cityg_client::demo::demo_member_leaf("alice");
        let headers = message_auth_headers();

        let err = send_message(
            State(state.clone()),
            HeaderMap::new(),
            encode_proto_request(&SendMessageRequest {
                we_epoch_id: weid.to_vec(),
                ciphertext: vec![0xAA],
                sender: leaf.to_vec(),
            }),
        )
        .await
        .expect_err("missing message auth header should fail");
        assert!(matches!(
            err,
            ApiError::Unauthorized("missing or invalid message auth token")
        ));

        let err = send_message(
            State(state.clone()),
            headers.clone(),
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
            headers.clone(),
            encode_proto_request(&SendMessageRequest {
                we_epoch_id: weid.to_vec(),
                ciphertext: vec![0xAA],
                sender: vec![0x01; 31],
            }),
        )
        .await
        .expect_err("invalid sender length should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("sender must be 32 bytes")
        ));

        let err = send_message(
            State(state.clone()),
            headers.clone(),
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
            headers.clone(),
            encode_proto_request(&SendMessageRequest {
                we_epoch_id: weid.to_vec(),
                ciphertext: b"hello".to_vec(),
                sender: leaf.to_vec(),
            }),
        )
        .await
        .expect("valid send should succeed");
        let decoded: SendMessageResponse = decode_proto_response(response).await;
        assert_eq!(decoded.status, "stored");

        let metadata = state.member_metadata.read().await;
        let member = metadata.get(&leaf).expect("member metadata");
        assert!(member.last_seen_timestamp_ms >= member.join_timestamp_ms);
        drop(metadata);

        let err = fetch_messages(
            State(state.clone()),
            headers.clone(),
            encode_proto_request(&FetchMessagesRequest {
                we_epoch_id: vec![0x01; 31],
                leaf_id: leaf.to_vec(),
            }),
        )
        .await
        .expect_err("invalid fetch weid length should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("we_epoch_id must be 32 bytes")
        ));

        let err = fetch_messages(
            State(state.clone()),
            headers.clone(),
            encode_proto_request(&FetchMessagesRequest {
                we_epoch_id: weid.to_vec(),
                leaf_id: vec![0xAB; 31],
            }),
        )
        .await
        .expect_err("invalid fetch leaf length should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("leaf_id must be 32 bytes")
        ));

        let response = fetch_messages(
            State(state.clone()),
            headers,
            encode_proto_request(&FetchMessagesRequest {
                we_epoch_id: weid.to_vec(),
                leaf_id: leaf.to_vec(),
            }),
        )
        .await
        .expect("fetch should succeed");
        let decoded: FetchMessagesResponse = decode_proto_response(response).await;
        assert_eq!(decoded.messages.len(), 1);
        assert_eq!(decoded.messages[0].ciphertext, b"hello");
    }

    #[tokio::test]
    async fn membership_checks_reject_non_member_leaves() {
        let state = test_api_state();
        let bundle = demo_bundle("alice").expect("alice bundle");
        apply_bundle(&state, &bundle)
            .await
            .expect("accept bundle should seed membership scope");
        let mut weid = [0u8; 32];
        weid.copy_from_slice(&bundle.we_epoch_id);
        let outsider = [0xF9; 32];

        let err = ensure_leaf_member_for_epoch(&state, &weid, outsider)
            .await
            .expect_err("non-member epoch send should fail");
        assert!(matches!(
            err,
            ApiError::Unauthorized("leaf is not a member for epoch")
        ));

        let err = ensure_leaf_member_for_room(&state, &DEMO_GID, outsider)
            .await
            .expect_err("non-member room subscription should fail");
        assert!(matches!(
            err,
            ApiError::Unauthorized("leaf is not a member for room")
        ));
    }

    #[tokio::test]
    async fn get_bundle_refresh_pivot_and_health_handlers_cover_core_paths() {
        let state = test_api_state();
        let headers = message_auth_headers();

        let err = get_bundle(
            State(state.clone()),
            headers.clone(),
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
            headers.clone(),
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
            headers.clone(),
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
            headers.clone(),
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
            headers.clone(),
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

        let mut demo_bundle = demo_bundle("pivot-missing").expect("demo bundle");
        demo_bundle.header_map.insert(
            hdr::HDR_ROLLUP_PIVOT_WEID,
            ciborium::value::Value::Bytes([0xAB; 32].to_vec()),
        );
        let err = refresh_pivot(
            State(state.clone()),
            headers,
            encode_proto_request(&RefreshPivotRequest {
                bundle_cbor: demo_bundle.to_cbor().expect("bundle cbor"),
            }),
        )
        .await
        .expect_err("stale refresh should report conflict");
        assert!(
            matches!(err, ApiError::Conflict(message) if message == "invalid input: pivot parity missing for refresh")
        );
        assert_eq!(
            classify_refresh_pivot_conflict(
                "invalid input: refresh payload diverges from stored parity"
            ),
            Some("payload_diverges")
        );
        assert_eq!(
            classify_refresh_pivot_conflict("invalid input: pivot head missing"),
            Some("pivot_head_missing")
        );

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
    async fn configure_window_validates_and_applies_limits() {
        let state = test_api_state();
        let headers = window_admin_headers();

        let err = configure_window(
            State(state.clone()),
            headers.clone(),
            encode_proto_request(&ConfigureWindowRequest {
                h_max: Some(0),
                ttl_ms: None,
            }),
        )
        .await
        .expect_err("zero h_max should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("h_max must be at least 1")
        ));

        let err = configure_window(
            State(state.clone()),
            headers.clone(),
            encode_proto_request(&ConfigureWindowRequest {
                h_max: Some(2048),
                ttl_ms: None,
            }),
        )
        .await
        .expect_err("oversized h_max should fail");
        assert!(matches!(err, ApiError::InvalidRequest("h_max too large")));

        let err = configure_window(
            State(state.clone()),
            headers.clone(),
            encode_proto_request(&ConfigureWindowRequest {
                h_max: None,
                ttl_ms: Some(0),
            }),
        )
        .await
        .expect_err("zero ttl should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("ttl_ms must be positive")
        ));

        let response = configure_window(
            State(state),
            headers,
            encode_proto_request(&ConfigureWindowRequest {
                h_max: Some(9),
                ttl_ms: Some(4_321),
            }),
        )
        .await
        .expect("window update should succeed");
        let decoded: ConfigureWindowResponse = decode_proto_response(response).await;
        assert_eq!(decoded.h_max, 9);
        assert_eq!(decoded.ttl_ms, 4_321);
    }

    #[tokio::test]
    async fn window_and_telemetry_handlers_emit_snapshot_and_freeze_stats() {
        let state = test_api_state();
        let headers = message_auth_headers();
        let bundle = demo_bundle("alice").expect("alice bundle");
        apply_bundle(&state, &bundle)
            .await
            .expect("accept bundle should seed window state");
        state
            .record_freeze(FreezeError {
                code: 4242,
                reason: "unit_test_freeze",
            })
            .await;

        let window_response = get_window(
            State(state.clone()),
            headers.clone(),
            encode_proto_request(&GetWindowRequest {}),
        )
        .await
        .expect("window snapshot should succeed");
        let window: GetWindowResponse = decode_proto_response(window_response).await;
        assert!(!window.entries.is_empty());
        assert!(!window.entries[0].heads.is_empty());
        let first_head = &window.entries[0].heads[0];
        assert_eq!(first_head.we_epoch_id.len(), 32);
        assert_eq!(first_head.msphf_hp_commit.len(), 32);
        assert_eq!(first_head.seed_ctx_hash.len(), 32);
        assert_eq!(first_head.rho_commit.len(), 32);
        assert_eq!(first_head.seed_commit.len(), 32);
        assert_eq!(first_head.xk_hash.len(), 32);

        let telemetry_response = get_telemetry(
            State(state),
            headers,
            encode_proto_request(&GetTelemetryRequest {}),
        )
        .await
        .expect("telemetry snapshot should succeed");
        let telemetry: GetTelemetryResponse = decode_proto_response(telemetry_response).await;
        assert!(!telemetry.entries.is_empty());
        assert!(
            telemetry.freeze_stats.iter().any(|stat| stat.code == 4242
                && stat.reason == "unit_test_freeze"
                && stat.count == 1)
        );
    }

    #[tokio::test]
    async fn websocket_handler_streams_message_and_membership_notifications() {
        ensure_test_admin_tokens();
        let state = test_api_state();
        let bundle = demo_bundle("alice").expect("alice bundle");
        apply_bundle(&state, &bundle)
            .await
            .expect("accept bundle for websocket membership auth");
        let leaf = cityg_client::demo::demo_member_leaf("alice");
        let token = configured_message_auth_token().expect("message auth token configured");
        let app = Router::new()
            .route("/v1/ws", get(websocket_handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral listener");
        let addr = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let unauthorized_url = format!(
            "ws://{addr}/v1/ws?gid={}&leaf_id={}",
            hex::encode(DEMO_GID),
            hex::encode(leaf)
        );
        assert!(
            tokio_tungstenite::connect_async(unauthorized_url)
                .await
                .is_err()
        );

        let url = format!(
            "ws://{addr}/v1/ws?gid={}&leaf_id={}&token={}",
            hex::encode(DEMO_GID),
            hex::encode(leaf),
            token
        );
        let (mut socket, _) = tokio_tungstenite::connect_async(url)
            .await
            .expect("connect websocket");

        state.broadcast_message(MessageNotification {
            gid: DEMO_GID,
            we_epoch_id: [0xA5; 32],
            timestamp_ms: 101,
        });
        let first = tokio::time::timeout(std::time::Duration::from_secs(2), socket.next())
            .await
            .expect("wait for message notification")
            .expect("message notification frame")
            .expect("message notification payload");
        let first_text = first.into_text().expect("expected text notification frame");
        let first_json: Value =
            serde_json::from_str(&first_text).expect("decode message notification JSON");
        assert_eq!(first_json["type"], "message");
        assert_eq!(first_json["gid"], hex::encode(DEMO_GID));
        assert_eq!(first_json["timestamp_ms"], 101);

        state.broadcast_membership(DEMO_GID, [0xB6; 32], MembershipEventKind::Join, 202);
        let second = tokio::time::timeout(std::time::Duration::from_secs(2), socket.next())
            .await
            .expect("wait for membership notification")
            .expect("membership notification frame")
            .expect("membership notification payload");
        let second_text = second.into_text().expect("expected text membership frame");
        let second_json: Value =
            serde_json::from_str(&second_text).expect("decode membership notification JSON");
        assert_eq!(second_json["type"], "membership");
        assert_eq!(second_json["event"], "join");
        assert_eq!(second_json["timestamp_ms"], 202);

        state.broadcast_membership(DEMO_GID, [0xC7; 32], MembershipEventKind::Revoke, 303);
        let third = tokio::time::timeout(std::time::Duration::from_secs(2), socket.next())
            .await
            .expect("wait for revoke notification")
            .expect("revoke notification frame")
            .expect("revoke notification payload");
        let third_text = third.into_text().expect("expected text revoke frame");
        let third_json: Value =
            serde_json::from_str(&third_text).expect("decode revoke notification JSON");
        assert_eq!(third_json["type"], "membership");
        assert_eq!(third_json["event"], "revoke");
        assert_eq!(third_json["timestamp_ms"], 303);

        socket
            .send(tokio_tungstenite::tungstenite::Message::Ping(
                vec![1, 2, 3].into(),
            ))
            .await
            .expect("send ping");
        socket
            .send(tokio_tungstenite::tungstenite::Message::Close(None))
            .await
            .expect("send close");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), socket.next()).await;

        server.abort();
    }

    #[tokio::test]
    async fn websocket_handler_emits_lag_signals_for_slow_clients() {
        ensure_test_admin_tokens();
        let state = test_api_state();
        let bundle = demo_bundle("alice").expect("alice bundle");
        apply_bundle(&state, &bundle)
            .await
            .expect("accept bundle for websocket membership auth");
        let leaf = cityg_client::demo::demo_member_leaf("alice");
        let token = configured_message_auth_token().expect("message auth token configured");
        let app = Router::new()
            .route("/v1/ws", get(websocket_handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral listener");
        let addr = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let url = format!(
            "ws://{addr}/v1/ws?gid={}&leaf_id={}&token={}",
            hex::encode(DEMO_GID),
            hex::encode(leaf),
            token
        );
        let (mut socket, _) = tokio_tungstenite::connect_async(url)
            .await
            .expect("connect websocket");

        for idx in 0u64..400 {
            state.broadcast_message(MessageNotification {
                gid: DEMO_GID,
                we_epoch_id: [(idx % 251) as u8; 32],
                timestamp_ms: 10_000 + idx,
            });
        }

        let mut saw_lag_signal = false;
        for _ in 0..20 {
            let frame = tokio::time::timeout(std::time::Duration::from_secs(2), socket.next())
                .await
                .expect("wait for lag-related websocket frame")
                .expect("lag-related frame")
                .expect("lag-related payload");
            let text = frame.into_text().expect("lag-related frame should be text");
            let json: Value = serde_json::from_str(&text).expect("decode lag-related JSON");
            let kind = json["type"].as_str().unwrap_or_default();
            if kind == "lag" || kind == "lag_disconnect" {
                saw_lag_signal = true;
                break;
            }
        }
        assert!(saw_lag_signal);

        socket
            .send(tokio_tungstenite::tungstenite::Message::Close(None))
            .await
            .expect("send close");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), socket.next()).await;

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
        assert!(retained.iter().all(|m| m.timestamp_ms >= 9_000),);
        assert!(!store.contains_key(&weid_b));
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
    fn should_prune_messages_throttles_global_pruning() {
        let due = AtomicU64::new(0);
        assert!(should_prune_messages(&due, 1_000));
        assert!(!should_prune_messages(&due, 1_100));
        assert!(should_prune_messages(&due, 2_100));
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
        assert!(server.context().fs_base_ts().is_none());
    }

    #[tokio::test]
    async fn alias_rate_limiter_allows_burst_then_rejects() {
        let burst = 3u32;
        let limiter = AliasRateLimiter::new(burst, Duration::from_secs(60));
        let alias = "squatter";

        for i in 0..burst {
            assert!(limiter.check_and_record(alias).await, "{i}");
        }
        assert!(!limiter.check_and_record(alias).await);

        // Different alias should still be allowed
        assert!(
            limiter.check_and_record("other-alias").await,
            "different alias should have independent budget"
        );
    }

    #[tokio::test]
    async fn alias_rate_limiter_rejects_produces_429() {
        let server = Arc::new(RwLock::new(server_from_config(&CityGConfig::default())));
        let state = ApiState {
            server: server.clone(),
            server_lanes: Arc::new(vec![server]),
            messages: Arc::new(RwLock::new(AHashMap::new())),
            bundles: Arc::new(RwLock::new(AHashMap::new())),
            message_retention: Duration::from_secs(DEFAULT_FS_MESSAGE_RETENTION_SECS),
            fs_epoch_period_seconds: CityGConfig::default().protocol.fs_policy.h_seconds.max(1),
            freeze_counts: Arc::new(RwLock::new(BTreeMap::new())),
            alias_registry: Arc::new(RwLock::new(AHashMap::new())),
            member_metadata: Arc::new(RwLock::new(AHashMap::new())),
            weid_to_leaf: Arc::new(RwLock::new(AHashMap::new())),
            epoch_scopes: Arc::new(RwLock::new(AHashMap::new())),
            notification_tx: broadcast::channel(4).0,
            // Burst of 1 so the second attempt triggers rate limit
            alias_rate_limiter: AliasRateLimiter::new(1, Duration::from_secs(60)),
            message_prune_due_ms: Arc::new(AtomicU64::new(0)),
            merge_ticket_cache: Arc::new(RwLock::new(AHashMap::new())),
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
        assert!(!guard.contains_key("old-alias"));
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
        assert!(!guard.contains_key("alias-a"));
        assert!(guard.contains_key("alias-b"));
        assert!(guard.contains_key("alias-c"));
    }
}
