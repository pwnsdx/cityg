#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

pub mod health;
mod middleware;

use std::{
    collections::BTreeMap,
    convert::TryInto,
    fs,
    hash::{Hash, Hasher},
    net::SocketAddr,
    path::Path,
    sync::Arc,
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
#[cfg(test)]
use cityg_api_schema::verify_identity_binding as schema_verify_identity_binding;
use cityg_api_schema::{
    API_PROFILE_VERSION, BarrierHelperRequestDecodeError, ExpelMemberTicketRequestValidationError,
    FetchMessagesRequestValidationError, FullVerificationWitnessRequestDecodeError,
    IdentityBindingValidationError, MAX_BARRIER_HELPER_PAGE_ENTRIES, MEMBERS_DEFAULT_PAGE_SIZE,
    MEMBERS_MAX_PAGE_SIZE, MergeTicketRequestValidationError, PreparedIdentityBindingError,
    RoomAdminProofValidationError, RoomAdminRequestValidationError,
    SendMessageRequestValidationError,
    decode_barrier_fetch_public_tree_request as schema_decode_barrier_fetch_public_tree_request,
    decode_barrier_lookup_merge_acceptance_request as schema_decode_barrier_lookup_merge_acceptance_request,
    decode_barrier_resolve_revoked_leaves_request as schema_decode_barrier_resolve_revoked_leaves_request,
    decode_full_verification_witness_request as schema_decode_full_verification_witness_request,
    encode_bootstrap_room_response, encode_full_verification_witness_response,
    encode_list_room_admins_response, encode_members_response,
    encode_prepared_barrier_public_tree_response, encode_prepared_join_ticket_response,
    encode_prepared_merge_acceptance_lookup_response, encode_prepared_merge_ticket_response,
    encode_prepared_resolved_joins_response, encode_prepared_resolved_revoked_leaves_response,
    encode_room_admin_leaf_pair_payload as schema_encode_room_admin_leaf_pair_payload,
    encode_room_admin_mutation_response, encode_rotate_room_kbroad_response,
    encode_search_members_response, encode_telemetry_snapshot_response,
    encode_window_snapshot_response, pb, pb_member as schema_pb_member,
    prepare_identity_binding as schema_prepare_identity_binding,
    room_admin_proof_replay_key as schema_room_admin_proof_replay_key,
    validate_bootstrap_room_request as schema_validate_bootstrap_room_request,
    validate_expel_member_ticket_request as schema_validate_expel_member_ticket_request,
    validate_fetch_messages_request as schema_validate_fetch_messages_request,
    validate_list_room_admins_request as schema_validate_list_room_admins_request,
    validate_merge_ticket_request as schema_validate_merge_ticket_request,
    validate_room_admin_mutation_request as schema_validate_room_admin_mutation_request,
    validate_rotate_room_kbroad_request as schema_validate_rotate_room_kbroad_request,
    validate_send_message_request as schema_validate_send_message_request,
    verify_room_admin_proof as schema_verify_room_admin_proof,
    verify_room_admin_proof_payload as schema_verify_room_admin_proof_payload,
};
use futures::{SinkExt, StreamExt};
use hex::FromHex;
#[cfg(test)]
use pb::IdentityBinding;
#[cfg(test)]
use pb::JoinTicketResponse;
#[cfg(test)]
use pb::MergeTicketResponse;
use pb::{
    AcceptEpochRequest, AcceptEpochResponse, BarrierFetchPublicTreeRequest,
    BarrierIssueFullVerificationWitnessRequest, BarrierLookupMergeAcceptanceRequest,
    BarrierResolveJoinsSinceRequest, BarrierResolveRevokedLeavesRequest, BootstrapRoomRequest,
    ChatMessage, ConfigureWindowRequest, ConfigureWindowResponse, ExpelMemberTicketRequest,
    FetchMessagesRequest, FetchMessagesResponse, GetBundleRequest, GetBundleResponse,
    GetTelemetryRequest, GetWindowRequest, HealthResponse, JoinTicketRequest,
    ListRoomAdminsRequest, Member, MembersRequest, MergeTicketIntent, MergeTicketRequest,
    RefreshPivotRequest, RefreshPivotResponse, RoomAdminMutationRequest, RoomAdminProof,
    RotateRoomKbroadRequest, SendMessageRequest, SendMessageResponse,
};
#[cfg(test)]
use pb::{
    BarrierFetchPublicTreeResponse, BarrierLookupMergeAcceptanceResponse,
    BarrierResolveJoinsSinceResponse, BarrierResolveRevokedLeavesResponse, BootstrapRoomResponse,
    GetTelemetryResponse, GetWindowResponse, ListRoomAdminsResponse, MembersResponse,
    MergeAcceptanceStatus, RoomAdminMutationResponse, RotateRoomKbroadResponse,
};
#[cfg(any(debug_assertions, feature = "debug-api"))]
use pb::{SeedHeadRequest, SeedHeadResponse};
use prost::Message;
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore, broadcast};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use cityg_client::{CityGError as ClientError, ClientEpochBundle, GroupMembership};
#[cfg(test)]
use cityg_runtime::MAX_MESSAGE_CIPHERTEXT_BYTES;
#[cfg(test)]
use cityg_runtime::StoredBundle;
#[cfg(test)]
use cityg_runtime::StoredMessage;
#[cfg(test)]
use cityg_runtime::aligned_fs_epoch_base_ts;
#[cfg(test)]
use cityg_runtime::ensure_leaf_member_for_epoch as runtime_ensure_leaf_member_for_epoch;
use cityg_runtime::{
    AcceptedRoomEpoch, AliasLeafLookup, AliasRegistrationError, AliasRegistry,
    AppliedBundleIndexes, BarrierPaginationError, EpochScope, MemberMetadata,
    PreparedAcceptedBundle, RoomAcceptEpochError, RoomAuthorizationError, RoomBarrierEnvelopeError,
    RoomBarrierHelperPreparationError, RoomBundleMaterializationError,
    RoomFullVerificationWitnessPreparationError, RoomMemberListingError, RoomMessageStoreError,
    RoomServiceError, RoomTicketPreparationError, RoomVolatileState, alias_entry_for_member,
    apply_bundle_indexes, apply_room_window_limit_update as runtime_apply_room_window_limit_update,
    classify_refresh_pivot_conflict,
    commit_prepared_accepted_bundle as runtime_commit_prepared_accepted_bundle,
    ensure_leaf_member_for_room as runtime_ensure_leaf_member_for_room,
    fetch_room_bundle as runtime_fetch_room_bundle,
    fetch_room_members as runtime_fetch_room_members,
    fetch_room_messages as runtime_fetch_room_messages, filter_room_members_by_query,
    lane_state_path, materialize_replayed_bundle as runtime_materialize_replayed_bundle,
    normalize_alias, paginate_room_members,
    parse_room_window_limit_update as runtime_parse_room_window_limit_update,
    prepare_accepted_bundle as runtime_prepare_accepted_bundle,
    prepare_barrier_public_tree as runtime_prepare_barrier_public_tree,
    prepare_full_verification_witness as runtime_prepare_full_verification_witness,
    prepare_join_ticket as runtime_prepare_join_ticket,
    prepare_merge_acceptance_lookup as runtime_prepare_merge_acceptance_lookup,
    prepare_merge_ticket as runtime_prepare_merge_ticket,
    prepare_merge_ticket_from_bundle as runtime_prepare_merge_ticket_from_bundle,
    prepare_resolved_joins as runtime_prepare_resolved_joins,
    prepare_resolved_revoked_leaves as runtime_prepare_resolved_revoked_leaves,
    refresh_room_pivot as runtime_refresh_room_pivot,
    seed_room_window_head as runtime_seed_room_window_head, server_from_cityg_config_for_lane,
    snapshot_room_telemetry as runtime_snapshot_room_telemetry,
    snapshot_room_window as runtime_snapshot_room_window,
    store_room_message as runtime_store_room_message,
};
use cityg_server::{CityGServer, MergeTicketIntent as ServerMergeTicketIntent, ServerOutcome};
use msphf_core::{MsphfError, merkle::canonical_set_root};
use msphf_orchestrator::{AcceptanceError, mhw::FreezeError};
#[cfg(test)]
use pqcrypto_kyber::kyber768::public_key_bytes as ml_kem_public_key_bytes;
use serde::{Deserialize, Serialize};
use serde_json::to_vec as to_json_vec;

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
const EXPENSIVE_RATE_LIMIT_BURST_ENV: &str = "CITYG_SERVER_EXPENSIVE_RATE_LIMIT_BURST";
const EXPENSIVE_RATE_LIMIT_WINDOW_SECS_ENV: &str = "CITYG_SERVER_EXPENSIVE_RATE_LIMIT_WINDOW_SECS";
const EXPENSIVE_RATE_LIMIT_MAX_KEYS_ENV: &str = "CITYG_SERVER_EXPENSIVE_RATE_LIMIT_MAX_KEYS";
const DEFAULT_EXPENSIVE_RATE_LIMIT_BURST: u32 = 120;
const DEFAULT_EXPENSIVE_RATE_LIMIT_WINDOW_SECS: u64 = 60;
const DEFAULT_EXPENSIVE_RATE_LIMIT_MAX_KEYS: usize = 100_000;
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
const GROUP_LANES_ENV: &str = "CITYG_SERVER_GROUP_LANES";
const DEFAULT_GROUP_LANES: usize = 4;
const MERGE_COALESCE_TTL_MS: u64 = 2_000;
const MERGE_COALESCE_MAX_ENTRIES: usize = 8_192;
const ACCEPT_EPOCH_MAX_IN_FLIGHT_ENV: &str = "CITYG_SERVER_ACCEPT_EPOCH_MAX_IN_FLIGHT";
const JOIN_TICKET_MAX_IN_FLIGHT_ENV: &str = "CITYG_SERVER_JOIN_TICKET_MAX_IN_FLIGHT";
const DEFAULT_ACCEPT_EPOCH_MAX_IN_FLIGHT: usize = 8;
const DEFAULT_JOIN_TICKET_MAX_IN_FLIGHT: usize = 16;

type RequestRateKey = (&'static str, u64);
type RequestRateBuckets = AHashMap<RequestRateKey, Vec<Instant>>;

#[derive(Clone)]
struct EndpointConcurrencyLimiter {
    semaphore: Arc<Semaphore>,
}

impl EndpointConcurrencyLimiter {
    fn new(limit: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(limit.max(1))),
        }
    }

    fn try_acquire(&self) -> Result<OwnedSemaphorePermit, ApiError> {
        self.semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApiError::RateLimited)
    }
}

/// Sliding-window limiter for expensive endpoints keyed by a stable request scope.
#[derive(Clone)]
struct RequestRateLimiter {
    attempts: Arc<RwLock<RequestRateBuckets>>,
    burst: u32,
    window: Duration,
    max_keys: usize,
}

impl RequestRateLimiter {
    #[cfg(test)]
    fn new(burst: u32, window: Duration) -> Self {
        Self::with_max_keys(burst, window, DEFAULT_EXPENSIVE_RATE_LIMIT_MAX_KEYS)
    }

    fn with_max_keys(burst: u32, window: Duration, max_keys: usize) -> Self {
        Self {
            attempts: Arc::new(RwLock::new(AHashMap::new())),
            burst: burst.max(1),
            window,
            max_keys: max_keys.max(1),
        }
    }

    async fn check_and_record(&self, endpoint: &'static str, key: u64) -> bool {
        let now = Instant::now();
        let mut guard = self.attempts.write().await;
        let window = self.window;
        guard.retain(|_, entries| {
            entries.retain(|ts| now.duration_since(*ts) <= window);
            !entries.is_empty()
        });

        let bucket = (endpoint, key);
        if !guard.contains_key(&bucket) && guard.len() >= self.max_keys {
            let evict_key = guard
                .iter()
                .filter_map(|(candidate, entries)| {
                    entries.last().copied().map(|ts| (*candidate, ts))
                })
                .min_by_key(|(_, ts)| *ts)
                .map(|(candidate, _)| candidate);
            if let Some(evict_key) = evict_key {
                guard.remove(&evict_key);
            }
        }

        let entries = guard.entry(bucket).or_default();
        if entries.len() >= self.burst as usize {
            return false;
        }
        entries.push(now);
        true
    }
}

#[derive(Clone)]
struct ApiState {
    // Compatibility handle for tests and single-lane deployments.
    server: Arc<RwLock<CityGServer>>,
    // Execution lanes keyed by gid hash; write-heavy gid-scoped operations
    // are routed to one lane to reduce cross-group lock contention.
    server_lanes: Arc<Vec<Arc<RwLock<CityGServer>>>>,
    room_state: Arc<RwLock<RoomVolatileState>>,
    message_retention: Duration,
    fs_epoch_period_seconds: u64,
    freeze_counts: Arc<RwLock<BTreeMap<(u32, String), u64>>>,
    // Alias registry: alias -> (leaf_id, pop_pk) for TOFU
    alias_registry: Arc<RwLock<AliasRegistry>>,
    // Broadcast channel for WebSocket notifications
    notification_tx: broadcast::Sender<BroadcastNotification>,
    alias_rate_limiter: AliasRateLimiter,
    merge_ticket_cache: Arc<RwLock<AHashMap<MergeTicketCacheKey, MergeTicketCacheEntry>>>,
    accept_epoch_limiter: EndpointConcurrencyLimiter,
    join_ticket_limiter: EndpointConcurrencyLimiter,
    expensive_request_limiter: RequestRateLimiter,
}

#[derive(Clone, Debug)]
struct MessageNotification {
    gid: [u8; 32],
    we_epoch_id: [u8; 32],
    timestamp_ms: u64,
}

#[derive(Clone, Deserialize)]
struct WebSocketSubscriptionQuery {
    gid: String,
    leaf_id: String,
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
        let normalized_alias = normalize_alias(alias);

        if !self
            .alias_rate_limiter
            .check_and_record(normalized_alias.as_str())
            .await
        {
            warn!(alias = normalized_alias, "alias registration rate-limited");
            return Err(ApiError::RateLimited);
        }

        let mut guard = self.alias_registry.write().await;
        match guard.register_alias(normalized_alias.as_str(), leaf_id, pop_public_key) {
            Ok(outcome) => {
                match outcome {
                    cityg_runtime::AliasRegistrationOutcome::Registered => {
                        info!("Alias '{}' registered with new binding", normalized_alias);
                    }
                    cityg_runtime::AliasRegistrationOutcome::MatchedExisting => {
                        info!(
                            "Alias '{}' verified: matches existing binding",
                            normalized_alias
                        );
                    }
                    cityg_runtime::AliasRegistrationOutcome::UpdatedLeafBinding => {
                        info!(
                            "Alias '{}' verified: updated leaf binding to {}",
                            normalized_alias,
                            hex::encode(leaf_id)
                        );
                    }
                }
                Ok(outcome.is_new())
            }
            Err(AliasRegistrationError::Conflict) => {
                error!(
                    "TOFU violation: Alias '{}' already bound to different public key",
                    normalized_alias
                );
                Err(ApiError::InvalidRequest(
                    "alias already bound to a different identity",
                ))
            }
        }
    }

    #[cfg(test)]
    async fn record_member_join(
        &self,
        leaf_id: [u8; 32],
        we_epoch_id: [u8; 32],
        timestamp_ms: u64,
    ) {
        let mut room_state = self.room_state.write().await;
        room_state.record_member_join(leaf_id, we_epoch_id, timestamp_ms);
    }

    #[cfg(test)]
    async fn record_member_revocations(&self, leaves: &[[u8; 32]]) {
        if leaves.is_empty() {
            return;
        }
        let mut room_state = self.room_state.write().await;
        let revoked = room_state.revoke_members(leaves);

        // Unbind aliases whose leaf_id was revoked so the same alias can
        // rejoin with a fresh identity key without triggering a TOFU violation.
        let mut alias_guard = self.alias_registry.write().await;
        alias_guard.remove_revoked_members(&revoked);
    }

    #[cfg(test)]
    async fn record_epoch_scope(&self, we_epoch_id: [u8; 32], scope: EpochScope) {
        let mut room_state = self.room_state.write().await;
        room_state.record_epoch_scope(we_epoch_id, scope);
    }

    async fn epoch_scope_for_weid(&self, we_epoch_id: &[u8; 32]) -> Option<EpochScope> {
        let room_state = self.room_state.read().await;
        room_state.epoch_scope_for_weid(we_epoch_id)
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

fn map_barrier_helper_error(err: ClientError) -> ApiError {
    match err {
        ClientError::InvalidInput("group not found") => ApiError::NotFound,
        ClientError::InvalidInput("historical barrier public tree snapshot unavailable") => {
            ApiError::NotFound
        }
        ClientError::InvalidInput(message) => ApiError::InvalidRequest(message),
        other => ApiError::from(other),
    }
}

fn map_room_admin_proof_validation_error(err: RoomAdminProofValidationError) -> ApiError {
    match err {
        RoomAdminProofValidationError::InvalidPublicKeyLength => {
            ApiError::InvalidRequest("invalid room admin public key length")
        }
        RoomAdminProofValidationError::InvalidSignatureLength => {
            ApiError::InvalidRequest("invalid room admin signature length")
        }
        RoomAdminProofValidationError::MissingRoomId => {
            ApiError::InvalidRequest("room_id must be provided")
        }
        RoomAdminProofValidationError::EncodeProofMessage => {
            ApiError::InvalidRequest("failed to encode room admin proof message")
        }
        RoomAdminProofValidationError::InvalidPublicKey => {
            ApiError::InvalidRequest("invalid room admin public key")
        }
        RoomAdminProofValidationError::InvalidSignature => {
            ApiError::InvalidRequest("invalid room admin signature")
        }
        RoomAdminProofValidationError::VerificationFailed => {
            ApiError::InvalidRequest("room admin proof verification failed")
        }
        RoomAdminProofValidationError::MissingKbroadPublic => {
            ApiError::InvalidRequest("kbroad_public must be provided")
        }
        RoomAdminProofValidationError::EncodePayload => {
            ApiError::InvalidRequest("failed to encode room admin proof payload")
        }
        RoomAdminProofValidationError::ReplayKey(message) => ApiError::server_message(message),
    }
}

fn map_room_admin_request_validation_error(err: RoomAdminRequestValidationError) -> ApiError {
    match err {
        RoomAdminRequestValidationError::MissingRoomId => {
            ApiError::InvalidRequest("room_id must be provided")
        }
        RoomAdminRequestValidationError::MissingKbroadPublic => {
            ApiError::InvalidRequest("kbroad_public must be provided")
        }
        RoomAdminRequestValidationError::InvalidKbroadPublicLength => {
            ApiError::InvalidRequest("kbroad_public has unexpected length")
        }
        RoomAdminRequestValidationError::InvalidTargetPopPublicKeyLength => {
            ApiError::InvalidRequest("target_pop_public_key has unexpected length")
        }
        RoomAdminRequestValidationError::MissingAdminProof => {
            ApiError::Unauthorized("room admin proof is required")
        }
    }
}

fn map_expel_member_ticket_request_validation_error(
    err: ExpelMemberTicketRequestValidationError,
) -> ApiError {
    match err {
        ExpelMemberTicketRequestValidationError::MissingRoomId => {
            ApiError::InvalidRequest("room_id must be provided")
        }
        ExpelMemberTicketRequestValidationError::InvalidAuthorLeafId => {
            ApiError::InvalidRequest("author_leaf_id must be 32 bytes")
        }
        ExpelMemberTicketRequestValidationError::InvalidTargetLeafId => {
            ApiError::InvalidRequest("target_leaf_id must be 32 bytes")
        }
        ExpelMemberTicketRequestValidationError::MatchingLeafIds => ApiError::InvalidRequest(
            "author_leaf_id and target_leaf_id must differ; use controlled leave instead",
        ),
        ExpelMemberTicketRequestValidationError::MissingAdminProof => {
            ApiError::Unauthorized("room admin proof is required")
        }
    }
}

fn map_merge_ticket_request_validation_error(err: MergeTicketRequestValidationError) -> ApiError {
    match err {
        MergeTicketRequestValidationError::MissingRoomId => {
            ApiError::InvalidRequest("room_id must be provided")
        }
        MergeTicketRequestValidationError::InvalidLeafId => {
            ApiError::InvalidRequest("leaf_id must be 32 bytes")
        }
        MergeTicketRequestValidationError::InvalidIntent => {
            ApiError::InvalidRequest("merge ticket intent is invalid")
        }
    }
}

fn map_fetch_messages_request_validation_error(
    err: FetchMessagesRequestValidationError,
) -> ApiError {
    match err {
        FetchMessagesRequestValidationError::InvalidWeEpochId => {
            ApiError::InvalidRequest("we_epoch_id must be 32 bytes")
        }
        FetchMessagesRequestValidationError::InvalidLeafId => {
            ApiError::InvalidRequest("leaf_id must be 32 bytes")
        }
    }
}

fn map_send_message_request_validation_error(err: SendMessageRequestValidationError) -> ApiError {
    match err {
        SendMessageRequestValidationError::InvalidWeEpochId => {
            ApiError::InvalidRequest("we_epoch_id must be 32 bytes")
        }
        SendMessageRequestValidationError::MissingCiphertext => {
            ApiError::InvalidRequest("ciphertext must be provided")
        }
        SendMessageRequestValidationError::CiphertextTooLarge => {
            ApiError::InvalidRequest("ciphertext exceeds MAX_PAYLOAD_ENVELOPE_BYTES")
        }
        SendMessageRequestValidationError::InvalidSender => {
            ApiError::InvalidRequest("sender must be 32 bytes")
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
            "{}=true with no {} or {} configured; insecure admin bypass is ignored and room admin endpoints remain unavailable",
            ALLOW_INSECURE_ADMIN_ENV, ROOMS_ADMIN_TOKEN_ENV, WINDOW_CONFIG_ADMIN_TOKEN_ENV
        );
    }
    if configured_window_admin_token().is_none() {
        warn!(
            "{}=true with no {} configured; insecure admin bypass is ignored and window admin endpoints remain unavailable",
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
            warn!(
                "{}=true was set without an admin token; refusing unauthenticated admin access",
                ALLOW_INSECURE_ADMIN_ENV
            );
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

fn enforce_message_auth_websocket(
    headers: &HeaderMap,
    expected_token: Option<&str>,
) -> Result<(), ApiError> {
    enforce_message_auth_query(
        headers
            .get(MESSAGE_AUTH_HEADER)
            .and_then(|value| value.to_str().ok()),
        expected_token,
    )
}

fn parse_ws_max_lag(raw: Option<&str>) -> u64 {
    raw.and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(WS_MAX_LAG_DEFAULT)
}

fn configured_accept_epoch_max_in_flight() -> usize {
    std::env::var(ACCEPT_EPOCH_MAX_IN_FLIGHT_ENV)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_ACCEPT_EPOCH_MAX_IN_FLIGHT)
}

fn configured_join_ticket_max_in_flight() -> usize {
    std::env::var(JOIN_TICKET_MAX_IN_FLIGHT_ENV)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_JOIN_TICKET_MAX_IN_FLIGHT)
}

fn configured_expensive_rate_limit_burst() -> u32 {
    std::env::var(EXPENSIVE_RATE_LIMIT_BURST_ENV)
        .ok()
        .and_then(|raw| raw.parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_EXPENSIVE_RATE_LIMIT_BURST)
}

fn configured_expensive_rate_limit_window() -> Duration {
    Duration::from_secs(
        std::env::var(EXPENSIVE_RATE_LIMIT_WINDOW_SECS_ENV)
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_EXPENSIVE_RATE_LIMIT_WINDOW_SECS),
    )
}

fn configured_expensive_rate_limit_max_keys() -> usize {
    std::env::var(EXPENSIVE_RATE_LIMIT_MAX_KEYS_ENV)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_EXPENSIVE_RATE_LIMIT_MAX_KEYS)
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

fn fingerprint_rate_limit_parts(parts: &[&[u8]]) -> u64 {
    let mut hasher = AHasher::default();
    for part in parts {
        hasher.write_u64(part.len() as u64);
        hasher.write(part);
    }
    hasher.finish()
}

fn message_scoped_rate_limit_key(headers: &HeaderMap, scope: &[u8]) -> u64 {
    if let Some(token) = headers.get(MESSAGE_AUTH_HEADER) {
        return fingerprint_rate_limit_parts(&[token.as_bytes(), scope]);
    }
    fingerprint_rate_limit_parts(&[scope])
}

fn join_ticket_rate_limit_key(request: &JoinTicketRequest) -> u64 {
    let mut parts: Vec<&[u8]> = vec![request.room_id.as_bytes(), request.alias.as_bytes()];
    if let Some(binding) = request.identity_binding.as_ref() {
        parts.push(binding.alias.as_bytes());
        parts.push(binding.pop_public_key.as_slice());
    }
    fingerprint_rate_limit_parts(&parts)
}

fn accept_epoch_rate_limit_key(bundle: &ClientEpochBundle) -> u64 {
    fingerprint_rate_limit_parts(&[
        bundle.gid(),
        &bundle.anchor.parent_root,
        &bundle.anchor.join_delta_root,
        &bundle.anchor.revoked_root,
    ])
}

async fn enforce_expensive_rate_limit(
    state: &ApiState,
    endpoint: &'static str,
    key: u64,
) -> Result<(), ApiError> {
    if state
        .expensive_request_limiter
        .check_and_record(endpoint, key)
        .await
    {
        return Ok(());
    }
    metrics::counter!(
        "cityg_endpoint_rate_limited_total",
        "endpoint" => endpoint
    )
    .increment(1);
    Err(ApiError::RateLimited)
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

fn record_concurrency_pressure(endpoint: &'static str, reason: &'static str) {
    metrics::counter!(
        "cityg_concurrency_pressure_total",
        "endpoint" => endpoint,
        "reason" => reason
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

fn map_room_ticket_preparation_error(
    endpoint: &'static str,
    err: RoomTicketPreparationError,
) -> ApiError {
    match err {
        RoomTicketPreparationError::Client(err) => {
            maybe_record_client_concurrency_error(endpoint, &err);
            ApiError::from(err)
        }
        other => ApiError::server_message(other.to_string()),
    }
}

fn map_room_barrier_envelope_error(
    endpoint: &'static str,
    err: RoomBarrierEnvelopeError,
) -> ApiError {
    match err {
        RoomBarrierEnvelopeError::Client(err) => {
            maybe_record_client_concurrency_error(endpoint, &err);
            ApiError::from(err)
        }
        other => ApiError::server_message(other.to_string()),
    }
}

fn map_barrier_pagination_error(err: BarrierPaginationError) -> ApiError {
    match err {
        BarrierPaginationError::MaxEntriesExceedsLimit => {
            ApiError::InvalidRequest("max_entries exceeds MAX_BARRIER_HELPER_PAGE_ENTRIES")
        }
        BarrierPaginationError::PageOffsetOutOfRange => {
            ApiError::InvalidRequest("page_offset out of range")
        }
        BarrierPaginationError::MaxEntriesOutOfRange => {
            ApiError::InvalidRequest("max_entries out of range")
        }
        BarrierPaginationError::TotalEntriesOverflow
        | BarrierPaginationError::NextPageOffsetOverflow => {
            ApiError::server_message(err.to_string())
        }
    }
}

fn map_room_barrier_helper_preparation_error(
    endpoint: &'static str,
    err: RoomBarrierHelperPreparationError,
) -> ApiError {
    match err {
        RoomBarrierHelperPreparationError::Client(err) => map_barrier_helper_error(err),
        RoomBarrierHelperPreparationError::Envelope(err) => {
            map_room_barrier_envelope_error(endpoint, err)
        }
        RoomBarrierHelperPreparationError::Pagination(err) => map_barrier_pagination_error(err),
    }
}

fn map_full_verification_witness_preparation_error(
    endpoint: &'static str,
    err: RoomFullVerificationWitnessPreparationError,
) -> ApiError {
    match err {
        RoomFullVerificationWitnessPreparationError::Client(err) => ApiError::from(err),
        RoomFullVerificationWitnessPreparationError::HelperClient(err) => {
            map_barrier_helper_error(err)
        }
        RoomFullVerificationWitnessPreparationError::Ticket(err) => {
            map_room_ticket_preparation_error(endpoint, err)
        }
        RoomFullVerificationWitnessPreparationError::GroupNotFound => {
            ApiError::InvalidRequest("group not found")
        }
        RoomFullVerificationWitnessPreparationError::CurrentHistoryCommitmentMismatch => {
            ApiError::InvalidRequest(
                "current_history_commitment mismatch with authenticated current state",
            )
        }
        RoomFullVerificationWitnessPreparationError::JoinsPrevBarrierVersionMismatch => {
            ApiError::InvalidRequest(
                "joins_prev_barrier_version mismatch with authenticated current state",
            )
        }
        RoomFullVerificationWitnessPreparationError::GlobalHistoryAttestationMismatch => {
            ApiError::InvalidRequest(
                "current_global_history_attestation mismatch with authenticated current state",
            )
        }
        RoomFullVerificationWitnessPreparationError::DeploymentProfileManifestMismatch => {
            ApiError::InvalidRequest(
                "deployment_profile_manifest mismatch with authenticated current state",
            )
        }
        RoomFullVerificationWitnessPreparationError::MergeTicketArtifactMismatch => {
            ApiError::InvalidRequest(
                "merge_ticket_artifact mismatch with authenticated current state",
            )
        }
        RoomFullVerificationWitnessPreparationError::RevocationRootsHashMismatch => {
            ApiError::InvalidRequest(
                "revocation_roots_hash mismatch with authenticated current state",
            )
        }
        RoomFullVerificationWitnessPreparationError::JoinHelperDataMismatch => {
            ApiError::InvalidRequest("join helper data mismatch with authenticated current state")
        }
        RoomFullVerificationWitnessPreparationError::RevokedHelperDataMismatch => {
            ApiError::InvalidRequest(
                "revoked helper data mismatch with authenticated current state",
            )
        }
        RoomFullVerificationWitnessPreparationError::CoverLeafIndexOutOfRange => {
            ApiError::InvalidRequest("cover_leaf_index out of range")
        }
    }
}

/// Verifies an identity binding signature.
/// The signature should be over CBOR([alias, pop_public_key])
#[cfg(test)]
fn verify_identity_binding(binding: &IdentityBinding) -> Result<(), ApiError> {
    schema_verify_identity_binding(binding).map_err(|error| match error {
        IdentityBindingValidationError::InvalidPublicKeyLength => {
            ApiError::InvalidRequest("invalid pop_public_key length")
        }
        IdentityBindingValidationError::InvalidSignatureLength => {
            ApiError::InvalidRequest("invalid signature length")
        }
        IdentityBindingValidationError::EmptyAlias => {
            ApiError::InvalidRequest("alias cannot be empty")
        }
        IdentityBindingValidationError::EncodeMessage => {
            ApiError::InvalidRequest("failed to encode message for verification")
        }
        IdentityBindingValidationError::InvalidPublicKey => {
            ApiError::InvalidRequest("invalid pop_public_key")
        }
        IdentityBindingValidationError::InvalidSignature => {
            ApiError::InvalidRequest("invalid signature")
        }
        IdentityBindingValidationError::VerificationFailed => {
            ApiError::InvalidRequest("signature verification failed")
        }
    })
}

fn verify_room_admin_proof_payload(
    proof: &RoomAdminProof,
    operation: &'static str,
    room_id: &str,
    payload: &[u8],
) -> Result<Vec<u8>, ApiError> {
    schema_verify_room_admin_proof_payload(proof, operation, room_id, payload)
        .map_err(map_room_admin_proof_validation_error)
}

fn verify_room_admin_proof(
    proof: &RoomAdminProof,
    operation: &'static str,
    room_id: &str,
    kbroad_public: &[u8],
) -> Result<Vec<u8>, ApiError> {
    schema_verify_room_admin_proof(proof, operation, room_id, kbroad_public)
        .map_err(map_room_admin_proof_validation_error)
}

fn room_admin_proof_replay_key(proof: &RoomAdminProof) -> Result<[u8; 32], ApiError> {
    schema_room_admin_proof_replay_key(proof).map_err(map_room_admin_proof_validation_error)
}

fn encode_room_admin_leaf_pair_payload(
    author_leaf_id: &[u8; 32],
    target_leaf_id: &[u8; 32],
) -> Result<Vec<u8>, ApiError> {
    schema_encode_room_admin_leaf_pair_payload(author_leaf_id, target_leaf_id)
        .map_err(map_room_admin_proof_validation_error)
}

async fn accept_epoch(State(state): State<ApiState>, body: Bytes) -> Result<Response, ApiError> {
    let _permit = state.accept_epoch_limiter.try_acquire()?;
    let request = AcceptEpochRequest::decode(body)?;
    let bundle = match ClientEpochBundle::from_cbor(&request.bundle_cbor) {
        Ok(bundle) => bundle,
        Err(ClientError::InvalidInput(_)) => {
            return Err(ApiError::InvalidRequest("invalid bundle encoding"));
        }
        Err(err) => return Err(ApiError::from(err)),
    };
    enforce_expensive_rate_limit(&state, "accept_epoch", accept_epoch_rate_limit_key(&bundle))
        .await?;

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
    let started = Instant::now();

    let prepared = {
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        match runtime_prepare_accepted_bundle(&mut guard, bundle) {
            Ok(prepared) => prepared,
            Err(err) => {
                drop(guard);
                let mapped = map_room_accept_error(state, err, None, None).await;
                maybe_record_api_concurrency_error("accept_epoch", &mapped);
                metrics::counter!("cityg_accept_epoch_total", "result" => "error").increment(1);
                metrics::histogram!("cityg_accept_epoch_duration_seconds", "result" => "error")
                    .record(started.elapsed().as_secs_f64());
                return Err(mapped);
            }
        }
    };

    let accepted = match commit_accepted_bundle(state, bundle, prepared, true).await {
        Ok(accepted) => accepted,
        Err(mapped) => {
            maybe_record_api_concurrency_error("accept_epoch", &mapped);
            metrics::counter!("cityg_accept_epoch_total", "result" => "error").increment(1);
            metrics::histogram!("cityg_accept_epoch_duration_seconds", "result" => "error")
                .record(started.elapsed().as_secs_f64());
            return Err(mapped);
        }
    };

    state.clear_merge_ticket_cache_for_gid(gid).await;
    metrics::counter!("cityg_accept_epoch_total", "result" => "ok").increment(1);
    metrics::histogram!("cityg_accept_epoch_duration_seconds", "result" => "ok")
        .record(started.elapsed().as_secs_f64());
    Ok(accept_response_from(&accepted.outcome))
}

#[cfg(test)]
async fn store_bundle_bytes(state: &ApiState, weid: [u8; 32], bytes: Vec<u8>) {
    let now_ms = current_timestamp_ms();
    let mut room_state = state.room_state.write().await;
    room_state.store_bundle(
        weid,
        StoredBundle {
            bytes,
            stored_at_ms: now_ms,
        },
        now_ms,
        state.message_retention,
        MESSAGE_PRUNE_INTERVAL_MS,
    );
}

fn load_journal_entries(path: &Path) -> anyhow::Result<Vec<Vec<u8>>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    let mut cursor = bytes.as_slice();
    let mut entries = Vec::new();
    while cursor.len() >= 4 {
        let (len_bytes, rest) = cursor.split_at(4);
        let len = u32::from_le_bytes(
            len_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid journal entry length"))?,
        ) as usize;
        if rest.len() < len {
            break;
        }
        let (entry, remainder) = rest.split_at(len);
        entries.push(entry.to_vec());
        cursor = remainder;
    }
    Ok(entries)
}

async fn commit_accepted_bundle(
    state: &ApiState,
    bundle: &ClientEpochBundle,
    prepared: PreparedAcceptedBundle,
    broadcast: bool,
) -> Result<AcceptedRoomEpoch, ApiError> {
    let timestamp_ms = current_timestamp_ms();
    let accepted = {
        let mut room_state = state.room_state.write().await;
        runtime_commit_prepared_accepted_bundle(
            &mut room_state,
            bundle,
            prepared,
            timestamp_ms,
            state.message_retention,
            MESSAGE_PRUNE_INTERVAL_MS,
        )
        .map_err(|err| map_bundle_index_error(err, "failed to compute membership delta"))?
    };
    apply_bundle_side_effects(state, &accepted.applied, broadcast).await;
    Ok(accepted)
}

async fn rehydrate_bundle_indexes(
    state: &ApiState,
    bundle: &ClientEpochBundle,
    weid: [u8; 32],
    bytes: Vec<u8>,
    membership_root: [u8; 32],
) -> Result<(), ApiError> {
    let timestamp_ms = current_timestamp_ms();
    let applied = {
        let mut room_state = state.room_state.write().await;
        apply_bundle_indexes(
            &mut room_state,
            bundle,
            weid,
            bytes,
            membership_root,
            timestamp_ms,
            state.message_retention,
            MESSAGE_PRUNE_INTERVAL_MS,
        )
        .map_err(|err| {
            map_bundle_index_error(err, "failed to compute membership delta during replay")
        })?
    };
    apply_bundle_side_effects(state, &applied, false).await;
    Ok(())
}

async fn rehydrate_persisted_bundle_indexes(
    state: &ApiState,
    cfg: &cityg_config::CityGConfig,
    lane_count: usize,
) -> anyhow::Result<()> {
    let Some(base_path) = cfg.server.state_path.as_ref() else {
        return Ok(());
    };

    let mut memberships: BTreeMap<[u8; 32], GroupMembership> = BTreeMap::new();
    for lane_index in 0..lane_count.max(1) {
        let journal_path = lane_state_path(base_path, lane_index, lane_count.max(1));
        let entries = load_journal_entries(&journal_path)?;
        for entry in entries {
            let bundle = ClientEpochBundle::from_cbor(&entry).map_err(|err| {
                anyhow::anyhow!("failed to decode replayed journal bundle: {err}")
            })?;
            let gid: [u8; 32] = bundle
                .gid()
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid gid length in replayed journal bundle"))?;
            let delta = bundle.membership_delta().map_err(|err| {
                anyhow::anyhow!("failed to compute replayed membership delta: {err}")
            })?;
            let membership = memberships.entry(gid).or_default();
            membership
                .apply_delta_checked(&delta)
                .map_err(|err| anyhow::anyhow!("failed to replay membership delta: {err}"))?;
            let leaves: Vec<[u8; 32]> = membership.members().copied().collect();
            let membership_root = canonical_set_root(&leaves)
                .map_err(|_| anyhow::anyhow!("failed to compute replayed membership root"))?;
            let bytes = {
                let lane = state.server_for_gid(&gid);
                let mut guard = lane.write().await;
                runtime_materialize_replayed_bundle(&mut guard, &bundle, membership_root)
                    .map_err(|err| anyhow::anyhow!(err.to_string()))?
            };
            rehydrate_bundle_indexes(state, &bundle, bundle.we_epoch_id, bytes, membership_root)
                .await?;
        }
    }

    Ok(())
}

fn map_bundle_index_error(err: RoomServiceError, context: &str) -> ApiError {
    match err {
        RoomServiceError::InvalidGidLength => {
            ApiError::server_message("invalid gid length in bundle")
        }
        RoomServiceError::MembershipDelta(message) => {
            ApiError::server_message(format!("{context}: {message}"))
        }
    }
}

fn map_bundle_materialization_error(err: RoomBundleMaterializationError) -> ApiError {
    ApiError::server_message(err.to_string())
}

async fn map_room_accept_error(
    state: &ApiState,
    err: RoomAcceptEpochError,
    error_label: Option<&'static str>,
    failed_index: Option<u32>,
) -> ApiError {
    match err {
        RoomAcceptEpochError::Client(err) => {
            map_accept_error(state, err, error_label, failed_index).await
        }
        RoomAcceptEpochError::Materialization(err) => map_bundle_materialization_error(err),
        RoomAcceptEpochError::Service(err) => {
            map_bundle_index_error(err, "failed to compute membership delta")
        }
    }
}

async fn apply_bundle_side_effects(
    state: &ApiState,
    applied: &AppliedBundleIndexes,
    broadcast: bool,
) {
    if !applied.revoked.is_empty() {
        let mut alias_guard = state.alias_registry.write().await;
        alias_guard.remove_revoked_slice(applied.revoked.as_slice());
    }
    if !broadcast {
        return;
    }
    for leaf in &applied.joined {
        state.broadcast_membership(
            applied.gid,
            *leaf,
            MembershipEventKind::Join,
            applied.timestamp_ms,
        );
    }
    for leaf in &applied.revoked {
        state.broadcast_membership(
            applied.gid,
            *leaf,
            MembershipEventKind::Revoke,
            applied.timestamp_ms,
        );
    }
}

#[cfg(test)]
async fn ensure_leaf_member_for_epoch(
    state: &ApiState,
    we_epoch_id: &[u8; 32],
    leaf_id: [u8; 32],
) -> Result<EpochScope, ApiError> {
    let scope = state
        .epoch_scope_for_weid(we_epoch_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let lane = state.server_for_gid(&scope.gid);
    let guard = lane.read().await;
    let room_state = state.room_state.read().await;
    runtime_ensure_leaf_member_for_epoch(&guard, &room_state, we_epoch_id, leaf_id).map_err(|err| {
        match err {
            RoomAuthorizationError::NotFound => ApiError::NotFound,
            RoomAuthorizationError::Unauthorized => {
                ApiError::Unauthorized("leaf is not a member for epoch")
            }
        }
    })
}

async fn ensure_leaf_member_for_room(
    state: &ApiState,
    gid: &[u8; 32],
    leaf_id: [u8; 32],
) -> Result<(), ApiError> {
    let lane = state.server_for_gid(gid);
    let guard = lane.read().await;
    runtime_ensure_leaf_member_for_room(&guard, gid, leaf_id).map_err(|err| match err {
        RoomAuthorizationError::NotFound => ApiError::NotFound,
        RoomAuthorizationError::Unauthorized => {
            ApiError::Unauthorized("leaf is not a member for room")
        }
    })
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

async fn members_for_request(
    state: &ApiState,
    gid: &[u8],
    parent_root: &[u8],
) -> Result<(Vec<[u8; 32]>, [u8; 32]), ApiError> {
    let lane = state.server_for_gid_bytes(gid);
    let guard = lane.read().await;
    let parent_root = if parent_root.is_empty() {
        None
    } else {
        Some(
            parent_root
                .try_into()
                .map_err(|_| ApiError::InvalidRequest("parent_root must be 32 bytes"))?,
        )
    };

    let gid: &[u8; 32] = gid.try_into().map_err(|_| ApiError::NotFound)?;
    runtime_fetch_room_members(&guard, gid, parent_root).map_err(|err| match err {
        RoomMemberListingError::NotFound => ApiError::NotFound,
    })
}

async fn alias_lookup_by_leaf(state: &ApiState) -> AliasLeafLookup {
    let registry = state.alias_registry.read().await;
    registry.leaf_lookup()
}

fn member_response(
    leaf: &[u8; 32],
    alias_lookup: &AliasLeafLookup,
    metadata: &AHashMap<[u8; 32], MemberMetadata>,
) -> Member {
    schema_pb_member(
        leaf,
        alias_entry_for_member(alias_lookup, leaf),
        metadata.get(leaf),
    )
}

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
    enforce_expensive_rate_limit(
        &state,
        "members",
        message_scoped_rate_limit_key(&headers, &gid),
    )
    .await?;
    let offset = request.offset.unwrap_or(0);
    let limit = request
        .limit
        .unwrap_or(MEMBERS_DEFAULT_PAGE_SIZE)
        .clamp(1, MEMBERS_MAX_PAGE_SIZE);
    let (members, root) = members_for_request(&state, &gid, &request.parent_root).await?;

    let page = paginate_room_members(members.as_slice(), offset, limit);

    let alias_lookup = alias_lookup_by_leaf(&state).await;
    let room_state = state.room_state.read().await;

    Ok(protobuf_response_bytes(encode_members_response(
        page.members
            .iter()
            .map(|leaf| member_response(leaf, &alias_lookup, room_state.member_metadata()))
            .collect(),
        root,
        page.total_count,
        page.next_offset,
    )))
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
    enforce_expensive_rate_limit(
        &state,
        "search_members",
        message_scoped_rate_limit_key(&headers, &gid),
    )
    .await?;
    let offset = request.offset.unwrap_or(0);
    let limit = request
        .limit
        .unwrap_or(MEMBERS_DEFAULT_PAGE_SIZE)
        .clamp(1, MEMBERS_MAX_PAGE_SIZE);
    let (members, root) = members_for_request(&state, &gid, &request.parent_root).await?;

    let alias_lookup = alias_lookup_by_leaf(&state).await;
    let room_state = state.room_state.read().await;

    let filtered_members =
        filter_room_members_by_query(members.as_slice(), &alias_lookup, request.query.as_str());
    let page = paginate_room_members(filtered_members.as_slice(), offset, limit);

    Ok(protobuf_response_bytes(encode_search_members_response(
        page.members
            .iter()
            .map(|leaf| member_response(leaf, &alias_lookup, room_state.member_metadata()))
            .collect(),
        root,
        page.total_count,
        page.next_offset,
    )))
}

async fn join_ticket(State(state): State<ApiState>, body: Bytes) -> Result<Response, ApiError> {
    let _permit = state.join_ticket_limiter.try_acquire()?;
    let request = JoinTicketRequest::decode(body)?;
    if request.room_id.is_empty() {
        return Err(ApiError::InvalidRequest("room_id must be provided"));
    }
    enforce_expensive_rate_limit(&state, "join_ticket", join_ticket_rate_limit_key(&request))
        .await?;
    let gid = parse_gid(&request.room_id)?;

    // Verify identity binding if provided; persist TOFU alias only after ticket succeeds.
    let prepared_binding = schema_prepare_identity_binding(&gid, request.identity_binding.as_ref())
        .map_err(|error| match error {
            PreparedIdentityBindingError::Validation(validation) => match validation {
                IdentityBindingValidationError::InvalidPublicKeyLength => {
                    ApiError::InvalidRequest("invalid pop_public_key length")
                }
                IdentityBindingValidationError::InvalidSignatureLength => {
                    ApiError::InvalidRequest("invalid signature length")
                }
                IdentityBindingValidationError::EmptyAlias => {
                    ApiError::InvalidRequest("alias cannot be empty")
                }
                IdentityBindingValidationError::EncodeMessage => {
                    ApiError::InvalidRequest("failed to encode message for verification")
                }
                IdentityBindingValidationError::InvalidPublicKey => {
                    ApiError::InvalidRequest("invalid pop_public_key")
                }
                IdentityBindingValidationError::InvalidSignature => {
                    ApiError::InvalidRequest("invalid signature")
                }
                IdentityBindingValidationError::VerificationFailed => {
                    ApiError::InvalidRequest("signature verification failed")
                }
            },
            PreparedIdentityBindingError::ComputeLeaf(message) => {
                ApiError::server_message(format!("failed to compute leaf_id: {message}"))
            }
        })?;
    let requested_leaf_id = prepared_binding
        .as_ref()
        .map(|binding| binding.requested_leaf_id);
    let confirmed_binding = prepared_binding.map(|binding| binding.confirmed_binding);

    let prepared = {
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        match runtime_prepare_join_ticket(
            &mut guard,
            &gid,
            requested_leaf_id,
            SystemTime::now(),
            state.fs_epoch_period_seconds,
            API_PROFILE_VERSION,
        ) {
            Ok(prepared) => prepared,
            Err(err) => {
                metrics::counter!("cityg_join_ticket_total", "result" => "error").increment(1);
                return Err(map_room_ticket_preparation_error("join_ticket", err));
            }
        }
    };
    let ticket_leaf_id = prepared.bundle.leaf_id;

    if let Some(binding) = confirmed_binding.as_ref() {
        state
            .register_alias(
                &binding.alias,
                ticket_leaf_id,
                binding.pop_public_key.clone(),
            )
            .await?;
    }
    metrics::counter!("cityg_join_ticket_total", "result" => "ok").increment(1);
    Ok(protobuf_response_bytes(
        encode_prepared_join_ticket_response(prepared, confirmed_binding),
    ))
}

async fn bootstrap_room(
    State(state): State<ApiState>,
    _headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request = schema_validate_bootstrap_room_request(BootstrapRoomRequest::decode(body)?)
        .map_err(map_room_admin_request_validation_error)?;
    let gid = parse_gid(&request.room_id)?;
    let initial_room_admin_pop_key = verify_room_admin_proof(
        &request.admin_proof,
        "bootstrap_room_v1",
        &request.room_id,
        &request.kbroad_public,
    )?;

    {
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        guard
            .register_group_with_admin(&gid, request.kbroad_public, initial_room_admin_pop_key)
            .map_err(|err| match err {
                ClientError::InvalidInput(message) => ApiError::InvalidRequest(message),
                other => ApiError::from(other),
            })?;
    }

    Ok(protobuf_response_bytes(encode_bootstrap_room_response(
        "registered",
    )))
}

async fn rotate_room_kbroad(
    State(state): State<ApiState>,
    _headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request =
        schema_validate_rotate_room_kbroad_request(RotateRoomKbroadRequest::decode(body)?)
            .map_err(map_room_admin_request_validation_error)?;
    let gid = parse_gid(&request.room_id)?;
    let replay_key = room_admin_proof_replay_key(&request.admin_proof)?;
    let kbroad_generation = {
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        let actor_pop_key = verify_room_admin_proof(
            &request.admin_proof,
            "rotate_room_kbroad_v1",
            &request.room_id,
            &request.kbroad_public,
        )?;
        guard
            .rotate_group_kbroad_with_actor(&gid, request.kbroad_public, &actor_pop_key, replay_key)
            .map_err(|err| match err {
                ClientError::InvalidInput(message) => ApiError::InvalidRequest(message),
                other => ApiError::from(other),
            })?
    };

    Ok(protobuf_response_bytes(encode_rotate_room_kbroad_response(
        "rotated",
        kbroad_generation,
    )))
}

async fn grant_room_admin(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request =
        schema_validate_room_admin_mutation_request(RoomAdminMutationRequest::decode(body)?)
            .map_err(map_room_admin_request_validation_error)?;
    let gid = parse_gid(&request.room_id)?;
    let replay_key = room_admin_proof_replay_key(&request.admin_proof)?;
    let actor_pop_key = verify_room_admin_proof_payload(
        &request.admin_proof,
        "grant_room_admin_v1",
        &request.room_id,
        &request.target_pop_public_key,
    )?;
    let (granted, admin_count) = {
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        guard
            .grant_room_admin(
                &gid,
                &actor_pop_key,
                request.target_pop_public_key,
                replay_key,
            )
            .map_err(|err| match err {
                ClientError::InvalidInput(message) => ApiError::InvalidRequest(message),
                other => ApiError::from(other),
            })?
    };

    Ok(protobuf_response_bytes(
        encode_room_admin_mutation_response(
            if granted {
                "granted"
            } else {
                "already_granted"
            },
            admin_count,
        ),
    ))
}

async fn revoke_room_admin(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request =
        schema_validate_room_admin_mutation_request(RoomAdminMutationRequest::decode(body)?)
            .map_err(map_room_admin_request_validation_error)?;
    let gid = parse_gid(&request.room_id)?;
    let replay_key = room_admin_proof_replay_key(&request.admin_proof)?;
    let actor_pop_key = verify_room_admin_proof_payload(
        &request.admin_proof,
        "revoke_room_admin_v1",
        &request.room_id,
        &request.target_pop_public_key,
    )?;
    let (revoked, admin_count) = {
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        guard
            .revoke_room_admin(
                &gid,
                &actor_pop_key,
                &request.target_pop_public_key,
                replay_key,
            )
            .map_err(|err| match err {
                ClientError::InvalidInput(message) => ApiError::InvalidRequest(message),
                other => ApiError::from(other),
            })?
    };

    Ok(protobuf_response_bytes(
        encode_room_admin_mutation_response(
            if revoked {
                "revoked"
            } else {
                "already_revoked"
            },
            admin_count,
        ),
    ))
}

async fn list_room_admins(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request = schema_validate_list_room_admins_request(ListRoomAdminsRequest::decode(body)?)
        .map_err(map_room_admin_request_validation_error)?;
    let gid = parse_gid(&request.room_id)?;
    let actor_pop_key = verify_room_admin_proof_payload(
        &request.admin_proof,
        "list_room_admins_v1",
        &request.room_id,
        &[],
    )?;
    let admin_pop_public_keys = {
        let lane = state.server_for_gid(&gid);
        let guard = lane.read().await;
        guard
            .list_room_admins(&gid, &actor_pop_key)
            .map_err(|err| match err {
                ClientError::InvalidInput(message) => ApiError::InvalidRequest(message),
                other => ApiError::from(other),
            })?
    };

    Ok(protobuf_response_bytes(encode_list_room_admins_response(
        admin_pop_public_keys,
    )))
}

async fn expel_member_ticket(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request =
        schema_validate_expel_member_ticket_request(ExpelMemberTicketRequest::decode(body)?)
            .map_err(map_expel_member_ticket_request_validation_error)?;
    let gid = parse_gid(&request.room_id)?;
    let payload =
        encode_room_admin_leaf_pair_payload(&request.author_leaf_id, &request.target_leaf_id)?;
    let replay_key = room_admin_proof_replay_key(&request.admin_proof)?;
    let actor_pop_key = verify_room_admin_proof_payload(
        &request.admin_proof,
        "expel_room_member_v1",
        &request.room_id,
        &payload,
    )?;
    enforce_expensive_rate_limit(
        &state,
        "expel_member_ticket",
        fingerprint_rate_limit_parts(&[
            &gid,
            &request.author_leaf_id,
            &request.target_leaf_id,
            actor_pop_key.as_slice(),
        ]),
    )
    .await?;

    let prepared = {
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        let bundle = guard
            .build_admin_expel_ticket(
                &gid,
                &actor_pop_key,
                &request.author_leaf_id,
                &request.target_leaf_id,
                replay_key,
            )
            .map_err(|err| {
                maybe_record_client_concurrency_error("expel_member_ticket", &err);
                ApiError::from(err)
            })?;
        runtime_prepare_merge_ticket_from_bundle(&guard, &gid, bundle, API_PROFILE_VERSION)
            .map_err(|err| map_room_ticket_preparation_error("expel_member_ticket", err))?
    };

    Ok(protobuf_response_bytes(
        encode_prepared_merge_ticket_response(prepared),
    ))
}

async fn merge_ticket(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let request = schema_validate_merge_ticket_request(MergeTicketRequest::decode(body)?)
        .map_err(map_merge_ticket_request_validation_error)?;
    let gid = parse_gid(&request.room_id)?;
    enforce_expensive_rate_limit(
        &state,
        "merge_ticket",
        fingerprint_rate_limit_parts(&[
            headers
                .get(MESSAGE_AUTH_HEADER)
                .map(HeaderValue::as_bytes)
                .unwrap_or_default(),
            &gid,
            &request.leaf_id,
        ]),
    )
    .await?;
    let cache_key = MergeTicketCacheKey {
        gid,
        leaf_id: request.leaf_id,
        intent: request.intent_value,
    };
    let now_ms = current_timestamp_ms();
    if request.intent == MergeTicketIntent::Leave
        && let Some(cached) = state.coalesced_merge_ticket_lookup(cache_key, now_ms).await
    {
        metrics::counter!(
            "cityg_merge_ticket_coalesced_total",
            "intent" => "leave"
        )
        .increment(1);
        metrics::counter!("cityg_merge_ticket_total", "result" => "ok").increment(1);
        return Ok(protobuf_response_bytes(cached));
    }

    let prepared = {
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        let server_intent = match request.intent {
            MergeTicketIntent::Leave => ServerMergeTicketIntent::Leave,
            MergeTicketIntent::Refresh => ServerMergeTicketIntent::Refresh,
        };
        match runtime_prepare_merge_ticket(
            &mut guard,
            &gid,
            &request.leaf_id,
            server_intent,
            API_PROFILE_VERSION,
        ) {
            Ok(prepared) => prepared,
            Err(err) => {
                metrics::counter!("cityg_merge_ticket_total", "result" => "error").increment(1);
                let endpoint = match request.intent {
                    MergeTicketIntent::Leave => "merge_ticket",
                    MergeTicketIntent::Refresh => "merge_ticket_refresh",
                };
                return Err(map_room_ticket_preparation_error(endpoint, err));
            }
        }
    };

    let response_bytes = encode_prepared_merge_ticket_response(prepared);
    if request.intent == MergeTicketIntent::Leave {
        state
            .coalesced_merge_ticket_store(cache_key, response_bytes.clone(), now_ms)
            .await;
    }
    metrics::counter!("cityg_merge_ticket_total", "result" => "ok").increment(1);
    Ok(protobuf_response_bytes(response_bytes))
}

async fn barrier_issue_full_verification_witness(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let request = BarrierIssueFullVerificationWitnessRequest::decode(body)?;
    if request.room_id.is_empty() {
        return Err(ApiError::InvalidRequest("room_id must be provided"));
    }
    let gid = parse_gid(&request.room_id)?;
    enforce_expensive_rate_limit(
        &state,
        "barrier_issue_full_verification_witness",
        message_scoped_rate_limit_key(&headers, &gid),
    )
    .await?;
    let witness_request =
        schema_decode_full_verification_witness_request(request).map_err(|error| match error {
            FullVerificationWitnessRequestDecodeError::InvalidAuthorLeafId
            | FullVerificationWitnessRequestDecodeError::MissingCurrentGlobalHistoryAttestation
            | FullVerificationWitnessRequestDecodeError::MissingDeploymentProfileManifest
            | FullVerificationWitnessRequestDecodeError::MissingMergeTicketArtifact
            | FullVerificationWitnessRequestDecodeError::InvalidBarrierUpdateReason
            | FullVerificationWitnessRequestDecodeError::InvalidRevocationRootsHash
            | FullVerificationWitnessRequestDecodeError::InvalidRevocationTargetLeafId
            | FullVerificationWitnessRequestDecodeError::HistoryCommitment(_) => {
                ApiError::InvalidRequest(error.api_message())
            }
        })?;
    let witness = {
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        runtime_prepare_full_verification_witness(
            &mut guard,
            &gid,
            witness_request,
            API_PROFILE_VERSION,
        )
        .map_err(|err| {
            map_full_verification_witness_preparation_error(
                "barrier_issue_full_verification_witness",
                err,
            )
        })?
    };

    Ok(protobuf_response_bytes(
        encode_full_verification_witness_response(witness),
    ))
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
    let gid = parse_gid(&request.room_id)?;
    enforce_expensive_rate_limit(
        &state,
        "barrier_resolve_revoked_leaves",
        message_scoped_rate_limit_key(&headers, &gid),
    )
    .await?;
    let request = schema_decode_barrier_resolve_revoked_leaves_request(request).map_err(
        |error| match error {
            BarrierHelperRequestDecodeError::InvalidRevocationRootsHash => {
                ApiError::InvalidRequest(error.api_message())
            }
            BarrierHelperRequestDecodeError::InvalidKemTreeHashAfter
            | BarrierHelperRequestDecodeError::InvalidPendingBarrierUpdateDigest
            | BarrierHelperRequestDecodeError::InvalidPendingWeEpochId => {
                unreachable!("resolve_revoked_leaves decoder returned unrelated error")
            }
        },
    )?;

    let prepared = {
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        runtime_prepare_resolved_revoked_leaves(
            &mut guard,
            &gid,
            &request.revocation_roots_hash,
            request.page_offset,
            request.max_entries,
            MAX_BARRIER_HELPER_PAGE_ENTRIES,
            API_PROFILE_VERSION,
        )
        .map_err(|err| {
            map_room_barrier_helper_preparation_error("barrier_resolve_revoked_leaves", err)
        })?
    };
    Ok(protobuf_response_bytes(
        encode_prepared_resolved_revoked_leaves_response(prepared),
    ))
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
    enforce_expensive_rate_limit(
        &state,
        "barrier_resolve_joins_since",
        message_scoped_rate_limit_key(&headers, &gid),
    )
    .await?;

    let prepared = {
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        runtime_prepare_resolved_joins(
            &mut guard,
            &gid,
            request.prev_barrier_version,
            request.page_offset,
            request.max_entries,
            MAX_BARRIER_HELPER_PAGE_ENTRIES,
            API_PROFILE_VERSION,
        )
        .map_err(|err| {
            map_room_barrier_helper_preparation_error("barrier_resolve_joins_since", err)
        })?
    };
    Ok(protobuf_response_bytes(
        encode_prepared_resolved_joins_response(prepared),
    ))
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
    let gid = parse_gid(&request.room_id)?;
    enforce_expensive_rate_limit(
        &state,
        "barrier_fetch_public_tree",
        message_scoped_rate_limit_key(&headers, &gid),
    )
    .await?;
    let request =
        schema_decode_barrier_fetch_public_tree_request(request).map_err(|error| match error {
            BarrierHelperRequestDecodeError::InvalidKemTreeHashAfter => {
                ApiError::InvalidRequest(error.api_message())
            }
            BarrierHelperRequestDecodeError::InvalidRevocationRootsHash
            | BarrierHelperRequestDecodeError::InvalidPendingBarrierUpdateDigest
            | BarrierHelperRequestDecodeError::InvalidPendingWeEpochId => {
                unreachable!("fetch_public_tree decoder returned unrelated error")
            }
        })?;

    let prepared = {
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        runtime_prepare_barrier_public_tree(
            &mut guard,
            &gid,
            &request.kem_tree_hash_after,
            request.entry_offset,
            request.max_entries,
            MAX_BARRIER_HELPER_PAGE_ENTRIES,
            API_PROFILE_VERSION,
        )
        .map_err(|err| {
            map_room_barrier_helper_preparation_error("barrier_fetch_public_tree", err)
        })?
    };
    Ok(protobuf_response_bytes(
        encode_prepared_barrier_public_tree_response(prepared),
    ))
}

async fn barrier_lookup_merge_acceptance(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let request = BarrierLookupMergeAcceptanceRequest::decode(body)?;
    if request.room_id.is_empty() {
        return Err(ApiError::InvalidRequest("room_id must be provided"));
    }
    let gid = parse_gid(&request.room_id)?;
    enforce_expensive_rate_limit(
        &state,
        "barrier_lookup_merge_acceptance",
        message_scoped_rate_limit_key(&headers, request.pending_we_epoch_id.as_slice()),
    )
    .await?;
    let request = schema_decode_barrier_lookup_merge_acceptance_request(request).map_err(
        |error| match error {
            BarrierHelperRequestDecodeError::InvalidPendingBarrierUpdateDigest
            | BarrierHelperRequestDecodeError::InvalidPendingWeEpochId => {
                ApiError::InvalidRequest(error.api_message())
            }
            BarrierHelperRequestDecodeError::InvalidRevocationRootsHash
            | BarrierHelperRequestDecodeError::InvalidKemTreeHashAfter => {
                unreachable!("lookup_merge_acceptance decoder returned unrelated error")
            }
        },
    )?;

    let prepared = {
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        runtime_prepare_merge_acceptance_lookup(
            &mut guard,
            &gid,
            request.pending_barrier_version,
            &request.pending_barrier_update_digest,
            &request.pending_we_epoch_id,
            API_PROFILE_VERSION,
        )
        .map_err(|err| {
            map_room_barrier_helper_preparation_error("barrier_lookup_merge_acceptance", err)
        })?
    };
    Ok(protobuf_response_bytes(
        encode_prepared_merge_acceptance_lookup_response(prepared),
    ))
}

async fn send_message(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let request = schema_validate_send_message_request(SendMessageRequest::decode(body)?)
        .map_err(map_send_message_request_validation_error)?;
    let timestamp_ms = current_timestamp_ms();
    let scope = {
        let epoch_scope = state
            .epoch_scope_for_weid(&request.we_epoch_id)
            .await
            .ok_or(ApiError::NotFound)?;
        let lane = state.server_for_gid(&epoch_scope.gid);
        let guard = lane.read().await;
        let mut room_state = state.room_state.write().await;
        runtime_store_room_message(
            &guard,
            &mut room_state,
            request.we_epoch_id,
            request.sender_leaf,
            request.ciphertext,
            request.sender,
            timestamp_ms,
            state.message_retention,
            MESSAGE_PRUNE_INTERVAL_MS,
        )
        .map_err(|error| match error {
            RoomMessageStoreError::NotFound => ApiError::NotFound,
            RoomMessageStoreError::EpochUnauthorized => {
                ApiError::Unauthorized("leaf is not a member for epoch")
            }
            RoomMessageStoreError::RoomUnauthorized => {
                ApiError::Unauthorized("leaf is not a member for room")
            }
        })?
    };

    // Broadcast notification to WebSocket clients
    let notification = MessageNotification {
        gid: scope.gid,
        we_epoch_id: request.we_epoch_id,
        timestamp_ms,
    };
    state.broadcast_message(notification);

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
    let request = schema_validate_fetch_messages_request(FetchMessagesRequest::decode(body)?)
        .map_err(map_fetch_messages_request_validation_error)?;
    let now_ms = current_timestamp_ms();
    let scope = state
        .epoch_scope_for_weid(&request.we_epoch_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let lane = state.server_for_gid(&scope.gid);
    let guard = lane.read().await;
    let messages = {
        let mut room_state = state.room_state.write().await;
        runtime_fetch_room_messages(
            &guard,
            &mut room_state,
            &request.we_epoch_id,
            request.leaf_id,
            now_ms,
            state.message_retention,
            MESSAGE_PRUNE_INTERVAL_MS,
        )
        .map_err(|err| match err {
            RoomAuthorizationError::NotFound => ApiError::NotFound,
            RoomAuthorizationError::Unauthorized => {
                ApiError::Unauthorized("leaf is not a member for epoch")
            }
        })?
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
    headers: HeaderMap,
    Query(query): Query<WebSocketSubscriptionQuery>,
) -> Result<Response, ApiError> {
    enforce_message_auth_websocket(&headers, configured_message_auth_token().as_deref())?;
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
    enforce_expensive_rate_limit(
        &state,
        "get_bundle",
        message_scoped_rate_limit_key(&headers, &weid),
    )
    .await?;

    let now_ms = current_timestamp_ms();
    let bundle = {
        let mut room_state = state.room_state.write().await;
        runtime_fetch_room_bundle(
            &mut room_state,
            &weid,
            now_ms,
            state.message_retention,
            MESSAGE_PRUNE_INTERVAL_MS,
        )
    };
    let bytes = bundle.ok_or(ApiError::NotFound)?.bytes;

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
    enforce_expensive_rate_limit(
        &state,
        "get_window",
        message_scoped_rate_limit_key(&headers, b"window"),
    )
    .await?;
    let mut snapshot = Vec::new();
    for lane in state.all_server_lanes() {
        let guard = lane.read().await;
        snapshot.extend(runtime_snapshot_room_window(&guard));
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/x-protobuf")
        .body(axum::body::Body::from(encode_window_snapshot_response(
            snapshot,
        )))
        .expect("protobuf response builder"))
}

async fn get_telemetry(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_message_auth_header(&headers, configured_message_auth_token().as_deref())?;
    let _ = GetTelemetryRequest::decode(body)?;
    enforce_expensive_rate_limit(
        &state,
        "get_telemetry",
        message_scoped_rate_limit_key(&headers, b"telemetry"),
    )
    .await?;
    let mut report = Vec::new();
    for lane in state.all_server_lanes() {
        let guard = lane.read().await;
        report.extend(runtime_snapshot_room_telemetry(&guard));
    }

    let freeze_stats = state.freeze_stats().await;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/x-protobuf")
        .body(axum::body::Body::from(encode_telemetry_snapshot_response(
            report,
            freeze_stats,
        )))
        .expect("protobuf response builder"))
}

async fn configure_window(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    enforce_window_config_auth(&headers, configured_window_admin_token().as_deref())?;
    let request = ConfigureWindowRequest::decode(body)?;
    let update = runtime_parse_room_window_limit_update(request.h_max, request.ttl_ms)
        .map_err(|err| ApiError::InvalidRequest(err.api_message()))?;

    let (effective_h, effective_ttl) = {
        let mut effective: Option<(usize, Duration)> = None;
        for lane in state.all_server_lanes() {
            let mut guard = lane.write().await;
            let applied = runtime_apply_room_window_limit_update(&mut guard, update);
            if effective.is_none() {
                effective = Some((applied.h_max, applied.ttl));
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
            Arc::new(RwLock::new(server_from_cityg_config_for_lane(
                &config, lane_index, lane_count,
            )))
        })
        .collect();
    let server = server_lanes_vec.first().cloned().unwrap_or_else(|| {
        Arc::new(RwLock::new(server_from_cityg_config_for_lane(
            &config, 0, lane_count,
        )))
    });
    let server_lanes = Arc::new(server_lanes_vec);
    let message_retention = message_retention_from_config(&config);
    let accept_epoch_max_in_flight = configured_accept_epoch_max_in_flight();
    let join_ticket_max_in_flight = configured_join_ticket_max_in_flight();
    let expensive_rate_limit_burst = configured_expensive_rate_limit_burst();
    let expensive_rate_limit_window = configured_expensive_rate_limit_window();
    let expensive_rate_limit_max_keys = configured_expensive_rate_limit_max_keys();
    info!(
        "message retention window set to {}s (group execution lanes: {})",
        message_retention.as_secs(),
        lane_count
    );
    info!(
        "endpoint concurrency limits: accept_epoch={} join_ticket={}",
        accept_epoch_max_in_flight, join_ticket_max_in_flight
    );
    info!(
        "expensive endpoint rate limit: burst={} window={}s max_keys={}",
        expensive_rate_limit_burst,
        expensive_rate_limit_window.as_secs(),
        expensive_rate_limit_max_keys
    );
    // Create broadcast channel for WebSocket notifications (capacity from config)
    let (notification_tx, _) = broadcast::channel(config.server.websocket_capacity);

    let state = ApiState {
        server,
        server_lanes,
        room_state: Arc::new(RwLock::new(RoomVolatileState::default())),
        message_retention,
        fs_epoch_period_seconds: config.protocol.fs_policy.h_seconds.max(1),
        freeze_counts: Arc::new(RwLock::new(BTreeMap::new())),
        alias_registry: Arc::new(RwLock::new(AliasRegistry::default())),
        notification_tx,
        alias_rate_limiter: AliasRateLimiter::new(
            ALIAS_RATE_LIMIT_BURST,
            Duration::from_secs(ALIAS_RATE_LIMIT_WINDOW_SECS),
        ),
        merge_ticket_cache: Arc::new(RwLock::new(AHashMap::new())),
        accept_epoch_limiter: EndpointConcurrencyLimiter::new(accept_epoch_max_in_flight),
        join_ticket_limiter: EndpointConcurrencyLimiter::new(join_ticket_max_in_flight),
        expensive_request_limiter: RequestRateLimiter::with_max_keys(
            expensive_rate_limit_burst,
            expensive_rate_limit_window,
            expensive_rate_limit_max_keys,
        ),
    };
    if let Err(err) = rehydrate_persisted_bundle_indexes(&state, &config, lane_count).await {
        warn!("bundle/runtime index recovery failed: {err:#}");
    }

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
        .route("/v1/rooms/grant_admin", post(grant_room_admin))
        .route("/v1/rooms/revoke_admin", post(revoke_room_admin))
        .route("/v1/rooms/list_admins", post(list_room_admins))
        .route("/v1/rooms/expel_member_ticket", post(expel_member_ticket))
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
        .route(
            "/v1/barrier/issue_full_verification_witness",
            post(barrier_issue_full_verification_witness),
        )
        .route(
            "/v1/barrier/lookup_merge_acceptance",
            post(barrier_lookup_merge_acceptance),
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

    {
        let gid: [u8; 32] = bundle
            .gid()
            .try_into()
            .map_err(|_| ApiError::InvalidRequest("bundle gid must be 32 bytes"))?;
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        runtime_seed_room_window_head(&mut guard, &bundle).map_err(|err| match err {
            cityg_runtime::RoomWindowSeedError::InvalidGidLength => {
                ApiError::InvalidRequest("bundle gid must be 32 bytes")
            }
            cityg_runtime::RoomWindowSeedError::ComputeWindowId(message)
            | cityg_runtime::RoomWindowSeedError::AcceptHead(message) => {
                ApiError::server_message(message)
            }
        })?;
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
    let gid: [u8; 32] = bundle
        .gid()
        .try_into()
        .map_err(|_| ApiError::InvalidRequest("bundle gid must be 32 bytes"))?;
    enforce_expensive_rate_limit(
        &state,
        "refresh_pivot",
        message_scoped_rate_limit_key(&headers, &gid),
    )
    .await?;

    {
        let lane = state.server_for_gid(&gid);
        let mut guard = lane.write().await;
        runtime_refresh_room_pivot(&mut guard, &bundle).map_err(|err| match err {
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
    use ciborium::value::Integer;
    use cityg_api_client::{
        RoomAdminOperation, build_room_admin_leaf_pair_proof, build_room_admin_listing_proof,
        build_room_admin_proof, build_room_admin_target_proof, generate_room_admin_keypair,
    };
    use cityg_client::{
        CityGClient,
        demo::{DEMO_GID, demo_bundle},
        witness::SrxInputsOwned,
    };
    use cityg_config::CityGConfig;
    use cityg_runtime::should_prune as runtime_should_prune;
    use futures::{SinkExt, StreamExt};
    use msphf_core::MsphfError;
    use msphf_core::merkle::canonical_set_root;
    use msphf_core::params::{RLWE_CRS_ID_DEFAULT, RLWE_PARAMS_ID_MOCK};
    use msphf_orchestrator::{
        AnchorInstanceParts, DEFAULT_POLICY_VERSION, DEFAULT_PROOF_MODE, DEFAULT_VRF_ID,
        FsJoinInputs, FsMergeInputs, LeafIdMode, OrchestrationParams, PopKeypair, SrxMode,
        compute_leaf_id, hdr, lb,
    };
    use pqcrypto_dilithium::dilithium5::{self, SecretKey as MlDsaSecretKey};
    use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
    use prost::Message;
    use serde_bytes::ByteBuf;
    use serde_json::Value;
    use std::sync::atomic::AtomicU64;
    use std::sync::{Mutex, Once, OnceLock};

    fn server_from_config(cfg: &CityGConfig) -> CityGServer {
        server_from_cityg_config_for_lane(cfg, 0, 1)
    }

    fn test_api_state_with_seeded_lanes(lane_count: usize, seed_demo_room: bool) -> ApiState {
        let mut cfg = CityGConfig::default();
        cfg.server.seed_demo_room = seed_demo_room;
        let lane_count = lane_count.max(1);
        let lanes: Vec<Arc<RwLock<CityGServer>>> = (0..lane_count)
            .map(|lane_index| {
                Arc::new(RwLock::new(server_from_cityg_config_for_lane(
                    &cfg, lane_index, lane_count,
                )))
            })
            .collect();
        let server = lanes
            .first()
            .cloned()
            .expect("test lane set must contain at least one lane");
        ApiState {
            server: server.clone(),
            server_lanes: Arc::new(lanes),
            room_state: Arc::new(RwLock::new(RoomVolatileState::default())),
            message_retention: Duration::from_secs(DEFAULT_FS_MESSAGE_RETENTION_SECS),
            fs_epoch_period_seconds: cfg.protocol.fs_policy.h_seconds.max(1),
            freeze_counts: Arc::new(RwLock::new(BTreeMap::new())),
            alias_registry: Arc::new(RwLock::new(AliasRegistry::default())),
            notification_tx: broadcast::channel(8).0,
            alias_rate_limiter: AliasRateLimiter::new(
                ALIAS_RATE_LIMIT_BURST,
                Duration::from_secs(ALIAS_RATE_LIMIT_WINDOW_SECS),
            ),
            merge_ticket_cache: Arc::new(RwLock::new(AHashMap::new())),
            accept_epoch_limiter: EndpointConcurrencyLimiter::new(
                DEFAULT_ACCEPT_EPOCH_MAX_IN_FLIGHT,
            ),
            join_ticket_limiter: EndpointConcurrencyLimiter::new(DEFAULT_JOIN_TICKET_MAX_IN_FLIGHT),
            expensive_request_limiter: RequestRateLimiter::new(
                DEFAULT_EXPENSIVE_RATE_LIMIT_BURST,
                Duration::from_secs(DEFAULT_EXPENSIVE_RATE_LIMIT_WINDOW_SECS),
            ),
        }
    }

    fn test_api_state_with_lanes(lane_count: usize) -> ApiState {
        test_api_state_with_seeded_lanes(lane_count, true)
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
            room_state: Arc::new(RwLock::new(RoomVolatileState::default())),
            message_retention: Duration::from_secs(DEFAULT_FS_MESSAGE_RETENTION_SECS),
            fs_epoch_period_seconds: cfg.protocol.fs_policy.h_seconds.max(1),
            freeze_counts: Arc::new(RwLock::new(BTreeMap::new())),
            alias_registry: Arc::new(RwLock::new(AliasRegistry::default())),
            notification_tx: broadcast::channel(4).0,
            alias_rate_limiter: AliasRateLimiter::new(100, Duration::from_secs(60)),
            merge_ticket_cache: Arc::new(RwLock::new(AHashMap::new())),
            accept_epoch_limiter: EndpointConcurrencyLimiter::new(
                DEFAULT_ACCEPT_EPOCH_MAX_IN_FLIGHT,
            ),
            join_ticket_limiter: EndpointConcurrencyLimiter::new(DEFAULT_JOIN_TICKET_MAX_IN_FLIGHT),
            expensive_request_limiter: RequestRateLimiter::new(
                DEFAULT_EXPENSIVE_RATE_LIMIT_BURST,
                Duration::from_secs(DEFAULT_EXPENSIVE_RATE_LIMIT_WINDOW_SECS),
            ),
        }
    }

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock poisoned")
    }

    fn test_room_admin_kbroad_proof(
        operation: RoomAdminOperation,
        room_id: &str,
        kbroad_public: &[u8],
        pop_public_key: &[u8],
        pop_secret_key: &[u8],
    ) -> RoomAdminProof {
        let proof = build_room_admin_proof(
            operation,
            room_id,
            kbroad_public,
            pop_public_key,
            pop_secret_key,
        )
        .expect("build room admin proof");
        RoomAdminProof {
            pop_public_key: proof.pop_public_key,
            signature: proof.signature,
        }
    }

    fn test_room_admin_target_proof(
        operation: RoomAdminOperation,
        room_id: &str,
        target_pop_public_key: &[u8],
        pop_public_key: &[u8],
        pop_secret_key: &[u8],
    ) -> RoomAdminProof {
        let proof = build_room_admin_target_proof(
            operation,
            room_id,
            target_pop_public_key,
            pop_public_key,
            pop_secret_key,
        )
        .expect("build room admin target proof");
        RoomAdminProof {
            pop_public_key: proof.pop_public_key,
            signature: proof.signature,
        }
    }

    fn test_room_admin_listing_proof(
        room_id: &str,
        pop_public_key: &[u8],
        pop_secret_key: &[u8],
    ) -> RoomAdminProof {
        let proof = build_room_admin_listing_proof(room_id, pop_public_key, pop_secret_key)
            .expect("build room admin listing proof");
        RoomAdminProof {
            pop_public_key: proof.pop_public_key,
            signature: proof.signature,
        }
    }

    fn test_room_admin_leaf_pair_proof(
        operation: RoomAdminOperation,
        room_id: &str,
        author_leaf_id: &[u8; 32],
        target_leaf_id: &[u8; 32],
        pop_public_key: &[u8],
        pop_secret_key: &[u8],
    ) -> RoomAdminProof {
        let proof = build_room_admin_leaf_pair_proof(
            operation,
            room_id,
            author_leaf_id,
            target_leaf_id,
            pop_public_key,
            pop_secret_key,
        )
        .expect("build room admin leaf-pair proof");
        RoomAdminProof {
            pop_public_key: proof.pop_public_key,
            signature: proof.signature,
        }
    }

    fn test_identity_binding(
        alias: &str,
        pop_public_key: &[u8],
        pop_secret_key: &MlDsaSecretKey,
    ) -> IdentityBinding {
        let message_data = (
            ByteBuf::from(alias.as_bytes().to_vec()),
            ByteBuf::from(pop_public_key.to_vec()),
        );
        let mut message = Vec::new();
        ciborium::ser::into_writer(&message_data, &mut message)
            .expect("encode identity binding message");
        let signature = dilithium5::detached_sign(message.as_slice(), pop_secret_key);
        IdentityBinding {
            alias: alias.to_string(),
            pop_public_key: pop_public_key.to_vec(),
            signature: signature.as_bytes().to_vec(),
        }
    }

    fn demo_vrf_keys_for_seed(seed: u8) -> (Vec<u8>, Vec<u8>) {
        let params = lb::generate_parameters([seed; 32]).expect("generate demo VRF params");
        let (sk, pk) = lb::generate_keypair(&params, [seed.wrapping_add(1); 32])
            .expect("generate demo VRF keypair");
        (sk, pk)
    }

    fn build_join_bundle_from_response(
        ticket: &JoinTicketResponse,
        pop_public_key: &[u8],
        pop_secret_key: &MlDsaSecretKey,
        seed: u8,
    ) -> ClientEpochBundle {
        let gid: [u8; 32] = ticket.gid.as_slice().try_into().expect("join ticket gid");
        let cat: [u8; 32] = ticket.cat.as_slice().try_into().expect("join ticket cat");
        let parent_root: [u8; 32] = ticket
            .parent_root
            .as_slice()
            .try_into()
            .expect("join ticket parent_root");
        let revoked_root: [u8; 32] = ticket
            .revoked_root
            .as_slice()
            .try_into()
            .expect("join ticket revoked_root");
        let revoked_since_root: [u8; 32] = ticket
            .revoked_since_root
            .as_slice()
            .try_into()
            .expect("join ticket revoked_since_root");
        let tswe_salt_hash: [u8; 32] = ticket
            .tswe_salt_hash
            .as_slice()
            .try_into()
            .expect("join ticket tswe_salt_hash");
        let join_delta_root: [u8; 32] = ticket
            .join_delta_root
            .as_slice()
            .try_into()
            .expect("join ticket join_delta_root");
        let pox_r_commit: [u8; 32] = ticket
            .pox_r_commit
            .as_slice()
            .try_into()
            .expect("join ticket pox_r_commit");

        let srx_inputs = SrxInputsOwned::from_cbor(ticket.srx_cbor.as_slice())
            .expect("decode join ticket srx")
            .into_srx_inputs();
        let (vrf_secret_key, vrf_public_key) = demo_vrf_keys_for_seed(seed);
        let mut fs_state = msphf_orchestrator::ForwardSecrecyState::new([seed.wrapping_add(2); 32]);

        let mut header = BTreeMap::new();
        header.insert(
            hdr::HDR_KBROAD_ALG,
            ciborium::value::Value::Text("ml-kem-768".to_string()),
        );
        header.insert(
            hdr::HDR_KBROAD_PUB,
            ciborium::value::Value::Bytes(ticket.kbroad_public.clone()),
        );
        header.insert(
            hdr::HDR_BARRIER_VERSION,
            ciborium::value::Value::Integer(Integer::from(ticket.barrier_version)),
        );
        header.insert(
            hdr::HDR_BARRIER_LEAF_PK,
            ciborium::value::Value::Bytes(vec![0x42; 1_184]),
        );

        let parts = AnchorInstanceParts {
            gid: &gid,
            cat: &cat,
            tswe_salt_hash: &tswe_salt_hash,
            parent_root: &parent_root,
            join_delta_root: &join_delta_root,
            revoked_since_prev_root: &revoked_since_root,
            revoked_root: &revoked_root,
            pox_r_commit: Some(&pox_r_commit),
        };

        let params = OrchestrationParams {
            msphf_crs_id: if ticket.msphf_crs_id.is_empty() {
                RLWE_CRS_ID_DEFAULT
            } else {
                ticket.msphf_crs_id.as_str()
            },
            params_id: if ticket.msphf_params_id.is_empty() {
                RLWE_PARAMS_ID_MOCK
            } else {
                ticket.msphf_params_id.as_str()
            },
            srx: Some(srx_inputs),
            srx_mode: SrxMode::Complete,
            pop_keys: Some(PopKeypair {
                algorithm: "ML-DSA-65",
                public_key: pop_public_key,
                secret_key: pop_secret_key,
            }),
            leaf_id_mode: LeafIdMode::PerGroup,
            proof_mode: if ticket.proof_mode.is_empty() {
                DEFAULT_PROOF_MODE
            } else {
                ticket.proof_mode.as_str()
            },
            vrf_id: if ticket.vrf_id.is_empty() {
                DEFAULT_VRF_ID
            } else {
                ticket.vrf_id.as_str()
            },
            policy_version: if ticket.policy_version.is_empty() {
                DEFAULT_POLICY_VERSION
            } else {
                ticket.policy_version.as_str()
            },
            vrf_secret_key: Some(vrf_secret_key.as_slice()),
            vrf_public_key: Some(vrf_public_key.as_slice()),
            fs_policy_version: ticket.fs_policy_version.as_str(),
            fs_epoch_base_ts: ticket.fs_epoch_base_ts,
            barrier_version: ticket.barrier_version,
            fs_join: FsJoinInputs::default(),
            fs_merge: FsMergeInputs::default(),
        };

        let witness_bytes = if ticket.witness_cbor.is_empty() {
            None
        } else {
            Some(ticket.witness_cbor.as_slice())
        };
        let mut bundle =
            CityGClient::generate_epoch(header, parts, params, &mut fs_state, witness_bytes)
                .expect("generate join bundle from ticket");
        if !ticket.bootstrap_public.is_empty() {
            cityg_client::demo::attach_bootstrap(&mut bundle).expect("attach bootstrap envelope");
        }
        bundle
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

    #[test]
    fn configured_endpoint_concurrency_limits_use_env_or_default() {
        let _guard = env_lock();
        unsafe {
            std::env::remove_var(ACCEPT_EPOCH_MAX_IN_FLIGHT_ENV);
            std::env::remove_var(JOIN_TICKET_MAX_IN_FLIGHT_ENV);
        }
        assert_eq!(
            configured_accept_epoch_max_in_flight(),
            DEFAULT_ACCEPT_EPOCH_MAX_IN_FLIGHT
        );
        assert_eq!(
            configured_join_ticket_max_in_flight(),
            DEFAULT_JOIN_TICKET_MAX_IN_FLIGHT
        );

        unsafe {
            std::env::set_var(ACCEPT_EPOCH_MAX_IN_FLIGHT_ENV, "3");
            std::env::set_var(JOIN_TICKET_MAX_IN_FLIGHT_ENV, "5");
        }
        assert_eq!(configured_accept_epoch_max_in_flight(), 3);
        assert_eq!(configured_join_ticket_max_in_flight(), 5);

        unsafe {
            std::env::remove_var(ACCEPT_EPOCH_MAX_IN_FLIGHT_ENV);
            std::env::remove_var(JOIN_TICKET_MAX_IN_FLIGHT_ENV);
        }
    }

    #[tokio::test]
    async fn server_lane_helpers_fallback_when_lane_set_is_empty() {
        let cfg = CityGConfig::default();
        let server = Arc::new(RwLock::new(server_from_config(&cfg)));
        let state = ApiState {
            server: server.clone(),
            server_lanes: Arc::new(Vec::new()),
            room_state: Arc::new(RwLock::new(RoomVolatileState::default())),
            message_retention: Duration::from_secs(DEFAULT_FS_MESSAGE_RETENTION_SECS),
            fs_epoch_period_seconds: cfg.protocol.fs_policy.h_seconds.max(1),
            freeze_counts: Arc::new(RwLock::new(BTreeMap::new())),
            alias_registry: Arc::new(RwLock::new(AliasRegistry::default())),
            notification_tx: broadcast::channel(4).0,
            alias_rate_limiter: AliasRateLimiter::new(100, Duration::from_secs(60)),
            merge_ticket_cache: Arc::new(RwLock::new(AHashMap::new())),
            accept_epoch_limiter: EndpointConcurrencyLimiter::new(
                DEFAULT_ACCEPT_EPOCH_MAX_IN_FLIGHT,
            ),
            join_ticket_limiter: EndpointConcurrencyLimiter::new(DEFAULT_JOIN_TICKET_MAX_IN_FLIGHT),
            expensive_request_limiter: RequestRateLimiter::new(
                DEFAULT_EXPENSIVE_RATE_LIMIT_BURST,
                Duration::from_secs(DEFAULT_EXPENSIVE_RATE_LIMIT_WINDOW_SECS),
            ),
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
    fn admin_auth_policy_refuses_missing_token_even_with_insecure_flag() {
        let empty_headers = HeaderMap::new();
        assert!(matches!(
            enforce_admin_token_with_policy(&empty_headers, None, true),
            Err(ApiError::Unauthorized("admin token is not configured"))
        ));
        assert!(matches!(
            enforce_admin_token_with_policy(&empty_headers, None, false),
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

    #[test]
    fn websocket_message_auth_requires_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            MESSAGE_AUTH_HEADER,
            HeaderValue::from_static("header-token"),
        );
        assert!(enforce_message_auth_websocket(&headers, Some("header-token")).is_ok());
        let empty_headers = HeaderMap::new();
        assert!(matches!(
            enforce_message_auth_websocket(&empty_headers, Some("header-token")),
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
    async fn register_alias_coalesces_multiple_canonical_unicode_forms() {
        let state = test_api_state();
        let canonical = "Ångström";
        let variants = [
            "A\u{30A}ngström",
            "Ångstro\u{308}m",
            "A\u{30A}ngstro\u{308}m",
        ];
        let leaf = [0x5B; 32];
        let pop_key = vec![0x7D; 8];

        assert!(
            state
                .register_alias(variants[0], leaf, pop_key.clone())
                .await
                .expect("first canonical variant should register")
        );

        for variant in &variants[1..] {
            assert!(
                !state
                    .register_alias(variant, leaf, pop_key.clone())
                    .await
                    .expect("canonically equivalent alias should coalesce")
            );
        }

        let registry = state.alias_registry.read().await;
        assert_eq!(registry.len(), 1);
        assert!(registry.contains_key(canonical));
    }

    #[tokio::test]
    async fn record_member_revocations_prunes_metadata_weid_map_and_aliases() {
        let state = test_api_state();
        let leaf_a = [0xA1; 32];
        let leaf_b = [0xB2; 32];
        let weid_a = [0x01; 32];
        let weid_b = [0x02; 32];
        let key_a = vec![0xAA; 32];
        let key_b = vec![0xBB; 32];

        state.record_member_join(leaf_a, weid_a, 100).await;
        state.record_member_join(leaf_b, weid_b, 200).await;
        state
            .register_alias("alice", leaf_a, key_a.clone())
            .await
            .expect("register alice");
        state
            .register_alias("bob", leaf_b, key_b.clone())
            .await
            .expect("register bob");

        state.record_member_revocations(&[]).await;
        let indexes = state.room_state.read().await;
        assert_eq!(indexes.member_metadata().len(), 2);
        assert_eq!(indexes.weid_to_leaf().len(), 2);
        drop(indexes);
        assert_eq!(state.alias_registry.read().await.len(), 2);

        state.record_member_revocations(&[leaf_a]).await;
        let indexes = state.room_state.read().await;
        assert!(!indexes.member_metadata().contains_key(&leaf_a));
        assert!(indexes.member_metadata().contains_key(&leaf_b));
        assert!(!indexes.weid_to_leaf().values().any(|leaf| leaf == &leaf_a));
        assert!(indexes.weid_to_leaf().values().any(|leaf| leaf == &leaf_b));
        drop(indexes);

        // Alias for the revoked leaf must be unbound so the same alias
        // can rejoin with a new identity key.
        let registry = state.alias_registry.read().await;
        assert!(
            !registry.contains_key("alice"),
            "revoked member's alias must be unbound"
        );
        assert!(
            registry.contains_key("bob"),
            "non-revoked member's alias must remain"
        );
        drop(registry);

        // After revocation, re-registering the same alias with a new key must succeed.
        let new_key_a = vec![0xCC; 32];
        assert!(
            state
                .register_alias("alice", leaf_a, new_key_a)
                .await
                .expect("re-register alice after revocation"),
            "re-registration with new key must succeed as a fresh binding"
        );
    }

    #[tokio::test]
    async fn register_alias_updates_leaf_binding() {
        let server = Arc::new(RwLock::new(server_from_config(&CityGConfig::default())));
        let state = ApiState {
            server: server.clone(),
            server_lanes: Arc::new(vec![server]),
            room_state: Arc::new(RwLock::new(RoomVolatileState::default())),
            message_retention: Duration::from_secs(DEFAULT_FS_MESSAGE_RETENTION_SECS),
            fs_epoch_period_seconds: CityGConfig::default().protocol.fs_policy.h_seconds.max(1),
            freeze_counts: Arc::new(RwLock::new(BTreeMap::new())),
            alias_registry: Arc::new(RwLock::new(AliasRegistry::default())),
            notification_tx: broadcast::channel(4).0,
            alias_rate_limiter: AliasRateLimiter::new(100, Duration::from_secs(60)),
            merge_ticket_cache: Arc::new(RwLock::new(AHashMap::new())),
            accept_epoch_limiter: EndpointConcurrencyLimiter::new(
                DEFAULT_ACCEPT_EPOCH_MAX_IN_FLIGHT,
            ),
            join_ticket_limiter: EndpointConcurrencyLimiter::new(DEFAULT_JOIN_TICKET_MAX_IN_FLIGHT),
            expensive_request_limiter: RequestRateLimiter::new(
                DEFAULT_EXPENSIVE_RATE_LIMIT_BURST,
                Duration::from_secs(DEFAULT_EXPENSIVE_RATE_LIMIT_WINDOW_SECS),
            ),
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
            room_state: Arc::new(RwLock::new(RoomVolatileState::default())),
            message_retention: Duration::from_secs(DEFAULT_FS_MESSAGE_RETENTION_SECS),
            fs_epoch_period_seconds: cfg.protocol.fs_policy.h_seconds.max(1),
            freeze_counts: Arc::new(RwLock::new(BTreeMap::new())),
            alias_registry: Arc::new(RwLock::new(AliasRegistry::default())),
            notification_tx: broadcast::channel(4).0,
            alias_rate_limiter: AliasRateLimiter::new(100, Duration::from_secs(60)),
            merge_ticket_cache: Arc::new(RwLock::new(AHashMap::new())),
            accept_epoch_limiter: EndpointConcurrencyLimiter::new(
                DEFAULT_ACCEPT_EPOCH_MAX_IN_FLIGHT,
            ),
            join_ticket_limiter: EndpointConcurrencyLimiter::new(DEFAULT_JOIN_TICKET_MAX_IN_FLIGHT),
            expensive_request_limiter: RequestRateLimiter::new(
                DEFAULT_EXPENSIVE_RATE_LIMIT_BURST,
                Duration::from_secs(DEFAULT_EXPENSIVE_RATE_LIMIT_WINDOW_SECS),
            ),
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
                admin_proof: None,
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
                admin_proof: None,
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
                admin_proof: None,
            }),
        )
        .await
        .expect_err("wrong kbroad key length must fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("kbroad_public has unexpected length")
        ));

        let (admin_pop_public_key, admin_pop_secret_key) = generate_room_admin_keypair();
        let room_id = hex::encode([0x66u8; 32]);
        let kbroad_public = vec![0x33; ml_kem_public_key_bytes()];
        let response = bootstrap_room(
            State(state),
            room_admin_headers(),
            encode(BootstrapRoomRequest {
                room_id: room_id.clone(),
                kbroad_public: kbroad_public.clone(),
                admin_proof: Some(test_room_admin_kbroad_proof(
                    RoomAdminOperation::Bootstrap,
                    &room_id,
                    &kbroad_public,
                    &admin_pop_public_key,
                    &admin_pop_secret_key,
                )),
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
        let room_id = hex::encode(gid);
        let (admin_pop_public_key, admin_pop_secret_key) = generate_room_admin_keypair();
        let encode = |request: BootstrapRoomRequest| -> Bytes {
            let mut body = Vec::new();
            request.encode(&mut body).expect("encode bootstrap request");
            Bytes::from(body)
        };

        bootstrap_room(
            State(state.clone()),
            room_admin_headers(),
            encode(BootstrapRoomRequest {
                room_id: room_id.clone(),
                kbroad_public: kbroad_public.clone(),
                admin_proof: Some(test_room_admin_kbroad_proof(
                    RoomAdminOperation::Bootstrap,
                    &room_id,
                    &kbroad_public,
                    &admin_pop_public_key,
                    &admin_pop_secret_key,
                )),
            }),
        )
        .await
        .expect("initial bootstrap should succeed");

        let err = bootstrap_room(
            State(state),
            room_admin_headers(),
            encode(BootstrapRoomRequest {
                room_id: room_id.clone(),
                kbroad_public: kbroad_public.clone(),
                admin_proof: Some(test_room_admin_kbroad_proof(
                    RoomAdminOperation::Bootstrap,
                    &room_id,
                    &kbroad_public,
                    &admin_pop_public_key,
                    &admin_pop_secret_key,
                )),
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
    async fn bootstrap_room_requires_room_admin_proof() {
        let state = test_api_state();
        let encode = |request: BootstrapRoomRequest| -> Bytes {
            let mut body = Vec::new();
            request.encode(&mut body).expect("encode bootstrap request");
            Bytes::from(body)
        };

        let err = bootstrap_room(
            State(state),
            HeaderMap::new(),
            encode(BootstrapRoomRequest {
                room_id: hex::encode([0x88u8; 32]),
                kbroad_public: vec![0x55; ml_kem_public_key_bytes()],
                admin_proof: None,
            }),
        )
        .await
        .expect_err("missing proof must fail");
        assert!(matches!(
            err,
            ApiError::Unauthorized("room admin proof is required")
        ));
    }

    #[tokio::test]
    async fn rotate_room_kbroad_validates_requests_and_updates_generation() {
        let state = test_api_state();
        let headers = room_admin_headers();
        let (admin_pop_public_key, admin_pop_secret_key) = generate_room_admin_keypair();
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
                admin_proof: None,
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
                admin_proof: None,
            }),
        )
        .await
        .expect_err("invalid key length must fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("kbroad_public has unexpected length")
        ));

        let room_id = hex::encode([0x97u8; 32]);
        let initial_kbroad = vec![0x31; ml_kem_public_key_bytes()];
        bootstrap_room(
            State(state.clone()),
            HeaderMap::new(),
            encode_proto_request(&BootstrapRoomRequest {
                room_id: room_id.clone(),
                kbroad_public: initial_kbroad.clone(),
                admin_proof: Some(test_room_admin_kbroad_proof(
                    RoomAdminOperation::Bootstrap,
                    &room_id,
                    &initial_kbroad,
                    &admin_pop_public_key,
                    &admin_pop_secret_key,
                )),
            }),
        )
        .await
        .expect("bootstrap should succeed");

        let mut rotated = initial_kbroad.clone();
        rotated[0] ^= 0x3C;
        let response = rotate_room_kbroad(
            State(state.clone()),
            headers.clone(),
            encode(RotateRoomKbroadRequest {
                room_id: room_id.clone(),
                kbroad_public: rotated.clone(),
                admin_proof: Some(test_room_admin_kbroad_proof(
                    RoomAdminOperation::RotateKbroad,
                    &room_id,
                    &rotated,
                    &admin_pop_public_key,
                    &admin_pop_secret_key,
                )),
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
                room_id: room_id.clone(),
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
        assert_eq!(decoded.provisioning_nonce.len(), 32);
        assert!(decoded.provisioning_expires_at_ms >= decoded.provisioning_issued_at_ms);
        assert!(!decoded.provisioning_artifact.is_empty());
        assert!(!decoded.deployment_profile_manifest.is_empty());
        assert!(decoded.n_max.is_power_of_two());
        assert!(decoded.max_barrier_update_bytes > 0);
    }

    #[tokio::test]
    async fn rotate_room_kbroad_rejects_rooms_without_explicit_admin_acl() {
        let state = test_api_state();
        let headers = room_admin_headers();
        let (admin_pop_public_key, admin_pop_secret_key) = generate_room_admin_keypair();
        let room_id = hex::encode(DEMO_GID);
        let mut rotated = cityg_client::demo::kbroad_public().to_vec();
        rotated[0] ^= 0x22;

        let err = rotate_room_kbroad(
            State(state),
            headers,
            encode_proto_request(&RotateRoomKbroadRequest {
                room_id: room_id.clone(),
                kbroad_public: rotated.clone(),
                admin_proof: Some(test_room_admin_kbroad_proof(
                    RoomAdminOperation::RotateKbroad,
                    &room_id,
                    &rotated,
                    &admin_pop_public_key,
                    &admin_pop_secret_key,
                )),
            }),
        )
        .await
        .expect_err("registry-only room must reject manual room-admin rotation");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("room admin proof is not authorized")
        ));
    }

    #[tokio::test]
    async fn rotate_room_kbroad_maps_server_invalid_input_paths() {
        let state = test_api_state();
        let headers = room_admin_headers();
        let (admin_pop_public_key, admin_pop_secret_key) = generate_room_admin_keypair();
        let encode = |request: RotateRoomKbroadRequest| -> Bytes {
            let mut body = Vec::new();
            request.encode(&mut body).expect("encode rotate request");
            Bytes::from(body)
        };

        let missing_gid = [0xEEu8; 32];
        let missing_room_id = hex::encode(missing_gid);
        let missing_err = rotate_room_kbroad(
            State(state.clone()),
            headers.clone(),
            encode(RotateRoomKbroadRequest {
                room_id: missing_room_id.clone(),
                kbroad_public: vec![0x22; ml_kem_public_key_bytes()],
                admin_proof: Some(test_room_admin_kbroad_proof(
                    RoomAdminOperation::RotateKbroad,
                    &missing_room_id,
                    &vec![0x22; ml_kem_public_key_bytes()],
                    &admin_pop_public_key,
                    &admin_pop_secret_key,
                )),
            }),
        )
        .await
        .expect_err("missing room should fail");
        assert!(matches!(
            missing_err,
            ApiError::InvalidRequest("kbroad key missing")
        ));

        let room_id = hex::encode([0x98u8; 32]);
        let initial_kbroad = vec![0x51; ml_kem_public_key_bytes()];
        bootstrap_room(
            State(state.clone()),
            HeaderMap::new(),
            encode_proto_request(&BootstrapRoomRequest {
                room_id: room_id.clone(),
                kbroad_public: initial_kbroad.clone(),
                admin_proof: Some(test_room_admin_kbroad_proof(
                    RoomAdminOperation::Bootstrap,
                    &room_id,
                    &initial_kbroad,
                    &admin_pop_public_key,
                    &admin_pop_secret_key,
                )),
            }),
        )
        .await
        .expect("bootstrap should succeed");

        let unchanged_err = rotate_room_kbroad(
            State(state),
            headers,
            encode(RotateRoomKbroadRequest {
                room_id: room_id.clone(),
                kbroad_public: initial_kbroad.clone(),
                admin_proof: Some(test_room_admin_kbroad_proof(
                    RoomAdminOperation::RotateKbroad,
                    &room_id,
                    &initial_kbroad,
                    &admin_pop_public_key,
                    &admin_pop_secret_key,
                )),
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
    async fn rotate_room_kbroad_rejects_non_admin_proof() {
        let state = test_api_state();
        let encode = |request: RotateRoomKbroadRequest| -> Bytes {
            let mut body = Vec::new();
            request.encode(&mut body).expect("encode rotate request");
            Bytes::from(body)
        };
        let room_id = hex::encode([0x99u8; 32]);
        let initial_kbroad_public = vec![0x41; ml_kem_public_key_bytes()];
        let rotated_kbroad_public = vec![0x42; ml_kem_public_key_bytes()];
        let (creator_pop_public_key, creator_pop_secret_key) = generate_room_admin_keypair();
        bootstrap_room(
            State(state.clone()),
            HeaderMap::new(),
            encode_proto_request(&BootstrapRoomRequest {
                room_id: room_id.clone(),
                kbroad_public: initial_kbroad_public.clone(),
                admin_proof: Some(test_room_admin_kbroad_proof(
                    RoomAdminOperation::Bootstrap,
                    &room_id,
                    &initial_kbroad_public,
                    &creator_pop_public_key,
                    &creator_pop_secret_key,
                )),
            }),
        )
        .await
        .expect("bootstrap should succeed");

        let (other_pop_public_key, other_pop_secret_key) = generate_room_admin_keypair();
        let err = rotate_room_kbroad(
            State(state),
            HeaderMap::new(),
            encode(RotateRoomKbroadRequest {
                room_id: room_id.clone(),
                kbroad_public: rotated_kbroad_public.clone(),
                admin_proof: Some(test_room_admin_kbroad_proof(
                    RoomAdminOperation::RotateKbroad,
                    &room_id,
                    &rotated_kbroad_public,
                    &other_pop_public_key,
                    &other_pop_secret_key,
                )),
            }),
        )
        .await
        .expect_err("non-admin proof must fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("room admin proof is not authorized")
        ));
    }

    #[tokio::test]
    async fn grant_revoke_and_list_room_admins_require_valid_admin_proofs() {
        let state = test_api_state();
        let room_id = hex::encode([0xA1u8; 32]);
        let kbroad_public = vec![0x41; ml_kem_public_key_bytes()];
        let (creator_pop_public_key, creator_pop_secret_key) = generate_room_admin_keypair();
        let (delegate_pop_public_key, delegate_pop_secret_key) = generate_room_admin_keypair();
        let (other_pop_public_key, other_pop_secret_key) = generate_room_admin_keypair();

        bootstrap_room(
            State(state.clone()),
            HeaderMap::new(),
            encode_proto_request(&BootstrapRoomRequest {
                room_id: room_id.clone(),
                kbroad_public: kbroad_public.clone(),
                admin_proof: Some(test_room_admin_kbroad_proof(
                    RoomAdminOperation::Bootstrap,
                    &room_id,
                    &kbroad_public,
                    &creator_pop_public_key,
                    &creator_pop_secret_key,
                )),
            }),
        )
        .await
        .expect("bootstrap should succeed");

        let missing_proof_err = grant_room_admin(
            State(state.clone()),
            encode_proto_request(&RoomAdminMutationRequest {
                room_id: room_id.clone(),
                target_pop_public_key: delegate_pop_public_key.clone(),
                admin_proof: None,
            }),
        )
        .await
        .expect_err("missing proof must fail");
        assert!(matches!(
            missing_proof_err,
            ApiError::Unauthorized("room admin proof is required")
        ));

        let unauthorized_err = grant_room_admin(
            State(state.clone()),
            encode_proto_request(&RoomAdminMutationRequest {
                room_id: room_id.clone(),
                target_pop_public_key: delegate_pop_public_key.clone(),
                admin_proof: Some(test_room_admin_target_proof(
                    RoomAdminOperation::GrantAdmin,
                    &room_id,
                    &delegate_pop_public_key,
                    &other_pop_public_key,
                    &other_pop_secret_key,
                )),
            }),
        )
        .await
        .expect_err("non-admin proof must fail");
        assert!(matches!(
            unauthorized_err,
            ApiError::InvalidRequest("room admin proof is not authorized")
        ));

        let initial_grant_request = RoomAdminMutationRequest {
            room_id: room_id.clone(),
            target_pop_public_key: delegate_pop_public_key.clone(),
            admin_proof: Some(test_room_admin_target_proof(
                RoomAdminOperation::GrantAdmin,
                &room_id,
                &delegate_pop_public_key,
                &creator_pop_public_key,
                &creator_pop_secret_key,
            )),
        };
        let grant_response = grant_room_admin(
            State(state.clone()),
            encode_proto_request(&initial_grant_request),
        )
        .await
        .expect("grant should succeed");
        let granted: RoomAdminMutationResponse = decode_proto_response(grant_response).await;
        assert_eq!(granted.status, "granted");
        assert_eq!(granted.admin_count, 2);

        let list_response = list_room_admins(
            State(state.clone()),
            encode_proto_request(&ListRoomAdminsRequest {
                room_id: room_id.clone(),
                admin_proof: Some(test_room_admin_listing_proof(
                    &room_id,
                    &delegate_pop_public_key,
                    &creator_pop_secret_key,
                )),
            }),
        )
        .await
        .expect_err("mismatched list proof must fail");
        assert!(matches!(
            list_response,
            ApiError::InvalidRequest("room admin proof verification failed")
        ));

        let list_response = list_room_admins(
            State(state.clone()),
            encode_proto_request(&ListRoomAdminsRequest {
                room_id: room_id.clone(),
                admin_proof: Some(test_room_admin_listing_proof(
                    &room_id,
                    &delegate_pop_public_key,
                    &delegate_pop_secret_key,
                )),
            }),
        )
        .await
        .expect("delegate should be able to list admins");
        let listed: ListRoomAdminsResponse = decode_proto_response(list_response).await;
        assert_eq!(listed.admin_pop_public_keys.len(), 2);
        let listed_admins: std::collections::BTreeSet<Vec<u8>> =
            listed.admin_pop_public_keys.into_iter().collect();
        assert!(listed_admins.contains(&creator_pop_public_key));
        assert!(listed_admins.contains(&delegate_pop_public_key));

        let revoke_response = revoke_room_admin(
            State(state.clone()),
            encode_proto_request(&RoomAdminMutationRequest {
                room_id: room_id.clone(),
                target_pop_public_key: delegate_pop_public_key.clone(),
                admin_proof: Some(test_room_admin_target_proof(
                    RoomAdminOperation::RevokeAdmin,
                    &room_id,
                    &delegate_pop_public_key,
                    &creator_pop_public_key,
                    &creator_pop_secret_key,
                )),
            }),
        )
        .await
        .expect("revoke should succeed");
        let revoked: RoomAdminMutationResponse = decode_proto_response(revoke_response).await;
        assert_eq!(revoked.status, "revoked");
        assert_eq!(revoked.admin_count, 1);

        let replay_grant_err = grant_room_admin(
            State(state.clone()),
            encode_proto_request(&initial_grant_request),
        )
        .await
        .expect_err("replayed grant proof must stay rejected after revocation");
        assert!(matches!(
            replay_grant_err,
            ApiError::InvalidRequest("room admin proof replayed")
        ));

        let revoke_last_err = revoke_room_admin(
            State(state),
            encode_proto_request(&RoomAdminMutationRequest {
                room_id,
                target_pop_public_key: creator_pop_public_key.clone(),
                admin_proof: Some(test_room_admin_target_proof(
                    RoomAdminOperation::RevokeAdmin,
                    &hex::encode([0xA1u8; 32]),
                    &creator_pop_public_key,
                    &creator_pop_public_key,
                    &creator_pop_secret_key,
                )),
            }),
        )
        .await
        .expect_err("last admin revoke must fail");
        assert!(matches!(
            revoke_last_err,
            ApiError::InvalidRequest("cannot revoke the last room admin")
        ));
    }

    #[tokio::test]
    async fn expel_member_ticket_validates_request_shape() {
        let state = test_api_state();
        let room_id = hex::encode(DEMO_GID);
        let author_leaf = cityg_client::demo::demo_member_leaf("alice");
        let target_leaf = cityg_client::demo::demo_member_leaf("bob");
        let (admin_pop_public_key, admin_pop_secret_key) = generate_room_admin_keypair();

        let missing_proof_err = expel_member_ticket(
            State(state.clone()),
            encode_proto_request(&ExpelMemberTicketRequest {
                room_id: room_id.clone(),
                author_leaf_id: author_leaf.to_vec(),
                target_leaf_id: target_leaf.to_vec(),
                admin_proof: None,
            }),
        )
        .await
        .expect_err("missing proof must fail");
        assert!(matches!(
            missing_proof_err,
            ApiError::Unauthorized("room admin proof is required")
        ));

        let bad_author_len_err = expel_member_ticket(
            State(state.clone()),
            encode_proto_request(&ExpelMemberTicketRequest {
                room_id: room_id.clone(),
                author_leaf_id: vec![0xAA; 31],
                target_leaf_id: target_leaf.to_vec(),
                admin_proof: Some(test_room_admin_leaf_pair_proof(
                    RoomAdminOperation::ExpelMember,
                    &room_id,
                    &author_leaf,
                    &target_leaf,
                    &admin_pop_public_key,
                    &admin_pop_secret_key,
                )),
            }),
        )
        .await
        .expect_err("invalid author leaf length must fail");
        assert!(matches!(
            bad_author_len_err,
            ApiError::InvalidRequest("author_leaf_id must be 32 bytes")
        ));

        let bad_target_len_err = expel_member_ticket(
            State(state.clone()),
            encode_proto_request(&ExpelMemberTicketRequest {
                room_id: room_id.clone(),
                author_leaf_id: author_leaf.to_vec(),
                target_leaf_id: vec![0xBB; 31],
                admin_proof: Some(test_room_admin_leaf_pair_proof(
                    RoomAdminOperation::ExpelMember,
                    &room_id,
                    &author_leaf,
                    &target_leaf,
                    &admin_pop_public_key,
                    &admin_pop_secret_key,
                )),
            }),
        )
        .await
        .expect_err("invalid target leaf length must fail");
        assert!(matches!(
            bad_target_len_err,
            ApiError::InvalidRequest("target_leaf_id must be 32 bytes")
        ));

        let self_target_err = expel_member_ticket(
            State(state),
            encode_proto_request(&ExpelMemberTicketRequest {
                room_id,
                author_leaf_id: author_leaf.to_vec(),
                target_leaf_id: author_leaf.to_vec(),
                admin_proof: Some(test_room_admin_leaf_pair_proof(
                    RoomAdminOperation::ExpelMember,
                    &hex::encode(DEMO_GID),
                    &author_leaf,
                    &author_leaf,
                    &admin_pop_public_key,
                    &admin_pop_secret_key,
                )),
            }),
        )
        .await
        .expect_err("self-targeted expel request must fail");
        assert!(matches!(
            self_target_err,
            ApiError::InvalidRequest(
                "author_leaf_id and target_leaf_id must differ; use controlled leave instead"
            )
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
        assert_eq!(decoded.current_history_view_id.len(), 32);
        assert!(decoded.current_history_commitment.is_some());
        assert!(!decoded.merge_ticket_artifact.is_empty());
        assert!(!decoded.deployment_profile_manifest.is_empty());
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
        assert_eq!(refresh_decoded.current_history_view_id.len(), 32);
        assert!(refresh_decoded.current_history_commitment.is_some());
        assert!(!refresh_decoded.merge_ticket_artifact.is_empty());
        assert!(!refresh_decoded.deployment_profile_manifest.is_empty());
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
            let room_id = hex::encode(gid);
            let kbroad_public = vec![seed; ml_kem_public_key_bytes()];
            let (pop_public_key, pop_secret_key) = generate_room_admin_keypair();
            let request = BootstrapRoomRequest {
                room_id: room_id.clone(),
                kbroad_public: kbroad_public.clone(),
                admin_proof: Some(test_room_admin_kbroad_proof(
                    RoomAdminOperation::Bootstrap,
                    &room_id,
                    &kbroad_public,
                    &pop_public_key,
                    &pop_secret_key,
                )),
            };
            bootstrap_room(
                State(state.clone()),
                HeaderMap::new(),
                encode_proto_request(&request),
            )
            .await
            .expect("bootstrap extra room for contention test");
            room_ids.push(room_id);
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
        let expected_history_authority_descriptor = {
            let guard = state.server.read().await;
            guard
                .history_authority_descriptor_bytes()
                .expect("history authority descriptor bytes")
        };

        let mut bad_body = Vec::new();
        BarrierResolveJoinsSinceRequest {
            room_id: String::new(),
            prev_barrier_version: 0,
            ..BarrierResolveJoinsSinceRequest::default()
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
            ..BarrierResolveJoinsSinceRequest::default()
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
        assert!(decoded.history_commitment.is_some());
        let first = &decoded.records[0];
        assert!(first.leaf_index > 0);
        assert!(!first.device_pk.is_empty());
        assert!(
            first.ek_leaf.is_empty() || first.ek_leaf.len() == ml_kem_public_key_bytes(),
            "ek_leaf should be absent or ML-KEM-768 size"
        );
        assert_eq!(
            decoded.history_authority_descriptor,
            expected_history_authority_descriptor
        );
        assert!(
            !decoded.global_history_attestation.is_empty(),
            "joins-since response should carry global history attestation under base-profile global authority"
        );
        assert!(
            !decoded.helper_completeness_attestation.is_empty(),
            "joins-since response should carry helper completeness attestation under base-profile global authority"
        );
        assert_eq!(decoded.profile_version, API_PROFILE_VERSION);
        assert!(decoded.n_max > 0);
        assert!(decoded.max_barrier_update_bytes > 0);
        assert!(decoded.fs_forward_leap_policy.is_some());
        assert!(
            !decoded.deployment_profile_manifest.is_empty(),
            "joins-since response should carry deployment_profile_manifest under base-profile global authority"
        );
    }

    #[tokio::test]
    async fn barrier_tree_and_revoked_leaves_endpoints_validate_inputs() {
        let state = test_api_state();
        let headers = message_auth_headers();
        let alice = demo_bundle("alice").expect("alice demo bundle");

        let (
            revocation_roots_hash,
            kem_tree_hash_after,
            n_max,
            expected_history_authority_descriptor,
        ) = {
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
                guard
                    .history_authority_descriptor_bytes()
                    .expect("history authority descriptor"),
            )
        };

        let mut bad_revoked_body = Vec::new();
        BarrierResolveRevokedLeavesRequest {
            room_id: String::new(),
            revocation_roots_hash: revocation_roots_hash.to_vec(),
            ..BarrierResolveRevokedLeavesRequest::default()
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
            ..BarrierResolveRevokedLeavesRequest::default()
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
            ..BarrierResolveRevokedLeavesRequest::default()
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
            ..BarrierResolveRevokedLeavesRequest::default()
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
        assert_eq!(
            revoked_decoded.history_authority_descriptor,
            expected_history_authority_descriptor
        );
        assert!(
            !revoked_decoded.global_history_attestation.is_empty(),
            "revoked-leaves response should carry global history attestation under base-profile global authority"
        );
        assert!(
            !revoked_decoded.helper_completeness_attestation.is_empty(),
            "revoked-leaves response should carry helper completeness attestation under base-profile global authority"
        );
        assert_eq!(revoked_decoded.profile_version, API_PROFILE_VERSION);
        assert!(revoked_decoded.n_max > 0);
        assert!(revoked_decoded.max_barrier_update_bytes > 0);
        assert!(revoked_decoded.fs_forward_leap_policy.is_some());
        assert!(
            !revoked_decoded.deployment_profile_manifest.is_empty(),
            "revoked-leaves response should carry deployment_profile_manifest under base-profile global authority"
        );

        let mut bad_tree_body = Vec::new();
        BarrierFetchPublicTreeRequest {
            room_id: String::new(),
            kem_tree_hash_after: kem_tree_hash_after.to_vec(),
            ..BarrierFetchPublicTreeRequest::default()
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
            ..BarrierFetchPublicTreeRequest::default()
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
            ..BarrierFetchPublicTreeRequest::default()
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
        assert!(tree_decoded.history_commitment.is_some());
        assert_eq!(
            tree_decoded.kem_tree_hash_after,
            kem_tree_hash_after.to_vec()
        );
        assert_eq!(
            tree_decoded.total_entries as u64,
            n_max.saturating_mul(2).saturating_sub(1)
        );
        assert_eq!(tree_decoded.entry_offset, 0);
        assert_eq!(tree_decoded.next_entry_offset, Some(512));
        assert_eq!(tree_decoded.pk_entries.len(), 512);
        assert_eq!(
            tree_decoded.history_authority_descriptor,
            expected_history_authority_descriptor
        );
        assert!(
            !tree_decoded.global_history_attestation.is_empty(),
            "fetch-public-tree response should carry global history attestation under base-profile global authority"
        );
        assert!(
            !tree_decoded.helper_completeness_attestation.is_empty(),
            "fetch-public-tree response should carry helper completeness attestation under base-profile global authority"
        );
        assert_eq!(tree_decoded.profile_version, API_PROFILE_VERSION);
        assert!(tree_decoded.max_barrier_update_bytes > 0);
        assert!(tree_decoded.fs_forward_leap_policy.is_some());
        assert!(
            !tree_decoded.deployment_profile_manifest.is_empty(),
            "fetch-public-tree response should carry deployment_profile_manifest under base-profile global authority"
        );
        assert_eq!(
            tree_decoded.global_history_attestation, revoked_decoded.global_history_attestation,
            "current-state helper endpoints should agree on the current global history attestation"
        );

        let mut bad_tree_body = Vec::new();
        BarrierFetchPublicTreeRequest {
            room_id: hex::encode(DEMO_GID),
            kem_tree_hash_after: vec![0xFF; 32],
            ..BarrierFetchPublicTreeRequest::default()
        }
        .encode(&mut bad_tree_body)
        .expect("encode bad barrier tree request");
        let err = barrier_fetch_public_tree(State(state), headers, Bytes::from(bad_tree_body))
            .await
            .expect_err("mismatched tree hash must fail");
        assert!(matches!(err, ApiError::NotFound));
    }

    #[tokio::test]
    async fn barrier_helper_endpoints_reject_page_size_above_limit() {
        let state = test_api_state();
        let headers = message_auth_headers();
        let alice = demo_bundle("alice").expect("alice demo bundle");

        let kem_tree_hash_after = {
            let mut guard = state.server.write().await;
            guard.accept_epoch(&alice).expect("accept alice");
            guard
                .barrier_kem_tree_hash_after(DEMO_GID.as_ref())
                .expect("barrier tree hash")
        };

        let mut body = Vec::new();
        BarrierFetchPublicTreeRequest {
            room_id: hex::encode(DEMO_GID),
            kem_tree_hash_after: kem_tree_hash_after.to_vec(),
            entry_offset: 0,
            max_entries: MAX_BARRIER_HELPER_PAGE_ENTRIES.saturating_add(1),
        }
        .encode(&mut body)
        .expect("encode oversized pagination request");
        let err = barrier_fetch_public_tree(State(state), headers, Bytes::from(body))
            .await
            .expect_err("oversized page size must fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("max_entries exceeds MAX_BARRIER_HELPER_PAGE_ENTRIES")
        ));
    }

    #[test]
    fn barrier_helper_error_mapping_preserves_not_found_and_invalid_request() {
        assert!(matches!(
            map_barrier_helper_error(ClientError::InvalidInput("group not found")),
            ApiError::NotFound
        ));
        assert!(matches!(
            map_barrier_helper_error(ClientError::InvalidInput(
                "historical barrier public tree snapshot unavailable"
            )),
            ApiError::NotFound
        ));
        assert!(matches!(
            map_barrier_helper_error(ClientError::InvalidInput(
                "revocation_roots_hash does not match committed barrier roots"
            )),
            ApiError::InvalidRequest(
                "revocation_roots_hash does not match committed barrier roots"
            )
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
    async fn bootstrapped_room_join_keeps_merge_ticket_refresh_available_across_lanes() {
        ensure_test_admin_tokens();
        let state = test_api_state_with_seeded_lanes(4, false);
        let headers = message_auth_headers();
        let gid = [0x91u8; 32];
        let room_id = hex::encode(gid);
        let kbroad_public = cityg_client::demo::kbroad_public().to_vec();
        let (admin_pop_public_key, admin_pop_secret_key) = generate_room_admin_keypair();

        bootstrap_room(
            State(state.clone()),
            HeaderMap::new(),
            encode_proto_request(&BootstrapRoomRequest {
                room_id: room_id.clone(),
                kbroad_public: kbroad_public.clone(),
                admin_proof: Some(test_room_admin_kbroad_proof(
                    RoomAdminOperation::Bootstrap,
                    room_id.as_str(),
                    kbroad_public.as_slice(),
                    admin_pop_public_key.as_slice(),
                    admin_pop_secret_key.as_slice(),
                )),
            }),
        )
        .await
        .expect("bootstrap room on routed lane");

        let routed_lane = state.server_for_gid(&gid);
        {
            let guard = routed_lane.read().await;
            assert!(
                guard
                    .context()
                    .kbroad_registry()
                    .and_then(|registry| registry.get(gid.as_slice()))
                    .is_some(),
                "bootstrap must register kbroad on the routed lane"
            );
        }

        let (pop_pk, pop_sk) = dilithium5::keypair();
        let alias = "alice-bootstrapped";
        let join_response = join_ticket(
            State(state.clone()),
            encode_proto_request(&JoinTicketRequest {
                room_id: room_id.clone(),
                alias: alias.to_string(),
                identity_binding: Some(test_identity_binding(alias, pop_pk.as_bytes(), &pop_sk)),
            }),
        )
        .await
        .expect("join ticket after bootstrap");
        let join_ticket_response: JoinTicketResponse = decode_proto_response(join_response).await;
        let join_bundle = build_join_bundle_from_response(
            &join_ticket_response,
            pop_pk.as_bytes(),
            &pop_sk,
            0x91,
        );
        accept_epoch(
            State(state.clone()),
            encode_proto_request(&AcceptEpochRequest {
                bundle_cbor: join_bundle.to_cbor().expect("join bundle cbor"),
            }),
        )
        .await
        .expect("accept first join into bootstrapped room");

        {
            let guard = routed_lane.read().await;
            assert!(
                guard
                    .context()
                    .kbroad_registry()
                    .and_then(|registry| registry.get(gid.as_slice()))
                    .is_some(),
                "accepted first join must not drop the room kbroad registry"
            );
        }

        let merge_response = merge_ticket(
            State(state),
            headers,
            encode_proto_request(&MergeTicketRequest {
                room_id,
                leaf_id: join_ticket_response.leaf_id.clone(),
                intent: MergeTicketIntent::Refresh as i32,
            }),
        )
        .await
        .expect("refresh merge ticket must remain available after first bootstrapped join");
        let merge_ticket_response: MergeTicketResponse =
            decode_proto_response(merge_response).await;
        assert_eq!(
            merge_ticket_response.kbroad_public, kbroad_public,
            "merge refresh must still expose the room kbroad key"
        );
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

        let err = send_message(
            State(state.clone()),
            headers.clone(),
            encode_proto_request(&SendMessageRequest {
                we_epoch_id: weid.to_vec(),
                ciphertext: vec![0xAA; MAX_MESSAGE_CIPHERTEXT_BYTES + 1],
                sender: leaf.to_vec(),
            }),
        )
        .await
        .expect_err("oversized ciphertext should fail");
        assert!(matches!(
            err,
            ApiError::InvalidRequest("ciphertext exceeds MAX_PAYLOAD_ENVELOPE_BYTES")
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

        let indexes = state.room_state.read().await;
        let member = indexes
            .member_metadata()
            .get(&leaf)
            .expect("member metadata");
        assert!(member.last_seen_timestamp_ms >= member.join_timestamp_ms);
        drop(indexes);

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
    async fn barrier_lookup_merge_acceptance_validates_pending_and_not_found() {
        let state = test_api_state();
        let headers = message_auth_headers();
        let gid = [0xA9; 32];

        {
            let lane = state.server_for_gid(&gid);
            let mut guard = lane.write().await;
            guard
                .register_group(&gid, vec![0xAA; 16])
                .expect("group registration should succeed");
        }

        let pending = barrier_lookup_merge_acceptance(
            State(state.clone()),
            headers.clone(),
            encode_proto_request(&BarrierLookupMergeAcceptanceRequest {
                room_id: hex::encode(gid),
                pending_barrier_version: 11,
                pending_barrier_update_digest: vec![0xAB; 32],
                pending_we_epoch_id: vec![0xCD; 32],
            }),
        )
        .await
        .expect("registered group should return pending lookup");
        let pending: BarrierLookupMergeAcceptanceResponse = decode_proto_response(pending).await;
        assert_eq!(pending.status, MergeAcceptanceStatus::Pending as i32);
        assert_eq!(pending.accepted_barrier_version, None);
        assert_eq!(pending.accepted_fs_ec, None);
        assert_eq!(pending.accepted_reason, None);
        assert_eq!(pending.accepted_digest, None);
        assert_ne!(pending.history_view_id, vec![0u8; 32]);
        assert!(pending.history_commitment.is_some());
        assert_eq!(pending.profile_version, API_PROFILE_VERSION);
        assert!(pending.n_max > 0);
        assert!(pending.max_barrier_update_bytes > 0);
        assert!(pending.fs_forward_leap_policy.is_some());
        assert!(
            !pending.deployment_profile_manifest.is_empty(),
            "lookup response should carry deployment_profile_manifest under base-profile global authority"
        );

        let err = barrier_lookup_merge_acceptance(
            State(state),
            headers,
            encode_proto_request(&BarrierLookupMergeAcceptanceRequest {
                room_id: hex::encode([0xEE; 32]),
                pending_barrier_version: 11,
                pending_barrier_update_digest: vec![0xEE; 32],
                pending_we_epoch_id: vec![0xEF; 32],
            }),
        )
        .await
        .expect_err("unknown group should map to not found");
        assert!(matches!(err, ApiError::NotFound));
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
            "ws://{addr}/v1/ws?gid={}&leaf_id={}",
            hex::encode(DEMO_GID),
            hex::encode(leaf)
        );
        let mut request =
            tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(url)
                .expect("websocket auth request");
        request.headers_mut().insert(
            MESSAGE_AUTH_HEADER,
            tokio_tungstenite::tungstenite::http::HeaderValue::from_str(&token)
                .expect("valid websocket auth header"),
        );
        let (mut socket, _) = tokio_tungstenite::connect_async(request)
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
            "ws://{addr}/v1/ws?gid={}&leaf_id={}",
            hex::encode(DEMO_GID),
            hex::encode(leaf)
        );
        let mut request =
            tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(url)
                .expect("websocket auth request");
        request.headers_mut().insert(
            MESSAGE_AUTH_HEADER,
            tokio_tungstenite::tungstenite::http::HeaderValue::from_str(&token)
                .expect("valid websocket auth header"),
        );
        let (mut socket, _) = tokio_tungstenite::connect_async(request)
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

    #[tokio::test]
    async fn websocket_handler_rejects_legacy_query_token_auth() {
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
        assert!(
            tokio_tungstenite::connect_async(url).await.is_err(),
            "legacy query token auth must be rejected"
        );

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

        cityg_runtime::prune_expired_messages(&mut store, 10_000, Duration::from_secs(1));

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

        cityg_runtime::prune_expired_messages(&mut store, now_ms, Duration::from_secs(0));

        let retained = store.get(&weid).expect("weid should exist");
        assert_eq!(retained.len(), 1, "only exact-now message should remain");
        assert_eq!(retained[0].timestamp_ms, now_ms);
    }

    #[tokio::test]
    async fn store_bundle_bytes_prunes_expired_bundle_indexes() {
        let mut state = empty_test_api_state();
        state.message_retention = Duration::from_secs(1);

        let expired_weid = [0xD1; 32];
        let fresh_weid = [0xD2; 32];
        let expired_leaf = [0xE1; 32];
        state
            .record_epoch_scope(
                expired_weid,
                EpochScope {
                    gid: DEMO_GID,
                    membership_root: [0xAB; 32],
                },
            )
            .await;
        state
            .record_member_join(expired_leaf, expired_weid, 0)
            .await;
        {
            let mut room_state = state.room_state.write().await;
            room_state.store_bundle(
                expired_weid,
                StoredBundle {
                    bytes: vec![0xAA],
                    stored_at_ms: 0,
                },
                0,
                state.message_retention,
                MESSAGE_PRUNE_INTERVAL_MS,
            );
        }

        store_bundle_bytes(&state, fresh_weid, vec![0xBB]).await;

        let mut room_state = state.room_state.write().await;
        assert!(!room_state.contains_bundle(&expired_weid));
        let fresh = room_state
            .bundle(
                &fresh_weid,
                current_timestamp_ms(),
                state.message_retention,
                MESSAGE_PRUNE_INTERVAL_MS,
            )
            .expect("fresh bundle retained");
        assert_eq!(fresh.bytes, vec![0xBB]);
        drop(room_state);

        assert!(state.epoch_scope_for_weid(&expired_weid).await.is_none());
        let indexes = state.room_state.read().await;
        assert!(!indexes.weid_to_leaf().contains_key(&expired_weid));
    }

    #[tokio::test]
    async fn accept_epoch_returns_rate_limited_when_concurrency_budget_is_exhausted() {
        let mut state = empty_test_api_state();
        state.accept_epoch_limiter = EndpointConcurrencyLimiter::new(1);
        let _permit = state
            .accept_epoch_limiter
            .try_acquire()
            .expect("test should acquire the only permit");

        let result = accept_epoch(State(state), Bytes::new()).await;
        assert!(matches!(result, Err(ApiError::RateLimited)));
    }

    #[tokio::test]
    async fn join_ticket_returns_rate_limited_when_concurrency_budget_is_exhausted() {
        let mut state = empty_test_api_state();
        state.join_ticket_limiter = EndpointConcurrencyLimiter::new(1);
        let _permit = state
            .join_ticket_limiter
            .try_acquire()
            .expect("test should acquire the only permit");

        let request = JoinTicketRequest {
            room_id: hex::encode(DEMO_GID),
            alias: String::new(),
            identity_binding: None,
        };
        let result = join_ticket(State(state), encode_proto_request(&request)).await;
        assert!(matches!(result, Err(ApiError::RateLimited)));
    }

    #[tokio::test]
    async fn request_rate_limiter_allows_burst_then_rejects() {
        let limiter = RequestRateLimiter::with_max_keys(2, Duration::from_secs(60), 8);
        let key = fingerprint_rate_limit_parts(&[b"room-a"]);
        assert!(limiter.check_and_record("join_ticket", key).await);
        assert!(limiter.check_and_record("join_ticket", key).await);
        assert!(!limiter.check_and_record("join_ticket", key).await);
        assert!(
            limiter
                .check_and_record("join_ticket", fingerprint_rate_limit_parts(&[b"room-b"]))
                .await
        );
    }

    #[test]
    fn configured_expensive_rate_limit_uses_env_or_defaults() {
        let _lock = env_lock();
        unsafe {
            std::env::remove_var(EXPENSIVE_RATE_LIMIT_BURST_ENV);
            std::env::remove_var(EXPENSIVE_RATE_LIMIT_WINDOW_SECS_ENV);
            std::env::remove_var(EXPENSIVE_RATE_LIMIT_MAX_KEYS_ENV);
        }
        assert_eq!(
            configured_expensive_rate_limit_burst(),
            DEFAULT_EXPENSIVE_RATE_LIMIT_BURST
        );
        assert_eq!(
            configured_expensive_rate_limit_window(),
            Duration::from_secs(DEFAULT_EXPENSIVE_RATE_LIMIT_WINDOW_SECS)
        );
        assert_eq!(
            configured_expensive_rate_limit_max_keys(),
            DEFAULT_EXPENSIVE_RATE_LIMIT_MAX_KEYS
        );

        unsafe {
            std::env::set_var(EXPENSIVE_RATE_LIMIT_BURST_ENV, "7");
            std::env::set_var(EXPENSIVE_RATE_LIMIT_WINDOW_SECS_ENV, "9");
            std::env::set_var(EXPENSIVE_RATE_LIMIT_MAX_KEYS_ENV, "11");
        }
        assert_eq!(configured_expensive_rate_limit_burst(), 7);
        assert_eq!(
            configured_expensive_rate_limit_window(),
            Duration::from_secs(9)
        );
        assert_eq!(configured_expensive_rate_limit_max_keys(), 11);
    }

    #[tokio::test]
    async fn accept_epoch_returns_rate_limited_when_request_budget_is_exhausted() {
        let mut state = test_api_state();
        state.expensive_request_limiter =
            RequestRateLimiter::with_max_keys(1, Duration::from_secs(60), 1);
        let bundle = demo_bundle("rate-limit-accept").expect("demo bundle");
        let request = AcceptEpochRequest {
            bundle_cbor: bundle.to_cbor().expect("bundle cbor"),
        };
        assert!(
            state
                .expensive_request_limiter
                .check_and_record("accept_epoch", accept_epoch_rate_limit_key(&bundle))
                .await
        );

        let result = accept_epoch(State(state), encode_proto_request(&request)).await;
        assert!(matches!(result, Err(ApiError::RateLimited)));
    }

    #[tokio::test]
    async fn accept_epoch_rejects_malformed_bundle_cbor_matrix() {
        let state = test_api_state();
        let malformed_bundles = [
            Vec::new(),
            vec![0x01],
            vec![0x9f, 0x01],
            vec![0xbf, 0x61, 0x61],
            vec![0x5a, 0x00, 0x00, 0x00, 0x08, 0x01, 0x02],
        ];

        for bundle_cbor in malformed_bundles {
            let err = accept_epoch(
                State(state.clone()),
                encode_proto_request(&AcceptEpochRequest { bundle_cbor }),
            )
            .await
            .expect_err("malformed bundle must be rejected");
            assert!(matches!(
                err,
                ApiError::InvalidRequest("invalid bundle encoding")
            ));
        }
    }

    #[tokio::test]
    async fn join_ticket_returns_rate_limited_when_request_budget_is_exhausted() {
        let mut state = test_api_state();
        state.expensive_request_limiter =
            RequestRateLimiter::with_max_keys(1, Duration::from_secs(60), 1);
        let request = JoinTicketRequest {
            room_id: hex::encode(DEMO_GID),
            alias: "rate-limit-join".to_string(),
            identity_binding: None,
        };
        assert!(
            state
                .expensive_request_limiter
                .check_and_record("join_ticket", join_ticket_rate_limit_key(&request))
                .await
        );

        let result = join_ticket(State(state), encode_proto_request(&request)).await;
        assert!(matches!(result, Err(ApiError::RateLimited)));
    }

    #[tokio::test]
    async fn search_members_returns_rate_limited_when_request_budget_is_exhausted() {
        let mut state = test_api_state();
        state.expensive_request_limiter =
            RequestRateLimiter::with_max_keys(1, Duration::from_secs(60), 1);
        let headers = message_auth_headers();
        let request = pb::SearchMembersRequest {
            gid: DEMO_GID.to_vec(),
            parent_root: Vec::new(),
            query: "alice".to_string(),
            offset: Some(0),
            limit: Some(10),
        };
        assert!(
            state
                .expensive_request_limiter
                .check_and_record(
                    "search_members",
                    message_scoped_rate_limit_key(&headers, &DEMO_GID),
                )
                .await
        );

        let result = search_members(State(state), headers, encode_proto_request(&request)).await;
        assert!(matches!(result, Err(ApiError::RateLimited)));
    }

    #[tokio::test]
    async fn refresh_pivot_rejects_malformed_bundle_cbor_matrix() {
        let state = test_api_state();
        let headers = message_auth_headers();
        let malformed_bundles = [
            Vec::new(),
            vec![0x01],
            vec![0x9f, 0x01],
            vec![0xbf, 0x61, 0x61],
            vec![0x5a, 0x00, 0x00, 0x00, 0x08, 0x01, 0x02],
        ];

        for bundle_cbor in malformed_bundles {
            let err = refresh_pivot(
                State(state.clone()),
                headers.clone(),
                encode_proto_request(&RefreshPivotRequest { bundle_cbor }),
            )
            .await
            .expect_err("malformed refresh bundle must be rejected");

            if matches!(
                &err,
                ApiError::InvalidRequest("bundle_cbor must be provided")
            ) {
                continue;
            }
            assert!(matches!(
                err,
                ApiError::InvalidRequest("invalid bundle encoding")
            ));
        }
    }

    #[test]
    fn should_prune_messages_throttles_global_pruning() {
        let due = AtomicU64::new(0);
        assert!(runtime_should_prune(&due, 1_000, 1_000));
        assert!(!runtime_should_prune(&due, 1_100, 1_000));
        assert!(runtime_should_prune(&due, 2_100, 1_000));
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
            room_state: Arc::new(RwLock::new(RoomVolatileState::default())),
            message_retention: Duration::from_secs(DEFAULT_FS_MESSAGE_RETENTION_SECS),
            fs_epoch_period_seconds: CityGConfig::default().protocol.fs_policy.h_seconds.max(1),
            freeze_counts: Arc::new(RwLock::new(BTreeMap::new())),
            alias_registry: Arc::new(RwLock::new(AliasRegistry::default())),
            notification_tx: broadcast::channel(4).0,
            // Burst of 1 so the second attempt triggers rate limit
            alias_rate_limiter: AliasRateLimiter::new(1, Duration::from_secs(60)),
            merge_ticket_cache: Arc::new(RwLock::new(AHashMap::new())),
            accept_epoch_limiter: EndpointConcurrencyLimiter::new(
                DEFAULT_ACCEPT_EPOCH_MAX_IN_FLIGHT,
            ),
            join_ticket_limiter: EndpointConcurrencyLimiter::new(DEFAULT_JOIN_TICKET_MAX_IN_FLIGHT),
            expensive_request_limiter: RequestRateLimiter::new(
                DEFAULT_EXPENSIVE_RATE_LIMIT_BURST,
                Duration::from_secs(DEFAULT_EXPENSIVE_RATE_LIMIT_WINDOW_SECS),
            ),
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
