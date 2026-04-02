//! # City-G API Client
//!
//! Rust client library for interacting with the City-G HTTP API server.
//!
//! This crate provides a high-level async interface to all City-G server operations,
//! including epoch acceptance, member roster queries, join/merge ticket generation,
//! messaging, and window configuration.
//!
//! ## Features
//!
//! - **Automatic retry logic** with exponential backoff for network errors
//! - **Protocol Buffers** for efficient binary serialization
//! - **Identity binding** (TOFU) support for join tickets
//! - **Pagination** support for member roster queries
//! - **WebSocket notifications** (see server documentation)
//!
//! ## Quick Start
//!
//! ```text
//! use cityg_api_client::CitygApiClient;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a client pointing to your City-G server
//!     let client = CitygApiClient::new("http://localhost:8080");
//!
//!     // Check server health
//!     client.health().await?;
//!
//!     println!("City-G server is healthy!");
//!     Ok(())
//! }
//! ```
//!
//! ## Common Workflows
//!
//! ### Bootstrap a New Room
//!
//! ```text
//! # use cityg_api_client::CitygApiClient;
//! # async fn example(client: &CitygApiClient) -> Result<(), Box<dyn std::error::Error>> {
//! // Generate a broadcast key (implementation not shown)
//! let kbroad_public = vec![0u8; 32]; // Replace with actual key
//!
//! # use cityg_api_client::{
//! #   build_room_admin_proof, generate_room_admin_keypair, RoomAdminOperation,
//! # };
//! let (pop_public_key, pop_secret_key) = generate_room_admin_keypair();
//! let admin_proof = build_room_admin_proof(
//!     RoomAdminOperation::Bootstrap,
//!     "room-123",
//!     &kbroad_public,
//!     &pop_public_key,
//!     &pop_secret_key,
//! )?;
//!
//! client
//!     .bootstrap_room_as_admin("room-123", &kbroad_public, admin_proof)
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Join a Room
//!
//! ```text
//! // Request a join ticket with identity binding (TOFU)
//! let identity = IdentityBinding {
//!     alias: "alice".to_string(),
//!     pop_public_key: vec![/* Dilithium public key */],
//!     signature: vec![/* signature over binding */],
//! };
//!
//! let ticket = client.join_ticket(
//!     "room-123",
//!     "alice",
//!     Some(identity)
//! ).await?;
//! ```
//!
//! ### Submit an Epoch Bundle
//!
//! ```text
//! // Submit an epoch bundle to the server
//! let response = client.accept_epoch_bundle(&bundle).await?;
//!
//! // Response contains we_epoch_id, wid, parent_root, new_root
//! println!("Epoch ID: {}", hex::encode(response.we_epoch_id));
//! ```
//!
//! ### Query Members
//!
//! ```text
//! # use cityg_api_client::CitygApiClient;
//! # async fn example(client: &CitygApiClient, gid: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
//! // Fetch all members (paginated)
//! let members = client.members(gid, None).await?;
//!
//! for member in members.members {
//!     println!("Member: {} (leaf_id: {})",
//!         member.alias,
//!         hex::encode(&member.leaf_id)
//!     );
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Error Handling
//!
//! The client returns detailed errors including:
//! - Network errors (with automatic retry)
//! - HTTP status codes
//! - City-G freeze codes (see [`Error::HttpStatus`])
//! - Protocol buffer decode errors
//!
//! ```text
//! # use cityg_api_client::{CitygApiClient, Error};
//! # async fn example(client: &CitygApiClient) -> Result<(), Error> {
//! match client.health().await {
//!     Ok(()) => println!("Server healthy"),
//!     Err(Error::HttpStatus { status, message, freeze_code, .. }) => {
//!         eprintln!("HTTP {}: {} (freeze code: {:?})", status, message, freeze_code);
//!     }
//!     Err(e) => eprintln!("Error: {}", e),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## See Also
//!
//! - [City-G Protocol Documentation](https://github.com/pwnsdx/cityg/tree/main/docs/protocol)
//! - [API Reference](https://github.com/pwnsdx/cityg/blob/main/docs/api-reference.md)
//! - [`cityg-api`](../cityg_api) - Server implementation
//! - [`cityg-client`](../cityg_client) - Client bundle generation

mod barrier_helpers;
mod epoch_routes;
mod join_ticket;
mod member_queries;
mod merge_tickets;
mod observability;
mod room_admin;
mod verification;

use ciborium::Value;
use cityg_api_schema::pb;
use cityg_client::{
    CityGError as ClientError, barrier::TICKET_RETRY_MAX_ATTEMPTS,
    barrier::should_retry_ticket_http_error, barrier::ticket_retry_delay,
    barrier_update::normalize_max_barrier_update_bytes, pivot::hydrate_parities,
};
use msphf_orchestrator::PivotParity;
pub use pb::IdentityBinding;
use pb::MergeTicketIntent as PbMergeTicketIntent;
pub use pb::RoomAdminProof;
#[cfg(test)]
use pb::{ListRoomAdminsResponse, MembersRequest, RoomAdminMutationResponse};
use prost::Message;
use reqwest::{Client, StatusCode};
pub use room_admin::*;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{collections::BTreeMap, future::Future};
use thiserror::Error;
use tracing::warn;
use verification::*;

pub use verification::{
    parse_fetch_public_tree_completeness_attestation_bytes, parse_global_history_attestation_bytes,
    parse_history_authority_descriptor_bytes, parse_joins_since_completeness_attestation_bytes,
    parse_revoked_leaves_completeness_attestation_bytes,
    verify_fetch_public_tree_completeness_attestation, verify_joins_since_completeness_attestation,
    verify_revoked_leaves_completeness_attestation,
};

const ADMIN_TOKEN_HEADER: &str = "x-cityg-admin-token";
const MESSAGE_AUTH_HEADER: &str = "x-cityg-message-token";
const JOIN_PROVISIONING_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;
const MAX_BARRIER_HELPER_PAGE_ENTRIES: u32 = 512;
const HELPER_KIND_REVOKED_LEAVES: &str = "resolve_revoked_leaves";
const HELPER_KIND_JOINS_SINCE: &str = "resolve_joins_since";
const HELPER_KIND_FETCH_PUBLIC_TREE: &str = "fetch_public_tree";
const LOCAL_HISTORY_AUTHORITY_EXTENSION_ID: &str = "local-history-authority-v1";
const GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID: &str = "global-history-authority-v1";
const LOCAL_HISTORY_ATTESTATION_FINALITY_KIND: &str = "local-append-only";
const GLOBAL_HISTORY_ATTESTATION_FINALITY_KIND: &str = "global-append-only";

const EXPECTED_PROFILE_VERSION: &str = "v0.1.4";
const EXPECTED_PROOF_MODE: &str = "lin+zkvrf";
const EXPECTED_VRF_ID: &str = "lb-vrf/v1";
const EXPECTED_MSPHF_CRS_ID: &str = "rlwe-merkle/v1";
const EXPECTED_MSPHF_PARAMS_ID: &str = "rlwe-params/mock";
const MAX_BARRIER_N_MAX: u64 = 65_536;

/// HTTP client for the City-G API server.
///
/// This client handles all communication with a City-G server, including:
/// - Epoch acceptance and validation
/// - Member roster queries and search
/// - Join and merge ticket generation
/// - Message storage and retrieval
/// - Window configuration and telemetry
///
/// # Features
///
/// - **Connection pooling**: Uses `reqwest::Client` internally
/// - **Automatic retries**: Network errors are retried with exponential backoff (up to 3 attempts)
/// - **Binary protocol**: Uses Protocol Buffers for efficient serialization
///
/// # Examples
///
/// ```no_run
/// use cityg_api_client::CitygApiClient;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let client = CitygApiClient::new("http://localhost:8080");
///
///     // Verify server is reachable
///     client.health().await?;
///
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone)]
pub struct CitygApiClient {
    http: Client,
    base_url: String,
    admin_token: Option<String>,
    message_auth_token: Option<String>,
}

impl CitygApiClient {
    /// Creates a new API client with default HTTP settings.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the City-G server (e.g., `http://localhost:8080`)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use cityg_api_client::CitygApiClient;
    ///
    /// let client = CitygApiClient::new("http://localhost:8080");
    /// ```
    ///
    /// ```no_run
    /// use cityg_api_client::CitygApiClient;
    ///
    /// // Trailing slashes are automatically removed
    /// let client = CitygApiClient::new("https://cityg.example.com/");
    /// ```
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            http: Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            admin_token: None,
            message_auth_token: None,
        }
    }

    /// Creates a new API client with a custom HTTP client.
    ///
    /// Use this constructor when you need to customize HTTP behavior such as:
    /// - Custom timeouts
    /// - Proxy configuration
    /// - TLS settings
    /// - Connection pooling limits
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the City-G server
    /// * `client` - A configured `reqwest::Client`
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use cityg_api_client::CitygApiClient;
    /// use reqwest::Client;
    /// use std::time::Duration;
    ///
    /// let http_client = Client::builder()
    ///     .timeout(Duration::from_secs(30))
    ///     .build()
    ///     .unwrap();
    ///
    /// let client = CitygApiClient::with_http_client(
    ///     "http://localhost:8080",
    ///     http_client
    /// );
    /// ```
    pub fn with_http_client(base_url: impl Into<String>, client: Client) -> Self {
        Self {
            http: client,
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            admin_token: None,
            message_auth_token: None,
        }
    }

    /// Configures an admin token for protected control-plane endpoints.
    ///
    /// The token is sent in the `x-cityg-admin-token` header for `/v1/config/window`.
    ///
    /// Room governance endpoints no longer use the server-global admin token and require
    /// room-scoped [`RoomAdminProof`] instead.
    pub fn with_admin_token(mut self, token: impl Into<String>) -> Self {
        let token = token.into().trim().to_string();
        self.admin_token = if token.is_empty() { None } else { Some(token) };
        self
    }

    /// Configures a message-plane token for send/fetch endpoints.
    ///
    /// The token is sent in the `x-cityg-message-token` header for:
    /// - `/v1/send_message`
    /// - `/v1/messages`
    pub fn with_message_auth_token(mut self, token: impl Into<String>) -> Self {
        let token = token.into().trim().to_string();
        self.message_auth_token = if token.is_empty() { None } else { Some(token) };
        self
    }

    /// Submits a client epoch bundle to the server for validation.
    ///
    /// The server validates the bundle against the current multi-head window state,
    /// checking cryptographic proofs, witness validity, and concurrency rules.
    ///
    /// # Arguments
    ///
    /// * `bundle` - A [`ClientEpochBundle`] containing the epoch to submit
    ///
    /// # Returns
    ///
    /// - `accepted: true` - The epoch was accepted and inserted into the window
    /// - `accepted: false` - The epoch was rejected (see `freeze_code` and `freeze_reason`)
    ///
    /// # Freeze Codes
    ///
    /// Common rejection reasons include:
    /// - **Code 2**: Witness validation failed
    /// - **Code 3**: SPHF verification failed
    /// - **Code 5**: Parent root not found in window
    /// - **Code 7**: Duplicate epoch ID
    ///
    /// See [`docs/protocol/12-error-reference.md`](https://github.com/pwnsdx/cityg/blob/main/docs/protocol/12-error-reference.md) for complete freeze code documentation.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use cityg_api_client::CitygApiClient;
    /// use cityg_client::ClientEpochBundle;
    ///
    /// # async fn example(bundle: &ClientEpochBundle) -> Result<(), Box<dyn std::error::Error>> {
    /// let client = CitygApiClient::new("http://localhost:8080");
    ///
    /// // Generate an epoch bundle using cityg_client (see cityg-client crate docs)
    /// match client.accept_epoch_bundle(&bundle).await {
    ///     Ok(response) => {
    ///         println!("✓ Epoch accepted: {}", hex::encode(&response.we_epoch_id));
    ///         println!("  New root: {}", hex::encode(&response.new_root));
    ///     }
    ///     Err(e) => {
    ///         eprintln!("✗ Epoch rejected: {}", e);
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    async fn post_proto<R>(&self, path: &str, request: impl Message) -> Result<R, Error>
    where
        R: Message + Default,
    {
        self.post_proto_with_retry(path, request, 3).await
    }

    /// Post a protobuf request with retry logic
    ///
    /// Retries on network errors with exponential backoff.
    /// Does NOT retry on application-level errors (4xx, 5xx responses).
    async fn post_proto_with_retry<R>(
        &self,
        path: &str,
        request: impl Message,
        max_retries: u32,
    ) -> Result<R, Error>
    where
        R: Message + Default,
    {
        let url = format!("{}{}", self.base_url, path);
        let buf = bytes::Bytes::from(request.encode_to_vec());
        let mut last_network_error: Option<reqwest::Error> = None;

        for attempt in 0..=max_retries {
            let mut req = self
                .http
                .post(&url)
                .header("Content-Type", "application/x-protobuf");
            if Self::requires_admin_token(path)
                && let Some(token) = self.admin_token.as_deref()
            {
                req = req.header(ADMIN_TOKEN_HEADER, token);
            }
            if Self::requires_message_auth(path)
                && let Some(token) = self.message_auth_token.as_deref()
            {
                req = req.header(MESSAGE_AUTH_HEADER, token);
            }
            let response = req.body(buf.clone()).send().await;

            match response {
                Ok(resp) => match Self::decode_response(resp).await {
                    Ok(decoded) => return Ok(decoded),
                    Err(err) => return Err(err),
                },
                Err(e) => {
                    // Only retry on network errors, not on HTTP status errors
                    if !e.is_timeout() && !e.is_connect() && !e.is_request() {
                        return Err(Error::Http(e));
                    }

                    if attempt < max_retries {
                        let backoff = Duration::from_millis(100 * (2_u64.pow(attempt)));
                        warn!(
                            "network error on attempt {}/{} for {}: {}. Retrying in {:?}",
                            attempt + 1,
                            max_retries + 1,
                            path,
                            e,
                            backoff
                        );
                        last_network_error = Some(e);
                        tokio::time::sleep(backoff).await;
                    } else {
                        warn!(
                            "network error on final attempt {}/{} for {}: {}",
                            attempt + 1,
                            max_retries + 1,
                            path,
                            e
                        );
                        last_network_error = Some(e);
                    }
                }
            }
        }

        if let Some(err) = last_network_error {
            Err(Error::Http(err))
        } else {
            Err(Error::Parse(
                "retry loop exhausted without a captured response error".to_string(),
            ))
        }
    }

    async fn decode_response<R>(response: reqwest::Response) -> Result<R, Error>
    where
        R: Message + Default,
    {
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            return Err(build_http_error(status, bytes.to_vec()));
        }
        R::decode(bytes).map_err(Error::from)
    }

    fn requires_admin_token(path: &str) -> bool {
        matches!(path, "/v1/config/window" | "/v1/debug/window/seed")
    }

    fn requires_message_auth(path: &str) -> bool {
        matches!(
            path,
            "/v1/send_message"
                | "/v1/messages"
                | "/v1/members"
                | "/v1/members/search"
                | "/v1/rooms/merge_ticket"
                | "/v1/barrier/resolve_revoked_leaves"
                | "/v1/barrier/resolve_joins_since"
                | "/v1/barrier/fetch_public_tree"
                | "/v1/barrier/issue_full_verification_witness"
                | "/v1/barrier/lookup_merge_acceptance"
                | "/v1/bundle"
                | "/v1/window"
                | "/v1/telemetry"
                | "/v1/pivot/refresh"
        )
    }
}

/// Join record returned by barrier join enumeration endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BarrierJoinRecord {
    pub device_pk: Vec<u8>,
    pub leaf_index: u32,
    pub ek_leaf: Vec<u8>,
}

fn to_core_join_snapshot_record(
    record: &BarrierJoinRecord,
) -> cityg_client::barrier::BarrierJoinSnapshotRecord {
    cityg_client::barrier::BarrierJoinSnapshotRecord {
        leaf_index: record.leaf_index,
        ek_leaf: record.ek_leaf.clone(),
    }
}

pub fn to_core_join_snapshot_records(
    join_records: &[BarrierJoinRecord],
) -> Vec<cityg_client::barrier::BarrierJoinSnapshotRecord> {
    join_records
        .iter()
        .map(to_core_join_snapshot_record)
        .collect()
}

/// Revoked-leaf response bound to a specific authenticated history view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarrierResolvedRevokedLeaves {
    pub history_view_id: [u8; 32],
    pub history_commitment: HistoryCommitment,
    pub history_authority_extension: Option<HistoryAuthorityExtension>,
    pub history_authority: Option<HistoryAuthorityDescriptor>,
    pub global_history_attestation: Option<GlobalHistoryAttestation>,
    pub leaf_indices: Vec<u32>,
}

/// Join enumeration response bound to a specific authenticated history view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarrierResolvedJoins {
    pub history_view_id: [u8; 32],
    pub history_commitment: HistoryCommitment,
    pub history_authority_extension: Option<HistoryAuthorityExtension>,
    pub history_authority: Option<HistoryAuthorityDescriptor>,
    pub global_history_attestation: Option<GlobalHistoryAttestation>,
    pub records: Vec<BarrierJoinRecord>,
}

/// Barrier public-tree snapshot returned by snapshot fetch endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarrierPublicTree {
    pub n_max: u64,
    pub kem_tree_hash_after: [u8; 32],
    pub pk_entries: Vec<Vec<u8>>,
}

/// Public-tree snapshot bound to a specific authenticated history view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarrierFetchedPublicTree {
    pub history_view_id: [u8; 32],
    pub history_commitment: HistoryCommitment,
    pub history_authority_extension: Option<HistoryAuthorityExtension>,
    pub history_authority: Option<HistoryAuthorityDescriptor>,
    pub global_history_attestation: Option<GlobalHistoryAttestation>,
    pub tree: BarrierPublicTree,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarrierSnapshotDependencies {
    pub public_tree: BarrierFetchedPublicTree,
    pub joins: BarrierResolvedJoins,
    pub revoked: BarrierResolvedRevokedLeaves,
}

pub struct BarrierSnapshotPreparationRequest<'a> {
    pub room_id: &'a str,
    pub gid: &'a [u8; 32],
    pub leaf_id: &'a [u8; 32],
    pub barrier_version: u64,
    pub cover_leaf_index: u64,
    pub snapshot_hash: [u8; 32],
    pub barrier_n_max: u64,
    pub max_barrier_update_bytes: u64,
    pub header: BTreeMap<u64, Value>,
    pub parities: &'a [PivotParity],
    pub cat: &'a [u8],
    pub pox_r_commit: &'a [u8],
    pub parent_root: &'a [u8],
    pub join_delta_root: &'a [u8],
    pub revoked_since_root: &'a [u8],
    pub revoked_root: &'a [u8],
    pub tswe_salt_hash: &'a [u8],
    pub ticket_history_commitment: &'a HistoryCommitment,
    pub ticket_history_authority_extension: Option<HistoryAuthorityExtension>,
    pub history_authority: Option<HistoryAuthorityDescriptor>,
    pub current_global_history_attestation_bytes: &'a [u8],
    pub merge_ticket_artifact_bytes: &'a [u8],
    pub deployment_profile_manifest_bytes: &'a [u8],
    pub pop_secret_key: &'a [u8],
    pub full_verification_target_leaf_id: Option<[u8; 32]>,
    pub barrier_update_reason: u64,
    pub operation_label: &'a str,
}

pub struct PreparedBarrierSnapshot {
    pub header: BTreeMap<u64, Value>,
    pub cat: [u8; 32],
    pub parent_root: [u8; 32],
    pub join_delta_root: [u8; 32],
    pub revoked_since_root: [u8; 32],
    pub revoked_root: [u8; 32],
    pub tswe_salt_hash: [u8; 32],
    pub pox_r_commit: [u8; 32],
    pub pivot: PivotParity,
    pub snapshot_hash: [u8; 32],
    pub committed_revocation_roots_hash: [u8; 32],
    pub revocation_roots_hash: [u8; 32],
    pub barrier_update: cityg_client::barrier_build::BarrierUpdateBuildResult,
}

/// Server-local append-only authenticated history commitment carried by A/B/C/D.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryCommitment {
    pub history_view_id: [u8; 32],
    pub history_commitment_id: [u8; 32],
    pub prev_history_commitment_id: [u8; 32],
    pub history_seq: u64,
}

pub fn ensure_matching_barrier_history_dependencies(
    context: &str,
    expected_view_id: Option<&[u8; 32]>,
    expected_commitment: &HistoryCommitment,
    tree: &BarrierFetchedPublicTree,
    joins: &BarrierResolvedJoins,
    revoked: &BarrierResolvedRevokedLeaves,
) -> Result<(), Error> {
    if tree.history_view_id == [0u8; 32]
        || tree.history_view_id != joins.history_view_id
        || tree.history_view_id != revoked.history_view_id
    {
        return Err(Error::Parse(format!(
            "{context}: public tree / joins / revoked leaves do not share one authenticated history view (960.9)"
        )));
    }
    if tree.history_commitment.history_view_id == [0u8; 32]
        || tree.history_commitment != joins.history_commitment
        || tree.history_commitment != revoked.history_commitment
    {
        return Err(Error::Parse(format!(
            "{context}: public tree / joins / revoked leaves do not share one authenticated history commitment (960.9)"
        )));
    }
    if tree.history_commitment != *expected_commitment {
        return Err(Error::Parse(format!(
            "{context}: authenticated history commitment does not match ticket/provisioning state (960.9)"
        )));
    }
    if let Some(expected_history_view_id) = expected_view_id
        && tree.history_view_id != *expected_history_view_id
    {
        return Err(Error::Parse(format!(
            "{context}: authenticated history view does not match provisioning state (960.9)"
        )));
    }
    Ok(())
}

pub fn to_core_history_commitment(
    commitment: &HistoryCommitment,
) -> cityg_client::barrier::BarrierHistoryCommitment {
    cityg_client::barrier::BarrierHistoryCommitment {
        history_view_id: commitment.history_view_id,
        history_commitment_id: commitment.history_commitment_id,
        prev_history_commitment_id: commitment.prev_history_commitment_id,
        history_seq: commitment.history_seq,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsForwardLeapPolicy {
    pub h: u64,
    pub checkpoint_interval: u64,
    pub slack_anchor: u64,
    pub slack_first_device: u64,
    pub slack_device: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeAcceptanceStatus {
    Pending,
    Accepted,
    Superseded,
    FinalRejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeAcceptanceLookup {
    pub status: MergeAcceptanceStatus,
    pub history_view_id: [u8; 32],
    pub history_commitment: HistoryCommitment,
    pub history_authority_extension: Option<HistoryAuthorityExtension>,
    pub history_authority: Option<HistoryAuthorityDescriptor>,
    pub global_history_attestation: Option<GlobalHistoryAttestation>,
    pub accepted_barrier_version: Option<u64>,
    pub accepted_fs_ec: Option<u64>,
    pub accepted_reason: Option<u64>,
    pub accepted_digest: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryAuthorityDescriptor {
    pub scope_id: [u8; 32],
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryAuthorityExtension {
    LocalHistoryAuthorityV1,
    GlobalHistoryAuthorityV1,
}

impl HistoryAuthorityExtension {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalHistoryAuthorityV1 => "local-history-authority-v1",
            Self::GlobalHistoryAuthorityV1 => "global-history-authority-v1",
        }
    }
}

pub fn build_identity_binding(
    alias: &str,
    pop_public_key: &[u8],
    pop_secret_key: &[u8],
) -> Result<IdentityBinding, Error> {
    let binding = cityg_client::message_auth::build_signed_identity_binding(
        alias,
        pop_public_key,
        pop_secret_key,
    )
    .map_err(|err| Error::Parse(err.to_string()))?;

    Ok(IdentityBinding {
        alias: binding.alias,
        pop_public_key: binding.pop_public_key,
        signature: binding.signature,
    })
}

pub fn require_base_profile_history_authority_extension(
    raw: &str,
    context: &str,
) -> Result<HistoryAuthorityExtension, Error> {
    match parse_history_authority_extension(raw, false) {
        Ok(extension) => {
            require_base_profile_global_history_authority_extension(extension, context)
        }
        Err(Error::Parse(_)) if !raw.is_empty() => Err(Error::Parse(format!(
            "{context} carries unsupported history authority extension: {raw}"
        ))),
        Err(err) => Err(err),
    }
}

pub fn ensure_supported_attested_current_state_extension(
    context: &str,
    extension: Option<HistoryAuthorityExtension>,
    current_global_history_attestation_bytes: &[u8],
) -> Result<(), Error> {
    if current_global_history_attestation_bytes.is_empty() {
        if extension.is_some() {
            return Err(Error::Parse(format!(
                "{context} carries history authority extension without current global history attestation"
            )));
        }
        return Ok(());
    }
    if extension.is_none() {
        return Err(Error::Parse(format!(
            "{context} carries attested current state without negotiated history authority extension"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalHistoryAttestation {
    pub scope_id: [u8; 32],
    pub gid: [u8; 32],
    pub history_commitment: HistoryCommitment,
    pub barrier_version: u64,
    pub kem_tree_hash_after: [u8; 32],
    pub parent_attestation_id: [u8; 32],
    pub finality_kind: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperCompletenessAttestation {
    pub scope_id: [u8; 32],
    pub helper_kind: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullVerificationWitness {
    pub scope_id: [u8; 32],
    pub history_authority_extension: String,
    pub gid: [u8; 32],
    pub history_commitment: HistoryCommitment,
    pub barrier_version: u64,
    pub kem_tree_hash_after: [u8; 32],
    pub author_leaf_id: [u8; 32],
    pub barrier_update_reason: u64,
    pub updater_leaf: u64,
    pub barrier_update_digest: [u8; 32],
    pub joins_digest: [u8; 32],
    pub revoked_digest: [u8; 32],
    pub deployment_profile_manifest_digest: [u8; 32],
    pub signature: Vec<u8>,
}

/// Merge ticket containing all data needed to create a new epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeTicketIntent {
    Leave,
    Refresh,
}

impl MergeTicketIntent {
    fn as_proto(self) -> i32 {
        match self {
            Self::Leave => PbMergeTicketIntent::Leave as i32,
            Self::Refresh => PbMergeTicketIntent::Refresh as i32,
        }
    }
}

/// Merge ticket containing all data needed to create a new epoch.
///
/// Returned by [`CitygApiClient::merge_ticket`], this structure contains:
/// - Fresh pivot parities for the current window state
/// - Merkle witness proving membership in the parent epoch
/// - Group configuration and cryptographic parameters
///
/// # Usage
///
/// A merge ticket allows an existing member to resync with the group after
/// being offline or to create a new epoch based on the current state.
///
/// # Fields
///
/// - `we_epoch_id`: The witness extraction epoch identifier for the merge point
/// - `parities`: Fresh pivot parities from the server
/// - `witness_cbor`: CBOR-encoded Merkle witness to parent root
/// - `srx_cbor`: CBOR-encoded server randomness extension
/// - `proof_mode`: Proof system identifier (base profile: `lin+zkvrf`)
/// - `vrf_id`: VRF configuration identifier
/// - `policy_version`: Protocol policy version
/// - `cat`: Combined authentication tag (32 bytes)
/// - `parent_root`: Parent epoch root (32 bytes)
/// - `join_delta_root`: Join delta Merkle root (32 bytes)
/// - `revoked_since_root`: Revoked-since delta root (32 bytes)
/// - `revoked_root`: Full revoked set root (32 bytes)
/// - `tswe_salt_hash`: Timelock WE salt hash (32 bytes)
/// - `pox_r_commit`: Proof-of-X randomness commitment (32 bytes)
/// - `kbroad_public`: Broadcast encryption public key
/// - `msphf_crs_id`: MSPHF common reference string identifier
/// - `msphf_params_id`: MSPHF parameter set identifier
/// - `fs_policy_version`: Forward secrecy policy version
/// - `fs_epoch_base_ts`: Forward secrecy epoch base timestamp (Unix ms)
/// - `kbroad_generation`: Monotonic room KBROAD generation
#[derive(Debug, Clone)]
pub struct MergeTicket {
    pub author_leaf_id: [u8; 32],
    pub we_epoch_id: [u8; 32],
    pub parities: Vec<PivotParity>,
    pub witness_cbor: Vec<u8>,
    pub srx_cbor: Vec<u8>,
    pub proof_mode: String,
    pub vrf_id: String,
    pub policy_version: String,
    pub cat: [u8; 32],
    pub parent_root: [u8; 32],
    pub join_delta_root: [u8; 32],
    pub revoked_since_root: [u8; 32],
    pub revoked_root: [u8; 32],
    pub tswe_salt_hash: [u8; 32],
    pub pox_r_commit: [u8; 32],
    pub kbroad_public: Vec<u8>,
    pub msphf_crs_id: String,
    pub msphf_params_id: String,
    pub fs_policy_version: String,
    pub fs_epoch_base_ts: u64,
    pub fs_forward_leap_policy: FsForwardLeapPolicy,
    pub last_accepted_ec: u64,
    pub kbroad_generation: u64,
    pub barrier_version: u64,
    pub cover_leaf_index: u64,
    pub kem_tree_hash_after: [u8; 32],
    pub current_history_commitment: HistoryCommitment,
    pub history_authority_extension: Option<HistoryAuthorityExtension>,
    pub history_authority_descriptor_bytes: Vec<u8>,
    pub history_authority: Option<HistoryAuthorityDescriptor>,
    pub current_global_history_attestation_bytes: Vec<u8>,
    pub current_global_history_attestation: Option<GlobalHistoryAttestation>,
    pub merge_ticket_artifact_bytes: Vec<u8>,
    pub deployment_profile_manifest_bytes: Vec<u8>,
    pub n_max: u64,
    pub max_barrier_update_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct PreparedRuntimeMergeTicket {
    pub snapshot_hash: [u8; 32],
    pub barrier_n_max: u64,
    pub cover_leaf_index: u64,
    pub max_barrier_update_bytes: u64,
    pub max_barrier_update_bytes_normalized: usize,
    pub parities: Vec<PivotParity>,
    pub witness_bytes: Option<Vec<u8>>,
}

impl MergeTicket {
    pub fn prepare_runtime(
        &self,
        fs_ec: u64,
        fs_epoch_commit: [u8; 32],
        fs_dev_prev_commit: [u8; 32],
        stored_max_barrier_update_bytes: u64,
    ) -> Result<PreparedRuntimeMergeTicket, Error> {
        let ticket_max_barrier_update_bytes = self.max_barrier_update_bytes.max(1);
        if stored_max_barrier_update_bytes != 0
            && stored_max_barrier_update_bytes != ticket_max_barrier_update_bytes
        {
            return Err(Error::Parse(format!(
                "max_barrier_update_bytes mismatch: local={} server={}",
                stored_max_barrier_update_bytes, ticket_max_barrier_update_bytes
            )));
        }

        if self.cover_leaf_index >= self.n_max {
            return Err(Error::Parse(format!(
                "merge ticket cover_leaf_index out of range: {} >= {}",
                self.cover_leaf_index, self.n_max
            )));
        }

        let max_barrier_update_bytes_normalized =
            normalize_max_barrier_update_bytes(ticket_max_barrier_update_bytes)
                .map_err(|err| Error::Parse(err.to_string()))?;

        Ok(PreparedRuntimeMergeTicket {
            snapshot_hash: self.kem_tree_hash_after,
            barrier_n_max: self.n_max,
            cover_leaf_index: self.cover_leaf_index,
            max_barrier_update_bytes: ticket_max_barrier_update_bytes,
            max_barrier_update_bytes_normalized,
            parities: hydrate_parities(&self.parities, fs_ec, fs_epoch_commit, fs_dev_prev_commit),
            witness_bytes: (!self.witness_cbor.is_empty()).then(|| self.witness_cbor.clone()),
        })
    }
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct ErrorEnvelope {
    message: String,
    freeze_code: Option<u32>,
    freeze_reason: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    failed_index: Option<u32>,
}

fn parse_error_envelope(body: &[u8]) -> (String, Option<u32>, Option<String>, Option<u32>) {
    if let Ok(env) = serde_json::from_slice::<ErrorEnvelope>(body) {
        (
            env.message,
            env.freeze_code,
            env.freeze_reason,
            env.failed_index,
        )
    } else {
        (String::from_utf8_lossy(body).to_string(), None, None, None)
    }
}

fn build_http_error(status: StatusCode, body: Vec<u8>) -> Error {
    let (message, freeze_code, freeze_reason, failed_index) = parse_error_envelope(&body);
    Error::HttpStatus {
        status,
        message,
        freeze_code,
        freeze_reason,
        failed_index,
    }
}

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

async fn retry_ticket_request<T, F, Fut>(
    request_name: &'static str,
    mut request: F,
) -> Result<T, Error>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, Error>>,
{
    let mut retry_attempt = 0u32;
    loop {
        match request().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                if let Error::HttpStatus {
                    status,
                    message,
                    freeze_code,
                    ..
                } = &err
                    && should_retry_ticket_http_error(status.as_u16(), message, *freeze_code)
                    && retry_attempt < TICKET_RETRY_MAX_ATTEMPTS
                {
                    let delay = ticket_retry_delay(retry_attempt);
                    retry_attempt = retry_attempt.saturating_add(1);
                    warn!(
                        request = request_name,
                        attempt = retry_attempt,
                        delay_ms = delay.as_millis() as u64,
                        status = status.as_u16(),
                        message = %message,
                        "ticket request race/concurrency rejection; retrying"
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }

                return Err(err);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Bytes,
        http::{HeaderMap, StatusCode as HttpStatusCode, Uri, header},
        response::{IntoResponse, Response},
        routing::{get, post},
    };
    use cityg_client::demo::demo_bundle_alice;
    use pb::{
        AcceptEpochResponse, BarrierFetchPublicTreeRequest, BarrierFetchPublicTreeResponse,
        BarrierLookupMergeAcceptanceResponse, BarrierResolveJoinsSinceRequest,
        BarrierResolveJoinsSinceResponse, BarrierResolveRevokedLeavesRequest,
        BarrierResolveRevokedLeavesResponse, BootstrapRoomResponse, ConfigureWindowResponse,
        FetchMessagesResponse, FsForwardLeapPolicy as PbFsForwardLeapPolicy, GetBundleResponse,
        GetTelemetryResponse, GetWindowResponse, HistoryCommitment as PbHistoryCommitment,
        JoinTicketResponse, MembersResponse, MergeAcceptanceStatus as PbMergeAcceptanceStatus,
        MergeTicketResponse, RefreshPivotResponse, RotateRoomKbroadResponse, SearchMembersResponse,
        SeedHeadResponse, SendMessageResponse,
    };
    use pqcrypto_dilithium::dilithium5;
    use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
    use prost::Message;
    use std::{
        error::Error as StdError,
        net::SocketAddr,
        sync::{
            Arc, OnceLock,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tokio::net::TcpListener;

    fn encode_proto<T: Message>(msg: T) -> Vec<u8> {
        msg.encode_to_vec()
    }

    fn encode_cbor_det<T: serde::Serialize>(value: &T) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(value, &mut bytes).expect("deterministic cbor encoding");
        bytes
    }

    struct TestHistoryAuthority {
        descriptor: HistoryAuthorityDescriptor,
        descriptor_bytes: Vec<u8>,
        secret_key: dilithium5::SecretKey,
        attestation_bytes: Vec<u8>,
    }

    fn test_history_authority_keypair() -> (&'static [u8], &'static [u8]) {
        static KEYPAIR: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
        let (public_key, secret_key) = KEYPAIR.get_or_init(|| {
            let (public_key, secret_key) = dilithium5::keypair();
            (
                public_key.as_bytes().to_vec(),
                secret_key.as_bytes().to_vec(),
            )
        });
        (public_key.as_slice(), secret_key.as_slice())
    }

    fn build_test_history_authority(
        history_commitment: HistoryCommitment,
        gid: [u8; 32],
        barrier_version: u64,
        kem_tree_hash_after: [u8; 32],
    ) -> TestHistoryAuthority {
        let (public_key_bytes, secret_key_bytes) = test_history_authority_keypair();
        let public_key = dilithium5::PublicKey::from_bytes(public_key_bytes)
            .expect("test history authority public key");
        let secret_key = dilithium5::SecretKey::from_bytes(secret_key_bytes)
            .expect("test history authority secret key");
        let descriptor = HistoryAuthorityDescriptor {
            scope_id: [0xA1; 32],
            public_key: public_key.as_bytes().to_vec(),
        };
        let descriptor_bytes = encode_cbor_det(&HistoryAuthorityDescriptorWire(
            descriptor.scope_id.to_vec(),
            descriptor.public_key.clone(),
        ));
        let parent_attestation_id = [0u8; 32];
        let payload = encode_cbor_det(&GlobalHistoryAttestationSignedPayload(
            "cityg/global-history-attestation-v1",
            &descriptor.scope_id,
            &gid,
            &history_commitment.history_view_id,
            &history_commitment.history_commitment_id,
            &history_commitment.prev_history_commitment_id,
            history_commitment.history_seq,
            barrier_version,
            &kem_tree_hash_after,
            &parent_attestation_id,
            GLOBAL_HISTORY_ATTESTATION_FINALITY_KIND,
        ));
        let signature = dilithium5::detached_sign(payload.as_slice(), &secret_key)
            .as_bytes()
            .to_vec();
        let attestation_bytes = encode_cbor_det(&GlobalHistoryAttestationWire(
            descriptor.scope_id.to_vec(),
            gid.to_vec(),
            history_commitment.history_view_id.to_vec(),
            history_commitment.history_commitment_id.to_vec(),
            history_commitment.prev_history_commitment_id.to_vec(),
            history_commitment.history_seq,
            barrier_version,
            kem_tree_hash_after.to_vec(),
            parent_attestation_id.to_vec(),
            GLOBAL_HISTORY_ATTESTATION_FINALITY_KIND.to_string(),
            signature,
        ));
        TestHistoryAuthority {
            descriptor,
            descriptor_bytes,
            secret_key,
            attestation_bytes,
        }
    }

    fn build_test_deployment_profile_manifest(
        authority: &TestHistoryAuthority,
        history_authority_extension: &str,
        gid: &[u8; 32],
        profile_version: &str,
        n_max: u64,
        max_barrier_update_bytes: u64,
        fs_policy: &PbFsForwardLeapPolicy,
    ) -> Vec<u8> {
        let payload = encode_cbor_det(&DeploymentProfileManifestSignedPayload {
            label: "cityg/deployment-profile-manifest-v1",
            scope_id: &authority.descriptor.scope_id,
            history_authority_extension,
            gid,
            profile_version,
            n_max,
            max_barrier_update_bytes,
            fs_forward_leap_h: fs_policy.h,
            fs_forward_leap_checkpoint_interval: fs_policy.checkpoint_interval,
            fs_forward_leap_slack_anchor: fs_policy.slack_anchor,
            fs_forward_leap_slack_first_device: fs_policy.slack_first_device,
            fs_forward_leap_slack_device: fs_policy.slack_device,
        });
        let signature = dilithium5::detached_sign(payload.as_slice(), &authority.secret_key)
            .as_bytes()
            .to_vec();
        encode_cbor_det(&DeploymentProfileManifestWire {
            scope_id: authority.descriptor.scope_id.to_vec(),
            history_authority_extension: history_authority_extension.to_string(),
            gid: gid.to_vec(),
            profile_version: profile_version.to_string(),
            n_max,
            max_barrier_update_bytes,
            fs_forward_leap_h: fs_policy.h,
            fs_forward_leap_checkpoint_interval: fs_policy.checkpoint_interval,
            fs_forward_leap_slack_anchor: fs_policy.slack_anchor,
            fs_forward_leap_slack_first_device: fs_policy.slack_first_device,
            fs_forward_leap_slack_device: fs_policy.slack_device,
            signature,
        })
    }

    fn build_test_helper_completeness_attestation<T: serde::Serialize>(
        authority: &TestHistoryAuthority,
        helper_kind: &'static str,
        history_commitment: &HistoryCommitment,
        page_offset: u32,
        total_entries: u32,
        selector: T,
    ) -> Vec<u8> {
        let payload = encode_cbor_det(&HelperCompletenessSignedPayload {
            label: "cityg/helper-completeness-attestation-v1",
            scope_id: &authority.descriptor.scope_id,
            helper_kind,
            history_view_id: &history_commitment.history_view_id,
            history_commitment_id: &history_commitment.history_commitment_id,
            page_offset,
            total_entries,
            selector,
        });
        let signature = dilithium5::detached_sign(payload.as_slice(), &authority.secret_key)
            .as_bytes()
            .to_vec();
        encode_cbor_det(&HelperCompletenessAttestationWire(
            authority.descriptor.scope_id.to_vec(),
            helper_kind.to_string(),
            signature,
        ))
    }

    fn build_test_join_provisioning_artifact(response: &JoinTicketResponse) -> Vec<u8> {
        let current_history_commitment = response
            .current_history_commitment
            .clone()
            .expect("join ticket current_history_commitment");
        let history_commitment = HistoryCommitment {
            history_view_id: array32(&current_history_commitment.history_view_id)
                .expect("history_view_id"),
            history_commitment_id: array32(&current_history_commitment.history_commitment_id)
                .expect("history_commitment_id"),
            prev_history_commitment_id: array32(
                &current_history_commitment.prev_history_commitment_id,
            )
            .expect("prev_history_commitment_id"),
            history_seq: current_history_commitment.history_seq,
        };
        let authority = build_test_history_authority(
            history_commitment,
            array32(&response.gid).expect("gid"),
            response.barrier_version,
            array32(&response.kem_tree_hash_after).expect("kem_tree_hash_after"),
        );
        let fs_policy = response
            .fs_forward_leap_policy
            .expect("fs_forward_leap_policy");
        let current_predecessor_kem_tree_hash_after =
            if response.current_predecessor_kem_tree_hash_after.is_empty() {
                [0u8; 32]
            } else {
                array32(&response.current_predecessor_kem_tree_hash_after)
                    .expect("current_predecessor_kem_tree_hash_after")
            };
        let gid = array32(&response.gid).expect("gid");
        let leaf_id = array32(&response.leaf_id).expect("leaf_id");
        let kem_tree_hash_after =
            array32(&response.kem_tree_hash_after).expect("kem_tree_hash_after");
        let join_finalize_auth_token =
            array32(&response.join_finalize_auth_token).expect("join_finalize_auth_token");
        let provisioning_nonce = array32(&response.provisioning_nonce).expect("provisioning_nonce");
        let join_records = response
            .current_join_records
            .iter()
            .map(|record| BarrierJoinRecord {
                device_pk: record.device_pk.clone(),
                leaf_index: record.leaf_index,
                ek_leaf: record.ek_leaf.clone(),
            })
            .collect::<Vec<_>>();
        let payload = encode_cbor_det(&JoinProvisioningArtifactSignedPayload {
            label: "cityg/join-provisioning-artifact-v1",
            scope_id: &authority.descriptor.scope_id,
            history_authority_extension: response.history_authority_extension.as_str(),
            gid: &gid,
            profile_version: response.profile_version.as_str(),
            leaf_id: &leaf_id,
            history_view_id: &history_commitment.history_view_id,
            history_commitment_id: &history_commitment.history_commitment_id,
            prev_history_commitment_id: &history_commitment.prev_history_commitment_id,
            history_seq: history_commitment.history_seq,
            barrier_version: response.barrier_version,
            cover_leaf_index: response.cover_leaf_index,
            n_max: response.n_max,
            max_barrier_update_bytes: response.max_barrier_update_bytes,
            kem_tree_hash_after: &kem_tree_hash_after,
            current_predecessor_kem_tree_hash_after: &current_predecessor_kem_tree_hash_after,
            join_finalize_auth_token: &join_finalize_auth_token,
            provisioning_nonce: &provisioning_nonce,
            provisioning_issued_at_ms: response.provisioning_issued_at_ms,
            provisioning_expires_at_ms: response.provisioning_expires_at_ms,
            fs_forward_leap_h: fs_policy.h,
            fs_forward_leap_checkpoint_interval: fs_policy.checkpoint_interval,
            fs_forward_leap_slack_anchor: fs_policy.slack_anchor,
            fs_forward_leap_slack_first_device: fs_policy.slack_first_device,
            fs_forward_leap_slack_device: fs_policy.slack_device,
            last_accepted_ec: response.last_accepted_ec,
            history_authority_descriptor: response.history_authority_descriptor.as_slice(),
            current_global_history_attestation: response
                .current_global_history_attestation
                .as_slice(),
            current_join_records_completeness_attestation: response
                .current_join_records_completeness_attestation
                .as_slice(),
            current_revoked_leaf_indices_completeness_attestation: response
                .current_revoked_leaf_indices_completeness_attestation
                .as_slice(),
            current_barrier_update: response.current_barrier_update.as_slice(),
            current_join_records: join_records.as_slice(),
            current_revoked_leaf_indices: response.current_revoked_leaf_indices.as_slice(),
        });
        let signature = dilithium5::detached_sign(payload.as_slice(), &authority.secret_key)
            .as_bytes()
            .to_vec();
        encode_cbor_det(&JoinProvisioningArtifactWire {
            scope_id: authority.descriptor.scope_id.to_vec(),
            history_authority_extension: response.history_authority_extension.clone(),
            gid: response.gid.clone(),
            profile_version: response.profile_version.clone(),
            leaf_id: response.leaf_id.clone(),
            history_view_id: response.current_history_view_id.clone(),
            history_commitment_id: current_history_commitment.history_commitment_id.clone(),
            prev_history_commitment_id: current_history_commitment
                .prev_history_commitment_id
                .clone(),
            history_seq: current_history_commitment.history_seq,
            barrier_version: response.barrier_version,
            cover_leaf_index: response.cover_leaf_index,
            n_max: response.n_max,
            max_barrier_update_bytes: response.max_barrier_update_bytes,
            kem_tree_hash_after: response.kem_tree_hash_after.clone(),
            current_predecessor_kem_tree_hash_after: current_predecessor_kem_tree_hash_after
                .to_vec(),
            join_finalize_auth_token: response.join_finalize_auth_token.clone(),
            provisioning_nonce: response.provisioning_nonce.clone(),
            provisioning_issued_at_ms: response.provisioning_issued_at_ms,
            provisioning_expires_at_ms: response.provisioning_expires_at_ms,
            fs_forward_leap_h: fs_policy.h,
            fs_forward_leap_checkpoint_interval: fs_policy.checkpoint_interval,
            fs_forward_leap_slack_anchor: fs_policy.slack_anchor,
            fs_forward_leap_slack_first_device: fs_policy.slack_first_device,
            fs_forward_leap_slack_device: fs_policy.slack_device,
            last_accepted_ec: response.last_accepted_ec,
            signature,
        })
    }

    fn build_test_deployment_profile_manifest_for_join(response: &JoinTicketResponse) -> Vec<u8> {
        let current_history_commitment = response
            .current_history_commitment
            .clone()
            .expect("join ticket current_history_commitment");
        let authority = build_test_history_authority(
            HistoryCommitment {
                history_view_id: array32(&current_history_commitment.history_view_id)
                    .expect("history_view_id"),
                history_commitment_id: array32(&current_history_commitment.history_commitment_id)
                    .expect("history_commitment_id"),
                prev_history_commitment_id: array32(
                    &current_history_commitment.prev_history_commitment_id,
                )
                .expect("prev_history_commitment_id"),
                history_seq: current_history_commitment.history_seq,
            },
            array32(&response.gid).expect("gid"),
            response.barrier_version,
            array32(&response.kem_tree_hash_after).expect("kem_tree_hash_after"),
        );
        let fs_policy = response
            .fs_forward_leap_policy
            .expect("fs_forward_leap_policy");
        let gid = array32(&response.gid).expect("gid");
        let payload = encode_cbor_det(&DeploymentProfileManifestSignedPayload {
            label: "cityg/deployment-profile-manifest-v1",
            scope_id: &authority.descriptor.scope_id,
            history_authority_extension: response.history_authority_extension.as_str(),
            gid: &gid,
            profile_version: response.profile_version.as_str(),
            n_max: response.n_max,
            max_barrier_update_bytes: response.max_barrier_update_bytes,
            fs_forward_leap_h: fs_policy.h,
            fs_forward_leap_checkpoint_interval: fs_policy.checkpoint_interval,
            fs_forward_leap_slack_anchor: fs_policy.slack_anchor,
            fs_forward_leap_slack_first_device: fs_policy.slack_first_device,
            fs_forward_leap_slack_device: fs_policy.slack_device,
        });
        let signature = dilithium5::detached_sign(payload.as_slice(), &authority.secret_key)
            .as_bytes()
            .to_vec();
        encode_cbor_det(&DeploymentProfileManifestWire {
            scope_id: authority.descriptor.scope_id.to_vec(),
            history_authority_extension: response.history_authority_extension.clone(),
            gid: response.gid.clone(),
            profile_version: response.profile_version.clone(),
            n_max: response.n_max,
            max_barrier_update_bytes: response.max_barrier_update_bytes,
            fs_forward_leap_h: fs_policy.h,
            fs_forward_leap_checkpoint_interval: fs_policy.checkpoint_interval,
            fs_forward_leap_slack_anchor: fs_policy.slack_anchor,
            fs_forward_leap_slack_first_device: fs_policy.slack_first_device,
            fs_forward_leap_slack_device: fs_policy.slack_device,
            signature,
        })
    }

    fn finalize_join_ticket_payload(mut response: JoinTicketResponse) -> JoinTicketResponse {
        if !response.history_authority_descriptor.is_empty()
            && !response.history_authority_extension.is_empty()
        {
            response.deployment_profile_manifest =
                build_test_deployment_profile_manifest_for_join(&response);
            response.provisioning_artifact = build_test_join_provisioning_artifact(&response);
        }
        response
    }

    fn build_test_merge_ticket_artifact(response: &MergeTicketResponse) -> Vec<u8> {
        let current_history_commitment = response
            .current_history_commitment
            .clone()
            .expect("merge ticket current_history_commitment");
        let history_commitment = HistoryCommitment {
            history_view_id: array32(&current_history_commitment.history_view_id)
                .expect("history_view_id"),
            history_commitment_id: array32(&current_history_commitment.history_commitment_id)
                .expect("history_commitment_id"),
            prev_history_commitment_id: array32(
                &current_history_commitment.prev_history_commitment_id,
            )
            .expect("prev_history_commitment_id"),
            history_seq: current_history_commitment.history_seq,
        };
        let authority = build_test_history_authority(
            history_commitment,
            [0x41; 32],
            response.barrier_version,
            array32(&response.kem_tree_hash_after).expect("kem_tree_hash_after"),
        );
        let gid = [0x41; 32];
        let leaf_id = [0x01; 32];
        let fs_policy = response
            .fs_forward_leap_policy
            .expect("merge ticket fs_forward_leap_policy");
        let we_epoch_id = array32(&response.we_epoch_id).expect("we_epoch_id");
        let cat = array32(&response.cat).expect("cat");
        let parent_root = array32(&response.parent_root).expect("parent_root");
        let join_delta_root = array32(&response.join_delta_root).expect("join_delta_root");
        let revoked_since_root = array32(&response.revoked_since_root).expect("revoked_since_root");
        let revoked_root = array32(&response.revoked_root).expect("revoked_root");
        let tswe_salt_hash = array32(&response.tswe_salt_hash).expect("tswe_salt_hash");
        let pox_r_commit = array32(&response.pox_r_commit).expect("pox_r_commit");
        let kem_tree_hash_after =
            array32(&response.kem_tree_hash_after).expect("kem_tree_hash_after");
        let payload = encode_cbor_det(&MergeTicketArtifactSignedPayload {
            label: "cityg/merge-ticket-artifact-v1",
            scope_id: &authority.descriptor.scope_id,
            history_authority_extension: response.history_authority_extension.as_str(),
            profile_version: response.profile_version.as_str(),
            gid: &gid,
            leaf_id: &leaf_id,
            history_view_id: &history_commitment.history_view_id,
            history_commitment_id: &history_commitment.history_commitment_id,
            prev_history_commitment_id: &history_commitment.prev_history_commitment_id,
            history_seq: history_commitment.history_seq,
            barrier_version: response.barrier_version,
            cover_leaf_index: response.cover_leaf_index,
            n_max: response.n_max,
            max_barrier_update_bytes: response.max_barrier_update_bytes,
            kem_tree_hash_after: &kem_tree_hash_after,
            fs_forward_leap_h: fs_policy.h,
            fs_forward_leap_checkpoint_interval: fs_policy.checkpoint_interval,
            fs_forward_leap_slack_anchor: fs_policy.slack_anchor,
            fs_forward_leap_slack_first_device: fs_policy.slack_first_device,
            fs_forward_leap_slack_device: fs_policy.slack_device,
            last_accepted_ec: response.last_accepted_ec,
            history_authority_descriptor: response.history_authority_descriptor.as_slice(),
            current_global_history_attestation: response
                .current_global_history_attestation
                .as_slice(),
            we_epoch_id: &we_epoch_id,
            pivot_parity_cbor: response.pivot_parity_cbor.as_slice(),
            witness_cbor: response.witness_cbor.as_slice(),
            srx_cbor: response.srx_cbor.as_slice(),
            proof_mode: response.proof_mode.as_str(),
            vrf_id: response.vrf_id.as_str(),
            policy_version: response.policy_version.as_str(),
            cat: &cat,
            parent_root: &parent_root,
            join_delta_root: &join_delta_root,
            revoked_since_root: &revoked_since_root,
            revoked_root: &revoked_root,
            tswe_salt_hash: &tswe_salt_hash,
            pox_r_commit: &pox_r_commit,
            kbroad_public: response.kbroad_public.as_slice(),
            msphf_crs_id: response.msphf_crs_id.as_str(),
            msphf_params_id: response.msphf_params_id.as_str(),
            fs_policy_version: response.fs_policy_version.as_str(),
            fs_epoch_base_ts: response.fs_epoch_base_ts,
            kbroad_generation: response.kbroad_generation,
        });
        let signature = dilithium5::detached_sign(payload.as_slice(), &authority.secret_key)
            .as_bytes()
            .to_vec();
        encode_cbor_det(&MergeTicketArtifactWire {
            scope_id: authority.descriptor.scope_id.to_vec(),
            history_authority_extension: response.history_authority_extension.clone(),
            profile_version: response.profile_version.clone(),
            gid: gid.to_vec(),
            leaf_id: leaf_id.to_vec(),
            history_view_id: response.current_history_view_id.clone(),
            history_commitment_id: current_history_commitment.history_commitment_id.clone(),
            prev_history_commitment_id: current_history_commitment
                .prev_history_commitment_id
                .clone(),
            history_seq: current_history_commitment.history_seq,
            barrier_version: response.barrier_version,
            cover_leaf_index: response.cover_leaf_index,
            n_max: response.n_max,
            max_barrier_update_bytes: response.max_barrier_update_bytes,
            kem_tree_hash_after: response.kem_tree_hash_after.clone(),
            fs_forward_leap_h: fs_policy.h,
            fs_forward_leap_checkpoint_interval: fs_policy.checkpoint_interval,
            fs_forward_leap_slack_anchor: fs_policy.slack_anchor,
            fs_forward_leap_slack_first_device: fs_policy.slack_first_device,
            fs_forward_leap_slack_device: fs_policy.slack_device,
            last_accepted_ec: response.last_accepted_ec,
            history_authority_descriptor: response.history_authority_descriptor.clone(),
            current_global_history_attestation: response.current_global_history_attestation.clone(),
            we_epoch_id: response.we_epoch_id.clone(),
            pivot_parity_cbor: response.pivot_parity_cbor.clone(),
            witness_cbor: response.witness_cbor.clone(),
            srx_cbor: response.srx_cbor.clone(),
            proof_mode: response.proof_mode.clone(),
            vrf_id: response.vrf_id.clone(),
            policy_version: response.policy_version.clone(),
            cat: response.cat.clone(),
            parent_root: response.parent_root.clone(),
            join_delta_root: response.join_delta_root.clone(),
            revoked_since_root: response.revoked_since_root.clone(),
            revoked_root: response.revoked_root.clone(),
            tswe_salt_hash: response.tswe_salt_hash.clone(),
            pox_r_commit: response.pox_r_commit.clone(),
            kbroad_public: response.kbroad_public.clone(),
            msphf_crs_id: response.msphf_crs_id.clone(),
            msphf_params_id: response.msphf_params_id.clone(),
            fs_policy_version: response.fs_policy_version.clone(),
            fs_epoch_base_ts: response.fs_epoch_base_ts,
            kbroad_generation: response.kbroad_generation,
            signature,
        })
    }

    fn build_test_deployment_profile_manifest_for_merge(response: &MergeTicketResponse) -> Vec<u8> {
        let current_history_commitment = response
            .current_history_commitment
            .clone()
            .expect("merge ticket current_history_commitment");
        let authority = build_test_history_authority(
            HistoryCommitment {
                history_view_id: array32(&current_history_commitment.history_view_id)
                    .expect("history_view_id"),
                history_commitment_id: array32(&current_history_commitment.history_commitment_id)
                    .expect("history_commitment_id"),
                prev_history_commitment_id: array32(
                    &current_history_commitment.prev_history_commitment_id,
                )
                .expect("prev_history_commitment_id"),
                history_seq: current_history_commitment.history_seq,
            },
            [0x41; 32],
            response.barrier_version,
            array32(&response.kem_tree_hash_after).expect("kem_tree_hash_after"),
        );
        let fs_policy = response
            .fs_forward_leap_policy
            .expect("merge ticket fs_forward_leap_policy");
        let gid = [0x41; 32];
        let payload = encode_cbor_det(&DeploymentProfileManifestSignedPayload {
            label: "cityg/deployment-profile-manifest-v1",
            scope_id: &authority.descriptor.scope_id,
            history_authority_extension: response.history_authority_extension.as_str(),
            gid: &gid,
            profile_version: response.profile_version.as_str(),
            n_max: response.n_max,
            max_barrier_update_bytes: response.max_barrier_update_bytes,
            fs_forward_leap_h: fs_policy.h,
            fs_forward_leap_checkpoint_interval: fs_policy.checkpoint_interval,
            fs_forward_leap_slack_anchor: fs_policy.slack_anchor,
            fs_forward_leap_slack_first_device: fs_policy.slack_first_device,
            fs_forward_leap_slack_device: fs_policy.slack_device,
        });
        let signature = dilithium5::detached_sign(payload.as_slice(), &authority.secret_key)
            .as_bytes()
            .to_vec();
        encode_cbor_det(&DeploymentProfileManifestWire {
            scope_id: authority.descriptor.scope_id.to_vec(),
            history_authority_extension: response.history_authority_extension.clone(),
            gid: gid.to_vec(),
            profile_version: response.profile_version.clone(),
            n_max: response.n_max,
            max_barrier_update_bytes: response.max_barrier_update_bytes,
            fs_forward_leap_h: fs_policy.h,
            fs_forward_leap_checkpoint_interval: fs_policy.checkpoint_interval,
            fs_forward_leap_slack_anchor: fs_policy.slack_anchor,
            fs_forward_leap_slack_first_device: fs_policy.slack_first_device,
            fs_forward_leap_slack_device: fs_policy.slack_device,
            signature,
        })
    }

    fn finalize_merge_ticket_payload(mut response: MergeTicketResponse) -> MergeTicketResponse {
        if !response.history_authority_descriptor.is_empty()
            && !response.history_authority_extension.is_empty()
        {
            response.deployment_profile_manifest =
                build_test_deployment_profile_manifest_for_merge(&response);
            response.merge_ticket_artifact = build_test_merge_ticket_artifact(&response);
        }
        response
    }

    fn merge_ticket_with_history_authority_payload() -> MergeTicketResponse {
        let mut response = merge_ticket_ok_payload();
        let current_history_commitment = HistoryCommitment {
            history_view_id: [0xD1; 32],
            history_commitment_id: [0xE1; 32],
            prev_history_commitment_id: [0x00; 32],
            history_seq: 7,
        };
        let authority = build_test_history_authority(
            current_history_commitment,
            [0x41; 32],
            response.barrier_version,
            [0x09; 32],
        );
        response.current_history_commitment =
            Some(history_commitment_ok_payload(0xD1, 0xE1, 0x00, 7));
        response.history_authority_extension = GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID.to_string();
        response.history_authority_descriptor = authority.descriptor_bytes;
        response.current_global_history_attestation = authority.attestation_bytes;
        finalize_merge_ticket_payload(response)
    }

    fn merge_ticket_ok_payload() -> MergeTicketResponse {
        let history_commitment = HistoryCommitment {
            history_view_id: [0xD1; 32],
            history_commitment_id: [0xE1; 32],
            prev_history_commitment_id: [0x00; 32],
            history_seq: 7,
        };
        let authority = build_test_history_authority(history_commitment, [0x41; 32], 0, [0x09; 32]);
        finalize_merge_ticket_payload(MergeTicketResponse {
            we_epoch_id: vec![0x01; 32],
            pivot_parity_cbor: Vec::new(),
            witness_cbor: Vec::new(),
            srx_cbor: Vec::new(),
            proof_mode: EXPECTED_PROOF_MODE.to_string(),
            vrf_id: EXPECTED_VRF_ID.to_string(),
            policy_version: "v0".to_string(),
            cat: vec![0x02; 32],
            parent_root: vec![0x03; 32],
            join_delta_root: vec![0x04; 32],
            revoked_since_root: vec![0x00; 32],
            revoked_root: vec![0x00; 32],
            tswe_salt_hash: vec![0x05; 32],
            pox_r_commit: vec![0x06; 32],
            kbroad_public: vec![0x07; 32],
            msphf_crs_id: EXPECTED_MSPHF_CRS_ID.to_string(),
            msphf_params_id: EXPECTED_MSPHF_PARAMS_ID.to_string(),
            fs_policy_version: "7".to_string(),
            fs_epoch_base_ts: 0,
            kbroad_generation: 0,
            barrier_version: 0,
            profile_version: EXPECTED_PROFILE_VERSION.to_string(),
            cover_leaf_index: 0,
            kem_tree_hash_after: vec![0x09; 32],
            n_max: 1024,
            max_barrier_update_bytes: 1_048_576,
            current_history_view_id: vec![0xD1; 32],
            current_history_commitment: Some(history_commitment_ok_payload(0xD1, 0xE1, 0x00, 7)),
            history_authority_extension: GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID.to_string(),
            history_authority_descriptor: authority.descriptor_bytes,
            current_global_history_attestation: authority.attestation_bytes,
            fs_forward_leap_policy: Some(fs_forward_leap_policy_ok_payload()),
            last_accepted_ec: 34,
            ..MergeTicketResponse::default()
        })
    }

    fn join_ticket_ok_payload() -> JoinTicketResponse {
        let history_commitment = HistoryCommitment {
            history_view_id: [0xD0; 32],
            history_commitment_id: [0xD1; 32],
            prev_history_commitment_id: [0x00; 32],
            history_seq: 1,
        };
        let authority = build_test_history_authority(history_commitment, [0x41; 32], 0, [0xCC; 32]);
        let join_records = Vec::<BarrierJoinRecord>::new();
        let revoked_leaf_indices = Vec::<u32>::new();
        let join_helper_attestation = build_test_helper_completeness_attestation(
            &authority,
            HELPER_KIND_JOINS_SINCE,
            &history_commitment,
            0,
            0,
            JoinsSinceSelector {
                prev_barrier_version: 0,
                records: join_records.as_slice(),
            },
        );
        let revoked_helper_attestation = encode_cbor_det(&HelperCompletenessAttestationWire(
            authority.descriptor.scope_id.to_vec(),
            HELPER_KIND_REVOKED_LEAVES.to_string(),
            vec![0xAB; 32],
        ));
        finalize_join_ticket_payload(JoinTicketResponse {
            profile_version: EXPECTED_PROFILE_VERSION.to_string(),
            gid: vec![0x41; 32],
            cat: vec![0x42; 32],
            parent_root: Vec::new(),
            revoked_root: vec![0x00; 32],
            revoked_since_root: vec![0x00; 32],
            tswe_salt_hash: vec![0x43; 32],
            join_delta_root: vec![0x00; 32],
            leaf_id: vec![0x44; 32],
            pox_r_commit: vec![0x45; 32],
            witness_cbor: Vec::new(),
            srx_cbor: Vec::new(),
            msphf_crs_id: EXPECTED_MSPHF_CRS_ID.to_string(),
            msphf_params_id: EXPECTED_MSPHF_PARAMS_ID.to_string(),
            proof_mode: EXPECTED_PROOF_MODE.to_string(),
            vrf_id: EXPECTED_VRF_ID.to_string(),
            policy_version: "v0".to_string(),
            fs_policy_version: "7".to_string(),
            fs_epoch_base_ts: 0,
            kbroad_public: vec![0x46; 32],
            bootstrap_public: vec![0x47; 32],
            kbroad_generation: 0,
            barrier_version: 0,
            current_history_view_id: vec![0xD0; 32],
            current_history_commitment: Some(history_commitment_ok_payload(0xD0, 0xD1, 0x00, 1)),
            history_authority_extension: GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID.to_string(),
            join_finalize_auth_token: vec![0xE5; 32],
            provisioning_nonce: vec![0xE6; 32],
            provisioning_issued_at_ms: 1,
            provisioning_expires_at_ms: u64::MAX,
            cover_leaf_index: 0,
            n_max: 1024,
            max_barrier_update_bytes: 1_048_576,
            kem_tree_hash_after: vec![0xCC; 32],
            history_authority_descriptor: authority.descriptor_bytes,
            current_global_history_attestation: authority.attestation_bytes,
            current_join_records: Vec::new(),
            current_revoked_leaf_indices: revoked_leaf_indices,
            current_join_records_completeness_attestation: join_helper_attestation,
            current_revoked_leaf_indices_completeness_attestation: revoked_helper_attestation,
            fs_forward_leap_policy: Some(fs_forward_leap_policy_ok_payload()),
            last_accepted_ec: 21,
            ..JoinTicketResponse::default()
        })
    }

    fn fs_forward_leap_policy_ok_payload() -> PbFsForwardLeapPolicy {
        PbFsForwardLeapPolicy {
            h: 300,
            checkpoint_interval: 3600,
            slack_anchor: 0,
            slack_first_device: 0,
            slack_device: 4,
        }
    }

    fn history_commitment_ok_payload(view: u8, id: u8, prev: u8, seq: u64) -> PbHistoryCommitment {
        PbHistoryCommitment {
            history_view_id: vec![view; 32],
            history_commitment_id: vec![id; 32],
            prev_history_commitment_id: vec![prev; 32],
            history_seq: seq,
        }
    }

    async fn mock_health() -> &'static str {
        "ok"
    }

    async fn unavailable_health() -> impl IntoResponse {
        (
            HttpStatusCode::SERVICE_UNAVAILABLE,
            [(header::CONTENT_TYPE, "application/json")],
            br#"{"message":"service unavailable"}"#.to_vec(),
        )
    }

    fn page_bounds(offset: u32, total: usize, page_len: usize) -> (usize, usize, Option<u32>) {
        let start = usize::try_from(offset).unwrap_or(total);
        let end = total.min(start.saturating_add(page_len));
        let next = if end < total {
            Some(u32::try_from(end).unwrap_or(u32::MAX))
        } else {
            None
        };
        (start.min(total), end, next)
    }

    async fn mock_post(uri: Uri, body: Bytes) -> Response {
        let payload = match uri.path() {
            "/v1/rooms/bootstrap" => encode_proto(BootstrapRoomResponse::default()),
            "/v1/rooms/rotate_kbroad" => encode_proto(RotateRoomKbroadResponse::default()),
            "/v1/rooms/grant_admin" => encode_proto(RoomAdminMutationResponse {
                status: "granted".to_string(),
                admin_count: 2,
            }),
            "/v1/rooms/revoke_admin" => encode_proto(RoomAdminMutationResponse {
                status: "revoked".to_string(),
                admin_count: 1,
            }),
            "/v1/rooms/list_admins" => encode_proto(ListRoomAdminsResponse {
                admin_pop_public_keys: vec![vec![0xA1; 32], vec![0xB2; 32]],
            }),
            "/v1/rooms/expel_member_ticket" => {
                encode_proto(merge_ticket_with_history_authority_payload())
            }
            "/v1/members" => encode_proto(MembersResponse::default()),
            "/v1/members/search" => encode_proto(SearchMembersResponse::default()),
            "/v1/rooms/join_ticket" => encode_proto(join_ticket_ok_payload()),
            "/v1/rooms/merge_ticket" => encode_proto(merge_ticket_with_history_authority_payload()),
            "/v1/accept_epoch" => encode_proto(AcceptEpochResponse::default()),
            "/v1/barrier/resolve_revoked_leaves" => {
                let request = BarrierResolveRevokedLeavesRequest::decode(body)
                    .unwrap_or_else(|_| BarrierResolveRevokedLeavesRequest::default());
                let all = [1u32, 7u32];
                let (start, end, next_page_offset) = page_bounds(request.page_offset, all.len(), 1);
                let history_commitment = HistoryCommitment {
                    history_view_id: [0xD1; 32],
                    history_commitment_id: [0xE1; 32],
                    prev_history_commitment_id: [0x00; 32],
                    history_seq: 7,
                };
                let authority =
                    build_test_history_authority(history_commitment, [0x41; 32], 7, [0xCC; 32]);
                let fs_forward_leap_policy = fs_forward_leap_policy_ok_payload();
                let deployment_profile_manifest = build_test_deployment_profile_manifest(
                    &authority,
                    GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID,
                    &[0x41; 32],
                    EXPECTED_PROFILE_VERSION,
                    8,
                    1_048_576,
                    &fs_forward_leap_policy,
                );
                let page_leaf_indices = all[start..end].to_vec();
                let helper_completeness_attestation = build_test_helper_completeness_attestation(
                    &authority,
                    HELPER_KIND_REVOKED_LEAVES,
                    &history_commitment,
                    request.page_offset,
                    u32::try_from(all.len()).unwrap_or(u32::MAX),
                    RevokedLeavesSelector {
                        revocation_roots_hash: &[0xCC; 32],
                        leaf_indices: page_leaf_indices.as_slice(),
                    },
                );
                encode_proto(BarrierResolveRevokedLeavesResponse {
                    leaf_indices: page_leaf_indices,
                    history_view_id: vec![0xD1; 32],
                    history_commitment: Some(history_commitment_ok_payload(0xD1, 0xE1, 0x00, 7)),
                    history_authority_extension: GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID.to_string(),
                    page_offset: request.page_offset,
                    next_page_offset,
                    total_entries: u32::try_from(all.len()).unwrap_or(u32::MAX),
                    helper_completeness_attestation,
                    history_authority_descriptor: authority.descriptor_bytes,
                    global_history_attestation: authority.attestation_bytes,
                    profile_version: EXPECTED_PROFILE_VERSION.to_string(),
                    n_max: 8,
                    max_barrier_update_bytes: 1_048_576,
                    fs_forward_leap_policy: Some(fs_forward_leap_policy),
                    deployment_profile_manifest,
                })
            }
            "/v1/barrier/resolve_joins_since" => {
                let request = BarrierResolveJoinsSinceRequest::decode(body)
                    .unwrap_or_else(|_| BarrierResolveJoinsSinceRequest::default());
                let all = [
                    pb::BarrierJoinLeafRecord {
                        device_pk: vec![0xAA; 32],
                        leaf_index: 9,
                        ek_leaf: vec![0xBB; 1184],
                    },
                    pb::BarrierJoinLeafRecord {
                        device_pk: vec![0xAB; 32],
                        leaf_index: 10,
                        ek_leaf: vec![0xBC; 1184],
                    },
                ];
                let (start, end, next_page_offset) = page_bounds(request.page_offset, all.len(), 1);
                let history_commitment = HistoryCommitment {
                    history_view_id: [0xD1; 32],
                    history_commitment_id: [0xE1; 32],
                    prev_history_commitment_id: [0x00; 32],
                    history_seq: 7,
                };
                let authority =
                    build_test_history_authority(history_commitment, [0x41; 32], 7, [0xCC; 32]);
                let fs_forward_leap_policy = fs_forward_leap_policy_ok_payload();
                let deployment_profile_manifest = build_test_deployment_profile_manifest(
                    &authority,
                    GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID,
                    &[0x41; 32],
                    EXPECTED_PROFILE_VERSION,
                    8,
                    1_048_576,
                    &fs_forward_leap_policy,
                );
                let page_records = all[start..end].to_vec();
                let signed_records = page_records
                    .iter()
                    .map(|record| BarrierJoinRecord {
                        device_pk: record.device_pk.clone(),
                        leaf_index: record.leaf_index,
                        ek_leaf: record.ek_leaf.clone(),
                    })
                    .collect::<Vec<_>>();
                let helper_completeness_attestation = build_test_helper_completeness_attestation(
                    &authority,
                    HELPER_KIND_JOINS_SINCE,
                    &history_commitment,
                    request.page_offset,
                    u32::try_from(all.len()).unwrap_or(u32::MAX),
                    JoinsSinceSelector {
                        prev_barrier_version: request.prev_barrier_version,
                        records: signed_records.as_slice(),
                    },
                );
                encode_proto(BarrierResolveJoinsSinceResponse {
                    records: page_records,
                    history_view_id: vec![0xD1; 32],
                    history_commitment: Some(history_commitment_ok_payload(0xD1, 0xE1, 0x00, 7)),
                    history_authority_extension: GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID.to_string(),
                    page_offset: request.page_offset,
                    next_page_offset,
                    total_entries: u32::try_from(all.len()).unwrap_or(u32::MAX),
                    helper_completeness_attestation,
                    history_authority_descriptor: authority.descriptor_bytes,
                    global_history_attestation: authority.attestation_bytes,
                    profile_version: EXPECTED_PROFILE_VERSION.to_string(),
                    n_max: 8,
                    max_barrier_update_bytes: 1_048_576,
                    fs_forward_leap_policy: Some(fs_forward_leap_policy),
                    deployment_profile_manifest,
                })
            }
            "/v1/barrier/fetch_public_tree" => {
                let request = BarrierFetchPublicTreeRequest::decode(body)
                    .unwrap_or_else(|_| BarrierFetchPublicTreeRequest::default());
                let all = vec![Vec::new(); 15];
                let (start, end, next_entry_offset) =
                    page_bounds(request.entry_offset, all.len(), 7);
                let history_commitment = HistoryCommitment {
                    history_view_id: [0xD1; 32],
                    history_commitment_id: [0xE1; 32],
                    prev_history_commitment_id: [0x00; 32],
                    history_seq: 7,
                };
                let authority =
                    build_test_history_authority(history_commitment, [0x41; 32], 7, [0xCC; 32]);
                let fs_forward_leap_policy = fs_forward_leap_policy_ok_payload();
                let deployment_profile_manifest = build_test_deployment_profile_manifest(
                    &authority,
                    GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID,
                    &[0x41; 32],
                    EXPECTED_PROFILE_VERSION,
                    8,
                    1_048_576,
                    &fs_forward_leap_policy,
                );
                let page_entries = all[start..end].to_vec();
                let helper_completeness_attestation = build_test_helper_completeness_attestation(
                    &authority,
                    HELPER_KIND_FETCH_PUBLIC_TREE,
                    &history_commitment,
                    request.entry_offset,
                    u32::try_from(all.len()).unwrap_or(u32::MAX),
                    FetchPublicTreeSelector {
                        kem_tree_hash_after: &[0xCC; 32],
                        pk_entries: page_entries.as_slice(),
                    },
                );
                encode_proto(BarrierFetchPublicTreeResponse {
                    n_max: 8,
                    kem_tree_hash_after: vec![0xCC; 32],
                    pk_entries: page_entries,
                    history_view_id: vec![0xD1; 32],
                    history_commitment: Some(history_commitment_ok_payload(0xD1, 0xE1, 0x00, 7)),
                    history_authority_extension: GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID.to_string(),
                    entry_offset: request.entry_offset,
                    next_entry_offset,
                    total_entries: u32::try_from(all.len()).unwrap_or(u32::MAX),
                    helper_completeness_attestation,
                    history_authority_descriptor: authority.descriptor_bytes,
                    global_history_attestation: authority.attestation_bytes,
                    profile_version: EXPECTED_PROFILE_VERSION.to_string(),
                    max_barrier_update_bytes: 1_048_576,
                    fs_forward_leap_policy: Some(fs_forward_leap_policy),
                    deployment_profile_manifest,
                })
            }
            "/v1/barrier/lookup_merge_acceptance" => {
                let history_commitment = HistoryCommitment {
                    history_view_id: [0xD1; 32],
                    history_commitment_id: [0xE2; 32],
                    prev_history_commitment_id: [0xE1; 32],
                    history_seq: 8,
                };
                let authority =
                    build_test_history_authority(history_commitment, [0x41; 32], 11, [0xCC; 32]);
                let fs_forward_leap_policy = fs_forward_leap_policy_ok_payload();
                let deployment_profile_manifest = build_test_deployment_profile_manifest(
                    &authority,
                    GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID,
                    &[0x41; 32],
                    EXPECTED_PROFILE_VERSION,
                    8,
                    1_048_576,
                    &fs_forward_leap_policy,
                );
                encode_proto(BarrierLookupMergeAcceptanceResponse {
                    status: PbMergeAcceptanceStatus::Accepted as i32,
                    history_view_id: vec![0xD1; 32],
                    accepted_barrier_version: Some(11),
                    accepted_fs_ec: Some(22),
                    accepted_reason: Some(1),
                    accepted_digest: Some(vec![0xDD; 32]),
                    history_commitment: Some(history_commitment_ok_payload(0xD1, 0xE2, 0xE1, 8)),
                    history_authority_extension: GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID.to_string(),
                    history_authority_descriptor: authority.descriptor_bytes,
                    global_history_attestation: authority.attestation_bytes,
                    profile_version: EXPECTED_PROFILE_VERSION.to_string(),
                    n_max: 8,
                    max_barrier_update_bytes: 1_048_576,
                    fs_forward_leap_policy: Some(fs_forward_leap_policy),
                    deployment_profile_manifest,
                })
            }
            "/v1/send_message" => encode_proto(SendMessageResponse::default()),
            "/v1/messages" => encode_proto(FetchMessagesResponse::default()),
            "/v1/bundle" => encode_proto(GetBundleResponse::default()),
            "/v1/config/window" => encode_proto(ConfigureWindowResponse::default()),
            "/v1/pivot/refresh" => encode_proto(RefreshPivotResponse::default()),
            "/v1/debug/window/seed" => encode_proto(SeedHeadResponse::default()),
            "/v1/telemetry" => encode_proto(GetTelemetryResponse::default()),
            "/v1/window" => encode_proto(GetWindowResponse::default()),
            _ => {
                let body = br#"{"message":"resource not found","freeze_code":404}"#.to_vec();
                return (
                    HttpStatusCode::NOT_FOUND,
                    [(header::CONTENT_TYPE, "application/json")],
                    body,
                )
                    .into_response();
            }
        };

        (
            HttpStatusCode::OK,
            [(header::CONTENT_TYPE, "application/x-protobuf")],
            payload,
        )
            .into_response()
    }

    async fn start_mock_server() -> Result<(String, tokio::task::JoinHandle<()>), Box<dyn StdError>>
    {
        let app = Router::new()
            .route("/health", get(mock_health))
            .route("/{*path}", post(mock_post));

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok((base, handle))
    }

    async fn start_unavailable_health_server()
    -> Result<(String, tokio::task::JoinHandle<()>), Box<dyn StdError>> {
        let app = Router::new().route("/health", get(unavailable_health));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok((base, handle))
    }

    async fn profile_mismatch_post(uri: Uri) -> Response {
        let payload = match uri.path() {
            "/v1/rooms/join_ticket" => encode_proto(JoinTicketResponse {
                profile_version: "v0.1.0".to_string(),
                ..JoinTicketResponse::default()
            }),
            "/v1/rooms/merge_ticket" => {
                let mut response = merge_ticket_ok_payload();
                response.profile_version = "v0.1.0".to_string();
                encode_proto(response)
            }
            _ => {
                return (
                    HttpStatusCode::NOT_FOUND,
                    [(header::CONTENT_TYPE, "application/json")],
                    br#"{"message":"resource not found","freeze_code":404}"#.to_vec(),
                )
                    .into_response();
            }
        };

        (
            HttpStatusCode::OK,
            [(header::CONTENT_TYPE, "application/x-protobuf")],
            payload,
        )
            .into_response()
    }

    async fn start_profile_mismatch_server()
    -> Result<(String, tokio::task::JoinHandle<()>), Box<dyn StdError>> {
        let app = Router::new()
            .route("/health", get(mock_health))
            .route("/{*path}", post(profile_mismatch_post));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok((base, handle))
    }

    async fn start_merge_ticket_server(
        payload: MergeTicketResponse,
    ) -> Result<(String, tokio::task::JoinHandle<()>), Box<dyn StdError>> {
        let app = Router::new().route(
            "/v1/rooms/merge_ticket",
            post(move || {
                let payload = payload.clone();
                async move {
                    (
                        HttpStatusCode::OK,
                        [(header::CONTENT_TYPE, "application/x-protobuf")],
                        encode_proto(payload),
                    )
                        .into_response()
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok((base, handle))
    }

    async fn auth_header_post(uri: Uri, headers: HeaderMap) -> Response {
        match uri.path() {
            "/v1/config/window" => {
                if headers
                    .get(ADMIN_TOKEN_HEADER)
                    .and_then(|value| value.to_str().ok())
                    == Some("admin-secret")
                {
                    (
                        HttpStatusCode::OK,
                        [(header::CONTENT_TYPE, "application/x-protobuf")],
                        encode_proto(ConfigureWindowResponse::default()),
                    )
                        .into_response()
                } else {
                    (
                        HttpStatusCode::UNAUTHORIZED,
                        [(header::CONTENT_TYPE, "application/json")],
                        br#"{"message":"missing admin token"}"#.to_vec(),
                    )
                        .into_response()
                }
            }
            "/v1/send_message" => {
                if headers
                    .get(MESSAGE_AUTH_HEADER)
                    .and_then(|value| value.to_str().ok())
                    == Some("msg-secret")
                {
                    (
                        HttpStatusCode::OK,
                        [(header::CONTENT_TYPE, "application/x-protobuf")],
                        encode_proto(SendMessageResponse::default()),
                    )
                        .into_response()
                } else {
                    (
                        HttpStatusCode::UNAUTHORIZED,
                        [(header::CONTENT_TYPE, "application/json")],
                        br#"{"message":"missing message token"}"#.to_vec(),
                    )
                        .into_response()
                }
            }
            _ => (
                HttpStatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "application/json")],
                br#"{"message":"resource not found","freeze_code":404}"#.to_vec(),
            )
                .into_response(),
        }
    }

    async fn start_auth_header_server()
    -> Result<(String, tokio::task::JoinHandle<()>), Box<dyn StdError>> {
        let app = Router::new().route("/{*path}", post(auth_header_post));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok((base, handle))
    }

    #[test]
    fn array32_parses_exact_length() -> Result<(), String> {
        let input = [0x11u8; 32];
        let parsed = array32(&input).map_err(|e| e.to_string())?;
        assert_eq!(parsed, input);
        Ok(())
    }

    #[test]
    fn array32_rejects_short_input() {
        let err = array32(&[0x11; 31]).expect_err("short array should fail");
        assert!(matches!(err, Error::Parse(msg) if msg.contains("invalid 32-byte field")));
    }

    #[test]
    fn parse_merge_acceptance_status_covers_final_rejected() -> Result<(), String> {
        let parsed = parse_merge_acceptance_status(PbMergeAcceptanceStatus::FinalRejected as i32)
            .map_err(|err| err.to_string())?;
        assert_eq!(parsed, MergeAcceptanceStatus::FinalRejected);
        Ok(())
    }

    #[test]
    fn parse_error_envelope_falls_back_to_raw_body() {
        let (message, freeze_code, freeze_reason, failed_index) =
            parse_error_envelope(b"plain text body");
        assert_eq!(message, "plain text body");
        assert_eq!(freeze_code, None);
        assert_eq!(freeze_reason, None);
        assert_eq!(failed_index, None);
    }

    #[test]
    fn admin_token_path_classification_and_builder() {
        assert!(CitygApiClient::requires_admin_token("/v1/config/window"));
        assert!(!CitygApiClient::requires_admin_token("/v1/rooms/bootstrap"));
        assert!(!CitygApiClient::requires_admin_token(
            "/v1/rooms/rotate_kbroad"
        ));
        assert!(!CitygApiClient::requires_admin_token(
            "/v1/rooms/grant_admin"
        ));
        assert!(!CitygApiClient::requires_admin_token(
            "/v1/rooms/revoke_admin"
        ));
        assert!(!CitygApiClient::requires_admin_token(
            "/v1/rooms/list_admins"
        ));
        assert!(!CitygApiClient::requires_admin_token(
            "/v1/rooms/expel_member_ticket"
        ));
        assert!(CitygApiClient::requires_admin_token(
            "/v1/debug/window/seed"
        ));
        assert!(!CitygApiClient::requires_admin_token("/v1/members"));
        assert!(CitygApiClient::requires_message_auth("/v1/send_message"));
        assert!(CitygApiClient::requires_message_auth("/v1/messages"));
        assert!(CitygApiClient::requires_message_auth("/v1/members"));
        assert!(CitygApiClient::requires_message_auth("/v1/members/search"));
        assert!(CitygApiClient::requires_message_auth(
            "/v1/rooms/merge_ticket"
        ));
        assert!(CitygApiClient::requires_message_auth(
            "/v1/barrier/resolve_revoked_leaves"
        ));
        assert!(CitygApiClient::requires_message_auth(
            "/v1/barrier/resolve_joins_since"
        ));
        assert!(CitygApiClient::requires_message_auth(
            "/v1/barrier/fetch_public_tree"
        ));
        assert!(CitygApiClient::requires_message_auth("/v1/bundle"));
        assert!(CitygApiClient::requires_message_auth("/v1/window"));
        assert!(CitygApiClient::requires_message_auth("/v1/telemetry"));
        assert!(CitygApiClient::requires_message_auth("/v1/pivot/refresh"));
        assert!(!CitygApiClient::requires_message_auth(
            "/v1/rooms/grant_admin"
        ));
        assert!(!CitygApiClient::requires_message_auth(
            "/v1/rooms/revoke_admin"
        ));
        assert!(!CitygApiClient::requires_message_auth(
            "/v1/rooms/list_admins"
        ));
        assert!(!CitygApiClient::requires_message_auth(
            "/v1/rooms/expel_member_ticket"
        ));

        let client = CitygApiClient::new("http://localhost:8080").with_admin_token("  secret  ");
        assert_eq!(client.admin_token.as_deref(), Some("secret"));
        let client = client.with_admin_token("   ");
        assert!(client.admin_token.is_none());

        let client =
            CitygApiClient::new("http://localhost:8080").with_message_auth_token("  msg-secret  ");
        assert_eq!(client.message_auth_token.as_deref(), Some("msg-secret"));
        let client = client.with_message_auth_token("   ");
        assert!(client.message_auth_token.is_none());
    }

    #[test]
    fn build_http_error_uses_payload_message_and_code() {
        let err = build_http_error(
            StatusCode::BAD_REQUEST,
            br#"{"message":"invalid input","freeze_code":17,"freeze_reason":"bad_field"}"#.to_vec(),
        );
        assert!(matches!(
            err,
            Error::HttpStatus {
                status: StatusCode::BAD_REQUEST,
                message,
                freeze_code: Some(17),
                freeze_reason,
                failed_index: None,
            } if message == "invalid input" && freeze_reason.as_deref() == Some("bad_field")
        ));
    }

    #[test]
    fn profile_version_validator_accepts_expected_and_rejects_mismatch() {
        assert!(ensure_profile_version(EXPECTED_PROFILE_VERSION).is_ok());
        let err = ensure_profile_version("v0.1.0").expect_err("mismatch must fail closed");
        assert!(
            matches!(err, Error::Parse(message) if message.contains("profile_version mismatch"))
        );
    }

    #[test]
    fn parse_history_authority_extension_accepts_empty_legacy_local_and_global_extensions()
    -> Result<(), String> {
        assert_eq!(
            parse_history_authority_extension("", false).map_err(|err| err.to_string())?,
            None
        );
        assert_eq!(
            parse_history_authority_extension(LOCAL_HISTORY_AUTHORITY_EXTENSION_ID, true)
                .map_err(|err| err.to_string())?,
            Some(HistoryAuthorityExtension::LocalHistoryAuthorityV1)
        );
        assert_eq!(
            parse_history_authority_extension(GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID, true)
                .map_err(|err| err.to_string())?,
            Some(HistoryAuthorityExtension::GlobalHistoryAuthorityV1)
        );
        Ok(())
    }

    #[test]
    fn parse_history_authority_extension_rejects_unnegotiated_and_unknown_extensions() {
        let err = parse_history_authority_extension("", true)
            .expect_err("extension bytes without negotiation must fail closed");
        assert!(matches!(
            err,
            Error::Parse(message)
                if message.contains("extension bytes present without negotiated extension")
        ));

        let err = parse_history_authority_extension("unknown-extension-v1", false)
            .expect_err("unknown extension id must fail closed");
        assert!(matches!(
            err,
            Error::Parse(message) if message.contains("unsupported history authority extension")
        ));
    }

    #[test]
    fn require_base_profile_history_authority_extension_enforces_global_extension() {
        assert_eq!(
            require_base_profile_history_authority_extension(
                GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID,
                "join ticket"
            )
            .expect("global extension must be accepted"),
            HistoryAuthorityExtension::GlobalHistoryAuthorityV1
        );

        let err = require_base_profile_history_authority_extension(
            LOCAL_HISTORY_AUTHORITY_EXTENSION_ID,
            "join ticket",
        )
        .expect_err("local extension must be rejected in base profile");
        assert!(matches!(
            err,
            Error::Parse(message)
                if message.contains("join ticket must carry global-history-authority-v1")
        ));

        let err = require_base_profile_history_authority_extension("", "join ticket")
            .expect_err("missing extension must be rejected");
        assert!(matches!(
            err,
            Error::Parse(message)
                if message.contains("join ticket missing required global-history-authority-v1")
        ));

        let err =
            require_base_profile_history_authority_extension("unknown-extension-v1", "join ticket")
                .expect_err("unknown extension must be rejected");
        assert!(matches!(
            err,
            Error::Parse(message)
                if message.contains(
                    "join ticket carries unsupported history authority extension: unknown-extension-v1"
                )
        ));
    }

    fn sample_runtime_pivot_parity() -> PivotParity {
        use std::sync::Arc;

        PivotParity {
            gid: vec![0x01; 32],
            cat: vec![0x02; 32],
            parent_root: [0x03; 32],
            we_epoch_id: [0x04; 32],
            rho_commit: [0x05; 32],
            seed_ctx_hash: [0x06; 32],
            seed_commit: [0x07; 32],
            hp_commit: [0x08; 32],
            xk_hash: [0x09; 32],
            join_delta_root: [0x0A; 32],
            revoked_since_root: [0x0B; 32],
            revoked_root: [0x0C; 32],
            accept_seq: 1,
            crs_id: b"crs-v1".to_vec(),
            params_id: b"params-v1".to_vec(),
            policy_version: "7".to_string(),
            proof_mode: "lin+zkvrf".to_string(),
            vrf_id: "lb-vrf".to_string(),
            vrf_proof: vec![0xDD, 0xEE],
            vrf_public: vec![0x11, 0x22],
            mask_a: [0xAA; 32],
            mask_b: [0xBB; 32],
            fs_capss: vec![0xCC],
            proofs_commit: [0xDD; 32],
            srx_commit: Some([0xEE; 32]),
            srx_root_sw: Some([0xEF; 32]),
            is_join: true,
            hp_envelope: Arc::<[u8]>::from(vec![0x99, 0x88]),
            fs_epoch_commit: None,
            fs_ec: None,
            fs_dev_commit: None,
        }
    }

    fn sample_runtime_merge_ticket() -> MergeTicket {
        MergeTicket {
            author_leaf_id: [0x55; 32],
            we_epoch_id: [0x04; 32],
            parities: vec![sample_runtime_pivot_parity()],
            witness_cbor: vec![0xA1, 0x01, 0x02],
            srx_cbor: vec![0xA1, 0x03, 0x04],
            proof_mode: "lin+zkvrf".to_string(),
            vrf_id: "lb-vrf".to_string(),
            policy_version: "7".to_string(),
            cat: [0x02; 32],
            parent_root: [0x03; 32],
            join_delta_root: [0x0A; 32],
            revoked_since_root: [0x0B; 32],
            revoked_root: [0x0C; 32],
            tswe_salt_hash: [0x0D; 32],
            pox_r_commit: [0x0E; 32],
            kbroad_public: vec![0x33; 32],
            msphf_crs_id: "crs-v1".to_string(),
            msphf_params_id: "params-v1".to_string(),
            fs_policy_version: "fs-v1".to_string(),
            fs_epoch_base_ts: 1_717_171_717,
            fs_forward_leap_policy: FsForwardLeapPolicy {
                h: 300,
                checkpoint_interval: 3600,
                slack_anchor: 0,
                slack_first_device: 0,
                slack_device: 4,
            },
            last_accepted_ec: 17,
            kbroad_generation: 3,
            barrier_version: 9,
            cover_leaf_index: 1,
            kem_tree_hash_after: [0x0F; 32],
            current_history_commitment: HistoryCommitment {
                history_view_id: [0x90; 32],
                history_commitment_id: [0x91; 32],
                prev_history_commitment_id: [0x92; 32],
                history_seq: 17,
            },
            history_authority_extension: None,
            history_authority_descriptor_bytes: Vec::new(),
            history_authority: None,
            current_global_history_attestation_bytes: Vec::new(),
            current_global_history_attestation: None,
            merge_ticket_artifact_bytes: Vec::new(),
            deployment_profile_manifest_bytes: Vec::new(),
            n_max: 8,
            max_barrier_update_bytes: 0,
        }
    }

    #[test]
    fn prepare_runtime_merge_ticket_hydrates_fs_fields_and_clamps_limit() {
        let prepared = sample_runtime_merge_ticket()
            .prepare_runtime(77, [0x44; 32], [0x55; 32], 0)
            .expect("runtime merge ticket preparation must succeed");

        assert_eq!(prepared.snapshot_hash, [0x0F; 32]);
        assert_eq!(prepared.barrier_n_max, 8);
        assert_eq!(prepared.cover_leaf_index, 1);
        assert_eq!(prepared.max_barrier_update_bytes, 1);
        assert_eq!(prepared.max_barrier_update_bytes_normalized, 1);
        assert_eq!(prepared.witness_bytes, Some(vec![0xA1, 0x01, 0x02]));
        assert_eq!(prepared.parities.len(), 1);
        assert_eq!(prepared.parities[0].fs_ec, Some(77));
        assert_eq!(prepared.parities[0].fs_epoch_commit, Some([0x44; 32]));
        assert_eq!(prepared.parities[0].fs_dev_commit, Some([0x55; 32]));
    }

    #[test]
    fn prepare_runtime_merge_ticket_rejects_stored_max_mismatch() {
        let err = sample_runtime_merge_ticket()
            .prepare_runtime(77, [0x44; 32], [0x55; 32], 64)
            .expect_err("stored max mismatch must fail");
        assert!(matches!(
            err,
            Error::Parse(message)
                if message.contains("max_barrier_update_bytes mismatch")
        ));
    }

    #[test]
    fn ensure_supported_attested_current_state_extension_requires_matching_presence() {
        ensure_supported_attested_current_state_extension("join ticket", None, &[])
            .expect("empty attestation without extension must be allowed");

        let err = ensure_supported_attested_current_state_extension(
            "join ticket",
            Some(HistoryAuthorityExtension::GlobalHistoryAuthorityV1),
            &[],
        )
        .expect_err("extension without attestation must be rejected");
        assert!(matches!(
            err,
            Error::Parse(message)
                if message.contains(
                    "join ticket carries history authority extension without current global history attestation"
                )
        ));

        let err =
            ensure_supported_attested_current_state_extension("join ticket", None, &[1, 2, 3])
                .expect_err("attestation without extension must be rejected");
        assert!(matches!(
            err,
            Error::Parse(message)
                if message.contains(
                    "join ticket carries attested current state without negotiated history authority extension"
                )
        ));

        ensure_supported_attested_current_state_extension(
            "join ticket",
            Some(HistoryAuthorityExtension::GlobalHistoryAuthorityV1),
            &[1, 2, 3],
        )
        .expect("matching extension and attestation must be allowed");
    }

    #[test]
    fn barrier_n_max_validator_rejects_zero_non_power_of_two_and_oversized_values() {
        assert_eq!(
            validate_barrier_n_max(1024).expect("1024 must be accepted"),
            1024
        );
        assert!(matches!(
            validate_barrier_n_max(0),
            Err(Error::Parse(message)) if message.contains("non-zero power of two")
        ));
        assert!(matches!(
            validate_barrier_n_max(3),
            Err(Error::Parse(message)) if message.contains("non-zero power of two")
        ));
        assert!(matches!(
            validate_barrier_n_max(MAX_BARRIER_N_MAX * 2),
            Err(Error::Parse(message)) if message.contains("MAX_BARRIER_N_MAX")
        ));
    }

    #[tokio::test]
    async fn wrappers_roundtrip_against_mock_server() -> Result<(), Box<dyn StdError>> {
        let (base_url, handle) = start_mock_server().await?;
        let client = CitygApiClient::with_http_client(base_url, Client::new());
        let demo_bundle = demo_bundle_alice()?;
        let (pop_public_key, pop_secret_key) = generate_room_admin_keypair();
        let target_pop_public_key = vec![0xA1; 32];

        client.health().await?;
        client
            .bootstrap_room_as_admin(
                "room-1",
                &[0xAB; 32],
                build_room_admin_proof(
                    RoomAdminOperation::Bootstrap,
                    "room-1",
                    &[0xAB; 32],
                    &pop_public_key,
                    &pop_secret_key,
                )?,
            )
            .await?;
        let _ = client
            .rotate_room_kbroad_as_admin(
                "room-1",
                &[0xBC; 32],
                build_room_admin_proof(
                    RoomAdminOperation::RotateKbroad,
                    "room-1",
                    &[0xBC; 32],
                    &pop_public_key,
                    &pop_secret_key,
                )?,
            )
            .await?;
        let grant = client
            .grant_room_admin(
                "room-1",
                &target_pop_public_key,
                build_room_admin_target_proof(
                    RoomAdminOperation::GrantAdmin,
                    "room-1",
                    &target_pop_public_key,
                    &pop_public_key,
                    &pop_secret_key,
                )?,
            )
            .await?;
        assert_eq!(grant.status, "granted");
        assert_eq!(grant.admin_count, 2);
        let listed = client
            .list_room_admins(
                "room-1",
                build_room_admin_listing_proof("room-1", &pop_public_key, &pop_secret_key)?,
            )
            .await?;
        assert_eq!(
            listed.admin_pop_public_keys,
            vec![vec![0xA1; 32], vec![0xB2; 32]]
        );
        let revoked = client
            .revoke_room_admin(
                "room-1",
                &target_pop_public_key,
                build_room_admin_target_proof(
                    RoomAdminOperation::RevokeAdmin,
                    "room-1",
                    &target_pop_public_key,
                    &pop_public_key,
                    &pop_secret_key,
                )?,
            )
            .await?;
        assert_eq!(revoked.status, "revoked");
        assert_eq!(revoked.admin_count, 1);
        let expelled = client
            .expel_member_ticket(
                "room-1",
                &[0x01; 32],
                &[0x02; 32],
                build_room_admin_leaf_pair_proof(
                    RoomAdminOperation::ExpelMember,
                    "room-1",
                    &[0x01; 32],
                    &[0x02; 32],
                    &pop_public_key,
                    &pop_secret_key,
                )?,
            )
            .await?;
        assert_eq!(expelled.we_epoch_id, [0x01; 32]);
        let _ = client.accept_epoch_bundle(&demo_bundle).await?;
        client.refresh_pivot(&demo_bundle).await?;
        #[cfg(any(debug_assertions, feature = "debug-api"))]
        client.debug_seed_window_head(&demo_bundle).await?;

        let gid = [0x33u8; 32];
        let _ = client.members(&gid, None).await?;
        let _ = client
            .members_with_range(&gid, Some(&[0x44; 32]), Some(1), Some(16))
            .await?;
        let _ = client
            .search_members(&gid, "alice", Some(&[0x55; 32]), Some(0), Some(10))
            .await?;
        let _ = client.join_ticket("room-1", "alice", None).await?;

        let merge = client.merge_ticket("room-1", &[0x01; 32]).await?;
        assert_eq!(merge.we_epoch_id, [0x01; 32]);
        assert_eq!(merge.parent_root, [0x03; 32]);
        assert_eq!(merge.kbroad_generation, 0);
        assert_eq!(merge.cover_leaf_index, 0);
        assert_eq!(merge.kem_tree_hash_after, [0x09; 32]);
        assert_eq!(
            merge.current_history_commitment.history_commitment_id,
            [0xE1; 32]
        );
        assert_eq!(merge.n_max, 1024);
        assert_eq!(merge.max_barrier_update_bytes, 1_048_576);
        assert_eq!(merge.last_accepted_ec, 34);
        assert_eq!(merge.fs_forward_leap_policy.h, 300);
        assert_eq!(merge.fs_forward_leap_policy.checkpoint_interval, 3600);
        let refresh_merge = client.merge_ticket_refresh("room-1", &[0x01; 32]).await?;
        assert_eq!(refresh_merge.we_epoch_id, [0x01; 32]);
        let refresh_with_intent = client
            .merge_ticket_with_intent("room-1", &[0x01; 32], MergeTicketIntent::Refresh)
            .await?;
        assert_eq!(refresh_with_intent.we_epoch_id, [0x01; 32]);

        let revoked = client
            .barrier_resolve_revoked_leaves(
                "4141414141414141414141414141414141414141414141414141414141414141",
                &[0xCC; 32],
            )
            .await?;
        assert_eq!(revoked.history_view_id, [0xD1; 32]);
        assert_eq!(revoked.history_commitment.history_commitment_id, [0xE1; 32]);
        assert_eq!(revoked.leaf_indices, vec![1, 7]);
        let joins = client
            .barrier_resolve_joins_since(
                "4141414141414141414141414141414141414141414141414141414141414141",
                3,
            )
            .await?;
        assert_eq!(joins.history_view_id, [0xD1; 32]);
        assert_eq!(joins.history_commitment.history_commitment_id, [0xE1; 32]);
        assert_eq!(joins.records.len(), 2);
        assert_eq!(joins.records[0].leaf_index, 9);
        assert_eq!(joins.records[1].leaf_index, 10);
        assert_eq!(joins.records[0].ek_leaf.len(), 1184);
        let tree = client
            .barrier_fetch_public_tree(
                "4141414141414141414141414141414141414141414141414141414141414141",
                &[0xCC; 32],
            )
            .await?;
        assert_eq!(tree.history_view_id, [0xD1; 32]);
        assert_eq!(tree.history_commitment.history_commitment_id, [0xE1; 32]);
        assert_eq!(tree.tree.n_max, 8);
        assert_eq!(tree.tree.kem_tree_hash_after, [0xCC; 32]);
        assert_eq!(tree.tree.pk_entries.len(), 15);
        let acceptance = client
            .barrier_lookup_merge_acceptance(
                "4141414141414141414141414141414141414141414141414141414141414141",
                11,
                &[0x44; 32],
                &[0x55; 32],
            )
            .await?;
        assert_eq!(acceptance.status, MergeAcceptanceStatus::Accepted);
        assert_eq!(acceptance.history_view_id, [0xD1; 32]);
        assert_eq!(
            acceptance.history_commitment.history_commitment_id,
            [0xE2; 32]
        );
        assert_eq!(acceptance.accepted_barrier_version, Some(11));
        assert_eq!(acceptance.accepted_fs_ec, Some(22));
        assert_eq!(acceptance.accepted_reason, Some(1));
        assert_eq!(acceptance.accepted_digest, Some([0xDD; 32]));

        let _ = client
            .send_message(&[0x22; 32], b"ciphertext", Some(&[0xAA; 32]))
            .await?;
        let _ = client.fetch_messages(&[0x22; 32], &[0xAA; 32]).await?;
        let _ = client.get_bundle(&[0x22; 32]).await?;
        let _ = client.window().await?;
        let _ = client.telemetry().await?;
        let _ = client.configure_window(Some(8), Some(120_000)).await?;

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn join_ticket_rejects_existing_group_without_current_barrier_update()
    -> Result<(), Box<dyn StdError>> {
        async fn mock_existing_group_without_barrier_update() -> impl IntoResponse {
            let mut response = join_ticket_ok_payload();
            response.parent_root = vec![0x11; 32];
            response.barrier_version = 2;
            response.current_barrier_update.clear();
            encode_proto(response)
        }

        let app = Router::new().route("/health", get(mock_health)).route(
            "/v1/rooms/join_ticket",
            post(mock_existing_group_without_barrier_update),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = CitygApiClient::new(base);
        let err = client
            .join_ticket("room-1", "alice", None)
            .await
            .expect_err("missing current barrier update must fail closed for existing group");
        assert!(
            err.to_string()
                .contains("join ticket missing current_barrier_update"),
            "unexpected error: {err}"
        );
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn join_ticket_rejects_existing_group_without_current_history_commitment()
    -> Result<(), Box<dyn StdError>> {
        async fn mock_existing_group_without_commitment() -> impl IntoResponse {
            let mut response = join_ticket_ok_payload();
            response.parent_root = vec![0x11; 32];
            response.barrier_version = 2;
            response.current_history_commitment = None;
            response.current_barrier_update = vec![0xAA];
            response.current_predecessor_kem_tree_hash_after = vec![0x99; 32];
            encode_proto(response)
        }

        let app = Router::new().route("/health", get(mock_health)).route(
            "/v1/rooms/join_ticket",
            post(mock_existing_group_without_commitment),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = CitygApiClient::new(base);
        let err = client
            .join_ticket("room-1", "alice", None)
            .await
            .expect_err("missing current history commitment must fail closed");
        assert!(
            err.to_string()
                .contains("join ticket missing current_history_commitment"),
            "unexpected error: {err}"
        );
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn join_ticket_rejects_existing_group_without_predecessor_hash()
    -> Result<(), Box<dyn StdError>> {
        async fn mock_existing_group_without_predecessor_hash() -> impl IntoResponse {
            let mut response = join_ticket_ok_payload();
            response.parent_root = vec![0x11; 32];
            response.barrier_version = 2;
            response.current_barrier_update = vec![0xAA];
            response.current_predecessor_kem_tree_hash_after.clear();
            encode_proto(response)
        }

        let app = Router::new().route("/health", get(mock_health)).route(
            "/v1/rooms/join_ticket",
            post(mock_existing_group_without_predecessor_hash),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = CitygApiClient::new(base);
        let err = client
            .join_ticket("room-1", "alice", None)
            .await
            .expect_err("missing predecessor hash must fail closed");
        assert!(
            err.to_string()
                .contains("join ticket missing current_predecessor_kem_tree_hash_after"),
            "unexpected error: {err}"
        );
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn join_ticket_rejects_missing_join_finalize_auth_token() -> Result<(), Box<dyn StdError>>
    {
        async fn mock_join_ticket_without_auth_token() -> impl IntoResponse {
            let mut response = join_ticket_ok_payload();
            response.join_finalize_auth_token.clear();
            encode_proto(response)
        }

        let app = Router::new().route("/health", get(mock_health)).route(
            "/v1/rooms/join_ticket",
            post(mock_join_ticket_without_auth_token),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = CitygApiClient::new(base);
        let err = client
            .join_ticket("room-1", "alice", None)
            .await
            .expect_err("missing join_finalize auth token must fail closed");
        assert!(
            err.to_string()
                .contains("join ticket missing join_finalize_auth_token"),
            "unexpected error: {err}"
        );
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn join_ticket_rejects_missing_provisioning_nonce() -> Result<(), Box<dyn StdError>> {
        async fn mock_join_ticket_without_provisioning_nonce() -> impl IntoResponse {
            let mut response = join_ticket_ok_payload();
            response.provisioning_nonce.clear();
            encode_proto(response)
        }

        let app = Router::new().route("/health", get(mock_health)).route(
            "/v1/rooms/join_ticket",
            post(mock_join_ticket_without_provisioning_nonce),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = CitygApiClient::new(base);
        let err = client
            .join_ticket("room-1", "alice", None)
            .await
            .expect_err("missing provisioning nonce must fail closed");
        assert!(
            err.to_string()
                .contains("join ticket missing provisioning_nonce"),
            "unexpected error: {err}"
        );
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn join_ticket_rejects_missing_fs_forward_leap_policy() -> Result<(), Box<dyn StdError>> {
        async fn mock_join_ticket_without_fs_forward_leap_policy() -> impl IntoResponse {
            let mut response = join_ticket_ok_payload();
            response.fs_forward_leap_policy = None;
            encode_proto(response)
        }

        let app = Router::new().route("/health", get(mock_health)).route(
            "/v1/rooms/join_ticket",
            post(mock_join_ticket_without_fs_forward_leap_policy),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = CitygApiClient::new(base);
        let err = client
            .join_ticket("room-1", "alice", None)
            .await
            .expect_err("missing fs_forward_leap_policy must fail closed");
        assert!(
            err.to_string().contains("missing fs_forward_leap_policy"),
            "unexpected error: {err}"
        );
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn join_ticket_rejects_expired_provisioning_artifact() -> Result<(), Box<dyn StdError>> {
        async fn mock_join_ticket_with_expired_provisioning() -> impl IntoResponse {
            let mut response = join_ticket_ok_payload();
            response.provisioning_issued_at_ms = 1;
            response.provisioning_expires_at_ms = 2;
            response.provisioning_artifact = build_test_join_provisioning_artifact(&response);
            encode_proto(response)
        }

        let app = Router::new().route("/health", get(mock_health)).route(
            "/v1/rooms/join_ticket",
            post(mock_join_ticket_with_expired_provisioning),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = CitygApiClient::new(base);
        let err = client
            .join_ticket("room-1", "alice", None)
            .await
            .expect_err("expired provisioning artifact must fail closed");
        assert!(
            err.to_string()
                .contains("join ticket provisioning artifact expired"),
            "unexpected error: {err}"
        );
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn join_ticket_rejects_missing_provisioning_artifact() -> Result<(), Box<dyn StdError>> {
        async fn mock_join_ticket_without_provisioning_artifact() -> impl IntoResponse {
            let mut response = join_ticket_ok_payload();
            response.provisioning_artifact.clear();
            encode_proto(response)
        }

        let app = Router::new().route("/health", get(mock_health)).route(
            "/v1/rooms/join_ticket",
            post(mock_join_ticket_without_provisioning_artifact),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = CitygApiClient::new(base);
        let err = client
            .join_ticket("room-1", "alice", None)
            .await
            .expect_err("missing provisioning_artifact must fail closed");
        assert!(
            err.to_string()
                .contains("join ticket missing provisioning_artifact"),
            "unexpected error: {err}"
        );
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn join_ticket_rejects_missing_deployment_profile_manifest()
    -> Result<(), Box<dyn StdError>> {
        async fn mock_join_ticket_without_deployment_profile_manifest() -> impl IntoResponse {
            let mut response = join_ticket_ok_payload();
            response.deployment_profile_manifest.clear();
            encode_proto(response)
        }

        let app = Router::new().route("/health", get(mock_health)).route(
            "/v1/rooms/join_ticket",
            post(mock_join_ticket_without_deployment_profile_manifest),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = CitygApiClient::new(base);
        let err = client
            .join_ticket("room-1", "alice", None)
            .await
            .expect_err("missing deployment_profile_manifest must fail closed");
        assert!(matches!(
            err,
            Error::Parse(message) if message.contains("missing deployment_profile_manifest")
        ));
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn join_ticket_rejects_tampered_deployment_profile_manifest()
    -> Result<(), Box<dyn StdError>> {
        async fn mock_join_ticket_with_tampered_deployment_profile_manifest() -> impl IntoResponse {
            let mut response = join_ticket_ok_payload();
            let last = response
                .deployment_profile_manifest
                .last_mut()
                .expect("deployment profile manifest bytes");
            *last ^= 0x01;
            encode_proto(response)
        }

        let app = Router::new().route("/health", get(mock_health)).route(
            "/v1/rooms/join_ticket",
            post(mock_join_ticket_with_tampered_deployment_profile_manifest),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = CitygApiClient::new(base);
        let err = client
            .join_ticket("room-1", "alice", None)
            .await
            .expect_err("tampered deployment_profile_manifest must fail closed");
        assert!(matches!(
            err,
            Error::Parse(message)
                if message.contains("history authority signature verification failed")
        ));
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn join_ticket_rejects_tampered_provisioning_artifact() -> Result<(), Box<dyn StdError>> {
        async fn mock_join_ticket_with_tampered_provisioning_artifact() -> impl IntoResponse {
            let mut response = join_ticket_ok_payload();
            response.provisioning_expires_at_ms =
                response.provisioning_expires_at_ms.saturating_sub(1);
            encode_proto(response)
        }

        let app = Router::new().route("/health", get(mock_health)).route(
            "/v1/rooms/join_ticket",
            post(mock_join_ticket_with_tampered_provisioning_artifact),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = CitygApiClient::new(base);
        let err = client
            .join_ticket("room-1", "alice", None)
            .await
            .expect_err("tampered provisioning_artifact must fail closed");
        assert!(
            err.to_string()
                .contains("join provisioning artifact token or expiry mismatch"),
            "unexpected error: {err}"
        );
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn join_ticket_rejects_profile_version_mismatch() -> Result<(), Box<dyn StdError>> {
        let (base_url, handle) = start_profile_mismatch_server().await?;
        let client = CitygApiClient::new(base_url);
        let err = client
            .join_ticket("room-1", "alice", None)
            .await
            .expect_err("profile mismatch must fail closed");
        assert!(matches!(
            err,
            Error::Parse(message) if message.contains("profile_version mismatch")
        ));
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn join_ticket_rejects_out_of_profile_suite_ids() -> Result<(), Box<dyn StdError>> {
        async fn mock_join_ticket_with_bad_suite_ids() -> impl IntoResponse {
            let mut response = join_ticket_ok_payload();
            response.proof_mode = "smallwood".to_string();
            encode_proto(response)
        }

        let app = Router::new().route("/health", get(mock_health)).route(
            "/v1/rooms/join_ticket",
            post(mock_join_ticket_with_bad_suite_ids),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = CitygApiClient::new(base);
        let err = client
            .join_ticket("room-1", "alice", None)
            .await
            .expect_err("out-of-profile suite ids must fail closed");
        assert!(matches!(
            err,
            Error::Parse(message) if message.contains("join ticket proof_mode mismatch")
        ));
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn merge_ticket_rejects_profile_version_mismatch() -> Result<(), Box<dyn StdError>> {
        let (base_url, handle) = start_profile_mismatch_server().await?;
        let client = CitygApiClient::new(base_url);
        let err = client
            .merge_ticket("room-1", &[0x01; 32])
            .await
            .expect_err("profile mismatch must fail closed");
        assert!(matches!(
            err,
            Error::Parse(message) if message.contains("profile_version mismatch")
        ));
        let req = MembersRequest {
            gid: vec![0x01; 32],
            parent_root: Vec::new(),
            offset: None,
            limit: None,
        };
        let not_found = client
            .post_proto_with_retry::<MembersResponse>("/v1/unknown", req, 0)
            .await
            .expect_err("unknown path should return HttpStatus");
        assert!(matches!(
            not_found,
            Error::HttpStatus {
                status: StatusCode::NOT_FOUND,
                freeze_code: Some(404),
                ..
            }
        ));
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn merge_ticket_rejects_out_of_profile_suite_ids() -> Result<(), Box<dyn StdError>> {
        let mut payload = merge_ticket_ok_payload();
        payload.vrf_id = "lb-vrf-v1".to_string();
        let (base_url, handle) = start_merge_ticket_server(payload).await?;
        let client = CitygApiClient::new(base_url);
        let err = client
            .merge_ticket("room-1", &[0x01; 32])
            .await
            .expect_err("out-of-profile suite ids must fail closed");
        assert!(matches!(
            err,
            Error::Parse(message) if message.contains("merge ticket vrf_id mismatch")
        ));
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn merge_ticket_rejects_invalid_kem_tree_hash_length() -> Result<(), Box<dyn StdError>> {
        let mut payload = merge_ticket_ok_payload();
        payload.kem_tree_hash_after = vec![0x09; 31];
        let (base_url, handle) = start_merge_ticket_server(payload).await?;
        let client = CitygApiClient::new(base_url);
        let err = client
            .merge_ticket("room-1", &[0x01; 32])
            .await
            .expect_err("invalid kem_tree_hash_after length must fail");
        assert!(matches!(
            err,
            Error::Parse(message) if message.contains("invalid 32-byte field")
        ));
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn merge_ticket_refresh_rejects_local_history_authority_in_base_profile()
    -> Result<(), Box<dyn StdError>> {
        let mut payload = merge_ticket_with_history_authority_payload();
        payload.history_authority_extension = LOCAL_HISTORY_AUTHORITY_EXTENSION_ID.to_string();
        let (base_url, handle) = start_merge_ticket_server(payload).await?;
        let client = CitygApiClient::new(base_url);
        let err = client
            .merge_ticket_refresh("room-1", &[0x01; 32])
            .await
            .expect_err("local history authority must be rejected on base-profile merge_ticket");
        assert!(matches!(
            err,
            Error::Parse(message)
                if message.contains("global-history-authority-v1")
                    && message.contains("base profile")
        ));
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn merge_ticket_refresh_accepts_global_history_authority_attestation()
    -> Result<(), Box<dyn StdError>> {
        let payload = merge_ticket_with_history_authority_payload();
        let (base_url, handle) = start_merge_ticket_server(payload).await?;
        let client = CitygApiClient::new(base_url);
        let ticket = client.merge_ticket_refresh("room-1", &[0x01; 32]).await?;
        assert_eq!(
            ticket.history_authority_extension,
            Some(HistoryAuthorityExtension::GlobalHistoryAuthorityV1)
        );
        let attestation = ticket
            .current_global_history_attestation
            .ok_or("missing parsed global history attestation")?;
        assert_eq!(
            attestation.finality_kind,
            GLOBAL_HISTORY_ATTESTATION_FINALITY_KIND
        );
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn merge_ticket_rejects_missing_merge_ticket_artifact() -> Result<(), Box<dyn StdError>> {
        let mut payload = merge_ticket_ok_payload();
        payload.merge_ticket_artifact.clear();
        let (base_url, handle) = start_merge_ticket_server(payload).await?;
        let client = CitygApiClient::new(base_url);
        let err = client
            .merge_ticket("room-1", &[0x01; 32])
            .await
            .expect_err("missing merge_ticket_artifact must fail closed");
        assert!(matches!(
            err,
            Error::Parse(message) if message.contains("missing merge_ticket_artifact")
        ));
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn merge_ticket_rejects_missing_deployment_profile_manifest()
    -> Result<(), Box<dyn StdError>> {
        let mut payload = merge_ticket_ok_payload();
        payload.deployment_profile_manifest.clear();
        let (base_url, handle) = start_merge_ticket_server(payload).await?;
        let client = CitygApiClient::new(base_url);
        let err = client
            .merge_ticket("room-1", &[0x01; 32])
            .await
            .expect_err("missing deployment_profile_manifest must fail closed");
        assert!(matches!(
            err,
            Error::Parse(message) if message.contains("missing deployment_profile_manifest")
        ));
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn merge_ticket_rejects_tampered_deployment_profile_manifest()
    -> Result<(), Box<dyn StdError>> {
        let mut payload = merge_ticket_ok_payload();
        let last = payload
            .deployment_profile_manifest
            .last_mut()
            .expect("deployment profile manifest bytes");
        *last ^= 0x01;
        let (base_url, handle) = start_merge_ticket_server(payload).await?;
        let client = CitygApiClient::new(base_url);
        let err = client
            .merge_ticket("room-1", &[0x01; 32])
            .await
            .expect_err("tampered deployment_profile_manifest must fail closed");
        assert!(matches!(
            err,
            Error::Parse(message)
                if message.contains("history authority signature verification failed")
        ));
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn merge_ticket_rejects_tampered_merge_ticket_artifact() -> Result<(), Box<dyn StdError>>
    {
        let mut payload = merge_ticket_ok_payload();
        let last = payload
            .merge_ticket_artifact
            .last_mut()
            .expect("merge ticket artifact bytes");
        *last ^= 0x01;
        let (base_url, handle) = start_merge_ticket_server(payload).await?;
        let client = CitygApiClient::new(base_url);
        let err = client
            .merge_ticket("room-1", &[0x01; 32])
            .await
            .expect_err("tampered merge_ticket_artifact must fail closed");
        assert!(matches!(
            err,
            Error::Parse(message)
                if message.contains("history authority signature verification failed")
        ));
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn merge_ticket_rejects_missing_current_history_commitment()
    -> Result<(), Box<dyn StdError>> {
        let mut payload = merge_ticket_ok_payload();
        payload.current_history_commitment = None;
        let (base_url, handle) = start_merge_ticket_server(payload).await?;
        let client = CitygApiClient::new(base_url);
        let err = client
            .merge_ticket("room-1", &[0x01; 32])
            .await
            .expect_err("missing current_history_commitment must fail");
        assert!(matches!(
            err,
            Error::Parse(message) if message.contains("missing history_commitment")
        ));
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn join_ticket_rejects_invalid_n_max() -> Result<(), Box<dyn StdError>> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let app = Router::new().route(
            "/v1/rooms/join_ticket",
            post(|| async {
                let mut response = join_ticket_ok_payload();
                response.n_max = MAX_BARRIER_N_MAX * 2;
                encode_proto(response)
            }),
        );
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = CitygApiClient::new(base);
        let err = client
            .join_ticket("room-1", "alice", None)
            .await
            .expect_err("oversized n_max must fail closed");
        assert!(matches!(
            err,
            Error::Parse(message) if message.contains("MAX_BARRIER_N_MAX")
        ));

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn barrier_fetch_public_tree_rejects_invalid_n_max() -> Result<(), Box<dyn StdError>> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let history_commitment = HistoryCommitment {
            history_view_id: [0xD1; 32],
            history_commitment_id: [0xE1; 32],
            prev_history_commitment_id: [0x00; 32],
            history_seq: 7,
        };
        let authority = build_test_history_authority(history_commitment, [0x41; 32], 7, [0xCC; 32]);
        let descriptor_bytes = authority.descriptor_bytes.clone();
        let attestation_bytes = authority.attestation_bytes.clone();
        let fs_forward_leap_policy = fs_forward_leap_policy_ok_payload();
        let deployment_profile_manifest = build_test_deployment_profile_manifest(
            &authority,
            GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID,
            &[0x41; 32],
            EXPECTED_PROFILE_VERSION,
            MAX_BARRIER_N_MAX * 2,
            1_048_576,
            &fs_forward_leap_policy,
        );
        let app = Router::new().route(
            "/v1/barrier/fetch_public_tree",
            post(move || {
                let descriptor_bytes = descriptor_bytes.clone();
                let attestation_bytes = attestation_bytes.clone();
                let fs_forward_leap_policy = fs_forward_leap_policy;
                let deployment_profile_manifest = deployment_profile_manifest.clone();
                async move {
                    encode_proto(BarrierFetchPublicTreeResponse {
                        n_max: MAX_BARRIER_N_MAX * 2,
                        kem_tree_hash_after: vec![0xCC; 32],
                        pk_entries: Vec::new(),
                        history_view_id: vec![0xD1; 32],
                        history_commitment: Some(history_commitment_ok_payload(
                            0xD1, 0xE1, 0x00, 7,
                        )),
                        history_authority_extension: GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID
                            .to_string(),
                        entry_offset: 0,
                        next_entry_offset: None,
                        total_entries: 0,
                        helper_completeness_attestation: Vec::new(),
                        history_authority_descriptor: descriptor_bytes,
                        global_history_attestation: attestation_bytes,
                        profile_version: EXPECTED_PROFILE_VERSION.to_string(),
                        max_barrier_update_bytes: 1_048_576,
                        fs_forward_leap_policy: Some(fs_forward_leap_policy),
                        deployment_profile_manifest,
                    })
                }
            }),
        );
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = CitygApiClient::new(base);
        let err = client
            .barrier_fetch_public_tree(
                "4141414141414141414141414141414141414141414141414141414141414141",
                &[0xCC; 32],
            )
            .await
            .expect_err("oversized n_max must fail closed");
        assert!(matches!(
            err,
            Error::Parse(message) if message.contains("MAX_BARRIER_N_MAX")
        ));

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn barrier_fetch_public_tree_rejects_missing_history_commitment()
    -> Result<(), Box<dyn StdError>> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let history_commitment = HistoryCommitment {
            history_view_id: [0xD1; 32],
            history_commitment_id: [0xE1; 32],
            prev_history_commitment_id: [0x00; 32],
            history_seq: 7,
        };
        let authority = build_test_history_authority(history_commitment, [0x41; 32], 7, [0xCC; 32]);
        let descriptor_bytes = authority.descriptor_bytes.clone();
        let attestation_bytes = authority.attestation_bytes.clone();
        let fs_forward_leap_policy = fs_forward_leap_policy_ok_payload();
        let deployment_profile_manifest = build_test_deployment_profile_manifest(
            &authority,
            GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID,
            &[0x41; 32],
            EXPECTED_PROFILE_VERSION,
            8,
            1_048_576,
            &fs_forward_leap_policy,
        );
        let app = Router::new().route(
            "/v1/barrier/fetch_public_tree",
            post(move || {
                let descriptor_bytes = descriptor_bytes.clone();
                let attestation_bytes = attestation_bytes.clone();
                let fs_forward_leap_policy = fs_forward_leap_policy;
                let deployment_profile_manifest = deployment_profile_manifest.clone();
                async move {
                    encode_proto(BarrierFetchPublicTreeResponse {
                        n_max: 8,
                        kem_tree_hash_after: vec![0xCC; 32],
                        pk_entries: vec![Vec::new(); 15],
                        history_view_id: vec![0xD1; 32],
                        history_commitment: None,
                        history_authority_extension: GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID
                            .to_string(),
                        entry_offset: 0,
                        next_entry_offset: None,
                        total_entries: 15,
                        helper_completeness_attestation: Vec::new(),
                        history_authority_descriptor: descriptor_bytes,
                        global_history_attestation: attestation_bytes,
                        profile_version: EXPECTED_PROFILE_VERSION.to_string(),
                        max_barrier_update_bytes: 1_048_576,
                        fs_forward_leap_policy: Some(fs_forward_leap_policy),
                        deployment_profile_manifest,
                    })
                }
            }),
        );
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = CitygApiClient::new(base);
        let err = client
            .barrier_fetch_public_tree(
                "4141414141414141414141414141414141414141414141414141414141414141",
                &[0xCC; 32],
            )
            .await
            .expect_err("missing history_commitment must fail closed");
        assert!(matches!(
            err,
            Error::Parse(message) if message.contains("missing history_commitment")
        ));

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn barrier_resolve_revoked_leaves_rejects_unexpected_completeness_attestation()
    -> Result<(), Box<dyn StdError>> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let history_commitment = HistoryCommitment {
            history_view_id: [0xD1; 32],
            history_commitment_id: [0xE1; 32],
            prev_history_commitment_id: [0x00; 32],
            history_seq: 7,
        };
        let authority = build_test_history_authority(history_commitment, [0x41; 32], 7, [0xCC; 32]);
        let descriptor_bytes = authority.descriptor_bytes.clone();
        let attestation_bytes = authority.attestation_bytes.clone();
        let fs_forward_leap_policy = fs_forward_leap_policy_ok_payload();
        let deployment_profile_manifest = build_test_deployment_profile_manifest(
            &authority,
            GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID,
            &[0x41; 32],
            EXPECTED_PROFILE_VERSION,
            8,
            1_048_576,
            &fs_forward_leap_policy,
        );
        let app = Router::new().route(
            "/v1/barrier/resolve_revoked_leaves",
            post(move || {
                let descriptor_bytes = descriptor_bytes.clone();
                let attestation_bytes = attestation_bytes.clone();
                let fs_forward_leap_policy = fs_forward_leap_policy;
                let deployment_profile_manifest = deployment_profile_manifest.clone();
                async move {
                    encode_proto(BarrierResolveRevokedLeavesResponse {
                        leaf_indices: vec![1, 2],
                        history_view_id: vec![0xD1; 32],
                        history_commitment: Some(history_commitment_ok_payload(
                            0xD1, 0xE1, 0x00, 7,
                        )),
                        history_authority_extension: GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID
                            .to_string(),
                        page_offset: 0,
                        next_page_offset: None,
                        total_entries: 2,
                        helper_completeness_attestation: vec![0xAA, 0xBB],
                        history_authority_descriptor: descriptor_bytes,
                        global_history_attestation: attestation_bytes,
                        profile_version: EXPECTED_PROFILE_VERSION.to_string(),
                        n_max: 8,
                        max_barrier_update_bytes: 1_048_576,
                        fs_forward_leap_policy: Some(fs_forward_leap_policy),
                        deployment_profile_manifest,
                    })
                }
            }),
        );
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = CitygApiClient::new(base);
        let err = client
            .barrier_resolve_revoked_leaves(
                "4141414141414141414141414141414141414141414141414141414141414141",
                &[0xCC; 32],
            )
            .await
            .expect_err("unexpected completeness attestation must fail closed");
        assert!(matches!(
            err,
            Error::Parse(message) if message.contains("helper_completeness_attestation")
        ));

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn barrier_resolve_joins_since_rejects_unexpected_completeness_attestation()
    -> Result<(), Box<dyn StdError>> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let history_commitment = HistoryCommitment {
            history_view_id: [0xD1; 32],
            history_commitment_id: [0xE1; 32],
            prev_history_commitment_id: [0x00; 32],
            history_seq: 7,
        };
        let authority = build_test_history_authority(history_commitment, [0x41; 32], 7, [0xCC; 32]);
        let descriptor_bytes = authority.descriptor_bytes.clone();
        let attestation_bytes = authority.attestation_bytes.clone();
        let fs_forward_leap_policy = fs_forward_leap_policy_ok_payload();
        let deployment_profile_manifest = build_test_deployment_profile_manifest(
            &authority,
            GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID,
            &[0x41; 32],
            EXPECTED_PROFILE_VERSION,
            8,
            1_048_576,
            &fs_forward_leap_policy,
        );
        let app = Router::new().route(
            "/v1/barrier/resolve_joins_since",
            post(move || {
                let descriptor_bytes = descriptor_bytes.clone();
                let attestation_bytes = attestation_bytes.clone();
                let fs_forward_leap_policy = fs_forward_leap_policy;
                let deployment_profile_manifest = deployment_profile_manifest.clone();
                async move {
                    encode_proto(BarrierResolveJoinsSinceResponse {
                        records: vec![pb::BarrierJoinLeafRecord {
                            device_pk: vec![0xAA; 32],
                            leaf_index: 9,
                            ek_leaf: vec![0xBB; 1184],
                        }],
                        history_view_id: vec![0xD1; 32],
                        history_commitment: Some(history_commitment_ok_payload(
                            0xD1, 0xE1, 0x00, 7,
                        )),
                        history_authority_extension: GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID
                            .to_string(),
                        page_offset: 0,
                        next_page_offset: None,
                        total_entries: 1,
                        helper_completeness_attestation: vec![0xCC],
                        history_authority_descriptor: descriptor_bytes,
                        global_history_attestation: attestation_bytes,
                        profile_version: EXPECTED_PROFILE_VERSION.to_string(),
                        n_max: 8,
                        max_barrier_update_bytes: 1_048_576,
                        fs_forward_leap_policy: Some(fs_forward_leap_policy),
                        deployment_profile_manifest,
                    })
                }
            }),
        );
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = CitygApiClient::new(base);
        let err = client
            .barrier_resolve_joins_since(
                "4141414141414141414141414141414141414141414141414141414141414141",
                0,
            )
            .await
            .expect_err("unexpected completeness attestation must fail closed");
        assert!(matches!(
            err,
            Error::Parse(message) if message.contains("helper_completeness_attestation")
        ));

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn barrier_resolve_revoked_leaves_rejects_missing_deployment_profile_manifest()
    -> Result<(), Box<dyn StdError>> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let history_commitment = HistoryCommitment {
            history_view_id: [0xD1; 32],
            history_commitment_id: [0xE1; 32],
            prev_history_commitment_id: [0x00; 32],
            history_seq: 7,
        };
        let authority = build_test_history_authority(history_commitment, [0x41; 32], 7, [0xCC; 32]);
        let descriptor_bytes = authority.descriptor_bytes.clone();
        let attestation_bytes = authority.attestation_bytes.clone();
        let fs_forward_leap_policy = fs_forward_leap_policy_ok_payload();
        let app = Router::new().route(
            "/v1/barrier/resolve_revoked_leaves",
            post(move || {
                let descriptor_bytes = descriptor_bytes.clone();
                let attestation_bytes = attestation_bytes.clone();
                let fs_forward_leap_policy = fs_forward_leap_policy;
                async move {
                    encode_proto(BarrierResolveRevokedLeavesResponse {
                        leaf_indices: vec![1, 2],
                        history_view_id: vec![0xD1; 32],
                        history_commitment: Some(history_commitment_ok_payload(
                            0xD1, 0xE1, 0x00, 7,
                        )),
                        page_offset: 0,
                        next_page_offset: None,
                        total_entries: 2,
                        helper_completeness_attestation: Vec::new(),
                        history_authority_descriptor: descriptor_bytes,
                        global_history_attestation: attestation_bytes,
                        history_authority_extension: GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID
                            .to_string(),
                        profile_version: EXPECTED_PROFILE_VERSION.to_string(),
                        n_max: 8,
                        max_barrier_update_bytes: 1_048_576,
                        fs_forward_leap_policy: Some(fs_forward_leap_policy),
                        deployment_profile_manifest: Vec::new(),
                    })
                }
            }),
        );
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = CitygApiClient::new(base);
        let err = client
            .barrier_resolve_revoked_leaves(
                "4141414141414141414141414141414141414141414141414141414141414141",
                &[0xCC; 32],
            )
            .await
            .expect_err("missing deployment_profile_manifest must fail closed");
        assert!(matches!(
            err,
            Error::Parse(message) if message.contains("missing deployment_profile_manifest")
        ));

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn barrier_resolve_revoked_leaves_rejects_local_history_authority_in_base_profile()
    -> Result<(), Box<dyn StdError>> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let history_commitment = HistoryCommitment {
            history_view_id: [0xD1; 32],
            history_commitment_id: [0xE1; 32],
            prev_history_commitment_id: [0x00; 32],
            history_seq: 7,
        };
        let authority = build_test_history_authority(history_commitment, [0x41; 32], 7, [0xCC; 32]);
        let descriptor_bytes = authority.descriptor_bytes.clone();
        let attestation_bytes = authority.attestation_bytes.clone();
        let fs_forward_leap_policy = fs_forward_leap_policy_ok_payload();
        let deployment_profile_manifest = build_test_deployment_profile_manifest(
            &authority,
            LOCAL_HISTORY_AUTHORITY_EXTENSION_ID,
            &[0x41; 32],
            EXPECTED_PROFILE_VERSION,
            8,
            1_048_576,
            &fs_forward_leap_policy,
        );
        let app = Router::new().route(
            "/v1/barrier/resolve_revoked_leaves",
            post(move || {
                let descriptor_bytes = descriptor_bytes.clone();
                let attestation_bytes = attestation_bytes.clone();
                let fs_forward_leap_policy = fs_forward_leap_policy;
                let deployment_profile_manifest = deployment_profile_manifest.clone();
                async move {
                    encode_proto(BarrierResolveRevokedLeavesResponse {
                        leaf_indices: vec![1, 2],
                        history_view_id: vec![0xD1; 32],
                        history_commitment: Some(history_commitment_ok_payload(
                            0xD1, 0xE1, 0x00, 7,
                        )),
                        page_offset: 0,
                        next_page_offset: None,
                        total_entries: 2,
                        helper_completeness_attestation: Vec::new(),
                        history_authority_descriptor: descriptor_bytes,
                        global_history_attestation: attestation_bytes,
                        history_authority_extension: LOCAL_HISTORY_AUTHORITY_EXTENSION_ID
                            .to_string(),
                        profile_version: EXPECTED_PROFILE_VERSION.to_string(),
                        n_max: 8,
                        max_barrier_update_bytes: 1_048_576,
                        fs_forward_leap_policy: Some(fs_forward_leap_policy),
                        deployment_profile_manifest,
                    })
                }
            }),
        );
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = CitygApiClient::new(base);
        let err = client
            .barrier_resolve_revoked_leaves(
                "4141414141414141414141414141414141414141414141414141414141414141",
                &[0xCC; 32],
            )
            .await
            .expect_err("local history authority must be rejected on base-profile helper");
        assert!(matches!(
            err,
            Error::Parse(message)
                if message.contains("global-history-authority-v1")
                    && message.contains("base profile")
        ));

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn barrier_resolve_revoked_leaves_rejects_deployment_profile_manifest_mismatch_across_pages()
    -> Result<(), Box<dyn StdError>> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let history_commitment = HistoryCommitment {
            history_view_id: [0xD1; 32],
            history_commitment_id: [0xE1; 32],
            prev_history_commitment_id: [0x00; 32],
            history_seq: 7,
        };
        let authority = build_test_history_authority(history_commitment, [0x41; 32], 7, [0xCC; 32]);
        let descriptor_bytes = authority.descriptor_bytes.clone();
        let attestation_bytes = authority.attestation_bytes.clone();
        let fs_forward_leap_policy = fs_forward_leap_policy_ok_payload();
        let deployment_profile_manifest_page_0 = build_test_deployment_profile_manifest(
            &authority,
            GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID,
            &[0x41; 32],
            EXPECTED_PROFILE_VERSION,
            8,
            1_048_576,
            &fs_forward_leap_policy,
        );
        let deployment_profile_manifest_page_1 = build_test_deployment_profile_manifest(
            &authority,
            GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID,
            &[0x41; 32],
            EXPECTED_PROFILE_VERSION,
            8,
            1_048_577,
            &fs_forward_leap_policy,
        );
        let helper_attestation_page_0 = build_test_helper_completeness_attestation(
            &authority,
            HELPER_KIND_REVOKED_LEAVES,
            &history_commitment,
            0,
            2,
            RevokedLeavesSelector {
                revocation_roots_hash: &[0xCC; 32],
                leaf_indices: &[1],
            },
        );
        let helper_attestation_page_1 = build_test_helper_completeness_attestation(
            &authority,
            HELPER_KIND_REVOKED_LEAVES,
            &history_commitment,
            1,
            2,
            RevokedLeavesSelector {
                revocation_roots_hash: &[0xCC; 32],
                leaf_indices: &[2],
            },
        );
        let page = Arc::new(AtomicUsize::new(0));
        let app = Router::new().route(
            "/v1/barrier/resolve_revoked_leaves",
            post(move || {
                let descriptor_bytes = descriptor_bytes.clone();
                let attestation_bytes = attestation_bytes.clone();
                let deployment_profile_manifest_page_0 = deployment_profile_manifest_page_0.clone();
                let deployment_profile_manifest_page_1 = deployment_profile_manifest_page_1.clone();
                let helper_attestation_page_0 = helper_attestation_page_0.clone();
                let helper_attestation_page_1 = helper_attestation_page_1.clone();
                let page = page.clone();
                let fs_forward_leap_policy = fs_forward_leap_policy;
                async move {
                    let call_index = page.fetch_add(1, Ordering::SeqCst);
                    let (
                        leaf_indices,
                        page_offset,
                        next_page_offset,
                        max_barrier_update_bytes,
                        deployment_profile_manifest,
                        helper_completeness_attestation,
                    ) = if call_index == 0 {
                        (
                            vec![1],
                            0,
                            Some(1),
                            1_048_576,
                            deployment_profile_manifest_page_0,
                            helper_attestation_page_0,
                        )
                    } else {
                        (
                            vec![2],
                            1,
                            None,
                            1_048_577,
                            deployment_profile_manifest_page_1,
                            helper_attestation_page_1,
                        )
                    };
                    encode_proto(BarrierResolveRevokedLeavesResponse {
                        leaf_indices,
                        history_view_id: vec![0xD1; 32],
                        history_commitment: Some(history_commitment_ok_payload(
                            0xD1, 0xE1, 0x00, 7,
                        )),
                        page_offset,
                        next_page_offset,
                        total_entries: 2,
                        helper_completeness_attestation,
                        history_authority_descriptor: descriptor_bytes,
                        global_history_attestation: attestation_bytes,
                        history_authority_extension: GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID
                            .to_string(),
                        profile_version: EXPECTED_PROFILE_VERSION.to_string(),
                        n_max: 8,
                        max_barrier_update_bytes,
                        fs_forward_leap_policy: Some(fs_forward_leap_policy),
                        deployment_profile_manifest,
                    })
                }
            }),
        );
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = CitygApiClient::new(base);
        let err = client
            .barrier_resolve_revoked_leaves(
                "4141414141414141414141414141414141414141414141414141414141414141",
                &[0xCC; 32],
            )
            .await
            .expect_err("manifest mismatch across revoked-leaf pages must fail closed");
        assert!(matches!(
            err,
            Error::Parse(message) if message.contains("deployment_profile_manifest mismatch across pages")
        ));

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn barrier_resolve_joins_since_rejects_missing_deployment_profile_manifest()
    -> Result<(), Box<dyn StdError>> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let history_commitment = HistoryCommitment {
            history_view_id: [0xD1; 32],
            history_commitment_id: [0xE1; 32],
            prev_history_commitment_id: [0x00; 32],
            history_seq: 7,
        };
        let authority = build_test_history_authority(history_commitment, [0x41; 32], 7, [0xCC; 32]);
        let descriptor_bytes = authority.descriptor_bytes.clone();
        let attestation_bytes = authority.attestation_bytes.clone();
        let fs_forward_leap_policy = fs_forward_leap_policy_ok_payload();
        let app = Router::new().route(
            "/v1/barrier/resolve_joins_since",
            post(move || {
                let descriptor_bytes = descriptor_bytes.clone();
                let attestation_bytes = attestation_bytes.clone();
                let fs_forward_leap_policy = fs_forward_leap_policy;
                async move {
                    encode_proto(BarrierResolveJoinsSinceResponse {
                        records: vec![pb::BarrierJoinLeafRecord {
                            device_pk: vec![0xAA; 32],
                            leaf_index: 9,
                            ek_leaf: vec![0xBB; 1184],
                        }],
                        history_view_id: vec![0xD1; 32],
                        history_commitment: Some(history_commitment_ok_payload(
                            0xD1, 0xE1, 0x00, 7,
                        )),
                        page_offset: 0,
                        next_page_offset: None,
                        total_entries: 1,
                        helper_completeness_attestation: Vec::new(),
                        history_authority_descriptor: descriptor_bytes,
                        global_history_attestation: attestation_bytes,
                        history_authority_extension: GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID
                            .to_string(),
                        profile_version: EXPECTED_PROFILE_VERSION.to_string(),
                        n_max: 8,
                        max_barrier_update_bytes: 1_048_576,
                        fs_forward_leap_policy: Some(fs_forward_leap_policy),
                        deployment_profile_manifest: Vec::new(),
                    })
                }
            }),
        );
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = CitygApiClient::new(base);
        let err = client
            .barrier_resolve_joins_since(
                "4141414141414141414141414141414141414141414141414141414141414141",
                0,
            )
            .await
            .expect_err("missing deployment_profile_manifest must fail closed");
        assert!(matches!(
            err,
            Error::Parse(message) if message.contains("missing deployment_profile_manifest")
        ));

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn barrier_resolve_joins_since_rejects_local_history_authority_in_base_profile()
    -> Result<(), Box<dyn StdError>> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let history_commitment = HistoryCommitment {
            history_view_id: [0xD1; 32],
            history_commitment_id: [0xE1; 32],
            prev_history_commitment_id: [0x00; 32],
            history_seq: 7,
        };
        let authority = build_test_history_authority(history_commitment, [0x41; 32], 7, [0xCC; 32]);
        let descriptor_bytes = authority.descriptor_bytes.clone();
        let attestation_bytes = authority.attestation_bytes.clone();
        let fs_forward_leap_policy = fs_forward_leap_policy_ok_payload();
        let deployment_profile_manifest = build_test_deployment_profile_manifest(
            &authority,
            LOCAL_HISTORY_AUTHORITY_EXTENSION_ID,
            &[0x41; 32],
            EXPECTED_PROFILE_VERSION,
            8,
            1_048_576,
            &fs_forward_leap_policy,
        );
        let app = Router::new().route(
            "/v1/barrier/resolve_joins_since",
            post(move || {
                let descriptor_bytes = descriptor_bytes.clone();
                let attestation_bytes = attestation_bytes.clone();
                let fs_forward_leap_policy = fs_forward_leap_policy;
                let deployment_profile_manifest = deployment_profile_manifest.clone();
                async move {
                    encode_proto(BarrierResolveJoinsSinceResponse {
                        records: vec![pb::BarrierJoinLeafRecord {
                            device_pk: vec![0xAA; 32],
                            leaf_index: 9,
                            ek_leaf: vec![0xBB; 1184],
                        }],
                        history_view_id: vec![0xD1; 32],
                        history_commitment: Some(history_commitment_ok_payload(
                            0xD1, 0xE1, 0x00, 7,
                        )),
                        page_offset: 0,
                        next_page_offset: None,
                        total_entries: 1,
                        helper_completeness_attestation: Vec::new(),
                        history_authority_descriptor: descriptor_bytes,
                        global_history_attestation: attestation_bytes,
                        history_authority_extension: LOCAL_HISTORY_AUTHORITY_EXTENSION_ID
                            .to_string(),
                        profile_version: EXPECTED_PROFILE_VERSION.to_string(),
                        n_max: 8,
                        max_barrier_update_bytes: 1_048_576,
                        fs_forward_leap_policy: Some(fs_forward_leap_policy),
                        deployment_profile_manifest,
                    })
                }
            }),
        );
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = CitygApiClient::new(base);
        let err = client
            .barrier_resolve_joins_since(
                "4141414141414141414141414141414141414141414141414141414141414141",
                0,
            )
            .await
            .expect_err("local history authority must be rejected on base-profile helper");
        assert!(matches!(
            err,
            Error::Parse(message)
                if message.contains("global-history-authority-v1")
                    && message.contains("base profile")
        ));

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn barrier_resolve_joins_since_rejects_global_history_attestation_mismatch_across_pages()
    -> Result<(), Box<dyn StdError>> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let history_commitment = HistoryCommitment {
            history_view_id: [0xD1; 32],
            history_commitment_id: [0xE1; 32],
            prev_history_commitment_id: [0x00; 32],
            history_seq: 7,
        };
        let authority_page_0 =
            build_test_history_authority(history_commitment, [0x41; 32], 7, [0xCC; 32]);
        let authority_page_1 =
            build_test_history_authority(history_commitment, [0x41; 32], 8, [0xCD; 32]);
        let descriptor_bytes = authority_page_0.descriptor_bytes.clone();
        let attestation_bytes_page_0 = authority_page_0.attestation_bytes.clone();
        let attestation_bytes_page_1 = authority_page_1.attestation_bytes.clone();
        let fs_forward_leap_policy = fs_forward_leap_policy_ok_payload();
        let deployment_profile_manifest = build_test_deployment_profile_manifest(
            &authority_page_0,
            GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID,
            &[0x41; 32],
            EXPECTED_PROFILE_VERSION,
            8,
            1_048_576,
            &fs_forward_leap_policy,
        );
        let helper_attestation_page_0 = build_test_helper_completeness_attestation(
            &authority_page_0,
            HELPER_KIND_JOINS_SINCE,
            &history_commitment,
            0,
            2,
            JoinsSinceSelector {
                prev_barrier_version: 0,
                records: &[BarrierJoinRecord {
                    device_pk: vec![0xAA; 32],
                    leaf_index: 9,
                    ek_leaf: vec![0xBB; 1184],
                }],
            },
        );
        let helper_attestation_page_1 = build_test_helper_completeness_attestation(
            &authority_page_0,
            HELPER_KIND_JOINS_SINCE,
            &history_commitment,
            1,
            2,
            JoinsSinceSelector {
                prev_barrier_version: 0,
                records: &[BarrierJoinRecord {
                    device_pk: vec![0xAB; 32],
                    leaf_index: 10,
                    ek_leaf: vec![0xBC; 1184],
                }],
            },
        );
        let page = Arc::new(AtomicUsize::new(0));
        let app = Router::new().route(
            "/v1/barrier/resolve_joins_since",
            post(move || {
                let descriptor_bytes = descriptor_bytes.clone();
                let attestation_bytes_page_0 = attestation_bytes_page_0.clone();
                let attestation_bytes_page_1 = attestation_bytes_page_1.clone();
                let deployment_profile_manifest = deployment_profile_manifest.clone();
                let helper_attestation_page_0 = helper_attestation_page_0.clone();
                let helper_attestation_page_1 = helper_attestation_page_1.clone();
                let page = page.clone();
                let fs_forward_leap_policy = fs_forward_leap_policy;
                async move {
                    let call_index = page.fetch_add(1, Ordering::SeqCst);
                    let (
                        records,
                        page_offset,
                        next_page_offset,
                        global_history_attestation,
                        helper_completeness_attestation,
                    ) = if call_index == 0 {
                        (
                            vec![pb::BarrierJoinLeafRecord {
                                device_pk: vec![0xAA; 32],
                                leaf_index: 9,
                                ek_leaf: vec![0xBB; 1184],
                            }],
                            0,
                            Some(1),
                            attestation_bytes_page_0,
                            helper_attestation_page_0,
                        )
                    } else {
                        (
                            vec![pb::BarrierJoinLeafRecord {
                                device_pk: vec![0xAB; 32],
                                leaf_index: 10,
                                ek_leaf: vec![0xBC; 1184],
                            }],
                            1,
                            None,
                            attestation_bytes_page_1,
                            helper_attestation_page_1,
                        )
                    };
                    encode_proto(BarrierResolveJoinsSinceResponse {
                        records,
                        history_view_id: vec![0xD1; 32],
                        history_commitment: Some(history_commitment_ok_payload(
                            0xD1, 0xE1, 0x00, 7,
                        )),
                        page_offset,
                        next_page_offset,
                        total_entries: 2,
                        helper_completeness_attestation,
                        history_authority_descriptor: descriptor_bytes,
                        global_history_attestation,
                        history_authority_extension: GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID
                            .to_string(),
                        profile_version: EXPECTED_PROFILE_VERSION.to_string(),
                        n_max: 8,
                        max_barrier_update_bytes: 1_048_576,
                        fs_forward_leap_policy: Some(fs_forward_leap_policy),
                        deployment_profile_manifest,
                    })
                }
            }),
        );
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = CitygApiClient::new(base);
        let err = client
            .barrier_resolve_joins_since(
                "4141414141414141414141414141414141414141414141414141414141414141",
                0,
            )
            .await
            .expect_err("attestation mismatch across joins pages must fail closed");
        assert!(matches!(
            err,
            Error::Parse(message) if message.contains("global history attestation mismatch across pages")
        ));

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn barrier_fetch_public_tree_rejects_missing_deployment_profile_manifest()
    -> Result<(), Box<dyn StdError>> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let history_commitment = HistoryCommitment {
            history_view_id: [0xD1; 32],
            history_commitment_id: [0xE1; 32],
            prev_history_commitment_id: [0x00; 32],
            history_seq: 7,
        };
        let authority = build_test_history_authority(history_commitment, [0x41; 32], 7, [0xCC; 32]);
        let descriptor_bytes = authority.descriptor_bytes.clone();
        let attestation_bytes = authority.attestation_bytes.clone();
        let fs_forward_leap_policy = fs_forward_leap_policy_ok_payload();
        let app = Router::new().route(
            "/v1/barrier/fetch_public_tree",
            post(move || {
                let descriptor_bytes = descriptor_bytes.clone();
                let attestation_bytes = attestation_bytes.clone();
                let fs_forward_leap_policy = fs_forward_leap_policy;
                async move {
                    encode_proto(BarrierFetchPublicTreeResponse {
                        n_max: 8,
                        kem_tree_hash_after: vec![0xCC; 32],
                        pk_entries: vec![Vec::new(); 15],
                        history_view_id: vec![0xD1; 32],
                        history_commitment: Some(history_commitment_ok_payload(
                            0xD1, 0xE1, 0x00, 7,
                        )),
                        entry_offset: 0,
                        next_entry_offset: None,
                        total_entries: 15,
                        helper_completeness_attestation: Vec::new(),
                        history_authority_descriptor: descriptor_bytes,
                        global_history_attestation: attestation_bytes,
                        history_authority_extension: GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID
                            .to_string(),
                        profile_version: EXPECTED_PROFILE_VERSION.to_string(),
                        max_barrier_update_bytes: 1_048_576,
                        fs_forward_leap_policy: Some(fs_forward_leap_policy),
                        deployment_profile_manifest: Vec::new(),
                    })
                }
            }),
        );
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = CitygApiClient::new(base);
        let err = client
            .barrier_fetch_public_tree(
                "4141414141414141414141414141414141414141414141414141414141414141",
                &[0xCC; 32],
            )
            .await
            .expect_err("missing deployment_profile_manifest must fail closed");
        assert!(matches!(
            err,
            Error::Parse(message) if message.contains("missing deployment_profile_manifest")
        ));

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn barrier_fetch_public_tree_rejects_local_history_authority_in_base_profile()
    -> Result<(), Box<dyn StdError>> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let history_commitment = HistoryCommitment {
            history_view_id: [0xD1; 32],
            history_commitment_id: [0xE1; 32],
            prev_history_commitment_id: [0x00; 32],
            history_seq: 7,
        };
        let authority = build_test_history_authority(history_commitment, [0x41; 32], 7, [0xCC; 32]);
        let descriptor_bytes = authority.descriptor_bytes.clone();
        let attestation_bytes = authority.attestation_bytes.clone();
        let fs_forward_leap_policy = fs_forward_leap_policy_ok_payload();
        let deployment_profile_manifest = build_test_deployment_profile_manifest(
            &authority,
            LOCAL_HISTORY_AUTHORITY_EXTENSION_ID,
            &[0x41; 32],
            EXPECTED_PROFILE_VERSION,
            8,
            1_048_576,
            &fs_forward_leap_policy,
        );
        let app = Router::new().route(
            "/v1/barrier/fetch_public_tree",
            post(move || {
                let descriptor_bytes = descriptor_bytes.clone();
                let attestation_bytes = attestation_bytes.clone();
                let fs_forward_leap_policy = fs_forward_leap_policy;
                let deployment_profile_manifest = deployment_profile_manifest.clone();
                async move {
                    encode_proto(BarrierFetchPublicTreeResponse {
                        n_max: 8,
                        kem_tree_hash_after: vec![0xCC; 32],
                        pk_entries: vec![Vec::new(); 15],
                        history_view_id: vec![0xD1; 32],
                        history_commitment: Some(history_commitment_ok_payload(
                            0xD1, 0xE1, 0x00, 7,
                        )),
                        entry_offset: 0,
                        next_entry_offset: None,
                        total_entries: 15,
                        helper_completeness_attestation: Vec::new(),
                        history_authority_descriptor: descriptor_bytes,
                        global_history_attestation: attestation_bytes,
                        history_authority_extension: LOCAL_HISTORY_AUTHORITY_EXTENSION_ID
                            .to_string(),
                        profile_version: EXPECTED_PROFILE_VERSION.to_string(),
                        max_barrier_update_bytes: 1_048_576,
                        fs_forward_leap_policy: Some(fs_forward_leap_policy),
                        deployment_profile_manifest,
                    })
                }
            }),
        );
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = CitygApiClient::new(base);
        let err = client
            .barrier_fetch_public_tree(
                "4141414141414141414141414141414141414141414141414141414141414141",
                &[0xCC; 32],
            )
            .await
            .expect_err("local history authority must be rejected on base-profile helper");
        assert!(matches!(
            err,
            Error::Parse(message)
                if message.contains("global-history-authority-v1")
                    && message.contains("base profile")
        ));

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn barrier_fetch_public_tree_rejects_deployment_profile_manifest_mismatch_across_pages()
    -> Result<(), Box<dyn StdError>> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let history_commitment = HistoryCommitment {
            history_view_id: [0xD1; 32],
            history_commitment_id: [0xE1; 32],
            prev_history_commitment_id: [0x00; 32],
            history_seq: 7,
        };
        let authority = build_test_history_authority(history_commitment, [0x41; 32], 7, [0xCC; 32]);
        let descriptor_bytes = authority.descriptor_bytes.clone();
        let attestation_bytes = authority.attestation_bytes.clone();
        let fs_forward_leap_policy = fs_forward_leap_policy_ok_payload();
        let deployment_profile_manifest_page_0 = build_test_deployment_profile_manifest(
            &authority,
            GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID,
            &[0x41; 32],
            EXPECTED_PROFILE_VERSION,
            8,
            1_048_576,
            &fs_forward_leap_policy,
        );
        let deployment_profile_manifest_page_1 = build_test_deployment_profile_manifest(
            &authority,
            GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID,
            &[0x41; 32],
            EXPECTED_PROFILE_VERSION,
            8,
            1_048_577,
            &fs_forward_leap_policy,
        );
        let helper_attestation_page_0 = build_test_helper_completeness_attestation(
            &authority,
            HELPER_KIND_FETCH_PUBLIC_TREE,
            &history_commitment,
            0,
            15,
            FetchPublicTreeSelector {
                kem_tree_hash_after: &[0xCC; 32],
                pk_entries: &vec![vec![0x01; 32]; 8],
            },
        );
        let helper_attestation_page_1 = build_test_helper_completeness_attestation(
            &authority,
            HELPER_KIND_FETCH_PUBLIC_TREE,
            &history_commitment,
            8,
            15,
            FetchPublicTreeSelector {
                kem_tree_hash_after: &[0xCC; 32],
                pk_entries: &vec![vec![0x02; 32]; 7],
            },
        );
        let page = Arc::new(AtomicUsize::new(0));
        let app = Router::new().route(
            "/v1/barrier/fetch_public_tree",
            post(move || {
                let descriptor_bytes = descriptor_bytes.clone();
                let attestation_bytes = attestation_bytes.clone();
                let deployment_profile_manifest_page_0 = deployment_profile_manifest_page_0.clone();
                let deployment_profile_manifest_page_1 = deployment_profile_manifest_page_1.clone();
                let helper_attestation_page_0 = helper_attestation_page_0.clone();
                let helper_attestation_page_1 = helper_attestation_page_1.clone();
                let page = page.clone();
                let fs_forward_leap_policy = fs_forward_leap_policy;
                async move {
                    let call_index = page.fetch_add(1, Ordering::SeqCst);
                    let (
                        pk_entries,
                        entry_offset,
                        next_entry_offset,
                        max_barrier_update_bytes,
                        deployment_profile_manifest,
                        helper_completeness_attestation,
                    ) = if call_index == 0 {
                        (
                            vec![vec![0x01; 32]; 8],
                            0,
                            Some(8),
                            1_048_576,
                            deployment_profile_manifest_page_0,
                            helper_attestation_page_0,
                        )
                    } else {
                        (
                            vec![vec![0x02; 32]; 7],
                            8,
                            None,
                            1_048_577,
                            deployment_profile_manifest_page_1,
                            helper_attestation_page_1,
                        )
                    };
                    encode_proto(BarrierFetchPublicTreeResponse {
                        n_max: 8,
                        kem_tree_hash_after: vec![0xCC; 32],
                        pk_entries,
                        history_view_id: vec![0xD1; 32],
                        history_commitment: Some(history_commitment_ok_payload(
                            0xD1, 0xE1, 0x00, 7,
                        )),
                        entry_offset,
                        next_entry_offset,
                        total_entries: 15,
                        helper_completeness_attestation,
                        history_authority_descriptor: descriptor_bytes,
                        global_history_attestation: attestation_bytes,
                        history_authority_extension: GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID
                            .to_string(),
                        profile_version: EXPECTED_PROFILE_VERSION.to_string(),
                        max_barrier_update_bytes,
                        fs_forward_leap_policy: Some(fs_forward_leap_policy),
                        deployment_profile_manifest,
                    })
                }
            }),
        );
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = CitygApiClient::new(base);
        let err = client
            .barrier_fetch_public_tree(
                "4141414141414141414141414141414141414141414141414141414141414141",
                &[0xCC; 32],
            )
            .await
            .expect_err("manifest mismatch across fetch-public-tree pages must fail closed");
        assert!(matches!(
            err,
            Error::Parse(message) if message.contains("deployment_profile_manifest mismatch across pages")
        ));

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn barrier_lookup_merge_acceptance_rejects_missing_deployment_profile_manifest()
    -> Result<(), Box<dyn StdError>> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let history_commitment = HistoryCommitment {
            history_view_id: [0xD1; 32],
            history_commitment_id: [0xE2; 32],
            prev_history_commitment_id: [0xE1; 32],
            history_seq: 8,
        };
        let authority =
            build_test_history_authority(history_commitment, [0x41; 32], 11, [0xCC; 32]);
        let descriptor_bytes = authority.descriptor_bytes.clone();
        let attestation_bytes = authority.attestation_bytes.clone();
        let fs_forward_leap_policy = fs_forward_leap_policy_ok_payload();
        let app = Router::new().route(
            "/v1/barrier/lookup_merge_acceptance",
            post(move || {
                let descriptor_bytes = descriptor_bytes.clone();
                let attestation_bytes = attestation_bytes.clone();
                let fs_forward_leap_policy = fs_forward_leap_policy;
                async move {
                    encode_proto(BarrierLookupMergeAcceptanceResponse {
                        status: PbMergeAcceptanceStatus::Accepted as i32,
                        history_view_id: vec![0xD1; 32],
                        accepted_barrier_version: Some(11),
                        accepted_fs_ec: Some(22),
                        accepted_reason: Some(1),
                        accepted_digest: Some(vec![0xDD; 32]),
                        history_commitment: Some(history_commitment_ok_payload(
                            0xD1, 0xE2, 0xE1, 8,
                        )),
                        history_authority_descriptor: descriptor_bytes,
                        global_history_attestation: attestation_bytes,
                        history_authority_extension: GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID
                            .to_string(),
                        profile_version: EXPECTED_PROFILE_VERSION.to_string(),
                        n_max: 8,
                        max_barrier_update_bytes: 1_048_576,
                        fs_forward_leap_policy: Some(fs_forward_leap_policy),
                        deployment_profile_manifest: Vec::new(),
                    })
                }
            }),
        );
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = CitygApiClient::new(base);
        let err = client
            .barrier_lookup_merge_acceptance(
                "4141414141414141414141414141414141414141414141414141414141414141",
                11,
                &[0xAB; 32],
                &[0xCD; 32],
            )
            .await
            .expect_err("missing deployment_profile_manifest must fail closed");
        assert!(matches!(
            err,
            Error::Parse(message) if message.contains("missing deployment_profile_manifest")
        ));

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn barrier_lookup_merge_acceptance_rejects_local_history_authority_in_base_profile()
    -> Result<(), Box<dyn StdError>> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let history_commitment = HistoryCommitment {
            history_view_id: [0xD1; 32],
            history_commitment_id: [0xE2; 32],
            prev_history_commitment_id: [0xE1; 32],
            history_seq: 8,
        };
        let authority =
            build_test_history_authority(history_commitment, [0x41; 32], 11, [0xCC; 32]);
        let descriptor_bytes = authority.descriptor_bytes.clone();
        let attestation_bytes = authority.attestation_bytes.clone();
        let fs_forward_leap_policy = fs_forward_leap_policy_ok_payload();
        let deployment_profile_manifest = build_test_deployment_profile_manifest(
            &authority,
            LOCAL_HISTORY_AUTHORITY_EXTENSION_ID,
            &[0x41; 32],
            EXPECTED_PROFILE_VERSION,
            8,
            1_048_576,
            &fs_forward_leap_policy,
        );
        let app = Router::new().route(
            "/v1/barrier/lookup_merge_acceptance",
            post(move || {
                let descriptor_bytes = descriptor_bytes.clone();
                let attestation_bytes = attestation_bytes.clone();
                let fs_forward_leap_policy = fs_forward_leap_policy;
                let deployment_profile_manifest = deployment_profile_manifest.clone();
                async move {
                    encode_proto(BarrierLookupMergeAcceptanceResponse {
                        status: PbMergeAcceptanceStatus::Accepted as i32,
                        history_view_id: vec![0xD1; 32],
                        accepted_barrier_version: Some(11),
                        accepted_fs_ec: Some(22),
                        accepted_reason: Some(1),
                        accepted_digest: Some(vec![0xDD; 32]),
                        history_commitment: Some(history_commitment_ok_payload(
                            0xD1, 0xE2, 0xE1, 8,
                        )),
                        history_authority_descriptor: descriptor_bytes,
                        global_history_attestation: attestation_bytes,
                        history_authority_extension: LOCAL_HISTORY_AUTHORITY_EXTENSION_ID
                            .to_string(),
                        profile_version: EXPECTED_PROFILE_VERSION.to_string(),
                        n_max: 8,
                        max_barrier_update_bytes: 1_048_576,
                        fs_forward_leap_policy: Some(fs_forward_leap_policy),
                        deployment_profile_manifest,
                    })
                }
            }),
        );
        let addr: SocketAddr = listener.local_addr()?;
        let base = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = CitygApiClient::new(base);
        let err = client
            .barrier_lookup_merge_acceptance(
                "4141414141414141414141414141414141414141414141414141414141414141",
                11,
                &[0xAB; 32],
                &[0xCD; 32],
            )
            .await
            .expect_err("local history authority must be rejected on base-profile helper");
        assert!(matches!(
            err,
            Error::Parse(message)
                if message.contains("global-history-authority-v1")
                    && message.contains("base profile")
        ));

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn merge_ticket_rejects_invalid_pivot_parity_entry() -> Result<(), Box<dyn StdError>> {
        let mut payload = merge_ticket_ok_payload();
        payload.pivot_parity_cbor = vec![vec![0x01]];
        let (base_url, handle) = start_merge_ticket_server(payload).await?;
        let client = CitygApiClient::new(base_url);
        let err = client
            .merge_ticket("room-1", &[0x01; 32])
            .await
            .expect_err("invalid pivot parity must fail");
        assert!(matches!(err, Error::Bundle(_)));
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn health_returns_http_status_error_for_non_success() -> Result<(), Box<dyn StdError>> {
        let (base_url, handle) = start_unavailable_health_server().await?;
        let client = CitygApiClient::new(base_url);
        let err = client
            .health()
            .await
            .expect_err("non-success health response should fail");

        assert!(matches!(
            err,
            Error::HttpStatus {
                status: StatusCode::SERVICE_UNAVAILABLE,
                ..
            }
        ));

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn post_proto_with_retry_returns_http_status_error() -> Result<(), Box<dyn StdError>> {
        let (base_url, handle) = start_mock_server().await?;
        let client = CitygApiClient::new(base_url);
        let req = MembersRequest {
            gid: vec![0x01; 32],
            parent_root: Vec::new(),
            offset: None,
            limit: None,
        };

        let err = client
            .post_proto_with_retry::<MembersResponse>("/v1/not-found", req, 0)
            .await
            .expect_err("missing endpoint should return HttpStatus");

        assert!(matches!(
            err,
            Error::HttpStatus {
                status: StatusCode::NOT_FOUND,
                freeze_code: Some(404),
                ..
            }
        ));

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn post_proto_with_retry_returns_http_error_after_retries() {
        let client = CitygApiClient::new("http://127.0.0.1:1");
        let req = MembersRequest {
            gid: vec![0x01; 32],
            parent_root: Vec::new(),
            offset: None,
            limit: None,
        };

        let err = client
            .post_proto_with_retry::<MembersResponse>("/v1/members", req, 1)
            .await
            .expect_err("unreachable host should return Http");
        assert!(matches!(err, Error::Http(_)));
    }

    #[tokio::test]
    async fn post_proto_with_retry_attaches_admin_and_message_auth_headers()
    -> Result<(), Box<dyn StdError>> {
        let (base_url, handle) = start_auth_header_server().await?;
        let client = CitygApiClient::new(base_url)
            .with_admin_token("admin-secret")
            .with_message_auth_token("msg-secret");

        let _ = client.configure_window(Some(4), Some(60_000)).await?;
        let _ = client
            .send_message(&[0x22; 32], b"ciphertext", Some(&[0xAA; 32]))
            .await?;

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn post_proto_with_retry_rejects_missing_admin_token() -> Result<(), Box<dyn StdError>> {
        let (base_url, handle) = start_auth_header_server().await?;
        let client = CitygApiClient::new(base_url);
        let err = client
            .configure_window(Some(4), Some(60_000))
            .await
            .expect_err("missing admin token must be rejected");
        assert!(matches!(
            err,
            Error::HttpStatus {
                status: StatusCode::UNAUTHORIZED,
                ..
            }
        ));
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn legacy_room_bootstrap_helpers_fail_closed_locally() -> Result<(), Box<dyn StdError>> {
        let client = CitygApiClient::new("http://localhost:8080");
        let bootstrap_err = client
            .bootstrap_room("room-1", &[0xAA; 32])
            .await
            .expect_err("legacy bootstrap helper must fail closed");
        assert!(matches!(
            bootstrap_err,
            Error::Parse(message)
                if message.contains("bootstrap_room_as_admin")
        ));

        let rotate_err = client
            .rotate_room_kbroad("room-1", &[0xBB; 32])
            .await
            .expect_err("legacy rotate helper must fail closed");
        assert!(matches!(
            rotate_err,
            Error::Parse(message)
                if message.contains("rotate_room_kbroad_as_admin")
        ));
        Ok(())
    }

    #[tokio::test]
    async fn post_proto_with_retry_rejects_missing_message_token() -> Result<(), Box<dyn StdError>>
    {
        let (base_url, handle) = start_auth_header_server().await?;
        let client = CitygApiClient::new(base_url);
        let err = client
            .send_message(&[0x22; 32], b"ciphertext", Some(&[0xAA; 32]))
            .await
            .expect_err("missing message token must be rejected");
        assert!(matches!(
            err,
            Error::HttpStatus {
                status: StatusCode::UNAUTHORIZED,
                ..
            }
        ));
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn auth_header_server_unknown_route_returns_not_found() -> Result<(), Box<dyn StdError>> {
        let (base_url, handle) = start_auth_header_server().await?;
        let client = CitygApiClient::new(base_url);
        let request = MembersRequest {
            gid: vec![0x01; 32],
            parent_root: Vec::new(),
            offset: None,
            limit: None,
        };
        let err = client
            .post_proto_with_retry::<MembersResponse>("/v1/unknown", request, 0)
            .await
            .expect_err("unknown path should return not found");
        assert!(matches!(
            err,
            Error::HttpStatus {
                status: StatusCode::NOT_FOUND,
                freeze_code: Some(404),
                ..
            }
        ));
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn post_proto_with_retry_returns_non_retryable_builder_error() {
        let client = CitygApiClient::new("http://[::1".to_string());
        let request = MembersRequest {
            gid: vec![0x01; 32],
            parent_root: Vec::new(),
            offset: None,
            limit: None,
        };
        let err = client
            .post_proto_with_retry::<MembersResponse>("/v1/members", request, 2)
            .await
            .expect_err("invalid URL should fail without retries");
        assert!(matches!(err, Error::Http(http_err) if http_err.is_builder()));
    }

    #[test]
    fn parses_failed_index_from_error_payload() -> Result<(), String> {
        let body = br#"{
            "message":"burst step failed",
            "error":"burst_step_failed",
            "freeze_code":9449,
            "freeze_reason":"fs_burst_non_monotone_ec",
            "failed_index":5
        }"#
        .to_vec();
        let err = build_http_error(StatusCode::BAD_REQUEST, body);
        let Error::HttpStatus { failed_index, .. } = err else {
            panic!("expected HttpStatus error");
        };
        assert_eq!(failed_index, Some(5));
        Ok(())
    }
}

/// Errors that can occur when using the City-G API client.
///
/// This enum provides detailed error information for all failure modes,
/// including network errors, HTTP status codes, and City-G-specific freeze codes.
///
/// # Freeze Codes
///
/// When the server rejects an epoch, the [`Error::HttpStatus`] variant includes
/// optional `freeze_code` and `freeze_reason` fields. Common freeze codes include:
///
/// - **Code 2**: Witness validation failed (Merkle proof invalid)
/// - **Code 3**: SPHF verification failed (cryptographic proof rejected)
/// - **Code 5**: Parent root not found in window (stale parent)
/// - **Code 7**: Duplicate epoch ID (replay attempt)
/// - **Code 9**: Revocation conflict (member was revoked)
/// - **Code 11**: Window full (h_max exceeded)
///
/// See [docs/protocol/12-error-reference.md](https://github.com/pwnsdx/cityg/blob/main/docs/protocol/12-error-reference.md)
/// for the complete freeze code reference.
///
/// # Examples
///
/// ```no_run
/// use cityg_api_client::{CitygApiClient, Error};
///
/// # async fn example(client: &CitygApiClient) -> Result<(), Error> {
/// match client.health().await {
///     Ok(()) => println!("Success"),
///     Err(Error::Http(e)) => eprintln!("Network error: {}", e),
///     Err(Error::HttpStatus { status, message, freeze_code, .. }) => {
///         eprintln!("HTTP {}: {}", status, message);
///         if let Some(code) = freeze_code {
///             eprintln!("Freeze code: {}", code);
///         }
///     }
///     Err(e) => eprintln!("Other error: {}", e),
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Error)]
pub enum Error {
    /// Network or HTTP client error (connection failed, timeout, etc.)
    ///
    /// The client automatically retries network errors up to 3 times with
    /// exponential backoff before returning this error.
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    /// Protocol buffer decoding error.
    ///
    /// This indicates the server returned malformed data or an incompatible
    /// protocol buffer version.
    #[error("decode error: {0}")]
    Decode(#[from] prost::DecodeError),

    /// HTTP request failed with a non-2xx status code.
    ///
    /// This variant includes City-G-specific freeze information when available:
    /// - `status`: The HTTP status code (e.g., 400, 409, 500)
    /// - `message`: Human-readable error message
    /// - `freeze_code`: Optional City-G freeze code (see freeze code reference)
    /// - `freeze_reason`: Optional detailed freeze reason
    #[error("request failed with status {status}: {message}")]
    HttpStatus {
        /// HTTP status code
        status: StatusCode,
        /// Error message from server
        message: String,
        /// City-G freeze code (if epoch was frozen)
        freeze_code: Option<u32>,
        /// Detailed freeze reason (if epoch was frozen)
        freeze_reason: Option<String>,
        /// Index of failed burst element (if provided)
        failed_index: Option<u32>,
    },

    /// Client bundle serialization error.
    ///
    /// This occurs when converting a [`ClientEpochBundle`] to/from CBOR fails.
    #[error("bundle error: {0}")]
    Bundle(#[from] ClientError),

    /// Response parsing error.
    ///
    /// This indicates an unexpected or invalid field in the server's response.
    #[error("invalid response: {0}")]
    Parse(String),
}
