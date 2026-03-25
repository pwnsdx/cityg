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

#[allow(dead_code)]
mod pb {
    include!(concat!(env!("OUT_DIR"), "/cityg.api.v1.rs"));
}

use ciborium::ser::into_writer;
use cityg_client::{CityGError as ClientError, ClientEpochBundle, pivot::pivot_parity_from_cbor};
use msphf_orchestrator::PivotParity;
pub use pb::IdentityBinding;
pub use pb::RoomAdminProof;
use pb::{
    AcceptEpochRequest, AcceptEpochResponse, BarrierFetchPublicTreeRequest,
    BarrierFetchPublicTreeResponse, BarrierResolveJoinsSinceRequest,
    BarrierResolveJoinsSinceResponse, BarrierResolveRevokedLeavesRequest,
    BarrierResolveRevokedLeavesResponse, BootstrapRoomRequest, BootstrapRoomResponse,
    ConfigureWindowRequest, ConfigureWindowResponse, ExpelMemberTicketRequest,
    FetchMessagesRequest, FetchMessagesResponse, GetBundleRequest, GetBundleResponse,
    GetTelemetryRequest, GetTelemetryResponse, GetWindowRequest, GetWindowResponse,
    JoinTicketRequest, JoinTicketResponse, ListRoomAdminsRequest, ListRoomAdminsResponse,
    MembersRequest, MembersResponse, MergeTicketIntent as PbMergeTicketIntent, MergeTicketRequest,
    MergeTicketResponse, RefreshPivotRequest, RefreshPivotResponse, RoomAdminMutationRequest,
    RoomAdminMutationResponse, RotateRoomKbroadRequest, RotateRoomKbroadResponse,
    SearchMembersRequest, SearchMembersResponse, SendMessageRequest, SendMessageResponse,
};
#[cfg(any(debug_assertions, feature = "debug-api"))]
use pb::{SeedHeadRequest, SeedHeadResponse};
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use prost::Message;
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use std::convert::TryInto;
use std::time::Duration;
use thiserror::Error;
use tracing::warn;

const ADMIN_TOKEN_HEADER: &str = "x-cityg-admin-token";
const MESSAGE_AUTH_HEADER: &str = "x-cityg-message-token";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoomAdminOperation {
    Bootstrap,
    RotateKbroad,
    GrantAdmin,
    RevokeAdmin,
    ListAdmins,
    ExpelMember,
}

impl RoomAdminOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap_room_v1",
            Self::RotateKbroad => "rotate_room_kbroad_v1",
            Self::GrantAdmin => "grant_room_admin_v1",
            Self::RevokeAdmin => "revoke_room_admin_v1",
            Self::ListAdmins => "list_room_admins_v1",
            Self::ExpelMember => "expel_room_member_v1",
        }
    }
}

fn build_room_admin_proof_payload(
    operation: RoomAdminOperation,
    room_id: &str,
    payload: &[u8],
    pop_public_key: &[u8],
    pop_secret_key: &[u8],
) -> Result<RoomAdminProof, Error> {
    let secret_key = dilithium5::SecretKey::from_bytes(pop_secret_key)
        .map_err(|_| Error::Parse("invalid room admin secret key".to_string()))?;
    let message = (operation.as_str(), room_id, ByteBuf::from(payload.to_vec()));
    let mut payload_bytes = Vec::new();
    into_writer(&message, &mut payload_bytes)
        .map_err(|err| Error::Parse(format!("encode room admin proof payload: {err}")))?;
    let signature = dilithium5::detached_sign(&payload_bytes, &secret_key);
    Ok(RoomAdminProof {
        pop_public_key: pop_public_key.to_vec(),
        signature: signature.as_bytes().to_vec(),
    })
}

pub fn generate_room_admin_keypair() -> (Vec<u8>, Vec<u8>) {
    let (public_key, secret_key) = dilithium5::keypair();
    (
        public_key.as_bytes().to_vec(),
        secret_key.as_bytes().to_vec(),
    )
}

pub fn build_room_admin_proof(
    operation: RoomAdminOperation,
    room_id: &str,
    kbroad_public: &[u8],
    pop_public_key: &[u8],
    pop_secret_key: &[u8],
) -> Result<RoomAdminProof, Error> {
    build_room_admin_proof_payload(
        operation,
        room_id,
        kbroad_public,
        pop_public_key,
        pop_secret_key,
    )
}

pub fn build_room_admin_target_proof(
    operation: RoomAdminOperation,
    room_id: &str,
    target_pop_public_key: &[u8],
    pop_public_key: &[u8],
    pop_secret_key: &[u8],
) -> Result<RoomAdminProof, Error> {
    build_room_admin_proof_payload(
        operation,
        room_id,
        target_pop_public_key,
        pop_public_key,
        pop_secret_key,
    )
}

pub fn build_room_admin_listing_proof(
    room_id: &str,
    pop_public_key: &[u8],
    pop_secret_key: &[u8],
) -> Result<RoomAdminProof, Error> {
    build_room_admin_proof_payload(
        RoomAdminOperation::ListAdmins,
        room_id,
        &[],
        pop_public_key,
        pop_secret_key,
    )
}

pub fn build_room_admin_leaf_pair_proof(
    operation: RoomAdminOperation,
    room_id: &str,
    author_leaf_id: &[u8; 32],
    target_leaf_id: &[u8; 32],
    pop_public_key: &[u8],
    pop_secret_key: &[u8],
) -> Result<RoomAdminProof, Error> {
    let payload = (
        ByteBuf::from(author_leaf_id.to_vec()),
        ByteBuf::from(target_leaf_id.to_vec()),
    );
    let mut payload_bytes = Vec::new();
    into_writer(&payload, &mut payload_bytes)
        .map_err(|err| Error::Parse(format!("encode room admin leaf-pair payload: {err}")))?;
    build_room_admin_proof_payload(
        operation,
        room_id,
        &payload_bytes,
        pop_public_key,
        pop_secret_key,
    )
}
const EXPECTED_PROFILE_VERSION: &str = "v0.1.4";

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

    /// Performs a health check on the server.
    ///
    /// This endpoint verifies that the server is running and accepting requests.
    /// It does not validate any cryptographic state or window configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The server is unreachable (network error)
    /// - The server returns a non-2xx status code
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use cityg_api_client::CitygApiClient;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = CitygApiClient::new("http://localhost:8080");
    ///
    /// match client.health().await {
    ///     Ok(()) => println!("Server is healthy"),
    ///     Err(e) => eprintln!("Health check failed: {}", e),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn health(&self) -> Result<(), Error> {
        let url = format!("{}/health", self.base_url);
        let response = self.http.get(url).send().await?;
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let body = response.bytes().await?.to_vec();
            Err(build_http_error(status, body))
        }
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
    pub async fn accept_epoch_bundle(
        &self,
        bundle: &ClientEpochBundle,
    ) -> Result<AcceptEpochResponse, Error> {
        let bytes = bundle.to_cbor()?;
        let request = AcceptEpochRequest { bundle_cbor: bytes };
        self.post_proto("/v1/accept_epoch", request).await
    }

    /// Bootstraps a new City-G room on the server.
    ///
    /// This initializes a new group by registering its broadcast key.
    /// The broadcast key is used to derive the group identifier (GID) and
    /// must be kept consistent across all clients.
    ///
    /// # Arguments
    ///
    /// * `room_id` - Unique identifier for the room (e.g., "room-123")
    /// * `kbroad_public` - Public broadcast key (typically 32 bytes)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The room already exists
    /// - The broadcast key is invalid
    /// - Network or server error occurs
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use cityg_api_client::CitygApiClient;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = CitygApiClient::new("http://localhost:8080");
    ///
    /// // Generate a fresh broadcast key and room-admin identity.
    /// let kbroad_public = vec![0u8; 32]; // Replace with actual key generation
    /// let (pop_public_key, pop_secret_key) = cityg_api_client::generate_room_admin_keypair();
    /// let admin_proof = cityg_api_client::build_room_admin_proof(
    ///     cityg_api_client::RoomAdminOperation::Bootstrap,
    ///     "my-secure-room",
    ///     &kbroad_public,
    ///     &pop_public_key,
    ///     &pop_secret_key,
    /// )?;
    ///
    /// client
    ///     .bootstrap_room_as_admin("my-secure-room", &kbroad_public, admin_proof)
    ///     .await?;
    /// println!("Room bootstrapped successfully!");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// This legacy helper no longer submits a request. Use [`Self::bootstrap_room_as_admin`]
    /// with a room-scoped [`RoomAdminProof`] instead.
    pub async fn bootstrap_room(&self, room_id: &str, kbroad_public: &[u8]) -> Result<(), Error> {
        let _ = (room_id, kbroad_public);
        Err(Error::Parse(
            "bootstrap_room without RoomAdminProof has been removed; use bootstrap_room_as_admin"
                .to_string(),
        ))
    }

    /// Bootstraps a room using room-scoped admin proof instead of a server-global token.
    pub async fn bootstrap_room_as_admin(
        &self,
        room_id: &str,
        kbroad_public: &[u8],
        admin_proof: RoomAdminProof,
    ) -> Result<(), Error> {
        let request = BootstrapRoomRequest {
            room_id: room_id.to_string(),
            kbroad_public: kbroad_public.to_vec(),
            admin_proof: Some(admin_proof),
        };
        let _: BootstrapRoomResponse = self.post_proto("/v1/rooms/bootstrap", request).await?;
        Ok(())
    }

    /// Rotates the room KBROAD public key and returns the new generation.
    ///
    /// This legacy helper no longer submits a request. Use [`Self::rotate_room_kbroad_as_admin`]
    /// with a room-scoped [`RoomAdminProof`] instead.
    pub async fn rotate_room_kbroad(
        &self,
        room_id: &str,
        kbroad_public: &[u8],
    ) -> Result<u64, Error> {
        let _ = (room_id, kbroad_public);
        Err(Error::Parse(
            "rotate_room_kbroad without RoomAdminProof has been removed; use rotate_room_kbroad_as_admin"
                .to_string(),
        ))
    }

    /// Rotates KBROAD using room-scoped admin proof instead of a server-global token.
    pub async fn rotate_room_kbroad_as_admin(
        &self,
        room_id: &str,
        kbroad_public: &[u8],
        admin_proof: RoomAdminProof,
    ) -> Result<u64, Error> {
        let request = RotateRoomKbroadRequest {
            room_id: room_id.to_string(),
            kbroad_public: kbroad_public.to_vec(),
            admin_proof: Some(admin_proof),
        };
        let response: RotateRoomKbroadResponse =
            self.post_proto("/v1/rooms/rotate_kbroad", request).await?;
        Ok(response.kbroad_generation)
    }

    /// Grants room-admin authority to another persistent room identity.
    pub async fn grant_room_admin(
        &self,
        room_id: &str,
        target_pop_public_key: &[u8],
        admin_proof: RoomAdminProof,
    ) -> Result<RoomAdminMutationResponse, Error> {
        let request = RoomAdminMutationRequest {
            room_id: room_id.to_string(),
            target_pop_public_key: target_pop_public_key.to_vec(),
            admin_proof: Some(admin_proof),
        };
        self.post_proto("/v1/rooms/grant_admin", request).await
    }

    /// Revokes room-admin authority from a room identity.
    pub async fn revoke_room_admin(
        &self,
        room_id: &str,
        target_pop_public_key: &[u8],
        admin_proof: RoomAdminProof,
    ) -> Result<RoomAdminMutationResponse, Error> {
        let request = RoomAdminMutationRequest {
            room_id: room_id.to_string(),
            target_pop_public_key: target_pop_public_key.to_vec(),
            admin_proof: Some(admin_proof),
        };
        self.post_proto("/v1/rooms/revoke_admin", request).await
    }

    /// Lists the persistent room identities that currently hold room-admin authority.
    pub async fn list_room_admins(
        &self,
        room_id: &str,
        admin_proof: RoomAdminProof,
    ) -> Result<ListRoomAdminsResponse, Error> {
        let request = ListRoomAdminsRequest {
            room_id: room_id.to_string(),
            admin_proof: Some(admin_proof),
        };
        self.post_proto("/v1/rooms/list_admins", request).await
    }

    /// Requests a room-admin authorized merge ticket that expels another member leaf.
    pub async fn expel_member_ticket(
        &self,
        room_id: &str,
        author_leaf_id: &[u8; 32],
        target_leaf_id: &[u8; 32],
        admin_proof: RoomAdminProof,
    ) -> Result<MergeTicket, Error> {
        let request = ExpelMemberTicketRequest {
            room_id: room_id.to_string(),
            author_leaf_id: author_leaf_id.to_vec(),
            target_leaf_id: target_leaf_id.to_vec(),
            admin_proof: Some(admin_proof),
        };
        let response: MergeTicketResponse = self
            .post_proto("/v1/rooms/expel_member_ticket", request)
            .await?;
        ensure_profile_version(&response.profile_version)?;

        let we_epoch_id = array32(&response.we_epoch_id)?;
        let mut parities = Vec::with_capacity(response.pivot_parity_cbor.len());
        for entry in &response.pivot_parity_cbor {
            parities.push(pivot_parity_from_cbor(entry).map_err(Error::from)?);
        }

        let cat = array32(&response.cat)?;
        let parent_root = array32(&response.parent_root)?;
        let join_delta_root = array32(&response.join_delta_root)?;
        let revoked_since_root = array32(&response.revoked_since_root)?;
        let revoked_root = array32(&response.revoked_root)?;
        let tswe_salt_hash = array32(&response.tswe_salt_hash)?;
        let pox_r_commit = array32(&response.pox_r_commit)?;

        Ok(MergeTicket {
            we_epoch_id,
            parities,
            witness_cbor: response.witness_cbor,
            srx_cbor: response.srx_cbor,
            proof_mode: response.proof_mode,
            vrf_id: response.vrf_id,
            policy_version: response.policy_version,
            cat,
            parent_root,
            join_delta_root,
            revoked_since_root,
            revoked_root,
            tswe_salt_hash,
            pox_r_commit,
            kbroad_public: response.kbroad_public,
            msphf_crs_id: response.msphf_crs_id,
            msphf_params_id: response.msphf_params_id,
            fs_policy_version: response.fs_policy_version,
            fs_epoch_base_ts: response.fs_epoch_base_ts,
            kbroad_generation: response.kbroad_generation,
            barrier_version: response.barrier_version,
            cover_leaf_index: response.cover_leaf_index,
            kem_tree_hash_after: array32(&response.kem_tree_hash_after)?,
            n_max: response.n_max,
            max_barrier_update_bytes: response.max_barrier_update_bytes,
        })
    }

    /// Retrieves the member roster for a group.
    ///
    /// This method returns all members in the group's current state,
    /// with automatic pagination (default: 256 members per page).
    ///
    /// # Arguments
    ///
    /// * `gid` - Group identifier (derived from broadcast key)
    /// * `parent_root` - Optional: filter to members at a specific epoch root
    ///
    /// # Returns
    ///
    /// A [`MembersResponse`] containing:
    /// - `members` - List of member records with `leaf_id`, `alias`, and `identity_binding`
    /// - `total_count` - Total number of members (for pagination)
    /// - `has_more` - Whether more results exist
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use cityg_api_client::CitygApiClient;
    ///
    /// # async fn example(client: &CitygApiClient, gid: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    /// // Fetch all members (paginated automatically)
    /// let response = client.members(gid, None).await?;
    ///
    /// for member in response.members {
    ///     println!(
    ///         "Member: {} (leaf_id: {})",
    ///         member.alias.as_deref().unwrap_or("unknown"),
    ///         hex::encode(&member.leaf_id)
    ///     );
    /// }
    ///
    /// if response.next_offset > 0 {
    ///     // Use members_with_range for pagination
    ///     println!("More members available at offset: {}", response.next_offset);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn members(
        &self,
        gid: &[u8],
        parent_root: Option<&[u8; 32]>,
    ) -> Result<MembersResponse, Error> {
        self.members_with_range(gid, parent_root, None, None).await
    }

    /// Retrieves the member roster with custom pagination.
    ///
    /// Use this method when you need to control pagination for large groups.
    ///
    /// # Arguments
    ///
    /// * `gid` - Group identifier
    /// * `parent_root` - Optional: filter to specific epoch root
    /// * `offset` - Number of members to skip (for pagination)
    /// * `limit` - Maximum members to return (max: 2000, default: 256)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use cityg_api_client::CitygApiClient;
    ///
    /// # async fn example(client: &CitygApiClient, gid: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    /// // Fetch members 100-199
    /// let response = client.members_with_range(
    ///     gid,
    ///     None,
    ///     Some(100),  // offset
    ///     Some(100)   // limit
    /// ).await?;
    ///
    /// println!("Retrieved {} of {} members", response.members.len(), response.total_count);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn members_with_range(
        &self,
        gid: &[u8],
        parent_root: Option<&[u8; 32]>,
        offset: Option<u64>,
        limit: Option<u32>,
    ) -> Result<MembersResponse, Error> {
        let request = MembersRequest {
            gid: gid.to_vec(),
            parent_root: parent_root.map(|root| root.to_vec()).unwrap_or_default(),
            offset,
            limit,
        };
        self.post_proto("/v1/members", request).await
    }

    /// Searches for members by alias or leaf ID.
    ///
    /// This method performs a substring search on member aliases and
    /// exact match on hexadecimal leaf IDs.
    ///
    /// # Arguments
    ///
    /// * `gid` - Group identifier
    /// * `query` - Search term (alias substring or leaf_id hex string)
    /// * `parent_root` - Optional: filter to specific epoch root
    /// * `offset` - Pagination offset
    /// * `limit` - Maximum results (max: 2000, default: 256)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use cityg_api_client::CitygApiClient;
    ///
    /// # async fn example(client: &CitygApiClient, gid: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    /// // Search by alias substring
    /// let results = client.search_members(
    ///     gid,
    ///     "alice",
    ///     None,
    ///     None,
    ///     None
    /// ).await?;
    ///
    /// for member in results.members {
    ///     println!("Found: {} ({})",
    ///         member.alias.as_deref().unwrap_or("unknown"),
    ///         hex::encode(&member.leaf_id));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ```no_run
    /// # use cityg_api_client::CitygApiClient;
    /// # async fn example(client: &CitygApiClient, gid: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    /// // Search by exact leaf_id (hex string)
    /// let results = client.search_members(
    ///     gid,
    ///     "a3b5c7d9e1f2...",
    ///     None,
    ///     None,
    ///     None
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn search_members(
        &self,
        gid: &[u8],
        query: &str,
        parent_root: Option<&[u8; 32]>,
        offset: Option<u64>,
        limit: Option<u32>,
    ) -> Result<SearchMembersResponse, Error> {
        let request = SearchMembersRequest {
            gid: gid.to_vec(),
            query: query.to_string(),
            parent_root: parent_root.map(|root| root.to_vec()).unwrap_or_default(),
            offset,
            limit,
        };
        self.post_proto("/v1/members/search", request).await
    }

    /// Requests a join ticket for a new member.
    ///
    /// Join tickets allow clients to create their first epoch and join the group.
    /// The ticket includes initial cryptographic material and group state.
    ///
    /// # Identity Binding (TOFU)
    ///
    /// When provided, the `identity_binding` associates the member's leaf_id with
    /// a long-term identity key (e.g., Ed25519 public key). This prevents
    /// impersonation and enables "Trust On First Use" semantics.
    ///
    /// # Arguments
    ///
    /// * `room_id` - The room to join
    /// * `alias` - Human-readable username (stored in member roster)
    /// * `identity_binding` - Optional cryptographic identity binding
    ///
    /// # Returns
    ///
    /// A [`JoinTicketResponse`] containing:
    /// - Initial witness and pivot parities
    /// - Group configuration (VRF ID, policy version, etc.)
    /// - Broadcast key and CRS parameters
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use cityg_api_client::{CitygApiClient, IdentityBinding};
    ///
    /// # async fn example(client: &CitygApiClient) -> Result<(), Box<dyn std::error::Error>> {
    /// // Join without identity binding
    /// let ticket = client.join_ticket(
    ///     "my-room",
    ///     "alice",
    ///     None
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ```no_run
    /// # use cityg_api_client::{CitygApiClient, IdentityBinding};
    /// # async fn example(client: &CitygApiClient, identity: IdentityBinding) -> Result<(), Box<dyn std::error::Error>> {
    /// // Join with identity binding (recommended)
    /// // See IdentityBinding struct for field details
    ///
    /// let ticket = client.join_ticket(
    ///     "my-room",
    ///     "alice",
    ///     Some(identity)
    /// ).await?;
    ///
    /// // Use ticket to generate first epoch...
    /// # Ok(())
    /// # }
    /// ```
    pub async fn join_ticket(
        &self,
        room_id: &str,
        alias: &str,
        identity_binding: Option<IdentityBinding>,
    ) -> Result<JoinTicketResponse, Error> {
        let request = JoinTicketRequest {
            room_id: room_id.to_string(),
            alias: alias.to_string(),
            identity_binding,
        };
        let response: JoinTicketResponse =
            self.post_proto("/v1/rooms/join_ticket", request).await?;
        ensure_profile_version(&response.profile_version)?;
        Ok(response)
    }

    /// Requests a merge ticket for an existing member.
    ///
    /// Merge tickets allow clients to resync after being offline or to create
    /// a new epoch based on the current group state. The server provides fresh
    /// pivot parities and witness data.
    ///
    /// # Arguments
    ///
    /// * `room_id` - The room identifier
    /// * `leaf_id` - The member's 32-byte leaf identifier
    ///
    /// # Returns
    ///
    /// A [`MergeTicket`] containing:
    /// - Fresh pivot parities for the current window
    /// - Merkle witness to the parent root
    /// - Group configuration and cryptographic parameters
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use cityg_api_client::CitygApiClient;
    ///
    /// # async fn example(client: &CitygApiClient, leaf_id: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    /// let ticket = client.merge_ticket("my-room", leaf_id).await?;
    ///
    /// println!("Merge ticket for epoch: {}", hex::encode(&ticket.we_epoch_id));
    /// println!("Parities: {}", ticket.parities.len());
    ///
    /// // Use ticket to generate a new epoch...
    /// # Ok(())
    /// # }
    /// ```
    pub async fn merge_ticket(
        &self,
        room_id: &str,
        leaf_id: &[u8; 32],
    ) -> Result<MergeTicket, Error> {
        self.merge_ticket_with_intent(room_id, leaf_id, MergeTicketIntent::Leave)
            .await
    }

    /// Requests a merge ticket for a non-leaving PCS refresh.
    pub async fn merge_ticket_refresh(
        &self,
        room_id: &str,
        leaf_id: &[u8; 32],
    ) -> Result<MergeTicket, Error> {
        self.merge_ticket_with_intent(room_id, leaf_id, MergeTicketIntent::Refresh)
            .await
    }

    /// Requests a merge ticket with explicit intent.
    pub async fn merge_ticket_with_intent(
        &self,
        room_id: &str,
        leaf_id: &[u8; 32],
        intent: MergeTicketIntent,
    ) -> Result<MergeTicket, Error> {
        let request = MergeTicketRequest {
            room_id: room_id.to_string(),
            leaf_id: leaf_id.to_vec(),
            intent: intent.as_proto(),
        };
        let response: MergeTicketResponse =
            self.post_proto("/v1/rooms/merge_ticket", request).await?;
        ensure_profile_version(&response.profile_version)?;

        let we_epoch_id = array32(&response.we_epoch_id)?;
        let mut parities = Vec::with_capacity(response.pivot_parity_cbor.len());
        for entry in &response.pivot_parity_cbor {
            parities.push(pivot_parity_from_cbor(entry).map_err(Error::from)?);
        }

        let cat = array32(&response.cat)?;
        let parent_root = array32(&response.parent_root)?;
        let join_delta_root = array32(&response.join_delta_root)?;
        let revoked_since_root = array32(&response.revoked_since_root)?;
        let revoked_root = array32(&response.revoked_root)?;
        let tswe_salt_hash = array32(&response.tswe_salt_hash)?;
        let pox_r_commit = array32(&response.pox_r_commit)?;

        Ok(MergeTicket {
            we_epoch_id,
            parities,
            witness_cbor: response.witness_cbor,
            srx_cbor: response.srx_cbor,
            proof_mode: response.proof_mode,
            vrf_id: response.vrf_id,
            policy_version: response.policy_version,
            cat,
            parent_root,
            join_delta_root,
            revoked_since_root,
            revoked_root,
            tswe_salt_hash,
            pox_r_commit,
            kbroad_public: response.kbroad_public,
            msphf_crs_id: response.msphf_crs_id,
            msphf_params_id: response.msphf_params_id,
            fs_policy_version: response.fs_policy_version,
            fs_epoch_base_ts: response.fs_epoch_base_ts,
            kbroad_generation: response.kbroad_generation,
            barrier_version: response.barrier_version,
            cover_leaf_index: response.cover_leaf_index,
            kem_tree_hash_after: array32(&response.kem_tree_hash_after)?,
            n_max: response.n_max,
            max_barrier_update_bytes: response.max_barrier_update_bytes,
        })
    }

    /// Resolves revoked cover leaf indices for a committed revocation roots hash.
    pub async fn barrier_resolve_revoked_leaves(
        &self,
        room_id: &str,
        revocation_roots_hash: &[u8; 32],
    ) -> Result<BarrierResolvedRevokedLeaves, Error> {
        let request = BarrierResolveRevokedLeavesRequest {
            room_id: room_id.to_string(),
            revocation_roots_hash: revocation_roots_hash.to_vec(),
        };
        let response: BarrierResolveRevokedLeavesResponse = self
            .post_proto("/v1/barrier/resolve_revoked_leaves", request)
            .await?;
        Ok(BarrierResolvedRevokedLeaves {
            history_view_id: array32(&response.history_view_id)?,
            leaf_indices: response.leaf_indices,
        })
    }

    /// Resolves join records that became active after `prev_barrier_version`.
    pub async fn barrier_resolve_joins_since(
        &self,
        room_id: &str,
        prev_barrier_version: u64,
    ) -> Result<BarrierResolvedJoins, Error> {
        let request = BarrierResolveJoinsSinceRequest {
            room_id: room_id.to_string(),
            prev_barrier_version,
        };
        let response: BarrierResolveJoinsSinceResponse = self
            .post_proto("/v1/barrier/resolve_joins_since", request)
            .await?;
        Ok(BarrierResolvedJoins {
            history_view_id: array32(&response.history_view_id)?,
            records: response
                .records
                .into_iter()
                .map(|record| BarrierJoinRecord {
                    device_pk: record.device_pk,
                    leaf_index: record.leaf_index,
                    ek_leaf: record.ek_leaf,
                })
                .collect(),
        })
    }

    /// Fetches a barrier public-tree snapshot for a committed tree hash.
    pub async fn barrier_fetch_public_tree(
        &self,
        room_id: &str,
        kem_tree_hash_after: &[u8; 32],
    ) -> Result<BarrierFetchedPublicTree, Error> {
        let request = BarrierFetchPublicTreeRequest {
            room_id: room_id.to_string(),
            kem_tree_hash_after: kem_tree_hash_after.to_vec(),
        };
        let response: BarrierFetchPublicTreeResponse = self
            .post_proto("/v1/barrier/fetch_public_tree", request)
            .await?;
        Ok(BarrierFetchedPublicTree {
            history_view_id: array32(&response.history_view_id)?,
            tree: BarrierPublicTree {
                n_max: response.n_max,
                kem_tree_hash_after: array32(&response.kem_tree_hash_after)?,
                pk_entries: response.pk_entries,
            },
        })
    }

    /// Stores an encrypted message in an epoch.
    ///
    /// Messages are associated with a specific epoch ID and can be retrieved
    /// by any client that knows the epoch ID and has the decryption key.
    ///
    /// # Arguments
    ///
    /// * `we_epoch_id` - The 32-byte witness extraction epoch ID
    /// * `ciphertext` - The encrypted message payload
    /// * `sender` - Optional sender identifier (for attribution)
    ///
    /// # Returns
    ///
    /// A [`SendMessageResponse`] containing:
    /// - `message_id` - Unique identifier for the stored message
    /// - `timestamp` - Server timestamp when message was stored
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use cityg_api_client::CitygApiClient;
    ///
    /// # async fn example(client: &CitygApiClient, epoch_id: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    /// let ciphertext = b"encrypted message payload";
    ///
    /// let response = client.send_message(
    ///     epoch_id,
    ///     ciphertext,
    ///     None  // anonymous sender
    /// ).await?;
    ///
    /// println!("Message stored with status: {}", response.status);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_message(
        &self,
        we_epoch_id: &[u8; 32],
        ciphertext: &[u8],
        sender: Option<&[u8]>,
    ) -> Result<SendMessageResponse, Error> {
        let request = SendMessageRequest {
            we_epoch_id: we_epoch_id.to_vec(),
            ciphertext: ciphertext.to_vec(),
            sender: sender.unwrap_or_default().to_vec(),
        };
        self.post_proto("/v1/send_message", request).await
    }

    /// Retrieves all messages stored for a specific epoch.
    ///
    /// Returns all messages that were stored using [`send_message`](Self::send_message)
    /// for the given epoch ID.
    ///
    /// # Arguments
    ///
    /// * `we_epoch_id` - The 32-byte witness extraction epoch ID
    ///
    /// # Returns
    ///
    /// A [`FetchMessagesResponse`] containing:
    /// - `messages` - List of stored messages with ciphertext and metadata
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use cityg_api_client::CitygApiClient;
    ///
    /// # async fn example(client: &CitygApiClient, epoch_id: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    /// let leaf_id = [0u8; 32];
    /// let response = client.fetch_messages(epoch_id, &leaf_id).await?;
    ///
    /// for msg in response.messages {
    ///     println!(
    ///         "Message: {} bytes (sent: {} ms)",
    ///         msg.ciphertext.len(),
    ///         msg.timestamp_ms
    ///     );
    ///     // Decrypt using your epoch key...
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn fetch_messages(
        &self,
        we_epoch_id: &[u8; 32],
        leaf_id: &[u8; 32],
    ) -> Result<FetchMessagesResponse, Error> {
        let request = FetchMessagesRequest {
            we_epoch_id: we_epoch_id.to_vec(),
            leaf_id: leaf_id.to_vec(),
        };
        self.post_proto("/v1/messages", request).await
    }

    /// Retrieves a stored client epoch bundle by its ID.
    ///
    /// This allows clients to fetch the CBOR-encoded bundle for any epoch
    /// that was previously accepted by the server.
    ///
    /// # Arguments
    ///
    /// * `we_epoch_id` - The 32-byte epoch identifier
    ///
    /// # Returns
    ///
    /// A [`GetBundleResponse`] containing:
    /// - `bundle_cbor` - The complete CBOR-encoded epoch bundle
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use cityg_api_client::CitygApiClient;
    /// use cityg_client::ClientEpochBundle;
    ///
    /// # async fn example(client: &CitygApiClient, epoch_id: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    /// let response = client.get_bundle(epoch_id).await?;
    ///
    /// // Deserialize the bundle
    /// let bundle = ClientEpochBundle::from_cbor(&response.bundle_cbor)?;
    /// println!("Retrieved bundle for epoch: {}", hex::encode(&bundle.we_epoch_id));
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_bundle(&self, we_epoch_id: &[u8; 32]) -> Result<GetBundleResponse, Error> {
        let request = GetBundleRequest {
            we_epoch_id: we_epoch_id.to_vec(),
        };
        self.post_proto("/v1/bundle", request).await
    }

    /// Retrieves the current multi-head window state.
    ///
    /// The window contains all accepted epoch heads, their roots, and metadata.
    /// This is useful for debugging, monitoring, and understanding the current
    /// group state.
    ///
    /// # Returns
    ///
    /// A [`GetWindowResponse`] containing:
    /// - `heads` - List of all current window heads
    /// - `h_max` - Maximum number of concurrent heads allowed
    /// - `ttl_ms` - Time-to-live for window heads (milliseconds)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use cityg_api_client::CitygApiClient;
    ///
    /// # async fn example(client: &CitygApiClient) -> Result<(), Box<dyn std::error::Error>> {
    /// let window = client.window().await?;
    ///
    /// println!("Window snapshot:");
    /// println!("  Entries: {}", window.entries.len());
    ///
    /// for entry in &window.entries {
    ///     println!("  WID: {} heads", entry.heads.len());
    ///     for head in &entry.heads {
    ///         println!("    Head: {}", hex::encode(&head.we_epoch_id));
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn window(&self) -> Result<GetWindowResponse, Error> {
        self.post_proto("/v1/window", GetWindowRequest {}).await
    }

    /// Retrieves server telemetry and statistics.
    ///
    /// Provides metrics about server operation, including:
    /// - Total epochs processed
    /// - Freeze statistics by code
    /// - Window utilization
    /// - Performance metrics
    ///
    /// # Returns
    ///
    /// A [`GetTelemetryResponse`] containing server metrics and freeze statistics.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use cityg_api_client::CitygApiClient;
    ///
    /// # async fn example(client: &CitygApiClient) -> Result<(), Box<dyn std::error::Error>> {
    /// let telemetry = client.telemetry().await?;
    ///
    /// println!("Server telemetry:");
    /// // Access telemetry fields based on GetTelemetryResponse structure
    /// // See API documentation for available metrics
    /// # Ok(())
    /// # }
    /// ```
    pub async fn telemetry(&self) -> Result<GetTelemetryResponse, Error> {
        self.post_proto("/v1/telemetry", GetTelemetryRequest {})
            .await
    }

    /// Configures the multi-head window parameters.
    ///
    /// Allows runtime adjustment of window behavior:
    /// - `h_max`: Maximum number of concurrent heads (concurrency limit)
    /// - `ttl_ms`: Time-to-live for heads before eviction
    ///
    /// # Arguments
    ///
    /// * `h_max` - Optional: new maximum head count (e.g., 10, 100)
    /// * `ttl_ms` - Optional: new TTL in milliseconds (e.g., 3600000 = 1 hour)
    ///
    /// # Returns
    ///
    /// A [`ConfigureWindowResponse`] with the updated configuration.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use cityg_api_client::CitygApiClient;
    ///
    /// # async fn example(client: &CitygApiClient) -> Result<(), Box<dyn std::error::Error>> {
    /// // Increase concurrency limit to 100 heads
    /// let response = client.configure_window(Some(100), None).await?;
    /// println!("Window h_max updated to: {}", response.h_max);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ```no_run
    /// # use cityg_api_client::CitygApiClient;
    /// # async fn example(client: &CitygApiClient) -> Result<(), Box<dyn std::error::Error>> {
    /// // Set TTL to 10 minutes
    /// let response = client.configure_window(None, Some(600_000)).await?;
    /// println!("Window TTL updated to: {} ms", response.ttl_ms);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn configure_window(
        &self,
        h_max: Option<u32>,
        ttl_ms: Option<u32>,
    ) -> Result<ConfigureWindowResponse, Error> {
        let request = ConfigureWindowRequest { h_max, ttl_ms };
        self.post_proto("/v1/config/window", request).await
    }

    /// **[Debug Only]** Seeds the window head with a bundle directly.
    ///
    /// This endpoint bypasses normal validation and inserts a bundle directly
    /// into the window. Only available in debug builds or with the `debug-api` feature.
    ///
    /// # ⚠️ Warning
    ///
    /// This endpoint is for testing only and should NEVER be exposed in production.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[cfg(any(debug_assertions, feature = "debug-api"))]
    /// # async fn example(bundle: &cityg_client::ClientEpochBundle) -> Result<(), Box<dyn std::error::Error>> {
    /// use cityg_api_client::CitygApiClient;
    ///
    /// let client = CitygApiClient::new("http://localhost:8080");
    /// // Generate test bundle (implementation not shown)
    ///
    /// client.debug_seed_window_head(&bundle).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(any(debug_assertions, feature = "debug-api"))]
    pub async fn debug_seed_window_head(&self, bundle: &ClientEpochBundle) -> Result<(), Error> {
        let bytes = bundle.to_cbor()?;
        let request = SeedHeadRequest { bundle_cbor: bytes };
        let _: SeedHeadResponse = self.post_proto("/v1/debug/window/seed", request).await?;
        Ok(())
    }

    /// Refreshes the pivot for forward secrecy epoch rotation.
    ///
    /// This endpoint triggers automatic pivot rotation based on the forward
    /// secrecy policy. It should be called periodically (e.g., every hour)
    /// to maintain forward secrecy guarantees.
    ///
    /// # Arguments
    ///
    /// * `bundle` - A client epoch bundle containing the new pivot commitment
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use cityg_api_client::CitygApiClient;
    /// use cityg_client::ClientEpochBundle;
    ///
    /// # async fn example(client: &CitygApiClient, bundle: &ClientEpochBundle) -> Result<(), Box<dyn std::error::Error>> {
    /// // Generate fresh pivot bundle (implementation not shown)
    ///
    /// client.refresh_pivot(&bundle).await?;
    /// println!("Pivot refreshed for forward secrecy");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn refresh_pivot(&self, bundle: &ClientEpochBundle) -> Result<(), Error> {
        let bytes = bundle.to_cbor()?;
        let request = RefreshPivotRequest { bundle_cbor: bytes };
        self.post_proto::<RefreshPivotResponse>("/v1/pivot/refresh", request)
            .await
            .map(|_| ())
    }

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
                Ok(resp) => return Self::decode_response(resp).await,
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
                | "/v1/bundle"
                | "/v1/window"
                | "/v1/telemetry"
                | "/v1/pivot/refresh"
        )
    }
}

/// Join record returned by barrier join enumeration endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarrierJoinRecord {
    pub device_pk: Vec<u8>,
    pub leaf_index: u32,
    pub ek_leaf: Vec<u8>,
}

/// Revoked-leaf response bound to a specific authenticated history view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarrierResolvedRevokedLeaves {
    pub history_view_id: [u8; 32],
    pub leaf_indices: Vec<u32>,
}

/// Join enumeration response bound to a specific authenticated history view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarrierResolvedJoins {
    pub history_view_id: [u8; 32],
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
    pub tree: BarrierPublicTree,
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
/// - `proof_mode`: Proof system identifier (e.g., "smallwood")
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
    pub kbroad_generation: u64,
    pub barrier_version: u64,
    pub cover_leaf_index: u64,
    pub kem_tree_hash_after: [u8; 32],
    pub n_max: u64,
    pub max_barrier_update_bytes: u64,
}

fn array32(bytes: &[u8]) -> Result<[u8; 32], Error> {
    bytes
        .try_into()
        .map_err(|_| Error::Parse("invalid 32-byte field".to_string()))
}

fn ensure_profile_version(version: &str) -> Result<(), Error> {
    if version == EXPECTED_PROFILE_VERSION {
        return Ok(());
    }
    Err(Error::Parse(format!(
        "profile_version mismatch: expected {EXPECTED_PROFILE_VERSION}, got {version}"
    )))
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::{
        Router,
        http::{HeaderMap, StatusCode as HttpStatusCode, Uri, header},
        response::{IntoResponse, Response},
        routing::{get, post},
    };
    use cityg_client::demo::demo_bundle_alice;
    use pb::{
        AcceptEpochResponse, BarrierFetchPublicTreeResponse, BarrierResolveJoinsSinceResponse,
        BarrierResolveRevokedLeavesResponse, BootstrapRoomResponse, ConfigureWindowResponse,
        FetchMessagesResponse, GetBundleResponse, GetTelemetryResponse, GetWindowResponse,
        JoinTicketResponse, MembersResponse, MergeTicketResponse, RefreshPivotResponse,
        RotateRoomKbroadResponse, SearchMembersResponse, SeedHeadResponse, SendMessageResponse,
    };
    use prost::Message;
    use std::{error::Error as StdError, net::SocketAddr};
    use tokio::net::TcpListener;

    fn encode_proto<T: Message>(msg: T) -> Vec<u8> {
        msg.encode_to_vec()
    }

    fn merge_ticket_ok_payload() -> MergeTicketResponse {
        MergeTicketResponse {
            we_epoch_id: vec![0x01; 32],
            pivot_parity_cbor: Vec::new(),
            witness_cbor: Vec::new(),
            srx_cbor: Vec::new(),
            proof_mode: "smallwood".to_string(),
            vrf_id: "lb-vrf-v1".to_string(),
            policy_version: "v0".to_string(),
            cat: vec![0x02; 32],
            parent_root: vec![0x03; 32],
            join_delta_root: vec![0x04; 32],
            revoked_since_root: vec![0x00; 32],
            revoked_root: vec![0x00; 32],
            tswe_salt_hash: vec![0x05; 32],
            pox_r_commit: vec![0x06; 32],
            kbroad_public: vec![0x07; 32],
            msphf_crs_id: "rlwe-crs-v1".to_string(),
            msphf_params_id: "rlwe-hps2048509".to_string(),
            fs_policy_version: "7".to_string(),
            fs_epoch_base_ts: 0,
            kbroad_generation: 0,
            barrier_version: 0,
            profile_version: EXPECTED_PROFILE_VERSION.to_string(),
            cover_leaf_index: 0,
            kem_tree_hash_after: vec![0x09; 32],
            n_max: 1024,
            max_barrier_update_bytes: 1_048_576,
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

    async fn mock_post(uri: Uri) -> Response {
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
            "/v1/rooms/expel_member_ticket" => encode_proto(merge_ticket_ok_payload()),
            "/v1/members" => encode_proto(MembersResponse::default()),
            "/v1/members/search" => encode_proto(SearchMembersResponse::default()),
            "/v1/rooms/join_ticket" => encode_proto(JoinTicketResponse {
                profile_version: EXPECTED_PROFILE_VERSION.to_string(),
                current_history_view_id: vec![0xD0; 32],
                ..JoinTicketResponse::default()
            }),
            "/v1/rooms/merge_ticket" => encode_proto(merge_ticket_ok_payload()),
            "/v1/accept_epoch" => encode_proto(AcceptEpochResponse::default()),
            "/v1/barrier/resolve_revoked_leaves" => {
                encode_proto(BarrierResolveRevokedLeavesResponse {
                    leaf_indices: vec![1, 7],
                    history_view_id: vec![0xD1; 32],
                })
            }
            "/v1/barrier/resolve_joins_since" => encode_proto(BarrierResolveJoinsSinceResponse {
                records: vec![pb::BarrierJoinLeafRecord {
                    device_pk: vec![0xAA; 32],
                    leaf_index: 9,
                    ek_leaf: vec![0xBB; 1184],
                }],
                history_view_id: vec![0xD1; 32],
            }),
            "/v1/barrier/fetch_public_tree" => encode_proto(BarrierFetchPublicTreeResponse {
                n_max: 8,
                kem_tree_hash_after: vec![0xCC; 32],
                pk_entries: vec![Vec::new(); 15],
                history_view_id: vec![0xD1; 32],
            }),
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
        assert_eq!(merge.n_max, 1024);
        assert_eq!(merge.max_barrier_update_bytes, 1_048_576);
        let refresh_merge = client.merge_ticket_refresh("room-1", &[0x01; 32]).await?;
        assert_eq!(refresh_merge.we_epoch_id, [0x01; 32]);
        let refresh_with_intent = client
            .merge_ticket_with_intent("room-1", &[0x01; 32], MergeTicketIntent::Refresh)
            .await?;
        assert_eq!(refresh_with_intent.we_epoch_id, [0x01; 32]);

        let revoked = client
            .barrier_resolve_revoked_leaves("room-1", &[0xCC; 32])
            .await?;
        assert_eq!(revoked.history_view_id, [0xD1; 32]);
        assert_eq!(revoked.leaf_indices, vec![1, 7]);
        let joins = client.barrier_resolve_joins_since("room-1", 3).await?;
        assert_eq!(joins.history_view_id, [0xD1; 32]);
        assert_eq!(joins.records.len(), 1);
        assert_eq!(joins.records[0].leaf_index, 9);
        assert_eq!(joins.records[0].ek_leaf.len(), 1184);
        let tree = client
            .barrier_fetch_public_tree("room-1", &[0xCC; 32])
            .await?;
        assert_eq!(tree.history_view_id, [0xD1; 32]);
        assert_eq!(tree.tree.n_max, 8);
        assert_eq!(tree.tree.kem_tree_hash_after, [0xCC; 32]);
        assert_eq!(tree.tree.pk_entries.len(), 15);

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
