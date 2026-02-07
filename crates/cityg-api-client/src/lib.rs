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
//! client.bootstrap_room("room-123", &kbroad_public).await?;
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

use cityg_client::{CityGError as ClientError, ClientEpochBundle, pivot::pivot_parity_from_cbor};
use msphf_orchestrator::PivotParity;
pub use pb::IdentityBinding;
use pb::{
    AcceptEpochRequest, AcceptEpochResponse, BootstrapRoomRequest, BootstrapRoomResponse,
    ConfigureWindowRequest, ConfigureWindowResponse, FetchMessagesRequest, FetchMessagesResponse,
    GetBundleRequest, GetBundleResponse, GetTelemetryRequest, GetTelemetryResponse,
    GetWindowRequest, GetWindowResponse, JoinTicketRequest, JoinTicketResponse, MembersRequest,
    MembersResponse, MergeTicketRequest, MergeTicketResponse, SearchMembersRequest,
    SearchMembersResponse, SendMessageRequest, SendMessageResponse,
};
#[cfg(any(debug_assertions, feature = "debug-api"))]
use pb::{RefreshPivotRequest, RefreshPivotResponse, SeedHeadRequest, SeedHeadResponse};
use prost::Message;
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use std::convert::TryInto;
use std::time::Duration;
use thiserror::Error;
use tracing::warn;

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
        }
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
    /// // Generate a fresh broadcast key (using your preferred crypto library)
    /// let kbroad_public = vec![0u8; 32]; // Replace with actual key generation
    ///
    /// client.bootstrap_room("my-secure-room", &kbroad_public).await?;
    /// println!("Room bootstrapped successfully!");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn bootstrap_room(&self, room_id: &str, kbroad_public: &[u8]) -> Result<(), Error> {
        let request = BootstrapRoomRequest {
            room_id: room_id.to_string(),
            kbroad_public: kbroad_public.to_vec(),
        };
        let _: BootstrapRoomResponse = self.post_proto("/v1/rooms/bootstrap", request).await?;
        Ok(())
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
        self.post_proto("/v1/rooms/join_ticket", request).await
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
        let request = MergeTicketRequest {
            room_id: room_id.to_string(),
            leaf_id: leaf_id.to_vec(),
        };
        let response: MergeTicketResponse =
            self.post_proto("/v1/rooms/merge_ticket", request).await?;

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
    /// let response = client.fetch_messages(epoch_id).await?;
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
    ) -> Result<FetchMessagesResponse, Error> {
        let request = FetchMessagesRequest {
            we_epoch_id: we_epoch_id.to_vec(),
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
        let _: RefreshPivotResponse = self.post_proto("/v1/pivot/refresh", request).await?;
        Ok(())
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
        let mut buf = Vec::with_capacity(request.encoded_len());

        // Handle encoding error gracefully
        if let Err(e) = request.encode(&mut buf) {
            return Err(Error::Parse(format!(
                "failed to encode protobuf request: {}",
                e
            )));
        }

        for attempt in 0..=max_retries {
            let response = self
                .http
                .post(&url)
                .header("Content-Type", "application/x-protobuf")
                .body(buf.clone())
                .send()
                .await;

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
                        tokio::time::sleep(backoff).await;
                    } else {
                        warn!(
                            "network error on final attempt {}/{} for {}: {}",
                            attempt + 1,
                            max_retries + 1,
                            path,
                            e
                        );
                        return Err(Error::Http(e));
                    }
                }
            }
        }

        // This should be unreachable because all error paths return above
        unreachable!("all retry attempts exhausted but no error was captured")
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
}

fn array32(bytes: &[u8]) -> Result<[u8; 32], Error> {
    bytes
        .try_into()
        .map_err(|_| Error::Parse("invalid 32-byte field".to_string()))
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
mod tests {
    use super::*;
    use axum::{
        Router,
        http::{StatusCode as HttpStatusCode, Uri, header},
        response::{IntoResponse, Response},
        routing::{get, post},
    };
    use pb::{
        BootstrapRoomResponse, ConfigureWindowResponse, FetchMessagesResponse, GetBundleResponse,
        GetTelemetryResponse, GetWindowResponse, JoinTicketResponse, MembersResponse,
        MergeTicketResponse, SearchMembersResponse, SendMessageResponse,
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
            fs_policy_version: "fs-policy-v1".to_string(),
            fs_epoch_base_ts: 0,
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
            "/v1/members" => encode_proto(MembersResponse::default()),
            "/v1/members/search" => encode_proto(SearchMembersResponse::default()),
            "/v1/rooms/join_ticket" => encode_proto(JoinTicketResponse::default()),
            "/v1/rooms/merge_ticket" => encode_proto(merge_ticket_ok_payload()),
            "/v1/send_message" => encode_proto(SendMessageResponse::default()),
            "/v1/messages" => encode_proto(FetchMessagesResponse::default()),
            "/v1/bundle" => encode_proto(GetBundleResponse::default()),
            "/v1/config/window" => encode_proto(ConfigureWindowResponse::default()),
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
            .route("/*path", post(mock_post));

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
        match err {
            Error::Parse(msg) => assert!(msg.contains("invalid 32-byte field")),
            other => panic!("expected parse error, got {other:?}"),
        }
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
    fn build_http_error_uses_payload_message_and_code() {
        let err = build_http_error(
            StatusCode::BAD_REQUEST,
            br#"{"message":"invalid input","freeze_code":17,"freeze_reason":"bad_field"}"#.to_vec(),
        );
        match err {
            Error::HttpStatus {
                status,
                message,
                freeze_code,
                freeze_reason,
                failed_index,
            } => {
                assert_eq!(status, StatusCode::BAD_REQUEST);
                assert_eq!(message, "invalid input");
                assert_eq!(freeze_code, Some(17));
                assert_eq!(freeze_reason.as_deref(), Some("bad_field"));
                assert_eq!(failed_index, None);
            }
            other => panic!("expected HttpStatus error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn wrappers_roundtrip_against_mock_server() -> Result<(), Box<dyn StdError>> {
        let (base_url, handle) = start_mock_server().await?;
        let client = CitygApiClient::with_http_client(base_url, Client::new());

        client.health().await?;
        client.bootstrap_room("room-1", &[0xAB; 32]).await?;

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

        let _ = client
            .send_message(&[0x22; 32], b"ciphertext", Some(b"sender"))
            .await?;
        let _ = client.fetch_messages(&[0x22; 32]).await?;
        let _ = client.get_bundle(&[0x22; 32]).await?;
        let _ = client.window().await?;
        let _ = client.telemetry().await?;
        let _ = client.configure_window(Some(8), Some(120_000)).await?;

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
            return Err("expected HttpStatus error".to_string());
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
