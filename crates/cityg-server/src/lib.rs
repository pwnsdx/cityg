//! Server-side validation and state management for City-G.
//!
//! This crate provides high-level server operations for the City-G protocol:
//!
//! - **Epoch validation**: Cryptographic verification without learning secrets
//! - **Multi-head window**: Concurrent branch tracking with TTL-based eviction
//! - **Crash recovery**: Journal-based state persistence with replay
//! - **Membership tracking**: Roster management per parent root
//! - **Pivot caching**: Forward secrecy parity management
//!
//! # Server-Blindness Guarantee
//!
//! The server validates all cryptographic proofs but **never learns**:
//! - `hp` (hash projection key) - encrypted in KBROAD envelope
//! - `Y*` (VRF output) - hidden via zero-knowledge proof
//! - `E_k` (epoch key) - derived client-side only
//!
//! This is cryptographically enforced (not trust-based) via ML-KEM-768 IND-CCA2
//! and zero-knowledge VRF proofs. Verified by `./scripts/verify_no_secrets.sh`.
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use cityg_server::{ServerConfig, CityGServer};
//!
//! // Create server with default configuration
//! let config = ServerConfig::new();
//! let mut server = CityGServer::new(config);
//!
//! // Accept an epoch bundle
//! let bundle_cbor = /* ... received from client ... */;
//! match server.accept_epoch(&bundle_cbor) {
//!     Ok(result) => {
//!         println!("Accepted! Epoch ID: {:?}", result.we_epoch_id);
//!     }
//!     Err(e) => {
//!         eprintln!("Rejected: {:?}", e);
//!     }
//! }
//! ```
//!
//! # Architecture
//!
//! ```text
//! CityGServer
//!   ├── AcceptanceContext (validation state)
//!   ├── ReceiverCache (pivot parity cache)
//!   ├── GroupRoster (membership tracking)
//!   └── ServerJournal (crash recovery)
//! ```
//!
//! # Performance
//!
//! - Epoch validation: <100ms typical
//! - Multi-head window: Up to 16 concurrent branches (configurable)
//! - Journal writes: fsync'd for durability
//!
//! # See Also
//!
//! - [`CityGServer`] - Main server struct
//! - [`ServerConfig`] - Configuration options
//! - [Server README](../README.md) - Complete server guide

#[cfg(test)]
use std::sync::{
    Mutex, MutexGuard, OnceLock,
    atomic::{AtomicIsize, Ordering},
};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ciborium::value::{Integer, Value};
use cityg_client::witness;
use cityg_client::{CityGError, ClientEpochBundle, GroupMembership, MembershipDelta};
use msphf_core::merkle::canonical_set_root;
use msphf_core::params::{RLWE_CRS_ID_DEFAULT, RLWE_PARAMS_ID_MOCK};
use msphf_core::{hash::h_l, serde_utils::to_cbor_vec};
use msphf_orchestrator::mhw::{DEFAULT_H_MAX, DEFAULT_T_WINDOW};
use msphf_orchestrator::process_anchor_or;
use msphf_orchestrator::{
    self, AcceptanceContext, AcceptanceOptions, BootstrapPolicy, DEFAULT_PROOF_MODE,
    DEFAULT_VRF_ID, PivotParity, ReceiverCache, compute_proofs_commit_bytes, hdr,
};
use pqcrypto_dilithium::dilithium5;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use rand::RngExt;
use serde::{Deserialize, Serialize};

/// Re-export commonly used client-side bundle types for convenience.
pub use cityg_client::{AnchorBundle, BindingMaterial};

const DEFAULT_CAT: [u8; 32] = [0x21; 32];
const KBROAD_ROTATION_REQUIRED_ERR: &str = "kbroad rotation required";
const KBROAD_KEY_UNCHANGED_ERR: &str = "kbroad key unchanged";
const KBROAD_HISTORY_EXISTS_ERR: &str = "group already has roster history";

/// Configuration for [`CityGServer`] initialization.
///
/// Controls server behavior including concurrency limits, state persistence,
/// and cryptographic validation policies.
///
/// # Examples
///
/// ```rust,ignore
/// use cityg_server::ServerConfig;
/// use std::time::Duration;
/// use std::path::PathBuf;
///
/// // Default configuration
/// let config = ServerConfig::new();
///
/// // Custom configuration
/// let config = ServerConfig {
///     h_max: Some(32),  // Allow 32 concurrent heads
///     window_ttl: Some(Duration::from_secs(60)),  // 1 minute TTL
///     state_path: Some(PathBuf::from("/var/lib/cityg/journal.cbor")),
///     acceptance_options: None,  // Use defaults
/// };
/// ```
#[derive(Clone)]
pub struct ServerConfig {
    /// Maximum concurrent heads in multi-head window (default: 16)
    pub h_max: Option<usize>,
    /// Window time-to-live for head eviction (default: 120 seconds)
    pub window_ttl: Option<Duration>,
    /// Cryptographic acceptance policy (default: permissive)
    pub acceptance_options: Option<AcceptanceOptions>,
    /// Journal file path for crash recovery (default: None, in-memory only)
    pub state_path: Option<PathBuf>,
    /// Optional local history authority extension.
    pub history_authority: Option<HistoryAuthorityConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryAuthorityConfig {
    pub mode: HistoryAuthorityMode,
    pub require_full_verification_receipt: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryAuthorityMode {
    Disabled,
    Local,
    Global,
}

pub const LOCAL_HISTORY_AUTHORITY_EXTENSION_ID: &str = "local-history-authority-v1";
pub const GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID: &str = "global-history-authority-v1";
const LOCAL_HISTORY_ATTESTATION_FINALITY_KIND: &str = "local-append-only";
const GLOBAL_HISTORY_ATTESTATION_FINALITY_KIND: &str = "global-append-only";

impl HistoryAuthorityMode {
    fn extension_id(self) -> &'static str {
        match self {
            Self::Disabled => "",
            Self::Local => LOCAL_HISTORY_AUTHORITY_EXTENSION_ID,
            Self::Global => GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID,
        }
    }

    fn finality_kind(self) -> &'static str {
        match self {
            Self::Disabled | Self::Local => LOCAL_HISTORY_ATTESTATION_FINALITY_KIND,
            Self::Global => GLOBAL_HISTORY_ATTESTATION_FINALITY_KIND,
        }
    }

    fn persisted_tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Local => "local",
            Self::Global => "global",
        }
    }

    fn requires_full_verification_receipt(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    fn requires_full_verification_witness(self) -> bool {
        matches!(self, Self::Global)
    }

    fn from_persisted_tag(tag: &str) -> Result<Self, CityGError> {
        match tag {
            "" | "local" => Ok(Self::Local),
            "global" => Ok(Self::Global),
            "disabled" => Ok(Self::Disabled),
            _ => Err(CityGError::InvalidInput("invalid history authority mode")),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerConfig {
    pub fn new() -> Self {
        Self {
            h_max: None,
            window_ttl: None,
            acceptance_options: None,
            state_path: None,
            history_authority: None,
        }
    }

    pub fn enable_local_history_authority(&mut self) {
        self.history_authority = Some(HistoryAuthorityConfig {
            mode: HistoryAuthorityMode::Local,
            require_full_verification_receipt: HistoryAuthorityMode::Local
                .requires_full_verification_receipt(),
        });
    }

    pub fn enable_global_history_authority(&mut self) {
        self.history_authority = Some(HistoryAuthorityConfig {
            mode: HistoryAuthorityMode::Global,
            require_full_verification_receipt: HistoryAuthorityMode::Global
                .requires_full_verification_receipt(),
        });
    }
}

/// High-level City-G server for epoch validation and state management.
///
/// `CityGServer` orchestrates the complete server-side validation pipeline:
/// - Cryptographic proof verification (CAPSS, VRF, witnesses)
/// - Multi-head window management with TTL-based eviction
/// - Membership roster tracking per parent root
/// - Forward secrecy pivot parity caching
/// - Crash recovery via append-only journal
///
/// # Thread Safety
///
/// This struct is **not** thread-safe. Wrap in `Arc<Mutex<CityGServer>>` for
/// concurrent access from multiple HTTP handlers.
///
/// # Server-Blindness
///
/// All validation operations preserve cryptographic blindness:
/// - Server never decrypts KBROAD envelopes
/// - Server never learns VRF outputs (Y*)
/// - Server never derives epoch keys (E_k)
///
/// Verified by: `./scripts/verify_no_secrets.sh`
///
/// # Examples
/// ```no_run
/// let mut server = cityg_server::demo::demo_server();
/// let bundle = cityg_client::demo::demo_bundle("test").unwrap();
/// let outcome = server.accept_epoch(&bundle).unwrap();
/// let (epoch_key, eid) = bundle.derive_epoch_secrets().unwrap();
/// assert_eq!(bundle.we_epoch_id, outcome.we_epoch_id);
/// assert_eq!(epoch_key, bundle.epoch_key);
/// assert_eq!(eid, bundle.eid);
/// ```
///
/// # Performance
///
/// - Validation latency: <100ms typical
/// - Window capacity: Up to `h_max` concurrent branches
/// - Journal writes: fsync'd for durability (~1-5ms)
///
/// # See Also
///
/// - [`accept_epoch`](Self::accept_epoch) - Main validation method
/// - [`ServerConfig`] - Configuration options
/// - [Server README](../README.md) - Deployment guide
pub struct CityGServer {
    ctx: AcceptanceContext,
    receiver: ReceiverCache,
    roster: GroupRoster,
    h_max: usize,
    window_ttl: Duration,
    acceptance_options: AcceptanceOptions,
    journal: Option<ServerJournal>,
    kbroad_state_path: Option<PathBuf>,
    history_authority: Option<HistoryAuthorityState>,
    replaying: bool,
}

/// Join ticket bundle provided to new members joining a group.
///
/// Contains all cryptographic material needed for a client to generate
/// their first epoch bundle without server interaction.
///
/// # Contents
///
/// - **Identity**: gid, cat, leaf_id (derived from device public key)
/// - **Merkle state**: parent_root, join_delta_root, witness data
/// - **Revocation**: revoked_root, revoked_since_root
/// - **KBROAD**: Public key for group key broadcasting
/// - **Witnesses**: CBOR-encoded witness and SRX data
///
/// # Security
///
/// The join ticket contains public information only. No secrets are transmitted.
/// The client uses this ticket to generate proofs that the server validates
/// without learning the client's secrets.
#[derive(Debug)]
pub struct JoinTicketBundle {
    /// Group identifier (32 bytes)
    pub gid: [u8; 32],
    /// Category identifier (32 bytes)
    pub cat: [u8; 32],
    /// Current parent Merkle root
    pub parent_root: [u8; 32],
    /// Accumulated revocation root
    pub revoked_root: [u8; 32],
    /// Revocations since previous root
    pub revoked_since_root: [u8; 32],
    /// TSWE salt hash for determinism
    pub tswe_salt_hash: [u8; 32],
    /// Merkle root after adding this leaf
    pub join_delta_root: [u8; 32],
    /// New member's leaf ID (H(device_pk))
    pub leaf_id: [u8; 32],
    /// Proof-of-X commitment (if applicable)
    pub pox_r_commit: [u8; 32],
    /// CBOR-encoded Merkle witness
    pub witness_cbor: Vec<u8>,
    /// CBOR-encoded SRX witness
    pub srx_cbor: Vec<u8>,
    /// KBROAD public key for encryption
    pub kbroad_public: Vec<u8>,
    /// Monotonic KBROAD generation for this group.
    pub kbroad_generation: u64,
    /// Current barrier version for this group.
    pub barrier_version: u64,
    /// Cover leaf index allocated to the joining device.
    pub cover_leaf_index: u64,
    /// Current committed barrier tree hash.
    pub kem_tree_hash_after: [u8; 32],
    /// Current authenticated history view for barrier membership and checkpoints.
    pub current_history_view_id: [u8; 32],
    /// Current authenticated local append-only history commitment.
    pub current_history_commitment: HistoryCommitment,
    /// Authenticated accepted current barrier_update bytes for bootstrap verification.
    pub current_barrier_update: Vec<u8>,
    /// Committed predecessor tree hash used as snapshot_base for the accepted current update.
    pub current_predecessor_kem_tree_hash_after: [u8; 32],
    /// Authenticated JoinSet for the provisioned current committed state.
    pub current_join_records: Vec<BarrierJoinLeafRecord>,
    /// Authenticated RevokedLeafSet for the provisioned current committed state.
    pub current_revoked_leaf_indices: Vec<u32>,
    /// Opaque server-issued capability required for reason-2 join_finalize.
    pub join_finalize_auth_token: [u8; 32],
    /// Unique nonce for this join provisioning artifact.
    pub provisioning_nonce: [u8; 32],
    /// Server issuance time for this join provisioning artifact.
    pub provisioning_issued_at_ms: u64,
    /// Expiry time for this join provisioning artifact.
    pub provisioning_expires_at_ms: u64,
    /// Forward-Leap Guard policy window parameters for client-visible replay checks.
    pub fs_forward_leap_policy: FsForwardLeapPolicy,
    /// Current group-level last accepted forward-secrecy epoch counter.
    pub last_accepted_ec: u64,
    /// Fixed barrier tree capacity.
    pub n_max: u64,
    /// Deployment-wide barrier update size limit.
    pub max_barrier_update_bytes: u64,
}

pub struct JoinProvisioningAuthorityArtifacts<'a> {
    pub history_authority_extension: &'a str,
    pub history_authority_descriptor: &'a [u8],
    pub current_global_history_attestation: &'a [u8],
    pub current_join_records_completeness_attestation: &'a [u8],
    pub current_revoked_leaf_indices_completeness_attestation: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsForwardLeapPolicy {
    pub h: u64,
    pub checkpoint_interval: u64,
    pub slack_anchor: u64,
    pub slack_first_device: u64,
    pub slack_device: u64,
}

/// Server-local append-only authenticated history commitment.
///
/// This strengthens `history_view_id` with an explicit monotonic local chain for
/// A/B/C/D barrier history responses. It does not claim global cross-server
/// canonicality by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HistoryCommitment {
    /// Exact committed membership/checkpoint/barrier view identifier.
    pub history_view_id: [u8; 32],
    /// Identifier for this local append-only commitment step.
    pub history_commitment_id: [u8; 32],
    /// Previous local append-only commitment step, or zero for the first step.
    pub prev_history_commitment_id: [u8; 32],
    /// Monotonic local append-only sequence number for this gid.
    pub history_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryAuthorityDescriptor {
    pub scope_id: [u8; 32],
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HistoryAuthorityState {
    mode: HistoryAuthorityMode,
    descriptor: HistoryAuthorityDescriptor,
    secret_key: Vec<u8>,
    require_full_verification_receipt: bool,
}

/// Revoked leaf enumeration bound to one authenticated history commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRevokedLeaves {
    pub history_view_id: [u8; 32],
    pub history_commitment: HistoryCommitment,
    pub leaf_indices: Vec<u32>,
}

/// Join enumeration bound to one authenticated history commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedJoins {
    pub history_view_id: [u8; 32],
    pub history_commitment: HistoryCommitment,
    pub records: Vec<BarrierJoinLeafRecord>,
}

/// Merge ticket bundle provided to existing members during leave/rekey flow.
///
/// Similar to [`JoinTicketBundle`] but for members who already have a leaf_id
/// in the roster. The current merge flow encodes requester self-revocation in
/// SRX `since_leaf_ids`, and carries fresh pivot parities for forward secrecy.
///
/// # Use Case
///
/// A member proves continuity against the current pivot and publishes a
/// revocation delta rooted at their own leaf during controlled leave/rekey.
///
/// # Security
///
/// Contains public state and fresh pivot parities. No client secrets exposed.
pub struct MergeTicketBundle {
    /// Group identifier (32 bytes)
    pub gid: [u8; 32],
    /// Category identifier (32 bytes)
    pub cat: [u8; 32],
    pub parent_root: [u8; 32],
    pub leaf_id: [u8; 32],
    pub pivot_we_epoch_id: [u8; 32],
    pub parities: Vec<PivotParity>,
    pub witness_cbor: Vec<u8>,
    pub srx_cbor: Vec<u8>,
    pub join_delta_root: [u8; 32],
    pub revoked_since_root: [u8; 32],
    pub revoked_root: [u8; 32],
    pub tswe_salt_hash: [u8; 32],
    pub pox_r_commit: [u8; 32],
    pub proof_mode: String,
    pub vrf_id: String,
    pub policy_version: String,
    pub msphf_crs_id: String,
    pub msphf_params_id: String,
    pub fs_policy_version: String,
    pub fs_epoch_base_ts: u64,
    pub kbroad_public: Vec<u8>,
    pub kbroad_generation: u64,
    pub barrier_version: u64,
    pub cover_leaf_index: u64,
    pub kem_tree_hash_after: [u8; 32],
    pub current_history_view_id: [u8; 32],
    pub current_history_commitment: HistoryCommitment,
    pub fs_forward_leap_policy: FsForwardLeapPolicy,
    pub last_accepted_ec: u64,
    pub n_max: u64,
    pub max_barrier_update_bytes: u64,
}

/// Intent used when preparing a merge ticket for an existing member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeTicketIntent {
    /// Merge ticket drives a controlled self-revocation (leave).
    Leave,
    /// Merge ticket drives a non-leaving proactive PCS refresh.
    Refresh,
}

/// Join-leaf record returned by barrier membership enumeration APIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BarrierJoinLeafRecord {
    /// Device public key associated with the join leaf.
    pub device_pk: Vec<u8>,
    /// Cover leaf index (0-based) for the member.
    pub leaf_index: u32,
    /// Barrier leaf ML-KEM public key (ek, 1184 bytes when provisioned).
    pub ek_leaf: Vec<u8>,
}

/// Public-tree snapshot returned by barrier tree APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarrierPublicTreeSnapshot {
    /// Fixed tree size for the group (power-of-two leaf capacity).
    pub n_max: u64,
    /// Requested tree commitment after barrier activation.
    pub kem_tree_hash_after: [u8; 32],
    /// Barrier version under which this snapshot was committed.
    pub barrier_version: u64,
    /// Authenticated history view under which this snapshot was committed.
    pub history_view_id: [u8; 32],
    /// Server-local append-only history commitment recorded for that snapshot.
    pub history_commitment: HistoryCommitment,
    /// Heap-indexed public key entries (`2*n_max-1` length).
    pub pk_entries: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeAcceptanceStatus {
    Pending,
    Accepted,
    Superseded,
    FinalRejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeAcceptanceRecord {
    pub status: MergeAcceptanceStatus,
    pub history_view_id: [u8; 32],
    pub history_commitment: HistoryCommitment,
    pub accepted_barrier_version: Option<u64>,
    pub accepted_fs_ec: Option<u64>,
    pub accepted_reason: Option<u64>,
    pub accepted_digest: Option<[u8; 32]>,
}

const DUPLICATE_ACTIVE_COVER_LEAF_ALLOCATION_ERR: &str = "duplicate active cover leaf allocation";
const COVER_LEAF_INDEX_ALREADY_ALLOCATED_ERR: &str = "cover leaf index already allocated";
const GENESIS_PROVISIONING_ARTIFACT_MISSING_ERR: &str = "genesis provisioning artifact missing";
const HISTORICAL_BARRIER_PUBLIC_TREE_SNAPSHOT_UNAVAILABLE_ERR: &str =
    "historical barrier public tree snapshot unavailable";
const UNRESOLVED_JOIN_HISTORY_EXHAUSTED_ERR: &str = "unresolved join history exceeds n_max";
const JOIN_PROVISIONING_TTL_MS: u64 = 5 * 60 * 1000;
const ROOM_ADMIN_PROOF_REPLAYED_ERR: &str = "room admin proof replayed";

fn genesis_provisioning_artifact_missing_error() -> CityGError {
    CityGError::InvalidInput(GENESIS_PROVISIONING_ARTIFACT_MISSING_ERR)
}

fn barrier_genesis_required_freeze_error() -> CityGError {
    CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(
        msphf_orchestrator::FREEZE_BARRIER_GENESIS_REQUIRED,
    ))
}

fn require_genesis_provisioning_snapshot(
    state: &GroupState,
    missing_err: impl FnOnce() -> CityGError,
) -> Result<&GroupMembership, CityGError> {
    state.latest_snapshot().ok_or_else(missing_err)
}

fn ensure_unused_room_admin_proof_replay_key(
    state: &GroupState,
    replay_key: &[u8; 32],
) -> Result<(), CityGError> {
    if state.room_admin_proof_replay_keys.contains(replay_key) {
        return Err(CityGError::InvalidInput(ROOM_ADMIN_PROOF_REPLAYED_ERR));
    }
    Ok(())
}

impl CityGServer {
    fn initialize_group_barrier_bootstrap_state(
        &mut self,
        gid: &[u8; 32],
    ) -> Result<(), CityGError> {
        let has_history = self.roster.has_history(gid);
        let (
            barrier_initialized,
            barrier_version,
            barrier_roots_hash,
            kem_tree_hash_after,
            n_max,
            last_checkpoint_ec,
            last_accepted_ec,
            last_pcs_refresh_ec,
            pcs_refresh_min_delta_device_ec,
            pcs_refresh_min_delta_group_ec,
            pcs_refresh_slot_width_ec,
            max_barrier_update_bytes,
        ) = {
            let state = self.roster.groups.entry(gid.to_vec()).or_default();
            state.max_barrier_update_bytes = state.max_barrier_update_bytes.max(1);
            if !state.barrier_initialized && !has_history {
                let zero = [0u8; 32];
                let revocation_roots_hash = compute_revocation_roots_hash(&zero, &zero)?;
                let n_max = state.n_max.max(1);
                let blank_entries = build_all_blank_pk_entries(n_max)?;
                let kem_tree_hash_after = compute_barrier_tree_hash(n_max, &blank_entries)?;
                state.barrier_initialized = true;
                state.barrier_version = 0;
                state.barrier_roots_hash = revocation_roots_hash;
                state.kem_tree_hash_after = kem_tree_hash_after;
                state.current_accepted_barrier_update.clear();
                state.current_accepted_barrier_predecessor_hash = [0u8; 32];
                state.pending_join_finalize_auth.clear();
                state.n_max = n_max;
                state.barrier_pk_entries = blank_entries;
                record_barrier_public_tree_snapshot(gid.as_slice(), state)?;
            }
            (
                state.barrier_initialized,
                state.barrier_version,
                state.barrier_roots_hash,
                state.kem_tree_hash_after,
                state.n_max.max(1),
                state.last_checkpoint_ec,
                state.last_accepted_ec,
                state.last_pcs_refresh_ec,
                state.pcs_refresh_min_delta_device_ec.max(1),
                state.pcs_refresh_min_delta_group_ec.max(1),
                state.pcs_refresh_slot_width_ec.max(1),
                state.max_barrier_update_bytes.max(1),
            )
        };

        let mut ctx_state = self
            .ctx
            .barrier_group_state(gid)
            .cloned()
            .unwrap_or_default();
        ctx_state.barrier_initialized = barrier_initialized;
        ctx_state.barrier_version = barrier_version;
        ctx_state.barrier_roots_hash = barrier_roots_hash;
        ctx_state.kem_tree_hash_after = kem_tree_hash_after;
        ctx_state.srx_root_sw = self
            .roster
            .groups
            .get(gid.as_slice())
            .and_then(|state| state.srx_root_sw);
        ctx_state.n_max = n_max;
        ctx_state.last_checkpoint_ec = last_checkpoint_ec;
        ctx_state.last_accepted_ec = last_accepted_ec;
        ctx_state.last_pcs_refresh_ec = last_pcs_refresh_ec;
        ctx_state.pcs_refresh_min_delta_device_ec = pcs_refresh_min_delta_device_ec;
        ctx_state.pcs_refresh_min_delta_group_ec = pcs_refresh_min_delta_group_ec;
        ctx_state.pcs_refresh_slot_width_ec = pcs_refresh_slot_width_ec;
        ctx_state.max_barrier_update_bytes = max_barrier_update_bytes.max(1);
        self.ctx
            .insert_barrier_group_state(gid.as_slice(), ctx_state);
        Ok(())
    }

    fn initialize_registered_groups_barrier_state(&mut self) -> Result<(), CityGError> {
        let gids: Vec<[u8; 32]> = self
            .ctx
            .kbroad_registry()
            .map(|registry| {
                registry
                    .keys()
                    .filter_map(|gid| gid.as_slice().try_into().ok())
                    .collect()
            })
            .unwrap_or_default();
        for gid in gids {
            self.initialize_group_barrier_bootstrap_state(&gid)?;
        }
        Ok(())
    }

    fn reset_empty_room_membership_state(&mut self, gid: &[u8; 32]) -> Result<(), CityGError> {
        let Some(state) = self.roster.groups.get_mut(gid.as_slice()) else {
            return Ok(());
        };

        let zero = [0u8; 32];
        let n_max = state.n_max.max(1);
        let blank_entries = build_all_blank_pk_entries(n_max)?;
        let blank_tree_hash = compute_barrier_tree_hash(n_max, blank_entries.as_slice())?;

        state.revoked.clear();
        state.leaf_device_pk.clear();
        state.leaf_barrier_public.clear();
        state.barrier_initialized = true;
        state.barrier_version = 0;
        state.barrier_roots_hash = compute_revocation_roots_hash(&zero, &zero)?;
        state.kem_tree_hash_after = blank_tree_hash;
        state.current_accepted_barrier_update.clear();
        state.current_accepted_barrier_predecessor_hash = [0u8; 32];
        state.pending_join_finalize_auth.clear();
        state.last_checkpoint_ec = 0;
        state.last_accepted_ec = 0;
        state.srx_root_sw = None;
        state.last_pcs_refresh_ec = None;
        state.join_history.clear();
        state.barrier_pk_entries = blank_entries;
        state.barrier_hash_cache = None;
        record_barrier_public_tree_snapshot(gid.as_slice(), state)?;

        let ctx_state = self.ctx.barrier_group_state_entry_mut(gid.as_slice());
        ctx_state.barrier_initialized = state.barrier_initialized;
        ctx_state.barrier_version = state.barrier_version;
        ctx_state.barrier_roots_hash = state.barrier_roots_hash;
        ctx_state.kem_tree_hash_after = state.kem_tree_hash_after;
        ctx_state.last_checkpoint_ec = state.last_checkpoint_ec;
        ctx_state.last_accepted_ec = state.last_accepted_ec;
        ctx_state.srx_root_sw = state.srx_root_sw;
        ctx_state.n_max = state.n_max.max(1);
        ctx_state.last_pcs_refresh_ec = state.last_pcs_refresh_ec;
        self.ctx.clear_device_chains_for_gid(gid.as_slice());
        self.ctx.clear_pivot_parities_for_gid(gid.as_slice());

        Ok(())
    }

    pub fn register_group(
        &mut self,
        gid: &[u8; 32],
        kbroad_public: Vec<u8>,
    ) -> Result<(), CityGError> {
        if self.roster.has_history(gid) {
            return Err(CityGError::InvalidInput(KBROAD_HISTORY_EXISTS_ERR));
        }
        let mut registry = self.ctx.kbroad_registry().cloned().unwrap_or_default();
        if registry.contains_key(gid.as_ref()) {
            return Err(CityGError::InvalidInput("kbroad key already registered"));
        }
        registry.insert(gid.to_vec(), kbroad_public);
        self.ctx.set_kbroad_registry(Some(registry));
        {
            let state = self.roster.groups.entry(gid.to_vec()).or_default();
            state.rotation_required = false;
            state.kbroad_generation = 0;
        }
        self.initialize_group_barrier_bootstrap_state(gid)?;
        self.persist_kbroad_state()?;
        Ok(())
    }

    pub fn register_group_with_admin(
        &mut self,
        gid: &[u8; 32],
        kbroad_public: Vec<u8>,
        initial_room_admin_pop_key: Vec<u8>,
    ) -> Result<(), CityGError> {
        self.register_group(gid, kbroad_public)?;
        self.roster
            .groups
            .entry(gid.to_vec())
            .or_default()
            .room_admin_pop_keys
            .insert(initial_room_admin_pop_key);
        self.persist_kbroad_state()?;
        Ok(())
    }

    pub fn attach_initial_room_admin(
        &mut self,
        gid: &[u8; 32],
        initial_room_admin_pop_key: Vec<u8>,
    ) -> Result<(), CityGError> {
        if self
            .ctx
            .kbroad_registry()
            .and_then(|registry| registry.get(gid.as_ref()))
            .is_none()
        {
            return Err(CityGError::InvalidInput("kbroad key missing"));
        }
        let state = self
            .roster
            .groups
            .get_mut(gid.as_slice())
            .ok_or(CityGError::InvalidInput("roster group missing"))?;
        if !state.room_admin_pop_keys.is_empty() {
            return Err(CityGError::InvalidInput("room admins already configured"));
        }
        state.room_admin_pop_keys.insert(initial_room_admin_pop_key);
        self.persist_kbroad_state()?;
        Ok(())
    }

    fn rotate_group_kbroad_in_place(
        &mut self,
        gid: &[u8; 32],
        kbroad_public: Vec<u8>,
    ) -> Result<u64, CityGError> {
        let mut registry = self.ctx.kbroad_registry().cloned().unwrap_or_default();
        let existing = registry
            .get(gid.as_ref())
            .ok_or(CityGError::InvalidInput("kbroad key missing"))?;
        if existing == &kbroad_public {
            return Err(CityGError::InvalidInput(KBROAD_KEY_UNCHANGED_ERR));
        }
        registry.insert(gid.to_vec(), kbroad_public);
        self.ctx.set_kbroad_registry(Some(registry));
        let generation = self.roster.increment_kbroad_generation(gid);
        self.roster.clear_kbroad_rotation_required(gid);
        Ok(generation)
    }

    pub fn rotate_group_kbroad(
        &mut self,
        gid: &[u8; 32],
        kbroad_public: Vec<u8>,
    ) -> Result<u64, CityGError> {
        let generation = self.rotate_group_kbroad_in_place(gid, kbroad_public)?;
        self.persist_kbroad_state()?;
        Ok(generation)
    }

    pub fn rotate_group_kbroad_with_actor(
        &mut self,
        gid: &[u8; 32],
        kbroad_public: Vec<u8>,
        actor_pop_public_key: &[u8],
        replay_key: [u8; 32],
    ) -> Result<u64, CityGError> {
        if self
            .ctx
            .kbroad_registry()
            .and_then(|registry| registry.get(gid.as_ref()))
            .is_none()
        {
            return Err(CityGError::InvalidInput("kbroad key missing"));
        }
        if !self.roster.has_explicit_room_admins(gid)
            || !self.roster.is_room_admin(gid, actor_pop_public_key)
        {
            return Err(CityGError::InvalidInput(
                "room admin proof is not authorized",
            ));
        }
        {
            let state = self
                .roster
                .groups
                .get(gid.as_slice())
                .ok_or(CityGError::InvalidInput("roster group missing"))?;
            ensure_unused_room_admin_proof_replay_key(state, &replay_key)?;
        }
        let generation = self.rotate_group_kbroad_in_place(gid, kbroad_public)?;
        self.roster
            .groups
            .get_mut(gid.as_slice())
            .ok_or(CityGError::InvalidInput("roster group missing"))?
            .room_admin_proof_replay_keys
            .insert(replay_key);
        self.persist_kbroad_state()?;
        Ok(generation)
    }

    pub fn grant_room_admin(
        &mut self,
        gid: &[u8; 32],
        actor_pop_public_key: &[u8],
        target_pop_public_key: Vec<u8>,
        replay_key: [u8; 32],
    ) -> Result<(bool, u64), CityGError> {
        if !self.roster.has_explicit_room_admins(gid) {
            return Err(CityGError::InvalidInput(
                "room admin proof is not authorized",
            ));
        }
        if !self.roster.is_room_admin(gid, actor_pop_public_key) {
            return Err(CityGError::InvalidInput(
                "room admin proof is not authorized",
            ));
        }
        if self
            .ctx
            .kbroad_registry()
            .and_then(|registry| registry.get(gid.as_ref()))
            .is_none()
        {
            return Err(CityGError::InvalidInput("kbroad key missing"));
        }

        let state = self
            .roster
            .groups
            .get_mut(gid.as_slice())
            .ok_or(CityGError::InvalidInput("roster group missing"))?;
        ensure_unused_room_admin_proof_replay_key(state, &replay_key)?;
        let granted = state.room_admin_pop_keys.insert(target_pop_public_key);
        state.room_admin_proof_replay_keys.insert(replay_key);
        let admin_count = u64::try_from(state.room_admin_pop_keys.len()).unwrap_or(u64::MAX);
        self.persist_kbroad_state()?;
        Ok((granted, admin_count))
    }

    pub fn revoke_room_admin(
        &mut self,
        gid: &[u8; 32],
        actor_pop_public_key: &[u8],
        target_pop_public_key: &[u8],
        replay_key: [u8; 32],
    ) -> Result<(bool, u64), CityGError> {
        if !self.roster.has_explicit_room_admins(gid) {
            return Err(CityGError::InvalidInput(
                "room admin proof is not authorized",
            ));
        }
        if !self.roster.is_room_admin(gid, actor_pop_public_key) {
            return Err(CityGError::InvalidInput(
                "room admin proof is not authorized",
            ));
        }
        if self
            .ctx
            .kbroad_registry()
            .and_then(|registry| registry.get(gid.as_ref()))
            .is_none()
        {
            return Err(CityGError::InvalidInput("kbroad key missing"));
        }

        let state = self
            .roster
            .groups
            .get_mut(gid.as_slice())
            .ok_or(CityGError::InvalidInput("roster group missing"))?;
        ensure_unused_room_admin_proof_replay_key(state, &replay_key)?;
        if !state.room_admin_pop_keys.contains(target_pop_public_key) {
            state.room_admin_proof_replay_keys.insert(replay_key);
            let admin_count = u64::try_from(state.room_admin_pop_keys.len()).unwrap_or(u64::MAX);
            self.persist_kbroad_state()?;
            return Ok((false, admin_count));
        }
        if state.room_admin_pop_keys.len() == 1 {
            return Err(CityGError::InvalidInput(
                "cannot revoke the last room admin",
            ));
        }
        let revoked = state.room_admin_pop_keys.remove(target_pop_public_key);
        state.room_admin_proof_replay_keys.insert(replay_key);
        let admin_count = u64::try_from(state.room_admin_pop_keys.len()).unwrap_or(u64::MAX);
        self.persist_kbroad_state()?;
        Ok((revoked, admin_count))
    }

    pub fn list_room_admins(
        &self,
        gid: &[u8; 32],
        actor_pop_public_key: &[u8],
    ) -> Result<Vec<Vec<u8>>, CityGError> {
        if !self.roster.has_explicit_room_admins(gid) {
            return Err(CityGError::InvalidInput(
                "room admin proof is not authorized",
            ));
        }
        if !self.roster.is_room_admin(gid, actor_pop_public_key) {
            return Err(CityGError::InvalidInput(
                "room admin proof is not authorized",
            ));
        }
        if self
            .ctx
            .kbroad_registry()
            .and_then(|registry| registry.get(gid.as_ref()))
            .is_none()
        {
            return Err(CityGError::InvalidInput("kbroad key missing"));
        }

        let admins = self
            .roster
            .groups
            .get(gid.as_slice())
            .ok_or(CityGError::InvalidInput("roster group missing"))?
            .room_admin_pop_keys
            .iter()
            .cloned()
            .collect();
        Ok(admins)
    }

    pub fn kbroad_generation(&self, gid: &[u8; 32]) -> u64 {
        self.roster.kbroad_generation(gid)
    }

    pub fn kbroad_rotation_required(&self, gid: &[u8; 32]) -> bool {
        self.roster.kbroad_rotation_required(gid)
    }

    pub fn room_uses_explicit_admins(&self, gid: &[u8; 32]) -> bool {
        self.roster.has_explicit_room_admins(gid)
    }

    pub fn new(config: ServerConfig) -> Self {
        let h_max = config.h_max.unwrap_or(DEFAULT_H_MAX);
        let ttl = config.window_ttl.unwrap_or(DEFAULT_T_WINDOW);
        let kbroad_state_path = config
            .state_path
            .as_ref()
            .map(|path| kbroad_state_path_for_journal(path.as_path()));
        let history_authority_path = config
            .state_path
            .as_ref()
            .map(|path| history_authority_path_for_journal(path.as_path()));
        let persisted_kbroad_state = kbroad_state_path
            .as_ref()
            .and_then(|path| match load_kbroad_state(path) {
                Ok(state) => Some(state),
                Err(err) => {
                    eprintln!("cityg-server: kbroad state recovery failed: {err:?}");
                    None
                }
            })
            .filter(|state| !state.is_empty());
        let history_authority = match config.history_authority.as_ref() {
            Some(authority)
                if matches!(
                    authority.mode,
                    HistoryAuthorityMode::Local | HistoryAuthorityMode::Global
                ) =>
            {
                match load_or_generate_history_authority_state(
                    history_authority_path.as_deref(),
                    authority.mode,
                    authority.require_full_verification_receipt,
                ) {
                    Ok(state) => Some(state),
                    Err(err) => {
                        eprintln!("cityg-server: history authority init failed: {err:?}");
                        None
                    }
                }
            }
            _ => None,
        };
        let options = config.acceptance_options.unwrap_or_default();
        let journal = config
            .state_path
            .as_ref()
            .and_then(|path| ServerJournal::open(path).ok());
        let mut server = Self {
            ctx: AcceptanceContext::with_options(h_max, ttl, options.clone()),
            receiver: ReceiverCache::new(ttl),
            roster: GroupRoster::default(),
            h_max,
            window_ttl: ttl,
            acceptance_options: options,
            journal,
            kbroad_state_path,
            history_authority,
            replaying: false,
        };
        #[allow(clippy::collapsible_if)]
        let journal_has_entries = config
            .state_path
            .as_ref()
            .and_then(|path| ServerJournal::load_entries(path).ok())
            .map(|entries| !entries.is_empty())
            .unwrap_or(false);
        if let Some(path) = config.state_path
            && let Err(err) = server.recover_from_state(&path, persisted_kbroad_state.as_ref())
        {
            eprintln!("cityg-server: state recovery failed: {err:?}");
        }
        if let Some(state) = persisted_kbroad_state
            && let Err(err) = if journal_has_entries {
                server.overlay_persisted_runtime_metadata_after_replay(&state)
            } else {
                server.apply_persisted_kbroad_state(&state)
            }
        {
            eprintln!("cityg-server: kbroad state apply failed: {err:?}");
        }
        if let Err(err) = server.initialize_registered_groups_barrier_state() {
            eprintln!("cityg-server: barrier bootstrap initialization failed: {err:?}");
        }
        server
    }

    pub fn build_join_ticket(&mut self, gid: &[u8; 32]) -> Result<JoinTicketBundle, CityGError> {
        self.build_join_ticket_with_leaf(gid, None)
    }

    pub fn build_join_ticket_with_leaf(
        &mut self,
        gid: &[u8; 32],
        leaf_id_override: Option<[u8; 32]>,
    ) -> Result<JoinTicketBundle, CityGError> {
        self.ensure_kbroad_ready(gid)?;
        let pox_r_commit = witness::demo_pox_commit();

        let (parent_root, leaf_id, parent_leaves) = {
            let state = self.roster.groups.entry(gid.to_vec()).or_default();
            let mut parent_leaves: Vec<[u8; 32]> = state
                .latest_snapshot()
                .map(|set| set.members().copied().collect())
                .unwrap_or_default();
            parent_leaves.sort();
            parent_leaves.dedup();

            let leaf_id = if let Some(explicit_leaf_id) = leaf_id_override {
                if parent_leaves.contains(&explicit_leaf_id) {
                    return Err(CityGError::InvalidInput("leaf already present in roster"));
                }
                explicit_leaf_id
            } else {
                state.sync_next_index();
                let index = state.allocate_leaf();
                witness::sequential_leaf(index)
            };
            ensure_join_cover_leaf_indices_available(state, std::slice::from_ref(&leaf_id))?;

            let parent_root = if parent_leaves.is_empty() {
                [0u8; 32]
            } else {
                canonical_set_root(&parent_leaves)?
            };
            (parent_root, leaf_id, parent_leaves)
        };
        let mut revoked_all = self.roster.revoked(gid);
        revoked_all.sort();
        revoked_all.dedup();
        if parent_leaves.is_empty() {
            // Once a room has no live members, the next join should behave like a
            // fresh admission for membership purposes even if the roster still
            // remembers prior self-revocations. This preserves rejoin-from-same-
            // identity flows after the room becomes empty while leaving admin ACLs
            // and other room-scoped state intact.
            revoked_all.clear();
        }
        let (revoked_since_root, revoked_root) = if revoked_all.is_empty() {
            ([0u8; 32], [0u8; 32])
        } else {
            let root = canonical_set_root(&revoked_all)?;
            (root, root)
        };

        let join_leaves = [leaf_id];
        let join_delta_root = witness::join_delta_root(&join_leaves)?;
        let (canonical_witness, srx_owned) = witness::build_branch_b_artifacts(
            &parent_leaves,
            &join_leaves,
            parent_root,
            &revoked_all,
            revoked_since_root,
            &revoked_all,
            revoked_root,
        )?;
        let witness_cbor = witness::witness_to_cbor(&canonical_witness)?;
        let srx_cbor = srx_owned.to_cbor()?;

        let tswe_salt_hash = msphf_core::instance::tswe_salt_hash(gid, &parent_root)?;

        let kbroad_public = self
            .ctx
            .kbroad_registry()
            .and_then(|registry| registry.get(&gid.to_vec()).cloned())
            .ok_or(CityGError::InvalidInput("kbroad key missing"))?;
        let kbroad_generation = self.roster.kbroad_generation(gid);
        let barrier_state = self
            .ctx
            .barrier_group_state(gid)
            .cloned()
            .unwrap_or_default();
        let (
            current_history_commitment,
            current_barrier_update,
            current_predecessor_kem_tree_hash_after,
        ) = {
            let state = self.roster.groups.entry(gid.to_vec()).or_default();
            (
                ensure_current_history_commitment(gid, state)?,
                state.current_accepted_barrier_update.clone(),
                current_accepted_barrier_predecessor_hash(state),
            )
        };
        let barrier_n_max = validate_barrier_n_max(barrier_state.n_max)?;
        let current_history_view_id = current_history_commitment.history_view_id;
        let barrier_version = barrier_state.barrier_version;
        let cover_leaf_index = u64::from(cover_leaf_index(&leaf_id, barrier_n_max));
        let max_barrier_update_bytes =
            u64::try_from(barrier_state.max_barrier_update_bytes).unwrap_or(u64::MAX);
        let requires_current_barrier_update = parent_root != [0u8; 32] || barrier_version > 0;
        if requires_current_barrier_update && current_barrier_update.is_empty() {
            return Err(CityGError::InvalidInput(
                "current barrier_update missing for join provisioning",
            ));
        }
        if requires_current_barrier_update && current_predecessor_kem_tree_hash_after == [0u8; 32] {
            return Err(CityGError::InvalidInput(
                "current barrier predecessor hash missing for join provisioning",
            ));
        }
        let (current_join_records, current_revoked_leaf_indices) =
            if requires_current_barrier_update {
                let BarrierUpdateWire(
                    _mode,
                    _barrier_version,
                    prev_barrier_version,
                    _tree_size,
                    revocation_roots_hash,
                    _kem_tree_hash_before,
                    _kem_tree_hash_after,
                    _cover_payload,
                ) = parse_deterministic_cbor(current_barrier_update.as_slice())?;
                let revocation_roots_hash = vec_to_32(revocation_roots_hash)?;
                (
                    self.resolve_joins_since(gid, prev_barrier_version)?.records,
                    self.resolve_revoked_leaf_indices(gid, &revocation_roots_hash)?
                        .leaf_indices,
                )
            } else {
                (Vec::new(), Vec::new())
            };
        let join_finalize_auth_token = fresh_join_finalize_auth_token();
        let provisioning_nonce = fresh_join_provisioning_nonce();
        let provisioning_issued_at_ms = current_timestamp_ms();
        let provisioning_expires_at_ms =
            provisioning_issued_at_ms.saturating_add(JOIN_PROVISIONING_TTL_MS);
        let fs_forward_leap_policy = FsForwardLeapPolicy {
            h: self.acceptance_options.fs_policy_config.h,
            checkpoint_interval: self.acceptance_options.fs_policy_config.checkpoint_interval,
            slack_anchor: self.acceptance_options.fs_policy_config.slack_anchor,
            slack_first_device: self.acceptance_options.fs_policy_config.slack_first_device,
            slack_device: self.acceptance_options.fs_policy_config.slack_device,
        };
        {
            let state = self.roster.groups.entry(gid.to_vec()).or_default();
            state.pending_join_finalize_auth.insert(
                leaf_id,
                JoinFinalizeAuthRecord {
                    leaf_id,
                    cover_leaf_index: cover_leaf_index as u32,
                    token: join_finalize_auth_token,
                },
            );
        }

        Ok(JoinTicketBundle {
            gid: *gid,
            cat: DEFAULT_CAT,
            parent_root,
            revoked_root,
            revoked_since_root,
            tswe_salt_hash,
            join_delta_root,
            leaf_id,
            pox_r_commit,
            witness_cbor,
            srx_cbor,
            kbroad_public,
            kbroad_generation,
            barrier_version,
            cover_leaf_index,
            kem_tree_hash_after: barrier_state.kem_tree_hash_after,
            current_history_view_id,
            current_history_commitment,
            current_barrier_update,
            current_predecessor_kem_tree_hash_after,
            current_join_records,
            current_revoked_leaf_indices,
            join_finalize_auth_token,
            provisioning_nonce,
            provisioning_issued_at_ms,
            provisioning_expires_at_ms,
            fs_forward_leap_policy,
            last_accepted_ec: barrier_state.last_accepted_ec,
            n_max: barrier_n_max,
            max_barrier_update_bytes,
        })
    }

    pub fn build_merge_ticket(
        &mut self,
        gid: &[u8; 32],
        leaf_id: &[u8; 32],
    ) -> Result<MergeTicketBundle, CityGError> {
        self.build_merge_ticket_core(gid, leaf_id, Some(*leaf_id))
    }

    pub fn build_merge_ticket_for_refresh(
        &mut self,
        gid: &[u8; 32],
        leaf_id: &[u8; 32],
    ) -> Result<MergeTicketBundle, CityGError> {
        self.build_merge_ticket_core(gid, leaf_id, None)
    }

    pub fn build_merge_ticket_for_targeted_revocation(
        &mut self,
        gid: &[u8; 32],
        author_leaf_id: &[u8; 32],
        target_leaf_id: &[u8; 32],
    ) -> Result<MergeTicketBundle, CityGError> {
        self.build_merge_ticket_core(gid, author_leaf_id, Some(*target_leaf_id))
    }

    pub fn build_admin_expel_ticket(
        &mut self,
        gid: &[u8; 32],
        actor_pop_public_key: &[u8],
        author_leaf_id: &[u8; 32],
        target_leaf_id: &[u8; 32],
        replay_key: [u8; 32],
    ) -> Result<MergeTicketBundle, CityGError> {
        if author_leaf_id == target_leaf_id {
            return Err(CityGError::InvalidInput(
                "author_leaf_id and target_leaf_id must differ; use controlled leave instead",
            ));
        }
        if !self.roster.has_explicit_room_admins(gid)
            || !self.roster.is_room_admin(gid, actor_pop_public_key)
        {
            return Err(CityGError::InvalidInput(
                "room admin proof is not authorized",
            ));
        }
        if self
            .ctx
            .kbroad_registry()
            .and_then(|registry| registry.get(gid.as_ref()))
            .is_none()
        {
            return Err(CityGError::InvalidInput("kbroad key missing"));
        }
        let Some(group) = self.roster.groups.get(gid.as_slice()) else {
            return Err(CityGError::InvalidInput(
                "author leaf not present in roster",
            ));
        };
        ensure_unused_room_admin_proof_replay_key(group, &replay_key)?;
        let Some(bound_pop_public_key) = group.leaf_device_pk.get(author_leaf_id) else {
            return Err(CityGError::InvalidInput(
                "author leaf not present in roster",
            ));
        };
        if bound_pop_public_key.as_slice() != actor_pop_public_key {
            return Err(CityGError::InvalidInput(
                "author leaf is not bound to room admin identity",
            ));
        }

        let bundle = self.build_merge_ticket_core(gid, author_leaf_id, Some(*target_leaf_id))?;
        self.roster
            .groups
            .get_mut(gid.as_slice())
            .ok_or(CityGError::InvalidInput("roster group missing"))?
            .room_admin_proof_replay_keys
            .insert(replay_key);
        self.persist_kbroad_state()?;
        Ok(bundle)
    }

    fn build_merge_ticket_core(
        &mut self,
        gid: &[u8; 32],
        author_leaf_id: &[u8; 32],
        revoked_leaf_id: Option<[u8; 32]>,
    ) -> Result<MergeTicketBundle, CityGError> {
        self.ensure_kbroad_ready(gid)?;
        let default_state = GroupState::default();
        ensure_distinct_active_cover_leaf_indices(
            self.roster
                .groups
                .get(gid.as_slice())
                .unwrap_or(&default_state),
        )?;
        let parent_root = self
            .roster
            .latest_root(gid)
            .ok_or(CityGError::InvalidInput("no anchors accepted for group"))?;

        let mut members = self
            .roster
            .members_for_root(gid, &parent_root)
            .ok_or(CityGError::InvalidInput("unknown membership root"))?;

        members.sort();

        if !members.iter().any(|member| member == author_leaf_id) {
            return Err(CityGError::InvalidInput("leaf not present in roster"));
        }
        if let Some(target_leaf_id) = revoked_leaf_id
            && !members.iter().any(|member| member == &target_leaf_id)
        {
            let message = if target_leaf_id == *author_leaf_id {
                "leaf not present in roster"
            } else {
                "target leaf not present in roster"
            };
            return Err(CityGError::InvalidInput(message));
        }

        let mut revoked_all = self.roster.revoked(gid);
        if let Some(target_leaf_id) = revoked_leaf_id
            && !revoked_all.iter().any(|leaf| leaf == &target_leaf_id)
        {
            revoked_all.push(target_leaf_id);
        }
        revoked_all.sort();
        revoked_all.dedup();

        let (revoked_since, srx_cbor): (Vec<[u8; 32]>, Vec<u8>) = match revoked_leaf_id {
            Some(target_leaf_id) => {
                let mut revoked_since = vec![target_leaf_id];
                revoked_since.sort();
                let revoked_root = canonical_set_root(&revoked_all)?;
                let join_leaves: Vec<[u8; 32]> = Vec::new();
                let srx_owned = witness::build_merge_srx_inputs(
                    &members,
                    &join_leaves,
                    parent_root,
                    &revoked_since,
                    &revoked_all,
                    revoked_root,
                )?;
                (revoked_since, srx_owned.to_cbor()?)
            }
            None => (revoked_all.clone(), Vec::new()),
        };

        let join_leaves: Vec<[u8; 32]> = Vec::new();
        let join_delta_root = witness::join_delta_root(&join_leaves)?;
        let revoked_since_root = if revoked_since.is_empty() {
            [0u8; 32]
        } else {
            canonical_set_root(&revoked_since)?
        };
        let revoked_root = if revoked_all.is_empty() {
            [0u8; 32]
        } else {
            canonical_set_root(&revoked_all)?
        };

        let tswe_salt_hash = msphf_core::instance::tswe_salt_hash(gid, &parent_root)?;
        let pox_r_commit = witness::demo_pox_commit();

        let live_parities: Vec<(Vec<u8>, PivotParity)> = self
            .ctx
            .pivot_parities_for(gid, &parent_root)
            .into_iter()
            .filter_map(|parity| {
                let wid = self.ctx.mh_window.find_head_window(&parity.we_epoch_id)?;
                self.ctx
                    .mh_window
                    .find_head(wid.as_slice(), &parity.we_epoch_id)
                    .map(|_| (wid, parity))
            })
            .collect();
        if live_parities.is_empty() {
            return Err(CityGError::InvalidInput("no pivot parity available"));
        }

        let mut parities_by_window: BTreeMap<Vec<u8>, Vec<PivotParity>> = BTreeMap::new();
        for (wid, parity) in live_parities {
            parities_by_window.entry(wid).or_default().push(parity);
        }
        let Some((_, mut parities)) =
            parities_by_window
                .into_iter()
                .max_by(|(_, left), (_, right)| {
                    let left_max_fs = left
                        .iter()
                        .filter_map(|parity| parity.fs_ec)
                        .max()
                        .unwrap_or(0);
                    let right_max_fs = right
                        .iter()
                        .filter_map(|parity| parity.fs_ec)
                        .max()
                        .unwrap_or(0);
                    match left_max_fs.cmp(&right_max_fs) {
                        core::cmp::Ordering::Equal => {
                            let left_best_accept = left
                                .iter()
                                .map(|parity| parity.accept_seq)
                                .max()
                                .unwrap_or(0);
                            let right_best_accept = right
                                .iter()
                                .map(|parity| parity.accept_seq)
                                .max()
                                .unwrap_or(0);
                            match left_best_accept.cmp(&right_best_accept) {
                                core::cmp::Ordering::Equal => {
                                    let left_best_weid = left
                                        .iter()
                                        .map(|parity| parity.we_epoch_id)
                                        .min()
                                        .unwrap_or([0u8; 32]);
                                    let right_best_weid = right
                                        .iter()
                                        .map(|parity| parity.we_epoch_id)
                                        .min()
                                        .unwrap_or([0u8; 32]);
                                    right_best_weid.cmp(&left_best_weid)
                                }
                                other => other,
                            }
                        }
                        other => other,
                    }
                })
        else {
            return Err(CityGError::InvalidInput("no pivot parity available"));
        };
        parities.sort_by(|a, b| match b.accept_seq.cmp(&a.accept_seq) {
            core::cmp::Ordering::Equal => a.we_epoch_id.cmp(&b.we_epoch_id),
            other => other,
        });
        let pivot_we_epoch_id = parities[0].we_epoch_id;

        let kbroad_public = self
            .ctx
            .kbroad_registry()
            .and_then(|registry| registry.get(&gid.to_vec()).cloned())
            .ok_or(CityGError::InvalidInput("kbroad key missing"))?;
        let kbroad_generation = self.roster.kbroad_generation(gid);
        let barrier_state = self
            .ctx
            .barrier_group_state(gid)
            .cloned()
            .unwrap_or_default();
        let barrier_n_max = validate_barrier_n_max(barrier_state.n_max)?;
        let barrier_version = barrier_state.barrier_version;
        let current_history_commitment = {
            let state = self.roster.groups.entry(gid.to_vec()).or_default();
            ensure_current_history_commitment(gid, state)?
        };
        let cover_leaf_index = u64::from(cover_leaf_index(
            revoked_leaf_id.as_ref().unwrap_or(author_leaf_id),
            barrier_n_max,
        ));
        let max_barrier_update_bytes =
            u64::try_from(barrier_state.max_barrier_update_bytes).unwrap_or(u64::MAX);

        let pivot = &parities[0];
        let proof_mode = pivot.proof_mode.clone();
        let vrf_id = pivot.vrf_id.clone();
        let policy_version = pivot.policy_version.clone();
        let msphf_crs_id = String::from_utf8(pivot.crs_id.clone())
            .unwrap_or_else(|_| RLWE_CRS_ID_DEFAULT.to_string());
        let msphf_params_id = String::from_utf8(pivot.params_id.clone())
            .unwrap_or_else(|_| RLWE_PARAMS_ID_MOCK.to_string());

        let fs_policy_version = self
            .ctx
            .fs_policy_version()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "7".to_string());
        let fs_epoch_base_ts = self.ctx.fs_base_ts().unwrap_or(0);
        let fs_forward_leap_policy = FsForwardLeapPolicy {
            h: self.acceptance_options.fs_policy_config.h,
            checkpoint_interval: self.acceptance_options.fs_policy_config.checkpoint_interval,
            slack_anchor: self.acceptance_options.fs_policy_config.slack_anchor,
            slack_first_device: self.acceptance_options.fs_policy_config.slack_first_device,
            slack_device: self.acceptance_options.fs_policy_config.slack_device,
        };

        Ok(MergeTicketBundle {
            gid: *gid,
            cat: DEFAULT_CAT,
            parent_root,
            leaf_id: *author_leaf_id,
            pivot_we_epoch_id,
            parities,
            witness_cbor: Vec::new(),
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
            kem_tree_hash_after: barrier_state.kem_tree_hash_after,
            current_history_view_id: current_history_commitment.history_view_id,
            current_history_commitment,
            fs_forward_leap_policy,
            last_accepted_ec: barrier_state.last_accepted_ec,
            n_max: barrier_n_max,
            max_barrier_update_bytes,
        })
    }

    pub fn accept_epoch(
        &mut self,
        bundle: &ClientEpochBundle,
    ) -> Result<ServerOutcome, CityGError> {
        if self.roster.kbroad_rotation_required(bundle.gid()) {
            return Err(CityGError::InvalidInput(KBROAD_ROTATION_REQUIRED_ERR));
        }
        let (outcome, staged_ctx, staged_receiver, staged_roster) =
            self.stage_bundle(bundle, self.replaying)?;
        #[allow(clippy::collapsible_if)]
        if !self.replaying {
            if let Some(journal) = &mut self.journal {
                journal.append(bundle)?;
            }
        }
        self.commit_staged(staged_ctx, staged_receiver, staged_roster);
        Ok(outcome)
    }

    fn ensure_kbroad_ready(&mut self, gid: &[u8; 32]) -> Result<(), CityGError> {
        if self.roster.kbroad_rotation_required(gid) {
            self.rotate_group_kbroad(gid, fresh_kbroad_public())?;
        }
        Ok(())
    }

    fn stage_bundle(
        &mut self,
        bundle: &ClientEpochBundle,
        replaying: bool,
    ) -> Result<(ServerOutcome, AcceptanceContext, ReceiverCache, GroupRoster), CityGError> {
        let mut staged_ctx = self.ctx.clone();
        staged_ctx.set_pending_capss_witness(Some(bundle.capss_witness.clone()));
        let mut staged_receiver = self.receiver.clone();
        let mut staged_roster = self.roster.clone();

        match Self::apply_bundle_to_state(
            &mut staged_ctx,
            &mut staged_receiver,
            &mut staged_roster,
            bundle,
            self.history_authority.as_ref(),
            replaying,
        ) {
            Ok(outcome) => Ok((outcome, staged_ctx, staged_receiver, staged_roster)),
            Err(err) => {
                self.ctx.merge_telemetry_from(&staged_ctx);
                Err(err)
            }
        }
    }

    fn apply_bundle_to_state(
        ctx: &mut AcceptanceContext,
        receiver: &mut ReceiverCache,
        roster: &mut GroupRoster,
        bundle: &ClientEpochBundle,
        history_authority: Option<&HistoryAuthorityState>,
        replaying: bool,
    ) -> Result<ServerOutcome, CityGError> {
        let mut state_before = {
            let state = roster.groups.entry(bundle.gid().to_vec()).or_default();
            if bundle.header_map.contains_key(&hdr::HDR_BARRIER_UPDATE) {
                let _ = ensure_current_history_commitment(bundle.gid(), state)?;
            }
            state.clone()
        };
        if replaying {
            rehydrate_replay_join_finalize_auth(&mut state_before, &bundle.header_map)?;
        }
        let delta = bundle.membership_delta()?;
        ensure_distinct_active_cover_leaf_indices(&state_before)?;
        ensure_join_cover_leaf_indices_available(&state_before, delta.joined.as_slice())?;
        let barrier_validation =
            validate_barrier_update_against_roster(&state_before, &bundle.header_map, &delta)?;
        let gid: [u8; 32] = bundle
            .gid()
            .try_into()
            .map_err(|_| CityGError::InvalidInput("gid must be 32 bytes"))?;
        validate_history_authority_headers(
            history_authority,
            &gid,
            &state_before,
            &bundle.header_map,
        )?;

        // Keep barrier acceptance/state logic on a single deterministic path:
        // groups without explicit prior state are treated as default-initialized.
        let _ = ctx.barrier_group_state_entry_mut(bundle.gid());

        let anchor = bundle.anchor_instance();
        let binding_inputs = bundle.hp_binding_inputs();
        let witness_bytes = bundle.witness_bytes().unwrap_or(&[]);

        let acceptance = process_anchor_or(
            ctx,
            receiver,
            &anchor,
            &bundle.header_map,
            &bundle.hp_proof,
            &binding_inputs,
            witness_bytes,
        )?;

        let barrier_state = ctx
            .barrier_group_state(bundle.gid())
            .ok_or(CityGError::InvalidInput("context barrier state missing"))?
            .clone();
        let group = roster.groups.entry(bundle.gid().to_vec()).or_default();
        group.barrier_initialized = barrier_state.barrier_initialized;
        group.barrier_version = barrier_state.barrier_version;
        group.barrier_roots_hash = barrier_state.barrier_roots_hash;
        group.kem_tree_hash_after = barrier_state.kem_tree_hash_after;
        group.srx_root_sw = barrier_state.srx_root_sw;
        group.n_max = barrier_state.n_max.max(1);
        group.last_checkpoint_ec = barrier_state.last_checkpoint_ec;
        group.last_accepted_ec = barrier_state.last_accepted_ec;
        group.last_pcs_refresh_ec = barrier_state.last_pcs_refresh_ec;
        group.pcs_refresh_min_delta_device_ec =
            barrier_state.pcs_refresh_min_delta_device_ec.max(1);
        group.pcs_refresh_min_delta_group_ec = barrier_state.pcs_refresh_min_delta_group_ec.max(1);
        group.pcs_refresh_slot_width_ec = barrier_state.pcs_refresh_slot_width_ec.max(1);
        group.max_barrier_update_bytes = barrier_state.max_barrier_update_bytes.max(1);
        if let Some(record) = accepted_barrier_merge_record(bundle)? {
            group
                .accepted_barrier_merges
                .insert(record.barrier_version, record);
        }
        if let Some(Value::Bytes(raw_update)) = bundle.header_map.get(&hdr::HDR_BARRIER_UPDATE) {
            group.current_accepted_barrier_update = raw_update.clone();
            group.current_accepted_barrier_predecessor_hash = barrier_validation
                .as_ref()
                .map(|validation| validation.parsed.kem_tree_hash_before)
                .unwrap_or(state_before.kem_tree_hash_after);
        }

        let barrier_version = ctx
            .barrier_group_state(bundle.gid())
            .map(|state| state.barrier_version)
            .unwrap_or(0);
        let maybe_device_pk = bundle
            .header_map
            .get(&hdr::HDR_POP_PK)
            .and_then(Value::as_bytes)
            .map(ToOwned::to_owned);
        let maybe_barrier_leaf_pk = bundle
            .header_map
            .get(&hdr::HDR_BARRIER_LEAF_PK)
            .and_then(Value::as_bytes)
            .map(ToOwned::to_owned);
        let barrier_update_reason = parse_barrier_update_reason(&bundle.header_map)?;
        let required_join_barrier_leaf_pk = if delta.joined.is_empty() {
            None
        } else {
            match maybe_barrier_leaf_pk {
                Some(ref ek) if ek.len() == 1184 => Some(ek.clone()),
                Some(_) => {
                    return Err(CityGError::InvalidInput(
                        "barrier_leaf_pk must be exactly 1184 bytes on join",
                    ));
                }
                None => {
                    return Err(CityGError::InvalidInput(
                        "barrier_leaf_pk (header[177]) is required on join",
                    ));
                }
            }
        };
        let new_root = roster.apply_delta(bundle.gid(), &bundle.anchor.parent_root, &delta)?;

        if !delta.joined.is_empty() || !delta.revoked.is_empty() {
            let state = roster.groups.entry(bundle.gid().to_vec()).or_default();
            for leaf in &delta.joined {
                let leaf_index = cover_leaf_index(leaf, state.n_max);
                let device_pk = maybe_device_pk.clone().unwrap_or_else(|| leaf.to_vec());
                let ek_leaf =
                    required_join_barrier_leaf_pk
                        .clone()
                        .ok_or(CityGError::InvalidInput(
                            "barrier_leaf_pk (header[177]) is required on join",
                        ))?;
                state.join_history.push(JoinLeafHistoryRecord {
                    leaf_id: *leaf,
                    barrier_version: barrier_version.saturating_add(1),
                    leaf_index,
                    device_pk: device_pk.clone(),
                    ek_leaf: ek_leaf.clone(),
                });
                state.leaf_device_pk.insert(*leaf, device_pk);
                if !ek_leaf.is_empty() {
                    state.leaf_barrier_public.insert(*leaf, ek_leaf);
                }
            }
            for leaf in &delta.revoked {
                state.leaf_device_pk.remove(leaf);
                state.leaf_barrier_public.remove(leaf);
                state.pending_join_finalize_auth.remove(leaf);
            }
            prune_join_history(state)?;
        }
        if let Some(state) = roster.groups.get_mut(bundle.gid())
            && matches!(barrier_update_reason, Some(2))
            && let Some(pop_pk) = maybe_device_pk.as_deref()
            && let Some(author_leaf_id) = state
                .leaf_device_pk
                .iter()
                .find(|(_, device_pk)| device_pk.as_slice() == pop_pk)
                .map(|(leaf_id, _)| *leaf_id)
        {
            state.pending_join_finalize_auth.remove(&author_leaf_id);
        }
        if let Some(validation) = barrier_validation.as_ref() {
            let predecessor_hash = compute_barrier_tree_hash(
                validation.parsed.tree_size.max(1),
                validation.snapshot_pre.as_slice(),
            )?;
            if predecessor_hash != validation.parsed.kem_tree_hash_before {
                return Err(CityGError::InvalidInput(
                    "current barrier predecessor snapshot mismatch",
                ));
            }
            let state = roster.groups.entry(bundle.gid().to_vec()).or_default();
            state.barrier_pk_entries = validation.snapshot_post.clone();
            state.kem_tree_hash_after = validation.parsed.kem_tree_hash_after;
            state.n_max = validation.parsed.tree_size.max(1);
            state.barrier_hash_cache = validation.hash_cache_post.clone();
            let current_history_commitment =
                ensure_current_history_commitment(bundle.gid(), state)?;
            record_barrier_public_tree_snapshot_with_metadata(
                state,
                predecessor_hash,
                state.barrier_version,
                current_history_commitment,
                validation.snapshot_pre.as_slice(),
            )?;
            record_barrier_public_tree_snapshot(bundle.gid(), state)?;
        }
        if let Some(state) = roster.groups.get(bundle.gid()) {
            let ctx_state = ctx.barrier_group_state_entry_mut(bundle.gid());
            ctx_state.barrier_initialized = state.barrier_initialized;
            ctx_state.barrier_version = state.barrier_version;
            ctx_state.barrier_roots_hash = state.barrier_roots_hash;
            ctx_state.kem_tree_hash_after = state.kem_tree_hash_after;
            ctx_state.srx_root_sw = state.srx_root_sw;
            ctx_state.n_max = state.n_max.max(1);
            ctx_state.last_checkpoint_ec = state.last_checkpoint_ec;
            ctx_state.last_accepted_ec = state.last_accepted_ec;
            ctx_state.last_pcs_refresh_ec = state.last_pcs_refresh_ec;
            ctx_state.pcs_refresh_min_delta_device_ec =
                state.pcs_refresh_min_delta_device_ec.max(1);
            ctx_state.pcs_refresh_min_delta_group_ec = state.pcs_refresh_min_delta_group_ec.max(1);
            ctx_state.pcs_refresh_slot_width_ec = state.pcs_refresh_slot_width_ec.max(1);
            ctx_state.max_barrier_update_bytes = state.max_barrier_update_bytes.max(1);
        }

        // Carry live pivot parities forward onto the resulting root so a new root
        // can still build merge tickets against the freshest checkpoint window.
        let mut live_prior_parities: Vec<PivotParity> = ctx
            .pivot_parities_for(bundle.gid(), &bundle.anchor.parent_root)
            .into_iter()
            .filter(|parity| {
                ctx.mh_window
                    .find_head_window(&parity.we_epoch_id)
                    .and_then(|wid| ctx.mh_window.find_head(wid.as_slice(), &parity.we_epoch_id))
                    .is_some()
            })
            .collect();
        if live_prior_parities.is_empty() {
            live_prior_parities.push(acceptance.pivot_parity.clone());
        }
        for mut mirrored in live_prior_parities {
            if mirrored.parent_root != new_root {
                mirrored.parent_root = new_root;
            }
            // Keep parity roots aligned with the accepted anchor when mirroring to
            // a new parent root; otherwise downstream tickets can diverge from the
            // barrier state after revocation-changing merges.
            mirrored.join_delta_root = bundle.anchor.join_delta_root;
            mirrored.revoked_since_root = bundle.anchor.revoked_since_prev_root;
            mirrored.revoked_root = bundle.anchor.revoked_root;
            ctx.insert_pivot_parity(mirrored, acceptance.outcome.accept_time);
        }
        if !delta.revoked.is_empty() {
            roster.mark_kbroad_rotation_required(bundle.gid());
        }

        Ok(ServerOutcome {
            we_epoch_id: acceptance.outcome.we_epoch_id,
            wid: acceptance.outcome.wid,
            parent_root: bundle.anchor.parent_root,
            new_root,
        })
    }

    fn commit_staged(
        &mut self,
        staged_ctx: AcceptanceContext,
        staged_receiver: ReceiverCache,
        staged_roster: GroupRoster,
    ) {
        self.ctx = staged_ctx;
        self.receiver = staged_receiver;
        self.roster = staged_roster;
        let empty_gids: Vec<[u8; 32]> = self
            .roster
            .groups
            .iter()
            .filter_map(|(gid, state)| {
                let is_empty = state
                    .latest_snapshot()
                    .map(|snapshot| snapshot.members().next().is_none())
                    .unwrap_or(false);
                if !is_empty {
                    return None;
                }
                gid.as_slice().try_into().ok()
            })
            .collect();
        for gid in empty_gids {
            if let Err(err) = self.reset_empty_room_membership_state(&gid) {
                eprintln!(
                    "cityg-server: failed to reset empty-room membership state for {}: {err:?}",
                    hex::encode(gid)
                );
            }
        }
    }

    fn apply_persisted_kbroad_state(
        &mut self,
        state: &PersistedKbroadState,
    ) -> Result<(), CityGError> {
        let mut registry = self.ctx.kbroad_registry().cloned().unwrap_or_default();
        for (gid, room_state) in state {
            registry.insert(gid.clone(), room_state.kbroad_public.clone());
            let group = self.roster.groups.entry(gid.clone()).or_default();
            group.kbroad_generation = room_state.kbroad_generation;
            group.rotation_required = room_state.rotation_required;
            group.room_admin_pop_keys = room_state.room_admin_pop_keys.iter().cloned().collect();
            group.room_admin_proof_replay_keys = room_state
                .room_admin_proof_replay_keys
                .iter()
                .copied()
                .collect();
            group.revoked = room_state
                .revoked_leaf_ids_hex
                .iter()
                .filter_map(|leaf| {
                    hex::decode(leaf)
                        .ok()
                        .and_then(|bytes| bytes.try_into().ok())
                })
                .collect();
            group.barrier_initialized = room_state.barrier_initialized;
            group.barrier_version = room_state.barrier_version;
            group.barrier_roots_hash = room_state.barrier_roots_hash;
            group.kem_tree_hash_after = room_state.kem_tree_hash_after;
            group.srx_root_sw = room_state.srx_root_sw;
            group.n_max = validate_barrier_n_max(room_state.n_max)?;
            group.last_checkpoint_ec = room_state.last_checkpoint_ec;
            group.last_accepted_ec = room_state.last_accepted_ec;
            group.barrier_pk_entries = room_state.barrier_pk_entries.clone();
            group.barrier_public_tree_blobs = room_state.barrier_public_tree_blobs.clone();
            group.accepted_barrier_merges =
                decode_persisted_accepted_barrier_merges(&room_state.accepted_barrier_merges);
            group.current_history_commitment = decode_persisted_history_commitment(
                gid.as_slice(),
                &room_state.current_history_commitment,
                [0u8; 32],
            )?;
            group.current_accepted_barrier_update =
                room_state.current_accepted_barrier_update.clone();
            group.current_accepted_barrier_predecessor_hash =
                room_state.current_accepted_barrier_predecessor_hash;
            group.pending_join_finalize_auth =
                decode_persisted_join_finalize_auth(&room_state.pending_join_finalize_auth);
            rebuild_barrier_public_tree_blob_index(group)?;
            group.barrier_public_tree_history.clear();
            for snapshot in &room_state.barrier_public_tree_history {
                let hash = match hex::decode(&snapshot.kem_tree_hash_after_hex)
                    .ok()
                    .and_then(|hash| hash.try_into().ok())
                {
                    Some(hash) => hash,
                    None => continue,
                };
                let snapshot_ref = if snapshot.blob_indices.is_empty() {
                    match encode_barrier_public_tree_snapshot_ref(
                        group,
                        snapshot.pk_entries.as_slice(),
                    ) {
                        Ok(mut snapshot_ref) => {
                            snapshot_ref.history_view_id =
                                hex::decode(&snapshot.history_view_id_hex)
                                    .ok()
                                    .and_then(|bytes| bytes.try_into().ok())
                                    .unwrap_or([0u8; 32]);
                            snapshot_ref.history_commitment = decode_persisted_history_commitment(
                                gid.as_slice(),
                                &snapshot.history_commitment,
                                snapshot_ref.history_view_id,
                            )?;
                            snapshot_ref
                        }
                        Err(_) => continue,
                    }
                } else {
                    let snapshot_ref = BarrierPublicTreeSnapshotRef {
                        blob_indices: snapshot.blob_indices.clone(),
                        barrier_version: snapshot.barrier_version,
                        history_view_id: hex::decode(&snapshot.history_view_id_hex)
                            .ok()
                            .and_then(|bytes| bytes.try_into().ok())
                            .unwrap_or([0u8; 32]),
                        history_commitment: decode_persisted_history_commitment(
                            gid.as_slice(),
                            &snapshot.history_commitment,
                            hex::decode(&snapshot.history_view_id_hex)
                                .ok()
                                .and_then(|bytes| bytes.try_into().ok())
                                .unwrap_or([0u8; 32]),
                        )?,
                    };
                    if decode_barrier_public_tree_snapshot_ref(group, &snapshot_ref).is_err() {
                        continue;
                    }
                    snapshot_ref
                };
                group.barrier_public_tree_history.insert(hash, snapshot_ref);
            }
            if group.barrier_public_tree_history.is_empty() && !group.barrier_pk_entries.is_empty()
            {
                record_barrier_public_tree_snapshot(gid.as_slice(), group)?;
            } else if !group.barrier_pk_entries.is_empty() {
                let current_history_commitment =
                    ensure_current_history_commitment(gid.as_slice(), group)?;
                let current_hash = group.kem_tree_hash_after;
                if !group
                    .barrier_public_tree_history
                    .contains_key(&current_hash)
                {
                    let current_entries = group.barrier_pk_entries.clone();
                    let mut snapshot_ref =
                        encode_barrier_public_tree_snapshot_ref(group, current_entries.as_slice())?;
                    snapshot_ref.barrier_version = group.barrier_version;
                    snapshot_ref.history_commitment = current_history_commitment;
                    snapshot_ref.history_view_id = current_history_commitment.history_view_id;
                    group
                        .barrier_public_tree_history
                        .insert(current_hash, snapshot_ref);
                } else {
                    let needs_history_commitment = group
                        .barrier_public_tree_history
                        .get(&current_hash)
                        .map(|snapshot_ref| {
                            snapshot_ref.history_view_id == [0u8; 32]
                                || snapshot_ref.history_commitment.history_commitment_id
                                    == [0u8; 32]
                        })
                        .unwrap_or(false);
                    if needs_history_commitment
                        && let Some(snapshot_ref) =
                            group.barrier_public_tree_history.get_mut(&current_hash)
                    {
                        snapshot_ref.history_commitment = current_history_commitment;
                        snapshot_ref.history_view_id = current_history_commitment.history_view_id;
                    }
                }
            }
            prune_barrier_public_tree_history(group)?;
            group.barrier_hash_cache = None;
            group.last_pcs_refresh_ec = room_state.last_pcs_refresh_ec;
            group.pcs_refresh_min_delta_device_ec =
                room_state.pcs_refresh_min_delta_device_ec.max(1);
            group.pcs_refresh_min_delta_group_ec = room_state.pcs_refresh_min_delta_group_ec.max(1);
            group.pcs_refresh_slot_width_ec = room_state.pcs_refresh_slot_width_ec.max(1);
            group.max_barrier_update_bytes = usize::try_from(room_state.max_barrier_update_bytes)
                .unwrap_or(
                    msphf_orchestrator::BarrierGroupState::default().max_barrier_update_bytes,
                )
                .max(1);
            self.ctx.insert_barrier_group_state(
                gid.as_slice(),
                msphf_orchestrator::BarrierGroupState {
                    barrier_initialized: group.barrier_initialized,
                    barrier_version: group.barrier_version,
                    barrier_roots_hash: group.barrier_roots_hash,
                    kem_tree_hash_after: group.kem_tree_hash_after,
                    last_checkpoint_ec: group.last_checkpoint_ec,
                    last_accepted_ec: group.last_accepted_ec,
                    srx_root_sw: group.srx_root_sw,
                    n_max: group.n_max,
                    max_barrier_update_bytes: group.max_barrier_update_bytes.max(1),
                    last_pcs_refresh_ec: group.last_pcs_refresh_ec,
                    pcs_refresh_min_delta_device_ec: group.pcs_refresh_min_delta_device_ec,
                    pcs_refresh_min_delta_group_ec: group.pcs_refresh_min_delta_group_ec,
                    pcs_refresh_slot_width_ec: group.pcs_refresh_slot_width_ec,
                },
            );
            for device_state in &room_state.device_chain_states {
                self.ctx.insert_device_chain_state(
                    gid.as_slice(),
                    device_state.device_pk.as_slice(),
                    msphf_orchestrator::DeviceChainState {
                        last_commit: device_state.last_commit,
                        last_ec: device_state.last_ec,
                        last_pcs_refresh_ec: device_state.last_pcs_refresh_ec,
                    },
                );
            }
        }
        self.ctx.set_kbroad_registry(Some(registry));
        Ok(())
    }

    fn overlay_persisted_runtime_metadata_after_replay(
        &mut self,
        state: &PersistedKbroadState,
    ) -> Result<(), CityGError> {
        let mut registry = self.ctx.kbroad_registry().cloned().unwrap_or_default();
        for (gid, room_state) in state {
            registry.insert(gid.clone(), room_state.kbroad_public.clone());
            let group = self.roster.groups.entry(gid.clone()).or_default();
            group.kbroad_generation = room_state.kbroad_generation;
            group.rotation_required = room_state.rotation_required;
            group.room_admin_pop_keys = room_state.room_admin_pop_keys.iter().cloned().collect();
            group.room_admin_proof_replay_keys = room_state
                .room_admin_proof_replay_keys
                .iter()
                .copied()
                .collect();
            let persisted_revoked: BTreeSet<[u8; 32]> = room_state
                .revoked_leaf_ids_hex
                .iter()
                .filter_map(|leaf| {
                    hex::decode(leaf)
                        .ok()
                        .and_then(|bytes| bytes.try_into().ok())
                })
                .collect();
            let persisted_n_max = validate_barrier_n_max(room_state.n_max)?;
            let persisted_current_history_commitment = decode_persisted_history_commitment(
                gid.as_slice(),
                &room_state.current_history_commitment,
                [0u8; 32],
            )?;
            let persisted_barrier_state_consistent = barrier_runtime_matches_current_update(
                room_state.barrier_version,
                &room_state.barrier_roots_hash,
                &room_state.kem_tree_hash_after,
                persisted_n_max,
                room_state.current_accepted_barrier_update.as_slice(),
            );
            let replay_barrier_state_consistent = barrier_runtime_matches_current_update(
                group.barrier_version,
                &group.barrier_roots_hash,
                &group.kem_tree_hash_after,
                group.n_max.max(1),
                group.current_accepted_barrier_update.as_slice(),
            );
            let prefer_persisted_barrier_state = persisted_barrier_state_consistent
                && (room_state.barrier_version > group.barrier_version
                    || !replay_barrier_state_consistent);
            if prefer_persisted_barrier_state {
                group.revoked = persisted_revoked.clone();
                group.barrier_initialized = room_state.barrier_initialized;
                group.barrier_version = room_state.barrier_version;
                group.barrier_roots_hash = room_state.barrier_roots_hash;
                group.kem_tree_hash_after = room_state.kem_tree_hash_after;
                group.srx_root_sw = room_state.srx_root_sw;
                group.n_max = persisted_n_max;
                group.last_checkpoint_ec = room_state.last_checkpoint_ec;
                group.last_accepted_ec = room_state.last_accepted_ec;
                group.last_pcs_refresh_ec = room_state.last_pcs_refresh_ec;
                group.pcs_refresh_min_delta_device_ec =
                    room_state.pcs_refresh_min_delta_device_ec.max(1);
                group.pcs_refresh_min_delta_group_ec =
                    room_state.pcs_refresh_min_delta_group_ec.max(1);
                group.pcs_refresh_slot_width_ec = room_state.pcs_refresh_slot_width_ec.max(1);
                group.max_barrier_update_bytes =
                    usize::try_from(room_state.max_barrier_update_bytes)
                        .unwrap_or(
                            msphf_orchestrator::BarrierGroupState::default()
                                .max_barrier_update_bytes,
                        )
                        .max(1);
                group.barrier_pk_entries = room_state.barrier_pk_entries.clone();
                group.current_history_commitment = persisted_current_history_commitment;
                group.current_accepted_barrier_update =
                    room_state.current_accepted_barrier_update.clone();
                group.current_accepted_barrier_predecessor_hash =
                    room_state.current_accepted_barrier_predecessor_hash;
                group.pending_join_finalize_auth =
                    decode_persisted_join_finalize_auth(&room_state.pending_join_finalize_auth);
            }
            group.last_pcs_refresh_ec =
                merge_optional_u64_max(group.last_pcs_refresh_ec, room_state.last_pcs_refresh_ec);
            group.pcs_refresh_min_delta_device_ec =
                room_state.pcs_refresh_min_delta_device_ec.max(1);
            group.pcs_refresh_min_delta_group_ec = room_state.pcs_refresh_min_delta_group_ec.max(1);
            group.pcs_refresh_slot_width_ec = room_state.pcs_refresh_slot_width_ec.max(1);
            group.max_barrier_update_bytes = usize::try_from(room_state.max_barrier_update_bytes)
                .unwrap_or(
                    msphf_orchestrator::BarrierGroupState::default().max_barrier_update_bytes,
                )
                .max(1);
            for (barrier_version, record) in
                decode_persisted_accepted_barrier_merges(&room_state.accepted_barrier_merges)
            {
                group
                    .accepted_barrier_merges
                    .entry(barrier_version)
                    .or_insert(record);
            }
            group.n_max = validate_barrier_n_max(group.n_max)?;
            if prefer_persisted_barrier_state
                || (persisted_current_history_commitment.history_commitment_id != [0u8; 32]
                    && group.current_history_commitment.history_commitment_id == [0u8; 32])
            {
                group.current_history_commitment = persisted_current_history_commitment;
            }
            if prefer_persisted_barrier_state
                || (group.current_accepted_barrier_update.is_empty()
                    && !room_state.current_accepted_barrier_update.is_empty())
            {
                group.current_accepted_barrier_update =
                    room_state.current_accepted_barrier_update.clone();
            }
            if prefer_persisted_barrier_state
                || (group.current_accepted_barrier_predecessor_hash == [0u8; 32]
                    && room_state.current_accepted_barrier_predecessor_hash != [0u8; 32])
            {
                group.current_accepted_barrier_predecessor_hash =
                    room_state.current_accepted_barrier_predecessor_hash;
            }
            if prefer_persisted_barrier_state
                || (group.pending_join_finalize_auth.is_empty()
                    && !room_state.pending_join_finalize_auth.is_empty())
            {
                group.pending_join_finalize_auth =
                    decode_persisted_join_finalize_auth(&room_state.pending_join_finalize_auth);
            }
            let prefer_persisted_tree_history =
                prefer_persisted_barrier_state || group.barrier_public_tree_history.is_empty();
            if prefer_persisted_tree_history {
                group.barrier_public_tree_blobs = room_state.barrier_public_tree_blobs.clone();
                rebuild_barrier_public_tree_blob_index(group)?;
                group.barrier_public_tree_history.clear();
                for snapshot in &room_state.barrier_public_tree_history {
                    let hash = match hex::decode(&snapshot.kem_tree_hash_after_hex)
                        .ok()
                        .and_then(|hash| hash.try_into().ok())
                    {
                        Some(hash) => hash,
                        None => continue,
                    };
                    let snapshot_ref = if snapshot.blob_indices.is_empty() {
                        match encode_barrier_public_tree_snapshot_ref(
                            group,
                            snapshot.pk_entries.as_slice(),
                        ) {
                            Ok(mut snapshot_ref) => {
                                snapshot_ref.history_view_id =
                                    hex::decode(&snapshot.history_view_id_hex)
                                        .ok()
                                        .and_then(|bytes| bytes.try_into().ok())
                                        .unwrap_or([0u8; 32]);
                                snapshot_ref.history_commitment =
                                    decode_persisted_history_commitment(
                                        gid.as_slice(),
                                        &snapshot.history_commitment,
                                        snapshot_ref.history_view_id,
                                    )?;
                                snapshot_ref
                            }
                            Err(_) => continue,
                        }
                    } else {
                        let snapshot_ref = BarrierPublicTreeSnapshotRef {
                            blob_indices: snapshot.blob_indices.clone(),
                            barrier_version: snapshot.barrier_version,
                            history_view_id: hex::decode(&snapshot.history_view_id_hex)
                                .ok()
                                .and_then(|bytes| bytes.try_into().ok())
                                .unwrap_or([0u8; 32]),
                            history_commitment: decode_persisted_history_commitment(
                                gid.as_slice(),
                                &snapshot.history_commitment,
                                hex::decode(&snapshot.history_view_id_hex)
                                    .ok()
                                    .and_then(|bytes| bytes.try_into().ok())
                                    .unwrap_or([0u8; 32]),
                            )?,
                        };
                        if decode_barrier_public_tree_snapshot_ref(group, &snapshot_ref).is_err() {
                            continue;
                        }
                        snapshot_ref
                    };
                    group.barrier_public_tree_history.insert(hash, snapshot_ref);
                }
            }
            if group.barrier_public_tree_history.is_empty() && !group.barrier_pk_entries.is_empty()
            {
                record_barrier_public_tree_snapshot(gid.as_slice(), group)?;
            } else if !group.barrier_pk_entries.is_empty() {
                let current_history_commitment =
                    ensure_current_history_commitment(gid.as_slice(), group)?;
                let current_hash = group.kem_tree_hash_after;
                if !group
                    .barrier_public_tree_history
                    .contains_key(&current_hash)
                {
                    let current_entries = group.barrier_pk_entries.clone();
                    let mut snapshot_ref =
                        encode_barrier_public_tree_snapshot_ref(group, current_entries.as_slice())?;
                    snapshot_ref.barrier_version = group.barrier_version;
                    snapshot_ref.history_commitment = current_history_commitment;
                    snapshot_ref.history_view_id = current_history_commitment.history_view_id;
                    group
                        .barrier_public_tree_history
                        .insert(current_hash, snapshot_ref);
                } else {
                    let needs_history_commitment = group
                        .barrier_public_tree_history
                        .get(&current_hash)
                        .map(|snapshot_ref| {
                            snapshot_ref.history_view_id == [0u8; 32]
                                || snapshot_ref.history_commitment.history_commitment_id
                                    == [0u8; 32]
                        })
                        .unwrap_or(false);
                    if needs_history_commitment
                        && let Some(snapshot_ref) =
                            group.barrier_public_tree_history.get_mut(&current_hash)
                    {
                        snapshot_ref.history_commitment = current_history_commitment;
                        snapshot_ref.history_view_id = current_history_commitment.history_view_id;
                    }
                }
            }
            prune_barrier_public_tree_history(group)?;
            group.barrier_hash_cache = None;

            let ctx_state = self.ctx.barrier_group_state_entry_mut(gid.as_slice());
            if prefer_persisted_barrier_state {
                ctx_state.barrier_initialized = group.barrier_initialized;
                ctx_state.barrier_version = group.barrier_version;
                ctx_state.barrier_roots_hash = group.barrier_roots_hash;
                ctx_state.kem_tree_hash_after = group.kem_tree_hash_after;
                ctx_state.last_checkpoint_ec = group.last_checkpoint_ec;
                ctx_state.last_accepted_ec = group.last_accepted_ec;
                ctx_state.srx_root_sw = group.srx_root_sw;
                ctx_state.n_max = group.n_max.max(1);
            }
            ctx_state.n_max = validate_barrier_n_max(ctx_state.n_max)?;
            ctx_state.last_pcs_refresh_ec = merge_optional_u64_max(
                ctx_state.last_pcs_refresh_ec,
                room_state.last_pcs_refresh_ec,
            );
            ctx_state.pcs_refresh_min_delta_device_ec =
                room_state.pcs_refresh_min_delta_device_ec.max(1);
            ctx_state.pcs_refresh_min_delta_group_ec =
                room_state.pcs_refresh_min_delta_group_ec.max(1);
            ctx_state.pcs_refresh_slot_width_ec = room_state.pcs_refresh_slot_width_ec.max(1);
            ctx_state.max_barrier_update_bytes =
                usize::try_from(room_state.max_barrier_update_bytes)
                    .unwrap_or(
                        msphf_orchestrator::BarrierGroupState::default().max_barrier_update_bytes,
                    )
                    .max(1);

            for device_state in &room_state.device_chain_states {
                let merged = if let Some(existing) = self
                    .ctx
                    .device_chain_get(gid.as_slice(), device_state.device_pk.as_slice())
                    .cloned()
                {
                    msphf_orchestrator::DeviceChainState {
                        last_commit: existing.last_commit,
                        last_ec: existing.last_ec,
                        last_pcs_refresh_ec: merge_optional_u64_max(
                            existing.last_pcs_refresh_ec,
                            device_state.last_pcs_refresh_ec,
                        ),
                    }
                } else {
                    msphf_orchestrator::DeviceChainState {
                        last_commit: device_state.last_commit,
                        last_ec: device_state.last_ec,
                        last_pcs_refresh_ec: device_state.last_pcs_refresh_ec,
                    }
                };
                self.ctx.insert_device_chain_state(
                    gid.as_slice(),
                    device_state.device_pk.as_slice(),
                    merged,
                );
            }
        }
        self.ctx.set_kbroad_registry(Some(registry));
        Ok(())
    }

    fn snapshot_kbroad_state(&self) -> PersistedKbroadState {
        let registry = self.ctx.kbroad_registry().cloned().unwrap_or_default();
        registry
            .into_iter()
            .map(|(gid, kbroad_public)| {
                let group_state = self.roster.groups.get(gid.as_slice());
                let device_chain_states = self
                    .ctx
                    .device_chain_entries_for_gid(gid.as_slice())
                    .map(|(device_pk, device_state)| PersistedDeviceChainState {
                        device_pk: device_pk.clone(),
                        last_commit: device_state.last_commit,
                        last_ec: device_state.last_ec,
                        last_pcs_refresh_ec: device_state.last_pcs_refresh_ec,
                    })
                    .collect();
                let room = persisted_kbroad_room_state(
                    group_state,
                    kbroad_public,
                    self.roster.kbroad_generation(gid.as_slice()),
                    self.roster.kbroad_rotation_required(gid.as_slice()),
                    device_chain_states,
                );
                (gid, room)
            })
            .collect()
    }

    fn persist_kbroad_state(&self) -> Result<(), CityGError> {
        if let Some(path) = self.kbroad_state_path.as_ref() {
            persist_kbroad_state(path, &self.snapshot_kbroad_state())?;
        }
        Ok(())
    }

    fn reset_state(&mut self) {
        self.ctx = AcceptanceContext::with_options(
            self.h_max,
            self.window_ttl,
            self.acceptance_options.clone(),
        );
        self.receiver = ReceiverCache::new(self.window_ttl);
        self.roster = GroupRoster::default();
        if let Err(err) = self.initialize_registered_groups_barrier_state() {
            eprintln!("cityg-server: barrier bootstrap initialization failed: {err:?}");
        }
    }

    fn seed_registered_groups_from_persisted_kbroad_state(
        &mut self,
        state: &PersistedKbroadState,
    ) -> Result<(), CityGError> {
        let mut registry = self.ctx.kbroad_registry().cloned().unwrap_or_default();
        for (gid, room_state) in state {
            let Ok(gid_arr) = gid.as_slice().try_into() else {
                continue;
            };
            registry.insert(gid.clone(), room_state.kbroad_public.clone());
            let group = self.roster.groups.entry(gid.clone()).or_default();
            group.kbroad_generation = room_state.kbroad_generation;
            group.rotation_required = room_state.rotation_required;
            group.room_admin_pop_keys = room_state.room_admin_pop_keys.iter().cloned().collect();
            group.room_admin_proof_replay_keys = room_state
                .room_admin_proof_replay_keys
                .iter()
                .copied()
                .collect();
            group.n_max = room_state.n_max.max(1);
            group.max_barrier_update_bytes = usize::try_from(room_state.max_barrier_update_bytes)
                .unwrap_or(
                    msphf_orchestrator::BarrierGroupState::default().max_barrier_update_bytes,
                )
                .max(1);
            self.initialize_group_barrier_bootstrap_state(&gid_arr)?;
        }
        self.ctx.set_kbroad_registry(Some(registry));
        Ok(())
    }

    fn recover_from_state(
        &mut self,
        path: &Path,
        persisted_kbroad_state: Option<&PersistedKbroadState>,
    ) -> Result<(), CityGError> {
        let entries = ServerJournal::load_entries(path)?;
        if entries.is_empty() {
            return Ok(());
        }
        self.reset_state();
        if let Some(state) = persisted_kbroad_state {
            self.seed_registered_groups_from_persisted_kbroad_state(state)?;
        }
        self.replaying = true;
        let replay_result = (|| -> Result<(), CityGError> {
            for entry in entries {
                let bundle = ClientEpochBundle::from_cbor(&entry)?;
                let (_, ctx, receiver, roster) = self.stage_bundle(&bundle, true)?;
                self.commit_staged(ctx, receiver, roster);
            }
            Ok(())
        })();
        self.replaying = false;
        replay_result
    }

    pub fn refresh_pivot(&mut self, bundle: &ClientEpochBundle) -> Result<(), CityGError> {
        let pivot_weid =
            header_bytes32(&bundle.header_map, hdr::HDR_ROLLUP_PIVOT_WEID, "pivot_weid")?;
        let parent_root = bundle.anchor.parent_root;
        let pivot = self
            .ctx
            .pivot_parities_for(bundle.gid(), &parent_root)
            .into_iter()
            .find(|parity| parity.we_epoch_id == pivot_weid)
            .ok_or(CityGError::InvalidInput("pivot parity missing for refresh"))?;

        let policy_version = header_string(&bundle.header_map, hdr::HDR_FS_POLICY_VERSION, None)?;
        let proof_mode = header_string(
            &bundle.header_map,
            hdr::HDR_PROOF_MODE,
            Some(DEFAULT_PROOF_MODE),
        )?;
        let vrf_id = header_string(&bundle.header_map, hdr::HDR_VRF_ID, Some(DEFAULT_VRF_ID))?;
        let vrf_proof = header_bytes(&bundle.header_map, hdr::HDR_VRF_PROOF, "vrf_proof")?;
        let vrf_public = header_bytes(
            &bundle.header_map,
            hdr::HDR_VRF_PUBLIC_KEY,
            "vrf_public_key",
        )?;
        let mask_a = header_bytes32(&bundle.header_map, hdr::HDR_VRF_MASK_A, "vrf_mask_a")?;
        let mask_b = header_bytes32(&bundle.header_map, hdr::HDR_VRF_MASK_B, "vrf_mask_b")?;
        let fs_capss = header_bytes(&bundle.header_map, hdr::HDR_FS_CAPSS, "fs_capss")?;
        let srx_commit = header_bytes32_opt(&bundle.header_map, hdr::HDR_SRX_COMMIT)?;
        let srx_root = header_bytes32_opt(&bundle.header_map, hdr::HDR_SRX_ROOT_SW)?;
        let srx_smallwood = header_bytes_opt(&bundle.header_map, hdr::HDR_SRX_SMALLWOOD)?;

        let proofs_commit = compute_proofs_commit_bytes(
            &vrf_proof,
            &fs_capss,
            srx_root.as_ref().map(|arr| arr.as_slice()),
            srx_smallwood.as_deref(),
        )?;
        if policy_version != pivot.policy_version
            || proof_mode != pivot.proof_mode
            || vrf_id != pivot.vrf_id
            || vrf_proof != pivot.vrf_proof
            || vrf_public != pivot.vrf_public
            || mask_a != pivot.mask_a
            || mask_b != pivot.mask_b
            || fs_capss != pivot.fs_capss
            || srx_commit != pivot.srx_commit
            || proofs_commit != pivot.proofs_commit
        {
            return Err(CityGError::InvalidInput(
                "refresh payload diverges from stored parity",
            ));
        }

        let wid = self
            .ctx
            .mh_window
            .find_head_window(&pivot.we_epoch_id)
            .ok_or(CityGError::InvalidInput("pivot head missing"))?;
        let old_record = self
            .ctx
            .mh_window
            .find_head(wid.as_slice(), &pivot.we_epoch_id)
            .ok_or(CityGError::InvalidInput("pivot head missing"))?
            .clone();
        let refreshed = msphf_orchestrator::mhw::HeadRecord::new(
            pivot.we_epoch_id,
            pivot.hp_commit,
            pivot.seed_ctx_hash,
            pivot.rho_commit,
            pivot.seed_commit,
            pivot.xk_hash,
            pivot.join_delta_root,
            pivot.revoked_since_root,
            pivot.revoked_root,
            old_record.accept_seq,
            old_record.accept_time(),
        );

        let accept_time = old_record.accept_time();
        self.ctx
            .mh_window
            .accept_merge(
                wid.as_slice(),
                wid.as_slice(),
                &[pivot.we_epoch_id],
                refreshed,
                accept_time,
            )
            .map_err(|freeze| {
                CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
            })?;
        self.ctx.insert_pivot_parity(pivot, accept_time);
        Ok(())
    }

    pub fn context(&self) -> &AcceptanceContext {
        &self.ctx
    }

    pub fn context_mut(&mut self) -> &mut AcceptanceContext {
        &mut self.ctx
    }

    pub fn update_window_limits(&mut self, h_max: Option<usize>, ttl: Option<Duration>) {
        if let Some(ttl) = ttl {
            let now = self.ctx.current_time();
            self.receiver.set_ttl(ttl, now);
        }
        self.ctx.update_window_limits(h_max, ttl);
    }

    pub fn window_limits(&self) -> (usize, Duration) {
        self.ctx.window_limits()
    }

    pub fn members(&self, gid: &[u8]) -> Vec<[u8; 32]> {
        self.roster.members(gid)
    }

    pub fn members_for_root(&self, gid: &[u8], parent_root: &[u8; 32]) -> Option<Vec<[u8; 32]>> {
        self.roster.members_for_root(gid, parent_root)
    }

    pub fn latest_parent_root(&self, gid: &[u8]) -> Option<[u8; 32]> {
        self.roster.latest_root(gid)
    }

    pub fn barrier_roots_hash(&self, gid: &[u8]) -> Option<[u8; 32]> {
        self.roster
            .groups
            .get(gid)
            .map(|state| state.barrier_roots_hash)
    }

    pub fn barrier_kem_tree_hash_after(&self, gid: &[u8]) -> Option<[u8; 32]> {
        self.roster
            .groups
            .get(gid)
            .map(|state| state.kem_tree_hash_after)
    }

    pub fn barrier_version(&self, gid: &[u8]) -> Option<u64> {
        self.roster
            .groups
            .get(gid)
            .map(|state| state.barrier_version)
    }

    pub fn barrier_n_max(&self, gid: &[u8]) -> Option<u64> {
        self.roster.groups.get(gid).map(|state| state.n_max)
    }

    pub fn barrier_max_barrier_update_bytes(&self, gid: &[u8]) -> Option<u64> {
        self.roster
            .groups
            .get(gid)
            .map(|state| u64::try_from(state.max_barrier_update_bytes).unwrap_or(u64::MAX))
    }

    pub fn fs_forward_leap_policy(&self) -> FsForwardLeapPolicy {
        FsForwardLeapPolicy {
            h: self.acceptance_options.fs_policy_config.h,
            checkpoint_interval: self.acceptance_options.fs_policy_config.checkpoint_interval,
            slack_anchor: self.acceptance_options.fs_policy_config.slack_anchor,
            slack_first_device: self.acceptance_options.fs_policy_config.slack_first_device,
            slack_device: self.acceptance_options.fs_policy_config.slack_device,
        }
    }

    pub fn lookup_merge_acceptance(
        &mut self,
        gid: &[u8; 32],
        pending_barrier_version: u64,
        pending_barrier_update_digest: &[u8; 32],
        pending_we_epoch_id: &[u8; 32],
    ) -> Result<MergeAcceptanceRecord, CityGError> {
        let state = self
            .roster
            .groups
            .get_mut(gid.as_slice())
            .ok_or(CityGError::InvalidInput("group not found"))?;
        let history_commitment = ensure_current_history_commitment(gid.as_slice(), state)?;
        let history_view_id = history_commitment.history_view_id;
        let accepted = state.accepted_barrier_merges.get(&pending_barrier_version);
        let response = match accepted {
            Some(record)
                if record.digest == *pending_barrier_update_digest
                    && record.we_epoch_id == *pending_we_epoch_id =>
            {
                MergeAcceptanceRecord {
                    status: MergeAcceptanceStatus::Accepted,
                    history_view_id,
                    history_commitment,
                    accepted_barrier_version: Some(record.barrier_version),
                    accepted_fs_ec: Some(record.fs_ec),
                    accepted_reason: Some(record.reason),
                    accepted_digest: Some(record.digest),
                }
            }
            Some(record) => MergeAcceptanceRecord {
                status: MergeAcceptanceStatus::Superseded,
                history_view_id,
                history_commitment,
                accepted_barrier_version: Some(record.barrier_version),
                accepted_fs_ec: Some(record.fs_ec),
                accepted_reason: Some(record.reason),
                accepted_digest: Some(record.digest),
            },
            None if state.barrier_version > pending_barrier_version => MergeAcceptanceRecord {
                status: MergeAcceptanceStatus::FinalRejected,
                history_view_id,
                history_commitment,
                accepted_barrier_version: None,
                accepted_fs_ec: None,
                accepted_reason: None,
                accepted_digest: None,
            },
            None => MergeAcceptanceRecord {
                status: MergeAcceptanceStatus::Pending,
                history_view_id,
                history_commitment,
                accepted_barrier_version: None,
                accepted_fs_ec: None,
                accepted_reason: None,
                accepted_digest: None,
            },
        };
        Ok(response)
    }

    pub fn resolve_revoked_leaf_indices(
        &mut self,
        gid: &[u8; 32],
        revocation_roots_hash: &[u8; 32],
    ) -> Result<ResolvedRevokedLeaves, CityGError> {
        let state = self
            .roster
            .groups
            .get_mut(gid.as_slice())
            .ok_or(CityGError::InvalidInput("group not found"))?;
        if state.barrier_roots_hash != *revocation_roots_hash {
            return Err(CityGError::InvalidInput(
                "revocation_roots_hash does not match committed barrier roots",
            ));
        }
        let history_commitment = ensure_current_history_commitment(gid.as_slice(), state)?;
        let mut indices: Vec<u32> = state
            .revoked
            .iter()
            .map(|leaf| cover_leaf_index(leaf, state.n_max))
            .collect();
        indices.sort_unstable();
        indices.dedup();
        Ok(ResolvedRevokedLeaves {
            history_view_id: history_commitment.history_view_id,
            history_commitment,
            leaf_indices: indices,
        })
    }

    pub fn resolve_joins_since(
        &mut self,
        gid: &[u8; 32],
        prev_barrier_version: u64,
    ) -> Result<ResolvedJoins, CityGError> {
        let state = self
            .roster
            .groups
            .get_mut(gid.as_slice())
            .ok_or(CityGError::InvalidInput("group not found"))?;
        ensure_distinct_active_cover_leaf_indices(state)?;
        prune_join_history(state)?;
        let history_commitment = ensure_current_history_commitment(gid.as_slice(), state)?;
        let active_leaves: BTreeSet<[u8; 32]> = state
            .latest_snapshot()
            .map(|snapshot| snapshot.members().copied().collect())
            .unwrap_or_default();
        let mut by_leaf: BTreeMap<u32, BarrierJoinLeafRecord> = BTreeMap::new();
        if prev_barrier_version == 0 && state.barrier_version == 0 {
            let snapshot = require_genesis_provisioning_snapshot(
                state,
                genesis_provisioning_artifact_missing_error,
            )?;
            for leaf in snapshot.members() {
                let leaf_index = cover_leaf_index(leaf, state.n_max);
                checked_insert_unique(
                    &mut by_leaf,
                    leaf_index,
                    BarrierJoinLeafRecord {
                        device_pk: state
                            .leaf_device_pk
                            .get(leaf)
                            .cloned()
                            .unwrap_or_else(|| leaf.to_vec()),
                        leaf_index,
                        ek_leaf: state
                            .leaf_barrier_public
                            .get(leaf)
                            .cloned()
                            .unwrap_or_default(),
                    },
                    DUPLICATE_ACTIVE_COVER_LEAF_ALLOCATION_ERR,
                )?;
            }
            return Ok(ResolvedJoins {
                history_view_id: history_commitment.history_view_id,
                history_commitment,
                records: by_leaf.into_values().collect(),
            });
        }
        for record in &state.join_history {
            if record.barrier_version > prev_barrier_version
                && active_leaves.contains(&record.leaf_id)
            {
                checked_insert_unique(
                    &mut by_leaf,
                    record.leaf_index,
                    BarrierJoinLeafRecord {
                        device_pk: record.device_pk.clone(),
                        leaf_index: record.leaf_index,
                        ek_leaf: record.ek_leaf.clone(),
                    },
                    DUPLICATE_ACTIVE_COVER_LEAF_ALLOCATION_ERR,
                )?;
            }
        }
        Ok(ResolvedJoins {
            history_view_id: history_commitment.history_view_id,
            history_commitment,
            records: by_leaf.into_values().collect(),
        })
    }

    pub fn fetch_barrier_public_tree(
        &mut self,
        gid: &[u8; 32],
        kem_tree_hash_after: &[u8; 32],
    ) -> Result<BarrierPublicTreeSnapshot, CityGError> {
        let state = self
            .roster
            .groups
            .get_mut(gid.as_slice())
            .ok_or(CityGError::InvalidInput("group not found"))?;
        let n_max = validate_barrier_n_max(state.n_max)?;
        prune_barrier_public_tree_history(state)?;
        let pk_entries_view = build_pk_entries_view(state)?;
        let current_hash = compute_barrier_tree_hash(n_max, pk_entries_view.as_ref())?;
        let current_predecessor_hash = current_accepted_barrier_predecessor_hash(state);
        let (pk_entries, barrier_version, history_commitment) = if current_hash
            == *kem_tree_hash_after
        {
            let pk_entries = match pk_entries_view {
                Cow::Borrowed(entries) => entries.to_vec(),
                Cow::Owned(entries) => entries,
            };
            let history_commitment = ensure_current_history_commitment(gid.as_slice(), state)?;
            (pk_entries, state.barrier_version, history_commitment)
        } else if let Some(mut snapshot) = state
            .barrier_public_tree_history
            .get(kem_tree_hash_after)
            .cloned()
        {
            if snapshot.history_commitment.history_commitment_id == [0u8; 32] {
                snapshot.history_commitment =
                    synthesize_legacy_history_commitment(gid.as_slice(), snapshot.history_view_id)?;
                if let Some(entry) = state
                    .barrier_public_tree_history
                    .get_mut(kem_tree_hash_after)
                {
                    entry.history_commitment = snapshot.history_commitment;
                    entry.history_view_id = snapshot.history_commitment.history_view_id;
                }
            }
            let history_commitment = if current_predecessor_hash != [0u8; 32]
                && current_predecessor_hash == *kem_tree_hash_after
            {
                ensure_current_history_commitment(gid.as_slice(), state)?
            } else {
                snapshot.history_commitment
            };
            (
                decode_barrier_public_tree_snapshot_ref(state, &snapshot)?,
                if current_predecessor_hash != [0u8; 32]
                    && current_predecessor_hash == *kem_tree_hash_after
                {
                    state.barrier_version
                } else {
                    snapshot.barrier_version
                },
                history_commitment,
            )
        } else {
            return Err(CityGError::InvalidInput(
                HISTORICAL_BARRIER_PUBLIC_TREE_SNAPSHOT_UNAVAILABLE_ERR,
            ));
        };
        let computed_hash = compute_barrier_tree_hash(n_max, pk_entries.as_slice())?;
        if computed_hash != *kem_tree_hash_after {
            return Err(CityGError::Acceptance(
                msphf_orchestrator::AcceptanceError::Freeze(
                    msphf_orchestrator::FREEZE_BARRIER_TREE_SNAPSHOT_AUTH_FAILURE,
                ),
            ));
        }
        Ok(BarrierPublicTreeSnapshot {
            n_max,
            kem_tree_hash_after: computed_hash,
            barrier_version,
            history_view_id: history_commitment.history_view_id,
            history_commitment,
            pk_entries,
        })
    }

    pub fn current_history_commitment(
        &mut self,
        gid: &[u8; 32],
    ) -> Result<HistoryCommitment, CityGError> {
        let state = self
            .roster
            .groups
            .get_mut(gid.as_slice())
            .ok_or(CityGError::InvalidInput("group not found"))?;
        ensure_current_history_commitment(gid.as_slice(), state)
    }

    pub fn current_history_view_id(&mut self, gid: &[u8; 32]) -> Result<[u8; 32], CityGError> {
        Ok(self.current_history_commitment(gid)?.history_view_id)
    }

    pub fn history_authority_descriptor_bytes(&self) -> Result<Vec<u8>, CityGError> {
        match self.history_authority.as_ref() {
            Some(authority) => encode_history_authority_descriptor(&authority.descriptor),
            None => Ok(Vec::new()),
        }
    }

    pub fn history_authority_descriptor(&self) -> Option<HistoryAuthorityDescriptor> {
        self.history_authority
            .as_ref()
            .map(|state| state.descriptor.clone())
    }

    pub fn join_provisioning_artifact_bytes(
        &self,
        bundle: &JoinTicketBundle,
        profile_version: &str,
        artifacts: JoinProvisioningAuthorityArtifacts<'_>,
    ) -> Result<Vec<u8>, CityGError> {
        let authority = self
            .history_authority
            .as_ref()
            .ok_or(CityGError::InvalidInput(
                "history authority unavailable for join provisioning artifact",
            ))?;
        encode_join_provisioning_artifact(authority, bundle, profile_version, artifacts)
    }

    pub fn merge_ticket_artifact_bytes(
        &self,
        bundle: &MergeTicketBundle,
        profile_version: &str,
        history_authority_extension: &str,
        history_authority_descriptor: &[u8],
        current_global_history_attestation: &[u8],
        pivot_parity_cbor: &[Vec<u8>],
    ) -> Result<Vec<u8>, CityGError> {
        let authority = self
            .history_authority
            .as_ref()
            .ok_or(CityGError::InvalidInput(
                "history authority unavailable for merge ticket artifact",
            ))?;
        encode_merge_ticket_artifact(
            authority,
            bundle,
            profile_version,
            history_authority_extension,
            history_authority_descriptor,
            current_global_history_attestation,
            pivot_parity_cbor,
        )
    }

    pub fn deployment_profile_manifest_bytes(
        &self,
        gid: &[u8; 32],
        profile_version: &str,
        history_authority_extension: &str,
        n_max: u64,
        max_barrier_update_bytes: u64,
        fs_forward_leap_policy: FsForwardLeapPolicy,
    ) -> Result<Vec<u8>, CityGError> {
        let authority = self
            .history_authority
            .as_ref()
            .ok_or(CityGError::InvalidInput(
                "history authority unavailable for deployment profile manifest",
            ))?;
        encode_deployment_profile_manifest(
            authority,
            gid,
            profile_version,
            history_authority_extension,
            n_max,
            max_barrier_update_bytes,
            fs_forward_leap_policy,
        )
    }

    pub fn history_authority_extension_id(&self) -> &'static str {
        self.history_authority
            .as_ref()
            .map(|authority| authority.mode.extension_id())
            .unwrap_or("")
    }

    pub fn history_authority_requires_full_verification_receipt(&self) -> bool {
        self.history_authority
            .as_ref()
            .map(|authority| authority.require_full_verification_receipt)
            .unwrap_or(false)
    }

    pub fn global_history_attestation_bytes(
        &self,
        gid: &[u8; 32],
        history_commitment: &HistoryCommitment,
        barrier_version: u64,
        kem_tree_hash_after: &[u8; 32],
    ) -> Result<Vec<u8>, CityGError> {
        let Some(authority) = self.history_authority.as_ref() else {
            return Ok(Vec::new());
        };
        encode_global_history_attestation(
            authority,
            gid,
            history_commitment,
            barrier_version,
            kem_tree_hash_after,
        )
    }

    pub fn helper_completeness_attestation_revoked_bytes(
        &self,
        history_commitment: &HistoryCommitment,
        revocation_roots_hash: &[u8; 32],
        page_offset: u32,
        total_entries: u32,
        leaf_indices: &[u32],
    ) -> Result<Vec<u8>, CityGError> {
        let Some(authority) = self.history_authority.as_ref() else {
            return Ok(Vec::new());
        };
        encode_helper_completeness_attestation_revoked(
            authority,
            history_commitment,
            revocation_roots_hash,
            page_offset,
            total_entries,
            leaf_indices,
        )
    }

    pub fn helper_completeness_attestation_joins_bytes(
        &self,
        history_commitment: &HistoryCommitment,
        prev_barrier_version: u64,
        page_offset: u32,
        total_entries: u32,
        records: &[BarrierJoinLeafRecord],
    ) -> Result<Vec<u8>, CityGError> {
        let Some(authority) = self.history_authority.as_ref() else {
            return Ok(Vec::new());
        };
        encode_helper_completeness_attestation_joins(
            authority,
            history_commitment,
            prev_barrier_version,
            page_offset,
            total_entries,
            records,
        )
    }

    pub fn helper_completeness_attestation_tree_bytes(
        &self,
        history_commitment: &HistoryCommitment,
        kem_tree_hash_after: &[u8; 32],
        entry_offset: u32,
        total_entries: u32,
        pk_entries: &[Vec<u8>],
    ) -> Result<Vec<u8>, CityGError> {
        let Some(authority) = self.history_authority.as_ref() else {
            return Ok(Vec::new());
        };
        encode_helper_completeness_attestation_tree(
            authority,
            history_commitment,
            kem_tree_hash_after,
            entry_offset,
            total_entries,
            pk_entries,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn full_verification_witness_bytes(
        &self,
        gid: &[u8; 32],
        history_commitment: &HistoryCommitment,
        barrier_version: u64,
        kem_tree_hash_after: &[u8; 32],
        author_leaf_id: &[u8; 32],
        barrier_update_reason: u64,
        updater_leaf: u64,
        barrier_update: &[u8],
        joins_prev_barrier_version: u64,
        join_records: &[BarrierJoinLeafRecord],
        revocation_roots_hash: &[u8; 32],
        revoked_leaf_indices: &[u32],
        deployment_profile_manifest: &[u8],
    ) -> Result<Vec<u8>, CityGError> {
        let authority = self
            .history_authority
            .as_ref()
            .ok_or(CityGError::InvalidInput(
                "history authority unavailable for full verification witness",
            ))?;
        let state = self
            .roster
            .groups
            .get(gid.as_slice())
            .ok_or(CityGError::InvalidInput("group not found"))?;
        if state.current_history_commitment != *history_commitment
            || state.barrier_version != barrier_version
            || state.kem_tree_hash_after != *kem_tree_hash_after
        {
            return Err(CityGError::InvalidInput(
                "full verification witness state mismatch",
            ));
        }
        validate_full_verification_witness_candidate(
            state,
            history_commitment,
            author_leaf_id,
            barrier_update_reason,
            updater_leaf,
            barrier_update,
            joins_prev_barrier_version,
            join_records,
            revocation_roots_hash,
            revoked_leaf_indices,
        )?;
        encode_full_verification_witness(
            authority,
            gid,
            history_commitment,
            barrier_version,
            kem_tree_hash_after,
            author_leaf_id,
            barrier_update_reason,
            updater_leaf,
            barrier_update,
            joins_prev_barrier_version,
            join_records,
            revocation_roots_hash,
            revoked_leaf_indices,
            deployment_profile_manifest,
        )
    }
}

#[derive(Serialize)]
struct BarrierTreeLeafHashArgs<'a> {
    n_max: u64,
    node_index: u64,
    #[serde(with = "serde_bytes")]
    pk: &'a [u8],
}

#[derive(Serialize)]
struct BarrierTreeNodeHashArgs<'a> {
    n_max: u64,
    node_index: u64,
    #[serde(with = "serde_bytes")]
    pk: &'a [u8],
    #[serde(with = "serde_bytes")]
    left_hash: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    right_hash: &'a [u8; 32],
}

#[derive(Serialize)]
struct HistoryViewIdArgs<'a> {
    #[serde(with = "serde_bytes")]
    gid: &'a [u8],
    barrier_initialized: bool,
    barrier_version: u64,
    #[serde(with = "serde_bytes")]
    barrier_roots_hash: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    kem_tree_hash_after: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    latest_root: &'a [u8; 32],
    last_checkpoint_ec: u64,
    last_accepted_ec: u64,
    n_max: u64,
}

#[derive(Serialize)]
struct HistoryCommitmentIdArgs<'a> {
    #[serde(with = "serde_bytes")]
    gid: &'a [u8],
    #[serde(with = "serde_bytes")]
    history_view_id: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    prev_history_commitment_id: &'a [u8; 32],
    history_seq: u64,
}

fn compute_history_view_id(gid: &[u8], state: &GroupState) -> Result<[u8; 32], CityGError> {
    let latest_root = state.latest_root.as_ref().unwrap_or(&[0u8; 32]);
    let n_max = validate_barrier_n_max(state.n_max)?;
    h_l(
        "barrier/history-view",
        &HistoryViewIdArgs {
            gid,
            barrier_initialized: state.barrier_initialized,
            barrier_version: state.barrier_version,
            barrier_roots_hash: &state.barrier_roots_hash,
            kem_tree_hash_after: &state.kem_tree_hash_after,
            latest_root,
            last_checkpoint_ec: state.last_checkpoint_ec,
            last_accepted_ec: state.last_accepted_ec,
            n_max,
        },
    )
    .map_err(CityGError::from)
}

fn compute_history_commitment_id(
    gid: &[u8],
    history_view_id: &[u8; 32],
    prev_history_commitment_id: &[u8; 32],
    history_seq: u64,
) -> Result<[u8; 32], CityGError> {
    h_l(
        "barrier/history-commitment",
        &HistoryCommitmentIdArgs {
            gid,
            history_view_id,
            prev_history_commitment_id,
            history_seq,
        },
    )
    .map_err(CityGError::from)
}

fn synthesize_legacy_history_commitment(
    gid: &[u8],
    history_view_id: [u8; 32],
) -> Result<HistoryCommitment, CityGError> {
    if history_view_id == [0u8; 32] {
        return Ok(HistoryCommitment::default());
    }
    let history_commitment_id = h_l(
        "barrier/history-commitment/legacy",
        &serde_bytes::Bytes::new(&[gid, history_view_id.as_slice()].concat()),
    )
    .map_err(CityGError::from)?;
    Ok(HistoryCommitment {
        history_view_id,
        history_commitment_id,
        prev_history_commitment_id: [0u8; 32],
        history_seq: 0,
    })
}

fn ensure_current_history_commitment(
    gid: &[u8],
    state: &mut GroupState,
) -> Result<HistoryCommitment, CityGError> {
    let history_view_id = compute_history_view_id(gid, state)?;
    let current = state.current_history_commitment;
    if current.history_view_id == history_view_id && current.history_commitment_id != [0u8; 32] {
        refresh_current_barrier_snapshot_commitments(state, current)?;
        return Ok(current);
    }
    let prev_history_commitment_id = current.history_commitment_id;
    let history_seq = current.history_seq.saturating_add(1);
    let history_commitment_id = compute_history_commitment_id(
        gid,
        &history_view_id,
        &prev_history_commitment_id,
        history_seq,
    )?;
    let commitment = HistoryCommitment {
        history_view_id,
        history_commitment_id,
        prev_history_commitment_id,
        history_seq,
    };
    state.current_history_commitment = commitment;
    refresh_current_barrier_snapshot_commitments(state, commitment)?;
    Ok(commitment)
}

fn persisted_history_commitment(commitment: HistoryCommitment) -> PersistedHistoryCommitment {
    PersistedHistoryCommitment {
        history_view_id_hex: hex::encode(commitment.history_view_id),
        history_commitment_id_hex: hex::encode(commitment.history_commitment_id),
        prev_history_commitment_id_hex: hex::encode(commitment.prev_history_commitment_id),
        history_seq: commitment.history_seq,
    }
}

fn decode_persisted_history_commitment(
    gid: &[u8],
    persisted: &PersistedHistoryCommitment,
    fallback_history_view_id: [u8; 32],
) -> Result<HistoryCommitment, CityGError> {
    let history_view_id = hex::decode(&persisted.history_view_id_hex)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .unwrap_or(fallback_history_view_id);
    let history_commitment_id = hex::decode(&persisted.history_commitment_id_hex)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .unwrap_or([0u8; 32]);
    let prev_history_commitment_id = hex::decode(&persisted.prev_history_commitment_id_hex)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .unwrap_or([0u8; 32]);
    if history_commitment_id == [0u8; 32] {
        return synthesize_legacy_history_commitment(gid, history_view_id);
    }
    Ok(HistoryCommitment {
        history_view_id,
        history_commitment_id,
        prev_history_commitment_id,
        history_seq: persisted.history_seq,
    })
}

fn compute_barrier_update_digest(raw_update: &[u8]) -> Result<[u8; 32], CityGError> {
    h_l(
        "barrier/update/digest",
        &serde_bytes::Bytes::new(raw_update),
    )
    .map_err(CityGError::from)
}

fn accepted_barrier_merge_record(
    bundle: &ClientEpochBundle,
) -> Result<Option<AcceptedBarrierMergeRecord>, CityGError> {
    let Some(Value::Bytes(raw_update)) = bundle.header_map.get(&hdr::HDR_BARRIER_UPDATE) else {
        return Ok(None);
    };
    let barrier_version = match bundle.header_map.get(&hdr::HDR_BARRIER_VERSION) {
        Some(Value::Integer(value)) => u64::try_from(*value).map_err(|_| {
            CityGError::InvalidInput("accepted barrier merge missing barrier_version")
        })?,
        _ => {
            return Err(CityGError::InvalidInput(
                "accepted barrier merge missing barrier_version",
            ));
        }
    };
    let fs_ec = match bundle.header_map.get(&hdr::HDR_FS_EC) {
        Some(Value::Integer(value)) => u64::try_from(*value)
            .map_err(|_| CityGError::InvalidInput("accepted barrier merge missing fs_ec"))?,
        _ => {
            return Err(CityGError::InvalidInput(
                "accepted barrier merge missing fs_ec",
            ));
        }
    };
    let reason = parse_barrier_update_reason(&bundle.header_map)?.ok_or(
        CityGError::InvalidInput("accepted barrier merge missing barrier_update_reason"),
    )?;
    let mut we_epoch_id = [0u8; 32];
    we_epoch_id.copy_from_slice(bundle.we_epoch_id.as_slice());
    Ok(Some(AcceptedBarrierMergeRecord {
        barrier_version,
        fs_ec,
        reason,
        digest: compute_barrier_update_digest(raw_update)?,
        we_epoch_id,
    }))
}

#[derive(Clone, Serialize, Deserialize)]
struct BarrierUpdateWire(
    String,
    u64,
    u64,
    u64,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
);

#[derive(Clone, Serialize, Deserialize)]
struct KemTreeCoverPayloadWire(
    u64,
    Vec<u64>,
    Option<Vec<u64>>,
    Vec<NodeCiphertextWire>,
    Vec<NewPublicKeyWire>,
);

#[derive(Clone, Serialize, Deserialize)]
struct NodeCiphertextWire(
    u64,
    u64,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
);

#[derive(Clone, Serialize, Deserialize)]
struct NewPublicKeyWire(u64, #[serde(with = "serde_bytes")] Vec<u8>);

#[derive(Clone)]
struct ParsedNodeCiphertext {
    source_node: u64,
    target_node: u64,
    target_pk_hash: [u8; 16],
}

#[derive(Clone)]
struct ParsedBarrierUpdate {
    prev_barrier_version: u64,
    updater_leaf: u64,
    tree_size: u64,
    revocation_roots_hash: [u8; 32],
    kem_tree_hash_before: [u8; 32],
    kem_tree_hash_after: [u8; 32],
    path_nodes: Vec<u64>,
    node_ciphertexts: Vec<ParsedNodeCiphertext>,
    new_public_keys: Vec<(u64, Vec<u8>)>,
}

#[derive(Clone)]
struct BarrierUpdateValidationOutcome {
    parsed: ParsedBarrierUpdate,
    snapshot_pre: Vec<Vec<u8>>,
    snapshot_post: Vec<Vec<u8>>,
    hash_cache_post: Option<Arc<HashMap<usize, [u8; 32]>>>,
}

#[derive(Serialize)]
struct BarrierPkHashArgs<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

fn parse_deterministic_cbor<T>(raw: &[u8]) -> Result<T, CityGError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let decoded: T = ciborium::de::from_reader(raw)
        .map_err(|_| CityGError::InvalidInput("barrier_update malformed"))?;
    let canonical =
        to_cbor_vec(&decoded).map_err(|_| CityGError::InvalidInput("barrier_update malformed"))?;
    if canonical.as_slice() != raw {
        return Err(CityGError::InvalidInput("barrier_update malformed"));
    }
    Ok(decoded)
}

fn vec_to_32(bytes: Vec<u8>) -> Result<[u8; 32], CityGError> {
    bytes
        .try_into()
        .map_err(|_| CityGError::InvalidInput("barrier_update malformed"))
}

fn vec_to_16(bytes: Vec<u8>) -> Result<[u8; 16], CityGError> {
    bytes
        .try_into()
        .map_err(|_| CityGError::InvalidInput("barrier_update malformed"))
}

fn parse_barrier_update_reason(header: &BTreeMap<u64, Value>) -> Result<Option<u64>, CityGError> {
    let has_update = header.contains_key(&hdr::HDR_BARRIER_UPDATE);
    let reason_value = header.get(&hdr::HDR_BARRIER_UPDATE_REASON);
    if !has_update {
        if reason_value.is_some() {
            return Err(CityGError::InvalidInput("barrier_update malformed"));
        }
        return Ok(None);
    }

    let Some(Value::Integer(reason_int)) = reason_value else {
        return Err(CityGError::InvalidInput("barrier_update malformed"));
    };
    let reason = u64::try_from(*reason_int)
        .map_err(|_| CityGError::InvalidInput("barrier_update malformed"))?;
    if reason > 2 {
        return Err(CityGError::InvalidInput("barrier_update malformed"));
    }
    Ok(Some(reason))
}

fn parse_join_finalize_auth_token(
    header: &BTreeMap<u64, Value>,
) -> Result<Option<[u8; 32]>, CityGError> {
    header_optional_bytes(header, hdr::HDR_JOIN_FINALIZE_AUTH)?
        .map(header_bytes32_from_slice)
        .transpose()
}

#[derive(Serialize, Deserialize)]
struct HistoryAuthorityDescriptorWire(
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
);

#[derive(Serialize, Deserialize)]
struct GlobalHistoryAttestationWire(
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    u64,
    u64,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    String,
    #[serde(with = "serde_bytes")] Vec<u8>,
);

#[derive(Serialize, Deserialize)]
struct JoinProvisioningArtifactWire {
    #[serde(with = "serde_bytes")]
    scope_id: Vec<u8>,
    history_authority_extension: String,
    #[serde(with = "serde_bytes")]
    gid: Vec<u8>,
    profile_version: String,
    #[serde(with = "serde_bytes")]
    leaf_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    history_view_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    history_commitment_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    prev_history_commitment_id: Vec<u8>,
    history_seq: u64,
    barrier_version: u64,
    cover_leaf_index: u64,
    n_max: u64,
    max_barrier_update_bytes: u64,
    #[serde(with = "serde_bytes")]
    kem_tree_hash_after: Vec<u8>,
    #[serde(with = "serde_bytes")]
    current_predecessor_kem_tree_hash_after: Vec<u8>,
    #[serde(with = "serde_bytes")]
    join_finalize_auth_token: Vec<u8>,
    #[serde(with = "serde_bytes")]
    provisioning_nonce: Vec<u8>,
    provisioning_issued_at_ms: u64,
    provisioning_expires_at_ms: u64,
    fs_forward_leap_h: u64,
    fs_forward_leap_checkpoint_interval: u64,
    fs_forward_leap_slack_anchor: u64,
    fs_forward_leap_slack_first_device: u64,
    fs_forward_leap_slack_device: u64,
    last_accepted_ec: u64,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct MergeTicketArtifactWire {
    #[serde(with = "serde_bytes")]
    scope_id: Vec<u8>,
    history_authority_extension: String,
    profile_version: String,
    #[serde(with = "serde_bytes")]
    gid: Vec<u8>,
    #[serde(with = "serde_bytes")]
    leaf_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    history_view_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    history_commitment_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    prev_history_commitment_id: Vec<u8>,
    history_seq: u64,
    barrier_version: u64,
    cover_leaf_index: u64,
    n_max: u64,
    max_barrier_update_bytes: u64,
    #[serde(with = "serde_bytes")]
    kem_tree_hash_after: Vec<u8>,
    fs_forward_leap_h: u64,
    fs_forward_leap_checkpoint_interval: u64,
    fs_forward_leap_slack_anchor: u64,
    fs_forward_leap_slack_first_device: u64,
    fs_forward_leap_slack_device: u64,
    last_accepted_ec: u64,
    #[serde(with = "serde_bytes")]
    history_authority_descriptor: Vec<u8>,
    #[serde(with = "serde_bytes")]
    current_global_history_attestation: Vec<u8>,
    #[serde(with = "serde_bytes")]
    we_epoch_id: Vec<u8>,
    pivot_parity_cbor: Vec<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    witness_cbor: Vec<u8>,
    #[serde(with = "serde_bytes")]
    srx_cbor: Vec<u8>,
    proof_mode: String,
    vrf_id: String,
    policy_version: String,
    #[serde(with = "serde_bytes")]
    cat: Vec<u8>,
    #[serde(with = "serde_bytes")]
    parent_root: Vec<u8>,
    #[serde(with = "serde_bytes")]
    join_delta_root: Vec<u8>,
    #[serde(with = "serde_bytes")]
    revoked_since_root: Vec<u8>,
    #[serde(with = "serde_bytes")]
    revoked_root: Vec<u8>,
    #[serde(with = "serde_bytes")]
    tswe_salt_hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pox_r_commit: Vec<u8>,
    #[serde(with = "serde_bytes")]
    kbroad_public: Vec<u8>,
    msphf_crs_id: String,
    msphf_params_id: String,
    fs_policy_version: String,
    fs_epoch_base_ts: u64,
    kbroad_generation: u64,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct DeploymentProfileManifestWire {
    #[serde(with = "serde_bytes")]
    scope_id: Vec<u8>,
    history_authority_extension: String,
    #[serde(with = "serde_bytes")]
    gid: Vec<u8>,
    profile_version: String,
    n_max: u64,
    max_barrier_update_bytes: u64,
    fs_forward_leap_h: u64,
    fs_forward_leap_checkpoint_interval: u64,
    fs_forward_leap_slack_anchor: u64,
    fs_forward_leap_slack_first_device: u64,
    fs_forward_leap_slack_device: u64,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}

#[derive(Serialize)]
struct GlobalHistoryAttestationSignedPayload<'a>(
    &'static str,
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    u64,
    u64,
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    &'a str,
);

#[derive(Serialize)]
struct JoinProvisioningArtifactSignedPayload<'a> {
    label: &'static str,
    #[serde(with = "serde_bytes")]
    scope_id: &'a [u8; 32],
    history_authority_extension: &'a str,
    #[serde(with = "serde_bytes")]
    gid: &'a [u8; 32],
    profile_version: &'a str,
    #[serde(with = "serde_bytes")]
    leaf_id: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    history_view_id: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    history_commitment_id: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    prev_history_commitment_id: &'a [u8; 32],
    history_seq: u64,
    barrier_version: u64,
    cover_leaf_index: u64,
    n_max: u64,
    max_barrier_update_bytes: u64,
    #[serde(with = "serde_bytes")]
    kem_tree_hash_after: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    current_predecessor_kem_tree_hash_after: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    join_finalize_auth_token: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    provisioning_nonce: &'a [u8; 32],
    provisioning_issued_at_ms: u64,
    provisioning_expires_at_ms: u64,
    fs_forward_leap_h: u64,
    fs_forward_leap_checkpoint_interval: u64,
    fs_forward_leap_slack_anchor: u64,
    fs_forward_leap_slack_first_device: u64,
    fs_forward_leap_slack_device: u64,
    last_accepted_ec: u64,
    #[serde(with = "serde_bytes")]
    history_authority_descriptor: &'a [u8],
    #[serde(with = "serde_bytes")]
    current_global_history_attestation: &'a [u8],
    #[serde(with = "serde_bytes")]
    current_join_records_completeness_attestation: &'a [u8],
    #[serde(with = "serde_bytes")]
    current_revoked_leaf_indices_completeness_attestation: &'a [u8],
    #[serde(with = "serde_bytes")]
    current_barrier_update: &'a [u8],
    current_join_records: &'a [BarrierJoinLeafRecord],
    current_revoked_leaf_indices: &'a [u32],
}

#[derive(Serialize)]
struct MergeTicketArtifactSignedPayload<'a> {
    label: &'static str,
    #[serde(with = "serde_bytes")]
    scope_id: &'a [u8; 32],
    history_authority_extension: &'a str,
    profile_version: &'a str,
    #[serde(with = "serde_bytes")]
    gid: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    leaf_id: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    history_view_id: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    history_commitment_id: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    prev_history_commitment_id: &'a [u8; 32],
    history_seq: u64,
    barrier_version: u64,
    cover_leaf_index: u64,
    n_max: u64,
    max_barrier_update_bytes: u64,
    #[serde(with = "serde_bytes")]
    kem_tree_hash_after: &'a [u8; 32],
    fs_forward_leap_h: u64,
    fs_forward_leap_checkpoint_interval: u64,
    fs_forward_leap_slack_anchor: u64,
    fs_forward_leap_slack_first_device: u64,
    fs_forward_leap_slack_device: u64,
    last_accepted_ec: u64,
    #[serde(with = "serde_bytes")]
    history_authority_descriptor: &'a [u8],
    #[serde(with = "serde_bytes")]
    current_global_history_attestation: &'a [u8],
    #[serde(with = "serde_bytes")]
    we_epoch_id: &'a [u8; 32],
    pivot_parity_cbor: &'a [Vec<u8>],
    #[serde(with = "serde_bytes")]
    witness_cbor: &'a [u8],
    #[serde(with = "serde_bytes")]
    srx_cbor: &'a [u8],
    proof_mode: &'a str,
    vrf_id: &'a str,
    policy_version: &'a str,
    #[serde(with = "serde_bytes")]
    cat: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    parent_root: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    join_delta_root: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    revoked_since_root: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    revoked_root: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    tswe_salt_hash: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pox_r_commit: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    kbroad_public: &'a [u8],
    msphf_crs_id: &'a str,
    msphf_params_id: &'a str,
    fs_policy_version: &'a str,
    fs_epoch_base_ts: u64,
    kbroad_generation: u64,
}

#[derive(Serialize)]
struct DeploymentProfileManifestSignedPayload<'a> {
    label: &'static str,
    #[serde(with = "serde_bytes")]
    scope_id: &'a [u8; 32],
    history_authority_extension: &'a str,
    #[serde(with = "serde_bytes")]
    gid: &'a [u8; 32],
    profile_version: &'a str,
    n_max: u64,
    max_barrier_update_bytes: u64,
    fs_forward_leap_h: u64,
    fs_forward_leap_checkpoint_interval: u64,
    fs_forward_leap_slack_anchor: u64,
    fs_forward_leap_slack_first_device: u64,
    fs_forward_leap_slack_device: u64,
}

#[derive(Serialize, Deserialize)]
struct HelperCompletenessAttestationWire(
    #[serde(with = "serde_bytes")] Vec<u8>,
    String,
    #[serde(with = "serde_bytes")] Vec<u8>,
);

#[derive(Serialize)]
struct HelperCompletenessSignedPayload<'a, T> {
    label: &'static str,
    #[serde(with = "serde_bytes")]
    scope_id: &'a [u8; 32],
    helper_kind: &'a str,
    #[serde(with = "serde_bytes")]
    history_view_id: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    history_commitment_id: &'a [u8; 32],
    page_offset: u32,
    total_entries: u32,
    selector: T,
}

#[derive(Serialize)]
struct RevokedLeavesSelector<'a> {
    #[serde(with = "serde_bytes")]
    revocation_roots_hash: &'a [u8; 32],
    leaf_indices: &'a [u32],
}

#[derive(Serialize)]
struct JoinsSinceSelector<'a> {
    prev_barrier_version: u64,
    records: &'a [BarrierJoinLeafRecord],
}

#[derive(Serialize)]
struct FetchPublicTreeSelector<'a> {
    #[serde(with = "serde_bytes")]
    kem_tree_hash_after: &'a [u8; 32],
    pk_entries: &'a [Vec<u8>],
}

#[derive(Serialize, Deserialize)]
struct FullVerificationReceiptWire {
    #[serde(with = "serde_bytes")]
    author_leaf_id: Vec<u8>,
    barrier_update_reason: u64,
    updater_leaf: u64,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}

#[derive(Serialize)]
struct FullVerificationReceiptSignedPayload<'a> {
    label: &'static str,
    #[serde(with = "serde_bytes")]
    gid: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    author_leaf_id: &'a [u8; 32],
    barrier_update_reason: u64,
    updater_leaf: u64,
    #[serde(with = "serde_bytes")]
    barrier_history_commitment: &'a [u8],
    #[serde(with = "serde_bytes")]
    global_history_attestation: &'a [u8],
    #[serde(with = "serde_bytes")]
    barrier_update: &'a [u8],
}

#[derive(Serialize, Deserialize)]
struct FullVerificationWitnessWire {
    #[serde(with = "serde_bytes")]
    scope_id: Vec<u8>,
    history_authority_extension: String,
    #[serde(with = "serde_bytes")]
    gid: Vec<u8>,
    #[serde(with = "serde_bytes")]
    history_view_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    history_commitment_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    prev_history_commitment_id: Vec<u8>,
    history_seq: u64,
    barrier_version: u64,
    #[serde(with = "serde_bytes")]
    kem_tree_hash_after: Vec<u8>,
    #[serde(with = "serde_bytes")]
    author_leaf_id: Vec<u8>,
    barrier_update_reason: u64,
    updater_leaf: u64,
    #[serde(with = "serde_bytes")]
    barrier_update_digest: Vec<u8>,
    #[serde(with = "serde_bytes")]
    joins_digest: Vec<u8>,
    #[serde(with = "serde_bytes")]
    revoked_digest: Vec<u8>,
    #[serde(with = "serde_bytes")]
    deployment_profile_manifest_digest: Vec<u8>,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}

#[derive(Serialize)]
struct FullVerificationWitnessSignedPayload<'a> {
    label: &'static str,
    #[serde(with = "serde_bytes")]
    scope_id: &'a [u8; 32],
    history_authority_extension: &'a str,
    #[serde(with = "serde_bytes")]
    gid: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    history_view_id: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    history_commitment_id: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    prev_history_commitment_id: &'a [u8; 32],
    history_seq: u64,
    barrier_version: u64,
    #[serde(with = "serde_bytes")]
    kem_tree_hash_after: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    author_leaf_id: &'a [u8; 32],
    barrier_update_reason: u64,
    updater_leaf: u64,
    #[serde(with = "serde_bytes")]
    barrier_update_digest: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    joins_digest: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    revoked_digest: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    deployment_profile_manifest_digest: &'a [u8; 32],
}

fn encode_history_authority_descriptor(
    descriptor: &HistoryAuthorityDescriptor,
) -> Result<Vec<u8>, CityGError> {
    Ok(to_cbor_vec(&HistoryAuthorityDescriptorWire(
        descriptor.scope_id.to_vec(),
        descriptor.public_key.clone(),
    ))?)
}

fn history_authority_secret_key(
    state: &HistoryAuthorityState,
) -> Result<dilithium5::SecretKey, CityGError> {
    dilithium5::SecretKey::from_bytes(&state.secret_key)
        .map_err(|_| CityGError::InvalidInput("invalid history authority secret key"))
}

fn sign_history_authority_message(
    state: &HistoryAuthorityState,
    payload: &[u8],
) -> Result<Vec<u8>, CityGError> {
    let secret_key = history_authority_secret_key(state)?;
    Ok(dilithium5::detached_sign(payload, &secret_key)
        .as_bytes()
        .to_vec())
}

fn verify_history_authority_signature(
    descriptor: &HistoryAuthorityDescriptor,
    payload: &[u8],
    signature: &[u8],
) -> Result<(), CityGError> {
    let public_key = dilithium5::PublicKey::from_bytes(&descriptor.public_key)
        .map_err(|_| CityGError::InvalidInput("invalid history authority public key"))?;
    let signature = dilithium5::DetachedSignature::from_bytes(signature)
        .map_err(|_| CityGError::InvalidInput("invalid history authority signature"))?;
    dilithium5::verify_detached_signature(&signature, payload, &public_key)
        .map_err(|_| CityGError::InvalidInput("history authority signature verification failed"))
}

fn global_history_parent_attestation_id(
    scope_id: &[u8; 32],
    gid: &[u8; 32],
    prev_history_commitment_id: &[u8; 32],
) -> Result<[u8; 32], CityGError> {
    if *prev_history_commitment_id == [0u8; 32] {
        return Ok([0u8; 32]);
    }
    #[derive(Serialize)]
    struct Preimage<'a>(
        #[serde(with = "serde_bytes")] &'a [u8; 32],
        #[serde(with = "serde_bytes")] &'a [u8; 32],
        #[serde(with = "serde_bytes")] &'a [u8; 32],
    );
    h_l(
        "barrier/global-history/parent-attestation",
        &Preimage(scope_id, gid, prev_history_commitment_id),
    )
    .map_err(CityGError::from)
}

fn encode_global_history_attestation(
    state: &HistoryAuthorityState,
    gid: &[u8; 32],
    history_commitment: &HistoryCommitment,
    barrier_version: u64,
    kem_tree_hash_after: &[u8; 32],
) -> Result<Vec<u8>, CityGError> {
    let parent_attestation_id = global_history_parent_attestation_id(
        &state.descriptor.scope_id,
        gid,
        &history_commitment.prev_history_commitment_id,
    )?;
    let finality_kind = state.mode.finality_kind().to_string();
    let payload = to_cbor_vec(&GlobalHistoryAttestationSignedPayload(
        "cityg/global-history-attestation-v1",
        &state.descriptor.scope_id,
        gid,
        &history_commitment.history_view_id,
        &history_commitment.history_commitment_id,
        &history_commitment.prev_history_commitment_id,
        history_commitment.history_seq,
        barrier_version,
        kem_tree_hash_after,
        &parent_attestation_id,
        finality_kind.as_str(),
    ))?;
    let signature = sign_history_authority_message(state, payload.as_slice())?;
    Ok(to_cbor_vec(&GlobalHistoryAttestationWire(
        state.descriptor.scope_id.to_vec(),
        gid.to_vec(),
        history_commitment.history_view_id.to_vec(),
        history_commitment.history_commitment_id.to_vec(),
        history_commitment.prev_history_commitment_id.to_vec(),
        history_commitment.history_seq,
        barrier_version,
        kem_tree_hash_after.to_vec(),
        parent_attestation_id.to_vec(),
        finality_kind,
        signature,
    ))?)
}

#[cfg(test)]
type ParsedGlobalHistoryAttestation = (
    HistoryAuthorityDescriptor,
    [u8; 32],
    HistoryCommitment,
    u64,
    [u8; 32],
    [u8; 32],
    String,
    Vec<u8>,
);

#[cfg(test)]
fn parse_global_history_attestation(
    raw: &[u8],
) -> Result<ParsedGlobalHistoryAttestation, CityGError> {
    let GlobalHistoryAttestationWire(
        scope_id,
        gid,
        history_view_id,
        history_commitment_id,
        prev_history_commitment_id,
        history_seq,
        barrier_version,
        kem_tree_hash_after,
        parent_attestation_id,
        finality_kind,
        signature,
    ) = parse_deterministic_cbor::<GlobalHistoryAttestationWire>(raw)?;
    Ok((
        HistoryAuthorityDescriptor {
            scope_id: vec_to_32(scope_id)?,
            public_key: Vec::new(),
        },
        vec_to_32(gid)?,
        HistoryCommitment {
            history_view_id: vec_to_32(history_view_id)?,
            history_commitment_id: vec_to_32(history_commitment_id)?,
            prev_history_commitment_id: vec_to_32(prev_history_commitment_id)?,
            history_seq,
        },
        barrier_version,
        vec_to_32(kem_tree_hash_after)?,
        vec_to_32(parent_attestation_id)?,
        finality_kind,
        signature,
    ))
}

#[cfg(test)]
fn encode_full_verification_receipt(
    author_leaf_id: &[u8; 32],
    barrier_update_reason: u64,
    updater_leaf: u64,
    signature: Vec<u8>,
) -> Result<Vec<u8>, CityGError> {
    Ok(to_cbor_vec(&FullVerificationReceiptWire {
        author_leaf_id: author_leaf_id.to_vec(),
        barrier_update_reason,
        updater_leaf,
        signature,
    })?)
}

fn full_verification_receipt_payload(
    gid: &[u8; 32],
    author_leaf_id: &[u8; 32],
    barrier_update_reason: u64,
    updater_leaf: u64,
    barrier_history_commitment: &[u8],
    global_history_attestation: &[u8],
    barrier_update: &[u8],
) -> Result<Vec<u8>, CityGError> {
    to_cbor_vec(&FullVerificationReceiptSignedPayload {
        label: "cityg/full-verification-receipt-v1",
        gid,
        author_leaf_id,
        barrier_update_reason,
        updater_leaf,
        barrier_history_commitment,
        global_history_attestation,
        barrier_update,
    })
    .map_err(CityGError::from)
}

fn compute_full_verification_barrier_update_digest(
    barrier_update: &[u8],
) -> Result<[u8; 32], CityGError> {
    #[derive(Serialize)]
    struct Preimage<'a> {
        #[serde(with = "serde_bytes")]
        barrier_update: &'a [u8],
    }
    h_l(
        "cityg/full-verification-witness/barrier-update",
        &Preimage { barrier_update },
    )
    .map_err(CityGError::from)
}

fn compute_full_verification_joins_digest(
    prev_barrier_version: u64,
    records: &[BarrierJoinLeafRecord],
) -> Result<[u8; 32], CityGError> {
    #[derive(Serialize)]
    struct Preimage<'a> {
        prev_barrier_version: u64,
        records: &'a [BarrierJoinLeafRecord],
    }
    h_l(
        "cityg/full-verification-witness/joins",
        &Preimage {
            prev_barrier_version,
            records,
        },
    )
    .map_err(CityGError::from)
}

fn compute_full_verification_revoked_digest(
    revocation_roots_hash: &[u8; 32],
    leaf_indices: &[u32],
) -> Result<[u8; 32], CityGError> {
    #[derive(Serialize)]
    struct Preimage<'a> {
        #[serde(with = "serde_bytes")]
        revocation_roots_hash: &'a [u8; 32],
        leaf_indices: &'a [u32],
    }
    h_l(
        "cityg/full-verification-witness/revoked",
        &Preimage {
            revocation_roots_hash,
            leaf_indices,
        },
    )
    .map_err(CityGError::from)
}

fn compute_full_verification_deployment_profile_manifest_digest(
    deployment_profile_manifest: &[u8],
) -> Result<[u8; 32], CityGError> {
    #[derive(Serialize)]
    struct Preimage<'a> {
        #[serde(with = "serde_bytes")]
        deployment_profile_manifest: &'a [u8],
    }
    h_l(
        "cityg/full-verification-witness/deployment-profile-manifest",
        &Preimage {
            deployment_profile_manifest,
        },
    )
    .map_err(CityGError::from)
}

#[allow(clippy::too_many_arguments)]
fn encode_full_verification_witness(
    state: &HistoryAuthorityState,
    gid: &[u8; 32],
    history_commitment: &HistoryCommitment,
    barrier_version: u64,
    kem_tree_hash_after: &[u8; 32],
    author_leaf_id: &[u8; 32],
    barrier_update_reason: u64,
    updater_leaf: u64,
    barrier_update: &[u8],
    joins_prev_barrier_version: u64,
    join_records: &[BarrierJoinLeafRecord],
    revocation_roots_hash: &[u8; 32],
    revoked_leaf_indices: &[u32],
    deployment_profile_manifest: &[u8],
) -> Result<Vec<u8>, CityGError> {
    let barrier_update_digest = compute_full_verification_barrier_update_digest(barrier_update)?;
    let joins_digest =
        compute_full_verification_joins_digest(joins_prev_barrier_version, join_records)?;
    let revoked_digest =
        compute_full_verification_revoked_digest(revocation_roots_hash, revoked_leaf_indices)?;
    let deployment_profile_manifest_digest =
        compute_full_verification_deployment_profile_manifest_digest(deployment_profile_manifest)?;
    let payload = to_cbor_vec(&FullVerificationWitnessSignedPayload {
        label: "cityg/full-verification-witness-v1",
        scope_id: &state.descriptor.scope_id,
        history_authority_extension: state.mode.extension_id(),
        gid,
        history_view_id: &history_commitment.history_view_id,
        history_commitment_id: &history_commitment.history_commitment_id,
        prev_history_commitment_id: &history_commitment.prev_history_commitment_id,
        history_seq: history_commitment.history_seq,
        barrier_version,
        kem_tree_hash_after,
        author_leaf_id,
        barrier_update_reason,
        updater_leaf,
        barrier_update_digest: &barrier_update_digest,
        joins_digest: &joins_digest,
        revoked_digest: &revoked_digest,
        deployment_profile_manifest_digest: &deployment_profile_manifest_digest,
    })?;
    let signature = sign_history_authority_message(state, payload.as_slice())?;
    Ok(to_cbor_vec(&FullVerificationWitnessWire {
        scope_id: state.descriptor.scope_id.to_vec(),
        history_authority_extension: state.mode.extension_id().to_string(),
        gid: gid.to_vec(),
        history_view_id: history_commitment.history_view_id.to_vec(),
        history_commitment_id: history_commitment.history_commitment_id.to_vec(),
        prev_history_commitment_id: history_commitment.prev_history_commitment_id.to_vec(),
        history_seq: history_commitment.history_seq,
        barrier_version,
        kem_tree_hash_after: kem_tree_hash_after.to_vec(),
        author_leaf_id: author_leaf_id.to_vec(),
        barrier_update_reason,
        updater_leaf,
        barrier_update_digest: barrier_update_digest.to_vec(),
        joins_digest: joins_digest.to_vec(),
        revoked_digest: revoked_digest.to_vec(),
        deployment_profile_manifest_digest: deployment_profile_manifest_digest.to_vec(),
        signature,
    })?)
}

fn encode_join_provisioning_artifact(
    state: &HistoryAuthorityState,
    bundle: &JoinTicketBundle,
    profile_version: &str,
    artifacts: JoinProvisioningAuthorityArtifacts<'_>,
) -> Result<Vec<u8>, CityGError> {
    let payload = to_cbor_vec(&JoinProvisioningArtifactSignedPayload {
        label: "cityg/join-provisioning-artifact-v1",
        scope_id: &state.descriptor.scope_id,
        history_authority_extension: artifacts.history_authority_extension,
        gid: &bundle.gid,
        profile_version,
        leaf_id: &bundle.leaf_id,
        history_view_id: &bundle.current_history_commitment.history_view_id,
        history_commitment_id: &bundle.current_history_commitment.history_commitment_id,
        prev_history_commitment_id: &bundle.current_history_commitment.prev_history_commitment_id,
        history_seq: bundle.current_history_commitment.history_seq,
        barrier_version: bundle.barrier_version,
        cover_leaf_index: bundle.cover_leaf_index,
        n_max: bundle.n_max,
        max_barrier_update_bytes: bundle.max_barrier_update_bytes,
        kem_tree_hash_after: &bundle.kem_tree_hash_after,
        current_predecessor_kem_tree_hash_after: &bundle.current_predecessor_kem_tree_hash_after,
        join_finalize_auth_token: &bundle.join_finalize_auth_token,
        provisioning_nonce: &bundle.provisioning_nonce,
        provisioning_issued_at_ms: bundle.provisioning_issued_at_ms,
        provisioning_expires_at_ms: bundle.provisioning_expires_at_ms,
        fs_forward_leap_h: bundle.fs_forward_leap_policy.h,
        fs_forward_leap_checkpoint_interval: bundle.fs_forward_leap_policy.checkpoint_interval,
        fs_forward_leap_slack_anchor: bundle.fs_forward_leap_policy.slack_anchor,
        fs_forward_leap_slack_first_device: bundle.fs_forward_leap_policy.slack_first_device,
        fs_forward_leap_slack_device: bundle.fs_forward_leap_policy.slack_device,
        last_accepted_ec: bundle.last_accepted_ec,
        history_authority_descriptor: artifacts.history_authority_descriptor,
        current_global_history_attestation: artifacts.current_global_history_attestation,
        current_join_records_completeness_attestation: artifacts
            .current_join_records_completeness_attestation,
        current_revoked_leaf_indices_completeness_attestation: artifacts
            .current_revoked_leaf_indices_completeness_attestation,
        current_barrier_update: bundle.current_barrier_update.as_slice(),
        current_join_records: bundle.current_join_records.as_slice(),
        current_revoked_leaf_indices: bundle.current_revoked_leaf_indices.as_slice(),
    })?;
    let signature = sign_history_authority_message(state, payload.as_slice())?;
    Ok(to_cbor_vec(&JoinProvisioningArtifactWire {
        scope_id: state.descriptor.scope_id.to_vec(),
        history_authority_extension: artifacts.history_authority_extension.to_string(),
        gid: bundle.gid.to_vec(),
        profile_version: profile_version.to_string(),
        leaf_id: bundle.leaf_id.to_vec(),
        history_view_id: bundle.current_history_commitment.history_view_id.to_vec(),
        history_commitment_id: bundle
            .current_history_commitment
            .history_commitment_id
            .to_vec(),
        prev_history_commitment_id: bundle
            .current_history_commitment
            .prev_history_commitment_id
            .to_vec(),
        history_seq: bundle.current_history_commitment.history_seq,
        barrier_version: bundle.barrier_version,
        cover_leaf_index: bundle.cover_leaf_index,
        n_max: bundle.n_max,
        max_barrier_update_bytes: bundle.max_barrier_update_bytes,
        kem_tree_hash_after: bundle.kem_tree_hash_after.to_vec(),
        current_predecessor_kem_tree_hash_after: bundle
            .current_predecessor_kem_tree_hash_after
            .to_vec(),
        join_finalize_auth_token: bundle.join_finalize_auth_token.to_vec(),
        provisioning_nonce: bundle.provisioning_nonce.to_vec(),
        provisioning_issued_at_ms: bundle.provisioning_issued_at_ms,
        provisioning_expires_at_ms: bundle.provisioning_expires_at_ms,
        fs_forward_leap_h: bundle.fs_forward_leap_policy.h,
        fs_forward_leap_checkpoint_interval: bundle.fs_forward_leap_policy.checkpoint_interval,
        fs_forward_leap_slack_anchor: bundle.fs_forward_leap_policy.slack_anchor,
        fs_forward_leap_slack_first_device: bundle.fs_forward_leap_policy.slack_first_device,
        fs_forward_leap_slack_device: bundle.fs_forward_leap_policy.slack_device,
        last_accepted_ec: bundle.last_accepted_ec,
        signature,
    })?)
}

fn encode_merge_ticket_artifact(
    state: &HistoryAuthorityState,
    bundle: &MergeTicketBundle,
    profile_version: &str,
    history_authority_extension: &str,
    history_authority_descriptor: &[u8],
    current_global_history_attestation: &[u8],
    pivot_parity_cbor: &[Vec<u8>],
) -> Result<Vec<u8>, CityGError> {
    let payload = to_cbor_vec(&MergeTicketArtifactSignedPayload {
        label: "cityg/merge-ticket-artifact-v1",
        scope_id: &state.descriptor.scope_id,
        history_authority_extension,
        profile_version,
        gid: &bundle.gid,
        leaf_id: &bundle.leaf_id,
        history_view_id: &bundle.current_history_commitment.history_view_id,
        history_commitment_id: &bundle.current_history_commitment.history_commitment_id,
        prev_history_commitment_id: &bundle.current_history_commitment.prev_history_commitment_id,
        history_seq: bundle.current_history_commitment.history_seq,
        barrier_version: bundle.barrier_version,
        cover_leaf_index: bundle.cover_leaf_index,
        n_max: bundle.n_max,
        max_barrier_update_bytes: bundle.max_barrier_update_bytes,
        kem_tree_hash_after: &bundle.kem_tree_hash_after,
        fs_forward_leap_h: bundle.fs_forward_leap_policy.h,
        fs_forward_leap_checkpoint_interval: bundle.fs_forward_leap_policy.checkpoint_interval,
        fs_forward_leap_slack_anchor: bundle.fs_forward_leap_policy.slack_anchor,
        fs_forward_leap_slack_first_device: bundle.fs_forward_leap_policy.slack_first_device,
        fs_forward_leap_slack_device: bundle.fs_forward_leap_policy.slack_device,
        last_accepted_ec: bundle.last_accepted_ec,
        history_authority_descriptor,
        current_global_history_attestation,
        we_epoch_id: &bundle.pivot_we_epoch_id,
        pivot_parity_cbor,
        witness_cbor: bundle.witness_cbor.as_slice(),
        srx_cbor: bundle.srx_cbor.as_slice(),
        proof_mode: bundle.proof_mode.as_str(),
        vrf_id: bundle.vrf_id.as_str(),
        policy_version: bundle.policy_version.as_str(),
        cat: &bundle.cat,
        parent_root: &bundle.parent_root,
        join_delta_root: &bundle.join_delta_root,
        revoked_since_root: &bundle.revoked_since_root,
        revoked_root: &bundle.revoked_root,
        tswe_salt_hash: &bundle.tswe_salt_hash,
        pox_r_commit: &bundle.pox_r_commit,
        kbroad_public: bundle.kbroad_public.as_slice(),
        msphf_crs_id: bundle.msphf_crs_id.as_str(),
        msphf_params_id: bundle.msphf_params_id.as_str(),
        fs_policy_version: bundle.fs_policy_version.as_str(),
        fs_epoch_base_ts: bundle.fs_epoch_base_ts,
        kbroad_generation: bundle.kbroad_generation,
    })?;
    let signature = sign_history_authority_message(state, payload.as_slice())?;
    Ok(to_cbor_vec(&MergeTicketArtifactWire {
        scope_id: state.descriptor.scope_id.to_vec(),
        history_authority_extension: history_authority_extension.to_string(),
        profile_version: profile_version.to_string(),
        gid: bundle.gid.to_vec(),
        leaf_id: bundle.leaf_id.to_vec(),
        history_view_id: bundle.current_history_commitment.history_view_id.to_vec(),
        history_commitment_id: bundle
            .current_history_commitment
            .history_commitment_id
            .to_vec(),
        prev_history_commitment_id: bundle
            .current_history_commitment
            .prev_history_commitment_id
            .to_vec(),
        history_seq: bundle.current_history_commitment.history_seq,
        barrier_version: bundle.barrier_version,
        cover_leaf_index: bundle.cover_leaf_index,
        n_max: bundle.n_max,
        max_barrier_update_bytes: bundle.max_barrier_update_bytes,
        kem_tree_hash_after: bundle.kem_tree_hash_after.to_vec(),
        fs_forward_leap_h: bundle.fs_forward_leap_policy.h,
        fs_forward_leap_checkpoint_interval: bundle.fs_forward_leap_policy.checkpoint_interval,
        fs_forward_leap_slack_anchor: bundle.fs_forward_leap_policy.slack_anchor,
        fs_forward_leap_slack_first_device: bundle.fs_forward_leap_policy.slack_first_device,
        fs_forward_leap_slack_device: bundle.fs_forward_leap_policy.slack_device,
        last_accepted_ec: bundle.last_accepted_ec,
        history_authority_descriptor: history_authority_descriptor.to_vec(),
        current_global_history_attestation: current_global_history_attestation.to_vec(),
        we_epoch_id: bundle.pivot_we_epoch_id.to_vec(),
        pivot_parity_cbor: pivot_parity_cbor.to_vec(),
        witness_cbor: bundle.witness_cbor.clone(),
        srx_cbor: bundle.srx_cbor.clone(),
        proof_mode: bundle.proof_mode.clone(),
        vrf_id: bundle.vrf_id.clone(),
        policy_version: bundle.policy_version.clone(),
        cat: bundle.cat.to_vec(),
        parent_root: bundle.parent_root.to_vec(),
        join_delta_root: bundle.join_delta_root.to_vec(),
        revoked_since_root: bundle.revoked_since_root.to_vec(),
        revoked_root: bundle.revoked_root.to_vec(),
        tswe_salt_hash: bundle.tswe_salt_hash.to_vec(),
        pox_r_commit: bundle.pox_r_commit.to_vec(),
        kbroad_public: bundle.kbroad_public.clone(),
        msphf_crs_id: bundle.msphf_crs_id.clone(),
        msphf_params_id: bundle.msphf_params_id.clone(),
        fs_policy_version: bundle.fs_policy_version.clone(),
        fs_epoch_base_ts: bundle.fs_epoch_base_ts,
        kbroad_generation: bundle.kbroad_generation,
        signature,
    })?)
}

fn encode_deployment_profile_manifest(
    state: &HistoryAuthorityState,
    gid: &[u8; 32],
    profile_version: &str,
    history_authority_extension: &str,
    n_max: u64,
    max_barrier_update_bytes: u64,
    fs_forward_leap_policy: FsForwardLeapPolicy,
) -> Result<Vec<u8>, CityGError> {
    let payload = to_cbor_vec(&DeploymentProfileManifestSignedPayload {
        label: "cityg/deployment-profile-manifest-v1",
        scope_id: &state.descriptor.scope_id,
        history_authority_extension,
        gid,
        profile_version,
        n_max,
        max_barrier_update_bytes,
        fs_forward_leap_h: fs_forward_leap_policy.h,
        fs_forward_leap_checkpoint_interval: fs_forward_leap_policy.checkpoint_interval,
        fs_forward_leap_slack_anchor: fs_forward_leap_policy.slack_anchor,
        fs_forward_leap_slack_first_device: fs_forward_leap_policy.slack_first_device,
        fs_forward_leap_slack_device: fs_forward_leap_policy.slack_device,
    })?;
    let signature = sign_history_authority_message(state, payload.as_slice())?;
    Ok(to_cbor_vec(&DeploymentProfileManifestWire {
        scope_id: state.descriptor.scope_id.to_vec(),
        history_authority_extension: history_authority_extension.to_string(),
        gid: gid.to_vec(),
        profile_version: profile_version.to_string(),
        n_max,
        max_barrier_update_bytes,
        fs_forward_leap_h: fs_forward_leap_policy.h,
        fs_forward_leap_checkpoint_interval: fs_forward_leap_policy.checkpoint_interval,
        fs_forward_leap_slack_anchor: fs_forward_leap_policy.slack_anchor,
        fs_forward_leap_slack_first_device: fs_forward_leap_policy.slack_first_device,
        fs_forward_leap_slack_device: fs_forward_leap_policy.slack_device,
        signature,
    })?)
}

fn encode_helper_completeness_attestation_revoked(
    state: &HistoryAuthorityState,
    history_commitment: &HistoryCommitment,
    revocation_roots_hash: &[u8; 32],
    page_offset: u32,
    total_entries: u32,
    leaf_indices: &[u32],
) -> Result<Vec<u8>, CityGError> {
    let helper_kind = "resolve_revoked_leaves";
    let payload = to_cbor_vec(&HelperCompletenessSignedPayload {
        label: "cityg/helper-completeness-attestation-v1",
        scope_id: &state.descriptor.scope_id,
        helper_kind,
        history_view_id: &history_commitment.history_view_id,
        history_commitment_id: &history_commitment.history_commitment_id,
        page_offset,
        total_entries,
        selector: RevokedLeavesSelector {
            revocation_roots_hash,
            leaf_indices,
        },
    })?;
    let signature = sign_history_authority_message(state, payload.as_slice())?;
    Ok(to_cbor_vec(&HelperCompletenessAttestationWire(
        state.descriptor.scope_id.to_vec(),
        helper_kind.to_string(),
        signature,
    ))?)
}

fn encode_helper_completeness_attestation_joins(
    state: &HistoryAuthorityState,
    history_commitment: &HistoryCommitment,
    prev_barrier_version: u64,
    page_offset: u32,
    total_entries: u32,
    records: &[BarrierJoinLeafRecord],
) -> Result<Vec<u8>, CityGError> {
    let helper_kind = "resolve_joins_since";
    let payload = to_cbor_vec(&HelperCompletenessSignedPayload {
        label: "cityg/helper-completeness-attestation-v1",
        scope_id: &state.descriptor.scope_id,
        helper_kind,
        history_view_id: &history_commitment.history_view_id,
        history_commitment_id: &history_commitment.history_commitment_id,
        page_offset,
        total_entries,
        selector: JoinsSinceSelector {
            prev_barrier_version,
            records,
        },
    })?;
    let signature = sign_history_authority_message(state, payload.as_slice())?;
    Ok(to_cbor_vec(&HelperCompletenessAttestationWire(
        state.descriptor.scope_id.to_vec(),
        helper_kind.to_string(),
        signature,
    ))?)
}

fn encode_helper_completeness_attestation_tree(
    state: &HistoryAuthorityState,
    history_commitment: &HistoryCommitment,
    kem_tree_hash_after: &[u8; 32],
    entry_offset: u32,
    total_entries: u32,
    pk_entries: &[Vec<u8>],
) -> Result<Vec<u8>, CityGError> {
    let helper_kind = "fetch_public_tree";
    let payload = to_cbor_vec(&HelperCompletenessSignedPayload {
        label: "cityg/helper-completeness-attestation-v1",
        scope_id: &state.descriptor.scope_id,
        helper_kind,
        history_view_id: &history_commitment.history_view_id,
        history_commitment_id: &history_commitment.history_commitment_id,
        page_offset: entry_offset,
        total_entries,
        selector: FetchPublicTreeSelector {
            kem_tree_hash_after,
            pk_entries,
        },
    })?;
    let signature = sign_history_authority_message(state, payload.as_slice())?;
    Ok(to_cbor_vec(&HelperCompletenessAttestationWire(
        state.descriptor.scope_id.to_vec(),
        helper_kind.to_string(),
        signature,
    ))?)
}

#[derive(Serialize, Deserialize)]
struct BarrierHistoryCommitmentHeaderWire(
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    u64,
);

#[allow(dead_code)]
fn encode_barrier_history_commitment_header(
    commitment: HistoryCommitment,
) -> Result<Vec<u8>, CityGError> {
    Ok(to_cbor_vec(&BarrierHistoryCommitmentHeaderWire(
        commitment.history_view_id.to_vec(),
        commitment.history_commitment_id.to_vec(),
        commitment.prev_history_commitment_id.to_vec(),
        commitment.history_seq,
    ))?)
}

fn parse_barrier_history_commitment(
    header: &BTreeMap<u64, Value>,
) -> Result<Option<HistoryCommitment>, CityGError> {
    header_optional_bytes(header, hdr::HDR_BARRIER_HISTORY_COMMITMENT)?
        .map(parse_deterministic_cbor::<BarrierHistoryCommitmentHeaderWire>)
        .transpose()?
        .map(
            |BarrierHistoryCommitmentHeaderWire(
                history_view_id,
                history_commitment_id,
                prev_history_commitment_id,
                history_seq,
            )| {
                Ok(HistoryCommitment {
                    history_view_id: vec_to_32(history_view_id)?,
                    history_commitment_id: vec_to_32(history_commitment_id)?,
                    prev_history_commitment_id: vec_to_32(prev_history_commitment_id)?,
                    history_seq,
                })
            },
        )
        .transpose()
}

fn parse_barrier_update(
    header: &BTreeMap<u64, Value>,
    expected_n_max: u64,
) -> Result<Option<ParsedBarrierUpdate>, CityGError> {
    let Some(Value::Bytes(raw_update)) = header.get(&hdr::HDR_BARRIER_UPDATE) else {
        return Ok(None);
    };

    if expected_n_max == 0 || !expected_n_max.is_power_of_two() {
        return Err(CityGError::InvalidInput("barrier_update malformed"));
    }

    let BarrierUpdateWire(
        mode,
        _barrier_version,
        prev_barrier_version,
        tree_size,
        revocation_roots_hash,
        kem_tree_hash_before,
        kem_tree_hash_after,
        cover_payload,
    ) = parse_deterministic_cbor(raw_update.as_slice())?;

    if mode != "barrier-v1" || tree_size != expected_n_max {
        return Err(CityGError::InvalidInput("barrier_update malformed"));
    }

    let KemTreeCoverPayloadWire(
        updater_leaf,
        path_nodes,
        revoked_leaf_indices_hint,
        node_ciphertexts,
        new_public_keys,
    ) = parse_deterministic_cbor(cover_payload.as_slice())?;

    let max_index = expected_n_max
        .checked_mul(2)
        .and_then(|v| v.checked_sub(2))
        .ok_or(CityGError::InvalidInput("barrier_update malformed"))?;
    let leaf_base = expected_n_max.saturating_sub(1);

    if path_nodes.is_empty() || updater_leaf >= expected_n_max {
        return Err(CityGError::InvalidInput("barrier_update malformed"));
    }
    let expected_leaf = leaf_base
        .checked_add(updater_leaf)
        .ok_or(CityGError::InvalidInput("barrier_update malformed"))?;
    if path_nodes.first().copied() != Some(expected_leaf) || path_nodes.last().copied() != Some(0) {
        return Err(CityGError::InvalidInput("barrier_update malformed"));
    }
    let mut seen_path = BTreeSet::new();
    for node in &path_nodes {
        if *node > max_index || !seen_path.insert(*node) {
            return Err(CityGError::InvalidInput("barrier_update malformed"));
        }
    }
    for pair in path_nodes.windows(2) {
        let child = pair[0];
        let parent = pair[1];
        if child == 0 || (child - 1) / 2 != parent {
            return Err(CityGError::InvalidInput("barrier_update malformed"));
        }
    }
    if let Some(hint) = revoked_leaf_indices_hint {
        let mut prev: Option<u64> = None;
        for value in hint {
            if prev.is_some_and(|p| p >= value) {
                return Err(CityGError::InvalidInput("barrier_update malformed"));
            }
            prev = Some(value);
        }
    }

    let expected_set: BTreeSet<u64> = path_nodes.iter().copied().skip(1).collect();
    if new_public_keys.len() != expected_set.len() {
        return Err(CityGError::InvalidInput("barrier_update malformed"));
    }
    let mut prev_node: Option<u64> = None;
    let mut seen_keys = BTreeSet::new();
    let mut normalized_keys = Vec::with_capacity(new_public_keys.len());
    for NewPublicKeyWire(node, ek) in new_public_keys {
        if node > max_index || node >= leaf_base || ek.len() != 1184 {
            return Err(CityGError::InvalidInput("barrier_update malformed"));
        }
        if prev_node.is_some_and(|p| p >= node) || !seen_keys.insert(node) {
            return Err(CityGError::InvalidInput("barrier_update malformed"));
        }
        prev_node = Some(node);
        normalized_keys.push((node, ek));
    }
    if seen_keys != expected_set {
        return Err(CityGError::InvalidInput("barrier_update malformed"));
    }

    let mut prev_pair: Option<(u64, u64)> = None;
    let mut normalized_ciphertexts = Vec::with_capacity(node_ciphertexts.len());
    for NodeCiphertextWire(source, target, target_pk_hash, kem_ct, wrapped_ps) in node_ciphertexts {
        if source > max_index
            || target > max_index
            || target_pk_hash.len() != 16
            || kem_ct.len() != 1088
            || wrapped_ps.len() != 48
        {
            return Err(CityGError::InvalidInput("barrier_update malformed"));
        }
        let pair = (source, target);
        if prev_pair.is_some_and(|p| p >= pair) {
            return Err(CityGError::InvalidInput("barrier_update malformed"));
        }
        prev_pair = Some(pair);
        normalized_ciphertexts.push(ParsedNodeCiphertext {
            source_node: source,
            target_node: target,
            target_pk_hash: vec_to_16(target_pk_hash)?,
        });
    }

    Ok(Some(ParsedBarrierUpdate {
        prev_barrier_version,
        updater_leaf,
        tree_size,
        revocation_roots_hash: vec_to_32(revocation_roots_hash)?,
        kem_tree_hash_before: vec_to_32(kem_tree_hash_before)?,
        kem_tree_hash_after: vec_to_32(kem_tree_hash_after)?,
        path_nodes,
        node_ciphertexts: normalized_ciphertexts,
        new_public_keys: normalized_keys,
    }))
}

fn current_accepted_barrier_predecessor_hash(state: &GroupState) -> [u8; 32] {
    if !state.current_accepted_barrier_update.is_empty()
        && let Ok(BarrierUpdateWire(
            _mode,
            _barrier_version,
            _prev_barrier_version,
            _tree_size,
            _revocation_roots_hash,
            kem_tree_hash_before,
            _kem_tree_hash_after,
            _cover_payload,
        )) = parse_deterministic_cbor::<BarrierUpdateWire>(
            state.current_accepted_barrier_update.as_slice(),
        )
        && let Ok(hash) = kem_tree_hash_before.as_slice().try_into()
    {
        return hash;
    }
    state.current_accepted_barrier_predecessor_hash
}

fn barrier_runtime_matches_current_update(
    barrier_version: u64,
    barrier_roots_hash: &[u8; 32],
    kem_tree_hash_after: &[u8; 32],
    n_max: u64,
    current_accepted_barrier_update: &[u8],
) -> bool {
    if current_accepted_barrier_update.is_empty() {
        return barrier_version == 0;
    }
    let Ok(BarrierUpdateWire(
        _mode,
        update_barrier_version,
        _prev_barrier_version,
        tree_size,
        revocation_roots_hash,
        _kem_tree_hash_before,
        update_kem_tree_hash_after,
        _cover_payload,
    )) = parse_deterministic_cbor::<BarrierUpdateWire>(current_accepted_barrier_update)
    else {
        return false;
    };
    let Ok(update_revocation_roots_hash) = vec_to_32(revocation_roots_hash) else {
        return false;
    };
    let Ok(update_kem_tree_hash_after) = vec_to_32(update_kem_tree_hash_after) else {
        return false;
    };
    update_barrier_version == barrier_version
        && tree_size == n_max
        && update_revocation_roots_hash == *barrier_roots_hash
        && update_kem_tree_hash_after == *kem_tree_hash_after
}

fn build_pk_entries_view<'a>(state: &'a GroupState) -> Result<Cow<'a, [Vec<u8>]>, CityGError> {
    ensure_distinct_active_cover_leaf_indices(state)?;
    let (_, expected_len, _) = barrier_pk_entry_layout(state.n_max)?;
    if state.barrier_pk_entries.len() == expected_len {
        return Ok(Cow::Borrowed(state.barrier_pk_entries.as_slice()));
    }
    Ok(Cow::Owned(build_fallback_pk_entries(
        state,
        Vec::new(),
        |ek_leaf| ek_leaf.clone(),
    )?))
}

#[cfg(test)]
fn build_pk_entries(state: &GroupState) -> Result<Vec<Vec<u8>>, CityGError> {
    Ok(build_pk_entries_cow(state)?
        .into_iter()
        .map(|cow| cow.into_owned())
        .collect())
}

fn rebuild_barrier_public_tree_blob_index(state: &mut GroupState) -> Result<(), CityGError> {
    state.barrier_public_tree_blob_index.clear();
    for (index, blob) in state.barrier_public_tree_blobs.iter().enumerate() {
        let blob_index = u32::try_from(index)
            .map_err(|_| CityGError::InvalidInput("barrier public tree blob index overflow"))?;
        state
            .barrier_public_tree_blob_index
            .insert(blob.clone(), blob_index);
    }
    Ok(())
}

fn intern_barrier_public_tree_blob(
    state: &mut GroupState,
    entry: &[u8],
) -> Result<BarrierBlobIndex, CityGError> {
    if let Some(index) = state.barrier_public_tree_blob_index.get(entry) {
        return Ok(*index);
    }
    let index = u32::try_from(state.barrier_public_tree_blobs.len())
        .map_err(|_| CityGError::InvalidInput("barrier public tree blob index overflow"))?;
    let owned = entry.to_vec();
    state.barrier_public_tree_blobs.push(owned.clone());
    state.barrier_public_tree_blob_index.insert(owned, index);
    Ok(index)
}

fn encode_barrier_public_tree_snapshot_ref(
    state: &mut GroupState,
    pk_entries: &[Vec<u8>],
) -> Result<BarrierPublicTreeSnapshotRef, CityGError> {
    let mut blob_indices = Vec::with_capacity(pk_entries.len());
    for entry in pk_entries {
        blob_indices.push(intern_barrier_public_tree_blob(state, entry.as_slice())?);
    }
    Ok(BarrierPublicTreeSnapshotRef {
        blob_indices,
        barrier_version: 0,
        history_view_id: [0u8; 32],
        history_commitment: HistoryCommitment::default(),
    })
}

fn decode_barrier_public_tree_snapshot_ref(
    state: &GroupState,
    snapshot: &BarrierPublicTreeSnapshotRef,
) -> Result<Vec<Vec<u8>>, CityGError> {
    decode_barrier_public_tree_snapshot_ref_with_blobs(
        state.barrier_public_tree_blobs.as_slice(),
        snapshot,
    )
}

fn decode_barrier_public_tree_snapshot_ref_with_blobs(
    blobs: &[Vec<u8>],
    snapshot: &BarrierPublicTreeSnapshotRef,
) -> Result<Vec<Vec<u8>>, CityGError> {
    snapshot
        .blob_indices
        .iter()
        .map(|index| {
            let index = usize::try_from(*index)
                .map_err(|_| CityGError::InvalidInput("barrier public tree blob index overflow"))?;
            blobs
                .get(index)
                .cloned()
                .ok_or(CityGError::InvalidInput("barrier public tree blob missing"))
        })
        .collect()
}

#[cfg(test)]
fn history_barrier_public_tree_entries(
    state: &GroupState,
    kem_tree_hash_after: &[u8; 32],
) -> Option<Vec<Vec<u8>>> {
    state
        .barrier_public_tree_history
        .get(kem_tree_hash_after)
        .and_then(|snapshot| decode_barrier_public_tree_snapshot_ref(state, snapshot).ok())
}

fn record_barrier_public_tree_snapshot(
    gid: &[u8],
    state: &mut GroupState,
) -> Result<(), CityGError> {
    if state.barrier_pk_entries.is_empty() {
        return Ok(());
    }
    let current_entries = state.barrier_pk_entries.clone();
    let mut snapshot = encode_barrier_public_tree_snapshot_ref(state, current_entries.as_slice())?;
    snapshot.barrier_version = state.barrier_version;
    snapshot.history_commitment = ensure_current_history_commitment(gid, state)?;
    snapshot.history_view_id = snapshot.history_commitment.history_view_id;
    state
        .barrier_public_tree_history
        .insert(state.kem_tree_hash_after, snapshot);
    prune_barrier_public_tree_history(state)?;
    Ok(())
}

fn record_barrier_public_tree_snapshot_with_metadata(
    state: &mut GroupState,
    kem_tree_hash_after: [u8; 32],
    barrier_version: u64,
    history_commitment: HistoryCommitment,
    pk_entries: &[Vec<u8>],
) -> Result<(), CityGError> {
    if pk_entries.is_empty() {
        return Ok(());
    }
    if let Some(snapshot) = state
        .barrier_public_tree_history
        .get_mut(&kem_tree_hash_after)
    {
        snapshot.barrier_version = barrier_version;
        snapshot.history_commitment = history_commitment;
        snapshot.history_view_id = history_commitment.history_view_id;
        return Ok(());
    }
    let mut snapshot = encode_barrier_public_tree_snapshot_ref(state, pk_entries)?;
    snapshot.barrier_version = barrier_version;
    snapshot.history_commitment = history_commitment;
    snapshot.history_view_id = history_commitment.history_view_id;
    state
        .barrier_public_tree_history
        .insert(kem_tree_hash_after, snapshot);
    Ok(())
}

fn refresh_current_barrier_snapshot_commitments(
    state: &mut GroupState,
    history_commitment: HistoryCommitment,
) -> Result<(), CityGError> {
    if !state.barrier_pk_entries.is_empty() {
        let current_entries = build_pk_entries_view(state)?.into_owned();
        let current_hash =
            compute_barrier_tree_hash(state.n_max.max(1), current_entries.as_slice())?;
        record_barrier_public_tree_snapshot_with_metadata(
            state,
            current_hash,
            state.barrier_version,
            history_commitment,
            current_entries.as_slice(),
        )?;
    }

    let predecessor_hash = current_accepted_barrier_predecessor_hash(state);
    if predecessor_hash != [0u8; 32]
        && let Some(snapshot) = state.barrier_public_tree_history.get_mut(&predecessor_hash)
    {
        snapshot.barrier_version = state.barrier_version;
        snapshot.history_commitment = history_commitment;
        snapshot.history_view_id = history_commitment.history_view_id;
    }
    Ok(())
}

fn prune_join_history(state: &mut GroupState) -> Result<(), CityGError> {
    if state.join_history.is_empty() {
        return Ok(());
    }
    let n_max = validate_barrier_n_max(state.n_max)?;
    let max_records =
        usize::try_from(n_max).map_err(|_| CityGError::InvalidInput("barrier n_max too large"))?;
    let active_leaves: BTreeSet<[u8; 32]> = state
        .latest_snapshot()
        .map(|snapshot| snapshot.members().copied().collect())
        .unwrap_or_default();
    if active_leaves.is_empty() {
        state.join_history.clear();
        return Ok(());
    }
    let mut latest_by_leaf: BTreeMap<[u8; 32], JoinLeafHistoryRecord> = BTreeMap::new();
    for record in &state.join_history {
        if !active_leaves.contains(&record.leaf_id) {
            continue;
        }
        match latest_by_leaf.get_mut(&record.leaf_id) {
            Some(existing) if record.barrier_version >= existing.barrier_version => {
                *existing = record.clone();
            }
            None => {
                latest_by_leaf.insert(record.leaf_id, record.clone());
            }
            _ => {}
        }
    }
    if latest_by_leaf.len() > max_records {
        return Err(CityGError::InvalidInput(
            UNRESOLVED_JOIN_HISTORY_EXHAUSTED_ERR,
        ));
    }
    let mut pruned: Vec<JoinLeafHistoryRecord> = latest_by_leaf.into_values().collect();
    pruned.sort_by_key(|record| (record.leaf_index, record.barrier_version, record.leaf_id));
    state.join_history = pruned;
    Ok(())
}

fn prune_barrier_public_tree_history(state: &mut GroupState) -> Result<(), CityGError> {
    if state.barrier_public_tree_history.is_empty() {
        state.barrier_public_tree_blobs.clear();
        state.barrier_public_tree_blob_index.clear();
        return Ok(());
    }

    let current_hash = state.kem_tree_hash_after;
    let mut retained: Vec<([u8; 32], BarrierPublicTreeSnapshotRef)> = state
        .barrier_public_tree_history
        .iter()
        .map(|(hash, snapshot)| (*hash, snapshot.clone()))
        .collect();
    retained.sort_by(|(left_hash, left), (right_hash, right)| {
        (*right_hash == current_hash)
            .cmp(&(*left_hash == current_hash))
            .then_with(|| {
                right
                    .history_commitment
                    .history_seq
                    .cmp(&left.history_commitment.history_seq)
            })
            .then_with(|| right_hash.cmp(left_hash))
    });
    retained.truncate(MAX_RETAINED_BARRIER_PUBLIC_TREE_SNAPSHOTS);

    let old_blobs = state.barrier_public_tree_blobs.clone();
    state.barrier_public_tree_history.clear();
    state.barrier_public_tree_blobs.clear();
    state.barrier_public_tree_blob_index.clear();

    for (hash, snapshot) in retained {
        let pk_entries =
            decode_barrier_public_tree_snapshot_ref_with_blobs(old_blobs.as_slice(), &snapshot)?;
        let mut encoded = encode_barrier_public_tree_snapshot_ref(state, pk_entries.as_slice())?;
        encoded.history_view_id = snapshot.history_view_id;
        encoded.history_commitment = snapshot.history_commitment;
        state.barrier_public_tree_history.insert(hash, encoded);
    }
    Ok(())
}

#[cfg(test)]
fn compute_group_barrier_tree_hash(state: &GroupState) -> Result<[u8; 32], CityGError> {
    let n_max_usize = usize::try_from(state.n_max)
        .map_err(|_| CityGError::InvalidInput("barrier n_max too large"))?;
    let expected_len = n_max_usize
        .checked_mul(2)
        .and_then(|v| v.checked_sub(1))
        .ok_or(CityGError::InvalidInput("barrier tree size overflow"))?;

    if state.barrier_pk_entries.len() == expected_len {
        return compute_barrier_tree_hash(state.n_max, state.barrier_pk_entries.as_slice());
    }

    let pk_entries = build_pk_entries_view(state)?;
    compute_barrier_tree_hash(state.n_max, pk_entries.as_ref())
}

fn compute_barrier_tree_hash(
    n_max: u64,
    pk_entries: &[impl AsRef<[u8]>],
) -> Result<[u8; 32], CityGError> {
    let n_max_usize =
        usize::try_from(n_max).map_err(|_| CityGError::InvalidInput("barrier n_max too large"))?;
    let expected_len = n_max_usize
        .checked_mul(2)
        .and_then(|v| v.checked_sub(1))
        .ok_or(CityGError::InvalidInput("barrier tree size overflow"))?;
    if pk_entries.len() != expected_len {
        return Err(CityGError::InvalidInput("barrier tree size mismatch"));
    }
    compute_barrier_tree_hash_recursive(0, n_max, n_max_usize, pk_entries)
}

fn compute_barrier_tree_hash_recursive(
    node_index: usize,
    n_max: u64,
    n_max_usize: usize,
    pk_entries: &[impl AsRef<[u8]>],
) -> Result<[u8; 32], CityGError> {
    let leaf_base = n_max_usize.saturating_sub(1);
    let pk = pk_entries
        .get(node_index)
        .map(|v| v.as_ref())
        .ok_or(CityGError::InvalidInput("barrier node index out of range"))?;
    let node_u64 = node_index as u64;
    if node_index >= leaf_base {
        return h_l(
            "barrier/tree/leaf-hash",
            &BarrierTreeLeafHashArgs {
                n_max,
                node_index: node_u64,
                pk,
            },
        )
        .map_err(CityGError::from);
    }
    let left = node_index
        .checked_mul(2)
        .and_then(|v| v.checked_add(1))
        .ok_or(CityGError::InvalidInput("barrier tree index overflow"))?;
    let right = node_index
        .checked_mul(2)
        .and_then(|v| v.checked_add(2))
        .ok_or(CityGError::InvalidInput("barrier tree index overflow"))?;
    let left_hash = compute_barrier_tree_hash_recursive(left, n_max, n_max_usize, pk_entries)?;
    let right_hash = compute_barrier_tree_hash_recursive(right, n_max, n_max_usize, pk_entries)?;
    h_l(
        "barrier/tree/node-hash",
        &BarrierTreeNodeHashArgs {
            n_max,
            node_index: node_u64,
            pk,
            left_hash: &left_hash,
            right_hash: &right_hash,
        },
    )
    .map_err(CityGError::from)
}

fn compute_barrier_subtree_hash_cached(
    node_index: usize,
    n_max: u64,
    n_max_usize: usize,
    pk_entries: &[impl AsRef<[u8]>],
    base_cache: Option<&HashMap<usize, [u8; 32]>>,
    cache: &mut HashMap<usize, [u8; 32]>,
) -> Result<[u8; 32], CityGError> {
    if let Some(existing) = cache.get(&node_index) {
        return Ok(*existing);
    }
    if let Some(existing) = base_cache.and_then(|hashes| hashes.get(&node_index)) {
        return Ok(*existing);
    }
    let leaf_base = n_max_usize.saturating_sub(1);
    let pk = pk_entries
        .get(node_index)
        .map(|v| v.as_ref())
        .ok_or(CityGError::InvalidInput("barrier node index out of range"))?;
    let node_u64 = node_index as u64;
    let hash = if node_index >= leaf_base {
        h_l(
            "barrier/tree/leaf-hash",
            &BarrierTreeLeafHashArgs {
                n_max,
                node_index: node_u64,
                pk,
            },
        )
        .map_err(CityGError::from)?
    } else {
        let left = node_index
            .checked_mul(2)
            .and_then(|v| v.checked_add(1))
            .ok_or(CityGError::InvalidInput("barrier tree index overflow"))?;
        let right = node_index
            .checked_mul(2)
            .and_then(|v| v.checked_add(2))
            .ok_or(CityGError::InvalidInput("barrier tree index overflow"))?;
        let left_hash = compute_barrier_subtree_hash_cached(
            left,
            n_max,
            n_max_usize,
            pk_entries,
            base_cache,
            cache,
        )?;
        let right_hash = compute_barrier_subtree_hash_cached(
            right,
            n_max,
            n_max_usize,
            pk_entries,
            base_cache,
            cache,
        )?;
        h_l(
            "barrier/tree/node-hash",
            &BarrierTreeNodeHashArgs {
                n_max,
                node_index: node_u64,
                pk,
                left_hash: &left_hash,
                right_hash: &right_hash,
            },
        )
        .map_err(CityGError::from)?
    };
    cache.insert(node_index, hash);
    Ok(hash)
}

type BarrierHashCache = HashMap<usize, [u8; 32]>;
type BarrierTreeHashWithCache = ([u8; 32], BarrierHashCache);

struct BarrierHashAfterInput<'a, T: AsRef<[u8]>> {
    n_max: u64,
    n_max_usize: usize,
    updated_entries: &'a [T],
    impacted_nodes: &'a BTreeSet<usize>,
    base_before_cache: Option<&'a BarrierHashCache>,
}

fn compute_barrier_subtree_hash_after_changes<T: AsRef<[u8]>>(
    node_index: usize,
    input: &BarrierHashAfterInput<'_, T>,
    before_cache: &mut BarrierHashCache,
    after_cache: &mut BarrierHashCache,
) -> Result<[u8; 32], CityGError> {
    if let Some(existing) = after_cache.get(&node_index) {
        return Ok(*existing);
    }
    if !input.impacted_nodes.contains(&node_index) {
        return compute_barrier_subtree_hash_cached(
            node_index,
            input.n_max,
            input.n_max_usize,
            input.updated_entries,
            input.base_before_cache,
            before_cache,
        );
    }

    let leaf_base = input.n_max_usize.saturating_sub(1);
    let pk = input
        .updated_entries
        .get(node_index)
        .map(|v| v.as_ref())
        .ok_or(CityGError::InvalidInput("barrier node index out of range"))?;
    let node_u64 = node_index as u64;
    let hash = if node_index >= leaf_base {
        h_l(
            "barrier/tree/leaf-hash",
            &BarrierTreeLeafHashArgs {
                n_max: input.n_max,
                node_index: node_u64,
                pk,
            },
        )
        .map_err(CityGError::from)?
    } else {
        let left = node_index
            .checked_mul(2)
            .and_then(|v| v.checked_add(1))
            .ok_or(CityGError::InvalidInput("barrier tree index overflow"))?;
        let right = node_index
            .checked_mul(2)
            .and_then(|v| v.checked_add(2))
            .ok_or(CityGError::InvalidInput("barrier tree index overflow"))?;
        let left_hash =
            compute_barrier_subtree_hash_after_changes(left, input, before_cache, after_cache)?;
        let right_hash =
            compute_barrier_subtree_hash_after_changes(right, input, before_cache, after_cache)?;
        h_l(
            "barrier/tree/node-hash",
            &BarrierTreeNodeHashArgs {
                n_max: input.n_max,
                node_index: node_u64,
                pk,
                left_hash: &left_hash,
                right_hash: &right_hash,
            },
        )
        .map_err(CityGError::from)?
    };
    after_cache.insert(node_index, hash);
    Ok(hash)
}

fn compute_barrier_tree_hash_with_changes(
    n_max: u64,
    updated_entries: &[impl AsRef<[u8]>],
    changed_nodes: &BTreeSet<usize>,
    base_before_cache: Option<&BarrierHashCache>,
    before_cache: &mut BarrierHashCache,
) -> Result<BarrierTreeHashWithCache, CityGError> {
    let n_max_usize =
        usize::try_from(n_max).map_err(|_| CityGError::InvalidInput("barrier n_max too large"))?;
    let expected_len = n_max_usize
        .checked_mul(2)
        .and_then(|v| v.checked_sub(1))
        .ok_or(CityGError::InvalidInput("barrier tree size overflow"))?;
    if updated_entries.len() != expected_len {
        return Err(CityGError::InvalidInput("barrier tree size mismatch"));
    }
    if changed_nodes.is_empty() {
        return Ok((
            compute_barrier_tree_hash(n_max, updated_entries)?,
            HashMap::new(),
        ));
    }
    if changed_nodes.iter().any(|node| *node >= expected_len) {
        return Err(CityGError::InvalidInput("barrier node index out of range"));
    }

    let mut impacted_nodes = BTreeSet::new();
    for node in changed_nodes {
        let mut current = *node;
        loop {
            impacted_nodes.insert(current);
            if current == 0 {
                break;
            }
            current = (current - 1) / 2;
        }
    }

    let input = BarrierHashAfterInput {
        n_max,
        n_max_usize,
        updated_entries,
        impacted_nodes: &impacted_nodes,
        base_before_cache,
    };
    let mut after_cache = HashMap::new();
    let root =
        compute_barrier_subtree_hash_after_changes(0, &input, before_cache, &mut after_cache)?;
    Ok((root, after_cache))
}

fn compute_barrier_pkhash(ek: &[u8]) -> Result<[u8; 32], CityGError> {
    h_l("barrier/pk-hash", &BarrierPkHashArgs(ek)).map_err(CityGError::from)
}

fn direct_path_nodes(mut node: usize) -> Vec<usize> {
    let mut out = vec![node];
    while node > 0 {
        node = (node - 1) / 2;
        out.push(node);
    }
    out
}

fn sibling_node(node: usize) -> Option<usize> {
    if node == 0 {
        return None;
    }
    if node & 1 == 0 {
        Some(node.saturating_sub(1))
    } else {
        Some(node.saturating_add(1))
    }
}

fn collect_resolution_nodes(
    pk_entries: &[impl AsRef<[u8]>],
    node: usize,
    leaf_base: usize,
    out: &mut Vec<usize>,
) {
    if node >= pk_entries.len() {
        return;
    }
    if !pk_entries[node].as_ref().is_empty() {
        out.push(node);
        return;
    }
    if node >= leaf_base {
        return;
    }
    let left = node.saturating_mul(2).saturating_add(1);
    let right = node.saturating_mul(2).saturating_add(2);
    collect_resolution_nodes(pk_entries, left, leaf_base, out);
    collect_resolution_nodes(pk_entries, right, leaf_base, out);
}

fn collect_expected_pairs(
    pk_entries: &[impl AsRef<[u8]>],
    path_nodes: &[u64],
    n_max: u64,
) -> Result<Vec<(u64, u64)>, CityGError> {
    if path_nodes.len() < 2 {
        return Ok(Vec::new());
    }
    let leaf_base = usize::try_from(n_max.saturating_sub(1))
        .map_err(|_| CityGError::InvalidInput("barrier_update malformed"))?;
    let mut pairs = Vec::new();
    for index in 0..path_nodes.len().saturating_sub(1) {
        let child = usize::try_from(path_nodes[index])
            .map_err(|_| CityGError::InvalidInput("barrier_update malformed"))?;
        let source = path_nodes[index + 1];
        let Some(sibling) = sibling_node(child) else {
            return Err(CityGError::InvalidInput("barrier_update malformed"));
        };
        let mut targets = Vec::new();
        collect_resolution_nodes(pk_entries, sibling, leaf_base, &mut targets);
        targets.sort_unstable();
        for target in targets {
            pairs.push((
                source,
                u64::try_from(target)
                    .map_err(|_| CityGError::InvalidInput("barrier_update malformed"))?,
            ));
        }
    }
    pairs.sort_unstable();
    Ok(pairs)
}

fn compute_revocation_roots_hash(
    revoked_since_root: &[u8; 32],
    revoked_root: &[u8; 32],
) -> Result<[u8; 32], CityGError> {
    #[derive(Serialize)]
    struct Preimage<'a>(
        #[serde(with = "serde_bytes")] &'a [u8; 32],
        #[serde(with = "serde_bytes")] &'a [u8; 32],
    );
    h_l("barrier/roots", &Preimage(revoked_since_root, revoked_root)).map_err(CityGError::from)
}

fn barrier_pk_entry_layout(n_max: u64) -> Result<(usize, usize, usize), CityGError> {
    let n_max = validate_barrier_n_max(n_max)?;
    let n_max_usize = usize::try_from(n_max)
        .map_err(|_| CityGError::InvalidInput("barrier n_max does not fit usize"))?;
    let expected_len = n_max_usize.saturating_mul(2).saturating_sub(1);
    let leaf_base = n_max_usize.saturating_sub(1);
    Ok((n_max_usize, expected_len, leaf_base))
}

fn checked_insert_unique<K, V>(
    map: &mut BTreeMap<K, V>,
    key: K,
    value: V,
    error: &'static str,
) -> Result<(), CityGError>
where
    K: Ord + Copy,
    V: PartialEq,
{
    if let Some(existing) = map.get(&key) {
        if existing != &value {
            return Err(CityGError::InvalidInput(error));
        }
        return Ok(());
    }
    map.insert(key, value);
    Ok(())
}

fn active_cover_leaf_allocations(
    state: &GroupState,
) -> Result<BTreeMap<u32, [u8; 32]>, CityGError> {
    let mut by_index = BTreeMap::new();
    if let Some(snapshot) = state.latest_snapshot() {
        for leaf in snapshot.members() {
            let leaf_index = cover_leaf_index(leaf, state.n_max);
            checked_insert_unique(
                &mut by_index,
                leaf_index,
                *leaf,
                DUPLICATE_ACTIVE_COVER_LEAF_ALLOCATION_ERR,
            )?;
        }
    }
    Ok(by_index)
}

fn ensure_distinct_active_cover_leaf_indices(state: &GroupState) -> Result<(), CityGError> {
    let _ = active_cover_leaf_allocations(state)?;
    Ok(())
}

fn ensure_join_cover_leaf_indices_available(
    state: &GroupState,
    joined: &[[u8; 32]],
) -> Result<(), CityGError> {
    let mut reserved: BTreeSet<u32> = active_cover_leaf_allocations(state)?.into_keys().collect();
    for leaf in &state.revoked {
        reserved.insert(cover_leaf_index(leaf, state.n_max));
    }
    for leaf in joined {
        let leaf_index = cover_leaf_index(leaf, state.n_max);
        if !reserved.insert(leaf_index) {
            return Err(CityGError::InvalidInput(
                COVER_LEAF_INDEX_ALREADY_ALLOCATED_ERR,
            ));
        }
    }
    Ok(())
}

fn build_fallback_pk_entries<'a, T, F>(
    state: &'a GroupState,
    empty: T,
    leaf_entry: F,
) -> Result<Vec<T>, CityGError>
where
    T: Clone,
    F: Fn(&'a Vec<u8>) -> T,
{
    ensure_distinct_active_cover_leaf_indices(state)?;
    let (n_max, expected_len, leaf_base) = barrier_pk_entry_layout(state.n_max)?;
    let mut pk_entries = vec![empty; expected_len];
    if let Some(snapshot) = state.latest_snapshot() {
        for leaf in snapshot.members() {
            let index = cover_leaf_index(leaf, state.n_max) as usize;
            if index >= n_max {
                continue;
            }
            if let Some(ek_leaf) = state.leaf_barrier_public.get(leaf) {
                pk_entries[leaf_base + index] = leaf_entry(ek_leaf);
            }
        }
    }
    Ok(pk_entries)
}

fn build_all_blank_pk_entries(n_max: u64) -> Result<Vec<Vec<u8>>, CityGError> {
    build_blank_pk_entries(n_max, Vec::new())
}

fn build_blank_pk_entries<T: Clone>(n_max: u64, empty: T) -> Result<Vec<T>, CityGError> {
    let n_max_usize =
        usize::try_from(n_max).map_err(|_| CityGError::InvalidInput("barrier n_max too large"))?;
    let len = n_max_usize
        .checked_mul(2)
        .and_then(|v| v.checked_sub(1))
        .ok_or(CityGError::InvalidInput("barrier tree size overflow"))?;
    Ok(vec![empty; len])
}

fn barrier_update_malformed_freeze_error() -> CityGError {
    CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(
        msphf_orchestrator::FREEZE_BARRIER_UPDATE_MALFORMED,
    ))
}

fn map_barrier_update_validation_error(err: CityGError) -> CityGError {
    match err {
        CityGError::InvalidInput(_) => barrier_update_malformed_freeze_error(),
        other => other,
    }
}

fn persisted_barrier_public_tree_history(
    state: &GroupState,
) -> Vec<PersistedBarrierPublicTreeSnapshot> {
    state
        .barrier_public_tree_history
        .iter()
        .map(|(hash, snapshot)| PersistedBarrierPublicTreeSnapshot {
            kem_tree_hash_after_hex: hex::encode(hash),
            barrier_version: snapshot.barrier_version,
            history_view_id_hex: hex::encode(snapshot.history_view_id),
            history_commitment: persisted_history_commitment(snapshot.history_commitment),
            blob_indices: snapshot.blob_indices.clone(),
            pk_entries: Vec::new(),
        })
        .collect()
}

fn persisted_accepted_barrier_merges(
    state: &GroupState,
) -> Vec<PersistedAcceptedBarrierMergeRecord> {
    state
        .accepted_barrier_merges
        .values()
        .map(|record| PersistedAcceptedBarrierMergeRecord {
            barrier_version: record.barrier_version,
            fs_ec: record.fs_ec,
            reason: record.reason,
            digest_hex: hex::encode(record.digest),
            we_epoch_id_hex: hex::encode(record.we_epoch_id),
        })
        .collect()
}

fn decode_persisted_accepted_barrier_merges(
    records: &[PersistedAcceptedBarrierMergeRecord],
) -> BTreeMap<u64, AcceptedBarrierMergeRecord> {
    records
        .iter()
        .filter_map(|record| {
            let digest = hex::decode(&record.digest_hex)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())?;
            let we_epoch_id = hex::decode(&record.we_epoch_id_hex)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())?;
            Some((
                record.barrier_version,
                AcceptedBarrierMergeRecord {
                    barrier_version: record.barrier_version,
                    fs_ec: record.fs_ec,
                    reason: record.reason,
                    digest,
                    we_epoch_id,
                },
            ))
        })
        .collect()
}

fn persisted_join_finalize_auth(state: &GroupState) -> Vec<PersistedJoinFinalizeAuthRecord> {
    state
        .pending_join_finalize_auth
        .values()
        .map(|record| PersistedJoinFinalizeAuthRecord {
            leaf_id_hex: hex::encode(record.leaf_id),
            cover_leaf_index: record.cover_leaf_index,
            token_hex: hex::encode(record.token),
        })
        .collect()
}

fn decode_persisted_join_finalize_auth(
    records: &[PersistedJoinFinalizeAuthRecord],
) -> BTreeMap<[u8; 32], JoinFinalizeAuthRecord> {
    records
        .iter()
        .filter_map(|record| {
            let leaf_id = hex::decode(&record.leaf_id_hex)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())?;
            let token = hex::decode(&record.token_hex)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())?;
            Some((
                leaf_id,
                JoinFinalizeAuthRecord {
                    leaf_id,
                    cover_leaf_index: record.cover_leaf_index,
                    token,
                },
            ))
        })
        .collect()
}

fn persisted_kbroad_room_state(
    state: Option<&GroupState>,
    kbroad_public: Vec<u8>,
    kbroad_generation: u64,
    rotation_required: bool,
    device_chain_states: Vec<PersistedDeviceChainState>,
) -> PersistedKbroadRoomState {
    let mut room = PersistedKbroadRoomState {
        kbroad_public,
        kbroad_generation,
        rotation_required,
        room_admin_pop_keys: Vec::new(),
        room_admin_proof_replay_keys: Vec::new(),
        n_max: DEFAULT_BARRIER_N_MAX,
        pcs_refresh_min_delta_device_ec: default_pcs_refresh_min_delta_device_ec(),
        pcs_refresh_min_delta_group_ec: default_pcs_refresh_min_delta_group_ec(),
        pcs_refresh_slot_width_ec: default_pcs_refresh_slot_width_ec(),
        max_barrier_update_bytes: default_max_barrier_update_bytes(),
        device_chain_states,
        ..PersistedKbroadRoomState::default()
    };
    let mut compacted_state = state.cloned();
    if let Some(state) = compacted_state.as_mut() {
        let _ = prune_barrier_public_tree_history(state);
        room.room_admin_pop_keys = state.room_admin_pop_keys.iter().cloned().collect();
        room.room_admin_proof_replay_keys =
            state.room_admin_proof_replay_keys.iter().copied().collect();
        room.revoked_leaf_ids_hex = state.revoked.iter().map(hex::encode).collect();
        room.barrier_initialized = state.barrier_initialized;
        room.barrier_version = state.barrier_version;
        room.barrier_roots_hash = state.barrier_roots_hash;
        room.kem_tree_hash_after = state.kem_tree_hash_after;
        room.last_checkpoint_ec = state.last_checkpoint_ec;
        room.last_accepted_ec = state.last_accepted_ec;
        room.srx_root_sw = state.srx_root_sw;
        room.barrier_pk_entries = state.barrier_pk_entries.clone();
        room.barrier_public_tree_blobs = state.barrier_public_tree_blobs.clone();
        room.barrier_public_tree_history = persisted_barrier_public_tree_history(state);
        room.n_max = state.n_max.max(1);
        room.last_pcs_refresh_ec = state.last_pcs_refresh_ec;
        room.pcs_refresh_min_delta_device_ec = state.pcs_refresh_min_delta_device_ec.max(1);
        room.pcs_refresh_min_delta_group_ec = state.pcs_refresh_min_delta_group_ec.max(1);
        room.pcs_refresh_slot_width_ec = state.pcs_refresh_slot_width_ec.max(1);
        room.max_barrier_update_bytes =
            u64::try_from(state.max_barrier_update_bytes).unwrap_or(u64::MAX);
        room.accepted_barrier_merges = persisted_accepted_barrier_merges(state);
        room.current_history_commitment =
            persisted_history_commitment(state.current_history_commitment);
        room.current_accepted_barrier_update = state.current_accepted_barrier_update.clone();
        room.current_accepted_barrier_predecessor_hash =
            state.current_accepted_barrier_predecessor_hash;
        room.pending_join_finalize_auth = persisted_join_finalize_auth(state);
    }
    room
}

fn merge_optional_u64_max(current: Option<u64>, persisted: Option<u64>) -> Option<u64> {
    match (current, persisted) {
        (Some(lhs), Some(rhs)) => Some(lhs.max(rhs)),
        (Some(lhs), None) => Some(lhs),
        (None, Some(rhs)) => Some(rhs),
        (None, None) => None,
    }
}

fn fresh_kbroad_public() -> Vec<u8> {
    let (public, _) = kyber768::keypair();
    public.as_bytes().to_vec()
}

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn fresh_join_finalize_auth_token() -> [u8; 32] {
    let mut token = [0u8; 32];
    rand::rng().fill(&mut token);
    token
}

fn fresh_join_provisioning_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rand::rng().fill(&mut nonce);
    nonce
}

fn clear_barrier_path<T>(
    pk_entries: &mut [T],
    leaf_node: usize,
    include_leaf: bool,
    mut clear_slot: impl FnMut(&mut T),
) {
    for (offset, node) in direct_path_nodes(leaf_node).into_iter().enumerate() {
        if !include_leaf && offset == 0 {
            continue;
        }
        if let Some(slot) = pk_entries.get_mut(node) {
            clear_slot(slot);
        }
    }
}

fn blank_internal_path_from_leaf_cow(pk_entries: &mut [Cow<'_, [u8]>], leaf_node: usize) {
    clear_barrier_path(pk_entries, leaf_node, false, |slot| {
        *slot = Cow::Borrowed(b"");
    });
}

fn blank_leaf_and_path_cow(pk_entries: &mut [Cow<'_, [u8]>], leaf_node: usize) {
    clear_barrier_path(pk_entries, leaf_node, true, |slot| {
        *slot = Cow::Borrowed(b"");
    });
}

fn build_all_blank_pk_entries_cow(n_max: u64) -> Result<Vec<Cow<'static, [u8]>>, CityGError> {
    build_blank_pk_entries(n_max, Cow::Borrowed(b""))
}

fn build_pk_entries_cow<'a>(state: &'a GroupState) -> Result<Vec<Cow<'a, [u8]>>, CityGError> {
    ensure_distinct_active_cover_leaf_indices(state)?;
    let (_, expected_len, _) = barrier_pk_entry_layout(state.n_max)?;
    if state.barrier_pk_entries.len() == expected_len {
        return Ok(state
            .barrier_pk_entries
            .iter()
            .map(|v| Cow::Borrowed(v.as_slice()))
            .collect());
    }
    build_fallback_pk_entries(state, Cow::Borrowed(b""), |ek_leaf| {
        Cow::Borrowed(ek_leaf.as_slice())
    })
}

fn verify_barrier_update_pairs_and_targets(
    snapshot_base: &[impl AsRef<[u8]>],
    parsed: &ParsedBarrierUpdate,
    tree_n_max: u64,
) -> Result<(), CityGError> {
    let expected_pairs =
        collect_expected_pairs(snapshot_base, parsed.path_nodes.as_slice(), tree_n_max)?;
    let actual_pairs: Vec<(u64, u64)> = parsed
        .node_ciphertexts
        .iter()
        .map(|node| (node.source_node, node.target_node))
        .collect();
    if actual_pairs != expected_pairs {
        return Err(CityGError::Acceptance(
            msphf_orchestrator::AcceptanceError::Freeze(
                msphf_orchestrator::FREEZE_BARRIER_EXPECTEDPAIRS_FAILURE,
            ),
        ));
    }
    for node in &parsed.node_ciphertexts {
        let target_index = usize::try_from(node.target_node)
            .map_err(|_| CityGError::InvalidInput("barrier_update malformed"))?;
        let target_pk = snapshot_base
            .get(target_index)
            .ok_or(CityGError::InvalidInput("barrier_update malformed"))?;
        let target_pkhash = compute_barrier_pkhash(target_pk.as_ref())?;
        if node.target_pk_hash.as_slice() != &target_pkhash[..16] {
            return Err(CityGError::Acceptance(
                msphf_orchestrator::AcceptanceError::Freeze(
                    msphf_orchestrator::FREEZE_BARRIER_EXPECTEDPAIRS_FAILURE,
                ),
            ));
        }
    }
    Ok(())
}

fn rehydrate_replay_join_finalize_auth(
    state_before: &mut GroupState,
    header: &BTreeMap<u64, Value>,
) -> Result<(), CityGError> {
    if !matches!(parse_barrier_update_reason(header)?, Some(2)) {
        return Ok(());
    }
    let Some(token) = parse_join_finalize_auth_token(header)? else {
        return Ok(());
    };
    let Some(parsed) = parse_barrier_update(header, state_before.n_max)? else {
        return Ok(());
    };
    let Some(author_pop_pk) = header.get(&hdr::HDR_POP_PK).and_then(Value::as_bytes) else {
        return Ok(());
    };
    let mut matching_leafs = state_before
        .leaf_device_pk
        .iter()
        .filter(|(_, device_pk)| device_pk.as_slice() == author_pop_pk)
        .map(|(leaf_id, _)| *leaf_id);
    let Some(author_leaf_id) = matching_leafs.next() else {
        return Ok(());
    };
    if matching_leafs.next().is_some() {
        return Ok(());
    }
    let expected_cover_leaf_index =
        u64::from(cover_leaf_index(&author_leaf_id, state_before.n_max));
    if expected_cover_leaf_index != parsed.updater_leaf {
        return Ok(());
    }
    let cover_leaf_index = u32::try_from(expected_cover_leaf_index)
        .map_err(|_| CityGError::InvalidInput("barrier_update malformed"))?;
    // Journal replay does not reconstruct server-issued join-ticket side effects.
    // Rehydrate the accepted join_finalize capability from the already-admitted
    // author binding so historical reason-2 merges validate exactly once on replay.
    state_before
        .pending_join_finalize_auth
        .entry(author_leaf_id)
        .or_insert(JoinFinalizeAuthRecord {
            leaf_id: author_leaf_id,
            cover_leaf_index,
            token,
        });
    Ok(())
}

fn freeze_barrier_updater_invalid_error() -> CityGError {
    CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(
        msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID,
    ))
}

fn parse_full_verification_receipt(
    raw: &[u8],
) -> Result<([u8; 32], u64, u64, Vec<u8>), CityGError> {
    let decoded = parse_deterministic_cbor::<FullVerificationReceiptWire>(raw)?;
    Ok((
        vec_to_32(decoded.author_leaf_id)?,
        decoded.barrier_update_reason,
        decoded.updater_leaf,
        decoded.signature,
    ))
}

fn parse_full_verification_witness(raw: &[u8]) -> Result<FullVerificationWitnessWire, CityGError> {
    parse_deterministic_cbor::<FullVerificationWitnessWire>(raw)
}

fn unique_author_leaf_for_pop_pk(
    state_before: &GroupState,
    author_pop_pk: &[u8],
) -> Result<[u8; 32], CityGError> {
    let mut matching_leafs = state_before
        .leaf_device_pk
        .iter()
        .filter(|(_, device_pk)| device_pk.as_slice() == author_pop_pk)
        .map(|(leaf_id, _)| *leaf_id);
    let Some(author_leaf_id) = matching_leafs.next() else {
        return Err(freeze_barrier_updater_invalid_error());
    };
    if matching_leafs.next().is_some() {
        return Err(freeze_barrier_updater_invalid_error());
    }
    Ok(author_leaf_id)
}

fn validate_history_authority_headers(
    history_authority: Option<&HistoryAuthorityState>,
    gid: &[u8; 32],
    state_before: &GroupState,
    header: &BTreeMap<u64, Value>,
) -> Result<(), CityGError> {
    let barrier_reason = parse_barrier_update_reason(header)?;
    let has_receipt = header.contains_key(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT);
    let has_attestation = header.contains_key(&hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION);
    let has_witness = header.contains_key(&hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS);
    if barrier_reason.is_none() {
        if has_receipt || has_attestation || has_witness {
            return Err(CityGError::InvalidInput("barrier_update malformed"));
        }
        return Ok(());
    }

    let Some(authority) = history_authority else {
        if has_receipt || has_attestation || has_witness {
            return Err(CityGError::InvalidInput("barrier_update malformed"));
        }
        return Ok(());
    };

    let raw_attestation = match header.get(&hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION) {
        Some(Value::Bytes(raw)) => raw.as_slice(),
        Some(_) => return Err(CityGError::InvalidInput("barrier_update malformed")),
        None => return Err(CityGError::InvalidInput("barrier_update malformed")),
    };
    let expected_attestation = encode_global_history_attestation(
        authority,
        gid,
        &state_before.current_history_commitment,
        state_before.barrier_version,
        &state_before.kem_tree_hash_after,
    )?;
    if raw_attestation != expected_attestation.as_slice() {
        return Err(CityGError::Acceptance(
            msphf_orchestrator::AcceptanceError::Freeze(
                msphf_orchestrator::FREEZE_BARRIER_TREE_SNAPSHOT_AUTH_FAILURE,
            ),
        ));
    }

    let Some(Value::Bytes(raw_history_commitment)) =
        header.get(&hdr::HDR_BARRIER_HISTORY_COMMITMENT)
    else {
        return Err(CityGError::InvalidInput("barrier_update malformed"));
    };
    let Some(Value::Bytes(raw_barrier_update)) = header.get(&hdr::HDR_BARRIER_UPDATE) else {
        return Err(CityGError::InvalidInput("barrier_update malformed"));
    };
    let Some(author_pop_pk) = header.get(&hdr::HDR_POP_PK).and_then(Value::as_bytes) else {
        return Err(freeze_barrier_updater_invalid_error());
    };
    let author_leaf_id = unique_author_leaf_for_pop_pk(state_before, author_pop_pk)?;

    let parsed = parse_barrier_update(header, state_before.n_max)?
        .ok_or(CityGError::InvalidInput("barrier_update malformed"))?;
    let barrier_reason =
        barrier_reason.ok_or(CityGError::InvalidInput("barrier_update malformed"))?;

    let raw_receipt = match header.get(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT) {
        Some(Value::Bytes(raw)) => Some(raw.as_slice()),
        Some(_) => return Err(CityGError::InvalidInput("barrier_update malformed")),
        None => None,
    };
    let raw_witness = match header.get(&hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS) {
        Some(Value::Bytes(raw)) => Some(raw.as_slice()),
        Some(_) => return Err(CityGError::InvalidInput("barrier_update malformed")),
        None => None,
    };
    if authority.require_full_verification_receipt && raw_receipt.is_none() {
        return Err(freeze_barrier_updater_invalid_error());
    }
    if has_witness && barrier_reason != 0 && barrier_reason != 1 {
        return Err(CityGError::InvalidInput("barrier_update malformed"));
    }
    if authority.mode.requires_full_verification_witness()
        && (barrier_reason == 0 || barrier_reason == 1)
        && raw_witness.is_none()
    {
        return Err(freeze_barrier_updater_invalid_error());
    }
    if let Some(raw_receipt) = raw_receipt {
        let (receipt_author_leaf_id, receipt_reason, receipt_updater_leaf, signature) =
            parse_full_verification_receipt(raw_receipt)?;
        if receipt_author_leaf_id != author_leaf_id
            || receipt_reason != barrier_reason
            || receipt_updater_leaf != parsed.updater_leaf
        {
            return Err(freeze_barrier_updater_invalid_error());
        }
        let payload = full_verification_receipt_payload(
            gid,
            &author_leaf_id,
            barrier_reason,
            parsed.updater_leaf,
            raw_history_commitment,
            raw_attestation,
            raw_barrier_update,
        )?;
        let author_pop_pk = dilithium5::PublicKey::from_bytes(author_pop_pk)
            .map_err(|_| freeze_barrier_updater_invalid_error())?;
        let signature = dilithium5::DetachedSignature::from_bytes(signature.as_slice())
            .map_err(|_| freeze_barrier_updater_invalid_error())?;
        dilithium5::verify_detached_signature(&signature, payload.as_slice(), &author_pop_pk)
            .map_err(|_| freeze_barrier_updater_invalid_error())?;
    }
    if let Some(raw_witness) = raw_witness {
        let witness = parse_full_verification_witness(raw_witness)?;
        let witness_scope_id = vec_to_32(witness.scope_id.clone())?;
        let witness_gid = vec_to_32(witness.gid.clone())?;
        let witness_history_view_id = vec_to_32(witness.history_view_id.clone())?;
        let witness_history_commitment_id = vec_to_32(witness.history_commitment_id.clone())?;
        let witness_prev_history_commitment_id =
            vec_to_32(witness.prev_history_commitment_id.clone())?;
        let witness_kem_tree_hash_after = vec_to_32(witness.kem_tree_hash_after.clone())?;
        let witness_author_leaf_id = vec_to_32(witness.author_leaf_id.clone())?;
        let witness_barrier_update_digest = vec_to_32(witness.barrier_update_digest.clone())?;
        let witness_joins_digest = vec_to_32(witness.joins_digest.clone())?;
        let witness_revoked_digest = vec_to_32(witness.revoked_digest.clone())?;
        let witness_manifest_digest =
            vec_to_32(witness.deployment_profile_manifest_digest.clone())?;
        let barrier_update_digest =
            compute_full_verification_barrier_update_digest(raw_barrier_update)?;
        if witness_scope_id != authority.descriptor.scope_id
            || witness.history_authority_extension != authority.mode.extension_id()
            || witness_gid != *gid
            || witness_history_view_id != state_before.current_history_commitment.history_view_id
            || witness_history_commitment_id
                != state_before
                    .current_history_commitment
                    .history_commitment_id
            || witness_prev_history_commitment_id
                != state_before
                    .current_history_commitment
                    .prev_history_commitment_id
            || witness.history_seq != state_before.current_history_commitment.history_seq
            || witness.barrier_version != state_before.barrier_version
            || witness_kem_tree_hash_after != state_before.kem_tree_hash_after
            || witness_author_leaf_id != author_leaf_id
            || witness.barrier_update_reason != barrier_reason
            || witness.updater_leaf != parsed.updater_leaf
            || witness_barrier_update_digest != barrier_update_digest
        {
            return Err(freeze_barrier_updater_invalid_error());
        }
        let payload = to_cbor_vec(&FullVerificationWitnessSignedPayload {
            label: "cityg/full-verification-witness-v1",
            scope_id: &authority.descriptor.scope_id,
            history_authority_extension: authority.mode.extension_id(),
            gid,
            history_view_id: &state_before.current_history_commitment.history_view_id,
            history_commitment_id: &state_before
                .current_history_commitment
                .history_commitment_id,
            prev_history_commitment_id: &state_before
                .current_history_commitment
                .prev_history_commitment_id,
            history_seq: state_before.current_history_commitment.history_seq,
            barrier_version: state_before.barrier_version,
            kem_tree_hash_after: &state_before.kem_tree_hash_after,
            author_leaf_id: &author_leaf_id,
            barrier_update_reason: barrier_reason,
            updater_leaf: parsed.updater_leaf,
            barrier_update_digest: &barrier_update_digest,
            joins_digest: &witness_joins_digest,
            revoked_digest: &witness_revoked_digest,
            deployment_profile_manifest_digest: &witness_manifest_digest,
        })?;
        verify_history_authority_signature(
            &authority.descriptor,
            payload.as_slice(),
            witness.signature.as_slice(),
        )
        .map_err(|_| freeze_barrier_updater_invalid_error())?;
    }

    Ok(())
}

fn validate_barrier_update_against_roster(
    state_before: &GroupState,
    header: &BTreeMap<u64, Value>,
    delta: &MembershipDelta,
) -> Result<Option<BarrierUpdateValidationOutcome>, CityGError> {
    let validation = (|| -> Result<Option<BarrierUpdateValidationOutcome>, CityGError> {
        if let Some(Value::Bytes(raw_update)) = header.get(&hdr::HDR_BARRIER_UPDATE)
            && raw_update.len() > state_before.max_barrier_update_bytes
        {
            return Err(barrier_update_malformed_freeze_error());
        }

        let barrier_update_reason = parse_barrier_update_reason(header)?;
        let history_commitment_present = header.contains_key(&hdr::HDR_BARRIER_HISTORY_COMMITMENT);
        let supplied_history_commitment = parse_barrier_history_commitment(header)?;
        if barrier_update_reason.is_none() {
            if history_commitment_present {
                return Err(CityGError::InvalidInput("barrier_update malformed"));
            }
            return Ok(None);
        }
        let Some(parsed) = parse_barrier_update(header, state_before.n_max)? else {
            return Ok(None);
        };
        let expected_history_commitment = state_before.current_history_commitment;
        let require_history_commitment = expected_history_commitment.history_view_id != [0u8; 32]
            && expected_history_commitment.history_commitment_id != [0u8; 32];
        if require_history_commitment {
            let supplied = supplied_history_commitment
                .ok_or(CityGError::InvalidInput("barrier_update malformed"))?;
            if supplied != expected_history_commitment {
                return Err(CityGError::Acceptance(
                    msphf_orchestrator::AcceptanceError::Freeze(
                        msphf_orchestrator::FREEZE_BARRIER_TREE_SNAPSHOT_AUTH_FAILURE,
                    ),
                ));
            }
        }
        ensure_distinct_active_cover_leaf_indices(state_before)?;
        ensure_join_cover_leaf_indices_available(state_before, delta.joined.as_slice())?;
        let active_leaves: BTreeSet<[u8; 32]> = state_before
            .latest_snapshot()
            .map(|snapshot| snapshot.members().copied().collect())
            .unwrap_or_default();

        let tree_n_max = state_before.n_max.max(1);
        let leaf_base = usize::try_from(tree_n_max.saturating_sub(1))
            .map_err(|_| CityGError::InvalidInput("barrier_update malformed"))?;

        // JoinSet: all joins activated after prev_barrier_version plus joins in current delta.
        let mut by_leaf: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        if parsed.prev_barrier_version == 0 && state_before.barrier_version == 0 {
            let snapshot = require_genesis_provisioning_snapshot(
                state_before,
                barrier_genesis_required_freeze_error,
            )?;
            for leaf in snapshot.members() {
                let leaf_index = cover_leaf_index(leaf, tree_n_max);
                let ek_leaf = state_before
                    .leaf_barrier_public
                    .get(leaf)
                    .cloned()
                    .unwrap_or_default();
                checked_insert_unique(
                    &mut by_leaf,
                    leaf_index,
                    ek_leaf,
                    DUPLICATE_ACTIVE_COVER_LEAF_ALLOCATION_ERR,
                )?;
            }
        } else {
            for record in &state_before.join_history {
                if record.barrier_version > parsed.prev_barrier_version
                    && active_leaves.contains(&record.leaf_id)
                {
                    checked_insert_unique(
                        &mut by_leaf,
                        record.leaf_index,
                        record.ek_leaf.clone(),
                        DUPLICATE_ACTIVE_COVER_LEAF_ALLOCATION_ERR,
                    )?;
                }
            }
        }
        let join_ek = header
            .get(&hdr::HDR_BARRIER_LEAF_PK)
            .and_then(Value::as_bytes)
            .map(ToOwned::to_owned)
            .unwrap_or_default();
        for leaf in &delta.joined {
            let leaf_index = cover_leaf_index(leaf, tree_n_max);
            checked_insert_unique(
                &mut by_leaf,
                leaf_index,
                join_ek.clone(),
                DUPLICATE_ACTIVE_COVER_LEAF_ALLOCATION_ERR,
            )?;
        }

        // RevokedLeafSet for snapshot construction: committed revoked set plus current delta.
        let mut revoked_set = state_before.revoked.clone();
        for leaf in &delta.revoked {
            revoked_set.insert(*leaf);
        }
        let mut revoked_indices = BTreeSet::new();
        for leaf in revoked_set {
            revoked_indices.insert(cover_leaf_index(&leaf, tree_n_max) as usize);
        }

        let expected_len = usize::try_from(tree_n_max)
            .map_err(|_| CityGError::InvalidInput("barrier_update malformed"))?
            .checked_mul(2)
            .and_then(|v| v.checked_sub(1))
            .ok_or(CityGError::InvalidInput("barrier_update malformed"))?;
        let can_borrow_snapshot_base = state_before.barrier_initialized
            && state_before.barrier_pk_entries.len() == expected_len
            && by_leaf.is_empty()
            && revoked_indices.is_empty();

        let unresolved_join_leaf_set: BTreeSet<u32> = by_leaf.keys().copied().collect();
        let snapshot_base_owned = if can_borrow_snapshot_base {
            None
        } else {
            let mut snapshot_base = if state_before.barrier_initialized {
                build_pk_entries_cow(state_before)?
            } else {
                build_all_blank_pk_entries_cow(tree_n_max)?
            };
            for (leaf_index, ek_leaf) in by_leaf {
                let leaf_node = leaf_base.saturating_add(leaf_index as usize);
                if let Some(slot) = snapshot_base.get_mut(leaf_node) {
                    *slot = Cow::Owned(ek_leaf);
                }
                blank_internal_path_from_leaf_cow(&mut snapshot_base, leaf_node);
            }
            for revoked_index in &revoked_indices {
                let leaf_node = leaf_base.saturating_add(*revoked_index);
                blank_leaf_and_path_cow(&mut snapshot_base, leaf_node);
            }
            Some(snapshot_base)
        };

        // Updater cannot be a previously revoked member; allow self-revocation merges.
        let mut committed_revoked_indices = BTreeSet::new();
        for leaf in &state_before.revoked {
            committed_revoked_indices.insert(cover_leaf_index(leaf, tree_n_max) as usize);
        }

        let author_pop_pk = header
            .get(&hdr::HDR_POP_PK)
            .and_then(Value::as_bytes)
            .ok_or({
                CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(
                    msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID,
                ))
            })?;
        let mut author_cover_indices = BTreeSet::new();
        let mut author_leaf_ids = Vec::new();
        for (leaf, device_pk) in &state_before.leaf_device_pk {
            if device_pk.as_slice() == author_pop_pk {
                author_cover_indices.insert(u64::from(cover_leaf_index(leaf, tree_n_max)));
                author_leaf_ids.push(*leaf);
            }
        }
        let parsed_updater_leaf_usize = usize::try_from(parsed.updater_leaf)
            .map_err(|_| CityGError::InvalidInput("barrier_update malformed"))?;
        let has_full_verification_witness =
            header.contains_key(&hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS);
        let author_is_room_admin = state_before
            .room_admin_pop_keys
            .iter()
            .any(|pop_key| pop_key.as_slice() == author_pop_pk);
        let targeted_admin_revocation = matches!(barrier_update_reason, Some(0))
            && delta.revoked.iter().any(|leaf| {
                *leaf != author_leaf_ids.first().copied().unwrap_or([0u8; 32])
                    && u64::from(cover_leaf_index(leaf, tree_n_max)) == parsed.updater_leaf
            })
            && has_full_verification_witness
            && author_is_room_admin;
        if author_cover_indices.len() != 1
            || (!author_cover_indices.contains(&parsed.updater_leaf) && !targeted_admin_revocation)
            || author_leaf_ids.len() != 1
            || committed_revoked_indices.contains(&parsed_updater_leaf_usize)
        {
            return Err(CityGError::Acceptance(
                msphf_orchestrator::AcceptanceError::Freeze(
                    msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID,
                ),
            ));
        }
        let author_leaf_id = author_leaf_ids[0];
        let join_finalize_auth_token = parse_join_finalize_auth_token(header)?;

        let author_is_unresolved_joiner = unresolved_join_leaf_set.contains(
            &u32::try_from(parsed.updater_leaf)
                .map_err(|_| CityGError::InvalidInput("barrier_update malformed"))?,
        );
        let revocation_changed = state_before.barrier_initialized
            && parsed.revocation_roots_hash != state_before.barrier_roots_hash;
        if revocation_changed {
            if matches!(barrier_update_reason, Some(1 | 2)) {
                return Err(CityGError::Acceptance(
                    msphf_orchestrator::AcceptanceError::Freeze(
                        msphf_orchestrator::FREEZE_BARRIER_NON_REVOCATION_REASON_FORBIDDEN_WHILE_PENDING_REVOCATIONS,
                    ),
                ));
            }
        } else if state_before.barrier_initialized {
            match barrier_update_reason {
                Some(2) if !author_is_unresolved_joiner => {
                    return Err(CityGError::Acceptance(
                        msphf_orchestrator::AcceptanceError::Freeze(
                            msphf_orchestrator::FREEZE_BARRIER_PROACTIVE_FORBIDDEN,
                        ),
                    ));
                }
                Some(1) if author_is_unresolved_joiner => {
                    return Err(CityGError::Acceptance(
                        msphf_orchestrator::AcceptanceError::Freeze(
                            msphf_orchestrator::FREEZE_BARRIER_PROACTIVE_FORBIDDEN,
                        ),
                    ));
                }
                _ => {}
            }
        }
        match barrier_update_reason {
            Some(2) => {
                let supplied = join_finalize_auth_token.ok_or(CityGError::Acceptance(
                    msphf_orchestrator::AcceptanceError::Freeze(
                        msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID,
                    ),
                ))?;
                let record = state_before
                    .pending_join_finalize_auth
                    .get(&author_leaf_id)
                    .ok_or(CityGError::Acceptance(
                        msphf_orchestrator::AcceptanceError::Freeze(
                            msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID,
                        ),
                    ))?;
                if record.token != supplied
                    || u64::from(record.cover_leaf_index) != parsed.updater_leaf
                {
                    return Err(CityGError::Acceptance(
                        msphf_orchestrator::AcceptanceError::Freeze(
                            msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID,
                        ),
                    ));
                }
            }
            Some(_) | None => {
                if join_finalize_auth_token.is_some() {
                    return Err(CityGError::InvalidInput("barrier_update malformed"));
                }
            }
        }

        let n_max_usize = usize::try_from(tree_n_max)
            .map_err(|_| CityGError::InvalidInput("barrier_update malformed"))?;
        let prior_hash_cache = state_before.barrier_hash_cache.clone();
        let base_before_cache = prior_hash_cache.as_deref();
        let mut before_hash_cache = HashMap::new();
        let expected_before = if can_borrow_snapshot_base {
            #[cfg(debug_assertions)]
            {
                let recomputed_before = compute_barrier_tree_hash(
                    tree_n_max,
                    state_before.barrier_pk_entries.as_slice(),
                )?;
                debug_assert_eq!(
                    recomputed_before, state_before.kem_tree_hash_after,
                    "materialized barrier snapshot/hash drifted"
                );
            }
            state_before.kem_tree_hash_after
        } else {
            let snapshot_base_ref = match snapshot_base_owned.as_ref() {
                Some(snapshot) => snapshot.as_slice(),
                None => return Err(CityGError::InvalidInput("barrier_update malformed")),
            };
            compute_barrier_subtree_hash_cached(
                0,
                tree_n_max,
                n_max_usize,
                snapshot_base_ref,
                None,
                &mut before_hash_cache,
            )?
        };
        if expected_before != parsed.kem_tree_hash_before {
            return Err(CityGError::Acceptance(
                msphf_orchestrator::AcceptanceError::Freeze(
                    msphf_orchestrator::FREEZE_BARRIER_TREE_HASH_CHAIN_FAILURE,
                ),
            ));
        }

        let revocation_roots_hash = compute_revocation_roots_hash(
            &header_bytes32(header, 112, "barrier_update malformed")?,
            &header_bytes32(header, hdr::HDR_REVOKED_ROOT, "barrier_update malformed")?,
        )?;
        if parsed.revocation_roots_hash != revocation_roots_hash {
            return Err(CityGError::InvalidInput("barrier_update malformed"));
        }

        if let Some(ref snapshot_base) = snapshot_base_owned {
            verify_barrier_update_pairs_and_targets(snapshot_base.as_slice(), &parsed, tree_n_max)?;
        } else {
            verify_barrier_update_pairs_and_targets(
                state_before.barrier_pk_entries.as_slice(),
                &parsed,
                tree_n_max,
            )?;
        }

        let snapshot_pre = match snapshot_base_owned.as_ref() {
            Some(snapshot) => snapshot
                .iter()
                .map(|cow| cow.clone().into_owned())
                .collect(),
            None => state_before.barrier_pk_entries.clone(),
        };
        let mut snapshot_post = snapshot_pre.clone();
        let mut changed_nodes = BTreeSet::new();
        for (node, ek) in &parsed.new_public_keys {
            let index = usize::try_from(*node)
                .map_err(|_| CityGError::InvalidInput("barrier_update malformed"))?;
            let slot = snapshot_post
                .get_mut(index)
                .ok_or(CityGError::InvalidInput("barrier_update malformed"))?;
            *slot = ek.clone();
            changed_nodes.insert(index);
        }
        let (expected_after, after_hash_cache) = if parsed.new_public_keys.is_empty() {
            (expected_before, HashMap::new())
        } else {
            let (expected_after, after_hash_cache) = compute_barrier_tree_hash_with_changes(
                tree_n_max,
                snapshot_post.as_slice(),
                &changed_nodes,
                if can_borrow_snapshot_base {
                    base_before_cache
                } else {
                    None
                },
                &mut before_hash_cache,
            )?;
            #[cfg(debug_assertions)]
            if !changed_nodes.is_empty() {
                let full_rehash_after =
                    compute_barrier_tree_hash(tree_n_max, snapshot_post.as_slice())?;
                debug_assert_eq!(
                    expected_after, full_rehash_after,
                    "incremental barrier after-hash diverged from full rehash"
                );
            }
            (expected_after, after_hash_cache)
        };
        if expected_after != parsed.kem_tree_hash_after {
            return Err(CityGError::Acceptance(
                msphf_orchestrator::AcceptanceError::Freeze(
                    msphf_orchestrator::FREEZE_BARRIER_TREE_HASH_CHAIN_FAILURE,
                ),
            ));
        }

        let hash_cache_post = if parsed.new_public_keys.is_empty() {
            prior_hash_cache
        } else {
            let mut merged_cache = HashMap::new();
            if let Some(base) = base_before_cache {
                merged_cache.extend(base.iter().map(|(node, hash)| (*node, *hash)));
            }
            merged_cache.extend(before_hash_cache);
            merged_cache.extend(after_hash_cache);
            if merged_cache.len() == expected_len {
                Some(Arc::new(merged_cache))
            } else {
                None
            }
        };

        Ok(Some(BarrierUpdateValidationOutcome {
            parsed,
            snapshot_pre,
            snapshot_post,
            hash_cache_post,
        }))
    })();
    validation.map_err(map_barrier_update_validation_error)
}

fn apply_join_records_to_snapshot(
    pk_entries: &mut [Vec<u8>],
    n_max: u64,
    join_records: &[BarrierJoinLeafRecord],
) -> Result<(), CityGError> {
    let leaf_base = usize::try_from(n_max.saturating_sub(1))
        .map_err(|_| CityGError::InvalidInput("barrier_update malformed"))?;
    for record in join_records {
        let leaf_node = leaf_base
            .checked_add(
                usize::try_from(record.leaf_index)
                    .map_err(|_| CityGError::InvalidInput("barrier_update malformed"))?,
            )
            .ok_or(CityGError::InvalidInput("barrier_update malformed"))?;
        let slot = pk_entries
            .get_mut(leaf_node)
            .ok_or(CityGError::InvalidInput("barrier_update malformed"))?;
        *slot = record.ek_leaf.clone();
        clear_barrier_path(pk_entries, leaf_node, false, Vec::clear);
    }
    Ok(())
}

fn apply_revoked_indices_to_snapshot(
    pk_entries: &mut [Vec<u8>],
    n_max: u64,
    revoked_leaf_indices: &[u32],
) -> Result<(), CityGError> {
    let leaf_base = usize::try_from(n_max.saturating_sub(1))
        .map_err(|_| CityGError::InvalidInput("barrier_update malformed"))?;
    for leaf_index in revoked_leaf_indices {
        let leaf_node = leaf_base
            .checked_add(
                usize::try_from(*leaf_index)
                    .map_err(|_| CityGError::InvalidInput("barrier_update malformed"))?,
            )
            .ok_or(CityGError::InvalidInput("barrier_update malformed"))?;
        if pk_entries.get(leaf_node).is_none() {
            return Err(CityGError::InvalidInput("barrier_update malformed"));
        }
        clear_barrier_path(pk_entries, leaf_node, true, Vec::clear);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_full_verification_witness_candidate(
    state_before: &GroupState,
    current_history_commitment: &HistoryCommitment,
    author_leaf_id: &[u8; 32],
    barrier_update_reason: u64,
    updater_leaf: u64,
    barrier_update: &[u8],
    joins_prev_barrier_version: u64,
    join_records: &[BarrierJoinLeafRecord],
    revocation_roots_hash: &[u8; 32],
    revoked_leaf_indices: &[u32],
) -> Result<(), CityGError> {
    if barrier_update_reason != 0 && barrier_update_reason != 1 {
        return Err(CityGError::InvalidInput("barrier_update malformed"));
    }
    if state_before.current_history_commitment != *current_history_commitment {
        return Err(CityGError::InvalidInput(
            "history commitment mismatch for full verification witness",
        ));
    }
    if joins_prev_barrier_version != state_before.barrier_version {
        return Err(CityGError::InvalidInput(
            "joins_prev_barrier_version mismatch for full verification witness",
        ));
    }
    if state_before.revoked.contains(author_leaf_id)
        || !state_before.leaf_device_pk.contains_key(author_leaf_id)
    {
        return Err(freeze_barrier_updater_invalid_error());
    }
    let mut header = BTreeMap::new();
    header.insert(
        hdr::HDR_BARRIER_UPDATE,
        Value::Bytes(barrier_update.to_vec()),
    );
    header.insert(
        hdr::HDR_BARRIER_UPDATE_REASON,
        Value::Integer(Integer::from(barrier_update_reason)),
    );
    let parsed = parse_barrier_update(&header, state_before.n_max)?
        .ok_or(CityGError::InvalidInput("barrier_update malformed"))?;
    if parsed.prev_barrier_version != state_before.barrier_version
        || parsed.updater_leaf != updater_leaf
        || parsed.revocation_roots_hash != *revocation_roots_hash
    {
        return Err(freeze_barrier_updater_invalid_error());
    }
    let revocation_changed = *revocation_roots_hash != state_before.barrier_roots_hash;
    if (revocation_changed && barrier_update_reason != 0)
        || (!revocation_changed && barrier_update_reason != 1)
    {
        return Err(freeze_barrier_updater_invalid_error());
    }

    let mut snapshot_pre = build_pk_entries_cow(state_before)?
        .into_iter()
        .map(|entry| entry.into_owned())
        .collect::<Vec<_>>();
    apply_join_records_to_snapshot(
        snapshot_pre.as_mut_slice(),
        state_before.n_max,
        join_records,
    )?;
    apply_revoked_indices_to_snapshot(
        snapshot_pre.as_mut_slice(),
        state_before.n_max,
        revoked_leaf_indices,
    )?;
    let expected_before = compute_barrier_tree_hash(state_before.n_max, snapshot_pre.as_slice())?;
    if expected_before != parsed.kem_tree_hash_before {
        return Err(CityGError::Acceptance(
            msphf_orchestrator::AcceptanceError::Freeze(
                msphf_orchestrator::FREEZE_BARRIER_TREE_HASH_CHAIN_FAILURE,
            ),
        ));
    }
    verify_barrier_update_pairs_and_targets(snapshot_pre.as_slice(), &parsed, state_before.n_max)?;
    for (node, ek) in &parsed.new_public_keys {
        let index = usize::try_from(*node)
            .map_err(|_| CityGError::InvalidInput("barrier_update malformed"))?;
        let slot = snapshot_pre
            .get_mut(index)
            .ok_or(CityGError::InvalidInput("barrier_update malformed"))?;
        *slot = ek.clone();
    }
    let expected_after = compute_barrier_tree_hash(state_before.n_max, snapshot_pre.as_slice())?;
    if expected_after != parsed.kem_tree_hash_after {
        return Err(CityGError::Acceptance(
            msphf_orchestrator::AcceptanceError::Freeze(
                msphf_orchestrator::FREEZE_BARRIER_TREE_HASH_CHAIN_FAILURE,
            ),
        ));
    }
    Ok(())
}

fn header_bytes32(
    header: &BTreeMap<u64, Value>,
    key: u64,
    label: &'static str,
) -> Result<[u8; 32], CityGError> {
    header_bytes32_from_slice(header_required_bytes(header, key, label)?)
}

fn header_bytes32_opt(
    header: &BTreeMap<u64, Value>,
    key: u64,
) -> Result<Option<[u8; 32]>, CityGError> {
    header_optional_bytes(header, key)?
        .map(header_bytes32_from_slice)
        .transpose()
}

fn header_bytes(
    header: &BTreeMap<u64, Value>,
    key: u64,
    label: &'static str,
) -> Result<Vec<u8>, CityGError> {
    Ok(header_required_bytes(header, key, label)?.to_vec())
}

fn header_bytes_opt(
    header: &BTreeMap<u64, Value>,
    key: u64,
) -> Result<Option<Vec<u8>>, CityGError> {
    Ok(header_optional_bytes(header, key)?.map(|bytes| bytes.to_vec()))
}

fn header_string(
    header: &BTreeMap<u64, Value>,
    key: u64,
    default: Option<&'static str>,
) -> Result<String, CityGError> {
    header_optional_string(header, key)?
        .map(Cow::into_owned)
        .or_else(|| default.map(str::to_string))
        .ok_or(CityGError::InvalidInput("pivot field missing"))
}

fn header_required_bytes<'a>(
    header: &'a BTreeMap<u64, Value>,
    key: u64,
    label: &'static str,
) -> Result<&'a [u8], CityGError> {
    match header.get(&key) {
        Some(Value::Bytes(bytes)) => Ok(bytes.as_slice()),
        Some(_) => Err(CityGError::InvalidInput("pivot field wrong type")),
        None => Err(CityGError::InvalidInput(label)),
    }
}

fn header_optional_bytes(
    header: &BTreeMap<u64, Value>,
    key: u64,
) -> Result<Option<&[u8]>, CityGError> {
    match header.get(&key) {
        Some(Value::Bytes(bytes)) => Ok(Some(bytes.as_slice())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(CityGError::InvalidInput("pivot field wrong type")),
    }
}

fn header_bytes32_from_slice(bytes: &[u8]) -> Result<[u8; 32], CityGError> {
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CityGError::InvalidInput("pivot field wrong length"))?;
    Ok(raw)
}

fn header_optional_string<'a>(
    header: &'a BTreeMap<u64, Value>,
    key: u64,
) -> Result<Option<Cow<'a, str>>, CityGError> {
    match header.get(&key) {
        Some(Value::Text(text)) => Ok(Some(Cow::Borrowed(text.as_str()))),
        Some(Value::Integer(value)) => u64::try_from(*value)
            .map(|v| Some(Cow::Owned(v.to_string())))
            .map_err(|_| CityGError::InvalidInput("pivot field wrong type")),
        Some(Value::Bytes(bytes)) => std::str::from_utf8(bytes)
            .map(|s| Some(Cow::Owned(s.to_string())))
            .map_err(|_| CityGError::InvalidInput("pivot field invalid utf8")),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(CityGError::InvalidInput("pivot field wrong type")),
    }
}

#[cfg(test)]
fn blank_internal_path_from_leaf(pk_entries: &mut [Vec<u8>], leaf_node: usize) {
    clear_barrier_path(pk_entries, leaf_node, false, Vec::clear);
}

#[cfg(test)]
fn blank_leaf_and_path(pk_entries: &mut [Vec<u8>], leaf_node: usize) {
    clear_barrier_path(pk_entries, leaf_node, true, Vec::clear);
}

/// Light-weight acceptance output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerOutcome {
    pub we_epoch_id: [u8; 32],
    pub wid: [u8; 32],
    pub parent_root: [u8; 32],
    pub new_root: [u8; 32],
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{
        CityGError, CityGServer, GLOBAL_HISTORY_ATTESTATION_FINALITY_KIND,
        GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID, GlobalHistoryAttestationSignedPayload,
        PersistedBarrierPublicTreeSnapshot, PersistedKbroadRoomState, ServerConfig,
        compute_barrier_tree_hash, global_history_parent_attestation_id,
        parse_global_history_attestation, verify_history_authority_signature,
    };
    use ciborium::value::{Integer, Value};
    use cityg_client::{CityGClient, ClientEpochBundle, witness};
    use msphf_core::hash::h_l;
    use msphf_core::merkle::canonical_set_root;
    use msphf_core::serde_utils::to_cbor_vec;
    use msphf_orchestrator::lb;
    use msphf_orchestrator::{
        AcceptanceOptions, AnchorInstanceParts, BootstrapPolicy, DEFAULT_POLICY_VERSION,
        DEFAULT_PROOF_MODE, DEFAULT_VRF_ID, FsJoinInputs, FsMergeInputs, LeafIdMode,
        OrchestrationParams, PivotParity, PopKeypair, SrxMode, compute_leaf_id, hdr,
        mhw::HeadRecord,
    };
    use pqcrypto_dilithium::dilithium5::{
        self, SecretKey as MlDsaSecretKey, keypair as ml_dsa_keypair,
    };
    use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey};
    use proptest::prelude::*;
    use rand::{RngExt, SeedableRng, rngs::StdRng};
    use serde::Serialize;
    use std::{
        borrow::Cow,
        collections::{BTreeMap, BTreeSet},
        fs::File,
        io::Write,
        path::Path,
        time::Duration,
    };
    use tempfile::tempdir;

    fn test_room_admin_replay_key(tag: u8) -> [u8; 32] {
        [tag; 32]
    }

    fn demo_server_with_journal(path: impl AsRef<Path>) -> CityGServer {
        let mut config = demo_acceptance_config();
        config.state_path = Some(path.as_ref().to_path_buf());
        CityGServer::new(config)
    }

    fn demo_server_with_journal_and_global_history_authority(
        path: impl AsRef<Path>,
    ) -> CityGServer {
        let mut config = demo_acceptance_config();
        config.state_path = Some(path.as_ref().to_path_buf());
        config.enable_global_history_authority();
        CityGServer::new(config)
    }

    fn demo_server_with_local_history_authority() -> CityGServer {
        let mut config = demo_acceptance_config();
        config.enable_local_history_authority();
        CityGServer::new(config)
    }

    fn demo_server_with_global_history_authority() -> CityGServer {
        let mut config = demo_acceptance_config();
        config.enable_global_history_authority();
        CityGServer::new(config)
    }

    fn demo_acceptance_config() -> ServerConfig {
        let mut config = ServerConfig::new();
        config.window_ttl = Some(Duration::from_secs(120));

        let mut registry = BTreeMap::new();
        registry.insert(
            cityg_client::demo::DEMO_GID.to_vec(),
            cityg_client::demo::kbroad_public().to_vec(),
        );

        config.acceptance_options = Some(AcceptanceOptions {
            bootstrap_policy: BootstrapPolicy::CaMlDsa {
                public_key: cityg_client::demo::bootstrap_public().to_vec(),
            },
            kbroad_registry: Some(registry),
            ..AcceptanceOptions::default()
        });
        config
    }

    fn barrier_leaf_public_key() -> Vec<u8> {
        vec![0x42; 1184]
    }

    fn demo_vrf_keys() -> Result<(Vec<u8>, Vec<u8>), CityGError> {
        let params = lb::generate_parameters([0u8; 32])
            .map_err(|_| CityGError::InvalidInput("vrf parameters"))?;
        let pair = lb::generate_keypair(&params, [1u8; 32])
            .map_err(|_| CityGError::InvalidInput("vrf keypair"))?;
        Ok((pair.0, pair.1))
    }

    fn bytes32_from_header(
        header: &BTreeMap<u64, Value>,
        key: u64,
    ) -> Result<[u8; 32], CityGError> {
        let bytes = header
            .get(&key)
            .and_then(Value::as_bytes)
            .ok_or(CityGError::InvalidInput("missing 32-byte header field"))?;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| CityGError::InvalidInput("invalid 32-byte header field"))
    }

    fn u64_from_header(header: &BTreeMap<u64, Value>, key: u64) -> Result<u64, CityGError> {
        let value = header
            .get(&key)
            .ok_or(CityGError::InvalidInput("missing integer header field"))?;
        match value {
            Value::Integer(i) => u64::try_from(*i)
                .map_err(|_| CityGError::InvalidInput("integer header out of range")),
            _ => Err(CityGError::InvalidInput("header field must be integer")),
        }
    }

    fn install_pending_join_finalize_auth(
        state: &mut super::GroupState,
        leaf_id: [u8; 32],
    ) -> [u8; 32] {
        let token = [0xE7; 32];
        state.pending_join_finalize_auth.insert(
            leaf_id,
            super::JoinFinalizeAuthRecord {
                leaf_id,
                cover_leaf_index: super::cover_leaf_index(&leaf_id, state.n_max),
                token,
            },
        );
        token
    }

    fn install_current_history_commitment_header(
        header: &mut BTreeMap<u64, Value>,
        commitment: super::HistoryCommitment,
    ) -> Result<(), CityGError> {
        header.insert(
            hdr::HDR_BARRIER_HISTORY_COMMITMENT,
            Value::Bytes(super::encode_barrier_history_commitment_header(commitment)?),
        );
        Ok(())
    }

    struct GeneratedMemberBundle {
        bundle: ClientEpochBundle,
        leaf_id: [u8; 32],
        pop_public_key: Vec<u8>,
        pop_secret_key: MlDsaSecretKey,
        vrf_secret_key: Vec<u8>,
        vrf_public_key: Vec<u8>,
        join_finalize_auth_token: [u8; 32],
    }

    fn build_genesis_member_bundle(label_seed: u8) -> Result<GeneratedMemberBundle, CityGError> {
        let gid = cityg_client::demo::DEMO_GID;
        let cat = [0x21; 32];
        let parent_root = canonical_set_root(&[])?;
        let revoked_since_root = [0u8; 32];
        let revoked_root = [0u8; 32];
        let pox_r_commit = cityg_client::witness::demo_pox_commit();
        let tswe_salt_hash = msphf_core::instance::tswe_salt_hash(&gid, &parent_root)?;

        let (pop_pk, pop_sk) = ml_dsa_keypair();
        let pop_public_key = pop_pk.as_bytes().to_vec();
        let pop_secret_key = pop_sk;
        let leaf_id = compute_leaf_id(
            LeafIdMode::PerGroup,
            &gid,
            "ML-DSA-65",
            pop_public_key.as_slice(),
        )
        .map_err(|_| CityGError::InvalidInput("leaf id derivation"))?;
        let join_delta_root = canonical_set_root(&[leaf_id])?;

        let (canonical_witness, srx_owned) = witness::build_branch_b_artifacts(
            &[],
            &[leaf_id],
            parent_root,
            &[],
            revoked_since_root,
            &[],
            [0u8; 32],
        )?;
        let witness_cbor = witness::witness_to_cbor(&canonical_witness)?;
        let srx_inputs = srx_owned.into_srx_inputs();

        let (vrf_secret_key, vrf_public_key) = demo_vrf_keys()?;
        let mut fs_state =
            msphf_orchestrator::ForwardSecrecyState::new([label_seed.wrapping_add(1); 32]);

        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_KBROAD_ALG, Value::Text("ml-kem-768".to_string()));
        header.insert(
            hdr::HDR_KBROAD_PUB,
            Value::Bytes(cityg_client::demo::kbroad_public().to_vec()),
        );
        header.insert(
            hdr::HDR_BARRIER_VERSION,
            Value::Integer(Integer::from(0u64)),
        );
        header.insert(
            hdr::HDR_BARRIER_LEAF_PK,
            Value::Bytes(barrier_leaf_public_key()),
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
            msphf_crs_id: msphf_core::params::RLWE_CRS_ID_DEFAULT,
            params_id: msphf_core::params::RLWE_PARAMS_ID_MOCK,
            srx: Some(srx_inputs),
            srx_mode: SrxMode::Complete,
            pop_keys: Some(PopKeypair {
                algorithm: "ML-DSA-65",
                public_key: pop_public_key.as_slice(),
                secret_key: &pop_secret_key,
            }),
            leaf_id_mode: LeafIdMode::PerGroup,
            proof_mode: DEFAULT_PROOF_MODE,
            vrf_id: DEFAULT_VRF_ID,
            policy_version: DEFAULT_POLICY_VERSION,
            vrf_secret_key: Some(vrf_secret_key.as_slice()),
            vrf_public_key: Some(vrf_public_key.as_slice()),
            fs_policy_version: "7",
            fs_epoch_base_ts: 0,
            barrier_version: 0,
            fs_join: FsJoinInputs::default(),
            fs_merge: FsMergeInputs::default(),
        };

        let mut bundle =
            CityGClient::generate_epoch(header, parts, params, &mut fs_state, Some(&witness_cbor))?;
        cityg_client::demo::attach_bootstrap(&mut bundle)?;

        Ok(GeneratedMemberBundle {
            bundle,
            leaf_id,
            pop_public_key,
            pop_secret_key,
            vrf_secret_key,
            vrf_public_key,
            join_finalize_auth_token: [0u8; 32],
        })
    }

    fn colliding_cover_leaf(leaf_suffix: u32) -> [u8; 32] {
        let mut leaf = [0u8; 32];
        leaf[28..32].copy_from_slice(&leaf_suffix.to_be_bytes());
        leaf
    }

    fn build_join_member_from_server_ticket(
        server: &mut CityGServer,
        gid: &[u8; 32],
        label_seed: u8,
        disable_autonomic_evolve: bool,
    ) -> Result<GeneratedMemberBundle, CityGError> {
        let (pop_pk, pop_sk) = ml_dsa_keypair();
        let pop_public_key = pop_pk.as_bytes().to_vec();
        let pop_secret_key = pop_sk;
        let leaf_id = compute_leaf_id(
            LeafIdMode::PerGroup,
            gid,
            "ML-DSA-65",
            pop_public_key.as_slice(),
        )
        .map_err(|_| CityGError::InvalidInput("leaf id derivation"))?;
        let ticket = server.build_join_ticket_with_leaf(gid, Some(leaf_id))?;
        let srx_inputs = witness::SrxInputsOwned::from_cbor(&ticket.srx_cbor)
            .map_err(|_| CityGError::InvalidInput("decode SRX inputs"))?
            .into_srx_inputs();
        let (vrf_secret_key, vrf_public_key) = demo_vrf_keys()?;
        let mut fs_state =
            msphf_orchestrator::ForwardSecrecyState::new([label_seed.wrapping_add(1); 32]);

        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_KBROAD_ALG, Value::Text("ml-kem-768".to_string()));
        header.insert(
            hdr::HDR_KBROAD_PUB,
            Value::Bytes(ticket.kbroad_public.clone()),
        );
        header.insert(
            hdr::HDR_BARRIER_VERSION,
            Value::Integer(Integer::from(ticket.barrier_version)),
        );
        header.insert(
            hdr::HDR_BARRIER_LEAF_PK,
            Value::Bytes(barrier_leaf_public_key()),
        );

        let parts = AnchorInstanceParts {
            gid,
            cat: &ticket.cat,
            tswe_salt_hash: &ticket.tswe_salt_hash,
            parent_root: &ticket.parent_root,
            join_delta_root: &ticket.join_delta_root,
            revoked_since_prev_root: &ticket.revoked_since_root,
            revoked_root: &ticket.revoked_root,
            pox_r_commit: Some(&ticket.pox_r_commit),
        };

        let params = OrchestrationParams {
            msphf_crs_id: msphf_core::params::RLWE_CRS_ID_DEFAULT,
            params_id: msphf_core::params::RLWE_PARAMS_ID_MOCK,
            srx: Some(srx_inputs),
            srx_mode: SrxMode::Complete,
            pop_keys: Some(PopKeypair {
                algorithm: "ML-DSA-65",
                public_key: pop_public_key.as_slice(),
                secret_key: &pop_secret_key,
            }),
            leaf_id_mode: LeafIdMode::PerGroup,
            proof_mode: DEFAULT_PROOF_MODE,
            vrf_id: DEFAULT_VRF_ID,
            policy_version: DEFAULT_POLICY_VERSION,
            vrf_secret_key: Some(vrf_secret_key.as_slice()),
            vrf_public_key: Some(vrf_public_key.as_slice()),
            fs_policy_version: "7",
            fs_epoch_base_ts: server.context().fs_base_ts().unwrap_or(0),
            barrier_version: ticket.barrier_version,
            fs_join: FsJoinInputs::default(),
            fs_merge: FsMergeInputs::default(),
        };

        let witness_bytes = if ticket.witness_cbor.is_empty() {
            None
        } else {
            Some(ticket.witness_cbor.as_slice())
        };

        let bundle = if disable_autonomic_evolve {
            CityGClient::generate_epoch_without_evolve(
                header,
                parts,
                params,
                &mut fs_state,
                witness_bytes,
            )
        } else {
            CityGClient::generate_epoch(header, parts, params, &mut fs_state, witness_bytes)
        }
        .map_err(|err| match err {
            cityg_client::CityGError::Acceptance(err) => CityGError::Acceptance(err),
            cityg_client::CityGError::InvalidInput(message) => CityGError::InvalidInput(message),
            _ => CityGError::InvalidInput("client generation failed"),
        })?;

        Ok(GeneratedMemberBundle {
            bundle,
            leaf_id,
            pop_public_key,
            pop_secret_key,
            vrf_secret_key,
            vrf_public_key,
            join_finalize_auth_token: ticket.join_finalize_auth_token,
        })
    }

    fn build_join_bundle_from_server_ticket(
        server: &mut CityGServer,
        gid: &[u8; 32],
        label_seed: u8,
        disable_autonomic_evolve: bool,
    ) -> Result<ClientEpochBundle, CityGError> {
        Ok(
            build_join_member_from_server_ticket(
                server,
                gid,
                label_seed,
                disable_autonomic_evolve,
            )?
            .bundle,
        )
    }

    fn hydrate_parities(
        parities: &[PivotParity],
        fs_ec: u64,
        fs_epoch_commit: [u8; 32],
        fs_dev_commit: [u8; 32],
    ) -> Vec<PivotParity> {
        parities
            .iter()
            .cloned()
            .map(|mut parity| {
                if parity.fs_ec.is_none() {
                    parity.fs_ec = Some(fs_ec);
                }
                if parity.fs_epoch_commit.is_none() {
                    parity.fs_epoch_commit = Some(fs_epoch_commit);
                }
                if parity.fs_dev_commit.is_none() {
                    parity.fs_dev_commit = Some(fs_dev_commit);
                }
                parity
            })
            .collect()
    }

    fn select_pivot_parity(parities: &[PivotParity]) -> Option<&PivotParity> {
        parities.iter().max_by(|a, b| {
            a.accept_seq
                .cmp(&b.accept_seq)
                .then_with(|| b.xk_hash.cmp(&a.xk_hash))
        })
    }

    fn strip_rollup_metadata(header: &mut BTreeMap<u64, Value>) {
        for key in [
            hdr::HDR_ROLLUP_PROVENANCE_COMMIT,
            hdr::HDR_ROLLUP_EPOCH_REPLAY,
            hdr::HDR_ROLLUP_VCK_COMMIT,
        ] {
            header.remove(&key);
        }
    }

    fn apply_pivot_alignment(header: &mut BTreeMap<u64, Value>, pivot: &PivotParity) {
        if let Ok(fs_policy_version) = pivot.policy_version.parse::<u64>() {
            header
                .entry(hdr::HDR_FS_POLICY_VERSION)
                .or_insert_with(|| Value::Integer(Integer::from(fs_policy_version)));
        }
        header
            .entry(hdr::HDR_PROOF_MODE)
            .or_insert_with(|| Value::Text(pivot.proof_mode.clone()));
        header
            .entry(hdr::HDR_VRF_ID)
            .or_insert_with(|| Value::Text(pivot.vrf_id.clone()));
        header
            .entry(hdr::HDR_VRF_PROOF)
            .or_insert_with(|| Value::Bytes(pivot.vrf_proof.clone()));
        header
            .entry(hdr::HDR_VRF_PUBLIC_KEY)
            .or_insert_with(|| Value::Bytes(pivot.vrf_public.clone()));
        header
            .entry(hdr::HDR_VRF_MASK_A)
            .or_insert_with(|| Value::Bytes(pivot.mask_a.to_vec()));
        header
            .entry(hdr::HDR_VRF_MASK_B)
            .or_insert_with(|| Value::Bytes(pivot.mask_b.to_vec()));
        header
            .entry(hdr::HDR_FS_CAPSS)
            .or_insert_with(|| Value::Bytes(pivot.fs_capss.clone()));
        header
            .entry(hdr::HDR_PROOFS_COMMIT)
            .or_insert_with(|| Value::Bytes(pivot.proofs_commit.to_vec()));
        if let Some(fs_ec) = pivot.fs_ec {
            header
                .entry(hdr::HDR_FS_EC)
                .or_insert_with(|| Value::Integer(Integer::from(fs_ec)));
            header
                .entry(hdr::HDR_FS_CHECKPOINT_EC)
                .or_insert_with(|| Value::Integer(Integer::from(fs_ec)));
        }
        if let Some(epoch_commit) = pivot.fs_epoch_commit {
            header
                .entry(hdr::HDR_FS_EPOCH_COMMIT)
                .or_insert_with(|| Value::Bytes(epoch_commit.to_vec()));
        }
        if let Some(dev_commit) = pivot.fs_dev_commit {
            header
                .entry(hdr::HDR_FS_DEV_PREV_COMMIT)
                .or_insert_with(|| Value::Bytes(dev_commit.to_vec()));
            header
                .entry(hdr::HDR_FS_DEV_COMMIT)
                .or_insert_with(|| Value::Bytes(dev_commit.to_vec()));
        }
    }

    fn apply_join_records_to_snapshot(
        snapshot: &mut [Vec<u8>],
        n_max: u64,
        records: &[super::BarrierJoinLeafRecord],
    ) -> Result<(), CityGError> {
        let leaf_base = usize::try_from(n_max.saturating_sub(1))
            .map_err(|_| CityGError::InvalidInput("leaf base overflow"))?;
        for record in records {
            let leaf_node = leaf_base.saturating_add(
                usize::try_from(record.leaf_index)
                    .map_err(|_| CityGError::InvalidInput("leaf index overflow"))?,
            );
            if let Some(slot) = snapshot.get_mut(leaf_node) {
                *slot = record.ek_leaf.clone();
            }
            super::blank_internal_path_from_leaf(snapshot, leaf_node);
        }
        Ok(())
    }

    fn apply_revoked_indices_to_snapshot(
        snapshot: &mut [Vec<u8>],
        n_max: u64,
        revoked_indices: &[u32],
    ) -> Result<(), CityGError> {
        let leaf_base = usize::try_from(n_max.saturating_sub(1))
            .map_err(|_| CityGError::InvalidInput("leaf base overflow"))?;
        for index in revoked_indices {
            let leaf_node = leaf_base.saturating_add(
                usize::try_from(*index)
                    .map_err(|_| CityGError::InvalidInput("revoked index overflow"))?,
            );
            super::blank_leaf_and_path(snapshot, leaf_node);
        }
        Ok(())
    }

    fn collect_resolution_targets(
        snapshot: &[Vec<u8>],
        node: usize,
        leaf_base: usize,
        targets: &mut Vec<usize>,
    ) -> Result<(), CityGError> {
        let Some(pk) = snapshot.get(node) else {
            return Ok(());
        };
        if !pk.is_empty() {
            targets.push(node);
            return Ok(());
        }
        if node >= leaf_base {
            return Ok(());
        }
        let left = node
            .checked_mul(2)
            .and_then(|v| v.checked_add(1))
            .ok_or(CityGError::InvalidInput("barrier tree index overflow"))?;
        let right = node
            .checked_mul(2)
            .and_then(|v| v.checked_add(2))
            .ok_or(CityGError::InvalidInput("barrier tree index overflow"))?;
        collect_resolution_targets(snapshot, left, leaf_base, targets)?;
        collect_resolution_targets(snapshot, right, leaf_base, targets)?;
        Ok(())
    }

    fn build_refresh_barrier_update_bytes(
        n_max: u64,
        updater_leaf: u64,
        barrier_version: u64,
        prev_barrier_version: u64,
        revocation_roots_hash: [u8; 32],
        kem_tree_hash_before: [u8; 32],
        snapshot_pre: &[Vec<u8>],
    ) -> Result<Vec<u8>, CityGError> {
        if n_max == 0 || !n_max.is_power_of_two() || updater_leaf >= n_max {
            return Err(CityGError::InvalidInput(
                "invalid barrier update tree parameters",
            ));
        }
        let expected_nodes = usize::try_from(n_max)
            .ok()
            .and_then(|n| n.checked_mul(2))
            .and_then(|v| v.checked_sub(1))
            .ok_or(CityGError::InvalidInput("invalid barrier n_max"))?;
        if snapshot_pre.len() != expected_nodes {
            return Err(CityGError::InvalidInput("barrier snapshot size mismatch"));
        }

        let leaf_base = n_max.saturating_sub(1);
        let mut path_nodes = vec![leaf_base.saturating_add(updater_leaf)];
        while let Some(&node) = path_nodes.last() {
            if node == 0 {
                break;
            }
            path_nodes.push((node - 1) / 2);
        }

        let mut expected_update_nodes: Vec<u64> = path_nodes.iter().copied().skip(1).collect();
        expected_update_nodes.sort_unstable();

        let new_public_keys = expected_update_nodes
            .iter()
            .map(|node| super::NewPublicKeyWire(*node, vec![(*node as u8).wrapping_add(1); 1184]))
            .collect::<Vec<_>>();

        let mut snapshot_post = snapshot_pre.to_vec();
        for super::NewPublicKeyWire(node, ek) in &new_public_keys {
            let idx = usize::try_from(*node)
                .map_err(|_| CityGError::InvalidInput("barrier node index out of range"))?;
            let slot = snapshot_post
                .get_mut(idx)
                .ok_or(CityGError::InvalidInput("barrier node index out of range"))?;
            *slot = ek.clone();
        }
        let kem_tree_hash_after =
            super::compute_barrier_tree_hash(n_max, snapshot_post.as_slice())?;

        let mut node_ciphertexts = Vec::new();
        let leaf_base_usize = usize::try_from(leaf_base)
            .map_err(|_| CityGError::InvalidInput("leaf base overflow"))?;
        for step in 0..path_nodes.len().saturating_sub(1) {
            let child = usize::try_from(path_nodes[step])
                .map_err(|_| CityGError::InvalidInput("path node overflow"))?;
            let source = path_nodes[step + 1];
            let Some(sibling) = super::sibling_node(child) else {
                continue;
            };
            let mut targets = Vec::new();
            collect_resolution_targets(snapshot_pre, sibling, leaf_base_usize, &mut targets)?;
            targets.sort_unstable();
            for target in targets {
                let target_pk = snapshot_pre
                    .get(target)
                    .ok_or(CityGError::InvalidInput("target index out of range"))?;
                let target_pkhash = super::compute_barrier_pkhash(target_pk.as_slice())?;
                node_ciphertexts.push(super::NodeCiphertextWire(
                    source,
                    u64::try_from(target)
                        .map_err(|_| CityGError::InvalidInput("target index overflow"))?,
                    target_pkhash[..16].to_vec(),
                    vec![0x33; 1088],
                    vec![0x44; 48],
                ));
            }
        }
        node_ciphertexts.sort_by_key(|entry| (entry.0, entry.1));

        let cover_payload = super::KemTreeCoverPayloadWire(
            updater_leaf,
            path_nodes,
            None,
            node_ciphertexts,
            new_public_keys,
        );
        let cover_bytes = super::to_cbor_vec(&cover_payload)?;
        let update = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            barrier_version,
            prev_barrier_version,
            n_max,
            revocation_roots_hash.to_vec(),
            kem_tree_hash_before.to_vec(),
            kem_tree_hash_after.to_vec(),
            cover_bytes,
        );
        Ok(super::to_cbor_vec(&update)?)
    }

    fn build_refresh_bundle_for_member(
        server: &mut CityGServer,
        generated: &GeneratedMemberBundle,
        source_bundle: &ClientEpochBundle,
    ) -> Result<(ClientEpochBundle, ClientEpochBundle), CityGError> {
        let gid = cityg_client::demo::DEMO_GID;
        let fs_ec = u64_from_header(&source_bundle.header_map, hdr::HDR_FS_EC)?;
        let fs_epoch_commit =
            bytes32_from_header(&source_bundle.header_map, hdr::HDR_FS_EPOCH_COMMIT)?;
        let fs_dev_prev_commit =
            bytes32_from_header(&source_bundle.header_map, hdr::HDR_FS_DEV_COMMIT)?;

        let ticket = server.build_merge_ticket_for_refresh(&gid, &generated.leaf_id)?;
        let parities = hydrate_parities(
            ticket.parities.as_slice(),
            fs_ec,
            fs_epoch_commit,
            fs_dev_prev_commit,
        );
        let pivot = select_pivot_parity(parities.as_slice())
            .ok_or(CityGError::InvalidInput("pivot parity missing"))?;

        let committed_roots_hash =
            super::compute_revocation_roots_hash(&pivot.revoked_since_root, &pivot.revoked_root)?;
        let ticket_roots_hash =
            super::compute_revocation_roots_hash(&ticket.revoked_since_root, &ticket.revoked_root)?;
        let mut snapshot_pre = server
            .fetch_barrier_public_tree(&gid, &ticket.kem_tree_hash_after)?
            .pk_entries;
        let join_records = server.resolve_joins_since(&gid, ticket.barrier_version)?;
        let unresolved_join_leaf_indices: BTreeSet<u32> = join_records
            .records
            .iter()
            .map(|record| record.leaf_index)
            .collect();
        let barrier_update_reason = if unresolved_join_leaf_indices
            .contains(&super::cover_leaf_index(&generated.leaf_id, ticket.n_max))
        {
            2u64
        } else {
            1u64
        };
        let committed_revoked = server.resolve_revoked_leaf_indices(&gid, &committed_roots_hash)?;
        apply_join_records_to_snapshot(
            snapshot_pre.as_mut_slice(),
            ticket.n_max,
            join_records.records.as_slice(),
        )?;
        apply_revoked_indices_to_snapshot(
            snapshot_pre.as_mut_slice(),
            ticket.n_max,
            committed_revoked.leaf_indices.as_slice(),
        )?;
        let kem_tree_hash_before =
            super::compute_barrier_tree_hash(ticket.n_max, snapshot_pre.as_slice())?;
        let next_barrier_version = ticket.barrier_version.saturating_add(1);
        let barrier_update = build_refresh_barrier_update_bytes(
            ticket.n_max,
            ticket.cover_leaf_index,
            next_barrier_version,
            ticket.barrier_version,
            ticket_roots_hash,
            kem_tree_hash_before,
            snapshot_pre.as_slice(),
        )?;

        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_KBROAD_ALG, Value::Text("ml-kem-768".to_string()));
        header.insert(
            hdr::HDR_KBROAD_PUB,
            Value::Bytes(ticket.kbroad_public.clone()),
        );
        header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(barrier_update));
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(barrier_update_reason)),
        );
        let history_commitment = server.current_history_commitment(&gid)?;
        let history_commitment_header =
            super::encode_barrier_history_commitment_header(history_commitment)?;
        header.insert(
            hdr::HDR_BARRIER_HISTORY_COMMITMENT,
            Value::Bytes(history_commitment_header.clone()),
        );
        if barrier_update_reason == 2 && generated.join_finalize_auth_token != [0u8; 32] {
            header.insert(
                hdr::HDR_JOIN_FINALIZE_AUTH,
                Value::Bytes(generated.join_finalize_auth_token.to_vec()),
            );
        }

        let parts = AnchorInstanceParts {
            gid: &gid,
            cat: &ticket.cat,
            tswe_salt_hash: &ticket.tswe_salt_hash,
            parent_root: &ticket.parent_root,
            join_delta_root: &ticket.join_delta_root,
            revoked_since_prev_root: &ticket.revoked_since_root,
            revoked_root: &ticket.revoked_root,
            pox_r_commit: Some(&ticket.pox_r_commit),
        };

        let params = OrchestrationParams {
            msphf_crs_id: ticket.msphf_crs_id.as_str(),
            params_id: ticket.msphf_params_id.as_str(),
            srx: None,
            srx_mode: SrxMode::Complete,
            pop_keys: Some(PopKeypair {
                algorithm: "ML-DSA-65",
                public_key: generated.pop_public_key.as_slice(),
                secret_key: &generated.pop_secret_key,
            }),
            leaf_id_mode: LeafIdMode::PerGroup,
            proof_mode: ticket.proof_mode.as_str(),
            vrf_id: ticket.vrf_id.as_str(),
            policy_version: ticket.policy_version.as_str(),
            vrf_secret_key: Some(generated.vrf_secret_key.as_slice()),
            vrf_public_key: Some(generated.vrf_public_key.as_slice()),
            fs_policy_version: ticket.fs_policy_version.as_str(),
            fs_epoch_base_ts: ticket.fs_epoch_base_ts,
            barrier_version: next_barrier_version,
            fs_join: FsJoinInputs {
                fs_ec,
                fs_epoch_commit,
                fs_dev_prev_commit,
            },
            fs_merge: FsMergeInputs::default(),
        };

        let witness_bytes = if ticket.witness_cbor.is_empty() {
            None
        } else {
            Some(ticket.witness_cbor.as_slice())
        };

        let mut refresh_bundle = CityGClient::generate_merge(
            header,
            parts,
            params,
            parities.as_slice(),
            None,
            witness_bytes,
        )?;
        strip_rollup_metadata(&mut refresh_bundle.header_map);
        apply_pivot_alignment(&mut refresh_bundle.header_map, pivot);
        if let Some(authority) = server.history_authority.as_ref() {
            let raw_history_commitment = match refresh_bundle
                .header_map
                .get(&hdr::HDR_BARRIER_HISTORY_COMMITMENT)
            {
                Some(Value::Bytes(raw)) => raw.clone(),
                _ => return Err(CityGError::InvalidInput("barrier_update malformed")),
            };
            let raw_barrier_update = match refresh_bundle.header_map.get(&hdr::HDR_BARRIER_UPDATE) {
                Some(Value::Bytes(raw)) => raw.clone(),
                _ => return Err(CityGError::InvalidInput("barrier_update malformed")),
            };
            let parsed_barrier_update =
                super::parse_barrier_update(&refresh_bundle.header_map, ticket.n_max)?
                    .ok_or(CityGError::InvalidInput("barrier_update malformed"))?;
            let global_history_attestation = super::encode_global_history_attestation(
                authority,
                &gid,
                &history_commitment,
                ticket.barrier_version,
                &ticket.kem_tree_hash_after,
            )?;
            refresh_bundle.header_map.insert(
                hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION,
                Value::Bytes(global_history_attestation.clone()),
            );
            let receipt_payload = super::full_verification_receipt_payload(
                &gid,
                &generated.leaf_id,
                barrier_update_reason,
                parsed_barrier_update.updater_leaf,
                raw_history_commitment.as_slice(),
                global_history_attestation.as_slice(),
                raw_barrier_update.as_slice(),
            )?;
            let receipt_signature =
                dilithium5::detached_sign(receipt_payload.as_slice(), &generated.pop_secret_key)
                    .as_bytes()
                    .to_vec();
            refresh_bundle.header_map.insert(
                hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT,
                Value::Bytes(super::encode_full_verification_receipt(
                    &generated.leaf_id,
                    barrier_update_reason,
                    parsed_barrier_update.updater_leaf,
                    receipt_signature,
                )?),
            );
            if authority.mode.requires_full_verification_witness()
                && (barrier_update_reason == 0 || barrier_update_reason == 1)
            {
                let deployment_profile_manifest = server.deployment_profile_manifest_bytes(
                    &gid,
                    "v0.1.4",
                    server.history_authority_extension_id(),
                    ticket.n_max,
                    ticket.max_barrier_update_bytes,
                    ticket.fs_forward_leap_policy,
                )?;
                refresh_bundle.header_map.insert(
                    hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS,
                    Value::Bytes(server.full_verification_witness_bytes(
                        &gid,
                        &history_commitment,
                        ticket.barrier_version,
                        &ticket.kem_tree_hash_after,
                        &generated.leaf_id,
                        barrier_update_reason,
                        parsed_barrier_update.updater_leaf,
                        raw_barrier_update.as_slice(),
                        ticket.barrier_version,
                        join_records.records.as_slice(),
                        &committed_roots_hash,
                        committed_revoked.leaf_indices.as_slice(),
                        deployment_profile_manifest.as_slice(),
                    )?),
                );
            }
        }
        let pristine_bundle = refresh_bundle.clone();

        Ok((refresh_bundle, pristine_bundle))
    }

    fn build_leave_bundle_for_member(
        server: &mut CityGServer,
        generated: &GeneratedMemberBundle,
        source_bundle: &ClientEpochBundle,
    ) -> Result<ClientEpochBundle, CityGError> {
        let gid = cityg_client::demo::DEMO_GID;
        let fs_ec = u64_from_header(&source_bundle.header_map, hdr::HDR_FS_EC)?;
        let fs_epoch_commit =
            bytes32_from_header(&source_bundle.header_map, hdr::HDR_FS_EPOCH_COMMIT)?;
        let fs_dev_prev_commit =
            bytes32_from_header(&source_bundle.header_map, hdr::HDR_FS_DEV_COMMIT)?;

        let ticket = server.build_merge_ticket(&gid, &generated.leaf_id)?;
        let parities = hydrate_parities(
            ticket.parities.as_slice(),
            fs_ec,
            fs_epoch_commit,
            fs_dev_prev_commit,
        );
        let pivot = select_pivot_parity(parities.as_slice())
            .ok_or(CityGError::InvalidInput("pivot parity missing"))?;

        let revocation_roots_hash =
            super::compute_revocation_roots_hash(&ticket.revoked_since_root, &ticket.revoked_root)?;
        let committed_roots_hash =
            super::compute_revocation_roots_hash(&pivot.revoked_since_root, &pivot.revoked_root)?;
        let mut snapshot_pre = server
            .fetch_barrier_public_tree(&gid, &ticket.kem_tree_hash_after)?
            .pk_entries;
        let join_records = server.resolve_joins_since(&gid, ticket.barrier_version)?;
        let committed_revoked = server.resolve_revoked_leaf_indices(&gid, &committed_roots_hash)?;
        let revoked_cover_leaf_index = u32::try_from(ticket.cover_leaf_index)
            .map_err(|_| CityGError::InvalidInput("cover_leaf_index out of range"))?;
        let mut post_revoked_leaf_indices = committed_revoked.leaf_indices.clone();
        if let Err(insert_at) = post_revoked_leaf_indices.binary_search(&revoked_cover_leaf_index) {
            post_revoked_leaf_indices.insert(insert_at, revoked_cover_leaf_index);
        }
        apply_join_records_to_snapshot(
            snapshot_pre.as_mut_slice(),
            ticket.n_max,
            join_records.records.as_slice(),
        )?;
        apply_revoked_indices_to_snapshot(
            snapshot_pre.as_mut_slice(),
            ticket.n_max,
            post_revoked_leaf_indices.as_slice(),
        )?;
        let kem_tree_hash_before =
            super::compute_barrier_tree_hash(ticket.n_max, snapshot_pre.as_slice())?;
        let next_barrier_version = ticket.barrier_version.saturating_add(1);
        let barrier_update = build_refresh_barrier_update_bytes(
            ticket.n_max,
            ticket.cover_leaf_index,
            next_barrier_version,
            ticket.barrier_version,
            revocation_roots_hash,
            kem_tree_hash_before,
            snapshot_pre.as_slice(),
        )?;

        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_KBROAD_ALG, Value::Text("ml-kem-768".to_string()));
        header.insert(
            hdr::HDR_KBROAD_PUB,
            Value::Bytes(ticket.kbroad_public.clone()),
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(barrier_update.clone()),
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(0u64)),
        );

        let history_commitment = ticket.current_history_commitment;
        let history_commitment_header =
            super::encode_barrier_history_commitment_header(history_commitment)?;
        header.insert(
            hdr::HDR_BARRIER_HISTORY_COMMITMENT,
            Value::Bytes(history_commitment_header.clone()),
        );

        if let Some(authority) = server.history_authority.as_ref() {
            let parsed_barrier_update = super::parse_barrier_update(&header, ticket.n_max)?
                .ok_or(CityGError::InvalidInput("barrier_update malformed"))?;
            let global_history_attestation = super::encode_global_history_attestation(
                authority,
                &gid,
                &history_commitment,
                ticket.barrier_version,
                &ticket.kem_tree_hash_after,
            )?;
            header.insert(
                hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION,
                Value::Bytes(global_history_attestation.clone()),
            );
            let receipt_payload = super::full_verification_receipt_payload(
                &gid,
                &generated.leaf_id,
                0,
                parsed_barrier_update.updater_leaf,
                history_commitment_header.as_slice(),
                global_history_attestation.as_slice(),
                barrier_update.as_slice(),
            )?;
            let receipt_signature =
                dilithium5::detached_sign(receipt_payload.as_slice(), &generated.pop_secret_key)
                    .as_bytes()
                    .to_vec();
            header.insert(
                hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT,
                Value::Bytes(super::encode_full_verification_receipt(
                    &generated.leaf_id,
                    0,
                    parsed_barrier_update.updater_leaf,
                    receipt_signature,
                )?),
            );
            if authority.mode.requires_full_verification_witness() {
                let deployment_profile_manifest = server.deployment_profile_manifest_bytes(
                    &gid,
                    "v0.1.4",
                    server.history_authority_extension_id(),
                    ticket.n_max,
                    ticket.max_barrier_update_bytes,
                    ticket.fs_forward_leap_policy,
                )?;
                header.insert(
                    hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS,
                    Value::Bytes(server.full_verification_witness_bytes(
                        &gid,
                        &history_commitment,
                        ticket.barrier_version,
                        &ticket.kem_tree_hash_after,
                        &generated.leaf_id,
                        0,
                        parsed_barrier_update.updater_leaf,
                        barrier_update.as_slice(),
                        ticket.barrier_version,
                        join_records.records.as_slice(),
                        &revocation_roots_hash,
                        post_revoked_leaf_indices.as_slice(),
                        deployment_profile_manifest.as_slice(),
                    )?),
                );
            }
        }

        let srx_inputs = witness::SrxInputsOwned::from_cbor(&ticket.srx_cbor)
            .map_err(|_| CityGError::InvalidInput("decode SRX inputs"))?
            .into_srx_inputs();
        let witness_bytes = if ticket.witness_cbor.is_empty() {
            None
        } else {
            Some(ticket.witness_cbor.as_slice())
        };

        let parts = AnchorInstanceParts {
            gid: &gid,
            cat: &ticket.cat,
            tswe_salt_hash: &ticket.tswe_salt_hash,
            parent_root: &ticket.parent_root,
            join_delta_root: &ticket.join_delta_root,
            revoked_since_prev_root: &ticket.revoked_since_root,
            revoked_root: &ticket.revoked_root,
            pox_r_commit: Some(&ticket.pox_r_commit),
        };

        let params = OrchestrationParams {
            msphf_crs_id: ticket.msphf_crs_id.as_str(),
            params_id: ticket.msphf_params_id.as_str(),
            srx: Some(srx_inputs),
            srx_mode: SrxMode::Complete,
            pop_keys: Some(PopKeypair {
                algorithm: "ML-DSA-65",
                public_key: generated.pop_public_key.as_slice(),
                secret_key: &generated.pop_secret_key,
            }),
            leaf_id_mode: LeafIdMode::PerGroup,
            proof_mode: ticket.proof_mode.as_str(),
            vrf_id: ticket.vrf_id.as_str(),
            policy_version: ticket.policy_version.as_str(),
            vrf_secret_key: Some(generated.vrf_secret_key.as_slice()),
            vrf_public_key: Some(generated.vrf_public_key.as_slice()),
            fs_policy_version: ticket.fs_policy_version.as_str(),
            fs_epoch_base_ts: ticket.fs_epoch_base_ts,
            barrier_version: next_barrier_version,
            fs_join: FsJoinInputs {
                fs_ec,
                fs_epoch_commit,
                fs_dev_prev_commit,
            },
            fs_merge: FsMergeInputs::default(),
        };

        let mut bundle = CityGClient::generate_merge(
            header,
            parts,
            params,
            parities.as_slice(),
            None,
            witness_bytes,
        )?;
        strip_rollup_metadata(&mut bundle.header_map);
        apply_pivot_alignment(&mut bundle.header_map, pivot);
        Ok(bundle)
    }

    fn build_admin_expel_bundle_for_member(
        server: &mut CityGServer,
        generated: &GeneratedMemberBundle,
        source_bundle: &ClientEpochBundle,
        target_leaf_id: &[u8; 32],
        replay_tag: u8,
    ) -> Result<ClientEpochBundle, CityGError> {
        let gid = cityg_client::demo::DEMO_GID;
        let fs_ec = u64_from_header(&source_bundle.header_map, hdr::HDR_FS_EC)?;
        let fs_epoch_commit =
            bytes32_from_header(&source_bundle.header_map, hdr::HDR_FS_EPOCH_COMMIT)?;
        let fs_dev_prev_commit =
            bytes32_from_header(&source_bundle.header_map, hdr::HDR_FS_DEV_COMMIT)?;

        let ticket = server.build_admin_expel_ticket(
            &gid,
            &generated.pop_public_key,
            &generated.leaf_id,
            target_leaf_id,
            test_room_admin_replay_key(replay_tag),
        )?;
        let parities = hydrate_parities(
            ticket.parities.as_slice(),
            fs_ec,
            fs_epoch_commit,
            fs_dev_prev_commit,
        );
        let pivot = select_pivot_parity(parities.as_slice())
            .ok_or(CityGError::InvalidInput("pivot parity missing"))?;

        let revocation_roots_hash =
            super::compute_revocation_roots_hash(&ticket.revoked_since_root, &ticket.revoked_root)?;
        let committed_roots_hash =
            super::compute_revocation_roots_hash(&pivot.revoked_since_root, &pivot.revoked_root)?;
        let mut snapshot_pre = server
            .fetch_barrier_public_tree(&gid, &ticket.kem_tree_hash_after)?
            .pk_entries;
        let join_records = server.resolve_joins_since(&gid, ticket.barrier_version)?;
        let committed_revoked = server.resolve_revoked_leaf_indices(&gid, &committed_roots_hash)?;
        let revoked_cover_leaf_index = u32::try_from(ticket.cover_leaf_index)
            .map_err(|_| CityGError::InvalidInput("cover_leaf_index out of range"))?;
        let mut post_revoked_leaf_indices = committed_revoked.leaf_indices.clone();
        if let Err(insert_at) = post_revoked_leaf_indices.binary_search(&revoked_cover_leaf_index) {
            post_revoked_leaf_indices.insert(insert_at, revoked_cover_leaf_index);
        }
        apply_join_records_to_snapshot(
            snapshot_pre.as_mut_slice(),
            ticket.n_max,
            join_records.records.as_slice(),
        )?;
        apply_revoked_indices_to_snapshot(
            snapshot_pre.as_mut_slice(),
            ticket.n_max,
            post_revoked_leaf_indices.as_slice(),
        )?;
        let kem_tree_hash_before =
            super::compute_barrier_tree_hash(ticket.n_max, snapshot_pre.as_slice())?;
        let next_barrier_version = ticket.barrier_version.saturating_add(1);
        let barrier_update = build_refresh_barrier_update_bytes(
            ticket.n_max,
            ticket.cover_leaf_index,
            next_barrier_version,
            ticket.barrier_version,
            revocation_roots_hash,
            kem_tree_hash_before,
            snapshot_pre.as_slice(),
        )?;

        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_KBROAD_ALG, Value::Text("ml-kem-768".to_string()));
        header.insert(
            hdr::HDR_KBROAD_PUB,
            Value::Bytes(ticket.kbroad_public.clone()),
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(barrier_update.clone()),
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(0u64)),
        );

        let history_commitment = ticket.current_history_commitment;
        let history_commitment_header =
            super::encode_barrier_history_commitment_header(history_commitment)?;
        header.insert(
            hdr::HDR_BARRIER_HISTORY_COMMITMENT,
            Value::Bytes(history_commitment_header.clone()),
        );

        if let Some(authority) = server.history_authority.as_ref() {
            let parsed_barrier_update = super::parse_barrier_update(&header, ticket.n_max)?
                .ok_or(CityGError::InvalidInput("barrier_update malformed"))?;
            let global_history_attestation = super::encode_global_history_attestation(
                authority,
                &gid,
                &history_commitment,
                ticket.barrier_version,
                &ticket.kem_tree_hash_after,
            )?;
            header.insert(
                hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION,
                Value::Bytes(global_history_attestation.clone()),
            );
            let receipt_payload = super::full_verification_receipt_payload(
                &gid,
                &generated.leaf_id,
                0,
                parsed_barrier_update.updater_leaf,
                history_commitment_header.as_slice(),
                global_history_attestation.as_slice(),
                barrier_update.as_slice(),
            )?;
            let receipt_signature =
                dilithium5::detached_sign(receipt_payload.as_slice(), &generated.pop_secret_key)
                    .as_bytes()
                    .to_vec();
            header.insert(
                hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT,
                Value::Bytes(super::encode_full_verification_receipt(
                    &generated.leaf_id,
                    0,
                    parsed_barrier_update.updater_leaf,
                    receipt_signature,
                )?),
            );
            if authority.mode.requires_full_verification_witness() {
                let deployment_profile_manifest = server.deployment_profile_manifest_bytes(
                    &gid,
                    "v0.1.4",
                    server.history_authority_extension_id(),
                    ticket.n_max,
                    ticket.max_barrier_update_bytes,
                    ticket.fs_forward_leap_policy,
                )?;
                header.insert(
                    hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS,
                    Value::Bytes(server.full_verification_witness_bytes(
                        &gid,
                        &history_commitment,
                        ticket.barrier_version,
                        &ticket.kem_tree_hash_after,
                        &generated.leaf_id,
                        0,
                        parsed_barrier_update.updater_leaf,
                        barrier_update.as_slice(),
                        ticket.barrier_version,
                        join_records.records.as_slice(),
                        &revocation_roots_hash,
                        post_revoked_leaf_indices.as_slice(),
                        deployment_profile_manifest.as_slice(),
                    )?),
                );
            }
        }

        let srx_inputs = witness::SrxInputsOwned::from_cbor(&ticket.srx_cbor)
            .map_err(|_| CityGError::InvalidInput("decode SRX inputs"))?
            .into_srx_inputs();
        let witness_bytes = if ticket.witness_cbor.is_empty() {
            None
        } else {
            Some(ticket.witness_cbor.as_slice())
        };

        let parts = AnchorInstanceParts {
            gid: &gid,
            cat: &ticket.cat,
            tswe_salt_hash: &ticket.tswe_salt_hash,
            parent_root: &ticket.parent_root,
            join_delta_root: &ticket.join_delta_root,
            revoked_since_prev_root: &ticket.revoked_since_root,
            revoked_root: &ticket.revoked_root,
            pox_r_commit: Some(&ticket.pox_r_commit),
        };

        let params = OrchestrationParams {
            msphf_crs_id: ticket.msphf_crs_id.as_str(),
            params_id: ticket.msphf_params_id.as_str(),
            srx: Some(srx_inputs),
            srx_mode: SrxMode::Complete,
            pop_keys: Some(PopKeypair {
                algorithm: "ML-DSA-65",
                public_key: generated.pop_public_key.as_slice(),
                secret_key: &generated.pop_secret_key,
            }),
            leaf_id_mode: LeafIdMode::PerGroup,
            proof_mode: ticket.proof_mode.as_str(),
            vrf_id: ticket.vrf_id.as_str(),
            policy_version: ticket.policy_version.as_str(),
            vrf_secret_key: Some(generated.vrf_secret_key.as_slice()),
            vrf_public_key: Some(generated.vrf_public_key.as_slice()),
            fs_policy_version: ticket.fs_policy_version.as_str(),
            fs_epoch_base_ts: ticket.fs_epoch_base_ts,
            barrier_version: next_barrier_version,
            fs_join: FsJoinInputs {
                fs_ec,
                fs_epoch_commit,
                fs_dev_prev_commit,
            },
            fs_merge: FsMergeInputs::default(),
        };

        let mut bundle = CityGClient::generate_merge(
            header,
            parts,
            params,
            parities.as_slice(),
            None,
            witness_bytes,
        )?;
        strip_rollup_metadata(&mut bundle.header_map);
        apply_pivot_alignment(&mut bundle.header_map, pivot);
        Ok(bundle)
    }

    fn advance_committed_tree_for_tests(
        server: &mut CityGServer,
        gid: &[u8; 32],
        marker: u8,
    ) -> Result<([u8; 32], Vec<Vec<u8>>), CityGError> {
        let group = server
            .roster
            .groups
            .get_mut(gid.as_slice())
            .ok_or(CityGError::InvalidInput("group not found"))?;
        let previous_entries = super::build_pk_entries_cow(group)?
            .into_iter()
            .map(|entry| entry.into_owned())
            .collect::<Vec<_>>();
        let previous_hash = compute_barrier_tree_hash(group.n_max, previous_entries.as_slice())?;
        let mut current_entries = previous_entries.clone();
        let target =
            if let Some(target) = current_entries.iter_mut().find(|entry| !entry.is_empty()) {
                target
            } else {
                let record = group
                    .join_history
                    .iter()
                    .rev()
                    .find(|record| !record.ek_leaf.is_empty())
                    .ok_or(CityGError::InvalidInput(
                        "barrier tree missing populated leaf",
                    ))?;
                let leaf_base = usize::try_from(group.n_max)
                    .map_err(|_| CityGError::InvalidInput("barrier n_max too large"))?
                    .saturating_sub(1);
                let leaf_node = leaf_base.saturating_add(record.leaf_index as usize);
                let slot = current_entries
                    .get_mut(leaf_node)
                    .ok_or(CityGError::InvalidInput("barrier leaf index out of bounds"))?;
                *slot = record.ek_leaf.clone();
                slot
            };
        target[0] ^= marker.max(1);
        let current_hash = compute_barrier_tree_hash(group.n_max, current_entries.as_slice())?;
        if current_hash == previous_hash {
            return Err(CityGError::InvalidInput(
                "test barrier tree mutation did not change hash",
            ));
        }
        let snapshot_ref =
            super::encode_barrier_public_tree_snapshot_ref(group, previous_entries.as_slice())?;
        let mut snapshot_ref = snapshot_ref;
        snapshot_ref.history_commitment =
            super::ensure_current_history_commitment(gid.as_slice(), group)?;
        snapshot_ref.history_view_id = snapshot_ref.history_commitment.history_view_id;
        group
            .barrier_public_tree_history
            .insert(previous_hash, snapshot_ref);
        group.barrier_pk_entries = current_entries.clone();
        group.kem_tree_hash_after = current_hash;
        let ctx_state = server.ctx.barrier_group_state_entry_mut(gid);
        ctx_state.kem_tree_hash_after = current_hash;
        Ok((current_hash, current_entries))
    }

    fn seed_current_accepted_barrier_update_for_tests(
        server: &mut CityGServer,
        gid: &[u8; 32],
    ) -> Result<[u8; 32], CityGError> {
        let group = server
            .roster
            .groups
            .get_mut(gid.as_slice())
            .ok_or(CityGError::InvalidInput("group not found"))?;
        let n_max = super::validate_barrier_n_max(group.n_max)?;
        let predecessor_entries = super::build_all_blank_pk_entries(n_max)?;
        let predecessor_hash =
            super::compute_barrier_tree_hash(n_max, predecessor_entries.as_slice())?;
        let barrier_update = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            group.barrier_version,
            group.barrier_version.saturating_sub(1),
            n_max,
            group.barrier_roots_hash.to_vec(),
            predecessor_hash.to_vec(),
            group.kem_tree_hash_after.to_vec(),
            Vec::new(),
        );
        group.current_accepted_barrier_update = super::to_cbor_vec(&barrier_update)?;
        group.current_accepted_barrier_predecessor_hash = predecessor_hash;
        Ok(predecessor_hash)
    }

    #[test]
    fn server_config_defaults() -> Result<(), Box<dyn std::error::Error>> {
        let cfg = ServerConfig::new();
        assert!(cfg.h_max.is_none());
        assert!(cfg.window_ttl.is_none());
        Ok(())
    }

    #[test]
    fn server_config_default_impl_matches_new() {
        let cfg = ServerConfig::default();
        assert!(cfg.h_max.is_none());
        assert!(cfg.window_ttl.is_none());
        assert!(cfg.acceptance_options.is_none());
        assert!(cfg.state_path.is_none());
    }

    #[test]
    fn register_group_rejects_duplicate_gid() -> Result<(), CityGError> {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid = [0xA1; 32];
        let key = vec![0x33; 16];

        server.register_group(&gid, key.clone())?;
        assert!(server.roster.groups.contains_key(gid.as_slice()));

        let err = server
            .register_group(&gid, key)
            .expect_err("duplicate gid should fail");
        assert!(matches!(
            err,
            CityGError::InvalidInput("kbroad key already registered")
        ));
        Ok(())
    }

    #[test]
    fn register_group_rejects_gid_with_existing_history_even_if_registry_is_missing()
    -> Result<(), CityGError> {
        let gid = [0xCA; 32];
        let leaf = cityg_client::demo::demo_member_leaf("history-owner");
        let mut server = CityGServer::new(ServerConfig::new());
        let mut membership = cityg_client::GroupMembership::default();
        membership.apply_delta(&cityg_client::MembershipDelta {
            joined: vec![leaf],
            revoked: Vec::new(),
        });
        let root = msphf_core::merkle::canonical_set_root(&[leaf])?;
        let mut state = super::GroupState::default();
        state.snapshots.insert(root, membership);
        state.latest_root = Some(root);
        server.roster.groups.insert(gid.to_vec(), state);

        let err = server
            .register_group(&gid, vec![0x9A; 16])
            .expect_err("group with history must not be re-bootstrapped");
        assert!(matches!(
            err,
            CityGError::InvalidInput(super::KBROAD_HISTORY_EXISTS_ERR)
        ));
        Ok(())
    }

    #[test]
    fn rotate_group_kbroad_rejects_missing_and_unchanged_keys() -> Result<(), CityGError> {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid = [0xB1; 32];
        let key = vec![0x44; 16];

        let missing = server
            .rotate_group_kbroad(&gid, key.clone())
            .expect_err("rotating an unknown group must fail");
        assert!(matches!(
            missing,
            CityGError::InvalidInput("kbroad key missing")
        ));

        server.register_group(&gid, key.clone())?;
        let unchanged = server
            .rotate_group_kbroad(&gid, key)
            .expect_err("rotating with the same key must fail");
        assert!(matches!(
            unchanged,
            CityGError::InvalidInput("kbroad key unchanged")
        ));
        Ok(())
    }

    #[test]
    fn rotate_group_kbroad_allows_successive_unflagged_rotations() -> Result<(), CityGError> {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid = [0xB2; 32];
        let key_a = vec![0x41; 16];
        let key_b = vec![0x42; 16];
        let key_c = vec![0x43; 16];

        server.register_group(&gid, key_a)?;
        assert_eq!(server.rotate_group_kbroad(&gid, key_b.clone())?, 1);
        assert_eq!(server.rotate_group_kbroad(&gid, key_c.clone())?, 2);
        assert_eq!(server.kbroad_generation(&gid), 2);
        assert!(!server.kbroad_rotation_required(&gid));
        assert_eq!(server.build_join_ticket(&gid)?.kbroad_public, key_c);
        Ok(())
    }

    #[test]
    fn room_admin_rotation_requires_authorized_identity() -> Result<(), CityGError> {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid = [0xB3; 32];
        let initial_kbroad = vec![0x41; 16];
        let rotated_kbroad = vec![0x42; 16];
        let admin_pop_key = vec![0xAA; 48];
        let other_pop_key = vec![0xBB; 48];

        server.register_group_with_admin(&gid, initial_kbroad, admin_pop_key.clone())?;

        let err = server
            .rotate_group_kbroad_with_actor(
                &gid,
                rotated_kbroad.clone(),
                &other_pop_key,
                test_room_admin_replay_key(1),
            )
            .expect_err("non-admin identity must be rejected");
        assert!(matches!(
            err,
            CityGError::InvalidInput("room admin proof is not authorized")
        ));

        assert_eq!(
            server.rotate_group_kbroad_with_actor(
                &gid,
                rotated_kbroad.clone(),
                &admin_pop_key,
                test_room_admin_replay_key(2),
            )?,
            1
        );
        assert_eq!(
            server.build_join_ticket(&gid)?.kbroad_public,
            rotated_kbroad
        );
        Ok(())
    }

    #[test]
    fn room_admin_rotation_requires_explicit_admin_acl() -> Result<(), CityGError> {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid = [0xB4; 32];
        server.register_group(&gid, vec![0x41; 16])?;

        let err = server
            .rotate_group_kbroad_with_actor(
                &gid,
                vec![0x42; 16],
                &[0xAB; 48],
                test_room_admin_replay_key(3),
            )
            .expect_err("legacy room without explicit admins must fail closed");
        assert!(matches!(
            err,
            CityGError::InvalidInput("room admin proof is not authorized")
        ));
        Ok(())
    }

    #[test]
    fn grant_revoke_and_list_room_admins_enforce_authorization() -> Result<(), CityGError> {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid = [0xB5; 32];
        let kbroad_public = vec![0x51; 16];
        let creator_pop_key = vec![0xA1; 48];
        let delegate_pop_key = vec![0xB1; 48];
        let outsider_pop_key = vec![0xC1; 48];

        server.register_group_with_admin(&gid, kbroad_public, creator_pop_key.clone())?;

        let err = server
            .grant_room_admin(
                &gid,
                &outsider_pop_key,
                delegate_pop_key.clone(),
                test_room_admin_replay_key(4),
            )
            .expect_err("non-admin grant must fail");
        assert!(matches!(
            err,
            CityGError::InvalidInput("room admin proof is not authorized")
        ));

        let (granted, admin_count) = server.grant_room_admin(
            &gid,
            &creator_pop_key,
            delegate_pop_key.clone(),
            test_room_admin_replay_key(5),
        )?;
        assert!(granted);
        assert_eq!(admin_count, 2);
        assert_eq!(
            server.list_room_admins(&gid, &creator_pop_key)?,
            vec![creator_pop_key.clone(), delegate_pop_key.clone()]
        );

        let replay_err = server
            .grant_room_admin(
                &gid,
                &creator_pop_key,
                delegate_pop_key.clone(),
                test_room_admin_replay_key(5),
            )
            .expect_err("replayed grant proof must fail");
        assert!(matches!(
            replay_err,
            CityGError::InvalidInput(super::ROOM_ADMIN_PROOF_REPLAYED_ERR)
        ));

        let (already_granted, admin_count) = server.grant_room_admin(
            &gid,
            &creator_pop_key,
            delegate_pop_key.clone(),
            test_room_admin_replay_key(6),
        )?;
        assert!(!already_granted);
        assert_eq!(admin_count, 2);

        assert_eq!(
            server.list_room_admins(&gid, &delegate_pop_key)?,
            vec![creator_pop_key.clone(), delegate_pop_key.clone()]
        );

        let err = server
            .revoke_room_admin(
                &gid,
                &outsider_pop_key,
                &delegate_pop_key,
                test_room_admin_replay_key(7),
            )
            .expect_err("non-admin revoke must fail");
        assert!(matches!(
            err,
            CityGError::InvalidInput("room admin proof is not authorized")
        ));

        let (revoked, admin_count) = server.revoke_room_admin(
            &gid,
            &creator_pop_key,
            &delegate_pop_key,
            test_room_admin_replay_key(8),
        )?;
        assert!(revoked);
        assert_eq!(admin_count, 1);
        assert_eq!(
            server.list_room_admins(&gid, &creator_pop_key)?,
            vec![creator_pop_key.clone()]
        );

        let (already_revoked, admin_count) = server.revoke_room_admin(
            &gid,
            &creator_pop_key,
            &delegate_pop_key,
            test_room_admin_replay_key(9),
        )?;
        assert!(!already_revoked);
        assert_eq!(admin_count, 1);
        Ok(())
    }

    #[test]
    fn revoke_room_admin_rejects_last_admin_and_persists_grants() -> Result<(), CityGError> {
        let _serial = super::journal_serial_guard();
        let dir = tempdir()?;
        let journal_path = dir.path().join("room-admin-grants.journal");
        let gid = [0xB6; 32];
        let kbroad_public = vec![0x61; 16];
        let creator_pop_key = vec![0xD1; 48];
        let delegate_pop_key = vec![0xE1; 48];

        {
            let mut config = ServerConfig::new();
            config.state_path = Some(journal_path.clone());
            let mut server = CityGServer::new(config);
            server.register_group_with_admin(&gid, kbroad_public, creator_pop_key.clone())?;

            let err = server
                .revoke_room_admin(
                    &gid,
                    &creator_pop_key,
                    &creator_pop_key,
                    test_room_admin_replay_key(10),
                )
                .expect_err("last admin revoke must fail");
            assert!(matches!(
                err,
                CityGError::InvalidInput("cannot revoke the last room admin")
            ));

            let (granted, admin_count) = server.grant_room_admin(
                &gid,
                &creator_pop_key,
                delegate_pop_key.clone(),
                test_room_admin_replay_key(11),
            )?;
            assert!(granted);
            assert_eq!(admin_count, 2);
        }

        let mut config = ServerConfig::new();
        config.state_path = Some(journal_path);
        let restarted = CityGServer::new(config);
        assert_eq!(
            restarted.list_room_admins(&gid, &creator_pop_key)?,
            vec![creator_pop_key, delegate_pop_key]
        );
        Ok(())
    }

    #[test]
    fn admin_expel_ticket_requires_authorized_admin_bound_to_author_leaf() -> Result<(), CityGError>
    {
        let mut server = super::demo::demo_server();
        let alice = cityg_client::demo::demo_bundle("alice")?;
        let bob = cityg_client::demo::demo_bundle("bob")?;
        server.accept_epoch(&alice)?;
        server.accept_epoch(&bob)?;

        let gid = cityg_client::demo::DEMO_GID;
        let alice_leaf = cityg_client::demo::demo_member_leaf("alice");
        let bob_leaf = cityg_client::demo::demo_member_leaf("bob");
        let bound_admin_pop_key = vec![0xD1; 48];
        let unbound_admin_pop_key = vec![0xE1; 48];
        let outsider_pop_key = vec![0xF1; 48];

        {
            let group = server
                .roster
                .groups
                .get_mut(gid.as_slice())
                .ok_or(CityGError::InvalidInput("missing demo group state"))?;
            group
                .room_admin_pop_keys
                .insert(bound_admin_pop_key.clone());
            group
                .room_admin_pop_keys
                .insert(unbound_admin_pop_key.clone());
            group
                .leaf_device_pk
                .insert(alice_leaf, bound_admin_pop_key.clone());
        }

        let err = match server.build_admin_expel_ticket(
            &gid,
            &outsider_pop_key,
            &alice_leaf,
            &bob_leaf,
            test_room_admin_replay_key(12),
        ) {
            Ok(_) => return Err(CityGError::InvalidInput("outsider expel must fail")),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            CityGError::InvalidInput("room admin proof is not authorized")
        ));

        let err = match server.build_admin_expel_ticket(
            &gid,
            &unbound_admin_pop_key,
            &alice_leaf,
            &bob_leaf,
            test_room_admin_replay_key(13),
        ) {
            Ok(_) => {
                return Err(CityGError::InvalidInput(
                    "author leaf must match signer identity",
                ));
            }
            Err(err) => err,
        };
        assert!(matches!(
            err,
            CityGError::InvalidInput("author leaf is not bound to room admin identity")
        ));

        let err = match server.build_admin_expel_ticket(
            &gid,
            &bound_admin_pop_key,
            &alice_leaf,
            &alice_leaf,
            test_room_admin_replay_key(14),
        ) {
            Ok(_) => return Err(CityGError::InvalidInput("self-targeted expel must fail")),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            CityGError::InvalidInput(
                "author_leaf_id and target_leaf_id must differ; use controlled leave instead"
            )
        ));

        let ticket = server.build_admin_expel_ticket(
            &gid,
            &bound_admin_pop_key,
            &alice_leaf,
            &bob_leaf,
            test_room_admin_replay_key(15),
        )?;
        assert_eq!(ticket.leaf_id, alice_leaf);
        assert_eq!(
            ticket.cover_leaf_index,
            u64::from(super::cover_leaf_index(&bob_leaf, ticket.n_max))
        );
        let srx = witness::SrxInputsOwned::from_cbor(&ticket.srx_cbor)?;
        assert_eq!(srx.since_leaf_ids, vec![bob_leaf]);
        let expected_revoked_root = msphf_core::merkle::canonical_set_root(&[bob_leaf])?;
        assert_eq!(ticket.revoked_since_root, expected_revoked_root);
        assert_eq!(ticket.revoked_root, expected_revoked_root);
        Ok(())
    }

    #[test]
    fn accept_epoch_blocks_while_kbroad_rotation_is_pending() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let gid = cityg_client::demo::DEMO_GID;

        server.roster.mark_kbroad_rotation_required(gid.as_slice());

        let bundle = cityg_client::demo::demo_bundle("rotation-gate")?;
        let accept_err = server
            .accept_epoch(&bundle)
            .expect_err("acceptance must be blocked while rotation is required");
        assert!(matches!(
            accept_err,
            CityGError::InvalidInput("kbroad rotation required")
        ));
        Ok(())
    }

    #[test]
    fn build_join_ticket_auto_rotates_kbroad_when_pending() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let gid = cityg_client::demo::DEMO_GID;
        let previous_key = server
            .ctx
            .kbroad_registry()
            .and_then(|registry| registry.get(gid.as_slice()).cloned())
            .expect("demo server should start with a KBROAD key");

        server.roster.mark_kbroad_rotation_required(gid.as_slice());

        let ticket = server.build_join_ticket(&gid)?;
        assert_eq!(server.kbroad_generation(&gid), 1);
        assert!(!server.kbroad_rotation_required(&gid));
        assert_ne!(ticket.kbroad_public, previous_key);
        assert_eq!(ticket.kbroad_generation, 1);
        Ok(())
    }

    #[test]
    fn build_merge_ticket_auto_rotates_kbroad_when_pending() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let gid = cityg_client::demo::DEMO_GID;
        let previous_key = server
            .ctx
            .kbroad_registry()
            .and_then(|registry| registry.get(gid.as_slice()).cloned())
            .expect("demo server should start with a KBROAD key");
        let bundle = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&bundle)?;
        let leaf_id = cityg_client::demo::demo_member_leaf("alice");

        server.roster.mark_kbroad_rotation_required(gid.as_slice());

        let ticket = server.build_merge_ticket(&gid, &leaf_id)?;
        assert_eq!(server.kbroad_generation(&gid), 1);
        assert!(!server.kbroad_rotation_required(&gid));
        assert_ne!(ticket.kbroad_public, previous_key);
        assert_eq!(ticket.kbroad_generation, 1);
        Ok(())
    }

    #[test]
    fn explicit_room_admins_persist_across_restart() -> Result<(), CityGError> {
        let _serial = super::journal_serial_guard();
        let dir = tempdir()?;
        let journal_path = dir.path().join("room-admins.journal");
        let gid = [0xB4; 32];
        let kbroad_public = vec![0x44; 16];
        let admin_pop_key = vec![0xCC; 48];

        {
            let mut config = ServerConfig::new();
            config.state_path = Some(journal_path.clone());
            let mut server = CityGServer::new(config);
            server.register_group_with_admin(&gid, kbroad_public.clone(), admin_pop_key.clone())?;
        }

        let mut config = ServerConfig::new();
        config.state_path = Some(journal_path);
        let mut restarted = CityGServer::new(config);
        let rotated_kbroad = vec![0x55; 16];
        assert_eq!(
            restarted.rotate_group_kbroad_with_actor(
                &gid,
                rotated_kbroad,
                &admin_pop_key,
                test_room_admin_replay_key(16),
            )?,
            1
        );
        Ok(())
    }

    #[test]
    fn room_admin_proof_replay_keys_persist_across_restart() -> Result<(), CityGError> {
        let _serial = super::journal_serial_guard();
        let dir = tempdir()?;
        let journal_path = dir.path().join("room-admin-proof-replay.journal");
        let gid = [0xB7; 32];
        let kbroad_public = vec![0x61; 16];
        let creator_pop_key = vec![0xD1; 48];
        let delegate_pop_key = vec![0xE1; 48];
        let replay_key = test_room_admin_replay_key(17);

        {
            let mut config = ServerConfig::new();
            config.state_path = Some(journal_path.clone());
            let mut server = CityGServer::new(config);
            server.register_group_with_admin(&gid, kbroad_public, creator_pop_key.clone())?;
            let (granted, admin_count) = server.grant_room_admin(
                &gid,
                &creator_pop_key,
                delegate_pop_key.clone(),
                replay_key,
            )?;
            assert!(granted);
            assert_eq!(admin_count, 2);
        }

        let mut config = ServerConfig::new();
        config.state_path = Some(journal_path);
        let mut restarted = CityGServer::new(config);
        let err = restarted
            .grant_room_admin(&gid, &creator_pop_key, delegate_pop_key, replay_key)
            .expect_err("replayed room-admin proof must remain rejected after restart");
        assert!(matches!(
            err,
            CityGError::InvalidInput(super::ROOM_ADMIN_PROOF_REPLAYED_ERR)
        ));
        Ok(())
    }

    #[test]
    fn kbroad_state_persists_across_restart() -> Result<(), CityGError> {
        let _serial = super::journal_serial_guard();
        let dir = tempdir()?;
        let journal_path = dir.path().join("kbroad-state.journal");
        let gid = [0xC1; 32];
        let initial_key = vec![0x44; 16];
        let rotated_key = vec![0x66; 16];
        let persisted_device_pk = vec![0x91; 32];
        let persisted_device_state = msphf_orchestrator::DeviceChainState {
            last_commit: Some([0xEF; 32]),
            last_ec: 88,
            last_pcs_refresh_ec: Some(77),
        };
        let persisted_roots_hash = super::compute_revocation_roots_hash(&[0u8; 32], &[0u8; 32])?;
        let mut persisted_entries = super::build_all_blank_pk_entries(4)?;
        persisted_entries[0] = vec![0xA5; 1184];
        let persisted_hash = super::compute_barrier_tree_hash(4, persisted_entries.as_slice())?;

        {
            let mut cfg = ServerConfig::new();
            cfg.state_path = Some(journal_path.clone());
            let mut server = CityGServer::new(cfg);
            server.register_group(&gid, initial_key.clone())?;
            server.roster.mark_kbroad_rotation_required(gid.as_slice());
            let generation = server.rotate_group_kbroad(&gid, rotated_key.clone())?;
            assert_eq!(generation, 1);
            assert_eq!(server.kbroad_generation(&gid), 1);
            assert!(!server.kbroad_rotation_required(&gid));
            {
                let state = server
                    .roster
                    .groups
                    .get_mut(gid.as_slice())
                    .expect("registered group state must exist");
                state.barrier_initialized = true;
                state.barrier_version = 9;
                state.barrier_roots_hash = persisted_roots_hash;
                state.kem_tree_hash_after = persisted_hash;
                state.srx_root_sw = Some([0xD7; 32]);
                state.n_max = 4;
                state.last_checkpoint_ec = 66;
                state.last_accepted_ec = 88;
                state.barrier_pk_entries = persisted_entries.clone();
                state.last_pcs_refresh_ec = Some(77);
                state.pcs_refresh_min_delta_device_ec = 3;
                state.pcs_refresh_min_delta_group_ec = 4;
                state.pcs_refresh_slot_width_ec = 5;
                state.max_barrier_update_bytes = 7777;
            }
            let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;
            server.ctx.insert_device_chain_state(
                gid.as_slice(),
                persisted_device_pk.as_slice(),
                persisted_device_state.clone(),
            );
            server.persist_kbroad_state()?;
        }

        let mut cfg = ServerConfig::new();
        cfg.state_path = Some(journal_path.clone());
        let mut server = CityGServer::new(cfg);
        assert_eq!(server.kbroad_generation(&gid), 1);
        assert!(!server.kbroad_rotation_required(&gid));
        let ticket = server.build_join_ticket(&gid)?;
        assert_eq!(ticket.kbroad_public, rotated_key);
        assert_eq!(ticket.kbroad_generation, 1);
        let state = server
            .roster
            .groups
            .get(gid.as_slice())
            .expect("recovered group state must exist");
        assert!(state.barrier_initialized);
        assert_eq!(state.barrier_version, 9);
        assert_eq!(state.barrier_roots_hash, persisted_roots_hash);
        assert_eq!(state.kem_tree_hash_after, persisted_hash);
        assert_eq!(state.srx_root_sw, Some([0xD7; 32]));
        assert_eq!(state.n_max, 4);
        assert_eq!(state.last_checkpoint_ec, 66);
        assert_eq!(state.last_accepted_ec, 88);
        assert_eq!(state.barrier_pk_entries, persisted_entries);
        assert_eq!(state.last_pcs_refresh_ec, Some(77));
        assert_eq!(state.pcs_refresh_min_delta_device_ec, 3);
        assert_eq!(state.pcs_refresh_min_delta_group_ec, 4);
        assert_eq!(state.pcs_refresh_slot_width_ec, 5);
        assert_eq!(state.max_barrier_update_bytes, 7777);
        assert_eq!(
            super::history_barrier_public_tree_entries(state, &persisted_hash).as_ref(),
            Some(&state.barrier_pk_entries),
            "persisted live tree should be promoted into history on reload"
        );
        assert!(
            server
                .ctx
                .barrier_group_state(gid.as_slice())
                .expect("recovered barrier group state must exist")
                .barrier_initialized
        );
        assert_eq!(
            server
                .ctx
                .barrier_group_state(gid.as_slice())
                .expect("recovered barrier group state must exist")
                .barrier_version,
            9
        );
        assert_eq!(
            server
                .ctx
                .barrier_group_state(gid.as_slice())
                .expect("recovered barrier group state must exist")
                .barrier_roots_hash,
            persisted_roots_hash
        );
        assert_eq!(
            server
                .ctx
                .barrier_group_state(gid.as_slice())
                .expect("recovered barrier group state must exist")
                .max_barrier_update_bytes,
            7777
        );
        assert_eq!(
            server
                .ctx
                .barrier_group_state(gid.as_slice())
                .expect("recovered barrier group state must exist")
                .last_checkpoint_ec,
            66
        );
        assert_eq!(
            server
                .ctx
                .barrier_group_state(gid.as_slice())
                .expect("recovered barrier group state must exist")
                .last_accepted_ec,
            88
        );
        assert_eq!(
            server
                .ctx
                .barrier_group_state(gid.as_slice())
                .expect("recovered barrier group state must exist")
                .kem_tree_hash_after,
            persisted_hash
        );
        assert_eq!(
            server
                .ctx
                .barrier_group_state(gid.as_slice())
                .expect("recovered barrier group state must exist")
                .srx_root_sw,
            Some([0xD7; 32])
        );
        assert_eq!(
            server
                .ctx
                .device_chain_get(gid.as_slice(), persisted_device_pk.as_slice()),
            Some(&persisted_device_state)
        );
        let snapshot = server.fetch_barrier_public_tree(&gid, &persisted_hash)?;
        assert_eq!(snapshot.kem_tree_hash_after, persisted_hash);
        assert_eq!(snapshot.pk_entries, persisted_entries);
        let duplicate = server
            .register_group(&gid, initial_key)
            .expect_err("restart must preserve registered room kbroad key");
        assert!(matches!(
            duplicate,
            CityGError::InvalidInput("kbroad key already registered")
        ));
        Ok(())
    }

    #[test]
    fn kbroad_state_persists_historical_barrier_tree_snapshots() -> Result<(), CityGError> {
        let _serial = super::journal_serial_guard();
        let dir = tempdir()?;
        let journal_path = dir.path().join("kbroad-history.journal");
        let gid = cityg_client::demo::DEMO_GID;
        let generated = build_genesis_member_bundle(0x73)?;
        let historical_hash: [u8; 32];
        let historical_entries: Vec<Vec<u8>>;
        let current_hash: [u8; 32];
        let current_entries: Vec<Vec<u8>>;

        {
            let mut server = demo_server_with_journal(&journal_path);
            server.accept_epoch(&generated.bundle)?;
            {
                let group = server
                    .roster
                    .groups
                    .get(gid.as_slice())
                    .ok_or(CityGError::InvalidInput("group not found"))?;
                historical_hash = group.kem_tree_hash_after;
                historical_entries = group.barrier_pk_entries.clone();
            }

            (current_hash, current_entries) =
                advance_committed_tree_for_tests(&mut server, &gid, 0x73)?;
            assert_ne!(current_hash, historical_hash);

            server.persist_kbroad_state()?;
        }

        std::fs::remove_file(&journal_path).ok();

        let mut reloaded = demo_server_with_journal(&journal_path);
        let historical_snapshot = reloaded.fetch_barrier_public_tree(&gid, &historical_hash)?;
        let current_snapshot = reloaded.fetch_barrier_public_tree(&gid, &current_hash)?;
        assert_eq!(historical_snapshot.kem_tree_hash_after, historical_hash);
        assert_eq!(historical_snapshot.pk_entries, historical_entries);
        assert_eq!(current_snapshot.kem_tree_hash_after, current_hash);
        assert_eq!(current_snapshot.pk_entries, current_entries);

        let history_len = reloaded
            .roster
            .groups
            .get(gid.as_slice())
            .ok_or(CityGError::InvalidInput("reloaded group missing"))?
            .barrier_public_tree_history
            .len();
        assert!(
            history_len >= 2,
            "reloaded persisted state should retain historical committed snapshots"
        );
        Ok(())
    }

    #[test]
    fn join_finalize_bundle_keeps_local_hp_commit() -> Result<(), CityGError> {
        let generated = build_genesis_member_bundle(0x74)?;
        let mut server = super::demo::demo_server();
        server.accept_epoch(&generated.bundle)?;

        let (bundle, _pristine_bundle) =
            build_refresh_bundle_for_member(&mut server, &generated, &generated.bundle)?;
        let reason = u64_from_header(&bundle.header_map, hdr::HDR_BARRIER_UPDATE_REASON)?;
        let header_hp_commit = bytes32_from_header(&bundle.header_map, hdr::HDR_HP_COMMIT)?;

        assert_eq!(reason, 2, "first post-join merge should be join_finalize");
        assert_eq!(
            header_hp_commit, bundle.hp_binding.hp_commit,
            "join_finalize bundle must remain self-consistent on hp_commit before acceptance"
        );
        Ok(())
    }

    #[test]
    fn accept_epoch_rejects_barrier_update_missing_history_commitment_header()
    -> Result<(), CityGError> {
        let generated = build_genesis_member_bundle(0x75)?;
        let mut server = super::demo::demo_server();
        server.accept_epoch(&generated.bundle)?;

        let (mut bundle, _pristine_bundle) =
            build_refresh_bundle_for_member(&mut server, &generated, &generated.bundle)?;
        bundle
            .header_map
            .remove(&hdr::HDR_BARRIER_HISTORY_COMMITMENT);

        let err = server
            .accept_epoch(&bundle)
            .expect_err("missing barrier history commitment header must fail closed");
        assert!(
            matches!(
                err,
                CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                    if freeze.code == msphf_orchestrator::FREEZE_BARRIER_UPDATE_MALFORMED.code
                        && freeze.reason
                            == msphf_orchestrator::FREEZE_BARRIER_UPDATE_MALFORMED.reason
            ),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_epoch_rejects_barrier_update_mismatched_history_commitment_header()
    -> Result<(), CityGError> {
        let generated = build_genesis_member_bundle(0x76)?;
        let mut server = super::demo::demo_server();
        server.accept_epoch(&generated.bundle)?;

        let gid = cityg_client::demo::DEMO_GID;
        let current = server.current_history_commitment(&gid)?;
        let mut wrong = current;
        wrong.history_commitment_id = [0xA5; 32];
        wrong.prev_history_commitment_id = current.history_commitment_id;
        wrong.history_seq = current.history_seq.saturating_add(1);

        let (mut bundle, _pristine_bundle) =
            build_refresh_bundle_for_member(&mut server, &generated, &generated.bundle)?;
        install_current_history_commitment_header(&mut bundle.header_map, wrong)?;

        let err = server
            .accept_epoch(&bundle)
            .expect_err("mismatched barrier history commitment header must fail auth");
        assert!(matches!(
            err,
            CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                if freeze.code == msphf_orchestrator::FREEZE_BARRIER_TREE_SNAPSHOT_AUTH_FAILURE.code
                    && freeze.reason
                        == msphf_orchestrator::FREEZE_BARRIER_TREE_SNAPSHOT_AUTH_FAILURE.reason
        ));
        Ok(())
    }

    #[test]
    fn accept_epoch_rejects_barrier_update_full_verification_receipt_without_extension()
    -> Result<(), CityGError> {
        let generated = build_genesis_member_bundle(0x77)?;
        let mut server = super::demo::demo_server();
        server.accept_epoch(&generated.bundle)?;
        let gid = cityg_client::demo::DEMO_GID;
        let _ = advance_committed_tree_for_tests(&mut server, &gid, 0x77)?;

        let (mut bundle, _pristine_bundle) =
            build_refresh_bundle_for_member(&mut server, &generated, &generated.bundle)?;
        bundle.header_map.insert(
            hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT,
            Value::Bytes(vec![0xAB; 32]),
        );

        let err = server
            .accept_epoch(&bundle)
            .expect_err("base profile must reject unsupported full-verification receipt header");
        assert!(
            matches!(err, CityGError::InvalidInput("barrier_update malformed"))
                || matches!(
                    err,
                    CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                        if freeze.code
                            == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.code
                            && freeze.reason
                                == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.reason
                ),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_epoch_rejects_barrier_update_global_history_attestation_without_extension()
    -> Result<(), CityGError> {
        let generated = build_genesis_member_bundle(0x78)?;
        let mut server = super::demo::demo_server();
        server.accept_epoch(&generated.bundle)?;
        let gid = cityg_client::demo::DEMO_GID;
        let _ = advance_committed_tree_for_tests(&mut server, &gid, 0x78)?;

        let (mut bundle, _pristine_bundle) =
            build_refresh_bundle_for_member(&mut server, &generated, &generated.bundle)?;
        bundle.header_map.insert(
            hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION,
            Value::Bytes(vec![0xCD; 32]),
        );

        let err = server
            .accept_epoch(&bundle)
            .expect_err("base profile must reject unsupported global-history attestation header");
        assert!(
            matches!(err, CityGError::InvalidInput("barrier_update malformed"))
                || matches!(
                    err,
                    CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                        if freeze.code
                            == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.code
                            && freeze.reason
                                == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.reason
                ),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn build_refresh_bundle_includes_local_history_authority_headers() -> Result<(), CityGError> {
        let generated = build_genesis_member_bundle(0x79)?;
        let mut server = demo_server_with_local_history_authority();
        server.accept_epoch(&generated.bundle)?;

        let (bundle, _pristine_bundle) =
            build_refresh_bundle_for_member(&mut server, &generated, &generated.bundle)?;
        assert!(
            bundle
                .header_map
                .contains_key(&hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION)
        );
        assert!(
            bundle
                .header_map
                .contains_key(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT)
        );
        assert!(
            !bundle
                .header_map
                .contains_key(&hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS)
        );
        Ok(())
    }

    #[test]
    fn build_refresh_bundle_includes_global_history_authority_headers() -> Result<(), CityGError> {
        let generated = build_genesis_member_bundle(0x7B)?;
        let mut server = demo_server_with_global_history_authority();
        server.accept_epoch(&generated.bundle)?;

        assert_eq!(
            server.history_authority_extension_id(),
            GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID
        );
        let (bundle, _pristine_bundle) =
            build_refresh_bundle_for_member(&mut server, &generated, &generated.bundle)?;
        assert!(
            bundle
                .header_map
                .contains_key(&hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION)
        );
        assert!(
            bundle
                .header_map
                .contains_key(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT)
        );
        let raw_attestation = bundle
            .header_map
            .get(&hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION)
            .and_then(Value::as_bytes)
            .ok_or(CityGError::InvalidInput("missing history attestation"))?;
        let (
            descriptor,
            gid,
            history_commitment,
            barrier_version,
            kem_tree_hash_after,
            _,
            finality_kind,
            signature,
        ) = parse_global_history_attestation(raw_attestation.as_slice())?;
        let payload = to_cbor_vec(&GlobalHistoryAttestationSignedPayload(
            "cityg/global-history-attestation-v1",
            &descriptor.scope_id,
            &gid,
            &history_commitment.history_view_id,
            &history_commitment.history_commitment_id,
            &history_commitment.prev_history_commitment_id,
            history_commitment.history_seq,
            barrier_version,
            &kem_tree_hash_after,
            &global_history_parent_attestation_id(
                &descriptor.scope_id,
                &gid,
                &history_commitment.prev_history_commitment_id,
            )?,
            finality_kind.as_str(),
        ))?;
        let stored_descriptor =
            server
                .history_authority_descriptor()
                .ok_or(CityGError::InvalidInput(
                    "missing history authority descriptor",
                ))?;
        verify_history_authority_signature(&stored_descriptor, payload.as_slice(), &signature)?;
        assert_eq!(finality_kind, GLOBAL_HISTORY_ATTESTATION_FINALITY_KIND);
        Ok(())
    }

    #[test]
    fn full_verification_witness_rejects_barrier_update_hash_mismatch() -> Result<(), CityGError> {
        let generated = build_genesis_member_bundle(0x7D)?;
        let mut server = demo_server_with_global_history_authority();
        server.accept_epoch(&generated.bundle)?;

        let ticket = server
            .build_merge_ticket_for_refresh(&cityg_client::demo::DEMO_GID, &generated.leaf_id)?;
        let join_records =
            server.resolve_joins_since(&cityg_client::demo::DEMO_GID, ticket.barrier_version)?;
        let committed_roots_hash =
            super::compute_revocation_roots_hash(&ticket.revoked_since_root, &ticket.revoked_root)?;
        let committed_revoked = server
            .resolve_revoked_leaf_indices(&cityg_client::demo::DEMO_GID, &committed_roots_hash)?;
        let (bundle, _) =
            build_refresh_bundle_for_member(&mut server, &generated, &generated.bundle)?;
        let raw_barrier_update = bundle
            .header_map
            .get(&hdr::HDR_BARRIER_UPDATE)
            .and_then(Value::as_bytes)
            .ok_or(CityGError::InvalidInput("missing barrier_update"))?;
        let super::BarrierUpdateWire(
            mode,
            barrier_version,
            prev_barrier_version,
            tree_size,
            revocation_roots_hash,
            kem_tree_hash_before,
            mut kem_tree_hash_after,
            cover_payload,
        ) = super::parse_deterministic_cbor(raw_barrier_update)?;
        kem_tree_hash_after[0] ^= 0xFF;
        let tampered_barrier_update = super::to_cbor_vec(&super::BarrierUpdateWire(
            mode,
            barrier_version,
            prev_barrier_version,
            tree_size,
            revocation_roots_hash,
            kem_tree_hash_before,
            kem_tree_hash_after,
            cover_payload,
        ))?;
        let deployment_profile_manifest = server.deployment_profile_manifest_bytes(
            &cityg_client::demo::DEMO_GID,
            "v0.1.4",
            server.history_authority_extension_id(),
            ticket.n_max,
            ticket.max_barrier_update_bytes,
            ticket.fs_forward_leap_policy,
        )?;

        let err = server
            .full_verification_witness_bytes(
                &cityg_client::demo::DEMO_GID,
                &ticket.current_history_commitment,
                ticket.barrier_version,
                &ticket.kem_tree_hash_after,
                &generated.leaf_id,
                1,
                ticket.cover_leaf_index,
                tampered_barrier_update.as_slice(),
                ticket.barrier_version,
                join_records.records.as_slice(),
                &committed_roots_hash,
                committed_revoked.leaf_indices.as_slice(),
                deployment_profile_manifest.as_slice(),
            )
            .expect_err("tampered barrier_update must not receive a full verification witness");
        assert!(matches!(
            err,
            CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                if freeze.code == msphf_orchestrator::FREEZE_BARRIER_TREE_HASH_CHAIN_FAILURE.code
                    && freeze.reason
                        == msphf_orchestrator::FREEZE_BARRIER_TREE_HASH_CHAIN_FAILURE.reason
        ));
        Ok(())
    }

    #[test]
    fn accept_epoch_rejects_barrier_update_missing_receipt_under_local_history_authority()
    -> Result<(), CityGError> {
        let generated = build_genesis_member_bundle(0x7A)?;
        let mut server = demo_server_with_local_history_authority();
        server.accept_epoch(&generated.bundle)?;

        let (mut bundle, _pristine_bundle) =
            build_refresh_bundle_for_member(&mut server, &generated, &generated.bundle)?;
        bundle
            .header_map
            .remove(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT);

        let err = server
            .accept_epoch(&bundle)
            .expect_err("local history authority must require full verification receipt");
        assert!(matches!(
            err,
            CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                if freeze.code == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.code
                    && freeze.reason == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.reason
        ));
        Ok(())
    }

    #[test]
    fn accept_epoch_rejects_barrier_update_missing_receipt_under_global_history_authority()
    -> Result<(), CityGError> {
        let generated = build_genesis_member_bundle(0x7C)?;
        let mut server = demo_server_with_global_history_authority();
        server.accept_epoch(&generated.bundle)?;

        let (mut bundle, _pristine_bundle) =
            build_refresh_bundle_for_member(&mut server, &generated, &generated.bundle)?;
        bundle
            .header_map
            .remove(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT);

        let err = server
            .accept_epoch(&bundle)
            .expect_err("global history authority must require full verification receipt");
        assert!(matches!(
            err,
            CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                if freeze.code == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.code
                    && freeze.reason == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.reason
        ));
        Ok(())
    }

    #[test]
    fn invalid_persisted_kbroad_state_is_ignored_on_boot() -> Result<(), CityGError> {
        let _serial = super::journal_serial_guard();
        let dir = tempdir()?;
        let journal_path = dir.path().join("invalid-kbroad-state.journal");
        let kbroad_path = super::kbroad_state_path_for_journal(&journal_path);
        std::fs::write(&kbroad_path, [0xA1, 0x01, 0x02])?;

        let mut cfg = ServerConfig::new();
        cfg.state_path = Some(journal_path);
        let mut server = CityGServer::new(cfg);
        let gid = [0x91; 32];

        assert!(matches!(
            server.build_join_ticket(&gid),
            Err(CityGError::InvalidInput("kbroad key missing"))
        ));
        server.register_group(&gid, vec![0x11; 16])?;
        assert_eq!(server.kbroad_generation(&gid), 0);
        Ok(())
    }

    #[test]
    fn initialize_group_barrier_bootstrap_state_preserves_existing_state() -> Result<(), CityGError>
    {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid = [0x92; 32];
        let existing_hash = [0xA5; 32];
        let existing_roots_hash = [0xB6; 32];
        let existing_srx = [0xC7; 32];

        let state = server.roster.groups.entry(gid.to_vec()).or_default();
        state.barrier_initialized = true;
        state.barrier_version = 9;
        state.barrier_roots_hash = existing_roots_hash;
        state.kem_tree_hash_after = existing_hash;
        state.n_max = 8;
        state.last_pcs_refresh_ec = Some(44);
        state.pcs_refresh_min_delta_device_ec = 0;
        state.pcs_refresh_min_delta_group_ec = 0;
        state.pcs_refresh_slot_width_ec = 0;
        state.max_barrier_update_bytes = 0;
        state.srx_root_sw = Some(existing_srx);

        server.initialize_group_barrier_bootstrap_state(&gid)?;

        let ctx_state = server
            .ctx
            .barrier_group_state(&gid)
            .ok_or(CityGError::InvalidInput("missing ctx barrier state"))?;
        assert!(ctx_state.barrier_initialized);
        assert_eq!(ctx_state.barrier_version, 9);
        assert_eq!(ctx_state.barrier_roots_hash, existing_roots_hash);
        assert_eq!(ctx_state.kem_tree_hash_after, existing_hash);
        assert_eq!(ctx_state.n_max, 8);
        assert_eq!(ctx_state.last_pcs_refresh_ec, Some(44));
        assert_eq!(ctx_state.pcs_refresh_min_delta_device_ec, 1);
        assert_eq!(ctx_state.pcs_refresh_min_delta_group_ec, 1);
        assert_eq!(ctx_state.pcs_refresh_slot_width_ec, 1);
        assert_eq!(ctx_state.max_barrier_update_bytes, 1);
        assert_eq!(ctx_state.srx_root_sw, Some(existing_srx));
        Ok(())
    }

    #[test]
    fn initialize_group_barrier_bootstrap_state_skips_history_only_group() -> Result<(), CityGError>
    {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid = [0x93; 32];
        let state = server.roster.groups.entry(gid.to_vec()).or_default();
        state.revoked.insert([0x44; 32]);
        state.barrier_initialized = false;
        state.n_max = 8;
        state.max_barrier_update_bytes = 77;

        server.initialize_group_barrier_bootstrap_state(&gid)?;

        let roster_state = server
            .roster
            .groups
            .get(gid.as_slice())
            .ok_or(CityGError::InvalidInput("missing roster group"))?;
        assert!(!roster_state.barrier_initialized);
        assert!(roster_state.barrier_public_tree_history.is_empty());

        let ctx_state = server
            .ctx
            .barrier_group_state(&gid)
            .ok_or(CityGError::InvalidInput("missing ctx barrier state"))?;
        assert!(!ctx_state.barrier_initialized);
        assert_eq!(ctx_state.n_max, 8);
        assert_eq!(ctx_state.max_barrier_update_bytes, 77);
        Ok(())
    }

    #[test]
    fn initialize_registered_groups_barrier_state_bootstraps_registry_groups()
    -> Result<(), CityGError> {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid1 = [0x31; 32];
        let gid2 = [0x32; 32];
        let registry = BTreeMap::from([
            (gid1.to_vec(), vec![0x11; 16]),
            (gid2.to_vec(), vec![0x22; 16]),
        ]);
        server.ctx.set_kbroad_registry(Some(registry));

        server.initialize_registered_groups_barrier_state()?;

        for gid in [gid1, gid2] {
            let roster_state = server
                .roster
                .groups
                .get(gid.as_slice())
                .ok_or(CityGError::InvalidInput("missing roster group"))?;
            assert!(roster_state.barrier_initialized);
            assert_eq!(roster_state.barrier_version, 0);
            assert_eq!(roster_state.n_max, super::DEFAULT_BARRIER_N_MAX);
            assert!(roster_state.max_barrier_update_bytes >= 1);
            assert!(
                roster_state
                    .barrier_public_tree_history
                    .contains_key(&roster_state.kem_tree_hash_after),
                "bootstrapped registry group should retain its committed tree snapshot"
            );

            let ctx_state = server
                .ctx
                .barrier_group_state(&gid)
                .ok_or(CityGError::InvalidInput("missing ctx barrier group"))?;
            assert!(ctx_state.barrier_initialized);
            assert_eq!(ctx_state.barrier_version, 0);
            assert_eq!(ctx_state.n_max, super::DEFAULT_BARRIER_N_MAX);
            assert_eq!(
                ctx_state.kem_tree_hash_after,
                roster_state.kem_tree_hash_after
            );
        }

        Ok(())
    }

    #[test]
    fn initialize_registered_groups_barrier_state_ignores_non_32_byte_registry_keys()
    -> Result<(), CityGError> {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid = [0x33; 32];
        let registry = BTreeMap::from([
            (gid.to_vec(), vec![0x11; 16]),
            (vec![0x22; 31], vec![0x33; 16]),
        ]);
        server.ctx.set_kbroad_registry(Some(registry));

        server.initialize_registered_groups_barrier_state()?;

        assert!(server.roster.groups.contains_key(gid.as_slice()));
        assert!(
            !server.roster.groups.contains_key(vec![0x22; 31].as_slice()),
            "malformed registry gid must be ignored during bootstrap"
        );
        Ok(())
    }

    #[test]
    fn register_group_reuses_existing_historyless_state_and_clears_stale_metadata()
    -> Result<(), CityGError> {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid = [0x34; 32];
        let state = server.roster.groups.entry(gid.to_vec()).or_default();
        state.rotation_required = true;
        state.kbroad_generation = 9;
        state.n_max = 8;

        server.register_group(&gid, vec![0x77; 16])?;

        let roster_state = server
            .roster
            .groups
            .get(gid.as_slice())
            .ok_or(CityGError::InvalidInput("missing roster state"))?;
        assert!(!roster_state.rotation_required);
        assert_eq!(roster_state.kbroad_generation, 0);
        assert_eq!(roster_state.n_max, 8);
        assert!(roster_state.barrier_initialized);
        assert!(
            roster_state
                .barrier_public_tree_history
                .contains_key(&roster_state.kem_tree_hash_after)
        );
        Ok(())
    }

    #[test]
    fn apply_persisted_kbroad_state_rebuilds_current_snapshot_when_history_is_invalid()
    -> Result<(), CityGError> {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid = [0x93; 32];
        let pk_entries = vec![vec![0x11; 4], vec![0x22; 4], vec![0x33; 4]];
        let current_hash = compute_barrier_tree_hash(2, pk_entries.as_slice())?;
        let state = BTreeMap::from([(
            gid.to_vec(),
            PersistedKbroadRoomState {
                kbroad_public: vec![0x44; 16],
                kbroad_generation: 7,
                rotation_required: true,
                room_admin_pop_keys: Vec::new(),
                room_admin_proof_replay_keys: Vec::new(),
                revoked_leaf_ids_hex: Vec::new(),
                barrier_initialized: true,
                barrier_version: 5,
                barrier_roots_hash: [0x55; 32],
                kem_tree_hash_after: current_hash,
                last_checkpoint_ec: 21,
                last_accepted_ec: 34,
                srx_root_sw: Some([0x66; 32]),
                barrier_pk_entries: pk_entries.clone(),
                barrier_public_tree_blobs: Vec::new(),
                barrier_public_tree_history: vec![PersistedBarrierPublicTreeSnapshot {
                    kem_tree_hash_after_hex: "not-hex".to_string(),
                    barrier_version: 5,
                    history_view_id_hex: String::new(),
                    history_commitment: super::PersistedHistoryCommitment::default(),
                    blob_indices: Vec::new(),
                    pk_entries: vec![vec![0x99; 3]],
                }],
                n_max: 2,
                last_pcs_refresh_ec: Some(12),
                pcs_refresh_min_delta_device_ec: 0,
                pcs_refresh_min_delta_group_ec: 0,
                pcs_refresh_slot_width_ec: 0,
                max_barrier_update_bytes: 0,
                accepted_barrier_merges: Vec::new(),
                current_history_commitment: super::PersistedHistoryCommitment::default(),
                current_accepted_barrier_update: Vec::new(),
                current_accepted_barrier_predecessor_hash: [0u8; 32],
                pending_join_finalize_auth: Vec::new(),
                device_chain_states: Vec::new(),
            },
        )]);

        server.apply_persisted_kbroad_state(&state)?;

        let group = server
            .roster
            .groups
            .get(gid.as_slice())
            .ok_or(CityGError::InvalidInput("missing restored group"))?;
        assert_eq!(group.kbroad_generation, 7);
        assert!(group.rotation_required);
        assert_eq!(group.barrier_public_tree_history.len(), 1);
        assert_eq!(
            super::history_barrier_public_tree_entries(group, &current_hash).as_ref(),
            Some(&pk_entries)
        );
        assert_eq!(group.max_barrier_update_bytes, 1);

        let ctx_state = server
            .ctx
            .barrier_group_state(&gid)
            .ok_or(CityGError::InvalidInput("missing restored ctx state"))?;
        assert_eq!(ctx_state.kem_tree_hash_after, current_hash);
        assert_eq!(ctx_state.n_max, 2);
        assert_eq!(ctx_state.last_checkpoint_ec, 21);
        assert_eq!(ctx_state.last_accepted_ec, 34);
        assert_eq!(ctx_state.max_barrier_update_bytes, 1);
        Ok(())
    }

    #[test]
    fn apply_persisted_kbroad_state_keeps_history_and_adds_missing_current_snapshot()
    -> Result<(), CityGError> {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid = [0x94; 32];
        let historical_entries = vec![vec![0x01; 4], vec![0x02; 4], vec![0x03; 4]];
        let current_entries = vec![vec![0x04; 4], vec![0x05; 4], vec![0x06; 4]];
        let historical_hash = compute_barrier_tree_hash(2, historical_entries.as_slice())?;
        let current_hash = compute_barrier_tree_hash(2, current_entries.as_slice())?;
        let state = BTreeMap::from([(
            gid.to_vec(),
            PersistedKbroadRoomState {
                kbroad_public: vec![0x77; 16],
                kbroad_generation: 2,
                rotation_required: false,
                room_admin_pop_keys: Vec::new(),
                room_admin_proof_replay_keys: Vec::new(),
                revoked_leaf_ids_hex: Vec::new(),
                barrier_initialized: true,
                barrier_version: 8,
                barrier_roots_hash: [0x88; 32],
                kem_tree_hash_after: current_hash,
                last_checkpoint_ec: 55,
                last_accepted_ec: 89,
                srx_root_sw: None,
                barrier_pk_entries: current_entries.clone(),
                barrier_public_tree_blobs: Vec::new(),
                barrier_public_tree_history: vec![PersistedBarrierPublicTreeSnapshot {
                    kem_tree_hash_after_hex: hex::encode(historical_hash),
                    barrier_version: 7,
                    history_view_id_hex: String::new(),
                    history_commitment: super::PersistedHistoryCommitment::default(),
                    blob_indices: Vec::new(),
                    pk_entries: historical_entries.clone(),
                }],
                n_max: 2,
                last_pcs_refresh_ec: None,
                pcs_refresh_min_delta_device_ec: 3,
                pcs_refresh_min_delta_group_ec: 4,
                pcs_refresh_slot_width_ec: 5,
                max_barrier_update_bytes: 99,
                accepted_barrier_merges: Vec::new(),
                current_history_commitment: super::PersistedHistoryCommitment::default(),
                current_accepted_barrier_update: Vec::new(),
                current_accepted_barrier_predecessor_hash: [0u8; 32],
                pending_join_finalize_auth: Vec::new(),
                device_chain_states: Vec::new(),
            },
        )]);

        server.apply_persisted_kbroad_state(&state)?;

        let group = server
            .roster
            .groups
            .get(gid.as_slice())
            .ok_or(CityGError::InvalidInput("missing restored group"))?;
        assert_eq!(group.barrier_public_tree_history.len(), 2);
        assert_eq!(
            super::history_barrier_public_tree_entries(group, &historical_hash).as_ref(),
            Some(&historical_entries)
        );
        assert_eq!(
            super::history_barrier_public_tree_entries(group, &current_hash).as_ref(),
            Some(&current_entries)
        );
        assert_eq!(group.pcs_refresh_min_delta_device_ec, 3);
        assert_eq!(group.pcs_refresh_min_delta_group_ec, 4);
        assert_eq!(group.pcs_refresh_slot_width_ec, 5);
        assert_eq!(group.max_barrier_update_bytes, 99);
        assert_eq!(group.last_checkpoint_ec, 55);
        assert_eq!(group.last_accepted_ec, 89);
        Ok(())
    }

    #[test]
    fn apply_persisted_kbroad_state_restores_revoked_leaf_set() -> Result<(), CityGError> {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid = [0x9Au8; 32];
        let revoked_leaf = [0xBC; 32];
        let state = BTreeMap::from([(
            gid.to_vec(),
            PersistedKbroadRoomState {
                kbroad_public: vec![0x77; 16],
                revoked_leaf_ids_hex: vec![hex::encode(revoked_leaf)],
                ..PersistedKbroadRoomState::default()
            },
        )]);

        server.apply_persisted_kbroad_state(&state)?;

        let group = server
            .roster
            .groups
            .get(gid.as_slice())
            .ok_or(CityGError::InvalidInput("missing restored group"))?;
        assert!(group.revoked.contains(&revoked_leaf));
        assert!(server.roster.has_history(&gid));
        Ok(())
    }

    #[test]
    fn apply_persisted_kbroad_state_restores_accepted_barrier_merges() -> Result<(), CityGError> {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid = [0x95; 32];
        let state = BTreeMap::from([(
            gid.to_vec(),
            PersistedKbroadRoomState {
                kbroad_public: vec![0x77; 16],
                barrier_initialized: true,
                barrier_version: 11,
                last_accepted_ec: 22,
                n_max: 2,
                accepted_barrier_merges: vec![super::PersistedAcceptedBarrierMergeRecord {
                    barrier_version: 11,
                    fs_ec: 22,
                    reason: 1,
                    digest_hex: "ab".repeat(32),
                    we_epoch_id_hex: "cd".repeat(32),
                }],
                ..PersistedKbroadRoomState::default()
            },
        )]);

        server.apply_persisted_kbroad_state(&state)?;
        let lookup = server.lookup_merge_acceptance(&gid, 11, &[0xAB; 32], &[0xCD; 32])?;
        assert_eq!(lookup.status, super::MergeAcceptanceStatus::Accepted);
        assert_eq!(lookup.accepted_barrier_version, Some(11));
        assert_eq!(lookup.accepted_fs_ec, Some(22));
        assert_eq!(lookup.accepted_reason, Some(1));
        assert_eq!(lookup.accepted_digest, Some([0xAB; 32]));
        Ok(())
    }

    #[test]
    fn lookup_merge_acceptance_returns_superseded_for_mismatched_locator() -> Result<(), CityGError>
    {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid = [0x96; 32];
        let group = server.roster.groups.entry(gid.to_vec()).or_default();
        group.barrier_initialized = true;
        group.barrier_version = 9;
        group.last_accepted_ec = 17;
        group.accepted_barrier_merges.insert(
            9,
            super::AcceptedBarrierMergeRecord {
                barrier_version: 9,
                fs_ec: 17,
                reason: 2,
                digest: [0x11; 32],
                we_epoch_id: [0x22; 32],
            },
        );

        let lookup = server.lookup_merge_acceptance(&gid, 9, &[0x33; 32], &[0x44; 32])?;
        assert_eq!(lookup.status, super::MergeAcceptanceStatus::Superseded);
        assert_eq!(lookup.accepted_digest, Some([0x11; 32]));
        assert_eq!(lookup.accepted_reason, Some(2));
        Ok(())
    }

    #[test]
    fn lookup_merge_acceptance_returns_final_rejected_after_version_advances_without_record()
    -> Result<(), CityGError> {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid = [0x97; 32];
        let group = server.roster.groups.entry(gid.to_vec()).or_default();
        group.barrier_initialized = true;
        group.barrier_version = 12;
        group.last_accepted_ec = 19;

        let lookup = server.lookup_merge_acceptance(&gid, 11, &[0x55; 32], &[0x66; 32])?;
        assert_eq!(lookup.status, super::MergeAcceptanceStatus::FinalRejected);
        assert_eq!(lookup.accepted_barrier_version, None);
        assert_eq!(lookup.accepted_fs_ec, None);
        assert_eq!(lookup.accepted_reason, None);
        assert_eq!(lookup.accepted_digest, None);
        Ok(())
    }

    #[test]
    fn apply_persisted_kbroad_state_rejects_oversized_n_max() {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid = [0x95; 32];
        let state = BTreeMap::from([(
            gid.to_vec(),
            PersistedKbroadRoomState {
                kbroad_public: vec![0x11; 16],
                n_max: super::MAX_BARRIER_N_MAX * 2,
                ..PersistedKbroadRoomState::default()
            },
        )]);

        let err = server
            .apply_persisted_kbroad_state(&state)
            .expect_err("oversized n_max must fail closed");
        assert!(matches!(
            err,
            CityGError::InvalidInput(message) if message.contains("MAX_BARRIER_N_MAX")
        ));
    }

    #[test]
    fn validate_barrier_n_max_rejects_invalid_shapes_and_oversized_values() {
        assert_eq!(
            super::validate_barrier_n_max(super::DEFAULT_BARRIER_N_MAX)
                .expect("default n_max must be valid"),
            super::DEFAULT_BARRIER_N_MAX
        );
        assert!(super::validate_barrier_n_max(0).is_err());
        assert!(super::validate_barrier_n_max(3).is_err());
        assert!(super::validate_barrier_n_max(super::MAX_BARRIER_N_MAX * 2).is_err());
    }

    #[test]
    fn snapshot_kbroad_state_captures_group_state_and_registry_defaults() -> Result<(), CityGError>
    {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid_with_group = [0x95; 32];
        let gid_without_group = [0x96; 32];
        let tree_entries = vec![vec![0x10; 4], vec![0x20; 4], vec![0x30; 4]];
        let tree_hash = compute_barrier_tree_hash(2, tree_entries.as_slice())?;

        let registry = BTreeMap::from([
            (gid_with_group.to_vec(), vec![0xAA; 16]),
            (gid_without_group.to_vec(), vec![0xBB; 16]),
        ]);
        server.ctx.set_kbroad_registry(Some(registry));
        server.ctx.insert_device_chain_state(
            gid_with_group.as_slice(),
            &[0xD1; 32],
            msphf_orchestrator::DeviceChainState {
                last_commit: Some([0xE2; 32]),
                last_ec: 17,
                last_pcs_refresh_ec: Some(9),
            },
        );

        let group = server
            .roster
            .groups
            .entry(gid_with_group.to_vec())
            .or_default();
        group.kbroad_generation = 4;
        group.rotation_required = true;
        group.barrier_initialized = true;
        group.barrier_version = 6;
        group.barrier_roots_hash = [0xC3; 32];
        group.kem_tree_hash_after = tree_hash;
        group.srx_root_sw = Some([0xF4; 32]);
        group.barrier_pk_entries = tree_entries.clone();
        super::record_barrier_public_tree_snapshot(&gid_with_group, group)?;
        group.n_max = 0;
        group.last_pcs_refresh_ec = Some(11);
        group.pcs_refresh_min_delta_device_ec = 0;
        group.pcs_refresh_min_delta_group_ec = 0;
        group.pcs_refresh_slot_width_ec = 0;
        group.max_barrier_update_bytes = 0;

        let snapshot = server.snapshot_kbroad_state();
        let with_group = snapshot
            .get(gid_with_group.as_slice())
            .ok_or(CityGError::InvalidInput("missing persisted grouped room"))?;
        assert_eq!(with_group.kbroad_public, vec![0xAA; 16]);
        assert_eq!(with_group.kbroad_generation, 4);
        assert!(with_group.rotation_required);
        assert!(with_group.barrier_initialized);
        assert_eq!(with_group.barrier_version, 6);
        assert_eq!(with_group.kem_tree_hash_after, tree_hash);
        assert_eq!(with_group.srx_root_sw, Some([0xF4; 32]));
        assert_eq!(with_group.n_max, 1);
        assert_eq!(with_group.pcs_refresh_min_delta_device_ec, 1);
        assert_eq!(with_group.pcs_refresh_min_delta_group_ec, 1);
        assert_eq!(with_group.pcs_refresh_slot_width_ec, 1);
        assert_eq!(with_group.device_chain_states.len(), 1);
        assert_eq!(
            with_group.barrier_public_tree_history[0].kem_tree_hash_after_hex,
            hex::encode(tree_hash)
        );
        assert!(
            with_group
                .barrier_public_tree_blobs
                .starts_with(tree_entries.as_slice()),
            "persisted blobs must retain the live tree entries in-order"
        );
        assert!(
            with_group.barrier_public_tree_blobs[tree_entries.len()..]
                .iter()
                .all(|entry| entry.is_empty()),
            "any additional persisted blobs must be empty placeholders"
        );
        assert!(
            with_group.barrier_public_tree_history[0]
                .blob_indices
                .starts_with(&[0, 1, 2]),
            "persisted history must reference the live tree-entry blob prefix"
        );
        assert!(
            with_group.barrier_public_tree_history[0]
                .pk_entries
                .is_empty()
        );

        let without_group = snapshot
            .get(gid_without_group.as_slice())
            .ok_or(CityGError::InvalidInput("missing default persisted room"))?;
        assert_eq!(without_group.kbroad_public, vec![0xBB; 16]);
        assert_eq!(without_group.kbroad_generation, 0);
        assert!(!without_group.rotation_required);
        assert!(!without_group.barrier_initialized);
        assert_eq!(without_group.n_max, super::DEFAULT_BARRIER_N_MAX);
        assert_eq!(
            without_group.max_barrier_update_bytes,
            super::default_max_barrier_update_bytes()
        );
        assert!(without_group.barrier_public_tree_history.is_empty());
        assert!(without_group.device_chain_states.is_empty());
        Ok(())
    }

    #[test]
    fn group_state_defaults_include_barrier_policy_bounds() -> Result<(), CityGError> {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid = [0xD1; 32];
        server.register_group(&gid, vec![0x11; 16])?;
        let state = server
            .roster
            .groups
            .get(gid.as_slice())
            .expect("group should exist after registration");
        assert_eq!(state.n_max, super::DEFAULT_BARRIER_N_MAX);
        assert!(state.n_max.is_power_of_two());
        assert!(state.pcs_refresh_min_delta_device_ec >= 1);
        assert!(state.pcs_refresh_min_delta_group_ec >= 1);
        assert!(state.pcs_refresh_slot_width_ec >= 1);
        Ok(())
    }

    #[test]
    fn build_join_ticket_requires_kbroad_and_advances_leaf_index() -> Result<(), CityGError> {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid = [0x42; 32];

        let err = server
            .build_join_ticket(&gid)
            .expect_err("missing kbroad should fail");
        assert!(matches!(
            err,
            CityGError::InvalidInput("kbroad key missing")
        ));

        server.register_group(&gid, vec![0x55; 16])?;
        let first = server.build_join_ticket(&gid)?;
        let second = server.build_join_ticket(&gid)?;
        assert!(super::leaf_index(&second.leaf_id) > super::leaf_index(&first.leaf_id));

        let mut demo_server = super::demo::demo_server();
        let bundle = cityg_client::demo::demo_bundle("alice")?;
        demo_server.accept_epoch(&bundle)?;
        let err = demo_server
            .build_join_ticket(&cityg_client::demo::DEMO_GID)
            .expect_err("join ticket must fail closed until current barrier_update is accepted");
        assert!(matches!(
            err,
            CityGError::InvalidInput("current barrier_update missing for join provisioning")
        ));
        Ok(())
    }

    #[test]
    fn build_join_ticket_with_leaf_uses_requested_leaf_and_rejects_duplicates()
    -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let gid = cityg_client::demo::DEMO_GID;
        let requested_leaf = cityg_client::demo::demo_member_leaf("bound-leaf");

        let ticket = server.build_join_ticket_with_leaf(&gid, Some(requested_leaf))?;
        assert_eq!(ticket.leaf_id, requested_leaf);

        let mut membership = cityg_client::GroupMembership::default();
        membership.apply_delta(&cityg_client::MembershipDelta {
            joined: vec![requested_leaf],
            revoked: Vec::new(),
        });
        let root = msphf_core::merkle::canonical_set_root(&[requested_leaf])?;
        let mut state = super::GroupState::default();
        state.snapshots.insert(root, membership);
        state.latest_root = Some(root);
        server.roster.groups.insert(gid.to_vec(), state);

        let err = server
            .build_join_ticket_with_leaf(&gid, Some(requested_leaf))
            .expect_err("duplicate requested leaf must fail");
        assert!(matches!(
            err,
            CityGError::InvalidInput("leaf already present in roster")
        ));
        Ok(())
    }

    #[test]
    fn build_join_ticket_with_leaf_rejects_cover_index_collisions() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let gid = cityg_client::demo::DEMO_GID;
        let active_leaf = colliding_cover_leaf(5);
        let colliding_leaf = colliding_cover_leaf(1029);

        let mut membership = cityg_client::GroupMembership::default();
        membership.apply_delta(&cityg_client::MembershipDelta {
            joined: vec![active_leaf],
            revoked: Vec::new(),
        });
        let root = msphf_core::merkle::canonical_set_root(&[active_leaf])?;
        let mut state = super::GroupState::default();
        state.snapshots.insert(root, membership);
        state.latest_root = Some(root);
        server.roster.groups.insert(gid.to_vec(), state);

        let err = server
            .build_join_ticket_with_leaf(&gid, Some(colliding_leaf))
            .expect_err("colliding cover index must be rejected");
        assert!(matches!(
            err,
            CityGError::InvalidInput(super::COVER_LEAF_INDEX_ALREADY_ALLOCATED_ERR)
        ));
        Ok(())
    }

    #[test]
    fn stale_group_second_join_accepts_without_autonomic_evolve() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let gid = cityg_client::demo::DEMO_GID;

        let first_member = build_genesis_member_bundle(0x75)?;
        server.accept_epoch(&first_member.bundle)?;
        let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;

        // Force the canonical FS base far enough behind wall clock that a fresh
        // client's autonomic catch-up overshoots the group's time-blind cap.
        server.context_mut().set_fs_base_ts(Some(1));

        let forward_jumping = build_join_bundle_from_server_ticket(&mut server, &gid, 0x76, false)?;
        let err = server
            .accept_epoch(&forward_jumping)
            .expect_err("autonomic-evolved second join should exceed the stale group cap");
        match err {
            CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze)) => {
                assert_eq!(freeze.code, 9476);
                assert_eq!(freeze.reason, "fs_forward_jump_group");
            }
            _ => {
                return Err(CityGError::InvalidInput(
                    "unexpected stale-group join error",
                ));
            }
        }

        let recovered = build_join_bundle_from_server_ticket(&mut server, &gid, 0x77, true)?;
        assert_eq!(u64_from_header(&recovered.header_map, hdr::HDR_FS_EC)?, 0);
        server.accept_epoch(&recovered)?;

        let latest_root =
            server
                .latest_parent_root(gid.as_slice())
                .ok_or(CityGError::InvalidInput(
                    "latest root missing after stale-group retry",
                ))?;
        let members = server
            .members_for_root(gid.as_slice(), &latest_root)
            .ok_or(CityGError::InvalidInput(
                "members missing after stale-group retry",
            ))?;
        assert_eq!(members.len(), 2);
        Ok(())
    }

    #[test]
    fn build_merge_ticket_reports_missing_anchor_leaf_and_parity() -> Result<(), CityGError> {
        let gid = [0x24; 32];
        let leaf = cityg_client::demo::demo_member_leaf("merge");

        let mut empty = CityGServer::new(ServerConfig::new());
        let err = empty
            .build_merge_ticket(&gid, &leaf)
            .err()
            .expect("empty server should reject merge ticket");
        assert!(matches!(
            err,
            CityGError::InvalidInput("no anchors accepted for group")
        ));

        let mut server = CityGServer::new(ServerConfig::new());
        let mut membership = cityg_client::GroupMembership::default();
        membership.apply_delta(&cityg_client::MembershipDelta {
            joined: vec![leaf],
            revoked: Vec::new(),
        });
        let root = msphf_core::merkle::canonical_set_root(&[leaf])?;
        let mut state = super::GroupState::default();
        state.snapshots.insert(root, membership);
        state.latest_root = Some(root);
        server.roster.groups.insert(gid.to_vec(), state);
        let mut registry = BTreeMap::new();
        registry.insert(gid.to_vec(), vec![0x77; 16]);
        server.context_mut().set_kbroad_registry(Some(registry));

        let missing_leaf_err = server
            .build_merge_ticket(&gid, &[0xFF; 32])
            .err()
            .expect("unknown leaf should fail before parity lookup");
        assert!(matches!(
            missing_leaf_err,
            CityGError::InvalidInput("leaf not present in roster")
        ));

        let no_parity_err = server
            .build_merge_ticket(&gid, &leaf)
            .err()
            .expect("missing parity should fail");
        assert!(matches!(
            no_parity_err,
            CityGError::InvalidInput("no pivot parity available")
        ));
        Ok(())
    }

    #[test]
    fn build_merge_ticket_rejects_unknown_membership_root() -> Result<(), CityGError> {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid = [0x25; 32];
        let leaf = cityg_client::demo::demo_member_leaf("merge-root");
        let state = super::GroupState {
            latest_root: Some([0xAB; 32]),
            ..super::GroupState::default()
        };
        server.roster.groups.insert(gid.to_vec(), state);

        let err = match server.build_merge_ticket(&gid, &leaf) {
            Ok(_) => return Err(CityGError::InvalidInput("missing snapshot for latest root")),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            CityGError::InvalidInput("unknown membership root")
        ));
        Ok(())
    }

    #[test]
    fn build_merge_ticket_preserves_existing_revoked_membership() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let bundle = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&bundle)?;

        let gid = cityg_client::demo::DEMO_GID;
        let leaf_id = cityg_client::demo::demo_member_leaf("alice");
        let group = server
            .roster
            .groups
            .get_mut(gid.as_slice())
            .ok_or(CityGError::InvalidInput("missing group state"))?;
        group.revoked.insert(leaf_id);

        let ticket = server.build_merge_ticket(&gid, &leaf_id)?;
        let expected_root = msphf_core::merkle::canonical_set_root(&[leaf_id])?;
        assert_eq!(ticket.revoked_since_root, expected_root);
        assert_eq!(ticket.revoked_root, expected_root);
        Ok(())
    }

    #[test]
    fn build_merge_ticket_requires_kbroad_even_with_live_roster_and_parity()
    -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let bundle = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&bundle)?;
        server.context_mut().set_kbroad_registry(None);

        let err = match server.build_merge_ticket(
            &cityg_client::demo::DEMO_GID,
            &cityg_client::demo::demo_member_leaf("alice"),
        ) {
            Ok(_) => return Err(CityGError::InvalidInput("expected kbroad key miss")),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            CityGError::InvalidInput("kbroad key missing")
        ));
        Ok(())
    }

    #[test]
    fn build_merge_ticket_falls_back_on_invalid_utf8_ids() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let bundle = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&bundle)?;

        let gid = cityg_client::demo::DEMO_GID;
        let parent_root = server
            .latest_parent_root(gid.as_slice())
            .ok_or(CityGError::InvalidInput("latest root missing"))?;
        let leaf_id = cityg_client::demo::demo_member_leaf("alice");
        let mut parity = server
            .context_mut()
            .pivot_parities_for(gid.as_slice(), &parent_root)
            .into_iter()
            .next()
            .ok_or(CityGError::InvalidInput("pivot parity missing"))?;
        parity.we_epoch_id = [0u8; 32];
        parity.crs_id = vec![0xFF];
        parity.params_id = vec![0xFE];
        let now = server.context().current_time();
        server.context_mut().insert_pivot_parity(parity, now);

        let ticket = server.build_merge_ticket(&gid, &leaf_id)?;
        assert_eq!(ticket.msphf_crs_id, msphf_core::params::RLWE_CRS_ID_DEFAULT);
        assert_eq!(
            ticket.msphf_params_id,
            msphf_core::params::RLWE_PARAMS_ID_MOCK
        );
        Ok(())
    }

    #[test]
    fn build_merge_ticket_prefers_highest_accept_seq_and_tie_breaks_on_weid()
    -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let bundle = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&bundle)?;

        let gid = cityg_client::demo::DEMO_GID;
        let parent_root = server
            .latest_parent_root(gid.as_slice())
            .ok_or(CityGError::InvalidInput("latest root missing"))?;
        let leaf_id = cityg_client::demo::demo_member_leaf("alice");
        let base_parity = server
            .context_mut()
            .pivot_parities_for(gid.as_slice(), &parent_root)
            .into_iter()
            .next()
            .ok_or(CityGError::InvalidInput("pivot parity missing"))?;
        let now = server.context().current_time();
        let wid = server
            .context()
            .mh_window
            .find_head_window(&base_parity.we_epoch_id)
            .ok_or(CityGError::InvalidInput("pivot head missing"))?;

        let mut higher_seq = base_parity.clone();
        higher_seq.accept_seq = base_parity.accept_seq.saturating_add(5);
        higher_seq.we_epoch_id = [0xEE; 32];
        higher_seq.proof_mode = "higher-seq".to_string();
        higher_seq.vrf_id = "higher-seq".to_string();
        higher_seq.policy_version = "41".to_string();
        server
            .context_mut()
            .mh_window
            .accept_head(
                wid.as_slice(),
                HeadRecord::new(
                    higher_seq.we_epoch_id,
                    higher_seq.hp_commit,
                    higher_seq.seed_ctx_hash,
                    higher_seq.rho_commit,
                    higher_seq.seed_commit,
                    higher_seq.xk_hash,
                    higher_seq.join_delta_root,
                    higher_seq.revoked_since_root,
                    higher_seq.revoked_root,
                    higher_seq.accept_seq,
                    now,
                ),
                now,
            )
            .map_err(|err| {
                CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(err))
            })?;
        server.context_mut().insert_pivot_parity(higher_seq, now);

        let mut tie_winner = base_parity.clone();
        tie_winner.accept_seq = base_parity.accept_seq.saturating_add(5);
        tie_winner.we_epoch_id = [0x11; 32];
        tie_winner.proof_mode = "tie-winner".to_string();
        tie_winner.vrf_id = "tie-winner".to_string();
        tie_winner.policy_version = "42".to_string();
        server
            .context_mut()
            .mh_window
            .accept_head(
                wid.as_slice(),
                HeadRecord::new(
                    tie_winner.we_epoch_id,
                    tie_winner.hp_commit,
                    tie_winner.seed_ctx_hash,
                    tie_winner.rho_commit,
                    tie_winner.seed_commit,
                    tie_winner.xk_hash,
                    tie_winner.join_delta_root,
                    tie_winner.revoked_since_root,
                    tie_winner.revoked_root,
                    tie_winner.accept_seq,
                    now,
                ),
                now,
            )
            .map_err(|err| {
                CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(err))
            })?;
        server.context_mut().insert_pivot_parity(tie_winner, now);

        let ticket = server.build_merge_ticket(&gid, &leaf_id)?;
        assert_eq!(ticket.pivot_we_epoch_id, [0x11; 32]);
        assert_eq!(ticket.proof_mode, "tie-winner");
        assert_eq!(ticket.vrf_id, "tie-winner");
        assert_eq!(ticket.policy_version, "42");
        Ok(())
    }

    #[test]
    fn build_merge_ticket_ignores_stale_parity_without_live_head() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let bundle = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&bundle)?;

        let gid = cityg_client::demo::DEMO_GID;
        let parent_root = server
            .latest_parent_root(gid.as_slice())
            .ok_or(CityGError::InvalidInput("latest root missing"))?;
        let leaf_id = cityg_client::demo::demo_member_leaf("alice");
        let base_parity = server
            .context_mut()
            .pivot_parities_for(gid.as_slice(), &parent_root)
            .into_iter()
            .next()
            .ok_or(CityGError::InvalidInput("pivot parity missing"))?;
        let now = server.context().current_time();

        let mut stale = base_parity.clone();
        stale.accept_seq = base_parity.accept_seq.saturating_add(9);
        stale.we_epoch_id = [0xEE; 32];
        stale.proof_mode = "stale".to_string();
        stale.vrf_id = "stale".to_string();
        stale.policy_version = "99".to_string();
        server.context_mut().insert_pivot_parity(stale, now);

        let ticket = server.build_merge_ticket(&gid, &leaf_id)?;
        assert_eq!(
            ticket.pivot_we_epoch_id, base_parity.we_epoch_id,
            "merge ticket must ignore parity entries whose heads are no longer live in mh_window"
        );
        Ok(())
    }

    #[test]
    fn join_root_carries_forward_live_checkpoint_parity() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let alice = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&alice)?;

        let gid = cityg_client::demo::DEMO_GID;
        let alice_root = server
            .latest_parent_root(gid.as_slice())
            .ok_or(CityGError::InvalidInput("latest root missing"))?;
        let now = server.context().current_time();
        let mut carried = server
            .context_mut()
            .pivot_parities_for(gid.as_slice(), &alice_root)
            .into_iter()
            .next()
            .ok_or(CityGError::InvalidInput("pivot parity missing"))?;
        carried.fs_ec = Some(carried.fs_ec.unwrap_or(0).saturating_add(50));
        server
            .context_mut()
            .insert_pivot_parity(carried.clone(), now);

        let bob = cityg_client::demo::demo_bundle("bob")?;
        server.accept_epoch(&bob)?;

        let new_root = server
            .latest_parent_root(gid.as_slice())
            .ok_or(CityGError::InvalidInput("latest root missing after bob"))?;
        let bob_leaf = cityg_client::demo::demo_member_leaf("bob");
        let ticket = server.build_merge_ticket(&gid, &bob_leaf)?;
        let max_ticket_fs = ticket
            .parities
            .iter()
            .filter_map(|parity| parity.fs_ec)
            .max()
            .ok_or(CityGError::InvalidInput("ticket missing fs_ec"))?;
        assert_eq!(
            max_ticket_fs,
            carried.fs_ec.unwrap_or(0),
            "new roots must keep a live parity at least as fresh as the prior checkpoint window"
        );
        assert_eq!(ticket.parent_root, new_root);
        Ok(())
    }

    #[test]
    fn build_merge_ticket_defaults_fs_policy_and_base_ts_when_context_unset()
    -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let bundle = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&bundle)?;
        server.context_mut().set_fs_policy_version(None);
        server.context_mut().set_fs_base_ts(None);

        let ticket = server.build_merge_ticket(
            &cityg_client::demo::DEMO_GID,
            &cityg_client::demo::demo_member_leaf("alice"),
        )?;
        assert_eq!(ticket.fs_policy_version, "7");
        assert_eq!(ticket.fs_epoch_base_ts, 0);
        Ok(())
    }

    #[test]
    fn build_merge_ticket_for_refresh_preserves_existing_revoked_roots() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let bundle = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&bundle)?;

        let gid = cityg_client::demo::DEMO_GID;
        let leaf_id = cityg_client::demo::demo_member_leaf("alice");
        let extra_revoked = cityg_client::demo::demo_member_leaf("retired-bob");
        let group = server
            .roster
            .groups
            .get_mut(gid.as_slice())
            .ok_or(CityGError::InvalidInput("missing group state"))?;
        group.revoked.insert(leaf_id);
        group.revoked.insert(extra_revoked);

        let ticket = server.build_merge_ticket_for_refresh(&gid, &leaf_id)?;
        let mut expected_revoked = vec![extra_revoked, leaf_id];
        expected_revoked.sort();
        let expected_root = msphf_core::merkle::canonical_set_root(&expected_revoked)?;
        assert_eq!(ticket.revoked_since_root, expected_root);
        assert_eq!(ticket.revoked_root, expected_root);
        assert!(ticket.srx_cbor.is_empty());
        Ok(())
    }

    #[test]
    fn build_merge_ticket_for_refresh_keeps_revocation_roots_stable() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let bundle = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&bundle)?;

        let gid = cityg_client::demo::DEMO_GID;
        let leaf_id = cityg_client::demo::demo_member_leaf("alice");
        let leave_ticket = server.build_merge_ticket(&gid, &leaf_id)?;
        let refresh_ticket = server.build_merge_ticket_for_refresh(&gid, &leaf_id)?;

        assert_eq!(
            refresh_ticket.join_delta_root,
            cityg_client::witness::join_delta_root(&[])?
        );
        assert_eq!(
            refresh_ticket.revoked_since_root,
            refresh_ticket.revoked_root
        );
        assert_eq!(refresh_ticket.srx_cbor, Vec::<u8>::new());

        assert_ne!(
            leave_ticket.revoked_root, refresh_ticket.revoked_root,
            "leave ticket should stage self-revocation while refresh ticket must not"
        );
        Ok(())
    }

    #[test]
    fn header_helpers_cover_defaults_and_type_validation() {
        let mut map = BTreeMap::new();
        map.insert(1, Value::Bytes(vec![0x11; 32]));
        map.insert(2, Value::Bytes(vec![0x22]));
        map.insert(3, Value::Integer(7.into()));
        map.insert(4, Value::Null);
        map.insert(5, Value::Text("ok".to_string()));
        map.insert(6, Value::Bytes(vec![0x66, 0x67]));
        map.insert(7, Value::Bool(true));

        assert!(super::header_bytes32(&map, 1, "required").is_ok());
        assert!(matches!(
            super::header_bytes32(&map, 2, "required"),
            Err(CityGError::InvalidInput("pivot field wrong length"))
        ));
        assert!(matches!(
            super::header_bytes32(&map, 3, "required"),
            Err(CityGError::InvalidInput("pivot field wrong type"))
        ));
        assert!(matches!(
            super::header_bytes32(&map, 99, "required"),
            Err(CityGError::InvalidInput("required"))
        ));

        assert!(matches!(super::header_bytes32_opt(&map, 1), Ok(Some(_))));
        assert!(matches!(super::header_bytes32_opt(&map, 4), Ok(None)));
        assert!(matches!(
            super::header_bytes32_opt(&map, 2),
            Err(CityGError::InvalidInput("pivot field wrong length"))
        ));
        assert!(matches!(
            super::header_bytes32_opt(&map, 7),
            Err(CityGError::InvalidInput("pivot field wrong type"))
        ));

        assert!(matches!(
            super::header_bytes(&map, 3, "bytes"),
            Err(CityGError::InvalidInput("pivot field wrong type"))
        ));
        assert!(matches!(
            super::header_bytes(&map, 99, "bytes"),
            Err(CityGError::InvalidInput("bytes"))
        ));
        assert!(matches!(
            super::header_bytes_opt(&map, 3),
            Err(CityGError::InvalidInput("pivot field wrong type"))
        ));
        assert!(matches!(
            super::header_string(&map, 5, None),
            Ok(value) if value == "ok"
        ));
        assert!(matches!(
            super::header_string(&map, 6, None),
            Ok(value) if value == "fg"
        ));
        assert!(matches!(
            super::header_string(&map, 4, Some("fallback")),
            Ok(value) if value == "fallback"
        ));
        assert!(matches!(
            super::header_string(&map, 4, None),
            Err(CityGError::InvalidInput("pivot field missing"))
        ));
        assert!(matches!(
            super::header_string(&map, 7, None),
            Err(CityGError::InvalidInput("pivot field wrong type"))
        ));
        assert!(matches!(
            super::header_string(&map, 99, Some("fallback")),
            Ok(value) if value == "fallback"
        ));
    }

    #[test]
    fn parse_barrier_update_reason_covers_presence_and_bounds() {
        let empty = BTreeMap::new();
        assert!(matches!(
            super::parse_barrier_update_reason(&empty),
            Ok(None)
        ));

        let mut reason_without_update = BTreeMap::new();
        reason_without_update.insert(hdr::HDR_BARRIER_UPDATE_REASON, Value::Integer(1.into()));
        assert!(matches!(
            super::parse_barrier_update_reason(&reason_without_update),
            Err(CityGError::InvalidInput("barrier_update malformed"))
        ));

        let mut update_without_reason = BTreeMap::new();
        update_without_reason.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(vec![0xAA]));
        assert!(matches!(
            super::parse_barrier_update_reason(&update_without_reason),
            Err(CityGError::InvalidInput("barrier_update malformed"))
        ));

        let mut invalid_type = update_without_reason.clone();
        invalid_type.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Text("not-an-integer".to_string()),
        );
        assert!(matches!(
            super::parse_barrier_update_reason(&invalid_type),
            Err(CityGError::InvalidInput("barrier_update malformed"))
        ));

        let mut negative = update_without_reason.clone();
        negative.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(-1i64)),
        );
        assert!(matches!(
            super::parse_barrier_update_reason(&negative),
            Err(CityGError::InvalidInput("barrier_update malformed"))
        ));

        let mut too_large = update_without_reason.clone();
        too_large.insert(hdr::HDR_BARRIER_UPDATE_REASON, Value::Integer(3.into()));
        assert!(matches!(
            super::parse_barrier_update_reason(&too_large),
            Err(CityGError::InvalidInput("barrier_update malformed"))
        ));

        for reason in 0u64..=2 {
            let mut header = update_without_reason.clone();
            header.insert(
                hdr::HDR_BARRIER_UPDATE_REASON,
                Value::Integer(Integer::from(reason)),
            );
            assert_eq!(
                super::parse_barrier_update_reason(&header).expect("valid reason"),
                Some(reason)
            );
        }
    }

    #[test]
    fn parse_deterministic_cbor_rejects_noncanonical_map_bytes() {
        // Non-canonical key order for map {1:1, 0:0}; canonical form must sort keys.
        let noncanonical = vec![0xA2, 0x01, 0x01, 0x00, 0x00];
        let parsed = super::parse_deterministic_cbor::<BTreeMap<u8, u8>>(&noncanonical);
        assert!(matches!(
            parsed,
            Err(CityGError::InvalidInput("barrier_update malformed"))
        ));
    }

    #[test]
    fn barrier_tree_helpers_cover_resolution_and_size_errors() -> Result<(), CityGError> {
        let base = super::build_all_blank_pk_entries(4)?;
        assert_eq!(base.len(), 7);
        assert!(super::collect_expected_pairs(base.as_slice(), &[3, 1, 0], 4)?.is_empty());

        let mut with_target = base.clone();
        with_target[4] = vec![0x44; 1184];
        let pairs = super::collect_expected_pairs(with_target.as_slice(), &[3, 1, 0], 4)?;
        assert_eq!(pairs, vec![(1, 4)]);

        assert!(matches!(
            super::compute_barrier_tree_hash(0, &[] as &[&[u8]]),
            Err(CityGError::InvalidInput(_))
        ));
        Ok(())
    }

    #[test]
    fn barrier_tree_path_and_cow_helpers_cover_mutation_paths() -> Result<(), CityGError> {
        assert_eq!(super::direct_path_nodes(5), vec![5, 2, 0]);
        assert_eq!(super::sibling_node(0), None);
        assert_eq!(super::sibling_node(5), Some(6));
        assert_eq!(super::sibling_node(6), Some(5));

        let mut borrowed = vec![
            Cow::Borrowed(&[0x00][..]),
            Cow::Borrowed(&[0x01][..]),
            Cow::Borrowed(&[0x02][..]),
            Cow::Borrowed(&[0x03][..]),
            Cow::Borrowed(&[0x04][..]),
            Cow::Borrowed(&[0x05][..]),
            Cow::Borrowed(&[0x06][..]),
        ];
        super::blank_internal_path_from_leaf_cow(&mut borrowed, 5);
        assert_eq!(borrowed[5].as_ref(), &[0x05]);
        assert!(borrowed[2].is_empty());
        assert!(borrowed[0].is_empty());
        assert_eq!(borrowed[1].as_ref(), &[0x01]);

        super::blank_leaf_and_path_cow(&mut borrowed, 4);
        assert!(borrowed[4].is_empty());
        assert!(borrowed[1].is_empty());
        assert!(borrowed[0].is_empty());
        assert_eq!(borrowed[6].as_ref(), &[0x06]);

        let blanks = super::build_all_blank_pk_entries_cow(4)?;
        assert_eq!(blanks.len(), 7);
        assert!(blanks.iter().all(|entry| entry.is_empty()));
        assert!(matches!(
            super::build_all_blank_pk_entries_cow(u64::MAX),
            Err(CityGError::InvalidInput(_))
        ));
        Ok(())
    }

    #[test]
    fn barrier_resolution_and_pk_entries_cow_helpers_cover_branches() -> Result<(), CityGError> {
        let snapshot: Vec<Cow<'_, [u8]>> = vec![
            Cow::Borrowed(&[]),
            Cow::Borrowed(&[]),
            Cow::Borrowed(&[0xC2][..]),
            Cow::Borrowed(&[0xD3][..]),
            Cow::Borrowed(&[]),
            Cow::Borrowed(&[]),
            Cow::Borrowed(&[]),
        ];
        let mut targets = Vec::new();
        super::collect_resolution_nodes(snapshot.as_slice(), 0, 3, &mut targets);
        assert_eq!(targets, vec![3, 2]);

        let mut state = super::GroupState {
            n_max: 4,
            ..super::GroupState::default()
        };
        state.barrier_pk_entries = (0..7).map(|idx| vec![idx as u8]).collect();
        let borrowed = super::build_pk_entries_cow(&state)?;
        assert_eq!(borrowed.len(), 7);
        assert_eq!(borrowed[6].as_ref(), &[6]);
        Ok(())
    }

    #[test]
    fn barrier_tree_incremental_hash_matches_full_rehash() -> Result<(), CityGError> {
        let n_max = 8;
        let mut base = super::build_all_blank_pk_entries(n_max)?;
        base[7] = vec![0x01; 1184];
        base[8] = vec![0x02; 1184];
        base[10] = vec![0x03; 1184];

        let mut updated = base.clone();
        updated[0] = vec![0xA0; 1184];
        updated[2] = vec![0xA2; 1184];
        updated[6] = vec![0xA6; 1184];
        updated[10] = vec![0xAA; 1184];

        let mut changed = std::collections::BTreeSet::new();
        changed.insert(0usize);
        changed.insert(2usize);
        changed.insert(6usize);
        changed.insert(10usize);
        let mut before_cache = std::collections::HashMap::new();

        let incremental = super::compute_barrier_tree_hash_with_changes(
            n_max,
            updated.as_slice(),
            &changed,
            None,
            &mut before_cache,
        )?
        .0;
        let full = super::compute_barrier_tree_hash(n_max, updated.as_slice())?;
        assert_eq!(incremental, full);

        let empty_change = std::collections::BTreeSet::new();
        let unchanged = super::compute_barrier_tree_hash_with_changes(
            n_max,
            base.as_slice(),
            &empty_change,
            None,
            &mut before_cache,
        )?
        .0;
        assert_eq!(
            unchanged,
            super::compute_barrier_tree_hash(n_max, base.as_slice())?
        );

        let mut out_of_range = std::collections::BTreeSet::new();
        out_of_range.insert(usize::MAX);
        assert!(matches!(
            super::compute_barrier_tree_hash_with_changes(
                n_max,
                updated.as_slice(),
                &out_of_range,
                None,
                &mut before_cache,
            ),
            Err(CityGError::InvalidInput("barrier node index out of range"))
        ));

        Ok(())
    }

    #[test]
    fn barrier_tree_fallback_helpers_cover_empty_and_owned_paths() -> Result<(), CityGError> {
        let zero_state = super::GroupState {
            n_max: 0,
            ..super::GroupState::default()
        };
        assert!(matches!(
            super::build_pk_entries_view(&zero_state),
            Err(CityGError::InvalidInput(
                "barrier n_max must be a non-zero power of two"
            ))
        ));

        let mut state = super::GroupState {
            n_max: 4,
            ..super::GroupState::default()
        };
        super::record_barrier_public_tree_snapshot(&[0u8; 32], &mut state)?;
        assert!(state.barrier_public_tree_history.is_empty());

        let leaf = cityg_client::demo::demo_member_leaf("fallback-owned");
        let mut membership = cityg_client::GroupMembership::default();
        membership.apply_delta(&cityg_client::MembershipDelta {
            joined: vec![leaf],
            revoked: Vec::new(),
        });
        let root = msphf_core::merkle::canonical_set_root(&[leaf])?;
        state.snapshots.insert(root, membership);
        state.latest_root = Some(root);
        state.leaf_barrier_public.insert(leaf, vec![0x77; 1184]);

        let view = super::build_pk_entries_view(&state)?;
        let owned = match view {
            Cow::Borrowed(_) => {
                return Err(CityGError::InvalidInput(
                    "expected fallback builder to allocate owned entries",
                ));
            }
            Cow::Owned(entries) => entries,
        };
        assert_eq!(owned.len(), 7);
        let computed = super::compute_group_barrier_tree_hash(&state)?;
        assert_eq!(
            computed,
            super::compute_barrier_tree_hash(state.n_max, owned.as_slice())?
        );
        Ok(())
    }

    #[test]
    #[ignore = "manual benchmark: compare full rehash vs incremental barrier tree hash"]
    fn benchmark_barrier_tree_incremental_hash_vs_full_rehash() -> Result<(), CityGError> {
        fn hex_prefix4(bytes: &[u8; 32]) -> String {
            format!(
                "{:02x}{:02x}{:02x}{:02x}",
                bytes[0], bytes[1], bytes[2], bytes[3]
            )
        }

        fn synthetic_entries(n_max: u64) -> Result<Vec<Vec<u8>>, CityGError> {
            let n_max_usize = usize::try_from(n_max)
                .map_err(|_| CityGError::InvalidInput("barrier n_max too large"))?;
            let total = n_max_usize
                .checked_mul(2)
                .and_then(|v| v.checked_sub(1))
                .ok_or(CityGError::InvalidInput("barrier tree size overflow"))?;
            let mut out = Vec::with_capacity(total);
            for i in 0..total {
                if i % 11 == 0 {
                    out.push(vec![0xA5; 1184]);
                } else {
                    out.push(Vec::new());
                }
            }
            Ok(out)
        }

        for &(n_max, rounds, stride) in &[(1024u64, 200u64, 257usize), (2048u64, 120u64, 389usize)]
        {
            let base = synthetic_entries(n_max)?;
            let mut updated = base.clone();
            let mut changed_nodes = std::collections::BTreeSet::new();
            for idx in (0..updated.len()).step_by(stride) {
                updated[idx] = vec![0x5A; 1184];
                changed_nodes.insert(idx);
            }

            let full_start = std::time::Instant::now();
            let mut full_acc = [0u8; 32];
            for _ in 0..rounds {
                let before = super::compute_barrier_tree_hash(n_max, base.as_slice())?;
                let after = super::compute_barrier_tree_hash(n_max, updated.as_slice())?;
                for i in 0..full_acc.len() {
                    full_acc[i] ^= before[i] ^ after[i];
                }
            }
            let full_elapsed = full_start.elapsed();

            let incremental_start = std::time::Instant::now();
            let mut incr_acc = [0u8; 32];
            for _ in 0..rounds {
                let mut before_cache = std::collections::HashMap::new();
                let before = super::compute_barrier_subtree_hash_cached(
                    0,
                    n_max,
                    usize::try_from(n_max)
                        .map_err(|_| CityGError::InvalidInput("barrier n_max too large"))?,
                    base.as_slice(),
                    None,
                    &mut before_cache,
                )?;
                let after = super::compute_barrier_tree_hash_with_changes(
                    n_max,
                    updated.as_slice(),
                    &changed_nodes,
                    None,
                    &mut before_cache,
                )?
                .0;
                for i in 0..incr_acc.len() {
                    incr_acc[i] ^= before[i] ^ after[i];
                }
            }
            let incremental_elapsed = incremental_start.elapsed();

            assert_eq!(
                super::compute_barrier_tree_hash(n_max, updated.as_slice())?,
                super::compute_barrier_tree_hash_with_changes(
                    n_max,
                    updated.as_slice(),
                    &changed_nodes,
                    None,
                    &mut std::collections::HashMap::new(),
                )?
                .0,
                "incremental hash must remain equivalent to full rehash"
            );

            let full_ms = full_elapsed.as_secs_f64() * 1_000.0;
            let incremental_ms = incremental_elapsed.as_secs_f64() * 1_000.0;
            let speedup = full_ms / incremental_ms.max(1e-9);
            eprintln!(
                "BENCH[server_barrier_hash] n_max={n_max} rounds={rounds} changed_nodes={} full_total_ms={full_ms:.2} full_per_round_ms={:.3} incremental_total_ms={incremental_ms:.2} incremental_per_round_ms={:.3} speedup_x={speedup:.2} hash_prefix_full={} hash_prefix_incr={}",
                changed_nodes.len(),
                full_ms / (rounds as f64),
                incremental_ms / (rounds as f64),
                hex_prefix4(&full_acc),
                hex_prefix4(&incr_acc),
            );
        }

        Ok(())
    }

    #[test]
    fn validate_barrier_update_accepts_expected_pairs_and_pkhash_binding() -> Result<(), CityGError>
    {
        let mut state = super::GroupState {
            n_max: 4,
            ..super::GroupState::default()
        };
        state.barrier_initialized = true;
        state.barrier_version = 1;
        state.barrier_pk_entries = super::build_all_blank_pk_entries(state.n_max)?;
        let leaf = cityg_client::demo::demo_member_leaf("barrier-expected-pairs");
        let pop_pk = vec![0xAB; 32];
        state.leaf_device_pk.insert(leaf, pop_pk.clone());
        let join_finalize_auth_token = install_pending_join_finalize_auth(&mut state, leaf);
        let join_ek = vec![0xA5; 1184];
        let delta = cityg_client::MembershipDelta {
            joined: vec![leaf],
            revoked: Vec::new(),
        };
        let updater_leaf = super::cover_leaf_index(&leaf, state.n_max);
        let leaf_base = usize::try_from(state.n_max.saturating_sub(1))
            .map_err(|_| CityGError::InvalidInput("leaf base overflow"))?;
        let leaf_node = leaf_base
            + usize::try_from(updater_leaf)
                .map_err(|_| CityGError::InvalidInput("leaf index overflow"))?;
        let sibling_node = super::sibling_node(leaf_node)
            .ok_or(CityGError::InvalidInput("invalid updater leaf node"))?;
        let parent_node = (leaf_node - 1) / 2;
        let path_nodes = vec![leaf_node as u64, parent_node as u64, 0];

        let target_ek = vec![0x91; 1184];
        state.barrier_pk_entries[sibling_node] = target_ek.clone();
        state.kem_tree_hash_after =
            super::compute_barrier_tree_hash(state.n_max, state.barrier_pk_entries.as_slice())?;

        let mut snapshot_pre = state.barrier_pk_entries.clone();
        snapshot_pre[leaf_node] = join_ek.clone();
        super::blank_internal_path_from_leaf(snapshot_pre.as_mut_slice(), leaf_node);
        let kem_before = super::compute_barrier_tree_hash(state.n_max, snapshot_pre.as_slice())?;

        let mut snapshot_post = snapshot_pre.clone();
        let ek_root = vec![0x11; 1184];
        let ek_parent = vec![0x22; 1184];
        snapshot_post[0] = ek_root.clone();
        snapshot_post[parent_node] = ek_parent.clone();
        let kem_after = super::compute_barrier_tree_hash(state.n_max, snapshot_post.as_slice())?;

        let target_pkhash = super::compute_barrier_pkhash(target_ek.as_slice())?;
        let cover_payload = super::KemTreeCoverPayloadWire(
            u64::from(updater_leaf),
            path_nodes,
            None,
            vec![super::NodeCiphertextWire(
                parent_node as u64,
                sibling_node as u64,
                target_pkhash[..16].to_vec(),
                vec![0x33; 1088],
                vec![0x44; 48],
            )],
            vec![
                super::NewPublicKeyWire(0, ek_root),
                super::NewPublicKeyWire(parent_node as u64, ek_parent),
            ],
        );
        let cover_payload_bytes = super::to_cbor_vec(&cover_payload)?;

        let revoked_since = [0u8; 32];
        let revoked_root = [0u8; 32];
        let revocation_roots_hash =
            super::compute_revocation_roots_hash(&revoked_since, &revoked_root)?;
        state.barrier_roots_hash = revocation_roots_hash;
        let barrier_update = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            2,
            1,
            state.n_max,
            revocation_roots_hash.to_vec(),
            kem_before.to_vec(),
            kem_after.to_vec(),
            cover_payload_bytes,
        );

        let mut header = BTreeMap::new();
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&barrier_update)?),
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(2u64)),
        );
        header.insert(112, Value::Bytes(revoked_since.to_vec()));
        header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
        header.insert(hdr::HDR_BARRIER_LEAF_PK, Value::Bytes(join_ek));
        header.insert(hdr::HDR_POP_PK, Value::Bytes(pop_pk));
        header.insert(
            hdr::HDR_JOIN_FINALIZE_AUTH,
            Value::Bytes(join_finalize_auth_token.to_vec()),
        );

        let validation = super::validate_barrier_update_against_roster(&state, &header, &delta)?
            .ok_or(CityGError::InvalidInput("missing parsed barrier update"))?;
        assert_eq!(validation.parsed.tree_size, state.n_max);
        assert_eq!(validation.parsed.kem_tree_hash_before, kem_before);
        assert_eq!(validation.parsed.kem_tree_hash_after, kem_after);
        assert_eq!(validation.snapshot_post, snapshot_post);
        Ok(())
    }

    #[test]
    fn validate_barrier_update_rejects_pcs_refresh_reason_for_unresolved_joiner()
    -> Result<(), CityGError> {
        let mut state = super::GroupState {
            n_max: 4,
            ..super::GroupState::default()
        };
        state.barrier_initialized = true;
        state.barrier_version = 1;
        state.barrier_pk_entries = super::build_all_blank_pk_entries(state.n_max)?;
        let leaf = cityg_client::demo::demo_member_leaf("barrier-join-finalize-must-use-reason2");
        let pop_pk = vec![0xAC; 32];
        state.leaf_device_pk.insert(leaf, pop_pk.clone());
        let _join_finalize_auth_token = install_pending_join_finalize_auth(&mut state, leaf);
        let join_ek = vec![0xA5; 1184];
        let delta = cityg_client::MembershipDelta {
            joined: vec![leaf],
            revoked: Vec::new(),
        };
        let updater_leaf = super::cover_leaf_index(&leaf, state.n_max);
        let leaf_base = usize::try_from(state.n_max.saturating_sub(1))
            .map_err(|_| CityGError::InvalidInput("leaf base overflow"))?;
        let leaf_node = leaf_base
            + usize::try_from(updater_leaf)
                .map_err(|_| CityGError::InvalidInput("leaf index overflow"))?;
        let sibling_node = super::sibling_node(leaf_node)
            .ok_or(CityGError::InvalidInput("invalid updater leaf node"))?;
        let parent_node = (leaf_node - 1) / 2;
        let path_nodes = vec![leaf_node as u64, parent_node as u64, 0];

        let target_ek = vec![0x91; 1184];
        state.barrier_pk_entries[sibling_node] = target_ek.clone();
        state.kem_tree_hash_after =
            super::compute_barrier_tree_hash(state.n_max, state.barrier_pk_entries.as_slice())?;

        let mut snapshot_pre = state.barrier_pk_entries.clone();
        snapshot_pre[leaf_node] = join_ek.clone();
        super::blank_internal_path_from_leaf(snapshot_pre.as_mut_slice(), leaf_node);
        let kem_before = super::compute_barrier_tree_hash(state.n_max, snapshot_pre.as_slice())?;

        let mut snapshot_post = snapshot_pre.clone();
        let ek_root = vec![0x11; 1184];
        let ek_parent = vec![0x22; 1184];
        snapshot_post[0] = ek_root.clone();
        snapshot_post[parent_node] = ek_parent.clone();
        let kem_after = super::compute_barrier_tree_hash(state.n_max, snapshot_post.as_slice())?;

        let target_pkhash = super::compute_barrier_pkhash(target_ek.as_slice())?;
        let cover_payload = super::KemTreeCoverPayloadWire(
            u64::from(updater_leaf),
            path_nodes,
            None,
            vec![super::NodeCiphertextWire(
                parent_node as u64,
                sibling_node as u64,
                target_pkhash[..16].to_vec(),
                vec![0x33; 1088],
                vec![0x44; 48],
            )],
            vec![
                super::NewPublicKeyWire(0, ek_root),
                super::NewPublicKeyWire(parent_node as u64, ek_parent),
            ],
        );
        let barrier_update = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            2,
            1,
            state.n_max,
            super::compute_revocation_roots_hash(&[0u8; 32], &[0u8; 32])?.to_vec(),
            kem_before.to_vec(),
            kem_after.to_vec(),
            super::to_cbor_vec(&cover_payload)?,
        );
        state.barrier_roots_hash = super::compute_revocation_roots_hash(&[0u8; 32], &[0u8; 32])?;

        let mut header = BTreeMap::new();
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&barrier_update)?),
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(1u64)),
        );
        header.insert(112, Value::Bytes(vec![0u8; 32]));
        header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(vec![0u8; 32]));
        header.insert(hdr::HDR_BARRIER_LEAF_PK, Value::Bytes(join_ek));
        header.insert(hdr::HDR_POP_PK, Value::Bytes(pop_pk));

        let err = super::validate_barrier_update_against_roster(&state, &header, &delta)
            .err()
            .ok_or(CityGError::InvalidInput(
                "reason 1 must be rejected for an unresolved joiner",
            ))?;
        assert!(matches!(
            err,
            CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                if freeze.code == msphf_orchestrator::FREEZE_BARRIER_PROACTIVE_FORBIDDEN.code
                    && freeze.reason
                        == msphf_orchestrator::FREEZE_BARRIER_PROACTIVE_FORBIDDEN.reason
        ));
        Ok(())
    }

    #[test]
    fn validate_barrier_update_rejects_join_finalize_reason_for_non_joiner()
    -> Result<(), CityGError> {
        let mut state = super::GroupState {
            n_max: 4,
            ..super::GroupState::default()
        };
        state.barrier_initialized = true;
        state.barrier_version = 1;
        state.barrier_pk_entries = super::build_all_blank_pk_entries(state.n_max)?;
        let leaf = cityg_client::demo::demo_member_leaf("barrier-join-finalize-non-joiner");
        let pop_pk = vec![0xAE; 32];
        let leaf_ek = vec![0xA5; 1184];
        state.leaf_device_pk.insert(leaf, pop_pk.clone());

        let leaf_index = super::cover_leaf_index(&leaf, state.n_max);
        let leaf_base = usize::try_from(state.n_max.saturating_sub(1))
            .map_err(|_| CityGError::InvalidInput("leaf base overflow"))?;
        let leaf_node = leaf_base
            + usize::try_from(leaf_index)
                .map_err(|_| CityGError::InvalidInput("leaf index overflow"))?;
        let sibling_node = super::sibling_node(leaf_node)
            .ok_or(CityGError::InvalidInput("invalid updater leaf node"))?;
        let parent_node = (leaf_node - 1) / 2;
        let path_nodes = vec![leaf_node as u64, parent_node as u64, 0];

        state.barrier_pk_entries[leaf_node] = leaf_ek.clone();
        let target_ek = vec![0x91; 1184];
        state.barrier_pk_entries[sibling_node] = target_ek.clone();
        state.kem_tree_hash_after =
            super::compute_barrier_tree_hash(state.n_max, state.barrier_pk_entries.as_slice())?;

        let mut snapshot_pre = state.barrier_pk_entries.clone();
        super::blank_internal_path_from_leaf(snapshot_pre.as_mut_slice(), leaf_node);
        let kem_before = super::compute_barrier_tree_hash(state.n_max, snapshot_pre.as_slice())?;

        let mut snapshot_post = snapshot_pre.clone();
        let ek_root = vec![0x19; 1184];
        let ek_parent = vec![0x2A; 1184];
        snapshot_post[0] = ek_root.clone();
        snapshot_post[parent_node] = ek_parent.clone();
        let kem_after = super::compute_barrier_tree_hash(state.n_max, snapshot_post.as_slice())?;

        let target_pkhash = super::compute_barrier_pkhash(target_ek.as_slice())?;
        let cover_payload = super::KemTreeCoverPayloadWire(
            u64::from(leaf_index),
            path_nodes,
            None,
            vec![super::NodeCiphertextWire(
                parent_node as u64,
                sibling_node as u64,
                target_pkhash[..16].to_vec(),
                vec![0x33; 1088],
                vec![0x44; 48],
            )],
            vec![
                super::NewPublicKeyWire(0, ek_root),
                super::NewPublicKeyWire(parent_node as u64, ek_parent),
            ],
        );
        let barrier_update = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            2,
            1,
            state.n_max,
            super::compute_revocation_roots_hash(&[0u8; 32], &[0u8; 32])?.to_vec(),
            kem_before.to_vec(),
            kem_after.to_vec(),
            super::to_cbor_vec(&cover_payload)?,
        );
        state.barrier_roots_hash = super::compute_revocation_roots_hash(&[0u8; 32], &[0u8; 32])?;

        let mut header = BTreeMap::new();
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&barrier_update)?),
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(2u64)),
        );
        header.insert(112, Value::Bytes(vec![0u8; 32]));
        header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(vec![0u8; 32]));
        header.insert(hdr::HDR_BARRIER_LEAF_PK, Value::Bytes(leaf_ek));
        header.insert(hdr::HDR_POP_PK, Value::Bytes(pop_pk));

        let err = super::validate_barrier_update_against_roster(
            &state,
            &header,
            &cityg_client::MembershipDelta {
                joined: Vec::new(),
                revoked: Vec::new(),
            },
        )
        .err()
        .ok_or(CityGError::InvalidInput(
            "reason 2 must be rejected for an updater outside the unresolved JoinSet",
        ))?;
        assert!(matches!(
            err,
            CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                if freeze.code == msphf_orchestrator::FREEZE_BARRIER_PROACTIVE_FORBIDDEN.code
                    && freeze.reason
                        == msphf_orchestrator::FREEZE_BARRIER_PROACTIVE_FORBIDDEN.reason
        ));
        Ok(())
    }

    #[test]
    fn validate_barrier_update_rejects_target_pkhash_mismatch() -> Result<(), CityGError> {
        let mut state = super::GroupState {
            n_max: 4,
            ..super::GroupState::default()
        };
        state.barrier_initialized = true;
        state.barrier_version = 1;
        state.barrier_pk_entries = super::build_all_blank_pk_entries(state.n_max)?;
        let leaf = cityg_client::demo::demo_member_leaf("barrier-target-pkhash-mismatch");
        let pop_pk = vec![0xAD; 32];
        state.leaf_device_pk.insert(leaf, pop_pk.clone());
        let join_finalize_auth_token = install_pending_join_finalize_auth(&mut state, leaf);
        let join_ek = vec![0xA5; 1184];
        let delta = cityg_client::MembershipDelta {
            joined: vec![leaf],
            revoked: Vec::new(),
        };
        let updater_leaf = super::cover_leaf_index(&leaf, state.n_max);
        let leaf_base = usize::try_from(state.n_max.saturating_sub(1))
            .map_err(|_| CityGError::InvalidInput("leaf base overflow"))?;
        let leaf_node = leaf_base
            + usize::try_from(updater_leaf)
                .map_err(|_| CityGError::InvalidInput("leaf index overflow"))?;
        let sibling_node = super::sibling_node(leaf_node)
            .ok_or(CityGError::InvalidInput("invalid updater leaf node"))?;
        let parent_node = (leaf_node - 1) / 2;
        let path_nodes = vec![leaf_node as u64, parent_node as u64, 0];

        let target_ek = vec![0x91; 1184];
        state.barrier_pk_entries[sibling_node] = target_ek;
        state.kem_tree_hash_after =
            super::compute_barrier_tree_hash(state.n_max, state.barrier_pk_entries.as_slice())?;

        let mut snapshot_pre = state.barrier_pk_entries.clone();
        snapshot_pre[leaf_node] = join_ek.clone();
        super::blank_internal_path_from_leaf(snapshot_pre.as_mut_slice(), leaf_node);
        let kem_before = super::compute_barrier_tree_hash(state.n_max, snapshot_pre.as_slice())?;

        let mut snapshot_post = snapshot_pre.clone();
        snapshot_post[0] = vec![0x11; 1184];
        snapshot_post[parent_node] = vec![0x22; 1184];
        let kem_after = super::compute_barrier_tree_hash(state.n_max, snapshot_post.as_slice())?;

        let cover_payload = super::KemTreeCoverPayloadWire(
            u64::from(updater_leaf),
            path_nodes,
            None,
            vec![super::NodeCiphertextWire(
                parent_node as u64,
                sibling_node as u64,
                vec![0xFF; 16],
                vec![0x33; 1088],
                vec![0x44; 48],
            )],
            vec![
                super::NewPublicKeyWire(0, vec![0x11; 1184]),
                super::NewPublicKeyWire(parent_node as u64, vec![0x22; 1184]),
            ],
        );
        let barrier_update = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            2,
            1,
            state.n_max,
            super::compute_revocation_roots_hash(&[0u8; 32], &[0u8; 32])?.to_vec(),
            kem_before.to_vec(),
            kem_after.to_vec(),
            super::to_cbor_vec(&cover_payload)?,
        );
        state.barrier_roots_hash = super::compute_revocation_roots_hash(&[0u8; 32], &[0u8; 32])?;

        let mut header = BTreeMap::new();
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&barrier_update)?),
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(2u64)),
        );
        header.insert(112, Value::Bytes(vec![0u8; 32]));
        header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(vec![0u8; 32]));
        header.insert(hdr::HDR_BARRIER_LEAF_PK, Value::Bytes(join_ek));
        header.insert(hdr::HDR_POP_PK, Value::Bytes(pop_pk));
        header.insert(
            hdr::HDR_JOIN_FINALIZE_AUTH,
            Value::Bytes(join_finalize_auth_token.to_vec()),
        );

        let err = match super::validate_barrier_update_against_roster(&state, &header, &delta) {
            Ok(_) => {
                return Err(CityGError::InvalidInput(
                    "target pkhash mismatch must be rejected",
                ));
            }
            Err(err) => err,
        };
        assert!(matches!(
            err,
            CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                if freeze.code == msphf_orchestrator::FREEZE_BARRIER_EXPECTEDPAIRS_FAILURE.code
                    && freeze.reason
                        == msphf_orchestrator::FREEZE_BARRIER_EXPECTEDPAIRS_FAILURE.reason
        ));
        Ok(())
    }

    #[test]
    fn validate_barrier_update_rejects_expected_pairs_mismatch() -> Result<(), CityGError> {
        let mut state = super::GroupState::default();
        state.n_max = 4;
        state.barrier_initialized = true;
        state.barrier_version = 1;
        state.barrier_pk_entries = super::build_all_blank_pk_entries(state.n_max)?;

        let leaf = cityg_client::demo::demo_member_leaf("barrier-pairs-mismatch");
        let pop_pk = vec![0xBC; 32];
        state.leaf_device_pk.insert(leaf, pop_pk.clone());
        let join_finalize_auth_token = install_pending_join_finalize_auth(&mut state, leaf);
        let join_ek = vec![0xA5; 1184];
        let delta = cityg_client::MembershipDelta {
            joined: vec![leaf],
            revoked: Vec::new(),
        };
        let updater_leaf = super::cover_leaf_index(&leaf, state.n_max);
        let leaf_base = usize::try_from(state.n_max.saturating_sub(1))
            .map_err(|_| CityGError::InvalidInput("leaf base overflow"))?;
        let leaf_node = leaf_base
            + usize::try_from(updater_leaf)
                .map_err(|_| CityGError::InvalidInput("leaf index overflow"))?;
        let sibling_node = super::sibling_node(leaf_node)
            .ok_or(CityGError::InvalidInput("invalid updater leaf node"))?;
        let parent_node = (leaf_node - 1) / 2;
        let path_nodes = vec![leaf_node as u64, parent_node as u64, 0];
        state.barrier_pk_entries[sibling_node] = vec![0x91; 1184];

        let mut snapshot_pre = state.barrier_pk_entries.clone();
        snapshot_pre[leaf_node] = join_ek.clone();
        super::blank_internal_path_from_leaf(snapshot_pre.as_mut_slice(), leaf_node);
        let kem_before = super::compute_barrier_tree_hash(state.n_max, snapshot_pre.as_slice())?;

        let mut snapshot_post = snapshot_pre.clone();
        snapshot_post[0] = vec![0x11; 1184];
        snapshot_post[parent_node] = vec![0x22; 1184];
        let kem_after = super::compute_barrier_tree_hash(state.n_max, snapshot_post.as_slice())?;

        let revoked_since = [0u8; 32];
        let revoked_root = [0u8; 32];
        let revocation_roots_hash =
            super::compute_revocation_roots_hash(&revoked_since, &revoked_root)?;
        state.barrier_roots_hash = revocation_roots_hash;
        let cover_payload = super::KemTreeCoverPayloadWire(
            u64::from(updater_leaf),
            path_nodes,
            None,
            vec![super::NodeCiphertextWire(
                parent_node as u64,
                leaf_node as u64,
                vec![0x55; 16],
                vec![0x66; 1088],
                vec![0x77; 48],
            )],
            vec![
                super::NewPublicKeyWire(0, vec![0x11; 1184]),
                super::NewPublicKeyWire(parent_node as u64, vec![0x22; 1184]),
            ],
        );
        let barrier_update = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            2,
            1,
            state.n_max,
            revocation_roots_hash.to_vec(),
            kem_before.to_vec(),
            kem_after.to_vec(),
            super::to_cbor_vec(&cover_payload)?,
        );

        let mut header = BTreeMap::new();
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&barrier_update)?),
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(2u64)),
        );
        header.insert(112, Value::Bytes(revoked_since.to_vec()));
        header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
        header.insert(hdr::HDR_BARRIER_LEAF_PK, Value::Bytes(join_ek));
        header.insert(hdr::HDR_POP_PK, Value::Bytes(pop_pk));
        header.insert(
            hdr::HDR_JOIN_FINALIZE_AUTH,
            Value::Bytes(join_finalize_auth_token.to_vec()),
        );

        let err = match super::validate_barrier_update_against_roster(&state, &header, &delta) {
            Ok(_) => {
                return Err(CityGError::InvalidInput(
                    "mismatched ExpectedPairs must be rejected",
                ));
            }
            Err(err) => err,
        };
        assert!(matches!(
            err,
            CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                if freeze.code == msphf_orchestrator::FREEZE_BARRIER_EXPECTEDPAIRS_FAILURE.code
                    && freeze.reason
                        == msphf_orchestrator::FREEZE_BARRIER_EXPECTEDPAIRS_FAILURE.reason
        ));
        Ok(())
    }

    #[test]
    fn validate_barrier_update_rejects_updater_identity_mismatch() -> Result<(), CityGError> {
        let mut state = super::GroupState {
            n_max: 4,
            ..super::GroupState::default()
        };
        state.barrier_initialized = true;
        state.barrier_version = 1;
        state.barrier_pk_entries = super::build_all_blank_pk_entries(state.n_max)?;
        let leaf = cityg_client::demo::demo_member_leaf("barrier-updater-mismatch");
        let mapped_pop_pk = vec![0xA1; 32];
        let header_pop_pk = vec![0xA2; 32];
        state.leaf_device_pk.insert(leaf, mapped_pop_pk);
        let join_ek = vec![0xA5; 1184];
        let delta = cityg_client::MembershipDelta {
            joined: vec![leaf],
            revoked: Vec::new(),
        };
        let updater_leaf = super::cover_leaf_index(&leaf, state.n_max);
        let leaf_base = usize::try_from(state.n_max.saturating_sub(1))
            .map_err(|_| CityGError::InvalidInput("leaf base overflow"))?;
        let leaf_node = leaf_base
            + usize::try_from(updater_leaf)
                .map_err(|_| CityGError::InvalidInput("leaf index overflow"))?;
        let sibling_node = super::sibling_node(leaf_node)
            .ok_or(CityGError::InvalidInput("invalid updater leaf node"))?;
        let parent_node = (leaf_node - 1) / 2;
        let path_nodes = vec![leaf_node as u64, parent_node as u64, 0];

        let target_ek = vec![0x91; 1184];
        state.barrier_pk_entries[sibling_node] = target_ek.clone();
        state.kem_tree_hash_after =
            super::compute_barrier_tree_hash(state.n_max, state.barrier_pk_entries.as_slice())?;

        let mut snapshot_pre = state.barrier_pk_entries.clone();
        snapshot_pre[leaf_node] = join_ek.clone();
        super::blank_internal_path_from_leaf(snapshot_pre.as_mut_slice(), leaf_node);
        let kem_before = super::compute_barrier_tree_hash(state.n_max, snapshot_pre.as_slice())?;

        let mut snapshot_post = snapshot_pre.clone();
        let ek_root = vec![0x11; 1184];
        let ek_parent = vec![0x22; 1184];
        snapshot_post[0] = ek_root.clone();
        snapshot_post[parent_node] = ek_parent.clone();
        let kem_after = super::compute_barrier_tree_hash(state.n_max, snapshot_post.as_slice())?;

        let target_pkhash = super::compute_barrier_pkhash(target_ek.as_slice())?;
        let cover_payload = super::KemTreeCoverPayloadWire(
            u64::from(updater_leaf),
            path_nodes,
            None,
            vec![super::NodeCiphertextWire(
                parent_node as u64,
                sibling_node as u64,
                target_pkhash[..16].to_vec(),
                vec![0x33; 1088],
                vec![0x44; 48],
            )],
            vec![
                super::NewPublicKeyWire(0, ek_root),
                super::NewPublicKeyWire(parent_node as u64, ek_parent),
            ],
        );
        let cover_payload_bytes = super::to_cbor_vec(&cover_payload)?;

        let revoked_since = [0u8; 32];
        let revoked_root = [0u8; 32];
        let revocation_roots_hash =
            super::compute_revocation_roots_hash(&revoked_since, &revoked_root)?;
        let barrier_update = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            2,
            1,
            state.n_max,
            revocation_roots_hash.to_vec(),
            kem_before.to_vec(),
            kem_after.to_vec(),
            cover_payload_bytes,
        );

        let mut header = BTreeMap::new();
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&barrier_update)?),
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(2u64)),
        );
        header.insert(112, Value::Bytes(revoked_since.to_vec()));
        header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
        header.insert(hdr::HDR_BARRIER_LEAF_PK, Value::Bytes(join_ek));
        header.insert(hdr::HDR_POP_PK, Value::Bytes(header_pop_pk));

        let err = super::validate_barrier_update_against_roster(&state, &header, &delta)
            .err()
            .ok_or(CityGError::InvalidInput(
                "updater identity mismatch must be rejected",
            ))?;
        assert!(matches!(
            err,
            CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                if freeze.code == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.code
                    && freeze.reason == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.reason
        ));
        Ok(())
    }

    #[test]
    fn validate_barrier_update_rejects_missing_author_pop_pk() -> Result<(), CityGError> {
        let mut state = super::GroupState {
            n_max: 4,
            ..super::GroupState::default()
        };
        state.barrier_initialized = true;
        state.barrier_version = 1;
        state.barrier_pk_entries = super::build_all_blank_pk_entries(state.n_max)?;
        let leaf = cityg_client::demo::demo_member_leaf("barrier-missing-pop");
        let mapped_pop_pk = vec![0xA1; 32];
        state.leaf_device_pk.insert(leaf, mapped_pop_pk);
        let join_ek = vec![0xA5; 1184];
        let delta = cityg_client::MembershipDelta {
            joined: vec![leaf],
            revoked: Vec::new(),
        };
        let updater_leaf = super::cover_leaf_index(&leaf, state.n_max);
        let leaf_base = usize::try_from(state.n_max.saturating_sub(1))
            .map_err(|_| CityGError::InvalidInput("leaf base overflow"))?;
        let leaf_node = leaf_base
            + usize::try_from(updater_leaf)
                .map_err(|_| CityGError::InvalidInput("leaf index overflow"))?;
        let sibling_node = super::sibling_node(leaf_node)
            .ok_or(CityGError::InvalidInput("invalid updater leaf node"))?;
        let parent_node = (leaf_node - 1) / 2;
        let path_nodes = vec![leaf_node as u64, parent_node as u64, 0];

        let target_ek = vec![0x91; 1184];
        state.barrier_pk_entries[sibling_node] = target_ek.clone();
        state.kem_tree_hash_after =
            super::compute_barrier_tree_hash(state.n_max, state.barrier_pk_entries.as_slice())?;

        let mut snapshot_pre = state.barrier_pk_entries.clone();
        snapshot_pre[leaf_node] = join_ek.clone();
        super::blank_internal_path_from_leaf(snapshot_pre.as_mut_slice(), leaf_node);
        let kem_before = super::compute_barrier_tree_hash(state.n_max, snapshot_pre.as_slice())?;

        let mut snapshot_post = snapshot_pre.clone();
        let ek_root = vec![0x11; 1184];
        let ek_parent = vec![0x22; 1184];
        snapshot_post[0] = ek_root.clone();
        snapshot_post[parent_node] = ek_parent.clone();
        let kem_after = super::compute_barrier_tree_hash(state.n_max, snapshot_post.as_slice())?;

        let target_pkhash = super::compute_barrier_pkhash(target_ek.as_slice())?;
        let cover_payload = super::KemTreeCoverPayloadWire(
            u64::from(updater_leaf),
            path_nodes,
            None,
            vec![super::NodeCiphertextWire(
                parent_node as u64,
                sibling_node as u64,
                target_pkhash[..16].to_vec(),
                vec![0x33; 1088],
                vec![0x44; 48],
            )],
            vec![
                super::NewPublicKeyWire(0, ek_root),
                super::NewPublicKeyWire(parent_node as u64, ek_parent),
            ],
        );
        let barrier_update = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            2,
            1,
            state.n_max,
            super::compute_revocation_roots_hash(&[0u8; 32], &[0u8; 32])?.to_vec(),
            kem_before.to_vec(),
            kem_after.to_vec(),
            super::to_cbor_vec(&cover_payload)?,
        );

        let mut header = BTreeMap::new();
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&barrier_update)?),
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(2u64)),
        );
        header.insert(112, Value::Bytes(vec![0u8; 32]));
        header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(vec![0u8; 32]));
        header.insert(hdr::HDR_BARRIER_LEAF_PK, Value::Bytes(join_ek));

        let err = match super::validate_barrier_update_against_roster(&state, &header, &delta) {
            Ok(_) => return Err(CityGError::InvalidInput("missing author pop key must fail")),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                if freeze.code == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.code
                    && freeze.reason == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.reason
        ));
        Ok(())
    }

    #[test]
    fn validate_barrier_update_rejects_oversized_bytes() -> Result<(), CityGError> {
        let state = super::GroupState {
            max_barrier_update_bytes: 8,
            ..super::GroupState::default()
        };
        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_BARRIER_UPDATE, Value::Bytes(vec![0xAA; 9]));
        let delta = cityg_client::MembershipDelta {
            joined: Vec::new(),
            revoked: Vec::new(),
        };

        let err = super::validate_barrier_update_against_roster(&state, &header, &delta)
            .err()
            .ok_or(CityGError::InvalidInput(
                "oversized barrier_update must be rejected",
            ))?;
        assert!(matches!(
            err,
            CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                if freeze.code == msphf_orchestrator::FREEZE_BARRIER_UPDATE_MALFORMED.code
                    && freeze.reason == msphf_orchestrator::FREEZE_BARRIER_UPDATE_MALFORMED.reason
        ));
        Ok(())
    }

    #[test]
    fn barrier_snapshot_helpers_cover_fallback_and_parser_paths() -> Result<(), CityGError> {
        let mut state = super::GroupState {
            n_max: 4,
            ..super::GroupState::default()
        };
        let leaf = cityg_client::demo::demo_member_leaf("barrier-snapshot-fallback");
        let mut membership = cityg_client::GroupMembership::default();
        membership.apply_delta(&cityg_client::MembershipDelta {
            joined: vec![leaf],
            revoked: Vec::new(),
        });
        let root = msphf_core::merkle::canonical_set_root(&[leaf])?;
        state.snapshots.insert(root, membership);
        state.latest_root = Some(root);
        let leaf_ek = vec![0x5A; 1184];
        state.leaf_barrier_public.insert(leaf, leaf_ek.clone());

        let pk_entries = super::build_pk_entries(&state)?;
        assert_eq!(pk_entries.len(), 7);
        let leaf_index = usize::try_from(super::cover_leaf_index(&leaf, state.n_max))
            .map_err(|_| CityGError::InvalidInput("leaf index overflow"))?;
        assert_eq!(pk_entries[3 + leaf_index], leaf_ek);
        let group_hash = super::compute_group_barrier_tree_hash(&state)?;
        let direct_hash = super::compute_barrier_tree_hash(state.n_max, pk_entries.as_slice())?;
        assert_eq!(group_hash, direct_hash);

        let mut header = BTreeMap::new();
        assert!(super::parse_barrier_update(&header, 4)?.is_none());

        let cover_payload = super::KemTreeCoverPayloadWire(
            0,
            vec![3, 1, 0],
            Some(vec![2, 1]), // unsorted hint -> malformed
            Vec::new(),
            vec![
                super::NewPublicKeyWire(0, vec![0x11; 1184]),
                super::NewPublicKeyWire(1, vec![0x22; 1184]),
            ],
        );
        let barrier_update = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            1,
            0,
            4,
            vec![0u8; 32],
            vec![0u8; 32],
            vec![0u8; 32],
            super::to_cbor_vec(&cover_payload)?,
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&barrier_update)?),
        );

        assert!(matches!(
            super::parse_barrier_update(&header, 3),
            Err(CityGError::InvalidInput("barrier_update malformed"))
        ));
        assert!(matches!(
            super::parse_barrier_update(&header, 4),
            Err(CityGError::InvalidInput("barrier_update malformed"))
        ));

        let blank_snapshot = super::build_all_blank_pk_entries(4)?;
        assert!(matches!(
            build_refresh_barrier_update_bytes(0, 0, 1, 0, [0u8; 32], [0u8; 32], &[],),
            Err(CityGError::InvalidInput(
                "invalid barrier update tree parameters"
            ))
        ));
        assert!(matches!(
            build_refresh_barrier_update_bytes(
                3,
                0,
                1,
                0,
                [0u8; 32],
                [0u8; 32],
                blank_snapshot.as_slice(),
            ),
            Err(CityGError::InvalidInput(
                "invalid barrier update tree parameters"
            ))
        ));
        assert!(matches!(
            build_refresh_barrier_update_bytes(
                4,
                4,
                1,
                0,
                [0u8; 32],
                [0u8; 32],
                blank_snapshot.as_slice(),
            ),
            Err(CityGError::InvalidInput(
                "invalid barrier update tree parameters"
            ))
        ));
        assert!(matches!(
            build_refresh_barrier_update_bytes(
                4,
                0,
                1,
                0,
                [0u8; 32],
                [0u8; 32],
                &blank_snapshot[..blank_snapshot.len() - 1],
            ),
            Err(CityGError::InvalidInput("barrier snapshot size mismatch"))
        ));
        Ok(())
    }

    #[test]
    fn validate_barrier_update_uses_genesis_snapshot_joinset() -> Result<(), CityGError> {
        let mut state = super::GroupState {
            n_max: 4,
            barrier_initialized: false,
            barrier_version: 0,
            ..super::GroupState::default()
        };

        let leaf = cityg_client::demo::demo_member_leaf("barrier-genesis-joinset");
        let pop_pk = vec![0xCD; 32];
        state.leaf_device_pk.insert(leaf, pop_pk.clone());
        let leaf_ek = vec![0x73; 1184];
        let mut membership = cityg_client::GroupMembership::default();
        membership.apply_delta(&cityg_client::MembershipDelta {
            joined: vec![leaf],
            revoked: Vec::new(),
        });
        let root = msphf_core::merkle::canonical_set_root(&[leaf])?;
        state.snapshots.insert(root, membership);
        state.latest_root = Some(root);
        state.leaf_barrier_public.insert(leaf, leaf_ek.clone());

        let updater_leaf = u64::from(super::cover_leaf_index(&leaf, state.n_max));
        let leaf_node = state.n_max.saturating_sub(1) + updater_leaf;
        let parent_node = (leaf_node - 1) / 2;
        let path_nodes = vec![leaf_node, parent_node, 0];

        let mut snapshot_pre = super::build_all_blank_pk_entries(state.n_max)?;
        snapshot_pre[usize::try_from(leaf_node).unwrap_or(0)] = leaf_ek.clone();
        super::blank_internal_path_from_leaf(
            snapshot_pre.as_mut_slice(),
            usize::try_from(leaf_node).unwrap_or(0),
        );
        let kem_before = super::compute_barrier_tree_hash(state.n_max, snapshot_pre.as_slice())?;
        let mut snapshot_post = snapshot_pre.clone();
        snapshot_post[0] = vec![0x11; 1184];
        snapshot_post[usize::try_from(parent_node).unwrap_or(0)] = vec![0x22; 1184];
        let kem_after = super::compute_barrier_tree_hash(state.n_max, snapshot_post.as_slice())?;

        let revoked_since = [0u8; 32];
        let revoked_root = [0u8; 32];
        let revocation_roots_hash =
            super::compute_revocation_roots_hash(&revoked_since, &revoked_root)?;
        let cover_payload = super::KemTreeCoverPayloadWire(
            updater_leaf,
            path_nodes,
            None,
            Vec::new(),
            vec![
                super::NewPublicKeyWire(0, vec![0x11; 1184]),
                super::NewPublicKeyWire(parent_node, vec![0x22; 1184]),
            ],
        );
        let barrier_update = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            0,
            0,
            state.n_max,
            revocation_roots_hash.to_vec(),
            kem_before.to_vec(),
            kem_after.to_vec(),
            super::to_cbor_vec(&cover_payload)?,
        );

        let mut header = BTreeMap::new();
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&barrier_update)?),
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(0u64)),
        );
        header.insert(112, Value::Bytes(revoked_since.to_vec()));
        header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
        header.insert(hdr::HDR_POP_PK, Value::Bytes(pop_pk));

        let delta = cityg_client::MembershipDelta {
            joined: Vec::new(),
            revoked: Vec::new(),
        };
        let validation = super::validate_barrier_update_against_roster(&state, &header, &delta)?
            .ok_or(CityGError::InvalidInput(
                "expected validated barrier update",
            ))?;
        assert_eq!(validation.parsed.prev_barrier_version, 0);
        assert_eq!(validation.parsed.tree_size, state.n_max);
        assert_eq!(validation.snapshot_post, snapshot_post);
        Ok(())
    }

    #[test]
    fn barrier_helpers_cover_remaining_error_paths() -> Result<(), CityGError> {
        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_BARRIER_UPDATE, Value::Integer(1.into()));
        assert!(matches!(super::parse_barrier_update(&header, 4), Ok(None)));

        let delta = cityg_client::MembershipDelta {
            joined: Vec::new(),
            revoked: Vec::new(),
        };
        let state = super::GroupState::default();
        assert!(
            super::validate_barrier_update_against_roster(&state, &BTreeMap::new(), &delta)?
                .is_none()
        );

        let empty_tree = super::build_all_blank_pk_entries(4)?;
        assert!(matches!(
            super::collect_expected_pairs(empty_tree.as_slice(), &[0, 0], 4),
            Err(CityGError::InvalidInput("barrier_update malformed"))
        ));
        assert!(matches!(
            super::compute_barrier_tree_hash(4, &empty_tree[..6]),
            Err(CityGError::InvalidInput("barrier tree size mismatch"))
        ));
        assert!(matches!(
            super::build_all_blank_pk_entries(u64::MAX),
            Err(CityGError::InvalidInput(_))
        ));
        Ok(())
    }

    #[test]
    fn parse_barrier_update_accepts_sorted_hint_and_ciphertexts() -> Result<(), CityGError> {
        let cover_payload = super::KemTreeCoverPayloadWire(
            0,
            vec![3, 1, 0],
            Some(vec![1, 2]),
            vec![super::NodeCiphertextWire(
                1,
                4,
                vec![0xAA; 16],
                vec![0xBB; 1088],
                vec![0xCC; 48],
            )],
            vec![
                super::NewPublicKeyWire(0, vec![0x11; 1184]),
                super::NewPublicKeyWire(1, vec![0x22; 1184]),
            ],
        );
        let barrier_update = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            7,
            6,
            4,
            vec![0x01; 32],
            vec![0x02; 32],
            vec![0x03; 32],
            super::to_cbor_vec(&cover_payload)?,
        );
        let mut header = BTreeMap::new();
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&barrier_update)?),
        );
        let parsed = super::parse_barrier_update(&header, 4)?
            .ok_or(CityGError::InvalidInput("expected parsed update"))?;
        assert_eq!(parsed.prev_barrier_version, 6);
        assert_eq!(parsed.path_nodes, vec![3, 1, 0]);
        assert_eq!(parsed.node_ciphertexts.len(), 1);
        assert_eq!(parsed.new_public_keys.len(), 2);
        Ok(())
    }

    #[test]
    fn parse_barrier_update_rejects_new_public_keys_expected_set_mismatch() -> Result<(), CityGError>
    {
        let cover_missing = super::KemTreeCoverPayloadWire(
            0,
            vec![3, 1, 0],
            None,
            Vec::new(),
            vec![super::NewPublicKeyWire(0, vec![0x11; 1184])],
        );
        let update_missing = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            1,
            0,
            4,
            vec![0x01; 32],
            vec![0x02; 32],
            vec![0x03; 32],
            super::to_cbor_vec(&cover_missing)?,
        );
        let mut header = BTreeMap::new();
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&update_missing)?),
        );
        assert!(matches!(
            super::parse_barrier_update(&header, 4),
            Err(CityGError::InvalidInput("barrier_update malformed"))
        ));

        let cover_extra = super::KemTreeCoverPayloadWire(
            0,
            vec![3, 1, 0],
            None,
            Vec::new(),
            vec![
                super::NewPublicKeyWire(0, vec![0x11; 1184]),
                super::NewPublicKeyWire(1, vec![0x22; 1184]),
                super::NewPublicKeyWire(2, vec![0x33; 1184]),
            ],
        );
        let update_extra = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            1,
            0,
            4,
            vec![0x01; 32],
            vec![0x02; 32],
            vec![0x03; 32],
            super::to_cbor_vec(&cover_extra)?,
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&update_extra)?),
        );
        assert!(matches!(
            super::parse_barrier_update(&header, 4),
            Err(CityGError::InvalidInput("barrier_update malformed"))
        ));
        Ok(())
    }

    #[test]
    fn parse_barrier_update_rejects_invalid_mode_and_path_shapes() -> Result<(), CityGError> {
        let valid_cover = super::KemTreeCoverPayloadWire(
            0,
            vec![3, 1, 0],
            None,
            Vec::new(),
            vec![
                super::NewPublicKeyWire(0, vec![0x11; 1184]),
                super::NewPublicKeyWire(1, vec![0x22; 1184]),
            ],
        );
        let mut header = BTreeMap::new();

        let wrong_mode = super::BarrierUpdateWire(
            "barrier-v0".to_string(),
            1,
            0,
            4,
            vec![0x01; 32],
            vec![0x02; 32],
            vec![0x03; 32],
            super::to_cbor_vec(&valid_cover)?,
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&wrong_mode)?),
        );
        assert!(matches!(
            super::parse_barrier_update(&header, 4),
            Err(CityGError::InvalidInput("barrier_update malformed"))
        ));

        let empty_path = super::KemTreeCoverPayloadWire(
            0,
            Vec::new(),
            None,
            Vec::new(),
            vec![
                super::NewPublicKeyWire(0, vec![0x11; 1184]),
                super::NewPublicKeyWire(1, vec![0x22; 1184]),
            ],
        );
        let update_empty_path = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            1,
            0,
            4,
            vec![0x01; 32],
            vec![0x02; 32],
            vec![0x03; 32],
            super::to_cbor_vec(&empty_path)?,
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&update_empty_path)?),
        );
        assert!(matches!(
            super::parse_barrier_update(&header, 4),
            Err(CityGError::InvalidInput("barrier_update malformed"))
        ));

        let wrong_leaf = super::KemTreeCoverPayloadWire(
            0,
            vec![4, 1, 0],
            None,
            Vec::new(),
            vec![
                super::NewPublicKeyWire(0, vec![0x11; 1184]),
                super::NewPublicKeyWire(1, vec![0x22; 1184]),
            ],
        );
        let update_wrong_leaf = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            1,
            0,
            4,
            vec![0x01; 32],
            vec![0x02; 32],
            vec![0x03; 32],
            super::to_cbor_vec(&wrong_leaf)?,
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&update_wrong_leaf)?),
        );
        assert!(matches!(
            super::parse_barrier_update(&header, 4),
            Err(CityGError::InvalidInput("barrier_update malformed"))
        ));

        let duplicate_path = super::KemTreeCoverPayloadWire(
            0,
            vec![3, 1, 1, 0],
            None,
            Vec::new(),
            vec![
                super::NewPublicKeyWire(0, vec![0x11; 1184]),
                super::NewPublicKeyWire(1, vec![0x22; 1184]),
                super::NewPublicKeyWire(1, vec![0x33; 1184]),
            ],
        );
        let update_duplicate_path = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            1,
            0,
            4,
            vec![0x01; 32],
            vec![0x02; 32],
            vec![0x03; 32],
            super::to_cbor_vec(&duplicate_path)?,
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&update_duplicate_path)?),
        );
        assert!(matches!(
            super::parse_barrier_update(&header, 4),
            Err(CityGError::InvalidInput("barrier_update malformed"))
        ));

        let non_parent_chain = super::KemTreeCoverPayloadWire(
            0,
            vec![3, 0],
            None,
            Vec::new(),
            vec![super::NewPublicKeyWire(0, vec![0x11; 1184])],
        );
        let update_non_parent_chain = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            1,
            0,
            4,
            vec![0x01; 32],
            vec![0x02; 32],
            vec![0x03; 32],
            super::to_cbor_vec(&non_parent_chain)?,
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&update_non_parent_chain)?),
        );
        assert!(matches!(
            super::parse_barrier_update(&header, 4),
            Err(CityGError::InvalidInput("barrier_update malformed"))
        ));
        Ok(())
    }

    #[test]
    fn parse_barrier_update_rejects_invalid_key_and_ciphertext_shapes() -> Result<(), CityGError> {
        let mut header = BTreeMap::new();

        let wrong_key_len = super::KemTreeCoverPayloadWire(
            0,
            vec![3, 1, 0],
            None,
            Vec::new(),
            vec![
                super::NewPublicKeyWire(0, vec![0x11; 64]),
                super::NewPublicKeyWire(1, vec![0x22; 1184]),
            ],
        );
        let update_wrong_key_len = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            1,
            0,
            4,
            vec![0x01; 32],
            vec![0x02; 32],
            vec![0x03; 32],
            super::to_cbor_vec(&wrong_key_len)?,
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&update_wrong_key_len)?),
        );
        assert!(matches!(
            super::parse_barrier_update(&header, 4),
            Err(CityGError::InvalidInput("barrier_update malformed"))
        ));

        let unsorted_keys = super::KemTreeCoverPayloadWire(
            0,
            vec![3, 1, 0],
            None,
            Vec::new(),
            vec![
                super::NewPublicKeyWire(1, vec![0x22; 1184]),
                super::NewPublicKeyWire(0, vec![0x11; 1184]),
            ],
        );
        let update_unsorted_keys = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            1,
            0,
            4,
            vec![0x01; 32],
            vec![0x02; 32],
            vec![0x03; 32],
            super::to_cbor_vec(&unsorted_keys)?,
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&update_unsorted_keys)?),
        );
        assert!(matches!(
            super::parse_barrier_update(&header, 4),
            Err(CityGError::InvalidInput("barrier_update malformed"))
        ));

        let wrong_ciphertext_size = super::KemTreeCoverPayloadWire(
            0,
            vec![3, 1, 0],
            None,
            vec![super::NodeCiphertextWire(
                1,
                4,
                vec![0xAA; 16],
                vec![0xBB; 1088],
                vec![0xCC; 47],
            )],
            vec![
                super::NewPublicKeyWire(0, vec![0x11; 1184]),
                super::NewPublicKeyWire(1, vec![0x22; 1184]),
            ],
        );
        let update_wrong_ciphertext_size = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            1,
            0,
            4,
            vec![0x01; 32],
            vec![0x02; 32],
            vec![0x03; 32],
            super::to_cbor_vec(&wrong_ciphertext_size)?,
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&update_wrong_ciphertext_size)?),
        );
        assert!(matches!(
            super::parse_barrier_update(&header, 4),
            Err(CityGError::InvalidInput("barrier_update malformed"))
        ));

        let unsorted_ciphertexts = super::KemTreeCoverPayloadWire(
            0,
            vec![3, 1, 0],
            None,
            vec![
                super::NodeCiphertextWire(1, 4, vec![0xAA; 16], vec![0xBB; 1088], vec![0xCC; 48]),
                super::NodeCiphertextWire(1, 3, vec![0xAA; 16], vec![0xBB; 1088], vec![0xCC; 48]),
            ],
            vec![
                super::NewPublicKeyWire(0, vec![0x11; 1184]),
                super::NewPublicKeyWire(1, vec![0x22; 1184]),
            ],
        );
        let update_unsorted_ciphertexts = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            1,
            0,
            4,
            vec![0x01; 32],
            vec![0x02; 32],
            vec![0x03; 32],
            super::to_cbor_vec(&unsorted_ciphertexts)?,
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&update_unsorted_ciphertexts)?),
        );
        assert!(matches!(
            super::parse_barrier_update(&header, 4),
            Err(CityGError::InvalidInput("barrier_update malformed"))
        ));
        Ok(())
    }

    #[test]
    fn validate_barrier_update_detects_hash_and_roots_mismatches() -> Result<(), CityGError> {
        let mut state = super::GroupState {
            n_max: 4,
            barrier_initialized: false,
            barrier_version: 0,
            ..super::GroupState::default()
        };

        let leaf = cityg_client::demo::demo_member_leaf("barrier-mismatch-matrix");
        let pop_pk = vec![0xDE; 32];
        state.leaf_device_pk.insert(leaf, pop_pk.clone());
        let leaf_ek = vec![0x33; 1184];
        let mut membership = cityg_client::GroupMembership::default();
        membership.apply_delta(&cityg_client::MembershipDelta {
            joined: vec![leaf],
            revoked: Vec::new(),
        });
        let root = msphf_core::merkle::canonical_set_root(&[leaf])?;
        state.snapshots.insert(root, membership);
        state.latest_root = Some(root);
        state.leaf_barrier_public.insert(leaf, leaf_ek.clone());

        let updater_leaf = u64::from(super::cover_leaf_index(&leaf, state.n_max));
        let leaf_node = state.n_max.saturating_sub(1) + updater_leaf;
        let parent_node = (leaf_node - 1) / 2;
        let path_nodes = vec![leaf_node, parent_node, 0];
        let mut snapshot_pre = super::build_all_blank_pk_entries(state.n_max)?;
        snapshot_pre[usize::try_from(leaf_node).unwrap_or(0)] = leaf_ek;
        super::blank_internal_path_from_leaf(
            snapshot_pre.as_mut_slice(),
            usize::try_from(leaf_node).unwrap_or(0),
        );
        let kem_before = super::compute_barrier_tree_hash(state.n_max, snapshot_pre.as_slice())?;
        let mut snapshot_post = snapshot_pre.clone();
        snapshot_post[0] = vec![0x11; 1184];
        snapshot_post[usize::try_from(parent_node).unwrap_or(0)] = vec![0x22; 1184];
        let kem_after = super::compute_barrier_tree_hash(state.n_max, snapshot_post.as_slice())?;

        let revoked_since = [0u8; 32];
        let revoked_root = [0u8; 32];
        let rrh = super::compute_revocation_roots_hash(&revoked_since, &revoked_root)?;
        let cover_payload = super::KemTreeCoverPayloadWire(
            updater_leaf,
            path_nodes,
            None,
            Vec::new(),
            vec![
                super::NewPublicKeyWire(0, vec![0x11; 1184]),
                super::NewPublicKeyWire(parent_node, vec![0x22; 1184]),
            ],
        );
        let cover_payload_bytes = super::to_cbor_vec(&cover_payload)?;

        let mut header = BTreeMap::new();
        header.insert(112, Value::Bytes(revoked_since.to_vec()));
        header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
        header.insert(hdr::HDR_POP_PK, Value::Bytes(pop_pk));

        let before_bad = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            0,
            0,
            state.n_max,
            rrh.to_vec(),
            vec![0x99; 32],
            kem_after.to_vec(),
            cover_payload_bytes.clone(),
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&before_bad)?),
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(0u64)),
        );
        let err = super::validate_barrier_update_against_roster(
            &state,
            &header,
            &cityg_client::MembershipDelta {
                joined: Vec::new(),
                revoked: Vec::new(),
            },
        )
        .err()
        .ok_or(CityGError::InvalidInput(
            "bad kem_tree_hash_before must fail",
        ))?;
        assert!(matches!(
            err,
            CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                if freeze.code == msphf_orchestrator::FREEZE_BARRIER_TREE_HASH_CHAIN_FAILURE.code
                    && freeze.reason
                        == msphf_orchestrator::FREEZE_BARRIER_TREE_HASH_CHAIN_FAILURE.reason
        ));

        let roots_bad = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            0,
            0,
            state.n_max,
            vec![0x88; 32],
            kem_before.to_vec(),
            kem_after.to_vec(),
            cover_payload_bytes.clone(),
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&roots_bad)?),
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(0u64)),
        );
        let err = super::validate_barrier_update_against_roster(
            &state,
            &header,
            &cityg_client::MembershipDelta {
                joined: Vec::new(),
                revoked: Vec::new(),
            },
        )
        .err()
        .ok_or(CityGError::InvalidInput(
            "bad revocation_roots_hash must fail",
        ))?;
        assert!(matches!(
            err,
            CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                if freeze.code == msphf_orchestrator::FREEZE_BARRIER_UPDATE_MALFORMED.code
                    && freeze.reason == msphf_orchestrator::FREEZE_BARRIER_UPDATE_MALFORMED.reason
        ));

        let valid_update = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            0,
            0,
            state.n_max,
            rrh.to_vec(),
            kem_before.to_vec(),
            kem_after.to_vec(),
            cover_payload_bytes.clone(),
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&valid_update)?),
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(0u64)),
        );
        let validation = super::validate_barrier_update_against_roster(
            &state,
            &header,
            &cityg_client::MembershipDelta {
                joined: Vec::new(),
                revoked: Vec::new(),
            },
        )?
        .ok_or(CityGError::InvalidInput(
            "valid barrier update should be accepted",
        ))?;
        assert_eq!(validation.snapshot_post, snapshot_post);
        assert!(
            validation.hash_cache_post.is_some(),
            "non-empty public-key updates should populate a hash cache"
        );
        header.insert(112, Value::Bytes(vec![0xAA; 31]));
        let err = super::validate_barrier_update_against_roster(
            &state,
            &header,
            &cityg_client::MembershipDelta {
                joined: Vec::new(),
                revoked: Vec::new(),
            },
        )
        .err()
        .ok_or(CityGError::InvalidInput(
            "invalid revocation roots header shape must fail",
        ))?;
        assert!(matches!(
            err,
            CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                if freeze.code == msphf_orchestrator::FREEZE_BARRIER_UPDATE_MALFORMED.code
                    && freeze.reason == msphf_orchestrator::FREEZE_BARRIER_UPDATE_MALFORMED.reason
        ));
        header.insert(112, Value::Bytes(revoked_since.to_vec()));

        let after_bad = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            0,
            0,
            state.n_max,
            rrh.to_vec(),
            kem_before.to_vec(),
            vec![0x77; 32],
            cover_payload_bytes,
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&after_bad)?),
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(0u64)),
        );
        let err = super::validate_barrier_update_against_roster(
            &state,
            &header,
            &cityg_client::MembershipDelta {
                joined: Vec::new(),
                revoked: Vec::new(),
            },
        )
        .err()
        .ok_or(CityGError::InvalidInput(
            "bad kem_tree_hash_after must fail",
        ))?;
        assert!(matches!(
            err,
            CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                if freeze.code == msphf_orchestrator::FREEZE_BARRIER_TREE_HASH_CHAIN_FAILURE.code
                    && freeze.reason
                        == msphf_orchestrator::FREEZE_BARRIER_TREE_HASH_CHAIN_FAILURE.reason
        ));

        let mut singleton_state = super::GroupState {
            n_max: 1,
            barrier_initialized: false,
            barrier_version: 0,
            ..super::GroupState::default()
        };
        let singleton_leaf = cityg_client::demo::demo_member_leaf("barrier-singleton-empty");
        let singleton_pop_pk = vec![0xC4; 32];
        singleton_state
            .leaf_device_pk
            .insert(singleton_leaf, singleton_pop_pk.clone());
        let singleton_leaf_ek = vec![0x55; 1184];
        let mut singleton_membership = cityg_client::GroupMembership::default();
        singleton_membership.apply_delta(&cityg_client::MembershipDelta {
            joined: vec![singleton_leaf],
            revoked: Vec::new(),
        });
        let singleton_root = msphf_core::merkle::canonical_set_root(&[singleton_leaf])?;
        singleton_state
            .snapshots
            .insert(singleton_root, singleton_membership);
        singleton_state.latest_root = Some(singleton_root);
        singleton_state
            .leaf_barrier_public
            .insert(singleton_leaf, singleton_leaf_ek.clone());

        let singleton_snapshot = vec![singleton_leaf_ek];
        let singleton_hash =
            super::compute_barrier_tree_hash(singleton_state.n_max, singleton_snapshot.as_slice())?;
        let singleton_rrh = super::compute_revocation_roots_hash(&[0u8; 32], &[0u8; 32])?;
        let singleton_cover =
            super::KemTreeCoverPayloadWire(0, vec![0], None, Vec::new(), Vec::new());
        let singleton_update = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            0,
            0,
            singleton_state.n_max,
            singleton_rrh.to_vec(),
            singleton_hash.to_vec(),
            singleton_hash.to_vec(),
            super::to_cbor_vec(&singleton_cover)?,
        );
        let mut singleton_header = BTreeMap::new();
        singleton_header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&singleton_update)?),
        );
        singleton_header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(0u64)),
        );
        singleton_header.insert(112, Value::Bytes(vec![0u8; 32]));
        singleton_header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(vec![0u8; 32]));
        singleton_header.insert(hdr::HDR_POP_PK, Value::Bytes(singleton_pop_pk));
        let singleton_validation = super::validate_barrier_update_against_roster(
            &singleton_state,
            &singleton_header,
            &cityg_client::MembershipDelta {
                joined: Vec::new(),
                revoked: Vec::new(),
            },
        )?
        .ok_or(CityGError::InvalidInput(
            "singleton barrier update without public-key changes should be accepted",
        ))?;
        assert!(singleton_validation.parsed.new_public_keys.is_empty());
        assert_eq!(singleton_validation.snapshot_post, singleton_snapshot);
        assert!(
            singleton_validation.hash_cache_post.is_none(),
            "empty update should reuse the prior cache instead of building a new one"
        );
        Ok(())
    }

    #[test]
    fn journal_helpers_handle_missing_and_truncated_entries() -> Result<(), CityGError> {
        let dir = tempdir()?;
        let missing_path = dir.path().join("missing.journal");
        let loaded = super::ServerJournal::load_entries(&missing_path)?;
        assert!(
            loaded.is_empty(),
            "missing journal should be treated as empty"
        );

        let nested_path = dir.path().join("nested").join("server.journal");
        let _journal = super::ServerJournal::open(&nested_path)?;
        assert!(
            nested_path.exists(),
            "opening a nested journal path should create parent directories"
        );

        let mut file = File::create(&nested_path)?;
        file.write_all(&3u32.to_le_bytes())?;
        file.write_all(&[0xAA, 0xBB, 0xCC])?;
        file.write_all(&5u32.to_le_bytes())?;
        file.write_all(&[0x01, 0x02])?;
        file.flush()?;

        let loaded = super::ServerJournal::load_entries(&nested_path)?;
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], vec![0xAA, 0xBB, 0xCC]);
        Ok(())
    }

    #[test]
    fn journal_helpers_ignore_partial_length_prefix() -> Result<(), CityGError> {
        let dir = tempdir()?;
        let journal_path = dir.path().join("partial-len.journal");
        let mut file = File::create(&journal_path)?;
        file.write_all(&[0x05, 0x00, 0x00])?;
        file.flush()?;

        let loaded = super::ServerJournal::load_entries(&journal_path)?;
        assert!(
            loaded.is_empty(),
            "partial length prefixes should be ignored fail-closed"
        );
        Ok(())
    }

    #[test]
    fn update_window_limits_updates_context_and_receiver_ttl() {
        let mut server = super::demo::demo_server();
        server.update_window_limits(Some(3), Some(Duration::from_secs(9)));
        let (h_max, ttl) = server.window_limits();
        assert_eq!(h_max, 3);
        assert_eq!(ttl, Duration::from_secs(9));
    }

    #[test]
    fn refresh_pivot_requires_pivot_weid_header() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let bundle = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&bundle)?;

        let pivot_weid = server
            .context_mut()
            .pivot_parities_for(bundle.gid(), &bundle.anchor.parent_root)
            .into_iter()
            .next()
            .ok_or(CityGError::InvalidInput("pivot parity missing"))?
            .we_epoch_id;
        let mut invalid = bundle.clone();
        invalid.header_map.insert(
            hdr::HDR_ROLLUP_PIVOT_WEID,
            Value::Bytes(pivot_weid.to_vec()),
        );
        invalid
            .header_map
            .remove(&msphf_orchestrator::hdr::HDR_ROLLUP_PIVOT_WEID);
        let err = server
            .refresh_pivot(&invalid)
            .expect_err("missing pivot_weid header should fail");
        assert!(matches!(err, CityGError::InvalidInput("pivot_weid")));
        Ok(())
    }

    #[test]
    fn refresh_pivot_rejects_mutated_proof_material() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let bundle = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&bundle)?;

        let mut tampered = bundle.clone();
        let pivot_weid = server
            .context_mut()
            .pivot_parities_for(bundle.gid(), &bundle.anchor.parent_root)
            .into_iter()
            .next()
            .ok_or(CityGError::InvalidInput("pivot parity missing"))?
            .we_epoch_id;
        tampered.header_map.insert(
            hdr::HDR_ROLLUP_PIVOT_WEID,
            Value::Bytes(pivot_weid.to_vec()),
        );
        let proof_field = tampered
            .header_map
            .get_mut(&hdr::HDR_VRF_PROOF)
            .ok_or(CityGError::InvalidInput("vrf proof missing from bundle"))?;
        if let Value::Bytes(bytes) = proof_field {
            if let Some(first) = bytes.first_mut() {
                *first ^= 0x01;
            }
        } else {
            return Err(CityGError::InvalidInput("vrf proof has invalid type"));
        }

        let err = server
            .refresh_pivot(&tampered)
            .err()
            .ok_or(CityGError::InvalidInput(
                "tampered refresh bundle must fail",
            ))?;
        assert!(matches!(
            err,
            CityGError::InvalidInput("refresh payload diverges from stored parity")
        ));
        Ok(())
    }

    #[test]
    fn refresh_pivot_accepts_matching_parity_payload() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let bundle = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&bundle)?;

        let pivot_weid = server
            .context_mut()
            .pivot_parities_for(bundle.gid(), &bundle.anchor.parent_root)
            .into_iter()
            .next()
            .ok_or(CityGError::InvalidInput("pivot parity missing"))?
            .we_epoch_id;
        let mut refresh = bundle.clone();
        refresh.header_map.insert(
            hdr::HDR_ROLLUP_PIVOT_WEID,
            Value::Bytes(pivot_weid.to_vec()),
        );

        server.refresh_pivot(&refresh)?;
        let still_present = server
            .context_mut()
            .pivot_parities_for(bundle.gid(), &bundle.anchor.parent_root)
            .into_iter()
            .any(|parity| parity.we_epoch_id == pivot_weid);
        assert!(
            still_present,
            "refresh should preserve pivot parity entry in store"
        );
        Ok(())
    }

    #[test]
    fn refresh_pivot_rejects_unknown_pivot_weid() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let bundle = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&bundle)?;

        let mut refresh = bundle.clone();
        refresh.header_map.insert(
            hdr::HDR_ROLLUP_PIVOT_WEID,
            Value::Bytes([0xEE; 32].to_vec()),
        );
        let err = server
            .refresh_pivot(&refresh)
            .expect_err("unknown pivot parity must fail");
        assert!(matches!(
            err,
            CityGError::InvalidInput("pivot parity missing for refresh")
        ));
        Ok(())
    }

    #[test]
    fn accept_epoch_reports_window_full() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        server.update_window_limits(Some(1), None);

        let bundle = cityg_client::demo::demo_bundle("alice")?;
        #[derive(Serialize)]
        struct WindowInputs<'a> {
            #[serde(with = "serde_bytes")]
            gid: &'a [u8],
            #[serde(with = "serde_bytes")]
            parent_root: &'a [u8; 32],
            #[serde(with = "serde_bytes")]
            seed_ctx_hash: &'a [u8; 32],
        }
        let wid = h_l(
            "mhw/window",
            &WindowInputs {
                gid: bundle.gid(),
                parent_root: &bundle.anchor.parent_root,
                seed_ctx_hash: &bundle.hp_binding.seed_ctx_hash,
            },
        )?;

        let accept_time = server.context_mut().next_accept_instant();
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
        server
            .context_mut()
            .mh_window
            .accept_head(&wid, record, accept_time)
            .map_err(|e| CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(e)))?;

        let err = server.accept_epoch(&bundle).expect_err("expected error");
        match err {
            CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(code)) => {
                assert_eq!(code, msphf_orchestrator::mhw::FreezeError::WINDOW_FULL);
                let telemetry = server.context().telemetry_report();
                let entry = telemetry
                    .into_iter()
                    .find(|(key, _)| {
                        key.gid.as_slice() == bundle.gid()
                            && key.parent_root == bundle.anchor.parent_root
                    })
                    .ok_or(CityGError::InvalidInput("telemetry entry not found"))?;
                assert_eq!(entry.1.freeze_window_full, 1);
                Ok(())
            }
            other => Err(other),
        }
    }

    #[test]
    fn accept_epoch_rolls_back_on_roster_failure() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let bundle_alice = cityg_client::demo::demo_bundle("alice")?;
        let outcome = server.accept_epoch(&bundle_alice)?;
        assert_eq!(server.context().active_heads(&outcome.wid), 1);

        let gid_key = bundle_alice.gid().to_vec();
        {
            let state = server
                .roster
                .groups
                .get_mut(&gid_key)
                .ok_or(CityGError::InvalidInput("group not found"))?;
            state.snapshots.remove(&outcome.new_root);
            state.latest_root = None;
        }

        let bundle_bob = cityg_client::demo::demo_bundle("bob")?;
        let err = server
            .accept_epoch(&bundle_bob)
            .expect_err("expected error");
        assert!(matches!(err, CityGError::InvalidInput(_)));

        assert_eq!(server.context().active_heads(&outcome.wid), 1);
        assert_eq!(server.receiver.len(), 1);
        Ok(())
    }

    #[test]
    fn journal_failure_aborts_single_accept() -> Result<(), CityGError> {
        let _serial = super::journal_serial_guard();
        let dir = tempdir()?;
        let journal = dir.path().join("single.journal");
        let mut server = demo_server_with_journal(&journal);
        let bundle = cityg_client::demo::demo_bundle("alice")?;
        let _guard = super::fail_journal_after(0);
        let err = server.accept_epoch(&bundle).expect_err("expected error");
        assert!(matches!(err, CityGError::Io(_)));
        assert!(server.members(&cityg_client::demo::DEMO_GID).is_empty());
        let bundle_retry = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&bundle_retry)?;
        assert_eq!(server.members(&cityg_client::demo::DEMO_GID).len(), 1);
        Ok(())
    }

    #[test]
    fn crash_recovery_replays_state_journal() -> Result<(), CityGError> {
        let _guard = super::journal_serial_guard();
        let dir = tempdir()?;
        let journal_path = dir.path().join("cityg-server.journal");
        let gid = cityg_client::demo::DEMO_GID.to_vec();
        let expected_barrier_state: msphf_orchestrator::BarrierGroupState;
        let expected_alice_device_state: msphf_orchestrator::DeviceChainState;
        let expected_bob_device_state: msphf_orchestrator::DeviceChainState;
        let alice_pop_pk: Vec<u8>;
        let bob_pop_pk: Vec<u8>;
        {
            let mut server = demo_server_with_journal(&journal_path);
            let bundle_alice = cityg_client::demo::demo_bundle("alice")?;
            let bundle_bob = cityg_client::demo::demo_bundle("bob")?;
            alice_pop_pk = bundle_alice
                .header_map
                .get(&hdr::HDR_POP_PK)
                .and_then(Value::as_bytes)
                .map(ToOwned::to_owned)
                .ok_or(CityGError::InvalidInput("alice pop_pk missing"))?;
            bob_pop_pk = bundle_bob
                .header_map
                .get(&hdr::HDR_POP_PK)
                .and_then(Value::as_bytes)
                .map(ToOwned::to_owned)
                .ok_or(CityGError::InvalidInput("bob pop_pk missing"))?;
            server.accept_epoch(&bundle_alice)?;
            server.accept_epoch(&bundle_bob)?;
            assert_eq!(server.members(&cityg_client::demo::DEMO_GID).len(), 2);

            expected_barrier_state = server
                .ctx
                .barrier_group_state(gid.as_slice())
                .cloned()
                .ok_or(CityGError::InvalidInput(
                    "missing barrier state after accepts",
                ))?;
            expected_alice_device_state = server
                .ctx
                .device_chain_get(gid.as_slice(), &alice_pop_pk)
                .cloned()
                .ok_or(CityGError::InvalidInput("missing alice device chain state"))?;
            expected_bob_device_state = server
                .ctx
                .device_chain_get(gid.as_slice(), &bob_pop_pk)
                .cloned()
                .ok_or(CityGError::InvalidInput("missing bob device chain state"))?;
        }

        let server = demo_server_with_journal(&journal_path);
        assert_eq!(server.members(&cityg_client::demo::DEMO_GID).len(), 2);
        assert_eq!(
            server
                .ctx
                .barrier_group_state(gid.as_slice())
                .ok_or(CityGError::InvalidInput("missing recovered barrier state"))?,
            &expected_barrier_state
        );
        assert_eq!(
            server.ctx.device_chain_get(gid.as_slice(), &alice_pop_pk),
            Some(&expected_alice_device_state)
        );
        assert_eq!(
            server.ctx.device_chain_get(gid.as_slice(), &bob_pop_pk),
            Some(&expected_bob_device_state)
        );
        assert_eq!(expected_alice_device_state.last_pcs_refresh_ec, None);
        assert_eq!(expected_bob_device_state.last_pcs_refresh_ec, None);
        Ok(())
    }

    #[test]
    fn replay_rehydrates_missing_join_finalize_auth_for_bound_author() -> Result<(), CityGError> {
        let mut state = super::GroupState {
            n_max: 4,
            ..super::GroupState::default()
        };
        state.barrier_initialized = true;
        state.barrier_version = 1;
        state.barrier_pk_entries = super::build_all_blank_pk_entries(state.n_max)?;
        let leaf = cityg_client::demo::demo_member_leaf("replay-join-finalize-author");
        let pop_pk = vec![0xA7; 32];
        let join_finalize_auth_token = [0xE7; 32];
        state.leaf_device_pk.insert(leaf, pop_pk.clone());
        let join_ek = vec![0xA5; 1184];
        let delta = cityg_client::MembershipDelta {
            joined: vec![leaf],
            revoked: Vec::new(),
        };
        let updater_leaf = super::cover_leaf_index(&leaf, state.n_max);
        let leaf_base = usize::try_from(state.n_max.saturating_sub(1))
            .map_err(|_| CityGError::InvalidInput("leaf base overflow"))?;
        let leaf_node = leaf_base
            + usize::try_from(updater_leaf)
                .map_err(|_| CityGError::InvalidInput("leaf index overflow"))?;
        let sibling_node = super::sibling_node(leaf_node)
            .ok_or(CityGError::InvalidInput("invalid updater leaf node"))?;
        let parent_node = (leaf_node - 1) / 2;
        let path_nodes = vec![leaf_node as u64, parent_node as u64, 0];
        let target_ek = vec![0x91; 1184];
        state.barrier_pk_entries[sibling_node] = target_ek.clone();
        state.kem_tree_hash_after =
            super::compute_barrier_tree_hash(state.n_max, state.barrier_pk_entries.as_slice())?;

        let mut snapshot_pre = state.barrier_pk_entries.clone();
        snapshot_pre[leaf_node] = join_ek.clone();
        super::blank_internal_path_from_leaf(snapshot_pre.as_mut_slice(), leaf_node);
        let kem_before = super::compute_barrier_tree_hash(state.n_max, snapshot_pre.as_slice())?;

        let mut snapshot_post = snapshot_pre.clone();
        let ek_root = vec![0x11; 1184];
        let ek_parent = vec![0x22; 1184];
        snapshot_post[0] = ek_root.clone();
        snapshot_post[parent_node] = ek_parent.clone();
        let kem_after = super::compute_barrier_tree_hash(state.n_max, snapshot_post.as_slice())?;

        let target_pkhash = super::compute_barrier_pkhash(target_ek.as_slice())?;
        let cover_payload = super::KemTreeCoverPayloadWire(
            u64::from(updater_leaf),
            path_nodes,
            None,
            vec![super::NodeCiphertextWire(
                parent_node as u64,
                sibling_node as u64,
                target_pkhash[..16].to_vec(),
                vec![0x33; 1088],
                vec![0x44; 48],
            )],
            vec![
                super::NewPublicKeyWire(0, ek_root),
                super::NewPublicKeyWire(parent_node as u64, ek_parent),
            ],
        );
        let revocation_roots_hash = super::compute_revocation_roots_hash(&[0u8; 32], &[0u8; 32])?;
        state.barrier_roots_hash = revocation_roots_hash;
        let barrier_update = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            2,
            1,
            state.n_max,
            revocation_roots_hash.to_vec(),
            kem_before.to_vec(),
            kem_after.to_vec(),
            super::to_cbor_vec(&cover_payload)?,
        );

        let mut header = BTreeMap::new();
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&barrier_update)?),
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(2u64)),
        );
        header.insert(hdr::HDR_REVOKED_SINCE_ROOT, Value::Bytes(vec![0u8; 32]));
        header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(vec![0u8; 32]));
        header.insert(hdr::HDR_BARRIER_LEAF_PK, Value::Bytes(join_ek));
        header.insert(hdr::HDR_POP_PK, Value::Bytes(pop_pk));
        header.insert(
            hdr::HDR_JOIN_FINALIZE_AUTH,
            Value::Bytes(join_finalize_auth_token.to_vec()),
        );

        let err = match super::validate_barrier_update_against_roster(&state, &header, &delta) {
            Ok(_) => {
                return Err(CityGError::InvalidInput(
                    "missing pending join_finalize auth must fail live validation",
                ));
            }
            Err(err) => err,
        };
        assert!(matches!(
            err,
            CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                if freeze.code == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.code
                    && freeze.reason == msphf_orchestrator::FREEZE_BARRIER_UPDATER_INVALID.reason
        ));

        super::rehydrate_replay_join_finalize_auth(&mut state, &header)?;
        let record =
            state
                .pending_join_finalize_auth
                .get(&leaf)
                .ok_or(CityGError::InvalidInput(
                    "replay rehydration must synthesize pending join_finalize auth",
                ))?;
        assert_eq!(record.token, join_finalize_auth_token);
        assert_eq!(record.cover_leaf_index, updater_leaf);
        assert!(
            super::validate_barrier_update_against_roster(&state, &header, &delta)?.is_some(),
            "rehydrated replay state must validate the historical reason-2 merge"
        );
        Ok(())
    }

    #[test]
    fn crash_recovery_does_not_rollback_barrier_state_from_stale_kbroad_snapshot()
    -> Result<(), CityGError> {
        let _guard = super::journal_serial_guard();
        let dir = tempdir()?;
        let journal_path = dir.path().join("cityg-server-stale-kbroad.journal");
        let gid = cityg_client::demo::DEMO_GID.to_vec();
        let expected_barrier_state: msphf_orchestrator::BarrierGroupState;

        {
            let mut server = demo_server_with_journal(&journal_path);
            server.persist_kbroad_state()?;
            let bundle_alice = cityg_client::demo::demo_bundle("alice")?;
            let bundle_bob = cityg_client::demo::demo_bundle("bob")?;
            server.accept_epoch(&bundle_alice)?;
            server.accept_epoch(&bundle_bob)?;
            expected_barrier_state = server
                .ctx
                .barrier_group_state(gid.as_slice())
                .cloned()
                .ok_or(CityGError::InvalidInput(
                    "missing barrier state after accepts",
                ))?;
            assert_eq!(server.members(gid.as_slice()).len(), 2);
        }

        let reloaded = demo_server_with_journal(&journal_path);
        assert_eq!(reloaded.members(gid.as_slice()).len(), 2);
        assert_eq!(
            reloaded
                .ctx
                .barrier_group_state(gid.as_slice())
                .ok_or(CityGError::InvalidInput("missing recovered barrier state"))?,
            &expected_barrier_state
        );
        Ok(())
    }

    #[test]
    fn overlay_persisted_runtime_metadata_after_replay_prefers_self_consistent_persisted_barrier_state()
    -> Result<(), CityGError> {
        let gid = [0xA7; 32];
        let kbroad_public = vec![0x66; 16];
        let n_max = 2u64;
        let barrier_pk_entries = super::build_all_blank_pk_entries(n_max)?;
        let kem_tree_hash_after =
            super::compute_barrier_tree_hash(n_max, barrier_pk_entries.as_slice())?;
        let barrier_roots_hash = [0xCC; 32];
        let predecessor_hash = [0xDD; 32];
        let persisted_update = super::to_cbor_vec(&super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            3,
            2,
            n_max,
            barrier_roots_hash.to_vec(),
            predecessor_hash.to_vec(),
            kem_tree_hash_after.to_vec(),
            Vec::new(),
        ))?;

        let mut server = CityGServer::new(ServerConfig::new());
        server.ctx.set_kbroad_registry(Some(BTreeMap::from([(
            gid.to_vec(),
            kbroad_public.clone(),
        )])));
        server.roster.groups.insert(
            gid.to_vec(),
            super::GroupState {
                barrier_initialized: true,
                barrier_version: 2,
                barrier_roots_hash: [0x11; 32],
                kem_tree_hash_after,
                n_max,
                barrier_pk_entries: barrier_pk_entries.clone(),
                current_accepted_barrier_update: super::to_cbor_vec(&super::BarrierUpdateWire(
                    "barrier-v1".to_string(),
                    2,
                    1,
                    n_max,
                    [0x22; 32].to_vec(),
                    predecessor_hash.to_vec(),
                    kem_tree_hash_after.to_vec(),
                    Vec::new(),
                ))?,
                ..super::GroupState::default()
            },
        );
        server.ctx.insert_barrier_group_state(
            gid.as_slice(),
            msphf_orchestrator::BarrierGroupState {
                barrier_initialized: true,
                barrier_version: 2,
                barrier_roots_hash: [0x11; 32],
                kem_tree_hash_after,
                n_max,
                ..msphf_orchestrator::BarrierGroupState::default()
            },
        );

        let persisted = BTreeMap::from([(
            gid.to_vec(),
            PersistedKbroadRoomState {
                kbroad_public,
                barrier_initialized: true,
                barrier_version: 3,
                barrier_roots_hash,
                kem_tree_hash_after,
                n_max,
                barrier_pk_entries,
                current_accepted_barrier_update: persisted_update,
                current_accepted_barrier_predecessor_hash: predecessor_hash,
                revoked_leaf_ids_hex: vec![hex::encode([0x44; 32])],
                ..PersistedKbroadRoomState::default()
            },
        )]);

        server.overlay_persisted_runtime_metadata_after_replay(&persisted)?;

        let group = server
            .roster
            .groups
            .get(gid.as_slice())
            .ok_or(CityGError::InvalidInput("missing overlaid group"))?;
        assert_eq!(group.barrier_version, 3);
        assert_eq!(group.barrier_roots_hash, barrier_roots_hash);
        assert_eq!(
            group.current_accepted_barrier_predecessor_hash,
            predecessor_hash
        );
        assert!(group.revoked.contains(&[0x44; 32]));
        let ctx_state = server
            .ctx
            .barrier_group_state(gid.as_slice())
            .ok_or(CityGError::InvalidInput("missing overlaid ctx state"))?;
        assert_eq!(ctx_state.barrier_version, 3);
        assert_eq!(ctx_state.barrier_roots_hash, barrier_roots_hash);
        Ok(())
    }

    #[test]
    fn crash_recovery_replays_pcs_refresh_last_refresh_state() -> Result<(), CityGError> {
        let _guard = super::journal_serial_guard();
        let dir = tempdir()?;
        let journal_path = dir.path().join("cityg-server-pcs-refresh.journal");
        let gid = cityg_client::demo::DEMO_GID;
        let expected_refresh_ec: u64;
        let expected_group_state: msphf_orchestrator::BarrierGroupState;
        let expected_device_state: msphf_orchestrator::DeviceChainState;
        let expected_pop_pk: Vec<u8>;

        {
            let generated = build_genesis_member_bundle(0x71)?;
            expected_pop_pk = generated.pop_public_key.clone();

            let mut server = demo_server_with_journal(&journal_path);
            server.accept_epoch(&generated.bundle)?;
            let existing_device_state = server
                .ctx
                .device_chain_get(gid.as_slice(), expected_pop_pk.as_slice())
                .cloned()
                .ok_or(CityGError::InvalidInput(
                    "missing device state after genesis accept",
                ))?;
            expected_refresh_ec = existing_device_state.last_ec.saturating_add(1);
            {
                let group = server.roster.groups.get_mut(gid.as_slice()).ok_or(
                    CityGError::InvalidInput("missing roster group after genesis accept"),
                )?;
                group.last_pcs_refresh_ec = Some(expected_refresh_ec);
            }
            {
                let ctx_state = server.ctx.barrier_group_state_entry_mut(gid.as_slice());
                ctx_state.last_pcs_refresh_ec = Some(expected_refresh_ec);
            }
            expected_group_state = server
                .ctx
                .barrier_group_state(gid.as_slice())
                .cloned()
                .ok_or(CityGError::InvalidInput(
                    "missing refreshed group barrier state",
                ))?;
            let mut updated_device_state = existing_device_state.clone();
            updated_device_state.last_pcs_refresh_ec = Some(expected_refresh_ec);
            server.ctx.insert_device_chain_state(
                gid.as_slice(),
                expected_pop_pk.as_slice(),
                updated_device_state.clone(),
            );
            expected_device_state = updated_device_state;
            server.persist_kbroad_state()?;
            assert_eq!(
                expected_group_state.last_pcs_refresh_ec,
                Some(expected_refresh_ec)
            );
            assert_eq!(
                expected_device_state.last_pcs_refresh_ec,
                Some(expected_refresh_ec)
            );
        }

        let reloaded = demo_server_with_journal(&journal_path);
        let recovered_group =
            reloaded
                .ctx
                .barrier_group_state(gid.as_slice())
                .ok_or(CityGError::InvalidInput(
                    "missing recovered group barrier state",
                ))?;
        let recovered_device = reloaded
            .ctx
            .device_chain_get(gid.as_slice(), expected_pop_pk.as_slice())
            .ok_or(CityGError::InvalidInput(
                "missing recovered refreshed device state",
            ))?;

        assert_eq!(recovered_group, &expected_group_state);
        assert_eq!(recovered_device, &expected_device_state);
        assert_eq!(
            recovered_group.last_pcs_refresh_ec,
            Some(expected_refresh_ec)
        );
        assert_eq!(
            recovered_device.last_pcs_refresh_ec,
            Some(expected_refresh_ec)
        );
        Ok(())
    }

    #[test]
    fn crash_recovery_preserves_current_predecessor_snapshot_history_commitment()
    -> Result<(), CityGError> {
        let _guard = super::journal_serial_guard();
        let dir = tempdir()?;
        let journal_path = dir.path().join("cityg-server-current-predecessor.journal");
        let gid = cityg_client::demo::DEMO_GID;
        let predecessor_hash: [u8; 32];
        let expected_current;

        {
            let mut server = demo_server_with_journal(&journal_path);
            let alice = cityg_client::demo::demo_bundle("alice")?;
            server.accept_epoch(&alice)?;
            predecessor_hash = server.barrier_kem_tree_hash_after(gid.as_slice()).ok_or(
                CityGError::InvalidInput("missing predecessor hash after first accept"),
            )?;
            let bob = cityg_client::demo::demo_bundle("bob")?;
            server.accept_epoch(&bob)?;
            expected_current = server.current_history_commitment(&gid)?;
        }

        let mut reloaded = demo_server_with_journal(&journal_path);
        let snapshot = reloaded.fetch_barrier_public_tree(&gid, &predecessor_hash)?;
        assert_eq!(snapshot.kem_tree_hash_after, predecessor_hash);
        assert_eq!(snapshot.history_commitment, expected_current);
        Ok(())
    }

    #[test]
    fn crash_recovery_accept_after_restart_preserves_current_predecessor_snapshot_history_commitment()
    -> Result<(), CityGError> {
        let _guard = super::journal_serial_guard();
        let dir = tempdir()?;
        let journal_path = dir
            .path()
            .join("cityg-server-current-predecessor-post-restart.journal");
        let gid = cityg_client::demo::DEMO_GID;
        let predecessor_hash: [u8; 32];

        {
            let mut server = demo_server_with_journal(&journal_path);
            let alice = cityg_client::demo::demo_bundle("alice")?;
            server.accept_epoch(&alice)?;
            predecessor_hash = server.barrier_kem_tree_hash_after(gid.as_slice()).ok_or(
                CityGError::InvalidInput("missing predecessor hash before restart"),
            )?;
        }

        let mut reloaded = demo_server_with_journal(&journal_path);
        let bob = cityg_client::demo::demo_bundle("bob")?;
        reloaded.accept_epoch(&bob)?;
        let expected_current = reloaded.current_history_commitment(&gid)?;
        let snapshot = reloaded.fetch_barrier_public_tree(&gid, &predecessor_hash)?;
        assert_eq!(snapshot.kem_tree_hash_after, predecessor_hash);
        assert_eq!(snapshot.history_commitment, expected_current);
        Ok(())
    }

    #[test]
    fn crash_recovery_without_membership_artifact_rejects_genesis_joinset_resolution()
    -> Result<(), CityGError> {
        let _guard = super::journal_serial_guard();
        let dir = tempdir()?;
        let journal_path = dir.path().join("cityg-server-genesis-artifact.journal");

        {
            let server = demo_server_with_journal(&journal_path);
            server.persist_kbroad_state()?;
        }

        let mut reloaded = demo_server_with_journal(&journal_path);
        let err = reloaded
            .resolve_joins_since(&cityg_client::demo::DEMO_GID, 0)
            .expect_err("restart without membership artifact must fail closed");
        assert!(matches!(
            err,
            CityGError::InvalidInput(super::GENESIS_PROVISIONING_ARTIFACT_MISSING_ERR)
        ));
        Ok(())
    }

    #[test]
    fn recovery_error_does_not_leave_server_replaying_or_disable_journaling()
    -> Result<(), CityGError> {
        let _guard = super::journal_serial_guard();
        let dir = tempdir()?;
        let journal_path = dir.path().join("corrupt.journal");
        {
            let mut file = File::create(&journal_path)?;
            let bad = [0xFFu8];
            file.write_all(&(bad.len() as u32).to_le_bytes())?;
            file.write_all(&bad)?;
            file.flush()?;
        }

        let mut server = demo_server_with_journal(&journal_path);
        assert!(
            !server.replaying,
            "replay flag must reset even when startup recovery fails"
        );

        let bundle = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&bundle)?;

        let entries = super::ServerJournal::load_entries(&journal_path)?;
        assert_eq!(
            entries.len(),
            2,
            "post-recovery accepts must still append to the journal"
        );
        let latest = entries
            .last()
            .ok_or(CityGError::InvalidInput("missing appended journal entry"))?;
        let decoded = ClientEpochBundle::from_cbor(latest)?;
        assert_eq!(decoded.gid(), cityg_client::demo::DEMO_GID.as_slice());
        Ok(())
    }

    #[test]
    fn chaos_replay_matches_reference_server() -> Result<(), CityGError> {
        let _serial = super::journal_serial_guard();
        let dir = tempdir()?;
        let journal_path = dir.path().join("chaos.journal");
        let base_config = demo_acceptance_config();

        let mut primary_cfg = base_config.clone();
        primary_cfg.state_path = Some(journal_path.clone());
        let mut primary = CityGServer::new(primary_cfg);
        let mut reference = CityGServer::new(base_config.clone());

        let mut membership: Vec<[u8; 32]> = Vec::new();
        let mut next_label = 0u32;
        let mut rng = StdRng::seed_from_u64(0xC17C5EED);

        for step in 0..64 {
            let action = if step < 3 { 0 } else { rng.random_range(0..3) };
            match action {
                0 => perform_single_join(
                    &mut primary,
                    &mut reference,
                    &mut membership,
                    &mut next_label,
                )?,
                _ => {
                    drop(primary);
                    let mut cfg = base_config.clone();
                    cfg.state_path = Some(journal_path.clone());
                    primary = CityGServer::new(cfg);
                }
            }
            assert_members_sync(&primary, &reference);
        }

        Ok(())
    }

    #[test]
    fn chaos_replay_survives_journal_failures() -> Result<(), CityGError> {
        let _serial = super::journal_serial_guard();
        let dir = tempdir()?;
        let journal_path = dir.path().join("chaos-fail.journal");
        let base_config = demo_acceptance_config();

        let mut primary = reload_server(&base_config, &journal_path);
        let mut reference = CityGServer::new(base_config.clone());
        let mut membership: Vec<[u8; 32]> = Vec::new();
        let mut next_label = 0u32;
        let mut rng = StdRng::seed_from_u64(0xC17F_1A17);

        for step in 0..96 {
            let action = if step < 2 { 0 } else { rng.random_range(0..3) };
            match action {
                0 => perform_single_join(
                    &mut primary,
                    &mut reference,
                    &mut membership,
                    &mut next_label,
                )?,
                1 => {
                    perform_join_with_forced_journal_failure(
                        &mut primary,
                        &mut membership,
                        &mut next_label,
                    )?;
                    primary = reload_server(&base_config, &journal_path);
                }
                _ => {
                    primary = reload_server(&base_config, &journal_path);
                }
            }
            assert_members_sync(&primary, &reference);
        }

        Ok(())
    }

    fn perform_single_join(
        primary: &mut CityGServer,
        reference: &mut CityGServer,
        membership: &mut Vec<[u8; 32]>,
        next_label: &mut u32,
    ) -> Result<(), CityGError> {
        let (bundle, leaf) = build_join_bundle(membership, next_label)?;
        let bundle_ref = bundle.clone();
        primary.accept_epoch(&bundle)?;
        reference.accept_epoch(&bundle_ref)?;
        membership.push(leaf);
        membership.sort();
        Ok(())
    }

    fn perform_join_with_forced_journal_failure(
        primary: &mut CityGServer,
        membership: &mut [[u8; 32]],
        next_label: &mut u32,
    ) -> Result<(), CityGError> {
        let (bundle, _) = build_join_bundle(membership, next_label)?;
        let _guard = super::fail_journal_after(0);
        let err = primary
            .accept_epoch(&bundle)
            .expect_err("forced journal failure should abort acceptance");
        if !matches!(err, CityGError::Io(_)) {
            return Err(err);
        }
        *next_label = next_label.saturating_sub(1);
        Ok(())
    }

    fn build_join_bundle(
        parent_leaves: &[[u8; 32]],
        next_label: &mut u32,
    ) -> Result<(ClientEpochBundle, [u8; 32]), CityGError> {
        let mut sorted = parent_leaves.to_vec();
        sorted.sort();
        sorted.dedup();
        let reserved_cover_indices: BTreeSet<u32> = sorted
            .iter()
            .map(|leaf| super::cover_leaf_index(leaf, super::DEFAULT_BARRIER_N_MAX))
            .collect();

        let pool = chaos_leaf_pool();
        let mut index = *next_label as usize;
        while index < pool.len() {
            let leaf = pool[index];
            index += 1;
            if sorted.binary_search(&leaf).is_ok() {
                continue;
            }
            let cover_index = super::cover_leaf_index(&leaf, super::DEFAULT_BARRIER_N_MAX);
            if reserved_cover_indices.contains(&cover_index) {
                continue;
            }
            *next_label = index as u32;
            let bundle = cityg_client::demo::demo_bundle_with_parent_leaves(parent_leaves, leaf)?;
            return Ok((bundle, leaf));
        }

        Err(CityGError::InvalidInput("chaos leaf pool exhausted"))
    }

    fn chaos_leaf_pool() -> &'static Vec<[u8; 32]> {
        static POOL: std::sync::OnceLock<Vec<[u8; 32]>> = std::sync::OnceLock::new();
        POOL.get_or_init(|| {
            let mut leaves: Vec<[u8; 32]> = (0..4096)
                .map(|idx| cityg_client::demo::demo_member_leaf(&format!("chaos-member-{idx}")))
                .collect();
            leaves.sort();
            leaves.dedup();
            leaves
        })
    }

    fn assert_members_sync(primary: &CityGServer, reference: &CityGServer) {
        let primary_members = primary.members(&cityg_client::demo::DEMO_GID);
        let reference_members = reference.members(&cityg_client::demo::DEMO_GID);
        assert_eq!(primary_members, reference_members, "membership diverged");
    }

    fn reload_server(base_config: &ServerConfig, journal_path: &Path) -> CityGServer {
        let mut cfg = base_config.clone();
        cfg.state_path = Some(journal_path.to_path_buf());
        CityGServer::new(cfg)
    }

    #[test]
    fn merge_ticket_after_single_join_has_parity() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let bundle = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&bundle)?;

        let leaf_id = cityg_client::demo::demo_member_leaf("alice");
        let ticket = server.build_merge_ticket(&cityg_client::demo::DEMO_GID, &leaf_id)?;

        assert!(
            !ticket.parities.is_empty(),
            "expected pivot parity snapshot for current parent root"
        );
        assert_eq!(ticket.parent_root, ticket.parities[0].parent_root);
        Ok(())
    }

    #[test]
    fn merge_ticket_encodes_requester_self_revocation_delta() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let bundle = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&bundle)?;

        let leaf_id = cityg_client::demo::demo_member_leaf("alice");
        let ticket = server.build_merge_ticket(&cityg_client::demo::DEMO_GID, &leaf_id)?;
        let srx = cityg_client::witness::SrxInputsOwned::from_cbor(ticket.srx_cbor.as_slice())
            .map_err(|_| CityGError::InvalidInput("merge srx decode failed"))?;

        assert!(
            srx.join_leaf_ids.is_empty(),
            "merge must not add join leaves"
        );
        assert_eq!(
            srx.since_leaf_ids,
            vec![leaf_id],
            "merge ticket should include requester in revoked_since delta"
        );
        let expected_since_root = msphf_core::merkle::canonical_set_root(&[leaf_id])?;
        assert_eq!(ticket.revoked_since_root, expected_since_root);
        assert_eq!(ticket.revoked_root, expected_since_root);
        Ok(())
    }

    #[test]
    fn resolve_joins_since_reports_join_metadata() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let bundle = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&bundle)?;

        let records = server.resolve_joins_since(&cityg_client::demo::DEMO_GID, 0)?;
        assert!(
            !records.records.is_empty(),
            "expected at least one join record"
        );
        let record = &records.records[0];
        assert!(record.leaf_index > 0);
        assert!(!record.device_pk.is_empty());
        assert!(
            record.ek_leaf.len() == 1184,
            "ek_leaf must be present and ML-KEM-768 size"
        );
        Ok(())
    }

    #[test]
    fn resolve_joins_since_filters_post_genesis_join_history() -> Result<(), CityGError> {
        let gid = [0x82; 32];
        let mut server = CityGServer::new(ServerConfig::new());
        let state = server.roster.groups.entry(gid.to_vec()).or_default();
        state.barrier_version = 3;
        let leaf_v2 = colliding_cover_leaf(8);
        let leaf_v3a = colliding_cover_leaf(10);
        let leaf_v3b = colliding_cover_leaf(9);
        let mut membership = cityg_client::GroupMembership::default();
        membership.apply_delta(&cityg_client::MembershipDelta {
            joined: vec![leaf_v2, leaf_v3a, leaf_v3b],
            revoked: Vec::new(),
        });
        let latest_root = [0xA1; 32];
        state.latest_root = Some(latest_root);
        state.snapshots.insert(latest_root, membership);
        state.join_history = vec![
            super::JoinLeafHistoryRecord {
                leaf_id: colliding_cover_leaf(7),
                barrier_version: 1,
                leaf_index: 7,
                device_pk: vec![0x11; 4],
                ek_leaf: vec![0x21; 1184],
            },
            super::JoinLeafHistoryRecord {
                leaf_id: leaf_v2,
                barrier_version: 2,
                leaf_index: 8,
                device_pk: vec![0x12; 4],
                ek_leaf: vec![0x22; 1184],
            },
            super::JoinLeafHistoryRecord {
                leaf_id: leaf_v3a,
                barrier_version: 3,
                leaf_index: 10,
                device_pk: vec![0x13; 4],
                ek_leaf: vec![0x23; 1184],
            },
            super::JoinLeafHistoryRecord {
                leaf_id: leaf_v3b,
                barrier_version: 3,
                leaf_index: 9,
                device_pk: vec![0x14; 4],
                ek_leaf: vec![0x24; 1184],
            },
        ];

        let records = server.resolve_joins_since(&gid, 1)?;
        assert_eq!(records.records.len(), 3);
        assert_eq!(records.records[0].leaf_index, 8);
        assert_eq!(records.records[0].device_pk, vec![0x12; 4]);
        assert_eq!(records.records[0].ek_leaf, vec![0x22; 1184]);
        assert_eq!(records.records[1].leaf_index, 9);
        assert_eq!(records.records[2].leaf_index, 10);
        Ok(())
    }

    #[test]
    fn resolve_joins_since_prunes_resolved_and_revoked_join_history() -> Result<(), CityGError> {
        let gid = [0x85; 32];
        let mut server = CityGServer::new(ServerConfig::new());
        let leaf_active = colliding_cover_leaf(11);
        let leaf_revoked = colliding_cover_leaf(12);
        let latest_root = [0xB1; 32];

        let mut membership = cityg_client::GroupMembership::default();
        membership.apply_delta(&cityg_client::MembershipDelta {
            joined: vec![leaf_active],
            revoked: Vec::new(),
        });
        let state = server.roster.groups.entry(gid.to_vec()).or_default();
        state.barrier_version = 5;
        state.latest_root = Some(latest_root);
        state.snapshots.insert(latest_root, membership);
        state.join_history = vec![
            super::JoinLeafHistoryRecord {
                leaf_id: leaf_active,
                barrier_version: 2,
                leaf_index: 11,
                device_pk: vec![0x11; 4],
                ek_leaf: vec![0x21; 1184],
            },
            super::JoinLeafHistoryRecord {
                leaf_id: leaf_active,
                barrier_version: 5,
                leaf_index: 11,
                device_pk: vec![0x15; 4],
                ek_leaf: vec![0x25; 1184],
            },
            super::JoinLeafHistoryRecord {
                leaf_id: leaf_revoked,
                barrier_version: 4,
                leaf_index: 12,
                device_pk: vec![0x12; 4],
                ek_leaf: vec![0x22; 1184],
            },
        ];

        let records = server.resolve_joins_since(&gid, 1)?;
        assert_eq!(records.records.len(), 1);
        assert_eq!(records.records[0].leaf_index, 11);
        assert_eq!(records.records[0].device_pk, vec![0x15; 4]);
        assert_eq!(records.records[0].ek_leaf, vec![0x25; 1184]);

        let pruned = &server
            .roster
            .groups
            .get(gid.as_slice())
            .ok_or(CityGError::InvalidInput("group not found"))?
            .join_history;
        assert_eq!(pruned.len(), 1);
        assert_eq!(pruned[0].leaf_id, leaf_active);
        assert_eq!(pruned[0].barrier_version, 5);
        Ok(())
    }

    #[test]
    fn resolve_joins_since_rejects_duplicate_active_cover_allocations() -> Result<(), CityGError> {
        let gid = [0x84; 32];
        let mut server = CityGServer::new(ServerConfig::new());
        let leaf_a = colliding_cover_leaf(5);
        let leaf_b = colliding_cover_leaf(1029);
        let mut membership = cityg_client::GroupMembership::default();
        membership.apply_delta(&cityg_client::MembershipDelta {
            joined: vec![leaf_a, leaf_b],
            revoked: Vec::new(),
        });
        let root = msphf_core::merkle::canonical_set_root(&[leaf_a, leaf_b])?;
        let state = server.roster.groups.entry(gid.to_vec()).or_default();
        state.snapshots.insert(root, membership);
        state.latest_root = Some(root);

        let err = server
            .resolve_joins_since(&gid, 0)
            .expect_err("duplicate active cover allocations must fail closed");
        assert!(matches!(
            err,
            CityGError::InvalidInput(super::DUPLICATE_ACTIVE_COVER_LEAF_ALLOCATION_ERR)
        ));
        Ok(())
    }

    #[test]
    fn resolve_joins_since_genesis_without_snapshot_rejects_missing_artifact()
    -> Result<(), CityGError> {
        let gid = [0x81; 32];
        let mut server = CityGServer::new(ServerConfig::new());
        server
            .roster
            .groups
            .insert(gid.to_vec(), super::GroupState::default());
        let err = server
            .resolve_joins_since(&gid, 0)
            .expect_err("missing genesis provisioning artifact must fail closed");
        assert!(matches!(
            err,
            CityGError::InvalidInput(super::GENESIS_PROVISIONING_ARTIFACT_MISSING_ERR)
        ));
        Ok(())
    }

    #[test]
    fn validate_barrier_update_rejects_genesis_update_without_snapshot_artifact()
    -> Result<(), CityGError> {
        let mut state = super::GroupState {
            n_max: 1,
            barrier_initialized: true,
            barrier_version: 0,
            ..super::GroupState::default()
        };
        state.barrier_pk_entries = super::build_all_blank_pk_entries(state.n_max)?;
        state.kem_tree_hash_after =
            super::compute_barrier_tree_hash(state.n_max, state.barrier_pk_entries.as_slice())?;
        state.barrier_roots_hash = super::compute_revocation_roots_hash(&[0u8; 32], &[0u8; 32])?;

        let barrier_update = super::BarrierUpdateWire(
            "barrier-v1".to_string(),
            0,
            0,
            state.n_max,
            state.barrier_roots_hash.to_vec(),
            state.kem_tree_hash_after.to_vec(),
            state.kem_tree_hash_after.to_vec(),
            super::to_cbor_vec(&super::KemTreeCoverPayloadWire(
                0,
                vec![0],
                None,
                Vec::new(),
                Vec::new(),
            ))?,
        );

        let mut header = BTreeMap::new();
        header.insert(
            hdr::HDR_BARRIER_UPDATE,
            Value::Bytes(super::to_cbor_vec(&barrier_update)?),
        );
        header.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(0u64)),
        );
        header.insert(112, Value::Bytes(vec![0u8; 32]));
        header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(vec![0u8; 32]));

        let err = match super::validate_barrier_update_against_roster(
            &state,
            &header,
            &cityg_client::MembershipDelta::default(),
        ) {
            Ok(_) => {
                return Err(CityGError::InvalidInput(
                    "genesis barrier update without snapshot artifact must freeze",
                ));
            }
            Err(err) => err,
        };
        assert!(matches!(
            err,
            CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                if freeze.code == msphf_orchestrator::FREEZE_BARRIER_GENESIS_REQUIRED.code
                    && freeze.reason
                        == msphf_orchestrator::FREEZE_BARRIER_GENESIS_REQUIRED.reason
        ));
        Ok(())
    }

    #[test]
    fn accept_epoch_rejects_join_without_barrier_leaf_pk() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let mut bundle = cityg_client::demo::demo_bundle("alice")?;
        bundle.header_map.remove(&hdr::HDR_BARRIER_LEAF_PK);

        let err = server
            .accept_epoch(&bundle)
            .expect_err("join without barrier leaf key must be rejected");
        assert!(
            matches!(err, CityGError::InvalidInput(message) if message.contains("barrier_leaf_pk"))
                || matches!(
                    err,
                    CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Msphf(
                        msphf_core::MsphfError::InvalidInput(ref message)
                    )) if message.contains("anchor_hdr_ctx mismatch")
                )
                || matches!(
                    err,
                    CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(code))
                        if code.code == 9071
                ),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn malformed_join_rejection_does_not_poison_room_state() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let alice = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&alice)?;
        assert_eq!(
            server.members(&cityg_client::demo::DEMO_GID).len(),
            1,
            "room must be healthy after the first honest join"
        );

        let mut malformed_bob = cityg_client::demo::demo_bundle("bob")?;
        malformed_bob.header_map.remove(&hdr::HDR_BARRIER_LEAF_PK);
        let err = server
            .accept_epoch(&malformed_bob)
            .expect_err("malformed join must be rejected");
        assert!(
            matches!(err, CityGError::InvalidInput(_)) || matches!(err, CityGError::Acceptance(_)),
            "unexpected malformed join error: {err:?}"
        );

        let members_after_reject = server.members(&cityg_client::demo::DEMO_GID);
        assert_eq!(
            members_after_reject.len(),
            1,
            "rejected malformed join must not change membership"
        );
        assert_eq!(
            members_after_reject[0],
            cityg_client::demo::demo_member_leaf("alice"),
            "the healthy survivor roster must remain intact"
        );

        let honest_bob = cityg_client::demo::demo_bundle("bob")?;
        server.accept_epoch(&honest_bob)?;
        assert_eq!(
            server.members(&cityg_client::demo::DEMO_GID).len(),
            2,
            "a later honest join must still succeed"
        );
        Ok(())
    }

    #[test]
    fn malformed_leave_rejection_does_not_poison_room_state() -> Result<(), CityGError> {
        let mut server = demo_server_with_global_history_authority();
        let gid = cityg_client::demo::DEMO_GID;
        let alice = build_genesis_member_bundle(0x86)?;
        server.accept_epoch(&alice.bundle)?;
        let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;
        let mut malformed_leave =
            build_leave_bundle_for_member(&mut server, &alice, &alice.bundle)?;
        assert_eq!(
            u64_from_header(&malformed_leave.header_map, hdr::HDR_BARRIER_UPDATE_REASON)?,
            0,
            "leave bundle should use barrier_update reason 0"
        );
        malformed_leave.header_map.remove(&hdr::HDR_BARRIER_UPDATE);
        let err = server
            .accept_epoch(&malformed_leave)
            .expect_err("malformed leave must be rejected");
        assert!(
            matches!(err, CityGError::InvalidInput(_)) || matches!(err, CityGError::Acceptance(_)),
            "unexpected malformed leave error: {err:?}"
        );

        let members_after_reject = server.members(&gid);
        assert_eq!(
            members_after_reject,
            vec![alice.leaf_id],
            "rejected malformed leave must not poison the live roster"
        );

        let bob = build_join_member_from_server_ticket(&mut server, &gid, 0x8A, true)?;
        server.accept_epoch(&bob.bundle)?;
        let members_after_honest_join = server.members(&gid);
        assert_eq!(
            members_after_honest_join.len(),
            2,
            "a later honest join must still succeed after malformed leave rejection"
        );
        Ok(())
    }

    #[test]
    fn malformed_refresh_rejection_does_not_poison_room_state() -> Result<(), CityGError> {
        let mut server = demo_server_with_global_history_authority();
        let gid = cityg_client::demo::DEMO_GID;
        let alice = build_genesis_member_bundle(0x87)?;
        server.accept_epoch(&alice.bundle)?;
        let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;

        let (join_finalize, _) =
            build_refresh_bundle_for_member(&mut server, &alice, &alice.bundle)?;
        assert_eq!(
            u64_from_header(&join_finalize.header_map, hdr::HDR_BARRIER_UPDATE_REASON)?,
            2,
            "first post-join merge should be join_finalize"
        );
        let mut malformed_refresh = join_finalize.clone();
        malformed_refresh.header_map.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(1u64)),
        );
        assert_eq!(
            u64_from_header(
                &malformed_refresh.header_map,
                hdr::HDR_BARRIER_UPDATE_REASON
            )?,
            1,
            "mutated hostile bundle should masquerade as a refresh"
        );
        malformed_refresh
            .header_map
            .remove(&hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS);
        let err = server
            .accept_epoch(&malformed_refresh)
            .expect_err("malformed refresh must be rejected");
        assert!(
            matches!(err, CityGError::InvalidInput(_)) || matches!(err, CityGError::Acceptance(_)),
            "unexpected malformed refresh error: {err:?}"
        );

        let members_after_reject = server.members(&gid);
        assert_eq!(
            members_after_reject,
            vec![alice.leaf_id],
            "rejected malformed refresh must not poison membership state"
        );

        let bob = build_join_member_from_server_ticket(&mut server, &gid, 0x8B, true)?;
        server.accept_epoch(&bob.bundle)?;
        assert_eq!(
            server.members(&gid).len(),
            2,
            "room must still accept an honest join after malformed refresh rejection"
        );
        Ok(())
    }

    #[test]
    fn malformed_refresh_concurrent_with_honest_join_preserves_live_state() -> Result<(), CityGError>
    {
        let mut server = demo_server_with_global_history_authority();
        let gid = cityg_client::demo::DEMO_GID;
        let alice = build_genesis_member_bundle(0x91)?;
        server.accept_epoch(&alice.bundle)?;
        let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;

        let (join_finalize, _) =
            build_refresh_bundle_for_member(&mut server, &alice, &alice.bundle)?;
        let mut malformed_refresh = join_finalize.clone();
        malformed_refresh.header_map.insert(
            hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(1u64)),
        );
        malformed_refresh
            .header_map
            .remove(&hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS);

        let bob = build_join_member_from_server_ticket(&mut server, &gid, 0x92, true)?;
        server.accept_epoch(&bob.bundle)?;

        let err = server
            .accept_epoch(&malformed_refresh)
            .expect_err("malformed refresh race must be rejected");
        assert!(
            matches!(err, CityGError::InvalidInput(_)) || matches!(err, CityGError::Acceptance(_)),
            "unexpected malformed refresh live-race error: {err:?}"
        );

        let members_after_race = server.members(&gid);
        assert_eq!(
            members_after_race.len(),
            2,
            "malformed refresh race must preserve the healthy live roster without restart"
        );
        assert!(
            members_after_race.contains(&alice.leaf_id)
                && members_after_race.contains(&bob.leaf_id),
            "alice and bob must remain present after the malformed refresh live race"
        );

        let followup_ticket = server.build_merge_ticket_for_refresh(&gid, &alice.leaf_id)?;
        assert_eq!(
            followup_ticket.barrier_version, 0,
            "live malformed refresh race must still allow a healthy survivor refresh ticket"
        );
        Ok(())
    }

    #[test]
    fn malformed_refresh_concurrent_with_honest_join_does_not_poison_restart_recovery()
    -> Result<(), CityGError> {
        let _guard = super::journal_serial_guard();
        let dir = tempdir()?;
        let journal_path = dir.path().join("malformed-refresh-race.journal");
        let gid = cityg_client::demo::DEMO_GID;
        let alice = build_genesis_member_bundle(0x92)?;
        let bob_leaf_id;

        {
            let mut server = demo_server_with_journal_and_global_history_authority(&journal_path);
            server.accept_epoch(&alice.bundle)?;
            let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;

            let (join_finalize, _) =
                build_refresh_bundle_for_member(&mut server, &alice, &alice.bundle)?;
            let mut malformed_refresh = join_finalize.clone();
            malformed_refresh.header_map.insert(
                hdr::HDR_BARRIER_UPDATE_REASON,
                Value::Integer(Integer::from(1u64)),
            );
            malformed_refresh
                .header_map
                .remove(&hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS);

            let bob = build_join_member_from_server_ticket(&mut server, &gid, 0x93, true)?;
            server.accept_epoch(&bob.bundle)?;
            bob_leaf_id = bob.leaf_id;

            let err = server
                .accept_epoch(&malformed_refresh)
                .expect_err("malformed refresh race must be rejected");
            assert!(
                matches!(err, CityGError::InvalidInput(_))
                    || matches!(err, CityGError::Acceptance(_)),
                "unexpected malformed refresh race error: {err:?}"
            );

            let members_before_restart = server.members(&gid);
            assert_eq!(
                members_before_restart.len(),
                2,
                "malformed refresh race must preserve the healthy live roster"
            );
            assert!(
                members_before_restart.contains(&alice.leaf_id)
                    && members_before_restart.contains(&bob.leaf_id),
                "alice and bob must remain visible after the malformed refresh race"
            );
        }

        let mut reloaded = demo_server_with_journal_and_global_history_authority(&journal_path);
        let members_after_restart = reloaded.members(&gid);
        assert_eq!(
            members_after_restart.len(),
            2,
            "restart must preserve the healthy roster after malformed refresh race rejection"
        );
        assert!(
            members_after_restart.contains(&alice.leaf_id)
                && members_after_restart.contains(&bob_leaf_id),
            "alice and bob must remain visible after restart"
        );

        let followup_ticket = reloaded.build_merge_ticket_for_refresh(&gid, &alice.leaf_id)?;
        assert_eq!(
            followup_ticket.barrier_version, 0,
            "restart must still allow a healthy survivor refresh ticket after malformed refresh race"
        );
        Ok(())
    }

    #[test]
    fn hostile_barrier_update_mutations_fail_closed_without_poisoning_restart_recovery()
    -> Result<(), CityGError> {
        let _guard = super::journal_serial_guard();
        let dir = tempdir()?;
        let journal_path = dir.path().join("hostile-barrier-mutations.journal");
        let gid = cityg_client::demo::DEMO_GID;
        let alice = build_genesis_member_bundle(0x95)?;

        {
            let mut server = demo_server_with_journal_and_global_history_authority(&journal_path);
            server.accept_epoch(&alice.bundle)?;
            let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;
            let (pristine_bundle, _) =
                build_refresh_bundle_for_member(&mut server, &alice, &alice.bundle)?;

            for mutation in [
                "missing_witness",
                "corrupt_receipt",
                "corrupt_attestation",
                "corrupt_barrier_update",
                "mismatched_reason",
            ] {
                let mut mutated = pristine_bundle.clone();
                match mutation {
                    "missing_witness" => {
                        mutated
                            .header_map
                            .remove(&hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS);
                    }
                    "corrupt_receipt" => {
                        let Value::Bytes(raw_receipt) = mutated
                            .header_map
                            .get_mut(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT)
                            .ok_or(CityGError::InvalidInput(
                                "missing full verification receipt",
                            ))?
                        else {
                            return Err(CityGError::InvalidInput(
                                "full verification receipt must be bytes",
                            ));
                        };
                        if raw_receipt.is_empty() {
                            raw_receipt.push(0x01);
                        } else {
                            raw_receipt[0] ^= 0x55;
                        }
                    }
                    "corrupt_attestation" => {
                        let Value::Bytes(raw_attestation) = mutated
                            .header_map
                            .get_mut(&hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION)
                            .ok_or(CityGError::InvalidInput(
                                "missing global history attestation",
                            ))?
                        else {
                            return Err(CityGError::InvalidInput(
                                "global history attestation must be bytes",
                            ));
                        };
                        if raw_attestation.is_empty() {
                            raw_attestation.push(0x01);
                        } else {
                            raw_attestation[0] ^= 0xA5;
                        }
                    }
                    "corrupt_barrier_update" => {
                        let Value::Bytes(raw_update) = mutated
                            .header_map
                            .get_mut(&hdr::HDR_BARRIER_UPDATE)
                            .ok_or(CityGError::InvalidInput("missing barrier update"))?
                        else {
                            return Err(CityGError::InvalidInput("barrier update must be bytes"));
                        };
                        raw_update.truncate(raw_update.len().min(4));
                        if raw_update.is_empty() {
                            raw_update.push(0x01);
                        }
                    }
                    "mismatched_reason" => {
                        mutated.header_map.insert(
                            hdr::HDR_BARRIER_UPDATE_REASON,
                            Value::Integer(Integer::from(1u64)),
                        );
                    }
                    _ => unreachable!("unknown mutation"),
                }

                let err = server
                    .accept_epoch(&mutated)
                    .expect_err("hostile mutation must be rejected");
                assert!(
                    matches!(err, CityGError::InvalidInput(_))
                        || matches!(err, CityGError::Acceptance(_)),
                    "unexpected hostile mutation error for {mutation}: {err:?}"
                );
                assert_eq!(
                    server.members(&gid),
                    vec![alice.leaf_id],
                    "mutation {mutation} must not poison the live roster",
                );
            }

            let bob = build_join_member_from_server_ticket(&mut server, &gid, 0x96, true)?;
            server.accept_epoch(&bob.bundle)?;
            let members_after_honest_join = server.members(&gid);
            assert_eq!(
                members_after_honest_join.len(),
                2,
                "room must still accept an honest join after hostile barrier mutations"
            );
        }

        let mut reloaded = demo_server_with_journal_and_global_history_authority(&journal_path);
        let members_after_restart = reloaded.members(&gid);
        assert_eq!(
            members_after_restart.len(),
            2,
            "restart must preserve the healthy roster after hostile barrier mutations"
        );
        let followup_ticket = reloaded.build_merge_ticket_for_refresh(&gid, &alice.leaf_id)?;
        assert_eq!(
            followup_ticket.barrier_version, 0,
            "restart must still allow a healthy survivor refresh ticket after hostile barrier mutations"
        );
        Ok(())
    }

    #[test]
    fn hostile_barrier_update_byte_flip_sweep_fail_closed_without_poisoning_restart_recovery()
    -> Result<(), CityGError> {
        fn mutation_offsets(len: usize) -> Vec<usize> {
            if len == 0 {
                return Vec::new();
            }
            let mut offsets = vec![0, len / 3, (2 * len) / 3, len - 1];
            offsets.sort_unstable();
            offsets.dedup();
            offsets
        }

        let _guard = super::journal_serial_guard();
        let dir = tempdir()?;
        let journal_path = dir.path().join("hostile-barrier-byte-flip-sweep.journal");
        let gid = cityg_client::demo::DEMO_GID;
        let alice = build_genesis_member_bundle(0x95)?;

        {
            let mut server = demo_server_with_journal_and_global_history_authority(&journal_path);
            server.accept_epoch(&alice.bundle)?;
            let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;
            let (pristine_bundle, _) =
                build_refresh_bundle_for_member(&mut server, &alice, &alice.bundle)?;

            let byte_flip_headers = [
                (
                    "witness",
                    hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS,
                    0x11u8,
                ),
                (
                    "receipt",
                    hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT,
                    0x22u8,
                ),
                (
                    "attestation",
                    hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION,
                    0x44u8,
                ),
                ("barrier_update", hdr::HDR_BARRIER_UPDATE, 0x88u8),
            ];

            let mut exercised_cases = 0usize;
            for (label, header, mask) in byte_flip_headers {
                let Some(raw) = pristine_bundle.header_map.get(&header) else {
                    continue;
                };
                let Value::Bytes(raw_bytes) = raw else {
                    return Err(CityGError::InvalidInput(
                        "byte-flip mutation target must be bytes",
                    ));
                };

                for offset in mutation_offsets(raw_bytes.len()) {
                    let mut mutated = pristine_bundle.clone();
                    let Value::Bytes(mutated_bytes) =
                        mutated
                            .header_map
                            .get_mut(&header)
                            .ok_or(CityGError::InvalidInput(
                                "missing byte-flip mutation target",
                            ))?
                    else {
                        return Err(CityGError::InvalidInput(
                            "byte-flip mutation target must stay bytes",
                        ));
                    };
                    mutated_bytes[offset] ^= mask;

                    let err = server
                        .accept_epoch(&mutated)
                        .expect_err("byte-flipped hostile mutation must be rejected");
                    assert!(
                        matches!(err, CityGError::InvalidInput(_))
                            || matches!(err, CityGError::Acceptance(_)),
                        "unexpected byte-flip mutation error for {label}@{offset}: {err:?}"
                    );
                    assert_eq!(
                        server.members(&gid),
                        vec![alice.leaf_id],
                        "mutation {label}@{offset} must not poison the live roster",
                    );
                    exercised_cases += 1;
                }
            }

            assert!(
                exercised_cases >= 10,
                "mutation sweep should exercise multiple hostile byte-flip cases"
            );

            for reason in [0u64, 2u64, 7u64, u16::MAX as u64] {
                let mut mutated = pristine_bundle.clone();
                mutated.header_map.insert(
                    hdr::HDR_BARRIER_UPDATE_REASON,
                    Value::Integer(Integer::from(reason)),
                );
                let err = server
                    .accept_epoch(&mutated)
                    .expect_err("mutated reason must be rejected");
                assert!(
                    matches!(err, CityGError::InvalidInput(_))
                        || matches!(err, CityGError::Acceptance(_)),
                    "unexpected mutated reason error for reason={reason}: {err:?}"
                );
                assert_eq!(
                    server.members(&gid),
                    vec![alice.leaf_id],
                    "mutated reason {reason} must not poison the live roster",
                );
                exercised_cases += 1;
            }

            assert!(
                exercised_cases >= 14,
                "mutation sweep should exercise a meaningful hostile bundle set"
            );

            let bob = build_join_member_from_server_ticket(&mut server, &gid, 0x98, true)?;
            server.accept_epoch(&bob.bundle)?;
            assert_eq!(
                server.members(&gid).len(),
                2,
                "room must still accept an honest join after the byte-flip mutation sweep"
            );
        }

        let mut reloaded = demo_server_with_journal_and_global_history_authority(&journal_path);
        assert_eq!(
            reloaded.members(&gid).len(),
            2,
            "restart must preserve the healthy roster after the byte-flip mutation sweep"
        );
        let followup_ticket = reloaded.build_merge_ticket_for_refresh(&gid, &alice.leaf_id)?;
        assert_eq!(
            followup_ticket.barrier_version, 0,
            "restart must still allow a healthy survivor refresh ticket after the byte-flip mutation sweep"
        );
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 24,
            max_shrink_iters: 0,
            .. ProptestConfig::default()
        })]

        #[test]
        fn prop_authority_bound_refresh_bundle_mutations_fail_closed_without_poisoning_live_state(
            mutation_target in 0u8..5,
            offset_seed in any::<usize>(),
            xor_mask in 1u8..=u8::MAX,
            alternate_reason in prop_oneof![Just(0u64), Just(2u64), 3u64..=32u64],
        ) {
            let gid = cityg_client::demo::DEMO_GID;
            let alice = build_genesis_member_bundle(0xA0).expect("build alice");
            let mut server = demo_server_with_global_history_authority();
            server.accept_epoch(&alice.bundle).expect("accept alice");
            let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)
                .expect("seed accepted barrier update");

            let (pristine_bundle, _) =
                build_refresh_bundle_for_member(&mut server, &alice, &alice.bundle)
                    .expect("build refresh bundle");
            let baseline_reason = u64_from_header(
                &pristine_bundle.header_map,
                hdr::HDR_BARRIER_UPDATE_REASON,
            )
            .expect("baseline reason");

            let mut mutated = pristine_bundle.clone();
            match mutation_target {
                0 => {
                    let Value::Bytes(raw) = mutated
                        .header_map
                        .get_mut(&hdr::HDR_BARRIER_FULL_VERIFICATION_RECEIPT)
                        .expect("refresh receipt must exist under global authority")
                    else {
                        panic!("refresh receipt must stay bytes");
                    };
                    let idx = offset_seed % raw.len();
                    raw[idx] ^= xor_mask;
                }
                1 => {
                    let Value::Bytes(raw) = mutated
                        .header_map
                        .get_mut(&hdr::HDR_BARRIER_GLOBAL_HISTORY_ATTESTATION)
                        .expect("refresh attestation must exist under global authority")
                    else {
                        panic!("refresh attestation must stay bytes");
                    };
                    let idx = offset_seed % raw.len();
                    raw[idx] ^= xor_mask;
                }
                2 => {
                    let Value::Bytes(raw) = mutated
                        .header_map
                        .get_mut(&hdr::HDR_BARRIER_UPDATE)
                        .expect("refresh barrier update must exist")
                    else {
                        panic!("refresh barrier update must stay bytes");
                    };
                    let idx = offset_seed % raw.len();
                    raw[idx] ^= xor_mask;
                }
                3 => {
                    let replacement_reason = if alternate_reason == baseline_reason {
                        if baseline_reason == 0 { 2 } else { 0 }
                    } else {
                        alternate_reason
                    };
                    mutated.header_map.insert(
                        hdr::HDR_BARRIER_UPDATE_REASON,
                        Value::Integer(Integer::from(replacement_reason)),
                    );
                }
                4 => {
                    if let Some(Value::Bytes(raw)) = mutated
                        .header_map
                        .get_mut(&hdr::HDR_BARRIER_FULL_VERIFICATION_WITNESS)
                    {
                        let idx = offset_seed % raw.len();
                        raw[idx] ^= xor_mask;
                    } else {
                        let Value::Bytes(raw) = mutated
                            .header_map
                            .get_mut(&hdr::HDR_BARRIER_UPDATE)
                            .expect("refresh barrier update must exist")
                        else {
                            panic!("refresh barrier update must stay bytes");
                        };
                        let idx = offset_seed % raw.len();
                        raw[idx] ^= xor_mask;
                    }
                }
                _ => unreachable!("bounded mutation target"),
            }

            let err = server
                .accept_epoch(&mutated)
                .expect_err("mutated refresh bundle must be rejected");
            prop_assert!(
                matches!(err, CityGError::InvalidInput(_))
                    || matches!(err, CityGError::Acceptance(_)),
                "unexpected property mutation error: {err:?}"
            );

            let members = server.members(&gid);
            prop_assert_eq!(
                members.len(),
                1,
                "mutated refresh bundle must not poison the live roster"
            );
            prop_assert!(members.contains(&alice.leaf_id));
        }
    }

    #[test]
    fn malformed_admin_expel_rejection_does_not_poison_room_state() -> Result<(), CityGError> {
        let mut server = demo_server_with_global_history_authority();
        let gid = cityg_client::demo::DEMO_GID;
        let alice = build_genesis_member_bundle(0x81)?;
        server.accept_epoch(&alice.bundle)?;
        let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;
        let bob = build_join_member_from_server_ticket(&mut server, &gid, 0x82, true)?;
        server.accept_epoch(&bob.bundle)?;

        {
            let group = server
                .roster
                .groups
                .get_mut(gid.as_slice())
                .ok_or(CityGError::InvalidInput("missing demo group state"))?;
            group
                .room_admin_pop_keys
                .insert(alice.pop_public_key.clone());
        }

        let mut malformed_expel = build_admin_expel_bundle_for_member(
            &mut server,
            &alice,
            &alice.bundle,
            &bob.leaf_id,
            0x31,
        )?;
        malformed_expel.header_map.remove(&hdr::HDR_BARRIER_UPDATE);
        let err = server
            .accept_epoch(&malformed_expel)
            .expect_err("malformed admin expel must be rejected");
        assert!(
            matches!(err, CityGError::InvalidInput(_)) || matches!(err, CityGError::Acceptance(_)),
            "unexpected malformed admin expel error: {err:?}"
        );

        let members_after_reject = server.members(&gid);
        assert_eq!(
            members_after_reject.len(),
            2,
            "rejected malformed admin expel must not evict or corrupt members"
        );
        assert!(
            members_after_reject.contains(&alice.leaf_id)
                && members_after_reject.contains(&bob.leaf_id),
            "the healthy room membership must remain intact after malformed admin expel"
        );

        let charlie = build_join_member_from_server_ticket(&mut server, &gid, 0x83, true)?;
        server.accept_epoch(&charlie.bundle)?;
        let members_after_honest_join = server.members(&gid);
        assert_eq!(
            members_after_honest_join.len(),
            3,
            "a later honest join must still succeed after malformed admin expel rejection"
        );
        assert!(
            members_after_honest_join.contains(&alice.leaf_id)
                && members_after_honest_join.contains(&bob.leaf_id)
                && members_after_honest_join.contains(&charlie.leaf_id),
            "the room must remain healthy after malformed admin expel rejection"
        );
        Ok(())
    }

    #[test]
    fn malformed_admin_expel_rejection_does_not_poison_restart_recovery() -> Result<(), CityGError>
    {
        let _guard = super::journal_serial_guard();
        let dir = tempdir()?;
        let journal_path = dir.path().join("malformed-admin-expel.journal");
        let gid = cityg_client::demo::DEMO_GID;

        {
            let mut server = demo_server_with_journal_and_global_history_authority(&journal_path);
            let alice = build_genesis_member_bundle(0x83)?;
            server.accept_epoch(&alice.bundle)?;
            let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;
            let bob = build_join_member_from_server_ticket(&mut server, &gid, 0x84, true)?;
            server.accept_epoch(&bob.bundle)?;

            {
                let group = server
                    .roster
                    .groups
                    .get_mut(gid.as_slice())
                    .ok_or(CityGError::InvalidInput("missing demo group state"))?;
                group
                    .room_admin_pop_keys
                    .insert(alice.pop_public_key.clone());
            }

            let mut malformed_expel = build_admin_expel_bundle_for_member(
                &mut server,
                &alice,
                &alice.bundle,
                &bob.leaf_id,
                0x41,
            )?;
            malformed_expel.header_map.remove(&hdr::HDR_BARRIER_UPDATE);
            let err = server
                .accept_epoch(&malformed_expel)
                .expect_err("malformed admin expel must be rejected before restart");
            assert!(
                matches!(err, CityGError::InvalidInput(_))
                    || matches!(err, CityGError::Acceptance(_)),
                "unexpected malformed admin expel error: {err:?}"
            );

            let members_before_restart = server.members(&gid);
            assert_eq!(members_before_restart.len(), 2);
        }

        let mut reloaded = demo_server_with_journal_and_global_history_authority(&journal_path);
        let members_after_restart = reloaded.members(&gid);
        assert_eq!(
            members_after_restart.len(),
            2,
            "restart must preserve the healthy roster after malformed admin expel rejection"
        );

        let charlie = build_join_member_from_server_ticket(&mut reloaded, &gid, 0x85, true)?;
        reloaded.accept_epoch(&charlie.bundle)?;
        let members_after_honest_join = reloaded.members(&gid);
        assert_eq!(
            members_after_honest_join.len(),
            3,
            "room must still accept later honest joins after restart"
        );
        Ok(())
    }

    #[test]
    fn malformed_join_finalize_rejection_does_not_poison_restart_recovery() -> Result<(), CityGError>
    {
        let _guard = super::journal_serial_guard();
        let dir = tempdir()?;
        let journal_path = dir.path().join("malformed-join-finalize.journal");
        let gid = cityg_client::demo::DEMO_GID;
        let alice = build_genesis_member_bundle(0x88)?;

        {
            let mut server = demo_server_with_journal_and_global_history_authority(&journal_path);
            server.accept_epoch(&alice.bundle)?;
            let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;

            let (pristine_join_finalize, _) =
                build_refresh_bundle_for_member(&mut server, &alice, &alice.bundle)?;
            let mut malformed_join_finalize = pristine_join_finalize.clone();
            assert_eq!(
                u64_from_header(
                    &malformed_join_finalize.header_map,
                    hdr::HDR_BARRIER_UPDATE_REASON
                )?,
                2,
                "first post-join merge should be join_finalize"
            );
            malformed_join_finalize
                .header_map
                .remove(&hdr::HDR_JOIN_FINALIZE_AUTH);
            let err = server
                .accept_epoch(&malformed_join_finalize)
                .expect_err("malformed join_finalize must be rejected");
            assert!(
                matches!(err, CityGError::InvalidInput(_))
                    || matches!(err, CityGError::Acceptance(_)),
                "unexpected malformed join_finalize error: {err:?}"
            );

            let members_before_restart = server.members(&gid);
            assert_eq!(
                members_before_restart,
                vec![alice.leaf_id],
                "rejected malformed join_finalize must not poison the live roster"
            );
        }

        let mut reloaded = demo_server_with_journal_and_global_history_authority(&journal_path);
        assert_eq!(
            reloaded.members(&gid),
            vec![alice.leaf_id],
            "restart must preserve healthy membership after malformed join_finalize rejection"
        );

        let followup_ticket = reloaded.build_merge_ticket_for_refresh(&gid, &alice.leaf_id)?;
        assert_eq!(
            followup_ticket.barrier_version, 0,
            "restart must still allow a fresh join_finalize/refresh ticket after malformed rejection"
        );
        let (fresh_join_finalize, _) =
            build_refresh_bundle_for_member(&mut reloaded, &alice, &alice.bundle)?;
        assert_eq!(
            u64_from_header(
                &fresh_join_finalize.header_map,
                hdr::HDR_BARRIER_UPDATE_REASON
            )?,
            2,
            "restart must still permit a valid join_finalize after malformed rejection"
        );
        Ok(())
    }

    #[test]
    fn stale_leave_race_with_honest_join_does_not_poison_restart_recovery() -> Result<(), CityGError>
    {
        let _guard = super::journal_serial_guard();
        let dir = tempdir()?;
        let journal_path = dir.path().join("stale-leave-race.journal");
        let gid = cityg_client::demo::DEMO_GID;
        let alice = build_genesis_member_bundle(0x8F)?;

        {
            let mut server = demo_server_with_journal_and_global_history_authority(&journal_path);
            server.accept_epoch(&alice.bundle)?;
            let _ = seed_current_accepted_barrier_update_for_tests(&mut server, &gid)?;

            let stale_leave = build_leave_bundle_for_member(&mut server, &alice, &alice.bundle)?;
            let bob = build_join_member_from_server_ticket(&mut server, &gid, 0x90, true)?;
            server.accept_epoch(&bob.bundle)?;

            let err = server
                .accept_epoch(&stale_leave)
                .expect_err("stale leave race must be rejected");
            assert!(
                matches!(err, CityGError::InvalidInput(_))
                    || matches!(err, CityGError::Acceptance(_)),
                "unexpected stale leave race error: {err:?}"
            );

            let members_before_restart = server.members(&gid);
            assert_eq!(
                members_before_restart.len(),
                2,
                "stale leave rejection must preserve the healthy live roster"
            );
            assert!(
                members_before_restart.contains(&alice.leaf_id)
                    && members_before_restart.contains(&bob.leaf_id),
                "alice and bob must remain visible after the stale leave race"
            );
        }

        let mut reloaded = demo_server_with_journal_and_global_history_authority(&journal_path);
        let members_after_restart = reloaded.members(&gid);
        assert_eq!(
            members_after_restart.len(),
            2,
            "restart must preserve the healthy roster after stale leave rejection"
        );
        assert!(
            members_after_restart.contains(&alice.leaf_id),
            "surviving author must remain visible after restart"
        );

        let followup_ticket = reloaded.build_merge_ticket_for_refresh(&gid, &alice.leaf_id)?;
        assert_eq!(
            followup_ticket.barrier_version, 0,
            "restart must still allow a healthy survivor refresh ticket after stale leave rejection"
        );
        Ok(())
    }

    #[test]
    fn join_cover_leaf_index_guard_rejects_colliding_cover_index() -> Result<(), CityGError> {
        let active_leaf = colliding_cover_leaf(5);
        let colliding_leaf = colliding_cover_leaf(1029);
        let mut membership = cityg_client::GroupMembership::default();
        membership.apply_delta(&cityg_client::MembershipDelta {
            joined: vec![active_leaf],
            revoked: Vec::new(),
        });
        let root = msphf_core::merkle::canonical_set_root(&[active_leaf])?;
        let mut state = super::GroupState::default();
        state.snapshots.insert(root, membership);
        state.latest_root = Some(root);
        let err = super::ensure_join_cover_leaf_indices_available(&state, &[colliding_leaf])
            .expect_err("colliding join must be rejected");
        assert!(
            matches!(
                err,
                CityGError::InvalidInput(super::COVER_LEAF_INDEX_ALREADY_ALLOCATED_ERR)
            ),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn fetch_barrier_public_tree_enforces_snapshot_auth() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let bundle = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&bundle)?;

        let group = server
            .roster
            .groups
            .get(cityg_client::demo::DEMO_GID.as_slice())
            .ok_or(CityGError::InvalidInput("group not found"))?;
        let expected_hash = group.kem_tree_hash_after;
        let n_max = group.n_max;

        let snapshot =
            server.fetch_barrier_public_tree(&cityg_client::demo::DEMO_GID, &expected_hash)?;
        assert_eq!(snapshot.n_max, n_max);
        assert_eq!(snapshot.kem_tree_hash_after, expected_hash);
        assert_eq!(
            snapshot.pk_entries.len() as u64,
            n_max.saturating_mul(2).saturating_sub(1)
        );

        let err = server
            .fetch_barrier_public_tree(&cityg_client::demo::DEMO_GID, &[0xFF; 32])
            .expect_err("mismatched hash must fail");
        assert!(
            matches!(
                err,
                CityGError::InvalidInput(
                    super::HISTORICAL_BARRIER_PUBLIC_TREE_SNAPSHOT_UNAVAILABLE_ERR
                )
            ),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn fetch_barrier_public_tree_rejects_corrupted_history_snapshot() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let bundle = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&bundle)?;

        let gid = cityg_client::demo::DEMO_GID;
        let (expected_hash, _current_hash) = {
            let historical_hash = server
                .roster
                .groups
                .get(gid.as_slice())
                .ok_or(CityGError::InvalidInput("group not found"))?
                .kem_tree_hash_after;
            let (current_hash, _entries) =
                advance_committed_tree_for_tests(&mut server, &gid, 0x55)?;
            (historical_hash, current_hash)
        };
        {
            let group = server
                .roster
                .groups
                .get_mut(gid.as_slice())
                .ok_or(CityGError::InvalidInput("group not found"))?;
            let historical_entries =
                super::history_barrier_public_tree_entries(group, &expected_hash).ok_or(
                    CityGError::InvalidInput("historical snapshot missing before corruption"),
                )?;
            let mut corrupted = historical_entries;
            corrupted[0] = vec![0x55; 1184];
            let snapshot_ref =
                super::encode_barrier_public_tree_snapshot_ref(group, corrupted.as_slice())?;
            group
                .barrier_public_tree_history
                .insert(expected_hash, snapshot_ref);
        }

        let err = server
            .fetch_barrier_public_tree(&gid, &expected_hash)
            .expect_err("corrupted historical snapshot must fail auth");
        assert!(
            matches!(
                err,
                CityGError::Acceptance(msphf_orchestrator::AcceptanceError::Freeze(freeze))
                    if freeze.code == msphf_orchestrator::FREEZE_BARRIER_TREE_SNAPSHOT_AUTH_FAILURE.code
                        && freeze.reason
                            == msphf_orchestrator::FREEZE_BARRIER_TREE_SNAPSHOT_AUTH_FAILURE.reason
            ),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn fetch_barrier_public_tree_rejects_duplicate_active_cover_allocations()
    -> Result<(), CityGError> {
        let gid = [0x85; 32];
        let mut server = CityGServer::new(ServerConfig::new());
        let leaf_a = colliding_cover_leaf(5);
        let leaf_b = colliding_cover_leaf(1029);
        let mut membership = cityg_client::GroupMembership::default();
        membership.apply_delta(&cityg_client::MembershipDelta {
            joined: vec![leaf_a, leaf_b],
            revoked: Vec::new(),
        });
        let root = msphf_core::merkle::canonical_set_root(&[leaf_a, leaf_b])?;
        let state = server.roster.groups.entry(gid.to_vec()).or_default();
        state.snapshots.insert(root, membership);
        state.latest_root = Some(root);
        state.leaf_barrier_public.insert(leaf_a, vec![0x11; 1184]);
        state.leaf_barrier_public.insert(leaf_b, vec![0x22; 1184]);

        let err = server
            .fetch_barrier_public_tree(&gid, &[0u8; 32])
            .expect_err("duplicate active cover allocations must fail closed");
        assert!(matches!(
            err,
            CityGError::InvalidInput(super::DUPLICATE_ACTIVE_COVER_LEAF_ALLOCATION_ERR)
        ));
        Ok(())
    }

    #[test]
    fn fetch_barrier_public_tree_serves_historical_committed_snapshots() -> Result<(), CityGError> {
        let generated = build_genesis_member_bundle(0x72)?;
        let mut server = super::demo::demo_server();
        server.accept_epoch(&generated.bundle)?;
        let gid = cityg_client::demo::DEMO_GID;
        let (historical_hash, historical_entries, n_max) = {
            let group = server
                .roster
                .groups
                .get(gid.as_slice())
                .ok_or(CityGError::InvalidInput("group not found"))?;
            (
                group.kem_tree_hash_after,
                group.barrier_pk_entries.clone(),
                group.n_max,
            )
        };

        let (current_hash, current_entries) =
            advance_committed_tree_for_tests(&mut server, &gid, 0x72)?;
        assert_ne!(
            current_hash, historical_hash,
            "accepted refresh should advance the committed public tree hash"
        );

        let snapshot = server.fetch_barrier_public_tree(&gid, &historical_hash)?;
        assert_eq!(snapshot.n_max, n_max);
        assert_eq!(snapshot.kem_tree_hash_after, historical_hash);
        assert_eq!(snapshot.pk_entries, historical_entries);

        {
            let group =
                server
                    .roster
                    .groups
                    .get_mut(gid.as_slice())
                    .ok_or(CityGError::InvalidInput(
                        "group not found before recompute fetch",
                    ))?;
            group.barrier_public_tree_history.remove(&current_hash);
            assert_eq!(group.barrier_pk_entries, current_entries);
        }
        let current_snapshot = server.fetch_barrier_public_tree(&gid, &current_hash)?;
        assert_eq!(current_snapshot.kem_tree_hash_after, current_hash);
        assert_ne!(current_snapshot.pk_entries, historical_entries);
        Ok(())
    }

    #[test]
    fn history_commitment_advances_monotonically_and_preserves_historical_snapshots()
    -> Result<(), CityGError> {
        let generated = build_genesis_member_bundle(0x74)?;
        let mut server = super::demo::demo_server();
        server.accept_epoch(&generated.bundle)?;
        let gid = cityg_client::demo::DEMO_GID;

        let first_hash = {
            let group = server
                .roster
                .groups
                .get(gid.as_slice())
                .ok_or(CityGError::InvalidInput("group not found"))?;
            group.kem_tree_hash_after
        };
        let first_snapshot = server.fetch_barrier_public_tree(&gid, &first_hash)?;
        let (second_hash, _) = advance_committed_tree_for_tests(&mut server, &gid, 0x74)?;
        let historical_hash = server
            .roster
            .groups
            .get(gid.as_slice())
            .and_then(|group| {
                group
                    .barrier_public_tree_history
                    .keys()
                    .copied()
                    .find(|hash| *hash != second_hash)
            })
            .ok_or(CityGError::InvalidInput(
                "missing historical barrier snapshot",
            ))?;
        let second_snapshot = server.fetch_barrier_public_tree(&gid, &second_hash)?;
        let historical_snapshot = server.fetch_barrier_public_tree(&gid, &historical_hash)?;

        assert_ne!(
            first_snapshot.history_commitment.history_commitment_id,
            [0u8; 32]
        );
        assert_ne!(
            historical_snapshot.history_commitment.history_commitment_id,
            [0u8; 32]
        );
        assert!(
            second_snapshot.history_commitment.history_seq
                > historical_snapshot.history_commitment.history_seq
        );
        assert_eq!(
            second_snapshot
                .history_commitment
                .prev_history_commitment_id,
            historical_snapshot.history_commitment.history_commitment_id
        );
        Ok(())
    }

    #[test]
    fn barrier_public_tree_history_prunes_retired_snapshots() -> Result<(), CityGError> {
        let gid = [0x91; 32];
        let mut state = super::GroupState::default();
        state.n_max = super::DEFAULT_BARRIER_N_MAX;
        state.barrier_pk_entries = super::build_all_blank_pk_entries(state.n_max)?;
        let mut historical_hashes = Vec::new();

        for seq in 0..(super::MAX_RETAINED_BARRIER_PUBLIC_TREE_SNAPSHOTS + 8) {
            state.barrier_version = u64::try_from(seq).unwrap_or(u64::MAX);
            state.barrier_pk_entries[0] = (seq as u64).to_le_bytes().to_vec();
            state.kem_tree_hash_after = super::compute_group_barrier_tree_hash(&state)?;
            historical_hashes.push(state.kem_tree_hash_after);
            super::record_barrier_public_tree_snapshot(&gid, &mut state)?;
        }

        assert_eq!(
            state.barrier_public_tree_history.len(),
            super::MAX_RETAINED_BARRIER_PUBLIC_TREE_SNAPSHOTS
        );
        let retired_hash = historical_hashes[0];
        assert!(
            !state
                .barrier_public_tree_history
                .contains_key(&retired_hash),
            "oldest committed snapshot should be retired once retention window is exceeded"
        );
        let current_hash = *historical_hashes
            .last()
            .ok_or(CityGError::InvalidInput("missing current hash"))?;
        assert!(
            state
                .barrier_public_tree_history
                .contains_key(&current_hash),
            "current committed snapshot must remain retained"
        );

        let mut server = CityGServer::new(ServerConfig::new());
        server.roster.groups.insert(gid.to_vec(), state);

        let err = server
            .fetch_barrier_public_tree(&gid, &retired_hash)
            .expect_err("retired historical snapshot should fail closed");
        assert!(matches!(
            err,
            CityGError::InvalidInput(
                super::HISTORICAL_BARRIER_PUBLIC_TREE_SNAPSHOT_UNAVAILABLE_ERR
            )
        ));

        let current = server.fetch_barrier_public_tree(&gid, &current_hash)?;
        assert_eq!(current.kem_tree_hash_after, current_hash);
        Ok(())
    }

    #[test]
    fn merge_ticket_hash_matches_fetchable_tree_snapshot() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let alice = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&alice)?;

        let ticket = server.build_merge_ticket(
            &cityg_client::demo::DEMO_GID,
            &cityg_client::demo::demo_member_leaf("alice"),
        )?;
        let snapshot = server.fetch_barrier_public_tree(
            &cityg_client::demo::DEMO_GID,
            &ticket.kem_tree_hash_after,
        )?;
        assert_eq!(snapshot.kem_tree_hash_after, ticket.kem_tree_hash_after);
        assert_eq!(snapshot.n_max, ticket.n_max);
        Ok(())
    }

    #[test]
    fn fetch_barrier_public_tree_prefers_current_commitment_for_current_hash()
    -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let alice = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&alice)?;

        let gid = cityg_client::demo::DEMO_GID;
        let ticket =
            server.build_merge_ticket(&gid, &cityg_client::demo::demo_member_leaf("alice"))?;
        let current = server.current_history_commitment(&gid)?;
        {
            let group = server
                .roster
                .groups
                .get_mut(gid.as_slice())
                .ok_or(CityGError::InvalidInput("group missing"))?;
            group.barrier_public_tree_history.insert(
                ticket.kem_tree_hash_after,
                super::BarrierPublicTreeSnapshotRef {
                    blob_indices: Vec::new(),
                    barrier_version: ticket.barrier_version,
                    history_view_id: [0xA1; 32],
                    history_commitment: super::HistoryCommitment {
                        history_view_id: [0xA1; 32],
                        history_commitment_id: [0xB2; 32],
                        prev_history_commitment_id: [0xC3; 32],
                        history_seq: current.history_seq.saturating_sub(1),
                    },
                },
            );
        }

        let snapshot = server.fetch_barrier_public_tree(&gid, &ticket.kem_tree_hash_after)?;
        assert_eq!(snapshot.kem_tree_hash_after, ticket.kem_tree_hash_after);
        assert_eq!(snapshot.history_commitment, current);
        Ok(())
    }

    #[test]
    fn fetch_barrier_public_tree_prefers_current_commitment_for_current_predecessor_hash()
    -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let gid = cityg_client::demo::DEMO_GID;
        let alice = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&alice)?;
        let predecessor_hash = {
            let group = server
                .roster
                .groups
                .get(gid.as_slice())
                .ok_or(CityGError::InvalidInput("group missing"))?;
            group.kem_tree_hash_after
        };
        let bob = cityg_client::demo::demo_bundle("bob")?;
        server.accept_epoch(&bob)?;

        let current = server.current_history_commitment(&gid)?;
        {
            let group = server
                .roster
                .groups
                .get_mut(gid.as_slice())
                .ok_or(CityGError::InvalidInput("group missing"))?;
            group.current_accepted_barrier_predecessor_hash = predecessor_hash;
        }

        let snapshot = server.fetch_barrier_public_tree(&gid, &predecessor_hash)?;
        assert_eq!(snapshot.kem_tree_hash_after, predecessor_hash);
        assert_eq!(snapshot.history_commitment, current);
        Ok(())
    }

    #[test]
    fn accepted_barrier_state_is_mirrored_to_roster() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let bundle = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&bundle)?;

        let gid = cityg_client::demo::DEMO_GID.as_slice();
        let ctx_state = server
            .ctx
            .barrier_group_state(gid)
            .ok_or(CityGError::InvalidInput("context barrier state missing"))?
            .clone();
        let roster_state = server
            .roster
            .groups
            .get(gid)
            .ok_or(CityGError::InvalidInput("roster group missing"))?;

        assert_eq!(
            roster_state.barrier_initialized,
            ctx_state.barrier_initialized
        );
        assert_eq!(roster_state.barrier_version, ctx_state.barrier_version);
        assert_eq!(
            roster_state.barrier_roots_hash,
            ctx_state.barrier_roots_hash
        );
        assert_eq!(
            roster_state.kem_tree_hash_after,
            ctx_state.kem_tree_hash_after
        );
        assert_eq!(roster_state.n_max, ctx_state.n_max);
        assert_eq!(
            roster_state.last_pcs_refresh_ec,
            ctx_state.last_pcs_refresh_ec
        );
        assert_eq!(
            roster_state.pcs_refresh_min_delta_device_ec,
            ctx_state.pcs_refresh_min_delta_device_ec
        );
        assert_eq!(
            roster_state.pcs_refresh_min_delta_group_ec,
            ctx_state.pcs_refresh_min_delta_group_ec
        );
        assert_eq!(
            roster_state.pcs_refresh_slot_width_ec,
            ctx_state.pcs_refresh_slot_width_ec
        );
        Ok(())
    }

    #[test]
    fn resolve_revoked_leaf_indices_requires_matching_roots_hash() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let bundle = cityg_client::demo::demo_bundle("alice")?;
        server.accept_epoch(&bundle)?;

        let (leaf, roots_hash) = {
            let group = server
                .roster
                .groups
                .get_mut(cityg_client::demo::DEMO_GID.as_slice())
                .ok_or(CityGError::InvalidInput("group not found"))?;
            let root = group.barrier_roots_hash;
            let leaf = group
                .latest_snapshot()
                .and_then(|snapshot| snapshot.members().next().copied())
                .ok_or(CityGError::InvalidInput("missing membership snapshot"))?;
            group.revoked.insert(leaf);
            (leaf, root)
        };

        let indices =
            server.resolve_revoked_leaf_indices(&cityg_client::demo::DEMO_GID, &roots_hash)?;
        let n_max = server
            .roster
            .groups
            .get(cityg_client::demo::DEMO_GID.as_slice())
            .map(|group| group.n_max)
            .unwrap_or(super::DEFAULT_BARRIER_N_MAX);
        assert_eq!(
            indices.leaf_indices,
            vec![super::cover_leaf_index(&leaf, n_max)]
        );

        let err = server
            .resolve_revoked_leaf_indices(&cityg_client::demo::DEMO_GID, &[0x42; 32])
            .expect_err("mismatched roots hash must fail");
        assert!(matches!(
            err,
            CityGError::InvalidInput(
                "revocation_roots_hash does not match committed barrier roots"
            )
        ));
        Ok(())
    }

    #[test]
    fn barrier_helpers_report_missing_group_state() {
        let mut server = super::demo::demo_server();
        let gid = [0xE1; 32];

        assert!(matches!(
            server.resolve_revoked_leaf_indices(&gid, &[0u8; 32]),
            Err(CityGError::InvalidInput("group not found"))
        ));
        assert!(matches!(
            server.resolve_joins_since(&gid, 0),
            Err(CityGError::InvalidInput("group not found"))
        ));
        assert!(matches!(
            server.fetch_barrier_public_tree(&gid, &[0u8; 32]),
            Err(CityGError::InvalidInput("group not found"))
        ));

        assert_eq!(server.barrier_roots_hash(gid.as_slice()), None);
        assert_eq!(server.barrier_kem_tree_hash_after(gid.as_slice()), None);
        assert_eq!(server.barrier_n_max(gid.as_slice()), None);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod roster_tests {
    use super::*;
    use msphf_core::merkle::canonical_set_root;

    fn leaf(id: u8) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[31] = id;
        bytes
    }

    #[test]
    fn apply_delta_tracks_multiple_roots() -> Result<(), Box<dyn std::error::Error>> {
        let mut roster = GroupRoster::default();
        let gid = b"gid";
        let zero = [0u8; 32];

        let delta1 = MembershipDelta {
            joined: vec![leaf(1)],
            revoked: Vec::new(),
        };
        let root1 = roster.apply_delta(gid, &zero, &delta1)?;
        let expected_root1 = canonical_set_root(&[leaf(1)])?;
        assert_eq!(root1, expected_root1);
        assert_eq!(
            roster
                .members_for_root(gid, &root1)
                .ok_or("members not found")?
                .len(),
            1
        );

        let delta2 = MembershipDelta {
            joined: vec![leaf(2)],
            revoked: Vec::new(),
        };
        let root2 = roster.apply_delta(gid, &root1, &delta2)?;
        let expected_root2 = canonical_set_root(&[leaf(1), leaf(2)])?;
        assert_eq!(root2, expected_root2);
        assert_eq!(
            roster
                .members_for_root(gid, &root1)
                .ok_or("members not found")?
                .len(),
            1
        );
        assert_eq!(
            roster
                .members_for_root(gid, &root2)
                .ok_or("members not found")?
                .len(),
            2
        );

        let delta_branch = MembershipDelta {
            joined: vec![leaf(3)],
            revoked: Vec::new(),
        };
        let root3 = roster.apply_delta(gid, &root1, &delta_branch)?;
        assert_ne!(root2, root3);
        assert_eq!(
            roster
                .members_for_root(gid, &root3)
                .ok_or("members not found")?
                .len(),
            2
        );
        Ok(())
    }

    #[test]
    fn unknown_base_root_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let mut roster = GroupRoster::default();
        let gid = b"gid";
        let bad_root = [0xAA; 32];
        let delta = MembershipDelta {
            joined: vec![leaf(1)],
            revoked: Vec::new(),
        };
        let err = roster
            .apply_delta(gid, &bad_root, &delta)
            .expect_err("expected error");
        assert!(matches!(err, CityGError::InvalidInput(_)));
        Ok(())
    }

    #[test]
    fn revoking_unknown_member_is_error() -> Result<(), Box<dyn std::error::Error>> {
        let mut roster = GroupRoster::default();
        let gid = b"gid";
        let zero = [0u8; 32];
        let delta = MembershipDelta {
            joined: Vec::new(),
            revoked: vec![leaf(10)],
        };
        let err = roster
            .apply_delta(gid, &zero, &delta)
            .expect_err("expected error");
        assert!(matches!(err, CityGError::InvalidInput(_)));
        Ok(())
    }

    #[test]
    fn duplicate_join_is_error() -> Result<(), Box<dyn std::error::Error>> {
        let mut roster = GroupRoster::default();
        let gid = b"gid";
        let zero = [0u8; 32];
        let delta1 = MembershipDelta {
            joined: vec![leaf(1)],
            revoked: Vec::new(),
        };
        let root1 = roster.apply_delta(gid, &zero, &delta1)?;
        let delta_dup = MembershipDelta {
            joined: vec![leaf(1)],
            revoked: Vec::new(),
        };
        let err = roster
            .apply_delta(gid, &root1, &delta_dup)
            .expect_err("expected error");
        assert!(matches!(err, CityGError::InvalidInput(_)));
        Ok(())
    }

    #[test]
    fn revoked_member_cannot_rejoin_in_same_delta() -> Result<(), Box<dyn std::error::Error>> {
        let mut roster = GroupRoster::default();
        let gid = b"gid";
        let zero = [0u8; 32];

        let delta1 = MembershipDelta {
            joined: vec![leaf(1)],
            revoked: Vec::new(),
        };
        let root1 = roster.apply_delta(gid, &zero, &delta1)?;

        let conflicting = MembershipDelta {
            joined: vec![leaf(1)],
            revoked: vec![leaf(1)],
        };
        let err = roster
            .apply_delta(gid, &root1, &conflicting)
            .expect_err("expected error");
        assert!(matches!(err, CityGError::InvalidInput(_)));
        Ok(())
    }

    #[test]
    fn cover_leaf_index_clamps_and_stays_deterministic() {
        let mut leaf = [0u8; 32];
        leaf[28..32].copy_from_slice(&0xFFFF_FFFE_u32.to_be_bytes());

        assert_eq!(super::leaf_index(&leaf), 0xFFFF_FFFE);
        assert_eq!(super::cover_leaf_index(&leaf, 0), 0);
        assert_eq!(super::cover_leaf_index(&leaf, 1), 0);
        assert_eq!(super::cover_leaf_index(&leaf, 4), 2);
        assert_eq!(
            super::cover_leaf_index(&leaf, u64::from(u32::MAX) + 99),
            0xFFFF_FFFE
        );

        for n_max in [2u64, 3, 1024, u64::MAX] {
            let first = super::cover_leaf_index(&leaf, n_max);
            let second = super::cover_leaf_index(&leaf, n_max);
            let clamped = n_max.max(1).min(u32::MAX as u64);
            assert_eq!(first, second);
            assert!(u64::from(first) < clamped);
        }
    }
}

#[derive(Clone, Default)]
struct GroupRoster {
    groups: BTreeMap<Vec<u8>, GroupState>,
}

impl GroupRoster {
    fn apply_delta(
        &mut self,
        gid: &[u8],
        base_root: &[u8; 32],
        delta: &MembershipDelta,
    ) -> Result<[u8; 32], CityGError> {
        let state = self.groups.entry(gid.to_vec()).or_default();
        let base_snapshot = if let Some(snapshot) = state.snapshots.get(base_root) {
            snapshot.clone()
        } else if is_zero_root(base_root) && state.snapshots.is_empty() {
            GroupMembership::default()
        } else {
            return Err(CityGError::InvalidInput("unknown membership base root"));
        };

        state
            .snapshots
            .entry(*base_root)
            .or_insert_with(|| base_snapshot.clone());

        let mut next = base_snapshot;
        for leaf in &delta.joined {
            state.revoked.remove(leaf);
        }
        for leaf in &delta.revoked {
            state.revoked.insert(*leaf);
        }
        for leaf in &delta.revoked {
            if !next.contains(leaf) {
                return Err(CityGError::InvalidInput("revoking non-member"));
            }
        }
        for leaf in &delta.joined {
            if next.contains(leaf) {
                return Err(CityGError::InvalidInput("duplicate join"));
            }
        }
        next.apply_delta(delta);

        let leaves: Vec<[u8; 32]> = next.members().copied().collect();
        let new_root = canonical_set_root(&leaves)
            .map_err(|_| CityGError::InvalidInput("unable to compute membership root"))?;

        state.snapshots.insert(new_root, next);
        state.latest_root = Some(new_root);
        state.sync_next_index();
        Ok(new_root)
    }

    fn members(&self, gid: &[u8]) -> Vec<[u8; 32]> {
        self.groups
            .get(gid)
            .and_then(|state| state.latest_snapshot())
            .map(|set| set.members().copied().collect())
            .unwrap_or_default()
    }

    fn members_for_root(&self, gid: &[u8], root: &[u8; 32]) -> Option<Vec<[u8; 32]>> {
        self.groups
            .get(gid)
            .and_then(|state| state.snapshots.get(root))
            .map(|set| set.members().copied().collect())
    }

    fn latest_root(&self, gid: &[u8]) -> Option<[u8; 32]> {
        self.groups.get(gid).and_then(|state| state.latest_root)
    }

    fn revoked(&self, gid: &[u8]) -> Vec<[u8; 32]> {
        self.groups
            .get(gid)
            .map(|state| state.revoked.iter().copied().collect())
            .unwrap_or_default()
    }

    fn has_history(&self, gid: &[u8]) -> bool {
        self.groups
            .get(gid)
            .map(|state| {
                state.latest_root.is_some()
                    || !state.snapshots.is_empty()
                    || !state.revoked.is_empty()
            })
            .unwrap_or(false)
    }

    fn kbroad_generation(&self, gid: &[u8]) -> u64 {
        self.groups
            .get(gid)
            .map(|state| state.kbroad_generation)
            .unwrap_or(0)
    }

    fn increment_kbroad_generation(&mut self, gid: &[u8]) -> u64 {
        let state = self.groups.entry(gid.to_vec()).or_default();
        state.kbroad_generation = state.kbroad_generation.saturating_add(1);
        state.kbroad_generation
    }

    fn kbroad_rotation_required(&self, gid: &[u8]) -> bool {
        self.groups
            .get(gid)
            .map(|state| state.rotation_required)
            .unwrap_or(false)
    }

    fn mark_kbroad_rotation_required(&mut self, gid: &[u8]) {
        self.groups
            .entry(gid.to_vec())
            .or_default()
            .rotation_required = true;
    }

    fn clear_kbroad_rotation_required(&mut self, gid: &[u8]) {
        self.groups
            .entry(gid.to_vec())
            .or_default()
            .rotation_required = false;
    }

    fn has_explicit_room_admins(&self, gid: &[u8]) -> bool {
        self.groups
            .get(gid)
            .map(|state| !state.room_admin_pop_keys.is_empty())
            .unwrap_or(false)
    }

    fn is_room_admin(&self, gid: &[u8], actor_pop_public_key: &[u8]) -> bool {
        self.groups
            .get(gid)
            .map(|state| state.room_admin_pop_keys.contains(actor_pop_public_key))
            .unwrap_or(false)
    }
}

#[derive(Clone)]
struct GroupState {
    latest_root: Option<[u8; 32]>,
    snapshots: BTreeMap<[u8; 32], GroupMembership>,
    revoked: BTreeSet<[u8; 32]>,
    next_index: u32,
    kbroad_generation: u64,
    rotation_required: bool,
    barrier_initialized: bool,
    barrier_version: u64,
    barrier_roots_hash: [u8; 32],
    kem_tree_hash_after: [u8; 32],
    last_checkpoint_ec: u64,
    last_accepted_ec: u64,
    srx_root_sw: Option<[u8; 32]>,
    n_max: u64,
    last_pcs_refresh_ec: Option<u64>,
    pcs_refresh_min_delta_device_ec: u64,
    pcs_refresh_min_delta_group_ec: u64,
    pcs_refresh_slot_width_ec: u64,
    max_barrier_update_bytes: usize,
    accepted_barrier_merges: BTreeMap<u64, AcceptedBarrierMergeRecord>,
    join_history: Vec<JoinLeafHistoryRecord>,
    leaf_device_pk: BTreeMap<[u8; 32], Vec<u8>>,
    leaf_barrier_public: BTreeMap<[u8; 32], Vec<u8>>,
    barrier_pk_entries: Vec<Vec<u8>>,
    barrier_public_tree_blobs: Vec<Vec<u8>>,
    barrier_public_tree_blob_index: HashMap<Vec<u8>, BarrierBlobIndex>,
    barrier_public_tree_history: BTreeMap<[u8; 32], BarrierPublicTreeSnapshotRef>,
    barrier_hash_cache: Option<Arc<HashMap<usize, [u8; 32]>>>,
    current_history_commitment: HistoryCommitment,
    current_accepted_barrier_update: Vec<u8>,
    current_accepted_barrier_predecessor_hash: [u8; 32],
    pending_join_finalize_auth: BTreeMap<[u8; 32], JoinFinalizeAuthRecord>,
    room_admin_pop_keys: BTreeSet<Vec<u8>>,
    room_admin_proof_replay_keys: BTreeSet<[u8; 32]>,
}

impl Default for GroupState {
    fn default() -> Self {
        Self {
            latest_root: None,
            snapshots: BTreeMap::new(),
            revoked: BTreeSet::new(),
            next_index: 0,
            kbroad_generation: 0,
            rotation_required: false,
            barrier_initialized: false,
            barrier_version: 0,
            barrier_roots_hash: [0u8; 32],
            kem_tree_hash_after: [0u8; 32],
            last_checkpoint_ec: 0,
            last_accepted_ec: 0,
            srx_root_sw: None,
            n_max: DEFAULT_BARRIER_N_MAX,
            last_pcs_refresh_ec: None,
            pcs_refresh_min_delta_device_ec: default_pcs_refresh_min_delta_device_ec(),
            pcs_refresh_min_delta_group_ec: default_pcs_refresh_min_delta_group_ec(),
            pcs_refresh_slot_width_ec: default_pcs_refresh_slot_width_ec(),
            max_barrier_update_bytes: usize::try_from(default_max_barrier_update_bytes())
                .unwrap_or(1_048_576),
            accepted_barrier_merges: BTreeMap::new(),
            join_history: Vec::new(),
            leaf_device_pk: BTreeMap::new(),
            leaf_barrier_public: BTreeMap::new(),
            barrier_pk_entries: Vec::new(),
            barrier_public_tree_blobs: Vec::new(),
            barrier_public_tree_blob_index: HashMap::new(),
            barrier_public_tree_history: BTreeMap::new(),
            barrier_hash_cache: None,
            current_history_commitment: HistoryCommitment::default(),
            current_accepted_barrier_update: Vec::new(),
            current_accepted_barrier_predecessor_hash: [0u8; 32],
            pending_join_finalize_auth: BTreeMap::new(),
            room_admin_pop_keys: BTreeSet::new(),
            room_admin_proof_replay_keys: BTreeSet::new(),
        }
    }
}

#[derive(Clone, Debug)]
struct JoinLeafHistoryRecord {
    leaf_id: [u8; 32],
    barrier_version: u64,
    leaf_index: u32,
    device_pk: Vec<u8>,
    ek_leaf: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct AcceptedBarrierMergeRecord {
    barrier_version: u64,
    fs_ec: u64,
    reason: u64,
    digest: [u8; 32],
    we_epoch_id: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct JoinFinalizeAuthRecord {
    leaf_id: [u8; 32],
    cover_leaf_index: u32,
    token: [u8; 32],
}

type BarrierBlobIndex = u32;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct BarrierPublicTreeSnapshotRef {
    blob_indices: Vec<BarrierBlobIndex>,
    barrier_version: u64,
    history_view_id: [u8; 32],
    history_commitment: HistoryCommitment,
}

impl GroupState {
    fn latest_snapshot(&self) -> Option<&GroupMembership> {
        self.latest_root.and_then(|root| self.snapshots.get(&root))
    }

    fn allocate_leaf(&mut self) -> u32 {
        if self.next_index == 0 {
            self.next_index = 1;
        }
        let index = self.next_index;
        self.next_index = self.next_index.saturating_add(1);
        index
    }

    fn sync_next_index(&mut self) {
        let max = self
            .snapshots
            .values()
            .flat_map(|set| set.members().map(leaf_index))
            .max()
            .unwrap_or(0);
        let candidate = max.saturating_add(1);
        if self.next_index < candidate {
            self.next_index = candidate;
        }
    }
}

type PersistedKbroadState = BTreeMap<Vec<u8>, PersistedKbroadRoomState>;

const DEFAULT_BARRIER_N_MAX: u64 = 1_024;
const MAX_BARRIER_N_MAX: u64 = 65_536;
const MAX_RETAINED_BARRIER_PUBLIC_TREE_SNAPSHOTS: usize = 256;

fn default_barrier_n_max() -> u64 {
    DEFAULT_BARRIER_N_MAX
}

fn validate_barrier_n_max(n_max: u64) -> Result<u64, CityGError> {
    if n_max == 0 || !n_max.is_power_of_two() {
        return Err(CityGError::InvalidInput(
            "barrier n_max must be a non-zero power of two",
        ));
    }
    if n_max > MAX_BARRIER_N_MAX {
        return Err(CityGError::InvalidInput(
            "barrier n_max exceeds MAX_BARRIER_N_MAX",
        ));
    }
    Ok(n_max)
}

fn default_pcs_refresh_min_delta_device_ec() -> u64 {
    1
}

fn default_pcs_refresh_min_delta_group_ec() -> u64 {
    1
}

fn default_pcs_refresh_slot_width_ec() -> u64 {
    1
}

fn default_max_barrier_update_bytes() -> u64 {
    u64::try_from(msphf_orchestrator::BarrierGroupState::default().max_barrier_update_bytes)
        .unwrap_or(u64::MAX)
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PersistedKbroadRoomState {
    kbroad_public: Vec<u8>,
    kbroad_generation: u64,
    rotation_required: bool,
    #[serde(default)]
    room_admin_pop_keys: Vec<Vec<u8>>,
    #[serde(default)]
    room_admin_proof_replay_keys: Vec<[u8; 32]>,
    #[serde(default)]
    revoked_leaf_ids_hex: Vec<String>,
    #[serde(default)]
    barrier_initialized: bool,
    #[serde(default)]
    barrier_version: u64,
    #[serde(default)]
    barrier_roots_hash: [u8; 32],
    #[serde(default)]
    kem_tree_hash_after: [u8; 32],
    #[serde(default)]
    last_checkpoint_ec: u64,
    #[serde(default)]
    last_accepted_ec: u64,
    #[serde(default)]
    srx_root_sw: Option<[u8; 32]>,
    #[serde(default)]
    barrier_pk_entries: Vec<Vec<u8>>,
    #[serde(default)]
    barrier_public_tree_blobs: Vec<Vec<u8>>,
    #[serde(default)]
    barrier_public_tree_history: Vec<PersistedBarrierPublicTreeSnapshot>,
    #[serde(default = "default_barrier_n_max")]
    n_max: u64,
    #[serde(default)]
    last_pcs_refresh_ec: Option<u64>,
    #[serde(default = "default_pcs_refresh_min_delta_device_ec")]
    pcs_refresh_min_delta_device_ec: u64,
    #[serde(default = "default_pcs_refresh_min_delta_group_ec")]
    pcs_refresh_min_delta_group_ec: u64,
    #[serde(default = "default_pcs_refresh_slot_width_ec")]
    pcs_refresh_slot_width_ec: u64,
    #[serde(default = "default_max_barrier_update_bytes")]
    max_barrier_update_bytes: u64,
    #[serde(default)]
    accepted_barrier_merges: Vec<PersistedAcceptedBarrierMergeRecord>,
    #[serde(default)]
    current_history_commitment: PersistedHistoryCommitment,
    #[serde(default)]
    current_accepted_barrier_update: Vec<u8>,
    #[serde(default)]
    current_accepted_barrier_predecessor_hash: [u8; 32],
    #[serde(default)]
    pending_join_finalize_auth: Vec<PersistedJoinFinalizeAuthRecord>,
    #[serde(default)]
    device_chain_states: Vec<PersistedDeviceChainState>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PersistedDeviceChainState {
    device_pk: Vec<u8>,
    #[serde(default)]
    last_commit: Option<[u8; 32]>,
    #[serde(default)]
    last_ec: u64,
    #[serde(default)]
    last_pcs_refresh_ec: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PersistedAcceptedBarrierMergeRecord {
    #[serde(default)]
    barrier_version: u64,
    #[serde(default)]
    fs_ec: u64,
    #[serde(default)]
    reason: u64,
    #[serde(default)]
    digest_hex: String,
    #[serde(default)]
    we_epoch_id_hex: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PersistedJoinFinalizeAuthRecord {
    #[serde(default)]
    leaf_id_hex: String,
    #[serde(default)]
    cover_leaf_index: u32,
    #[serde(default)]
    token_hex: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PersistedBarrierPublicTreeSnapshot {
    #[serde(default)]
    kem_tree_hash_after_hex: String,
    #[serde(default)]
    barrier_version: u64,
    #[serde(default)]
    history_view_id_hex: String,
    #[serde(default)]
    history_commitment: PersistedHistoryCommitment,
    #[serde(default)]
    blob_indices: Vec<BarrierBlobIndex>,
    #[serde(default)]
    pk_entries: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PersistedHistoryCommitment {
    #[serde(default)]
    history_view_id_hex: String,
    #[serde(default)]
    history_commitment_id_hex: String,
    #[serde(default)]
    prev_history_commitment_id_hex: String,
    #[serde(default)]
    history_seq: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PersistedHistoryAuthorityState {
    #[serde(default)]
    mode: String,
    #[serde(default)]
    scope_id_hex: String,
    #[serde(default)]
    public_key_hex: String,
    #[serde(default)]
    secret_key_hex: String,
    #[serde(default = "default_require_full_verification_receipt")]
    require_full_verification_receipt: bool,
}

fn default_require_full_verification_receipt() -> bool {
    true
}

fn history_authority_path_for_journal(journal_path: &Path) -> PathBuf {
    journal_path.with_extension("history-authority.cbor")
}

fn load_history_authority_state(path: &Path) -> Result<Option<HistoryAuthorityState>, CityGError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(CityGError::Io(err)),
    };
    let persisted: PersistedHistoryAuthorityState = ciborium::de::from_reader(file)
        .map_err(|_| CityGError::InvalidInput("invalid history authority state"))?;
    if persisted.scope_id_hex.is_empty()
        || persisted.public_key_hex.is_empty()
        || persisted.secret_key_hex.is_empty()
    {
        return Ok(None);
    }
    let mode = HistoryAuthorityMode::from_persisted_tag(&persisted.mode)?;
    Ok(Some(HistoryAuthorityState {
        mode,
        descriptor: HistoryAuthorityDescriptor {
            scope_id: decode_hex_32("history authority scope_id", &persisted.scope_id_hex)?,
            public_key: hex::decode(&persisted.public_key_hex)
                .map_err(|_| CityGError::InvalidInput("invalid history authority public key"))?,
        },
        secret_key: hex::decode(&persisted.secret_key_hex)
            .map_err(|_| CityGError::InvalidInput("invalid history authority secret key"))?,
        require_full_verification_receipt: normalize_history_authority_receipt_requirement(
            mode,
            persisted.require_full_verification_receipt,
        ),
    }))
}

fn persist_history_authority_state(
    path: &Path,
    state: &HistoryAuthorityState,
) -> Result<(), CityGError> {
    #[allow(clippy::collapsible_if)]
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let persisted = PersistedHistoryAuthorityState {
        mode: state.mode.persisted_tag().to_string(),
        scope_id_hex: hex::encode(state.descriptor.scope_id),
        public_key_hex: hex::encode(&state.descriptor.public_key),
        secret_key_hex: hex::encode(&state.secret_key),
        require_full_verification_receipt: state.require_full_verification_receipt,
    };
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&persisted, &mut bytes)
        .map_err(|_| CityGError::InvalidInput("failed to encode history authority state"))?;
    let mut tmp_os = path.as_os_str().to_os_string();
    tmp_os.push(".tmp");
    let tmp_path = PathBuf::from(tmp_os);
    {
        let mut file = File::create(&tmp_path)?;
        file.write_all(&bytes)?;
        file.flush()?;
        file.sync_data()?;
    }
    std::fs::rename(tmp_path, path)?;
    Ok(())
}

fn derive_history_authority_scope_id(public_key: &[u8]) -> Result<[u8; 32], CityGError> {
    #[derive(Serialize)]
    struct ScopePreimage<'a>(#[serde(with = "serde_bytes")] &'a [u8]);
    h_l(
        "barrier/history-authority/scope",
        &ScopePreimage(public_key),
    )
    .map_err(CityGError::from)
}

fn generate_history_authority_state(
    mode: HistoryAuthorityMode,
    require_full_verification_receipt: bool,
) -> Result<HistoryAuthorityState, CityGError> {
    let (public_key, secret_key) = dilithium5::keypair();
    let public_key = public_key.as_bytes().to_vec();
    let secret_key = secret_key.as_bytes().to_vec();
    Ok(HistoryAuthorityState {
        mode,
        descriptor: HistoryAuthorityDescriptor {
            scope_id: derive_history_authority_scope_id(public_key.as_slice())?,
            public_key,
        },
        secret_key,
        require_full_verification_receipt: normalize_history_authority_receipt_requirement(
            mode,
            require_full_verification_receipt,
        ),
    })
}

fn normalize_history_authority_receipt_requirement(
    mode: HistoryAuthorityMode,
    requested: bool,
) -> bool {
    if mode.requires_full_verification_receipt() {
        true
    } else {
        requested
    }
}

fn load_or_generate_history_authority_state(
    path: Option<&Path>,
    mode: HistoryAuthorityMode,
    require_full_verification_receipt: bool,
) -> Result<HistoryAuthorityState, CityGError> {
    let require_full_verification_receipt =
        normalize_history_authority_receipt_requirement(mode, require_full_verification_receipt);
    if let Some(path) = path {
        if let Some(mut state) = load_history_authority_state(path)? {
            state.mode = mode;
            state.require_full_verification_receipt = require_full_verification_receipt;
            persist_history_authority_state(path, &state)?;
            return Ok(state);
        }
        let state = generate_history_authority_state(mode, require_full_verification_receipt)?;
        persist_history_authority_state(path, &state)?;
        return Ok(state);
    }
    generate_history_authority_state(mode, require_full_verification_receipt)
}

fn decode_hex_32(label: &'static str, value: &str) -> Result<[u8; 32], CityGError> {
    let bytes = hex::decode(value).map_err(|_| CityGError::InvalidInput(label))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| CityGError::InvalidInput(label))
}

fn kbroad_state_path_for_journal(journal_path: &Path) -> PathBuf {
    journal_path.with_extension("kbroad.cbor")
}

fn load_kbroad_state(path: &Path) -> Result<PersistedKbroadState, CityGError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(err) => return Err(CityGError::Io(err)),
    };
    ciborium::de::from_reader(file).map_err(|_| CityGError::InvalidInput("invalid kbroad state"))
}

fn persist_kbroad_state(path: &Path, state: &PersistedKbroadState) -> Result<(), CityGError> {
    #[allow(clippy::collapsible_if)]
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let mut bytes = Vec::new();
    ciborium::ser::into_writer(state, &mut bytes)
        .map_err(|_| CityGError::InvalidInput("failed to encode kbroad state"))?;

    let mut tmp_os = path.as_os_str().to_os_string();
    tmp_os.push(".tmp");
    let tmp_path = PathBuf::from(tmp_os);
    {
        let mut file = File::create(&tmp_path)?;
        file.write_all(&bytes)?;
        file.flush()?;
        file.sync_data()?;
    }
    std::fs::rename(tmp_path, path)?;
    Ok(())
}

fn is_zero_root(root: &[u8; 32]) -> bool {
    root.iter().all(|byte| *byte == 0)
}

fn leaf_index(leaf: &[u8; 32]) -> u32 {
    let bytes: [u8; 4] = leaf[28..32].try_into().unwrap_or_default();
    u32::from_be_bytes(bytes)
}

/// Spec S3.2 cover index mapping.
///
/// The mapping is deterministic across components:
/// `cover_leaf_index(device_pk) = leaf_index(device_pk) mod n_max`.
/// We clamp `n_max` to `[1, u32::MAX]` before applying modulo.
fn cover_leaf_index(leaf: &[u8; 32], n_max: u64) -> u32 {
    let n_max = n_max.max(1).min(u32::MAX as u64) as u32;
    leaf_index(leaf) % n_max
}

#[derive(Debug)]
struct ServerJournal {
    file: File,
}

#[cfg(test)]
static JOURNAL_FAIL_ON_APPEND: AtomicIsize = AtomicIsize::new(-1);
#[cfg(test)]
static JOURNAL_HOOK_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
#[cfg(test)]
static JOURNAL_SERIAL_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[cfg(test)]
fn journal_failure_lock() -> &'static Mutex<()> {
    JOURNAL_HOOK_LOCK.get_or_init(Mutex::default)
}

#[cfg(test)]
fn journal_serial_lock() -> &'static Mutex<()> {
    JOURNAL_SERIAL_LOCK.get_or_init(Mutex::default)
}

#[cfg(test)]
pub(crate) struct JournalFailureGuard {
    _lock: MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for JournalFailureGuard {
    fn drop(&mut self) {
        JOURNAL_FAIL_ON_APPEND.store(-1, Ordering::SeqCst);
    }
}

#[cfg(test)]
pub(crate) fn fail_journal_after(countdown: usize) -> JournalFailureGuard {
    let lock = match journal_failure_lock().lock() {
        Ok(lock) => lock,
        Err(poisoned) => poisoned.into_inner(),
    };
    JOURNAL_FAIL_ON_APPEND.store(countdown as isize, Ordering::SeqCst);
    JournalFailureGuard { _lock: lock }
}

#[cfg(test)]
pub(crate) fn journal_serial_guard() -> MutexGuard<'static, ()> {
    match journal_serial_lock().lock() {
        Ok(lock) => lock,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl ServerJournal {
    fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();
        #[allow(clippy::collapsible_if)]
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(path)?;
        Ok(Self { file })
    }

    fn append(&mut self, bundle: &ClientEpochBundle) -> Result<(), CityGError> {
        let bytes = bundle.to_cbor()?;
        let len = bytes.len() as u32;
        #[cfg(test)]
        {
            let remaining = JOURNAL_FAIL_ON_APPEND.load(Ordering::SeqCst);
            if remaining >= 0 {
                if remaining == 0 {
                    JOURNAL_FAIL_ON_APPEND.store(-1, Ordering::SeqCst);
                    return Err(std::io::Error::other("forced journal failure").into());
                } else {
                    JOURNAL_FAIL_ON_APPEND.store(remaining - 1, Ordering::SeqCst);
                }
            }
        }
        self.file.write_all(&len.to_le_bytes())?;
        self.file.write_all(&bytes)?;
        self.file.flush()?;
        self.file.sync_data()?;
        Ok(())
    }

    fn load_entries(path: &Path) -> Result<Vec<Vec<u8>>, CityGError> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(CityGError::Io(err)),
        };
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        let mut cursor = &buf[..];
        let mut entries = Vec::new();
        while cursor.len() >= 4 {
            let (len_bytes, rest) = cursor.split_at(4);
            let len = u32::from_le_bytes(
                len_bytes
                    .try_into()
                    .map_err(|_| CityGError::InvalidInput("Invalid journal entry length"))?,
            );
            if rest.len() < len as usize {
                break;
            }
            let (entry, remainder) = rest.split_at(len as usize);
            entries.push(entry.to_vec());
            cursor = remainder;
        }
        Ok(entries)
    }
}

pub mod demo {
    use super::*;

    /// Build a server configured with the demo KBROAD keypair.
    pub fn demo_server() -> CityGServer {
        let mut config = ServerConfig::new();
        let mut registry = BTreeMap::new();
        registry.insert(
            cityg_client::demo::DEMO_GID.to_vec(),
            cityg_client::demo::kbroad_public().to_vec(),
        );
        config.window_ttl = Some(Duration::from_secs(120));
        let options = AcceptanceOptions {
            bootstrap_policy: BootstrapPolicy::CaMlDsa {
                public_key: cityg_client::demo::bootstrap_public().to_vec(),
            },
            kbroad_registry: Some(registry),
            ..AcceptanceOptions::default()
        };
        config.acceptance_options = Some(options);
        CityGServer::new(config)
    }
}
