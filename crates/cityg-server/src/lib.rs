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

mod barrier_tree_state;
mod history_authority_state;
mod journal_io;
mod kbroad_state_io;
mod persisted_state;
mod roster_state;

pub(crate) use barrier_tree_state::*;
/// Re-export commonly used client-side bundle types for convenience.
pub use cityg_client::{AnchorBundle, BindingMaterial};
pub(crate) use history_authority_state::*;
pub(crate) use journal_io::*;
pub(crate) use kbroad_state_io::*;
pub(crate) use persisted_state::*;
pub(crate) use roster_state::*;

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
        BarrierUpdateWire, CityGError, CityGServer, GLOBAL_HISTORY_ATTESTATION_FINALITY_KIND,
        GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID, GlobalHistoryAttestationSignedPayload, GroupState,
        KemTreeCoverPayloadWire, NewPublicKeyWire, NodeCiphertextWire,
        PersistedBarrierPublicTreeSnapshot, PersistedKbroadRoomState, ServerConfig,
        blank_internal_path_from_leaf, build_all_blank_pk_entries, build_pk_entries,
        collect_expected_pairs, compute_barrier_pkhash, compute_barrier_tree_hash,
        compute_group_barrier_tree_hash, compute_revocation_roots_hash, cover_leaf_index,
        global_history_parent_attestation_id, parse_barrier_update,
        parse_global_history_attestation, sibling_node, validate_barrier_update_against_roster,
        verify_history_authority_signature,
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

    #[path = "hostile_recovery.rs"]
    mod hostile_recovery;

    #[path = "admin_acl.rs"]
    mod admin_acl;

    #[path = "barrier_snapshot_helpers.rs"]
    mod barrier_snapshot_helpers;

    #[path = "kbroad_persistence.rs"]
    mod kbroad_persistence;

    #[path = "ticket_generation.rs"]
    mod ticket_generation;

    #[path = "barrier_validation.rs"]
    mod barrier_validation;

    #[path = "barrier_update_parsing.rs"]
    mod barrier_update_parsing;

    #[path = "barrier_update_validation.rs"]
    mod barrier_update_validation;

    #[path = "history_authority.rs"]
    mod history_authority;

    #[path = "barrier_hash_helpers.rs"]
    mod barrier_hash_helpers;

    #[path = "parsing_and_barrier_helpers.rs"]
    mod parsing_and_barrier_helpers;

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
