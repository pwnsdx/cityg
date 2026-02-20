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
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use ciborium::value::Value;
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
use rand::{RngCore, rngs::OsRng};
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
        }
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
    /// Provisioned barrier secret for payload key schedule binding.
    pub k_barrier: [u8; 32],
    /// Current committed barrier tree hash.
    pub kem_tree_hash_after: [u8; 32],
    /// Fixed barrier tree capacity.
    pub n_max: u64,
    /// Deployment-wide barrier update size limit.
    pub max_barrier_update_bytes: u64,
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
    pub k_barrier: [u8; 32],
    pub kem_tree_hash_after: [u8; 32],
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Heap-indexed public key entries (`2*n_max-1` length).
    pub pk_entries: Vec<Vec<u8>>,
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
            last_pcs_refresh_ec,
            pcs_refresh_min_delta_device_ec,
            pcs_refresh_min_delta_group_ec,
            pcs_refresh_slot_width_ec,
        ) = {
            let state = self.roster.groups.entry(gid.to_vec()).or_default();
            if state.k_barrier == [0u8; 32] {
                state.k_barrier = random_barrier_key();
            }
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
                state.n_max = n_max;
                state.barrier_pk_entries = blank_entries;
            }
            (
                state.barrier_initialized,
                state.barrier_version,
                state.barrier_roots_hash,
                state.kem_tree_hash_after,
                state.n_max.max(1),
                state.last_pcs_refresh_ec,
                state.pcs_refresh_min_delta_device_ec.max(1),
                state.pcs_refresh_min_delta_group_ec.max(1),
                state.pcs_refresh_slot_width_ec.max(1),
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
        ctx_state.n_max = n_max;
        ctx_state.last_pcs_refresh_ec = last_pcs_refresh_ec;
        ctx_state.pcs_refresh_min_delta_device_ec = pcs_refresh_min_delta_device_ec;
        ctx_state.pcs_refresh_min_delta_group_ec = pcs_refresh_min_delta_group_ec;
        ctx_state.pcs_refresh_slot_width_ec = pcs_refresh_slot_width_ec;
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

    pub fn rotate_group_kbroad(
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
        self.persist_kbroad_state()?;
        Ok(generation)
    }

    pub fn kbroad_generation(&self, gid: &[u8; 32]) -> u64 {
        self.roster.kbroad_generation(gid)
    }

    pub fn kbroad_rotation_required(&self, gid: &[u8; 32]) -> bool {
        self.roster.kbroad_rotation_required(gid)
    }

    fn ensure_group_barrier_secret(&mut self, gid: &[u8; 32]) -> Result<[u8; 32], CityGError> {
        let mut changed = false;
        let key = {
            let state = self.roster.groups.entry(gid.to_vec()).or_default();
            if state.k_barrier == [0u8; 32] {
                state.k_barrier = random_barrier_key();
                changed = true;
            }
            state.k_barrier
        };
        if changed {
            self.persist_kbroad_state()?;
        }
        Ok(key)
    }

    pub fn new(config: ServerConfig) -> Self {
        let h_max = config.h_max.unwrap_or(DEFAULT_H_MAX);
        let ttl = config.window_ttl.unwrap_or(DEFAULT_T_WINDOW);
        let kbroad_state_path = config
            .state_path
            .as_ref()
            .map(|path| kbroad_state_path_for_journal(path.as_path()));
        let persisted_kbroad_state = kbroad_state_path
            .as_ref()
            .and_then(|path| load_kbroad_state(path).ok())
            .filter(|state| !state.is_empty());
        let mut options = config.acceptance_options.unwrap_or_default();
        if let Some(state) = persisted_kbroad_state.as_ref() {
            let registry: BTreeMap<Vec<u8>, Vec<u8>> = state
                .iter()
                .map(|(gid, room)| (gid.clone(), room.kbroad_public.clone()))
                .collect();
            options.kbroad_registry = Some(registry);
        }
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
            replaying: false,
        };
        #[allow(clippy::collapsible_if)]
        if let Some(path) = config.state_path {
            if let Err(err) = server.recover_from_state(&path) {
                eprintln!("cityg-server: state recovery failed: {err:?}");
            }
        }
        if let Some(state) = persisted_kbroad_state {
            server.apply_persisted_kbroad_state(&state);
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
        if self.roster.kbroad_rotation_required(gid) {
            return Err(CityGError::InvalidInput(KBROAD_ROTATION_REQUIRED_ERR));
        }
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
            revoked_since_root,
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
        let k_barrier = self.ensure_group_barrier_secret(gid)?;
        let barrier_version = barrier_state.barrier_version;
        let cover_leaf_index = u64::from(cover_leaf_index(&leaf_id, barrier_state.n_max.max(1)));
        let max_barrier_update_bytes =
            u64::try_from(barrier_state.max_barrier_update_bytes).unwrap_or(u64::MAX);

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
            k_barrier,
            kem_tree_hash_after: barrier_state.kem_tree_hash_after,
            n_max: barrier_state.n_max.max(1),
            max_barrier_update_bytes,
        })
    }

    pub fn build_merge_ticket(
        &mut self,
        gid: &[u8; 32],
        leaf_id: &[u8; 32],
    ) -> Result<MergeTicketBundle, CityGError> {
        self.build_merge_ticket_with_intent(gid, leaf_id, MergeTicketIntent::Leave)
    }

    pub fn build_merge_ticket_for_refresh(
        &mut self,
        gid: &[u8; 32],
        leaf_id: &[u8; 32],
    ) -> Result<MergeTicketBundle, CityGError> {
        self.build_merge_ticket_with_intent(gid, leaf_id, MergeTicketIntent::Refresh)
    }

    fn build_merge_ticket_with_intent(
        &mut self,
        gid: &[u8; 32],
        leaf_id: &[u8; 32],
        intent: MergeTicketIntent,
    ) -> Result<MergeTicketBundle, CityGError> {
        if self.roster.kbroad_rotation_required(gid) {
            return Err(CityGError::InvalidInput(KBROAD_ROTATION_REQUIRED_ERR));
        }
        let parent_root = self
            .roster
            .latest_root(gid)
            .ok_or(CityGError::InvalidInput("no anchors accepted for group"))?;

        let mut members = self
            .roster
            .members_for_root(gid, &parent_root)
            .ok_or(CityGError::InvalidInput("unknown membership root"))?;

        members.sort();

        if !members.iter().any(|member| member == leaf_id) {
            return Err(CityGError::InvalidInput("leaf not present in roster"));
        }

        let (revoked_since, revoked_all, srx_cbor): (Vec<[u8; 32]>, Vec<[u8; 32]>, Vec<u8>) =
            match intent {
                MergeTicketIntent::Leave => {
                    let mut revoked_since = vec![*leaf_id];
                    revoked_since.sort();

                    let mut revoked_all = self.roster.revoked(gid);
                    if !revoked_all.iter().any(|leaf| leaf == leaf_id) {
                        revoked_all.push(*leaf_id);
                    }
                    revoked_all.sort();
                    revoked_all.dedup();

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
                    (revoked_since, revoked_all, srx_owned.to_cbor()?)
                }
                MergeTicketIntent::Refresh => {
                    let mut revoked_all = self.roster.revoked(gid);
                    revoked_all.sort();
                    revoked_all.dedup();
                    (revoked_all.clone(), revoked_all, Vec::new())
                }
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

        let mut parities = self.ctx.pivot_parities_for(gid, &parent_root);
        if parities.is_empty() {
            return Err(CityGError::InvalidInput("no pivot parity available"));
        }

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
        let k_barrier = self.ensure_group_barrier_secret(gid)?;
        let barrier_version = barrier_state.barrier_version;
        let cover_leaf_index = u64::from(cover_leaf_index(leaf_id, barrier_state.n_max.max(1)));
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

        Ok(MergeTicketBundle {
            gid: *gid,
            cat: DEFAULT_CAT,
            parent_root,
            leaf_id: *leaf_id,
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
            k_barrier,
            kem_tree_hash_after: barrier_state.kem_tree_hash_after,
            n_max: barrier_state.n_max.max(1),
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
        let (outcome, staged_ctx, staged_receiver, staged_roster) = self.stage_bundle(bundle)?;
        #[allow(clippy::collapsible_if)]
        if !self.replaying {
            if let Some(journal) = &mut self.journal {
                journal.append(bundle)?;
            }
        }
        self.commit_staged(staged_ctx, staged_receiver, staged_roster);
        Ok(outcome)
    }

    fn stage_bundle(
        &mut self,
        bundle: &ClientEpochBundle,
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
    ) -> Result<ServerOutcome, CityGError> {
        let state_before = roster.groups.get(bundle.gid()).cloned().unwrap_or_default();
        let delta = bundle.membership_delta()?;
        let barrier_validation =
            validate_barrier_update_against_roster(&state_before, &bundle.header_map, &delta)?;

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
        group.n_max = barrier_state.n_max.max(1);
        group.last_pcs_refresh_ec = barrier_state.last_pcs_refresh_ec;
        group.pcs_refresh_min_delta_device_ec =
            barrier_state.pcs_refresh_min_delta_device_ec.max(1);
        group.pcs_refresh_min_delta_group_ec = barrier_state.pcs_refresh_min_delta_group_ec.max(1);
        group.pcs_refresh_slot_width_ec = barrier_state.pcs_refresh_slot_width_ec.max(1);

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
        let new_root = roster.apply_delta(bundle.gid(), &bundle.anchor.parent_root, &delta)?;

        if !delta.joined.is_empty() || !delta.revoked.is_empty() {
            let state = roster.groups.entry(bundle.gid().to_vec()).or_default();
            for leaf in &delta.joined {
                let leaf_index = cover_leaf_index(leaf, state.n_max.max(1));
                let device_pk = maybe_device_pk.clone().unwrap_or_else(|| leaf.to_vec());
                let ek_leaf = maybe_barrier_leaf_pk.clone().unwrap_or_default();
                state.join_history.push(JoinLeafHistoryRecord {
                    barrier_version,
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
            }
            if barrier_validation.is_none() {
                state.kem_tree_hash_after = compute_group_barrier_tree_hash(state)?;
            }
        }
        if let Some(validation) = barrier_validation.as_ref() {
            let state = roster.groups.entry(bundle.gid().to_vec()).or_default();
            state.barrier_pk_entries = validation.snapshot_post.clone();
            state.kem_tree_hash_after = validation.parsed.kem_tree_hash_after;
            state.n_max = validation.parsed.tree_size.max(1);
        }
        if let Some(state) = roster.groups.get(bundle.gid()) {
            let ctx_state = ctx.barrier_group_state_entry_mut(bundle.gid());
            ctx_state.barrier_initialized = state.barrier_initialized;
            ctx_state.barrier_version = state.barrier_version;
            ctx_state.barrier_roots_hash = state.barrier_roots_hash;
            ctx_state.kem_tree_hash_after = state.kem_tree_hash_after;
            ctx_state.n_max = state.n_max.max(1);
            ctx_state.last_pcs_refresh_ec = state.last_pcs_refresh_ec;
            ctx_state.pcs_refresh_min_delta_device_ec =
                state.pcs_refresh_min_delta_device_ec.max(1);
            ctx_state.pcs_refresh_min_delta_group_ec = state.pcs_refresh_min_delta_group_ec.max(1);
            ctx_state.pcs_refresh_slot_width_ec = state.pcs_refresh_slot_width_ec.max(1);
        }

        // Keep at least one pivot parity available on the resulting root so members
        // can always fetch a merge ticket for subsequent membership changes.
        let mut mirrored = ctx
            .pivot_parities_for(bundle.gid(), &bundle.anchor.parent_root)
            .into_iter()
            .find(|parity| parity.we_epoch_id == acceptance.outcome.we_epoch_id)
            .unwrap_or_else(|| acceptance.pivot_parity.clone());
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
    }

    fn apply_persisted_kbroad_state(&mut self, state: &PersistedKbroadState) {
        let mut registry = self.ctx.kbroad_registry().cloned().unwrap_or_default();
        for (gid, room_state) in state {
            registry.insert(gid.clone(), room_state.kbroad_public.clone());
            let group = self.roster.groups.entry(gid.clone()).or_default();
            group.kbroad_generation = room_state.kbroad_generation;
            group.rotation_required = room_state.rotation_required;
            group.barrier_initialized = room_state.barrier_initialized;
            group.barrier_version = room_state.barrier_version;
            group.k_barrier = room_state.k_barrier;
            group.barrier_roots_hash = room_state.barrier_roots_hash;
            group.kem_tree_hash_after = room_state.kem_tree_hash_after;
            group.n_max = room_state.n_max.max(1);
            group.barrier_pk_entries = room_state.barrier_pk_entries.clone();
            group.last_pcs_refresh_ec = room_state.last_pcs_refresh_ec;
            group.pcs_refresh_min_delta_device_ec =
                room_state.pcs_refresh_min_delta_device_ec.max(1);
            group.pcs_refresh_min_delta_group_ec = room_state.pcs_refresh_min_delta_group_ec.max(1);
            group.pcs_refresh_slot_width_ec = room_state.pcs_refresh_slot_width_ec.max(1);
            self.ctx.insert_barrier_group_state(
                gid.as_slice(),
                msphf_orchestrator::BarrierGroupState {
                    barrier_initialized: group.barrier_initialized,
                    barrier_version: group.barrier_version,
                    barrier_roots_hash: group.barrier_roots_hash,
                    kem_tree_hash_after: group.kem_tree_hash_after,
                    n_max: group.n_max,
                    max_barrier_update_bytes: msphf_orchestrator::BarrierGroupState::default()
                        .max_barrier_update_bytes,
                    last_pcs_refresh_ec: group.last_pcs_refresh_ec,
                    pcs_refresh_min_delta_device_ec: group.pcs_refresh_min_delta_device_ec,
                    pcs_refresh_min_delta_group_ec: group.pcs_refresh_min_delta_group_ec,
                    pcs_refresh_slot_width_ec: group.pcs_refresh_slot_width_ec,
                },
            );
        }
        self.ctx.set_kbroad_registry(Some(registry));
    }

    fn snapshot_kbroad_state(&self) -> PersistedKbroadState {
        let registry = self.ctx.kbroad_registry().cloned().unwrap_or_default();
        registry
            .into_iter()
            .map(|(gid, kbroad_public)| {
                let room = PersistedKbroadRoomState {
                    kbroad_public,
                    kbroad_generation: self.roster.kbroad_generation(gid.as_slice()),
                    rotation_required: self.roster.kbroad_rotation_required(gid.as_slice()),
                    barrier_initialized: self
                        .roster
                        .groups
                        .get(gid.as_slice())
                        .map(|state| state.barrier_initialized)
                        .unwrap_or(false),
                    barrier_version: self
                        .roster
                        .groups
                        .get(gid.as_slice())
                        .map(|state| state.barrier_version)
                        .unwrap_or(0),
                    k_barrier: self
                        .roster
                        .groups
                        .get(gid.as_slice())
                        .map(|state| state.k_barrier)
                        .unwrap_or([0u8; 32]),
                    barrier_roots_hash: self
                        .roster
                        .groups
                        .get(gid.as_slice())
                        .map(|state| state.barrier_roots_hash)
                        .unwrap_or([0u8; 32]),
                    kem_tree_hash_after: self
                        .roster
                        .groups
                        .get(gid.as_slice())
                        .map(|state| state.kem_tree_hash_after)
                        .unwrap_or([0u8; 32]),
                    barrier_pk_entries: self
                        .roster
                        .groups
                        .get(gid.as_slice())
                        .map(|state| state.barrier_pk_entries.clone())
                        .unwrap_or_default(),
                    n_max: self
                        .roster
                        .groups
                        .get(gid.as_slice())
                        .map(|state| state.n_max.max(1))
                        .unwrap_or(DEFAULT_BARRIER_N_MAX),
                    last_pcs_refresh_ec: self
                        .roster
                        .groups
                        .get(gid.as_slice())
                        .and_then(|state| state.last_pcs_refresh_ec),
                    pcs_refresh_min_delta_device_ec: self
                        .roster
                        .groups
                        .get(gid.as_slice())
                        .map(|state| state.pcs_refresh_min_delta_device_ec.max(1))
                        .unwrap_or_else(default_pcs_refresh_min_delta_device_ec),
                    pcs_refresh_min_delta_group_ec: self
                        .roster
                        .groups
                        .get(gid.as_slice())
                        .map(|state| state.pcs_refresh_min_delta_group_ec.max(1))
                        .unwrap_or_else(default_pcs_refresh_min_delta_group_ec),
                    pcs_refresh_slot_width_ec: self
                        .roster
                        .groups
                        .get(gid.as_slice())
                        .map(|state| state.pcs_refresh_slot_width_ec.max(1))
                        .unwrap_or_else(default_pcs_refresh_slot_width_ec),
                };
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

    fn recover_from_state(&mut self, path: &Path) -> Result<(), CityGError> {
        let entries = ServerJournal::load_entries(path)?;
        if entries.is_empty() {
            return Ok(());
        }
        self.reset_state();
        self.replaying = true;
        let replay_result = (|| -> Result<(), CityGError> {
            for entry in entries {
                let bundle = ClientEpochBundle::from_cbor(&entry)?;
                let (_, ctx, receiver, roster) = self.stage_bundle(&bundle)?;
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

    pub fn barrier_n_max(&self, gid: &[u8]) -> Option<u64> {
        self.roster.groups.get(gid).map(|state| state.n_max)
    }

    pub fn resolve_revoked_leaf_indices(
        &self,
        gid: &[u8; 32],
        revocation_roots_hash: &[u8; 32],
    ) -> Result<Vec<u32>, CityGError> {
        let state = self
            .roster
            .groups
            .get(gid.as_slice())
            .ok_or(CityGError::InvalidInput("group not found"))?;
        if state.barrier_roots_hash != *revocation_roots_hash {
            return Err(CityGError::InvalidInput(
                "revocation_roots_hash does not match committed barrier roots",
            ));
        }
        let mut indices: Vec<u32> = state
            .revoked
            .iter()
            .map(|leaf| cover_leaf_index(leaf, state.n_max.max(1)))
            .collect();
        indices.sort_unstable();
        indices.dedup();
        Ok(indices)
    }

    pub fn resolve_joins_since(
        &self,
        gid: &[u8; 32],
        prev_barrier_version: u64,
    ) -> Result<Vec<BarrierJoinLeafRecord>, CityGError> {
        let state = self
            .roster
            .groups
            .get(gid.as_slice())
            .ok_or(CityGError::InvalidInput("group not found"))?;
        let mut by_leaf: BTreeMap<u32, BarrierJoinLeafRecord> = BTreeMap::new();
        if prev_barrier_version == 0 && state.barrier_version == 0 {
            if let Some(snapshot) = state.latest_snapshot() {
                for leaf in snapshot.members() {
                    let leaf_index = cover_leaf_index(leaf, state.n_max.max(1));
                    by_leaf.insert(
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
                    );
                }
            }
            return Ok(by_leaf.into_values().collect());
        }
        for record in &state.join_history {
            if record.barrier_version > prev_barrier_version {
                by_leaf.insert(
                    record.leaf_index,
                    BarrierJoinLeafRecord {
                        device_pk: record.device_pk.clone(),
                        leaf_index: record.leaf_index,
                        ek_leaf: record.ek_leaf.clone(),
                    },
                );
            }
        }
        Ok(by_leaf.into_values().collect())
    }

    pub fn fetch_barrier_public_tree(
        &self,
        gid: &[u8; 32],
        kem_tree_hash_after: &[u8; 32],
    ) -> Result<BarrierPublicTreeSnapshot, CityGError> {
        let state = self
            .roster
            .groups
            .get(gid.as_slice())
            .ok_or(CityGError::InvalidInput("group not found"))?;
        let pk_entries = build_pk_entries(state)?;
        let computed_hash = compute_barrier_tree_hash(state.n_max, &pk_entries)?;
        if computed_hash != *kem_tree_hash_after {
            return Err(CityGError::InvalidInput(
                "barrier tree snapshot auth failure",
            ));
        }
        Ok(BarrierPublicTreeSnapshot {
            n_max: state.n_max,
            kem_tree_hash_after: computed_hash,
            pk_entries,
        })
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
    snapshot_post: Vec<Vec<u8>>,
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
        tree_size,
        revocation_roots_hash: vec_to_32(revocation_roots_hash)?,
        kem_tree_hash_before: vec_to_32(kem_tree_hash_before)?,
        kem_tree_hash_after: vec_to_32(kem_tree_hash_after)?,
        path_nodes,
        node_ciphertexts: normalized_ciphertexts,
        new_public_keys: normalized_keys,
    }))
}

fn build_pk_entries(state: &GroupState) -> Result<Vec<Vec<u8>>, CityGError> {
    let n_max = usize::try_from(state.n_max)
        .map_err(|_| CityGError::InvalidInput("barrier n_max does not fit usize"))?;
    if n_max == 0 {
        return Err(CityGError::InvalidInput("barrier n_max must be positive"));
    }
    let expected_len = n_max.saturating_mul(2).saturating_sub(1);
    if state.barrier_pk_entries.len() == expected_len {
        return Ok(state.barrier_pk_entries.clone());
    }

    let leaf_base = n_max.saturating_sub(1);
    let mut pk_entries = vec![Vec::new(); expected_len];
    if let Some(snapshot) = state.latest_snapshot() {
        for leaf in snapshot.members() {
            let index = cover_leaf_index(leaf, state.n_max.max(1)) as usize;
            if index >= n_max {
                continue;
            }
            if let Some(ek_leaf) = state.leaf_barrier_public.get(leaf) {
                pk_entries[leaf_base + index] = ek_leaf.clone();
            }
        }
    }
    Ok(pk_entries)
}

fn compute_group_barrier_tree_hash(state: &GroupState) -> Result<[u8; 32], CityGError> {
    let pk_entries = build_pk_entries(state)?;
    compute_barrier_tree_hash(state.n_max, &pk_entries)
}

fn compute_barrier_tree_hash(n_max: u64, pk_entries: &[Vec<u8>]) -> Result<[u8; 32], CityGError> {
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
    pk_entries: &[Vec<u8>],
) -> Result<[u8; 32], CityGError> {
    let leaf_base = n_max_usize.saturating_sub(1);
    let pk = pk_entries
        .get(node_index)
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

fn blank_internal_path_from_leaf(pk_entries: &mut [Vec<u8>], leaf_node: usize) {
    for node in direct_path_nodes(leaf_node).into_iter().skip(1) {
        if let Some(slot) = pk_entries.get_mut(node) {
            slot.clear();
        }
    }
}

fn blank_leaf_and_path(pk_entries: &mut [Vec<u8>], leaf_node: usize) {
    for node in direct_path_nodes(leaf_node) {
        if let Some(slot) = pk_entries.get_mut(node) {
            slot.clear();
        }
    }
}

fn sibling_node(node: usize) -> Option<usize> {
    if node == 0 {
        return None;
    }
    if node.is_multiple_of(2) {
        Some(node.saturating_sub(1))
    } else {
        Some(node.saturating_add(1))
    }
}

fn collect_resolution_nodes(
    pk_entries: &[Vec<u8>],
    node: usize,
    leaf_base: usize,
    out: &mut Vec<usize>,
) {
    if node >= pk_entries.len() {
        return;
    }
    if !pk_entries[node].is_empty() {
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
    pk_entries: &[Vec<u8>],
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

fn build_all_blank_pk_entries(n_max: u64) -> Result<Vec<Vec<u8>>, CityGError> {
    let n_max_usize =
        usize::try_from(n_max).map_err(|_| CityGError::InvalidInput("barrier n_max too large"))?;
    let len = n_max_usize
        .checked_mul(2)
        .and_then(|v| v.checked_sub(1))
        .ok_or(CityGError::InvalidInput("barrier tree size overflow"))?;
    Ok(vec![Vec::new(); len])
}

fn validate_barrier_update_against_roster(
    state_before: &GroupState,
    header: &BTreeMap<u64, Value>,
    delta: &MembershipDelta,
) -> Result<Option<BarrierUpdateValidationOutcome>, CityGError> {
    let Some(parsed) = parse_barrier_update(header, state_before.n_max.max(1))? else {
        return Ok(None);
    };

    let mut snapshot_base = if state_before.barrier_initialized {
        build_pk_entries(state_before)?
    } else {
        build_all_blank_pk_entries(state_before.n_max.max(1))?
    };
    let leaf_base = usize::try_from(state_before.n_max.saturating_sub(1))
        .map_err(|_| CityGError::InvalidInput("barrier_update malformed"))?;

    // JoinSet: all joins activated after prev_barrier_version plus joins in current delta.
    let mut by_leaf: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    if parsed.prev_barrier_version == 0 && state_before.barrier_version == 0 {
        if let Some(snapshot) = state_before.latest_snapshot() {
            for leaf in snapshot.members() {
                let leaf_index = cover_leaf_index(leaf, state_before.n_max.max(1));
                let ek_leaf = state_before
                    .leaf_barrier_public
                    .get(leaf)
                    .cloned()
                    .unwrap_or_default();
                by_leaf.insert(leaf_index, ek_leaf);
            }
        }
    } else {
        for record in &state_before.join_history {
            if record.barrier_version > parsed.prev_barrier_version {
                by_leaf.insert(record.leaf_index, record.ek_leaf.clone());
            }
        }
    }
    let join_ek = header
        .get(&hdr::HDR_BARRIER_LEAF_PK)
        .and_then(Value::as_bytes)
        .map(ToOwned::to_owned)
        .unwrap_or_default();
    for leaf in &delta.joined {
        let leaf_index = cover_leaf_index(leaf, state_before.n_max.max(1));
        by_leaf.insert(leaf_index, join_ek.clone());
    }
    for (leaf_index, ek_leaf) in by_leaf {
        let leaf_node = leaf_base.saturating_add(leaf_index as usize);
        if let Some(slot) = snapshot_base.get_mut(leaf_node) {
            *slot = ek_leaf;
        }
        blank_internal_path_from_leaf(&mut snapshot_base, leaf_node);
    }

    // RevokedLeafSet: committed revoked set plus current delta revocations.
    let mut revoked_set = state_before.revoked.clone();
    for leaf in &delta.revoked {
        revoked_set.insert(*leaf);
    }
    let mut revoked_indices = BTreeSet::new();
    for leaf in revoked_set {
        revoked_indices.insert(cover_leaf_index(&leaf, state_before.n_max.max(1)) as usize);
    }
    for revoked_index in revoked_indices {
        let leaf_node = leaf_base.saturating_add(revoked_index);
        blank_leaf_and_path(&mut snapshot_base, leaf_node);
    }

    let expected_before =
        compute_barrier_tree_hash(state_before.n_max.max(1), snapshot_base.as_slice())?;
    if expected_before != parsed.kem_tree_hash_before {
        return Err(CityGError::InvalidInput("barrier tree hash chain failure"));
    }

    let revocation_roots_hash = compute_revocation_roots_hash(
        &header_bytes32(header, 112, "missing revoked_since_root")?,
        &header_bytes32(header, hdr::HDR_REVOKED_ROOT, "missing revoked_root")?,
    )?;
    if parsed.revocation_roots_hash != revocation_roots_hash {
        return Err(CityGError::InvalidInput("barrier_update malformed"));
    }

    let mut snapshot_post = snapshot_base.clone();
    for (node, ek) in &parsed.new_public_keys {
        let index = usize::try_from(*node)
            .map_err(|_| CityGError::InvalidInput("barrier_update malformed"))?;
        let slot = snapshot_post
            .get_mut(index)
            .ok_or(CityGError::InvalidInput("barrier_update malformed"))?;
        *slot = ek.clone();
    }
    let expected_after =
        compute_barrier_tree_hash(state_before.n_max.max(1), snapshot_post.as_slice())?;
    if expected_after != parsed.kem_tree_hash_after {
        return Err(CityGError::InvalidInput("barrier tree hash chain failure"));
    }

    let expected_pairs = collect_expected_pairs(
        snapshot_base.as_slice(),
        parsed.path_nodes.as_slice(),
        state_before.n_max.max(1),
    )?;
    let actual_pairs: Vec<(u64, u64)> = parsed
        .node_ciphertexts
        .iter()
        .map(|node| (node.source_node, node.target_node))
        .collect();
    if actual_pairs != expected_pairs {
        return Err(CityGError::InvalidInput("barrier expectedpairs failure"));
    }
    for node in &parsed.node_ciphertexts {
        let target_index = usize::try_from(node.target_node)
            .map_err(|_| CityGError::InvalidInput("barrier_update malformed"))?;
        let target_pk = snapshot_base
            .get(target_index)
            .ok_or(CityGError::InvalidInput("barrier_update malformed"))?;
        let target_pkhash = compute_barrier_pkhash(target_pk.as_slice())?;
        if node.target_pk_hash.as_slice() != &target_pkhash[..16] {
            return Err(CityGError::InvalidInput("barrier expectedpairs failure"));
        }
    }

    Ok(Some(BarrierUpdateValidationOutcome {
        parsed,
        snapshot_post,
    }))
}

fn header_bytes32(
    header: &BTreeMap<u64, Value>,
    key: u64,
    label: &'static str,
) -> Result<[u8; 32], CityGError> {
    match header.get(&key) {
        Some(Value::Bytes(bytes)) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            Ok(arr)
        }
        Some(Value::Bytes(_)) => Err(CityGError::InvalidInput("pivot field wrong length")),
        Some(_) => Err(CityGError::InvalidInput("pivot field wrong type")),
        None => Err(CityGError::InvalidInput(label)),
    }
}

fn header_bytes32_opt(
    header: &BTreeMap<u64, Value>,
    key: u64,
) -> Result<Option<[u8; 32]>, CityGError> {
    match header.get(&key) {
        Some(Value::Bytes(bytes)) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            Ok(Some(arr))
        }
        Some(Value::Bytes(_)) => Err(CityGError::InvalidInput("pivot field wrong length")),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(CityGError::InvalidInput("pivot field wrong type")),
    }
}

fn header_bytes(
    header: &BTreeMap<u64, Value>,
    key: u64,
    label: &'static str,
) -> Result<Vec<u8>, CityGError> {
    match header.get(&key) {
        Some(Value::Bytes(bytes)) => Ok(bytes.clone()),
        Some(_) => Err(CityGError::InvalidInput("pivot field wrong type")),
        None => Err(CityGError::InvalidInput(label)),
    }
}

fn header_bytes_opt(
    header: &BTreeMap<u64, Value>,
    key: u64,
) -> Result<Option<Vec<u8>>, CityGError> {
    match header.get(&key) {
        Some(Value::Bytes(bytes)) => Ok(Some(bytes.clone())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(CityGError::InvalidInput("pivot field wrong type")),
    }
}

fn header_string(
    header: &BTreeMap<u64, Value>,
    key: u64,
    default: Option<&'static str>,
) -> Result<String, CityGError> {
    match header.get(&key) {
        Some(Value::Text(text)) => Ok(text.clone()),
        Some(Value::Integer(value)) => u64::try_from(*value)
            .map(|v| v.to_string())
            .map_err(|_| CityGError::InvalidInput("pivot field wrong type")),
        Some(Value::Bytes(bytes)) => std::str::from_utf8(bytes)
            .map(|s| s.to_string())
            .map_err(|_| CityGError::InvalidInput("pivot field invalid utf8")),
        Some(Value::Null) => default
            .map(|s| s.to_string())
            .ok_or(CityGError::InvalidInput("pivot field missing")),
        Some(_) => Err(CityGError::InvalidInput("pivot field wrong type")),
        None => default
            .map(|s| s.to_string())
            .ok_or(CityGError::InvalidInput("pivot field missing")),
    }
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
    use super::{CityGError, CityGServer, ServerConfig};
    use ciborium::value::Value;
    use cityg_client::ClientEpochBundle;
    use msphf_core::hash::h_l;
    use msphf_orchestrator::{AcceptanceOptions, BootstrapPolicy, hdr, mhw::HeadRecord};
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use serde::Serialize;
    use std::{collections::BTreeMap, fs::File, io::Write, path::Path, time::Duration};
    use tempfile::tempdir;

    fn demo_server_with_journal(path: impl AsRef<Path>) -> CityGServer {
        let mut config = demo_acceptance_config();
        config.state_path = Some(path.as_ref().to_path_buf());
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
    fn kbroad_rotation_gate_blocks_until_rotated() -> Result<(), CityGError> {
        let mut server = super::demo::demo_server();
        let gid = cityg_client::demo::DEMO_GID;

        server.roster.mark_kbroad_rotation_required(gid.as_slice());

        let join_err = server
            .build_join_ticket(&gid)
            .expect_err("join ticket must be blocked while rotation is required");
        assert!(matches!(
            join_err,
            CityGError::InvalidInput("kbroad rotation required")
        ));

        let bundle = cityg_client::demo::demo_bundle("rotation-gate")?;
        let accept_err = server
            .accept_epoch(&bundle)
            .expect_err("acceptance must be blocked while rotation is required");
        assert!(matches!(
            accept_err,
            CityGError::InvalidInput("kbroad rotation required")
        ));

        let mut rotated_key = cityg_client::demo::kbroad_public().to_vec();
        rotated_key[0] ^= 0x5A;
        let generation = server.rotate_group_kbroad(&gid, rotated_key.clone())?;
        assert_eq!(generation, 1);
        assert_eq!(server.kbroad_generation(&gid), 1);
        assert!(!server.kbroad_rotation_required(&gid));

        let ticket = server.build_join_ticket(&gid)?;
        assert_eq!(ticket.kbroad_public, rotated_key);
        assert_eq!(ticket.kbroad_generation, 1);
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
        let persisted_k_barrier: [u8; 32];

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
            let state = server
                .roster
                .groups
                .get_mut(gid.as_slice())
                .expect("registered group state must exist");
            state.barrier_initialized = true;
            state.barrier_version = 9;
            state.barrier_roots_hash = [0xAB; 32];
            state.kem_tree_hash_after = [0xCD; 32];
            state.n_max = 2048;
            state.last_pcs_refresh_ec = Some(77);
            state.pcs_refresh_min_delta_device_ec = 3;
            state.pcs_refresh_min_delta_group_ec = 4;
            state.pcs_refresh_slot_width_ec = 5;
            persisted_k_barrier = state.k_barrier;
            assert_ne!(persisted_k_barrier, [0u8; 32]);
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
        assert_eq!(state.barrier_roots_hash, [0xAB; 32]);
        assert_eq!(state.kem_tree_hash_after, [0xCD; 32]);
        assert_eq!(state.k_barrier, persisted_k_barrier);
        assert_eq!(state.n_max, 2048);
        assert_eq!(state.last_pcs_refresh_ec, Some(77));
        assert_eq!(state.pcs_refresh_min_delta_device_ec, 3);
        assert_eq!(state.pcs_refresh_min_delta_group_ec, 4);
        assert_eq!(state.pcs_refresh_slot_width_ec, 5);
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
    fn group_state_defaults_include_barrier_policy_bounds() -> Result<(), CityGError> {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid = [0xD1; 32];
        server.register_group(&gid, vec![0x11; 16])?;
        let state = server
            .roster
            .groups
            .get(gid.as_slice())
            .expect("group should exist after registration");
        assert_ne!(state.k_barrier, [0u8; 32]);
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
        assert_ne!(first.k_barrier, [0u8; 32]);
        assert_eq!(first.k_barrier, second.k_barrier);

        let mut demo_server = super::demo::demo_server();
        let bundle = cityg_client::demo::demo_bundle("alice")?;
        demo_server.accept_epoch(&bundle)?;
        let demo_ticket = demo_server.build_join_ticket(&cityg_client::demo::DEMO_GID)?;
        assert_ne!(
            demo_ticket.parent_root, [0u8; 32],
            "join ticket on non-empty roster should reference non-zero root"
        );
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
            super::header_bytes(&map, 3, "bytes"),
            Err(CityGError::InvalidInput("pivot field wrong type"))
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
            super::compute_barrier_tree_hash(0, &[]),
            Err(CityGError::InvalidInput(_))
        ));
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
        let join_ek = vec![0xA5; 1184];
        let delta = cityg_client::MembershipDelta {
            joined: vec![leaf],
            revoked: Vec::new(),
        };
        let updater_leaf = super::cover_leaf_index(&leaf, state.n_max.max(1));
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
        header.insert(112, Value::Bytes(revoked_since.to_vec()));
        header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
        header.insert(hdr::HDR_BARRIER_LEAF_PK, Value::Bytes(join_ek));

        let validation = super::validate_barrier_update_against_roster(&state, &header, &delta)?
            .ok_or(CityGError::InvalidInput("missing parsed barrier update"))?;
        assert_eq!(validation.parsed.tree_size, state.n_max);
        assert_eq!(validation.parsed.kem_tree_hash_before, kem_before);
        assert_eq!(validation.parsed.kem_tree_hash_after, kem_after);
        assert_eq!(validation.snapshot_post, snapshot_post);
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
        let join_ek = vec![0xA5; 1184];
        let delta = cityg_client::MembershipDelta {
            joined: vec![leaf],
            revoked: Vec::new(),
        };
        let updater_leaf = super::cover_leaf_index(&leaf, state.n_max.max(1));
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
        header.insert(112, Value::Bytes(revoked_since.to_vec()));
        header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));
        header.insert(hdr::HDR_BARRIER_LEAF_PK, Value::Bytes(join_ek));

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
            CityGError::InvalidInput("barrier expectedpairs failure")
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
        let leaf_index = usize::try_from(super::cover_leaf_index(&leaf, state.n_max.max(1)))
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

        let updater_leaf = u64::from(super::cover_leaf_index(&leaf, state.n_max.max(1)));
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
        header.insert(112, Value::Bytes(revoked_since.to_vec()));
        header.insert(hdr::HDR_REVOKED_ROOT, Value::Bytes(revoked_root.to_vec()));

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
    fn validate_barrier_update_detects_hash_and_roots_mismatches() -> Result<(), CityGError> {
        let mut state = super::GroupState {
            n_max: 4,
            barrier_initialized: false,
            barrier_version: 0,
            ..super::GroupState::default()
        };

        let leaf = cityg_client::demo::demo_member_leaf("barrier-mismatch-matrix");
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

        let updater_leaf = u64::from(super::cover_leaf_index(&leaf, state.n_max.max(1)));
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
            CityGError::InvalidInput("barrier tree hash chain failure")
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
            CityGError::InvalidInput("barrier_update malformed")
        ));

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
            CityGError::InvalidInput("barrier tree hash chain failure")
        ));
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
        {
            let mut server = demo_server_with_journal(&journal_path);
            let bundle_alice = cityg_client::demo::demo_bundle("alice")?;
            let bundle_bob = cityg_client::demo::demo_bundle("bob")?;
            server.accept_epoch(&bundle_alice)?;
            server.accept_epoch(&bundle_bob)?;
            assert_eq!(server.members(&cityg_client::demo::DEMO_GID).len(), 2);
        }

        let server = demo_server_with_journal(&journal_path);
        assert_eq!(server.members(&cityg_client::demo::DEMO_GID).len(), 2);
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
            let action = if step < 3 { 0 } else { rng.gen_range(0..3) };
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
            let action = if step < 2 { 0 } else { rng.gen_range(0..3) };
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

        let pool = chaos_leaf_pool();
        let mut index = *next_label as usize;
        while index < pool.len() {
            let leaf = pool[index];
            index += 1;
            if sorted.binary_search(&leaf).is_ok() {
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
        assert!(!records.is_empty(), "expected at least one join record");
        let record = &records[0];
        assert!(record.leaf_index > 0);
        assert!(!record.device_pk.is_empty());
        assert!(
            record.ek_leaf.is_empty() || record.ek_leaf.len() == 1184,
            "ek_leaf should be absent or ML-KEM-768 size"
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
        assert!(matches!(
            err,
            CityGError::InvalidInput("barrier tree snapshot auth failure")
        ));
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
        assert_eq!(snapshot.n_max, ticket.n_max.max(1));
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
        assert_eq!(indices, vec![super::cover_leaf_index(&leaf, n_max)]);

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
        let server = super::demo::demo_server();
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
    k_barrier: [u8; 32],
    barrier_roots_hash: [u8; 32],
    kem_tree_hash_after: [u8; 32],
    n_max: u64,
    last_pcs_refresh_ec: Option<u64>,
    pcs_refresh_min_delta_device_ec: u64,
    pcs_refresh_min_delta_group_ec: u64,
    pcs_refresh_slot_width_ec: u64,
    join_history: Vec<JoinLeafHistoryRecord>,
    leaf_device_pk: BTreeMap<[u8; 32], Vec<u8>>,
    leaf_barrier_public: BTreeMap<[u8; 32], Vec<u8>>,
    barrier_pk_entries: Vec<Vec<u8>>,
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
            k_barrier: [0u8; 32],
            barrier_roots_hash: [0u8; 32],
            kem_tree_hash_after: [0u8; 32],
            n_max: DEFAULT_BARRIER_N_MAX,
            last_pcs_refresh_ec: None,
            pcs_refresh_min_delta_device_ec: default_pcs_refresh_min_delta_device_ec(),
            pcs_refresh_min_delta_group_ec: default_pcs_refresh_min_delta_group_ec(),
            pcs_refresh_slot_width_ec: default_pcs_refresh_slot_width_ec(),
            join_history: Vec::new(),
            leaf_device_pk: BTreeMap::new(),
            leaf_barrier_public: BTreeMap::new(),
            barrier_pk_entries: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
struct JoinLeafHistoryRecord {
    barrier_version: u64,
    leaf_index: u32,
    device_pk: Vec<u8>,
    ek_leaf: Vec<u8>,
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

fn default_barrier_n_max() -> u64 {
    DEFAULT_BARRIER_N_MAX
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

fn random_barrier_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PersistedKbroadRoomState {
    kbroad_public: Vec<u8>,
    kbroad_generation: u64,
    rotation_required: bool,
    #[serde(default)]
    barrier_initialized: bool,
    #[serde(default)]
    barrier_version: u64,
    #[serde(default)]
    k_barrier: [u8; 32],
    #[serde(default)]
    barrier_roots_hash: [u8; 32],
    #[serde(default)]
    kem_tree_hash_after: [u8; 32],
    #[serde(default)]
    barrier_pk_entries: Vec<Vec<u8>>,
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
