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
use msphf_orchestrator::mhw::{DEFAULT_H_MAX, DEFAULT_T_WINDOW};
use msphf_orchestrator::process_anchor_or;
use msphf_orchestrator::{
    self, AcceptanceContext, AcceptanceOptions, BootstrapPolicy, DEFAULT_POLICY_VERSION,
    DEFAULT_PROOF_MODE, DEFAULT_VRF_ID, PivotParity, ReceiverCache, compute_proofs_commit_bytes,
    hdr,
};

/// Re-export commonly used client-side bundle types for convenience.
pub use cityg_client::{AnchorBundle, BindingMaterial};

const DEFAULT_CAT: [u8; 32] = [0x21; 32];

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
}

/// Merge ticket bundle provided to existing members resyncing after offline.
///
/// Similar to [`JoinTicketBundle`] but for members who already have a leaf_id
/// in the roster. Contains fresh pivot parities for forward secrecy.
///
/// # Use Case
///
/// When a member has been offline and needs to create a new epoch with
/// current group state without generating new cryptographic material.
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
}

impl CityGServer {
    pub fn register_group(
        &mut self,
        gid: &[u8; 32],
        kbroad_public: Vec<u8>,
    ) -> Result<(), CityGError> {
        let mut registry = self.ctx.kbroad_registry().cloned().unwrap_or_default();
        if registry.contains_key(gid.as_ref()) {
            return Err(CityGError::InvalidInput("kbroad key already registered"));
        }
        registry.insert(gid.to_vec(), kbroad_public);
        self.ctx.set_kbroad_registry(Some(registry));
        self.roster.groups.entry(gid.to_vec()).or_default();
        Ok(())
    }

    pub fn new(config: ServerConfig) -> Self {
        let h_max = config.h_max.unwrap_or(DEFAULT_H_MAX);
        let ttl = config.window_ttl.unwrap_or(DEFAULT_T_WINDOW);
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
            replaying: false,
        };
        #[allow(clippy::collapsible_if)]
        if let Some(path) = config.state_path {
            if let Err(err) = server.recover_from_state(&path) {
                eprintln!("cityg-server: state recovery failed: {err:?}");
            }
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
        let revoked_root = [0u8; 32];
        let revoked_since_root = [0u8; 32];
        let pox_r_commit = witness::demo_pox_commit();

        let (parent_root, leaf_id, join_delta_root, tswe_salt_hash, witness_cbor, srx_cbor) = {
            let state = self.roster.groups.entry(gid.to_vec()).or_default();
            let mut parent_leaves: Vec<[u8; 32]> = state
                .latest_snapshot()
                .map(|set| set.members().copied().collect())
                .unwrap_or_default();
            parent_leaves.sort();
            parent_leaves.dedup();

            let leaf_id = if let Some(explicit_leaf_id) = leaf_id_override {
                if parent_leaves
                    .iter()
                    .any(|member_leaf| *member_leaf == explicit_leaf_id)
                {
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

            (
                parent_root,
                leaf_id,
                join_delta_root,
                tswe_salt_hash,
                witness_cbor,
                srx_cbor,
            )
        };

        let kbroad_public = self
            .ctx
            .kbroad_registry()
            .and_then(|registry| registry.get(&gid.to_vec()).cloned())
            .ok_or(CityGError::InvalidInput("kbroad key missing"))?;

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
        })
    }

    pub fn build_merge_ticket(
        &mut self,
        gid: &[u8; 32],
        leaf_id: &[u8; 32],
    ) -> Result<MergeTicketBundle, CityGError> {
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

        let mut revoked_since = vec![*leaf_id];
        revoked_since.sort();

        let mut revoked_all = self.roster.revoked(gid);
        if !revoked_all.iter().any(|leaf| leaf == leaf_id) {
            revoked_all.push(*leaf_id);
        }
        revoked_all.sort();
        revoked_all.dedup();

        let join_leaves: Vec<[u8; 32]> = Vec::new();

        let join_delta_root = witness::join_delta_root(&join_leaves)?;
        let revoked_since_root = canonical_set_root(&revoked_since)?;
        let revoked_root = canonical_set_root(&revoked_all)?;

        let srx_owned = witness::build_merge_srx_inputs(
            &members,
            &join_leaves,
            parent_root,
            &revoked_since,
            &revoked_all,
            revoked_root,
        )?;
        let srx_cbor = srx_owned.to_cbor()?;

        let tswe_salt_hash = msphf_core::instance::tswe_salt_hash(gid, &parent_root)?;
        let pox_r_commit = witness::demo_pox_commit();

        let mut parities = self.ctx.pivot_parities_for(gid, &parent_root);
        if parities.is_empty() {
            return Err(CityGError::InvalidInput("no pivot parity available"));
        }

        parities.sort_by(|a, b| match a.accept_seq.cmp(&b.accept_seq) {
            core::cmp::Ordering::Equal => a.we_epoch_id.cmp(&b.we_epoch_id),
            other => other,
        });
        let pivot_we_epoch_id = parities[0].we_epoch_id;

        let kbroad_public = self
            .ctx
            .kbroad_registry()
            .and_then(|registry| registry.get(&gid.to_vec()).cloned())
            .ok_or(CityGError::InvalidInput("kbroad key missing"))?;

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
            .unwrap_or_else(|| "fs-policy-v1".to_string());
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
        })
    }

    pub fn accept_epoch(
        &mut self,
        bundle: &ClientEpochBundle,
    ) -> Result<ServerOutcome, CityGError> {
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

        let delta = bundle.membership_delta()?;
        let new_root = roster.apply_delta(bundle.gid(), &bundle.anchor.parent_root, &delta)?;

        // Keep at least one pivot parity available on the resulting root so members
        // can always fetch a merge ticket for subsequent membership changes.
        let parities_for_new = ctx.pivot_parities_for(bundle.gid(), &new_root);
        if parities_for_new.is_empty() {
            let mut mirrored = ctx
                .pivot_parities_for(bundle.gid(), &bundle.anchor.parent_root)
                .into_iter()
                .find(|parity| parity.we_epoch_id == acceptance.outcome.we_epoch_id)
                .unwrap_or_else(|| acceptance.pivot_parity.clone());
            if mirrored.parent_root != new_root {
                mirrored.parent_root = new_root;
            }
            ctx.insert_pivot_parity(mirrored, acceptance.outcome.accept_time);
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

    fn reset_state(&mut self) {
        self.ctx = AcceptanceContext::with_options(
            self.h_max,
            self.window_ttl,
            self.acceptance_options.clone(),
        );
        self.receiver = ReceiverCache::new(self.window_ttl);
        self.roster = GroupRoster::default();
    }

    fn recover_from_state(&mut self, path: &Path) -> Result<(), CityGError> {
        let entries = ServerJournal::load_entries(path)?;
        if entries.is_empty() {
            return Ok(());
        }
        self.reset_state();
        self.replaying = true;
        for entry in entries {
            let bundle = ClientEpochBundle::from_cbor(&entry)?;
            let (_, ctx, receiver, roster) = self.stage_bundle(&bundle)?;
            self.commit_staged(ctx, receiver, roster);
        }
        self.replaying = false;
        Ok(())
    }

    pub fn refresh_pivot(&mut self, bundle: &ClientEpochBundle) -> Result<(), CityGError> {
        let pivot_weid =
            header_bytes32(&bundle.header_map, hdr::HDR_ROLLUP_PIVOT_WEID, "pivot_weid")?;
        let parent_root = bundle.anchor.parent_root;
        let mut pivot = self
            .ctx
            .pivot_parities_for(bundle.gid(), &parent_root)
            .into_iter()
            .find(|parity| parity.we_epoch_id == pivot_weid)
            .ok_or(CityGError::InvalidInput("pivot parity missing for refresh"))?;

        let policy_version = header_string(
            &bundle.header_map,
            hdr::HDR_POLICY_VERSION,
            Some(DEFAULT_POLICY_VERSION),
        )?;
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

        pivot.policy_version = policy_version;
        pivot.proof_mode = proof_mode;
        pivot.vrf_id = vrf_id;
        pivot.vrf_proof = vrf_proof;
        pivot.vrf_public = vrf_public;
        pivot.mask_a = mask_a;
        pivot.mask_b = mask_b;
        pivot.fs_capss = fs_capss;
        pivot.proofs_commit = proofs_commit;
        pivot.srx_commit = srx_commit;
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
mod tests {
    use super::{CityGError, CityGServer, ServerConfig};
    use ciborium::value::Value;
    use cityg_client::ClientEpochBundle;
    use msphf_core::hash::h_l;
    use msphf_orchestrator::{AcceptanceOptions, BootstrapPolicy, mhw::HeadRecord};
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

        let err = match server.register_group(&gid, key) {
            Err(e) => e,
            Ok(_) => unreachable!("duplicate gid should fail"),
        };
        assert!(matches!(
            err,
            CityGError::InvalidInput("kbroad key already registered")
        ));
        Ok(())
    }

    #[test]
    fn build_join_ticket_requires_kbroad_and_advances_leaf_index() -> Result<(), CityGError> {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid = [0x42; 32];

        let err = match server.build_join_ticket(&gid) {
            Err(e) => e,
            Ok(_) => unreachable!("missing kbroad should fail"),
        };
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

        let err = match server.build_join_ticket_with_leaf(&gid, Some(requested_leaf)) {
            Err(e) => e,
            Ok(_) => unreachable!("duplicate requested leaf must fail"),
        };
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
        let err = match empty.build_merge_ticket(&gid, &leaf) {
            Err(e) => e,
            Ok(_) => unreachable!("empty server should reject merge ticket"),
        };
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
        server.register_group(&gid, vec![0x77; 16])?;

        let missing_leaf_err = match server.build_merge_ticket(&gid, &[0xFF; 32]) {
            Err(e) => e,
            Ok(_) => unreachable!("unknown leaf should fail before parity lookup"),
        };
        assert!(matches!(
            missing_leaf_err,
            CityGError::InvalidInput("leaf not present in roster")
        ));

        let no_parity_err = match server.build_merge_ticket(&gid, &leaf) {
            Err(e) => e,
            Ok(_) => unreachable!("missing parity should fail"),
        };
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

        assert!(
            super::header_bytes32_opt(&map, 1)
                .expect("optional bytes")
                .is_some()
        );
        assert!(
            super::header_bytes32_opt(&map, 4)
                .expect("null optional")
                .is_none()
        );
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
        assert_eq!(
            super::header_string(&map, 5, None).expect("text value"),
            "ok".to_string()
        );
        assert_eq!(
            super::header_string(&map, 6, None).expect("bytes utf8 value"),
            "fg".to_string()
        );
        assert_eq!(
            super::header_string(&map, 4, Some("fallback")).expect("null fallback"),
            "fallback".to_string()
        );
        assert!(matches!(
            super::header_string(&map, 4, None),
            Err(CityGError::InvalidInput("pivot field missing"))
        ));
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

        let mut invalid = bundle.clone();
        invalid
            .header_map
            .remove(&msphf_orchestrator::hdr::HDR_ROLLUP_PIVOT_WEID);
        let err = match server.refresh_pivot(&invalid) {
            Err(e) => e,
            Ok(_) => unreachable!("missing pivot_weid header should fail"),
        };
        assert!(matches!(err, CityGError::InvalidInput("pivot_weid")));
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

        let err = match server.accept_epoch(&bundle) {
            Err(e) => e,
            Ok(_) => unreachable!("expected error"),
        };
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
        let err = match server.accept_epoch(&bundle_bob) {
            Err(e) => e,
            Ok(_) => unreachable!("expected error"),
        };
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
        let err = match server.accept_epoch(&bundle) {
            Err(e) => e,
            Ok(_) => unreachable!("expected error"),
        };
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
        match primary.accept_epoch(&bundle) {
            Err(CityGError::Io(_)) => {
                *next_label = next_label.saturating_sub(1);
                Ok(())
            }
            Err(err) => Err(err),
            Ok(_) => Err(CityGError::Io(std::io::Error::other(
                "forced journal failure should abort acceptance",
            ))),
        }
    }

    fn build_join_bundle(
        parent_leaves: &[[u8; 32]],
        next_label: &mut u32,
    ) -> Result<(ClientEpochBundle, [u8; 32]), CityGError> {
        let label = format!("chaos-member-{}", next_label);
        *next_label = next_label.saturating_add(1);
        let leaf = cityg_client::demo::demo_member_leaf(&label);
        let bundle = cityg_client::demo::demo_bundle_with_parent_leaves(parent_leaves, leaf)?;
        Ok((bundle, leaf))
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
}

#[cfg(test)]
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
        let err = match roster.apply_delta(gid, &bad_root, &delta) {
            Err(e) => e,
            Ok(_) => unreachable!("expected error"),
        };
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
        let err = match roster.apply_delta(gid, &zero, &delta) {
            Err(e) => e,
            Ok(_) => unreachable!("expected error"),
        };
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
        let err = match roster.apply_delta(gid, &root1, &delta_dup) {
            Err(e) => e,
            Ok(_) => unreachable!("expected error"),
        };
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
        let err = match roster.apply_delta(gid, &root1, &conflicting) {
            Err(e) => e,
            Ok(_) => unreachable!("expected error"),
        };
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
}

#[derive(Clone, Default)]
struct GroupState {
    latest_root: Option<[u8; 32]>,
    snapshots: BTreeMap<[u8; 32], GroupMembership>,
    revoked: BTreeSet<[u8; 32]>,
    next_index: u32,
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

fn is_zero_root(root: &[u8; 32]) -> bool {
    root.iter().all(|byte| *byte == 0)
}

fn leaf_index(leaf: &[u8; 32]) -> u32 {
    let bytes: [u8; 4] = leaf[28..32].try_into().unwrap_or_default();
    u32::from_be_bytes(bytes)
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
#[allow(clippy::expect_used)]
pub(crate) fn fail_journal_after(countdown: usize) -> JournalFailureGuard {
    let lock = journal_failure_lock()
        .lock()
        .expect("Failed to acquire journal failure lock");
    JOURNAL_FAIL_ON_APPEND.store(countdown as isize, Ordering::SeqCst);
    JournalFailureGuard { _lock: lock }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) fn journal_serial_guard() -> MutexGuard<'static, ()> {
    journal_serial_lock().lock().unwrap()
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
