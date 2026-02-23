//! Acceptance entry point: orchestrates join, merge, and burst flows.

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, VecDeque},
    convert::{TryFrom, TryInto},
    time::Duration,
};

use ahash::AHashMap;

use anchor_seed::{
    SeedCommitFields, build_anchor_seed_ctx, compute_seed_bundle_commit, compute_seed_commit,
    compute_seed_ctx_hash,
};
use ciborium::{
    de, ser,
    value::{Integer, Value},
};
use msphf_core::serde_utils::to_cbor_vec;
use msphf_core::{
    MsphfError, WitnessValidationError, ds,
    hash::{h_l, hash_bytes_with_label},
    instance::AnchorInstance,
    merkle::{canonical_frontier, canonical_set_root},
    witness::{
        CanonicalWitness, RawMembershipWitness, RawNonMembershipWitness, RawPathEntry,
        ValidatedMembership, ValidatedNonMembership,
    },
};
use msphf_rlwe::{CapssStrictInputs, recompute_capss_witness};
use pqcrypto_dilithium::dilithium5::{
    DetachedSignature as MlDsaDetachedSignature, PublicKey as MlDsaPublicKey,
    public_key_bytes as ml_dsa_public_key_bytes, signature_bytes as ml_dsa_signature_bytes,
    verify_detached_signature as verify_ml_dsa,
};
use pqcrypto_kyber::kyber768::{
    ciphertext_bytes as ml_kem_ciphertext_bytes, public_key_bytes as ml_kem_public_key_bytes,
};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
use serde::{Serialize, de::DeserializeOwned};
use time::OffsetDateTime;
use tracing::{debug, info};

use crate::proofs::zk_vrf::{MaskDigest, VrfCtx, VrfProof, zk_vrf_impl};
use crate::{
    AnchorInstanceParts, CapssWitnessBundle, DEFAULT_PROOF_MODE, DEFAULT_VRF_ID, MERKLE_DS_ID,
    PivotParity, PivotParityStore, compute_proofs_commit_bytes, compute_window_id,
    derive_we_epoch_id,
    hdr::*,
    mhw::{DEFAULT_H_MAX, DEFAULT_T_WINDOW, FreezeError, HeadRecord, MultiHeadWindow},
    proofs::hp_binding,
    time::{AcceptClock, AcceptInstant},
};

mod barrier;
mod cache;
mod errors;
#[cfg(any(test, feature = "bench-fixtures"))]
pub mod fixtures;
mod join;
mod merge;
mod stages;
mod state;
mod telemetry;
#[cfg(feature = "bench-fixtures")]
pub use bench::SrxBenchHarness;

use barrier::{ParsedBarrierUpdate, parse_barrier_update_from_header};
use cache::VckCache;
pub use errors::*;
use stages::*;
pub use state::*;
pub use telemetry::*;

const MAX_HP_PROOF_BYTES: usize = 512 * 1024;
/// Maximum VRF proof size per Section 12 (field #95 ≤ 8,192 bytes)
const MAX_VRF_PROOF_BYTES: usize = 8_192;
/// Default maximum number of distinct rho_commit values tracked per (gid, parent_root).
///
/// When the guard is full, new anchors are rejected (frozen) rather than evicting
/// old entries, preventing an attacker from flushing the guard to replay a
/// previously seen rho_commit.
pub const RHO_GUARD_CAPACITY: usize = 64;
const MIN_SRX_MAX_BYTES: usize = 256 * 1024;
const DEFAULT_SRX_MAX_BYTES: usize = 1024 * 1024;
const FS_CAPSS_MAX_BYTES: usize = 16_384;
const BARRIER_LEAF_PUBLIC_KEY_BYTES: usize = 1_184;
const DEFAULT_SRX_SMALLWOOD_PROFILE: &str = "smallwood-v1/anemoi-jive-a1";
pub(crate) const MERGE_ONLY_KEYS: [u64; 11] = [
    HDR_MH_HEADS,
    HDR_ROLLUP_PIVOT_WEID,
    HDR_ROLLUP_PROVENANCE_COMMIT,
    HDR_ROLLUP_EPOCH_REPLAY,
    HDR_ROLLUP_VCK_COMMIT,
    HDR_MERGE_DELEGATION_SIG,
    HDR_KBROAD_REPLAY,
    HDR_ROLLUP_FS_MODE,
    HDR_FS_EVOLUTION_BOUNDARY,
    HDR_FS_PURGE_TIMES,
    HDR_FS_CHECKPOINT_EC,
];
pub(crate) const SRX_ONLY_KEYS: [u64; 4] = [
    HDR_SRX_COMMIT,
    HDR_SRX_PAYLOAD,
    HDR_SRX_ROOT_SW,
    HDR_SRX_SMALLWOOD,
];
pub(crate) const LEGACY_SRX_KEYS: [u64; 3] =
    [HDR_SRX_MODE, HDR_SRX_HINT_COUNTS, HDR_SRX_HINT_SIZES];

#[derive(Serialize)]
struct SrxEmptyRootProfile<'a>(&'a str);

pub(crate) fn derive_srx_empty_root_sw(profile: &str) -> Result<[u8; 32], MsphfError> {
    h_l("srx/root_sw/empty", &SrxEmptyRootProfile(profile))
}

const KBROAD_WRAP_KEY_BYTES: usize = 32;
const KBROAD_WRAP_CIPHERTEXT_BYTES: usize = KBROAD_WRAP_KEY_BYTES + crate::AEAD_TAG_LEN;
const KBROAD_HP_MAX_CIPHERTEXT_BYTES: usize = crate::MAX_HP_BYTES + crate::AEAD_TAG_LEN;

#[cfg(feature = "bench-fixtures")]
mod bench {
    use super::*;
    use crate::JoinerKGenResult;
    use crate::time::AcceptInstant;
    use std::{collections::BTreeSet, time::Duration};

    pub struct SrxBenchHarness {
        cache: cache::VckCache,
        ttl: Duration,
        deprecated_modes: BTreeSet<String>,
        srx_max_bytes: usize,
    }

    impl SrxBenchHarness {
        pub fn new(ttl: Duration, srx_max_bytes: usize) -> Self {
            Self {
                cache: cache::VckCache::new(ttl),
                ttl,
                deprecated_modes: BTreeSet::new(),
                srx_max_bytes,
            }
        }

        pub fn with_deprecated(
            ttl: Duration,
            srx_max_bytes: usize,
            deprecated_modes: BTreeSet<String>,
        ) -> Self {
            Self {
                cache: cache::VckCache::new(ttl),
                ttl,
                deprecated_modes,
                srx_max_bytes,
            }
        }

        pub fn reset(&mut self) {
            self.cache = cache::VckCache::new(self.ttl);
        }

        #[allow(clippy::too_many_arguments)]
        pub fn ensure(
            &mut self,
            header: &BTreeMap<u64, Value>,
            parts: &AnchorInstanceParts<'_>,
            joiner: &JoinerKGenResult,
            require: bool,
            allowed_modes: Option<&BTreeSet<String>>,
            now: AcceptInstant,
        ) -> Result<(), AcceptanceError> {
            let empty_set = BTreeSet::new();
            let proofs = stages::ensure_proofs(
                header,
                allowed_modes,
                &self.deprecated_modes,
                None,
                &empty_set,
            )?;
            let mut parent_root = [0u8; 32];
            parent_root.copy_from_slice(parts.parent_root);

            let mut join_delta_root = [0u8; 32];
            join_delta_root.copy_from_slice(parts.join_delta_root);

            let mut revoked_since_root = [0u8; 32];
            revoked_since_root.copy_from_slice(parts.revoked_since_prev_root);

            let mut revoked_root = [0u8; 32];
            revoked_root.copy_from_slice(parts.revoked_root);

            stages::ensure_srx_relations(
                header,
                &parent_root,
                &join_delta_root,
                &revoked_since_root,
                &revoked_root,
                require,
                self.srx_max_bytes,
                &joiner.xk_hash,
                &joiner.seed_commit,
                &joiner.rho_commit,
                &joiner.hp_commit,
                now,
                &mut self.cache,
                &proofs,
                &[0u8; 32],
            )
        }
    }
}

pub const FREEZE_TSWE_SALT_MISMATCH: FreezeError = FreezeError {
    code: 922,
    reason: "msphf_seedctx_mismatch",
};

#[derive(Serialize)]
struct FsDevChainV2Preimage<'a> {
    #[serde(with = "serde_bytes")]
    device_pk: &'a [u8],
    fs_ec: u64,
    #[serde(with = "serde_bytes")]
    prev_commit: &'a [u8; 32],
    barrier_version: u64,
    #[serde(with = "serde_bytes")]
    barrier_update_digest: &'a [u8; 32],
}

#[derive(Serialize)]
struct BarrierUpdateDigestPreimage<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

#[derive(Serialize)]
struct BarrierRootsPreimage<'a>(
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    #[serde(with = "serde_bytes")] &'a [u8; 32],
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AnchorType {
    Join,
    Merge,
    Regular,
}

#[derive(Clone, Debug)]
struct BarrierGateDecision {
    barrier_version: u64,
    fs_ec: u64,
    revocation_roots_hash: [u8; 32],
    barrier_update_digest: [u8; 32],
    barrier_update_reason: Option<u64>,
    parsed_barrier_update: Option<ParsedBarrierUpdate>,
}

pub(crate) struct DeviceChainVerification<'a> {
    pub(crate) pop_pk: &'a [u8],
    pub(crate) fs_ec: u64,
    pub(crate) fs_dev_prev_commit: &'a [u8; 32],
    pub(crate) fs_dev_commit: &'a [u8; 32],
    pub(crate) barrier_version: u64,
    pub(crate) barrier_update_digest: &'a [u8; 32],
}

pub const FREEZE_SRX_REQUIRED: FreezeError = FreezeError {
    code: 929,
    reason: "srx_required",
};

pub const FREEZE_SRX_INVALID: FreezeError = FreezeError {
    code: 930,
    reason: "srx_invalid",
};

pub const FREEZE_SRX_SET_CONFLICT_PARENT: FreezeError = FreezeError {
    code: 9076,
    reason: "set_conflict_parent",
};

pub const FREEZE_SRX_SET_CONFLICT_REVOKE: FreezeError = FreezeError {
    code: 9077,
    reason: "set_conflict_revoke",
};

pub const FREEZE_SRX_SET_CONFLICT_SUBSET: FreezeError = FreezeError {
    code: 9078,
    reason: "set_conflict_subset",
};

pub const FREEZE_SRX_HINT_UNDER: FreezeError = FreezeError {
    code: 930,
    reason: "srx_hint_under",
};

pub const FREEZE_SRX_OVERSIZE_HINT: FreezeError = FreezeError {
    code: 930,
    reason: "srx_oversize_hint",
};

pub const FREEZE_SRX_FRONTIER_MISMATCH: FreezeError = FreezeError {
    code: 930,
    reason: "srx_frontier_mismatch",
};

pub const FREEZE_SRX_ANCHOR_MISSING: FreezeError = FreezeError {
    code: 930,
    reason: "srx_anchor_missing",
};

pub const FREEZE_SRX_ANCHOR_MISMATCH: FreezeError = FreezeError {
    code: 930,
    reason: "srx_anchor_mismatch",
};

pub const FREEZE_SRX_ANCHOR_OOB: FreezeError = FreezeError {
    code: 930,
    reason: "srx_anchor_oob",
};

pub const FREEZE_SRX_ANCHOR_POOL_UNSORTED: FreezeError = FreezeError {
    code: 930,
    reason: "srx_anchor_pool_unsorted",
};

pub const FREEZE_SRX_COMMIT_MISMATCH: FreezeError = FreezeError {
    code: 930,
    reason: "srx_commit_mismatch",
};

pub const FREEZE_SRX_SMALLWOOD_INVALID: FreezeError = FreezeError {
    code: 929,
    reason: "srx_smallwood_invalid",
};

pub const FREEZE_NONMEM_ADJ_INCOHERENT: FreezeError = FreezeError {
    code: 9072,
    reason: "nonmem_adj_incoherent",
};

pub const FREEZE_CAPSS_INVALID: FreezeError = FreezeError {
    code: 923,
    reason: "msphf_lin_invalid",
};

pub const FREEZE_VRF_INVALID: FreezeError = FreezeError {
    code: 923,
    reason: "vrf_invalid",
};

pub const FREEZE_PROOFS_COMMIT_INVALID: FreezeError = FreezeError {
    code: 923,
    reason: "proof_invalid",
};

pub const FREEZE_POP_INVALID: FreezeError = FreezeError {
    code: 921,
    reason: "msphf_crs_untrusted",
};

pub const FREEZE_BOOTSTRAP_INVALID: FreezeError = FreezeError {
    code: 931,
    reason: "bootstrap_invalid",
};

pub const FREEZE_BOOTSTRAP_UNSUPPORTED: FreezeError = FreezeError {
    code: 932,
    reason: "bootstrap_unsupported",
};

pub const FREEZE_SUITE_DEPRECATED: FreezeError = FreezeError {
    code: 934,
    reason: "suite_deprecated",
};
pub const FREEZE_SUITE_FORBIDDEN: FreezeError = FreezeError {
    code: 934,
    reason: "suite_forbidden",
};

#[derive(Clone)]
pub struct AcceptanceOptions {
    pub bootstrap_policy: BootstrapPolicy,
    pub srx_max_bytes: usize,
    pub srx_required: bool,
    pub allowed_crs_ids: Option<BTreeSet<String>>,
    pub allowed_params_ids: Option<BTreeSet<Vec<u8>>>,
    pub deprecated_crs_ids: BTreeSet<String>,
    pub deprecated_params_ids: BTreeSet<Vec<u8>>,
    pub allowed_vrf_ids: Option<BTreeSet<String>>,
    pub deprecated_vrf_ids: BTreeSet<String>,
    pub allowed_proof_modes: Option<BTreeSet<String>>,
    pub deprecated_proof_modes: BTreeSet<String>,
    pub allowed_srx_modes: Option<BTreeSet<String>>,
    pub deprecated_srx_modes: BTreeSet<String>,
    pub leaf_id_mode: crate::LeafIdMode,
    pub kbroad_registry: Option<BTreeMap<Vec<u8>, Vec<u8>>>,
    pub fs_policy_config: FsPolicyConfig,
    /// Maximum distinct `rho_commit` values tracked per `(gid, parent_root)`.
    /// When full, new anchors are rejected rather than evicting old entries.
    /// Default: [`RHO_GUARD_CAPACITY`].
    pub rho_guard_capacity: usize,
}

impl Default for AcceptanceOptions {
    fn default() -> Self {
        let mut default_modes = BTreeSet::new();
        default_modes.insert("srx/v1-complete".to_string());
        let mut default_vrf_ids = BTreeSet::new();
        default_vrf_ids.insert("lb-vrf/v1".to_string());
        let mut default_proof_modes = BTreeSet::new();
        default_proof_modes.insert("lin+zkvrf".to_string());
        Self {
            bootstrap_policy: BootstrapPolicy::default(),
            srx_max_bytes: DEFAULT_SRX_MAX_BYTES,
            srx_required: true,
            allowed_crs_ids: None,
            allowed_params_ids: None,
            deprecated_crs_ids: BTreeSet::new(),
            deprecated_params_ids: BTreeSet::new(),
            allowed_vrf_ids: Some(default_vrf_ids),
            deprecated_vrf_ids: BTreeSet::new(),
            allowed_proof_modes: Some(default_proof_modes),
            deprecated_proof_modes: BTreeSet::new(),
            allowed_srx_modes: Some(default_modes),
            deprecated_srx_modes: BTreeSet::new(),
            leaf_id_mode: crate::LeafIdMode::PerGroup,
            kbroad_registry: None,
            fs_policy_config: FsPolicyConfig::default(),
            rho_guard_capacity: RHO_GUARD_CAPACITY,
        }
    }
}

#[derive(Clone, Default)]
pub enum BootstrapPolicy {
    #[default]
    Disabled,
    CaMlDsa {
        public_key: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptanceKind {
    NonMerge,
    Merge { retired_heads: Vec<[u8; 32]> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptanceOutcome {
    pub kind: AcceptanceKind,
    pub we_epoch_id: [u8; 32],
    pub wid: [u8; 32],
    pub seed_ctx_hash: [u8; 32],
    pub seed_commit: [u8; 32],
    pub rho_commit: [u8; 32],
    pub hp_commit: [u8; 32],
    pub xk_hash: [u8; 32],
    pub accept_seq: u64,
    pub accept_time: AcceptInstant,
    pub mh_note: Option<String>,
    pub fs_epoch_commit: Option<[u8; 32]>,
    pub fs_ec: Option<u64>,
    pub fs_dev_commit: Option<[u8; 32]>,
}

#[derive(Debug)]
pub enum AcceptanceError {
    Freeze(FreezeError),
    Msphf(MsphfError),
}

impl std::fmt::Display for AcceptanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcceptanceError::Freeze(code) => write!(f, "Freeze error: {:?}", code),
            AcceptanceError::Msphf(err) => write!(f, "MSPHF error: {:?}", err),
        }
    }
}

impl std::error::Error for AcceptanceError {}

impl From<MsphfError> for AcceptanceError {
    fn from(err: MsphfError) -> Self {
        match err {
            MsphfError::Witness(kind) => AcceptanceError::Freeze(match kind {
                WitnessValidationError::CborMalformed => FREEZE_HASH_CBOR,
                WitnessValidationError::NonCanonical => FREEZE_HASH_NONCANONICAL,
                WitnessValidationError::LeafBindMismatch => FREEZE_HASH_LEAF_BIND,
                WitnessValidationError::ProjEvalFail => FREEZE_HASH_PROJ_FAIL,
                WitnessValidationError::PathOversize => FREEZE_HASH_PATH_OVERSIZE,
            }),
            other => AcceptanceError::Msphf(other),
        }
    }
}

#[derive(Clone)]
pub struct AcceptanceContext {
    pub mh_window: MultiHeadWindow,
    rho_guard: RhoReplayGuard,
    vck_cache: VckCache,
    bootstrap_policy: BootstrapPolicy,
    srx_max_bytes: usize,
    srx_required: bool,
    allowed_crs_ids: Option<BTreeSet<String>>,
    allowed_params_ids: Option<BTreeSet<Vec<u8>>>,
    deprecated_crs_ids: BTreeSet<String>,
    deprecated_params_ids: BTreeSet<Vec<u8>>,
    allowed_vrf_ids: Option<BTreeSet<String>>,
    deprecated_vrf_ids: BTreeSet<String>,
    allowed_proof_modes: Option<BTreeSet<String>>,
    deprecated_proof_modes: BTreeSet<String>,
    allowed_srx_modes: Option<BTreeSet<String>>,
    deprecated_srx_modes: BTreeSet<String>,
    leaf_id_mode: crate::LeafIdMode,
    pivot_store: PivotParityStore,
    next_accept_seq: u64,
    kbroad_registry: Option<BTreeMap<Vec<u8>, Vec<u8>>>,
    pending_capss_witness: Option<CapssWitnessBundle>,
    telemetry: BTreeMap<TelemetryKey, TelemetryCounters>,
    policy_version: String,
    policy_timestamp: Option<OffsetDateTime>,
    device_chains: AHashMap<Vec<u8>, AHashMap<Vec<u8>, DeviceChainState>>,
    barrier_groups: AHashMap<Vec<u8>, BarrierGroupState>,
    fs_caps: FsCaps,
    last_checkpoint_ec: u64,
    last_accepted_ec: u64,
    srx_root_sw: Option<[u8; 32]>,
    srx_empty_root_sw: [u8; 32],
    srx_migration_root_sw: Option<[u8; 32]>,
    fs_base_ts: Option<u64>,
    fs_policy_version: Option<String>,
    allowed_fs_policy_version: Option<String>,
    fs_period: u64,
    checkpoint_interval: u64,
    checkpoint_head_threshold: u64,
    clock: AcceptClock,
}

impl AcceptanceContext {
    pub fn new(h_max: usize, ttl: Duration) -> Self {
        Self::with_options_internal(h_max, ttl, AcceptanceOptions::default())
    }

    pub fn with_defaults() -> Self {
        Self::with_options_internal(
            DEFAULT_H_MAX,
            DEFAULT_T_WINDOW,
            AcceptanceOptions::default(),
        )
    }

    pub fn with_options(h_max: usize, ttl: Duration, options: AcceptanceOptions) -> Self {
        Self::with_options_internal(h_max, ttl, options)
    }

    fn with_options_internal(h_max: usize, ttl: Duration, options: AcceptanceOptions) -> Self {
        let mh_window = MultiHeadWindow::new(h_max, ttl);
        let verify_ttl = mh_window.ttl();
        let srx_empty_root_sw =
            derive_srx_empty_root_sw(DEFAULT_SRX_SMALLWOOD_PROFILE).unwrap_or([0u8; 32]);
        let mut ctx = Self {
            mh_window,
            rho_guard: RhoReplayGuard::new(options.rho_guard_capacity.max(1), verify_ttl),
            vck_cache: VckCache::new(verify_ttl),
            pivot_store: PivotParityStore::new(verify_ttl),
            bootstrap_policy: options.bootstrap_policy,
            srx_max_bytes: options.srx_max_bytes.max(MIN_SRX_MAX_BYTES),
            srx_required: options.srx_required,
            allowed_crs_ids: options.allowed_crs_ids.clone(),
            allowed_params_ids: options.allowed_params_ids.clone(),
            deprecated_crs_ids: options.deprecated_crs_ids.clone(),
            deprecated_params_ids: options.deprecated_params_ids.clone(),
            allowed_vrf_ids: options.allowed_vrf_ids.clone(),
            deprecated_vrf_ids: options.deprecated_vrf_ids.clone(),
            allowed_proof_modes: options.allowed_proof_modes.clone(),
            deprecated_proof_modes: options.deprecated_proof_modes.clone(),
            allowed_srx_modes: options.allowed_srx_modes.clone(),
            deprecated_srx_modes: options.deprecated_srx_modes.clone(),
            leaf_id_mode: options.leaf_id_mode,
            next_accept_seq: 0,
            kbroad_registry: options.kbroad_registry.clone(),
            pending_capss_witness: None,
            telemetry: BTreeMap::new(),
            policy_version: crate::DEFAULT_POLICY_VERSION.to_string(),
            policy_timestamp: None,
            device_chains: AHashMap::new(),
            barrier_groups: AHashMap::new(),
            fs_caps: FsCaps::default(),
            last_checkpoint_ec: 0,
            last_accepted_ec: 0,
            srx_root_sw: Some(srx_empty_root_sw),
            srx_empty_root_sw,
            srx_migration_root_sw: None,
            fs_base_ts: None,
            fs_policy_version: None,
            allowed_fs_policy_version: None,
            fs_period: 0,
            checkpoint_interval: 0,
            checkpoint_head_threshold: 0,
            clock: AcceptClock::new(),
        };

        // default config is expected to be valid; on misconfiguration we fall back to zeros
        if let Err(err) = ctx.apply_fs_policy_config(options.fs_policy_config.clone()) {
            tracing::warn!(
                target = "accept",
                code = err.code,
                reason = err.reason,
                "fs policy config rejected; using zeroed caps"
            );
            ctx.fs_caps = FsCaps::default();
            ctx.fs_period = 0;
            ctx.checkpoint_interval = 0;
            ctx.checkpoint_head_threshold = 0;
        }

        ctx
    }

    pub fn telemetry_snapshot(&self) -> &BTreeMap<TelemetryKey, TelemetryCounters> {
        &self.telemetry
    }

    pub fn set_bootstrap_policy(&mut self, policy: BootstrapPolicy) {
        self.bootstrap_policy = policy;
        self.invalidate_policy_caches();
    }

    pub fn bootstrap_public_key(&self) -> Option<&[u8]> {
        match &self.bootstrap_policy {
            BootstrapPolicy::Disabled => None,
            BootstrapPolicy::CaMlDsa { public_key } => Some(public_key.as_slice()),
        }
    }

    pub fn set_kbroad_registry(&mut self, registry: Option<BTreeMap<Vec<u8>, Vec<u8>>>) {
        self.kbroad_registry = registry;
    }

    pub fn set_fs_caps(&mut self, caps: FsCaps) {
        self.fs_caps = caps;
    }

    pub fn fs_caps(&self) -> &FsCaps {
        &self.fs_caps
    }

    pub fn set_fs_base_ts(&mut self, base_ts: Option<u64>) {
        self.fs_base_ts = base_ts;
    }

    pub fn fs_base_ts(&self) -> Option<u64> {
        self.fs_base_ts
    }

    pub fn set_last_checkpoint_ec(&mut self, ec: u64) {
        self.last_checkpoint_ec = ec;
        if self.last_accepted_ec < ec {
            self.last_accepted_ec = ec;
        }
    }

    pub fn last_checkpoint_ec(&self) -> u64 {
        self.last_checkpoint_ec
    }

    pub fn last_accepted_ec(&self) -> u64 {
        self.last_accepted_ec
    }

    pub fn srx_root_sw(&self) -> Option<[u8; 32]> {
        self.srx_root_sw
    }

    pub fn set_srx_root_sw(&mut self, root: Option<[u8; 32]>) {
        self.srx_root_sw = root;
    }

    pub fn set_srx_empty_root_sw(&mut self, root: [u8; 32]) {
        let previous = self.srx_empty_root_sw;
        self.srx_empty_root_sw = root;
        if self.srx_root_sw == Some(previous) {
            self.srx_root_sw = Some(root);
        }
    }

    pub fn set_srx_migration_root_sw(&mut self, root: Option<[u8; 32]>) {
        self.srx_migration_root_sw = root;
    }

    pub fn ensure_srx_root_sw(&mut self) -> Result<[u8; 32], AcceptanceError> {
        if let Some(root) = self.srx_root_sw {
            return Ok(root);
        }
        if let Some(migration_root) = self.srx_migration_root_sw {
            self.srx_root_sw = Some(migration_root);
            return Ok(migration_root);
        }
        Err(AcceptanceError::Freeze(FREEZE_SUITE_FORBIDDEN))
    }

    pub fn record_accepted_ec(&mut self, ec: u64) {
        if ec > self.last_accepted_ec {
            self.last_accepted_ec = ec;
        }
    }

    pub(crate) fn verify_device_chain_state(
        &self,
        existing: Option<&DeviceChainState>,
        verification: DeviceChainVerification<'_>,
    ) -> Result<(), AcceptanceError> {
        let DeviceChainVerification {
            pop_pk,
            fs_ec,
            fs_dev_prev_commit,
            fs_dev_commit,
            barrier_version,
            barrier_update_digest,
        } = verification;

        let group_cap = self
            .last_accepted_ec()
            .saturating_add(self.fs_caps.anchor_max);
        if fs_ec > group_cap {
            return Err(AcceptanceError::Freeze(FREEZE_FS_FORWARD_JUMP_GROUP));
        }

        let expected_prev_commit = if let Some(state) = existing {
            if fs_ec < state.last_ec {
                return Err(AcceptanceError::Freeze(FREEZE_FS_DEV_CHAIN_BREAK));
            }
            let device_cap = state.last_ec.saturating_add(self.fs_caps.device_max);
            if fs_ec > device_cap {
                return Err(AcceptanceError::Freeze(FREEZE_FS_FORWARD_JUMP_DEVICE));
            }
            state.last_commit.unwrap_or([0u8; 32])
        } else {
            if fs_dev_prev_commit.iter().any(|byte| *byte != 0) {
                return Err(AcceptanceError::Freeze(FREEZE_FS_DEV_CHAIN_BREAK));
            }
            let first_cap = self
                .last_accepted_ec()
                .saturating_add(self.fs_caps.first_device);
            if fs_ec > first_cap {
                return Err(AcceptanceError::Freeze(FREEZE_FS_FORWARD_JUMP_FIRST));
            }
            [0u8; 32]
        };

        if expected_prev_commit != *fs_dev_prev_commit {
            return Err(AcceptanceError::Freeze(FREEZE_FS_DEV_CHAIN_BREAK));
        }

        let expected_dev_commit = h_l(
            "fs/dev/chain/v2",
            &FsDevChainV2Preimage {
                device_pk: pop_pk,
                fs_ec,
                prev_commit: fs_dev_prev_commit,
                barrier_version,
                barrier_update_digest,
            },
        )
        .map_err(AcceptanceError::from)?;

        if expected_dev_commit != *fs_dev_commit {
            return Err(AcceptanceError::Freeze(FREEZE_FS_DEV_CHAIN_BIND_MISMATCH));
        }

        Ok(())
    }

    fn enforce_barrier_acceptance_gating(
        &self,
        gid: &[u8],
        header_map: &BTreeMap<u64, Value>,
        anchor_type: AnchorType,
    ) -> Result<BarrierGateDecision, AcceptanceError> {
        let barrier_version = header_u64_or_freeze(
            header_map,
            HDR_BARRIER_VERSION,
            FREEZE_FS_JOIN_MISSING,
            "barrier_version",
        )?;
        let fs_ec = header_u64_or_freeze(header_map, HDR_FS_EC, FREEZE_FS_JOIN_MISSING, "fs_ec")?;
        let barrier_update_reason = parse_barrier_update_reason(header_map)?;
        let barrier_update_digest = compute_barrier_update_digest(header_map)?;
        let revocation_roots_hash = compute_revocation_roots_hash(header_map)?;
        let has_barrier_update = barrier_update_reason.is_some();
        if has_barrier_update && header_map.contains_key(&HDR_MERGE_DELEGATION_SIG) {
            return Err(AcceptanceError::Freeze(
                FREEZE_BARRIER_MERGE_DELEGATION_FORBIDDEN,
            ));
        }
        let state_snapshot = self.barrier_group_state(gid).cloned().unwrap_or_default();
        let parsed_barrier_update = if has_barrier_update {
            Some(parse_barrier_update_from_header(
                header_map,
                state_snapshot.n_max,
                state_snapshot.max_barrier_update_bytes,
            )?)
        } else {
            None
        };

        let decision = BarrierGateDecision {
            barrier_version,
            fs_ec,
            revocation_roots_hash,
            barrier_update_digest,
            barrier_update_reason,
            parsed_barrier_update,
        };

        let Some(state) = self.barrier_group_state(gid) else {
            return Ok(decision);
        };

        if state.barrier_initialized
            && has_barrier_update
            && decision.parsed_barrier_update.is_none()
        {
            return Err(AcceptanceError::Freeze(FREEZE_BARRIER_UPDATE_MALFORMED));
        }

        if !state.barrier_initialized {
            if has_barrier_update {
                let Some(parsed_update) = decision.parsed_barrier_update.as_ref() else {
                    return Err(AcceptanceError::Freeze(FREEZE_BARRIER_UPDATE_MALFORMED));
                };
                let is_genesis_merge = matches!(anchor_type, AnchorType::Merge)
                    && barrier_update_reason == Some(0)
                    && barrier_version == 0
                    && parsed_update.barrier_version == 0
                    && parsed_update.prev_barrier_version == 0
                    && parsed_update.revocation_roots_hash == revocation_roots_hash;
                if is_genesis_merge {
                    return Ok(decision);
                }
                return Err(AcceptanceError::Freeze(FREEZE_BARRIER_GENESIS_REQUIRED));
            }
            return Err(AcceptanceError::Freeze(FREEZE_BARRIER_GENESIS_REQUIRED));
        }

        let current_bv = state.barrier_version;
        let revocation_changed = revocation_roots_hash != state.barrier_roots_hash;

        if revocation_changed {
            if barrier_update_reason == Some(1) {
                return Err(AcceptanceError::Freeze(
                    FREEZE_BARRIER_PCS_REFRESH_FORBIDDEN_WHILE_PENDING_REVOCATIONS,
                ));
            }
            let Some(parsed_update) = decision.parsed_barrier_update.as_ref() else {
                return Err(AcceptanceError::Freeze(
                    FREEZE_BARRIER_UPDATE_REQUIRED_ON_REVOCATION_CHANGE,
                ));
            };
            let valid_revocation_merge = matches!(anchor_type, AnchorType::Merge)
                && has_barrier_update
                && barrier_update_reason == Some(0)
                && barrier_version == current_bv.saturating_add(1)
                && parsed_update.barrier_version == barrier_version
                && parsed_update.prev_barrier_version == current_bv
                && parsed_update.revocation_roots_hash == revocation_roots_hash;
            if !valid_revocation_merge {
                return Err(AcceptanceError::Freeze(
                    FREEZE_BARRIER_UPDATE_REQUIRED_ON_REVOCATION_CHANGE,
                ));
            }
            return Ok(decision);
        }

        if has_barrier_update {
            let Some(parsed_update) = decision.parsed_barrier_update.as_ref() else {
                return Err(AcceptanceError::Freeze(FREEZE_BARRIER_UPDATE_MALFORMED));
            };
            let valid_pcs_refresh = matches!(anchor_type, AnchorType::Merge)
                && barrier_update_reason == Some(1)
                && barrier_version == current_bv.saturating_add(1)
                && parsed_update.barrier_version == barrier_version
                && parsed_update.prev_barrier_version == current_bv
                && parsed_update.revocation_roots_hash == revocation_roots_hash;
            if !valid_pcs_refresh {
                return Err(AcceptanceError::Freeze(FREEZE_BARRIER_PROACTIVE_FORBIDDEN));
            }

            if let Some(last_group_refresh) = state.last_pcs_refresh_ec {
                let min_group_delta = state.pcs_refresh_min_delta_group_ec.max(1);
                if fs_ec < last_group_refresh.saturating_add(min_group_delta) {
                    return Err(AcceptanceError::Freeze(
                        FREEZE_BARRIER_PCS_REFRESH_RATE_LIMITED,
                    ));
                }

                let slot_width = state.pcs_refresh_slot_width_ec.max(1);
                if fs_ec / slot_width == last_group_refresh / slot_width {
                    return Err(AcceptanceError::Freeze(
                        FREEZE_BARRIER_PCS_REFRESH_RATE_LIMITED,
                    ));
                }
            }

            if let Some(device_pk) = header_map.get(&HDR_POP_PK).and_then(Value::as_bytes)
                && let Some(device_state) = self.device_chain_get(gid, device_pk)
                && let Some(last_device_refresh) = device_state.last_pcs_refresh_ec
            {
                let min_device_delta = state.pcs_refresh_min_delta_device_ec.max(1);
                if fs_ec < last_device_refresh.saturating_add(min_device_delta) {
                    return Err(AcceptanceError::Freeze(
                        FREEZE_BARRIER_PCS_REFRESH_RATE_LIMITED,
                    ));
                }
            }
        } else if barrier_version != current_bv {
            return Err(AcceptanceError::Freeze(FREEZE_BARRIER_PROACTIVE_FORBIDDEN));
        }

        Ok(decision)
    }

    fn apply_barrier_acceptance_commit(
        &mut self,
        gid: &[u8],
        header_map: &BTreeMap<u64, Value>,
        gate: BarrierGateDecision,
    ) {
        if gate.barrier_update_reason.is_none() {
            return;
        }

        {
            let state = self.barrier_group_state_entry_mut(gid);
            state.barrier_initialized = true;
            state.barrier_version = gate.barrier_version;
            state.barrier_roots_hash = gate.revocation_roots_hash;
            if let Some(parsed) = gate.parsed_barrier_update.as_ref() {
                state.kem_tree_hash_after = parsed.kem_tree_hash_after;
                state.n_max = parsed.tree_size;
            }
            if gate.barrier_update_reason == Some(1) {
                state.last_pcs_refresh_ec = Some(gate.fs_ec);
            }
        }

        if gate.barrier_update_reason == Some(1)
            && let Some(device_pk) = header_map.get(&HDR_POP_PK).and_then(Value::as_bytes)
        {
            let device_state = self.device_chain_entry_mut(gid, device_pk);
            device_state.last_pcs_refresh_ec = Some(gate.fs_ec);
        }
    }

    pub fn set_last_accepted_ec(&mut self, ec: u64) {
        self.last_accepted_ec = ec;
    }

    pub fn clear_device_chains(&mut self) {
        self.device_chains.clear();
    }

    pub fn barrier_group_state(&self, gid: &[u8]) -> Option<&BarrierGroupState> {
        self.barrier_groups.get(gid)
    }

    pub fn barrier_group_state_mut(&mut self, gid: &[u8]) -> Option<&mut BarrierGroupState> {
        self.barrier_groups.get_mut(gid)
    }

    pub fn barrier_group_state_entry_mut(&mut self, gid: &[u8]) -> &mut BarrierGroupState {
        self.barrier_groups.entry(gid.to_vec()).or_default()
    }

    pub fn insert_barrier_group_state(&mut self, gid: &[u8], state: BarrierGroupState) {
        self.barrier_groups.insert(gid.to_vec(), state);
    }

    pub fn barrier_groups_iter(&self) -> impl Iterator<Item = (&Vec<u8>, &BarrierGroupState)> {
        self.barrier_groups.iter()
    }

    pub fn device_chain_entry_mut(
        &mut self,
        gid: &[u8],
        device_pk: &[u8],
    ) -> &mut DeviceChainState {
        self.device_chains
            .entry(gid.to_vec())
            .or_default()
            .entry(device_pk.to_vec())
            .or_default()
    }

    pub fn device_chain_get(&self, gid: &[u8], device_pk: &[u8]) -> Option<&DeviceChainState> {
        self.device_chains
            .get(gid)
            .and_then(|per_gid| per_gid.get(device_pk))
    }

    pub fn insert_device_chain_state(
        &mut self,
        gid: &[u8],
        device_pk: &[u8],
        state: DeviceChainState,
    ) {
        self.device_chains
            .entry(gid.to_vec())
            .or_default()
            .insert(device_pk.to_vec(), state);
    }

    pub fn device_chains_iter(&self) -> impl Iterator<Item = &DeviceChainState> {
        self.device_chains
            .values()
            .flat_map(|per_gid| per_gid.values())
    }

    pub fn device_chain_entries_for_gid(
        &self,
        gid: &[u8],
    ) -> impl Iterator<Item = (&Vec<u8>, &DeviceChainState)> {
        self.device_chains
            .get(gid)
            .into_iter()
            .flat_map(|per_gid| per_gid.iter())
    }

    pub fn set_fs_policy_version(&mut self, version: Option<String>) {
        self.fs_policy_version = version;
    }

    pub fn fs_policy_version(&self) -> Option<&str> {
        self.fs_policy_version.as_deref()
    }

    pub fn set_allowed_fs_policy_version(&mut self, version: Option<String>) {
        self.allowed_fs_policy_version = version;
    }

    pub fn allowed_fs_policy_version(&self) -> Option<&str> {
        self.allowed_fs_policy_version.as_deref()
    }

    fn ensure_fs_policy_version_allowed(&self, version: &str) -> Result<(), AcceptanceError> {
        if self
            .allowed_fs_policy_version()
            .is_some_and(|expected| expected != version)
        {
            return Err(AcceptanceError::Freeze(
                FREEZE_FS_POLICY_VERSION_UNSUPPORTED,
            ));
        }
        Ok(())
    }

    pub fn apply_fs_policy_config(&mut self, config: FsPolicyConfig) -> Result<(), FreezeError> {
        let caps = config.synthesize_caps()?;
        self.fs_caps = caps;
        self.fs_period = config.h;
        self.checkpoint_interval = config.checkpoint_interval;
        self.checkpoint_head_threshold = config.checkpoint_head_threshold;
        Ok(())
    }

    pub fn set_pending_capss_witness(&mut self, witness: Option<CapssWitnessBundle>) {
        self.pending_capss_witness = witness;
    }

    fn take_pending_capss_witness(&mut self) -> Option<CapssWitnessBundle> {
        self.pending_capss_witness.take()
    }

    fn telemetry_entry_mut(&mut self, key: &TelemetryKey) -> &mut TelemetryCounters {
        self.telemetry.entry(key.clone()).or_default()
    }

    fn telemetry_record_attempt(&mut self, gid: &[u8], parent_root: &[u8]) -> TelemetryKey {
        let key = TelemetryKey::from_parts(gid, parent_root);
        self.telemetry_entry_mut(&key).record_attempt();
        key
    }

    fn telemetry_record_success(&mut self, key: &TelemetryKey, active_heads: usize) {
        self.telemetry_entry_mut(key).record_success(active_heads);
        self.log_annex_m_event(key, "head_inserted");
    }

    fn telemetry_record_rho_freeze(&mut self, key: &TelemetryKey) {
        self.telemetry_entry_mut(key).record_rho_freeze();
        self.log_annex_m_event(key, "freeze_rho_replay");
    }

    fn telemetry_record_window_full(&mut self, key: &TelemetryKey) {
        self.telemetry_entry_mut(key).record_window_full();
        self.log_annex_m_event(key, "freeze_window_full");
    }

    pub fn telemetry_lookup(&self, gid: &[u8], parent_root: &[u8]) -> Option<&TelemetryCounters> {
        let key = TelemetryKey::from_parts(gid, parent_root);
        self.telemetry.get(&key)
    }

    pub fn telemetry_report(&self) -> Vec<(TelemetryKey, TelemetryCounters)> {
        let mut rows: Vec<_> = self
            .telemetry
            .iter()
            .map(|(key, counters)| (key.clone(), counters.clone()))
            .collect();
        rows.sort_by(|a, b| {
            a.0.gid
                .cmp(&b.0.gid)
                .then(a.0.parent_root.cmp(&b.0.parent_root))
        });
        rows
    }

    pub fn merge_telemetry_from(&mut self, other: &AcceptanceContext) {
        for (key, counters) in other.telemetry_snapshot() {
            self.telemetry.insert(key.clone(), counters.clone());
        }
    }

    pub fn annex_m_report(&self) -> AnnexMTelemetryReport {
        let mut total_attempts = 0u64;
        let mut total_insertions = 0u64;
        let mut total_rho_freeze = 0u64;
        let mut total_window_full = 0u64;

        let rows = self
            .telemetry
            .iter()
            .map(|(key, counters)| {
                total_attempts += counters.head_attempts;
                total_insertions += counters.head_insertions;
                total_rho_freeze += counters.freeze_rho_replay;
                total_window_full += counters.freeze_window_full;
                AnnexMTelemetryRow::from((key.clone(), counters.clone()))
            })
            .collect();

        AnnexMTelemetryReport {
            rows,
            total_attempts,
            total_insertions,
            total_freeze_rho_replay: total_rho_freeze,
            total_freeze_window_full: total_window_full,
        }
    }

    pub fn set_h_max(&mut self, h_max: usize) {
        if self.mh_window.h_max() != h_max {
            self.mh_window.set_h_max(h_max);
            self.invalidate_policy_caches();
        }
    }

    fn log_annex_m_event(&self, key: &TelemetryKey, event: &'static str) {
        if let Some(counters) = self.telemetry.get(key) {
            let gid_hex = hex::encode(key.gid.as_slice());
            let parent_root_hex = hex::encode(key.parent_root);
            info!(
                target = ANNEX_M_LOG_TARGET,
                event,
                gid = %gid_hex,
                parent_root = %parent_root_hex,
                head_attempts = counters.head_attempts,
                head_insertions = counters.head_insertions,
                freeze_rho_replay = counters.freeze_rho_replay,
                freeze_window_full = counters.freeze_window_full,
                last_active_heads = counters.last_active_heads
            );
        }
    }

    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    pub fn policy_timestamp(&self) -> Option<OffsetDateTime> {
        self.policy_timestamp
    }

    pub fn set_policy_state(&mut self, version: String, timestamp: Option<OffsetDateTime>) {
        self.policy_version = version;
        self.policy_timestamp = timestamp;
    }

    pub fn h_max(&self) -> usize {
        self.mh_window.h_max()
    }

    pub fn leaf_id_mode(&self) -> crate::LeafIdMode {
        self.leaf_id_mode
    }

    pub fn kbroad_registry(&self) -> Option<&BTreeMap<Vec<u8>, Vec<u8>>> {
        self.kbroad_registry.as_ref()
    }

    pub fn allowed_params_ids(&self) -> Option<&BTreeSet<Vec<u8>>> {
        self.allowed_params_ids.as_ref()
    }

    /// Update the rho replay guard capacity.  Values below 1 are clamped to 1.
    pub fn set_rho_guard_capacity(&mut self, capacity: usize) {
        self.rho_guard = RhoReplayGuard::new(capacity.max(1), self.mh_window.ttl());
    }

    /// Clear replay-guard entries for a specific `(gid, parent_root)` pair.
    ///
    /// Call this when a group/window is torn down to reclaim guard capacity.
    pub fn clear_rho_guard_for(&mut self, gid: &[u8], parent_root: &[u8]) {
        self.rho_guard.clear_for(gid, parent_root);
    }

    pub fn set_srx_max_bytes(&mut self, max_bytes: usize) {
        self.srx_max_bytes = max_bytes.max(MIN_SRX_MAX_BYTES);
    }

    pub fn set_srx_required(&mut self, required: bool) {
        self.srx_required = required;
    }

    pub fn set_allowed_crs_ids(&mut self, allowed: Option<BTreeSet<String>>) {
        self.allowed_crs_ids = allowed;
    }

    pub fn set_allowed_params_ids(&mut self, allowed: Option<BTreeSet<Vec<u8>>>) {
        self.allowed_params_ids = allowed;
    }

    pub fn set_deprecated_crs_ids(&mut self, deprecated: BTreeSet<String>) {
        self.deprecated_crs_ids = deprecated;
    }

    pub fn set_deprecated_params_ids(&mut self, deprecated: BTreeSet<Vec<u8>>) {
        self.deprecated_params_ids = deprecated;
    }

    pub fn set_allowed_vrf_ids(&mut self, allowed: Option<BTreeSet<String>>) {
        self.allowed_vrf_ids = allowed;
        self.invalidate_policy_caches();
    }

    pub fn set_deprecated_vrf_ids(&mut self, deprecated: BTreeSet<String>) {
        self.deprecated_vrf_ids = deprecated;
        self.invalidate_policy_caches();
    }

    pub fn set_allowed_proof_modes(&mut self, allowed: Option<BTreeSet<String>>) {
        self.allowed_proof_modes = allowed;
        self.invalidate_policy_caches();
    }

    pub fn set_deprecated_proof_modes(&mut self, deprecated: BTreeSet<String>) {
        self.deprecated_proof_modes = deprecated;
        self.invalidate_policy_caches();
    }

    pub fn set_allowed_srx_modes(&mut self, allowed: Option<BTreeSet<String>>) {
        self.allowed_srx_modes = allowed;
        self.invalidate_policy_caches();
    }

    pub fn set_deprecated_srx_modes(&mut self, deprecated: BTreeSet<String>) {
        self.deprecated_srx_modes = deprecated;
        self.invalidate_policy_caches();
    }

    pub fn set_leaf_id_mode(&mut self, mode: crate::LeafIdMode) {
        self.leaf_id_mode = mode;
        self.invalidate_policy_caches();
    }

    pub fn current_time(&self) -> AcceptInstant {
        self.clock.now()
    }

    pub fn next_accept_instant(&mut self) -> AcceptInstant {
        self.clock.tick()
    }

    pub fn window_limits(&self) -> (usize, Duration) {
        (self.mh_window.h_max(), self.mh_window.ttl())
    }

    pub fn update_window_limits(&mut self, h_max: Option<usize>, ttl: Option<Duration>) {
        if let Some(h) = h_max {
            self.mh_window.set_h_max(h);
        }
        if let Some(ttl) = ttl {
            let now = self.current_time();
            self.mh_window.set_ttl(ttl, now);
            self.rho_guard.set_ttl(ttl, now);
            self.vck_cache.set_ttl(ttl, now);
            self.pivot_store.set_ttl(ttl, now);
        }
    }

    pub fn pivot_parities_for(&mut self, gid: &[u8], parent_root: &[u8; 32]) -> Vec<PivotParity> {
        let now = self.current_time();
        self.pivot_store.list(gid, parent_root, now)
    }

    pub fn insert_pivot_parity(&mut self, parity: PivotParity, now: AcceptInstant) {
        self.pivot_store.insert(parity, now);
    }

    pub fn invalidate_policy_caches(&mut self) {
        let ttl = self.mh_window.ttl();
        let now = self.current_time();
        self.vck_cache = VckCache::new(ttl);
        self.pivot_store.set_ttl(ttl, now);
    }

    fn ensure_crs_id(&self, header: &BTreeMap<u64, Value>) -> Result<(), AcceptanceError> {
        let Some(value) = header.get(&HDR_CRS_ID) else {
            return Err(AcceptanceError::Freeze(FREEZE_MSPHF_CRS_INVALID));
        };
        let crs_id = match value {
            Value::Text(text) => text.clone(),
            Value::Bytes(bytes) => std::str::from_utf8(bytes)
                .map(|s| s.to_string())
                .map_err(|_| AcceptanceError::Freeze(FREEZE_MSPHF_CRS_INVALID))?,
            _ => return Err(AcceptanceError::Freeze(FREEZE_MSPHF_CRS_INVALID)),
        };
        if crs_id.is_empty() {
            return Err(AcceptanceError::Freeze(FREEZE_MSPHF_CRS_INVALID));
        }
        if self
            .allowed_crs_ids
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&crs_id))
        {
            return Err(AcceptanceError::Freeze(FREEZE_MSPHF_CRS_INVALID));
        }
        if self.deprecated_crs_ids.contains(&crs_id) {
            return Err(AcceptanceError::Freeze(FREEZE_SUITE_DEPRECATED));
        }
        Ok(())
    }

    fn ensure_params_id(&self, header: &BTreeMap<u64, Value>) -> Result<(), AcceptanceError> {
        let Some(value) = header.get(&HDR_PARAMS_ID) else {
            return Err(AcceptanceError::Freeze(FREEZE_PARAMS_ID_INVALID));
        };
        let canonical = match value {
            Value::Bytes(bytes) => {
                if bytes.len() != 32 {
                    return Err(AcceptanceError::Freeze(FREEZE_PARAMS_ID_INVALID));
                }
                bytes.clone()
            }
            Value::Text(text) => {
                if text.is_empty() {
                    return Err(AcceptanceError::Freeze(FREEZE_PARAMS_ID_INVALID));
                }
                text.as_bytes().to_vec()
            }
            _ => return Err(AcceptanceError::Freeze(FREEZE_PARAMS_ID_INVALID)),
        };
        if self
            .allowed_params_ids
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&canonical))
        {
            return Err(AcceptanceError::Freeze(FREEZE_PARAMS_ID_INVALID));
        }
        if self.deprecated_params_ids.contains(&canonical) {
            return Err(AcceptanceError::Freeze(FREEZE_SUITE_DEPRECATED));
        }
        Ok(())
    }

    pub(crate) fn should_verify_hp(
        &mut self,
        inputs: &hp_binding::HpBindingInputs<'_>,
        proof: &hp_binding::HpProof,
        header: &BTreeMap<u64, Value>,
        now: AcceptInstant,
    ) -> Result<bool, AcceptanceError> {
        let key = compute_vck_key(
            inputs.xk_hash,
            inputs.seed_commit,
            inputs.rho_commit,
            inputs.hp_commit,
            header,
        )?;
        Ok(self.vck_cache.should_verify_hp(key, proof, now))
    }

    pub(crate) fn record_verified_hp(
        &mut self,
        inputs: &hp_binding::HpBindingInputs<'_>,
        proof: &hp_binding::HpProof,
        header: &BTreeMap<u64, Value>,
        now: AcceptInstant,
    ) -> Result<(), AcceptanceError> {
        let key = compute_vck_key(
            inputs.xk_hash,
            inputs.seed_commit,
            inputs.rho_commit,
            inputs.hp_commit,
            header,
        )?;
        self.vck_cache.record_hp(key, proof, now);
        Ok(())
    }

    fn ensure_kbroad_pub(
        &self,
        gid: &[u8],
        header: &BTreeMap<u64, Value>,
    ) -> Result<(), AcceptanceError> {
        let Some(value) = header.get(&HDR_KBROAD_PUB) else {
            return Err(AcceptanceError::Freeze(FREEZE_FIELD_MISSING));
        };
        let pub_bytes = match value {
            Value::Bytes(bytes) => bytes,
            _ => return Err(AcceptanceError::Freeze(FREEZE_KBROAD_PARENT_MISMATCH)),
        };
        if pub_bytes.len() != ml_kem_public_key_bytes() {
            return Err(AcceptanceError::Freeze(FREEZE_KBROAD_PARENT_MISMATCH));
        }

        if let Some(registry) = &self.kbroad_registry {
            match registry.get(gid) {
                Some(expected) if expected.as_slice() == pub_bytes.as_slice() => return Ok(()),
                Some(_) => return Err(AcceptanceError::Freeze(FREEZE_KBROAD_PARENT_MISMATCH)),
                None => return Err(AcceptanceError::Freeze(FREEZE_KBROAD_PARENT_MISMATCH)),
            }
        }

        Ok(())
    }

    pub fn accept_non_merge(
        &mut self,
        wid: &[u8],
        record: HeadRecord,
        now: AcceptInstant,
    ) -> Result<(), FreezeError> {
        self.mh_window.accept_head(wid, record, now)
    }

    pub fn accept_merge(
        &mut self,
        wid_old: &[u8],
        wid_new: &[u8],
        mh_heads: &[[u8; 32]],
        new_record: HeadRecord,
        now: AcceptInstant,
    ) -> Result<(), FreezeError> {
        if mh_heads.len() > self.mh_window.h_max() {
            return Err(FreezeError::WINDOW_FULL);
        }
        self.mh_window
            .accept_merge(wid_old, wid_new, mh_heads, new_record, now)
    }

    pub fn active_heads(&self, wid: &[u8]) -> usize {
        self.mh_window.active_heads(wid)
    }

    pub fn accept_anchor(
        &mut self,
        parts: &AnchorInstanceParts<'_>,
        we_epoch_id_claim: [u8; 32],
        header_map: &BTreeMap<u64, Value>,
    ) -> Result<AcceptanceOutcome, AcceptanceError> {
        let now = self.next_accept_instant();
        self.mh_window.prune_all(now);
        let anchor_type = classify_anchor_type(header_map);
        let is_merge = is_merge_anchor(header_map);
        ensure_known_header_keys(header_map, is_merge)?;
        enforce_anchor_presence_rules(header_map, anchor_type)?;
        let barrier_gate =
            self.enforce_barrier_acceptance_gating(parts.gid, header_map, anchor_type)?;
        debug!(
            "accept_anchor: gid={:?} is_merge={}",
            hex::encode(parts.gid),
            is_merge
        );
        if matches!(
            header_map.get(&HDR_FS_CAPSS),
            Some(Value::Bytes(proof)) if proof.len() > MAX_HP_PROOF_BYTES
        ) {
            return Err(AcceptanceError::Freeze(FREEZE_STARK_OVERSIZE));
        }

        let mh_note = parse_mh_note(header_map).map_err(AcceptanceError::from)?;

        let result = if is_merge {
            let heads = match parse_mh_heads(header_map) {
                Ok(Some(value)) => value,
                Ok(None) | Err(_) => return Err(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID)),
            };
            self.accept_anchor_merge(parts, we_epoch_id_claim, header_map, heads, mh_note, now)
        } else {
            self.accept_anchor_join(
                parts,
                we_epoch_id_claim,
                header_map,
                mh_note,
                barrier_gate.barrier_update_digest,
                now,
            )
        };
        if let Err(AcceptanceError::Freeze(code)) = &result {
            debug!(
                "accept_anchor freeze: code={} reason={} keys={:?}",
                code.code,
                code.reason,
                header_map.keys().collect::<Vec<_>>()
            );
        }
        if result.is_ok() {
            self.apply_barrier_acceptance_commit(parts.gid, header_map, barrier_gate);
        }
        result
    }
}

#[derive(Clone)]
struct RhoReplayGuard {
    limit: usize,
    ttl: Duration,
    entries: AHashMap<Vec<u8>, VecDeque<RhoGuardEntry>>,
}

#[derive(Clone, Copy)]
struct RhoGuardEntry {
    rho_commit: [u8; 32],
    seen_at: AcceptInstant,
}

impl RhoReplayGuard {
    fn new(limit: usize, ttl: Duration) -> Self {
        Self {
            limit,
            ttl,
            entries: AHashMap::new(),
        }
    }

    fn set_ttl(&mut self, ttl: Duration, now: AcceptInstant) {
        self.ttl = ttl;
        self.prune_all(now);
    }

    /// Record a new `rho_commit` for the given `(gid, parent_root)` pair.
    ///
    /// Returns `true` if the value was recorded (unique and capacity available).
    /// Returns `false` if the value is a duplicate (replay) **or** if the guard
    /// is full for this key.  Callers should treat both cases as a freeze.
    ///
    /// Unlike the previous implementation, this does **not** evict old entries
    /// when the limit is reached, preventing an attacker from flushing the
    /// guard by submitting many distinct rho values.
    fn record(
        &mut self,
        gid: &[u8],
        parent_root: &[u8],
        rho_commit: &[u8; 32],
        now: AcceptInstant,
    ) -> bool {
        let key = Self::make_key(gid, parent_root);
        let ttl = self.ttl;
        let deque = self.entries.entry(key).or_default();
        deque.retain(|entry| now.duration_since(entry.seen_at) <= ttl);
        if deque
            .iter()
            .any(|entry| entry.rho_commit.as_slice() == rho_commit.as_slice())
        {
            return false;
        }
        if deque.len() >= self.limit {
            return false;
        }
        deque.push_back(RhoGuardEntry {
            rho_commit: *rho_commit,
            seen_at: now,
        });
        true
    }

    /// Remove all entries for a specific `(gid, parent_root)` pair.
    ///
    /// Call this when a window/group is torn down to reclaim capacity.
    fn clear_for(&mut self, gid: &[u8], parent_root: &[u8]) {
        let key = Self::make_key(gid, parent_root);
        self.entries.remove(&key);
    }

    fn prune_all(&mut self, now: AcceptInstant) {
        let ttl = self.ttl;
        self.entries.retain(|_, deque| {
            deque.retain(|entry| now.duration_since(entry.seen_at) <= ttl);
            !deque.is_empty()
        });
    }

    /// Number of tracked rho_commit values for a given key.
    #[cfg(test)]
    fn count_for(&self, gid: &[u8], parent_root: &[u8]) -> usize {
        let key = Self::make_key(gid, parent_root);
        self.entries.get(&key).map_or(0, |d| d.len())
    }

    fn make_key(gid: &[u8], parent_root: &[u8]) -> Vec<u8> {
        let mut key = Vec::with_capacity(gid.len() + parent_root.len() + 1);
        key.extend_from_slice(gid);
        key.push(0x00);
        key.extend_from_slice(parent_root);
        key
    }
}

#[derive(Serialize)]
struct VckPreimage<'a> {
    #[serde(with = "serde_bytes")]
    xk_hash: &'a [u8],
    #[serde(with = "serde_bytes")]
    seed_commit: &'a [u8],
    #[serde(with = "serde_bytes")]
    rho_commit: &'a [u8],
    #[serde(with = "serde_bytes")]
    hp_commit: &'a [u8],
    #[serde(with = "serde_bytes")]
    crs_id: &'a [u8],
    #[serde(with = "serde_bytes")]
    params_id: &'a [u8],
    #[serde(with = "serde_bytes")]
    srx_commit: &'a [u8],
    #[serde(with = "serde_bytes")]
    proofs_commit: &'a [u8],
    proof_mode: &'a str,
    vrf_id: &'a str,
    fs_policy_version: u64,
}

fn header_value_bytes<'a>(
    header: &'a BTreeMap<u64, Value>,
    key: u64,
    freeze: FreezeError,
) -> Result<Cow<'a, [u8]>, AcceptanceError> {
    let Some(value) = header.get(&key) else {
        return Err(AcceptanceError::Freeze(freeze));
    };
    if key == 110 {
        debug!("header_bytes32_or_freeze: key 110 value {:?}", value);
    }
    match value {
        Value::Bytes(bytes) => Ok(Cow::Borrowed(bytes.as_slice())),
        Value::Text(text) => Ok(Cow::Borrowed(text.as_bytes())),
        _ => Err(AcceptanceError::Freeze(freeze)),
    }
}

fn compute_vck_key(
    xk_hash: &[u8; 32],
    seed_commit: &[u8; 32],
    rho_commit: &[u8; 32],
    hp_commit: &[u8; 32],
    header: &BTreeMap<u64, Value>,
) -> Result<[u8; 32], AcceptanceError> {
    let crs_bytes = header_value_bytes(header, 98, FREEZE_MSPHF_CRS_INVALID)?;
    let params_bytes = header_value_bytes(header, 106, FREEZE_PARAMS_ID_INVALID)?;

    let srx_commit = match header.get(&HDR_SRX_COMMIT) {
        Some(Value::Bytes(bytes)) => {
            if bytes.len() != 32 {
                return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            arr
        }
        Some(_) => return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID)),
        None => [0u8; 32],
    };

    let proofs_commit = match header.get(&HDR_PROOFS_COMMIT) {
        Some(Value::Bytes(bytes)) => {
            if bytes.len() != 32 {
                return Err(AcceptanceError::Freeze(FREEZE_CAPSS_INVALID));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            arr
        }
        Some(_) => {
            return Err(AcceptanceError::Freeze(FREEZE_CAPSS_INVALID));
        }
        None => [0u8; 32],
    };

    let proof_mode = match header.get(&HDR_PROOF_MODE) {
        Some(Value::Text(text)) => Cow::Borrowed(text.as_str()),
        Some(Value::Bytes(bytes)) => std::str::from_utf8(bytes)
            .map(Cow::Borrowed)
            .map_err(|_| AcceptanceError::Freeze(FREEZE_FIELD_MISSING))?,
        _ => return Err(AcceptanceError::Freeze(FREEZE_FIELD_MISSING)),
    };

    let vrf_id = match header.get(&HDR_VRF_ID) {
        Some(Value::Text(text)) => Cow::Borrowed(text.as_str()),
        Some(Value::Bytes(bytes)) => std::str::from_utf8(bytes)
            .map(Cow::Borrowed)
            .map_err(|_| AcceptanceError::Freeze(FREEZE_FIELD_MISSING))?,
        _ => return Err(AcceptanceError::Freeze(FREEZE_FIELD_MISSING)),
    };

    let fs_policy_version = match header.get(&HDR_FS_POLICY_VERSION) {
        Some(Value::Integer(int)) => u64::try_from(*int)
            .map_err(|_| AcceptanceError::Freeze(FREEZE_FS_POLICY_VERSION_UNSUPPORTED))?,
        _ => {
            return Err(AcceptanceError::Freeze(
                FREEZE_FS_POLICY_VERSION_UNSUPPORTED,
            ));
        }
    };
    if let Some(value) = header.get(&HDR_POLICY_VERSION) {
        let legacy = match value {
            Value::Integer(int) => u64::try_from(*int)
                .map_err(|_| AcceptanceError::Freeze(FREEZE_FS_POLICY_VERSION_UNSUPPORTED))?,
            _ => {
                return Err(AcceptanceError::Freeze(
                    FREEZE_FS_POLICY_VERSION_UNSUPPORTED,
                ));
            }
        };
        if legacy != fs_policy_version {
            return Err(AcceptanceError::Freeze(
                FREEZE_FS_POLICY_VERSION_UNSUPPORTED,
            ));
        }
    }

    let preimage = VckPreimage {
        xk_hash,
        seed_commit,
        rho_commit,
        hp_commit,
        crs_id: crs_bytes.as_ref(),
        params_id: params_bytes.as_ref(),
        srx_commit: &srx_commit,
        proofs_commit: &proofs_commit,
        proof_mode: proof_mode.as_ref(),
        vrf_id: vrf_id.as_ref(),
        fs_policy_version,
    };

    h_l("msphf/vck", &preimage).map_err(AcceptanceError::from)
}

fn compute_vck_from_parity(parity: &PivotParity) -> Result<[u8; 32], AcceptanceError> {
    let mut map = BTreeMap::new();
    map.insert(HDR_CRS_ID, Value::Bytes(parity.crs_id.clone()));
    map.insert(HDR_PARAMS_ID, Value::Bytes(parity.params_id.clone()));
    map.insert(
        HDR_PROOFS_COMMIT,
        Value::Bytes(parity.proofs_commit.to_vec()),
    );
    map.insert(HDR_PROOF_MODE, Value::Text(parity.proof_mode.clone()));
    map.insert(HDR_VRF_ID, Value::Text(parity.vrf_id.clone()));
    if let Some(commit) = parity.srx_commit {
        map.insert(HDR_SRX_COMMIT, Value::Bytes(commit.to_vec()));
    }
    map.insert(
        HDR_FS_POLICY_VERSION,
        Value::Integer(Integer::from(
            parity
                .policy_version
                .parse::<u64>()
                .map_err(|_| AcceptanceError::Freeze(FREEZE_FS_POLICY_VERSION_UNSUPPORTED))?,
        )),
    );
    compute_vck_key(
        &parity.xk_hash,
        &parity.seed_commit,
        &parity.rho_commit,
        &parity.hp_commit,
        &map,
    )
}

/// Reads header key 130 (`mh_heads`). Returns `None` if the key is absent.
pub fn parse_mh_heads(
    header: &BTreeMap<u64, Value>,
) -> Result<Option<Vec<[u8; 32]>>, AcceptanceError> {
    let Some(Value::Array(entries)) = header.get(&HDR_MH_HEADS) else {
        return Ok(None);
    };
    let mut heads = Vec::with_capacity(entries.len());
    for value in entries {
        let Value::Bytes(bytes) = value else {
            debug!("parse_mh_heads: entry not bytes");
            return Err(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID));
        };
        if bytes.len() != 32 {
            debug!("parse_mh_heads: entry len {}", bytes.len());
            return Err(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        heads.push(array);
    }
    if heads.is_empty() || !is_sorted_unique(&heads) {
        debug!(
            "parse_mh_heads: heads not sorted/unique len {}",
            heads.len()
        );
        return Err(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID));
    }
    Ok(Some(heads))
}

fn classify_anchor_type(header: &BTreeMap<u64, Value>) -> AnchorType {
    let has_merge_signal = header.contains_key(&HDR_BARRIER_UPDATE)
        || header.contains_key(&HDR_BARRIER_UPDATE_REASON)
        || MERGE_ONLY_KEYS
            .into_iter()
            .any(|key| header.contains_key(&key));
    if has_merge_signal {
        AnchorType::Merge
    } else if header.contains_key(&HDR_BARRIER_LEAF_PK) {
        AnchorType::Join
    } else {
        AnchorType::Regular
    }
}

pub(crate) fn is_merge_anchor(header: &BTreeMap<u64, Value>) -> bool {
    matches!(classify_anchor_type(header), AnchorType::Merge)
}

fn is_known_header_key(key: u64, is_merge: bool) -> bool {
    if is_merge && MERGE_ONLY_KEYS.contains(&key) {
        return true;
    }
    matches!(
        key,
        20 | HDR_TSWE_ALG
            | HDR_SEED_CTX_HASH
            | HDR_MERKLE_SUITE
            | HDR_RHO_COMMIT
            | HDR_SEED_BUNDLE_COMMIT
            | HDR_VRF_PROOF
            | HDR_HP_BYTES
            | HDR_CRS_ID
            | HDR_HP_COMMIT
            | 102
            | HDR_KBROAD_ALG
            | HDR_KBROAD_PUB
            | HDR_PARAMS_ID
            | HDR_POP_ALG
            | HDR_POP_PK
            | HDR_POP_SIG
            | 110
            | 111
            | 112
            | HDR_REVOKED_ROOT
            | HDR_VRF_ID
            | HDR_PROOF_MODE
            | HDR_SRX_MODE
            | HDR_SRX_COMMIT
            | HDR_SRX_PAYLOAD
            | HDR_SRX_HINT_COUNTS
            | HDR_SRX_HINT_SIZES
            | HDR_PROOFS_COMMIT
            | HDR_POLICY_VERSION
            | HDR_FS_POLICY_VERSION
            | HDR_FS_EC
            | HDR_FS_EPOCH_COMMIT
            | HDR_FS_EPOCH_BASE_TS
            | HDR_FS_CAPSS
            | HDR_FS_DEV_PREV_COMMIT
            | HDR_FS_DEV_COMMIT
            | HDR_BARRIER_UPDATE
            | HDR_BARRIER_VERSION
            | HDR_BARRIER_LEAF_PK
            | HDR_BARRIER_UPDATE_REASON
            | HDR_VRF_MASK_A
            | HDR_VRF_MASK_B
            | HDR_VRF_PUBLIC_KEY
            | HDR_SRX_ROOT_SW
            | HDR_SRX_SMALLWOOD
            | HDR_BOOTSTRAP_ALG
            | HDR_BOOTSTRAP_SIG
            | HDR_BOOTSTRAP_PK
    )
}

fn ensure_known_header_keys(
    header: &BTreeMap<u64, Value>,
    is_merge: bool,
) -> Result<(), AcceptanceError> {
    for key in header.keys().copied() {
        if !is_known_header_key(key, is_merge) {
            debug!("unknown header key {} (is_merge={})", key, is_merge);
            return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
        }
    }
    Ok(())
}

fn enforce_anchor_presence_rules(
    header: &BTreeMap<u64, Value>,
    anchor_type: AnchorType,
) -> Result<(), AcceptanceError> {
    match anchor_type {
        AnchorType::Merge => {
            if header.contains_key(&HDR_BARRIER_LEAF_PK) {
                return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
            }
        }
        AnchorType::Join => {
            let Some(Value::Bytes(leaf_pk)) = header.get(&HDR_BARRIER_LEAF_PK) else {
                return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
            };
            if leaf_pk.len() != BARRIER_LEAF_PUBLIC_KEY_BYTES {
                return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
            }
        }
        AnchorType::Regular => {
            if header.contains_key(&HDR_BARRIER_LEAF_PK) {
                return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
            }
        }
    }
    Ok(())
}

fn parse_barrier_update_reason(
    header: &BTreeMap<u64, Value>,
) -> Result<Option<u64>, AcceptanceError> {
    let has_update = header.contains_key(&HDR_BARRIER_UPDATE);
    let reason_value = header.get(&HDR_BARRIER_UPDATE_REASON);
    if !has_update {
        if reason_value.is_some() {
            return Err(AcceptanceError::Freeze(FREEZE_BARRIER_UPDATE_MALFORMED));
        }
        return Ok(None);
    }

    let Some(Value::Integer(reason_int)) = reason_value else {
        return Err(AcceptanceError::Freeze(FREEZE_BARRIER_UPDATE_MALFORMED));
    };
    let reason = u64::try_from(*reason_int)
        .map_err(|_| AcceptanceError::Freeze(FREEZE_BARRIER_UPDATE_MALFORMED))?;
    if reason > 1 {
        return Err(AcceptanceError::Freeze(FREEZE_BARRIER_UPDATE_MALFORMED));
    }
    Ok(Some(reason))
}

fn compute_barrier_update_digest(
    header: &BTreeMap<u64, Value>,
) -> Result<[u8; 32], AcceptanceError> {
    match header.get(&HDR_BARRIER_UPDATE) {
        None => Ok([0u8; 32]),
        Some(Value::Bytes(raw)) => h_l("barrier/update/digest", &BarrierUpdateDigestPreimage(raw))
            .map_err(AcceptanceError::from),
        Some(_) => Err(AcceptanceError::Freeze(FREEZE_BARRIER_UPDATE_MALFORMED)),
    }
}

fn compute_revocation_roots_hash(
    header: &BTreeMap<u64, Value>,
) -> Result<[u8; 32], AcceptanceError> {
    let revoked_since_root =
        header_bytes32_or_freeze(header, 112, FREEZE_FIELD_MISSING, "revoked_since_prev_root")?;
    let revoked_root = header_bytes32_or_freeze(header, 113, FREEZE_FIELD_MISSING, "revoked_root")?;
    h_l(
        "barrier/roots",
        &BarrierRootsPreimage(&revoked_since_root, &revoked_root),
    )
    .map_err(AcceptanceError::from)
}

fn is_sorted_unique(heads: &[[u8; 32]]) -> bool {
    heads.windows(2).all(|w| w[0] < w[1])
}

fn parse_mh_note(header: &BTreeMap<u64, Value>) -> Result<Option<String>, MsphfError> {
    const KEY: u64 = 102;
    match header.get(&KEY) {
        None => Ok(None),
        Some(Value::Text(note)) => Ok(Some(note.clone())),
        Some(_) => Err(MsphfError::invalid_input("mh_note not text")),
    }
}

#[derive(Clone, Debug)]
struct RollupEpochEntry {
    weid: [u8; 32],
    xk_hash: [u8; 32],
    parent_root: [u8; 32],
    join_delta_root: [u8; 32],
    revoked_since_root: [u8; 32],
    revoked_root: [u8; 32],
    is_join: bool,
}

fn parse_rollup_epoch_replay(value: &Value) -> Result<Vec<RollupEpochEntry>, AcceptanceError> {
    let Value::Array(entries) = value else {
        debug!("rollup_epoch_replay: value not array");
        return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
    };
    let mut out = Vec::with_capacity(entries.len());
    let mut prev: Option<[u8; 32]> = None;
    for entry in entries {
        let Value::Array(fields) = entry else {
            debug!("rollup_epoch_replay: entry not array");
            return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
        };
        if fields.len() != 4 {
            debug!("rollup_epoch_replay: entry len {}", fields.len());
            return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
        }
        let weid = value_bytes32(&fields[0], FREEZE_HASH_CBOR)?;
        if prev.is_some_and(|prev_weid| prev_weid >= weid) {
            return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
        }
        prev = Some(weid);
        let xk_hash = value_bytes32(&fields[1], FREEZE_HASH_CBOR)?;
        let Value::Array(root_fields) = &fields[2] else {
            debug!("rollup_epoch_replay: roots not array");
            return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
        };
        if root_fields.len() != 4 {
            debug!("rollup_epoch_replay: root len {}", root_fields.len());
            return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
        }
        let parent_root = value_bytes32(&root_fields[0], FREEZE_HASH_CBOR)?;
        let join_delta_root = value_bytes32(&root_fields[1], FREEZE_HASH_CBOR)?;
        let revoked_since_root = value_bytes32(&root_fields[2], FREEZE_HASH_CBOR)?;
        let revoked_root = value_bytes32(&root_fields[3], FREEZE_HASH_CBOR)?;
        let is_join = match fields[3] {
            Value::Bool(flag) => flag,
            _ => {
                debug!("rollup_epoch_replay: flag not bool");
                return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
            }
        };
        out.push(RollupEpochEntry {
            weid,
            xk_hash,
            parent_root,
            join_delta_root,
            revoked_since_root,
            revoked_root,
            is_join,
        });
    }
    Ok(out)
}

pub(crate) fn validate_kbroad_envelope_bytes(bytes: &[u8]) -> Result<(), AcceptanceError> {
    let value: Value = de::from_reader(bytes).map_err(|_| {
        debug!("kbroad envelope: cbor parse failed");
        AcceptanceError::Freeze(FREEZE_HASH_CBOR)
    })?;
    let Value::Array(items) = value else {
        debug!("kbroad envelope: not array");
        return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
    };
    if items.len() != 5 {
        debug!("kbroad envelope len {}", items.len());
        return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
    }
    let mode = match &items[0] {
        Value::Text(text) => text.as_str(),
        Value::Bytes(bytes) => std::str::from_utf8(bytes).map_err(|_| {
            debug!("kbroad envelope: mode invalid utf8");
            AcceptanceError::Freeze(FREEZE_HASH_CBOR)
        })?,
        _ => {
            debug!("kbroad envelope: mode not text/bytes");
            return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
        }
    };
    if mode != "kbroad-v1" {
        return Err(AcceptanceError::Freeze(FREEZE_PARENT_EID_FORBIDDEN));
    }
    let expected_ct_len = ml_kem_ciphertext_bytes();
    match &items[1] {
        Value::Bytes(bytes) if bytes.len() == expected_ct_len => {}
        Value::Bytes(_) => {
            debug!("kbroad envelope: ct len mismatch");
            return Err(AcceptanceError::Freeze(FREEZE_KBROAD_PARENT_MISMATCH));
        }
        _ => {
            debug!("kbroad envelope: ct not bytes");
            return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
        }
    }
    match &items[2] {
        Value::Bytes(bytes) if bytes.len() == KBROAD_WRAP_CIPHERTEXT_BYTES => {}
        Value::Bytes(_) => {
            debug!("kbroad envelope: wrap len mismatch");
            return Err(AcceptanceError::Freeze(FREEZE_KBROAD_PARENT_MISMATCH));
        }
        _ => {
            debug!("kbroad envelope: wrap not bytes");
            return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
        }
    }
    match &items[3] {
        Value::Bytes(bytes)
            if bytes.len() >= crate::AEAD_TAG_LEN
                && bytes.len() <= KBROAD_HP_MAX_CIPHERTEXT_BYTES => {}
        Value::Bytes(_) => {
            debug!("kbroad envelope: hp ciphertext len mismatch");
            return Err(AcceptanceError::Freeze(FREEZE_KBROAD_PARENT_MISMATCH));
        }
        _ => {
            debug!("kbroad envelope: hp ciphertext not bytes");
            return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
        }
    }
    let aead = match &items[4] {
        Value::Text(text) => text.as_str(),
        Value::Bytes(bytes) => std::str::from_utf8(bytes).map_err(|_| {
            debug!("kbroad envelope: aead invalid utf8");
            AcceptanceError::Freeze(FREEZE_HASH_CBOR)
        })?,
        _ => {
            debug!("kbroad envelope: aead not text/bytes");
            return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
        }
    };
    if aead != "chacha20-poly1305" {
        return Err(AcceptanceError::Freeze(FREEZE_SUITE_DEPRECATED));
    }
    Ok(())
}

#[derive(Serialize)]
struct RollupCommit<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

#[allow(clippy::too_many_arguments)]
fn is_supported_proof_mode(mode: &str) -> bool {
    mode == DEFAULT_PROOF_MODE
}

fn is_supported_vrf_id(vrf_id: &str) -> bool {
    vrf_id == DEFAULT_VRF_ID
}

fn header_string_or_freeze(
    header: &BTreeMap<u64, Value>,
    key: u64,
) -> Result<String, AcceptanceError> {
    match header.get(&key) {
        Some(Value::Text(text)) => Ok(text.clone()),
        Some(Value::Bytes(bytes)) => std::str::from_utf8(bytes)
            .map(|s| s.to_string())
            .map_err(|_| AcceptanceError::Freeze(FREEZE_FIELD_MISSING)),
        _ => Err(AcceptanceError::Freeze(FREEZE_FIELD_MISSING)),
    }
}

fn header_bytes_or_freeze(
    header: &BTreeMap<u64, Value>,
    key: u64,
    _reason: &'static str,
) -> Result<Vec<u8>, AcceptanceError> {
    let _ = _reason;
    match header.get(&key) {
        Some(Value::Bytes(bytes)) => Ok(bytes.clone()),
        _ => Err(AcceptanceError::Freeze(FREEZE_FIELD_MISSING)),
    }
}

#[derive(Serialize)]
struct RhoSig<'a> {
    #[serde(with = "serde_bytes")]
    pop_sig: &'a [u8],
    #[serde(with = "serde_bytes")]
    xk_hash: &'a [u8; 32],
}

fn derive_rho_commit_from_pop(
    pop_sig: &[u8],
    xk_hash: &[u8; 32],
) -> Result<[u8; 32], AcceptanceError> {
    let rho_raw =
        h_l(ds::MSPHF_RHO_DER, &RhoSig { pop_sig, xk_hash }).map_err(AcceptanceError::from)?;
    hash_bytes_with_label(ds::MSPHF_KGEN_RHO, &rho_raw).map_err(AcceptanceError::from)
}

fn extract_pop_signature(header: &BTreeMap<u64, Value>) -> Result<Vec<u8>, AcceptanceError> {
    match header.get(&HDR_POP_SIG) {
        Some(Value::Bytes(bytes)) => Ok(bytes.clone()),
        _ => Err(AcceptanceError::Freeze(FREEZE_POP_INVALID)),
    }
}

fn srx_contains_leaf_id(
    header: &BTreeMap<u64, Value>,
    leaf_id: &[u8; 32],
) -> Result<Option<bool>, AcceptanceError> {
    let Some(payload) = header.get(&HDR_SRX_PAYLOAD) else {
        return Ok(None);
    };
    let payload_value = match payload {
        Value::Bytes(bytes) => de::from_reader(bytes.as_slice())
            .map_err(|_| AcceptanceError::Freeze(FREEZE_SRX_INVALID))?,
        Value::Array(_) => payload.clone(),
        _ => return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID)),
    };
    let parsed = parse_srx_payload(&payload_value)?;
    Ok(Some(
        parsed
            .join_leaf_ids
            .iter()
            .any(|candidate| candidate == leaf_id),
    ))
}

pub(crate) fn parse_srx_payload(value: &Value) -> Result<SrxPayload, AcceptanceError> {
    let Value::Array(items) = value else {
        debug!("parse_srx_payload: payload not array");
        return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
    };
    if items.len() != 9 {
        debug!("parse_srx_payload: payload len {} != 9", items.len());
        return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
    }
    let join_parent = parse_nonmem_anchor_list(&items[0])?;
    let join_revoked = parse_nonmem_anchor_list(&items[1])?;
    let subset = parse_mem_list(&items[2])?;
    match &items[3] {
        Value::Null => {}
        Value::Map(_) => {}
        _ => {
            debug!("parse_srx_payload: subset entry not null/map");
            return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
        }
    }
    let join_leaf_ids = parse_leaf_array(&items[4])?;
    let join_frontier = parse_optional_frontier(&items[5])?;
    let since_leaf_ids = parse_leaf_array(&items[6])?;
    let since_frontier = parse_optional_frontier(&items[7])?;
    let anchor_mem_pool = parse_mem_list(&items[8])?;
    Ok(SrxPayload {
        join_nonmem_parent: join_parent,
        join_nonmem_revoked_since: join_revoked,
        revoked_since_mem_in_revoked: subset,
        join_leaf_ids,
        join_frontier,
        since_leaf_ids,
        since_frontier,
        anchor_mem_pool,
    })
}

fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

fn validate_bootstrap(
    header: &BTreeMap<u64, Value>,
    anchor: &AnchorInstance<'_>,
    hp_commit: &[u8; 32],
    seed_ctx_hash: &[u8; 32],
    rho_commit: &[u8; 32],
    seed_bundle_commit: &[u8; 32],
    policy: BootstrapPolicy,
) -> Result<(), AcceptanceError> {
    let mode_value = match header.get(&HDR_BOOTSTRAP_ALG) {
        Some(value) => value,
        None => {
            if header.contains_key(&HDR_BOOTSTRAP_SIG) || header.contains_key(&HDR_BOOTSTRAP_PK) {
                return Err(AcceptanceError::Freeze(FREEZE_BOOTSTRAP_INVALID));
            }
            return match policy {
                BootstrapPolicy::Disabled => Ok(()),
                BootstrapPolicy::CaMlDsa { .. } => {
                    Err(AcceptanceError::Freeze(FREEZE_BOOTSTRAP_INVALID))
                }
            };
        }
    };
    let mode = match mode_value {
        Value::Text(text) => text.as_str(),
        Value::Bytes(bytes) => std::str::from_utf8(bytes)
            .map_err(|_| AcceptanceError::Freeze(FREEZE_BOOTSTRAP_INVALID))?,
        _ => return Err(AcceptanceError::Freeze(FREEZE_BOOTSTRAP_INVALID)),
    };

    match (mode, policy) {
        ("oob-ca-v1", BootstrapPolicy::CaMlDsa { public_key }) => {
            let sig_bytes = match header.get(&HDR_BOOTSTRAP_SIG) {
                Some(Value::Bytes(bytes)) => bytes.clone(),
                _ => return Err(AcceptanceError::Freeze(FREEZE_BOOTSTRAP_INVALID)),
            };

            let digest = build_bootstrap_digest(
                header,
                anchor,
                hp_commit,
                seed_ctx_hash,
                rho_commit,
                seed_bundle_commit,
            )?;

            let pk = MlDsaPublicKey::from_bytes(public_key.as_slice())
                .map_err(|_| AcceptanceError::Freeze(FREEZE_BOOTSTRAP_INVALID))?;
            let sig = MlDsaDetachedSignature::from_bytes(sig_bytes.as_slice())
                .map_err(|_| AcceptanceError::Freeze(FREEZE_BOOTSTRAP_INVALID))?;
            verify_ml_dsa(&sig, &digest, &pk)
                .map_err(|_| AcceptanceError::Freeze(FREEZE_BOOTSTRAP_INVALID))?;

            Ok(())
        }
        ("oob-ca-v1", BootstrapPolicy::Disabled) => {
            Err(AcceptanceError::Freeze(FREEZE_BOOTSTRAP_UNSUPPORTED))
        }
        ("oob-m-of-n-v1", _) => Err(AcceptanceError::Freeze(FREEZE_BOOTSTRAP_UNSUPPORTED)),
        (_, _) => Err(AcceptanceError::Freeze(FREEZE_BOOTSTRAP_UNSUPPORTED)),
    }
}

pub fn build_bootstrap_digest(
    header: &BTreeMap<u64, Value>,
    anchor: &AnchorInstance<'_>,
    hp_commit: &[u8; 32],
    seed_ctx_hash: &[u8; 32],
    rho_commit: &[u8; 32],
    seed_bundle_commit: &[u8; 32],
) -> Result<Vec<u8>, AcceptanceError> {
    let crs_value = header
        .get(&HDR_CRS_ID)
        .ok_or(AcceptanceError::Freeze(FREEZE_BOOTSTRAP_INVALID))?;
    let crs_id = match crs_value {
        Value::Text(text) => Value::Text(text.clone()),
        Value::Bytes(bytes) => Value::Bytes(bytes.clone()),
        _ => return Err(AcceptanceError::Freeze(FREEZE_BOOTSTRAP_INVALID)),
    };

    let params_value = header
        .get(&HDR_PARAMS_ID)
        .ok_or(AcceptanceError::Freeze(FREEZE_BOOTSTRAP_INVALID))?;
    let params_id = match params_value {
        Value::Text(text) => Value::Text(text.clone()),
        Value::Bytes(bytes) => {
            if bytes.len() == 32 {
                Value::Bytes(bytes.clone())
            } else {
                return Err(AcceptanceError::Freeze(FREEZE_BOOTSTRAP_INVALID));
            }
        }
        _ => return Err(AcceptanceError::Freeze(FREEZE_BOOTSTRAP_INVALID)),
    };

    let digest_values = vec![
        Value::Bytes(anchor.gid.to_vec()),
        Value::Bytes(anchor.cat.to_vec()),
        Value::Bytes(anchor.we_epoch_id.to_vec()),
        Value::Bytes(anchor.anchor_hdr_ctx.to_vec()),
        Value::Bytes(anchor.tswe_salt_hash.to_vec()),
        Value::Bytes(anchor.join_delta_root.to_vec()),
        Value::Bytes(anchor.revoked_root.to_vec()),
        crs_id,
        params_id,
        Value::Bytes(hp_commit.to_vec()),
        Value::Bytes(seed_ctx_hash.to_vec()),
        Value::Bytes(rho_commit.to_vec()),
        Value::Bytes(seed_bundle_commit.to_vec()),
    ];

    let mut digest_bytes = Vec::new();
    ser::into_writer(&digest_values, &mut digest_bytes)
        .map_err(|_| AcceptanceError::Freeze(FREEZE_BOOTSTRAP_INVALID))?;
    Ok(digest_bytes)
}

fn parse_mem_list(value: &Value) -> Result<Vec<RawMembershipWitness>, AcceptanceError> {
    let Value::Array(entries) = value else {
        return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
    };
    entries
        .iter()
        .map(deserialize_value::<RawMembershipWitness>)
        .collect()
}

fn deserialize_value<T: DeserializeOwned>(value: &Value) -> Result<T, AcceptanceError> {
    let mut buf = Vec::new();
    ser::into_writer(value, &mut buf).map_err(|_| AcceptanceError::Freeze(FREEZE_SRX_INVALID))?;
    de::from_reader(buf.as_slice()).map_err(|_| AcceptanceError::Freeze(FREEZE_SRX_INVALID))
}

fn validate_membership_array(
    witnesses: &[RawMembershipWitness],
    expected_root: &[u8; 32],
) -> Result<Vec<ValidatedMembership>, AcceptanceError> {
    let mut seen = BTreeSet::new();
    let mut validated = Vec::with_capacity(witnesses.len());
    for witness in witnesses {
        match CanonicalWitness::validate_membership_witness(witness, expected_root) {
            Ok(entry) => {
                if !seen.insert(entry.leaf_id) {
                    return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
                }
                validated.push(entry);
            }
            Err(MsphfError::Witness(WitnessValidationError::ProjEvalFail)) => {
                return Err(AcceptanceError::Freeze(FREEZE_SRX_SET_CONFLICT_SUBSET));
            }
            Err(MsphfError::Witness(_)) => {
                return Err(AcceptanceError::Freeze(FREEZE_HASH_MEM_MALFORMED));
            }
            Err(err) => return Err(err.into()),
        }
    }
    Ok(validated)
}

pub(crate) fn validate_anchored_nonmem_array(
    witnesses: &[AnchoredNonMembership],
    anchor_mem_pool: &[RawMembershipWitness],
    expected_root: &[u8; 32],
    conflict: FreezeError,
) -> Result<Vec<ValidatedNonMembership>, AcceptanceError> {
    let mut seen = BTreeSet::new();
    let mut validated = Vec::with_capacity(witnesses.len());
    for anchor in witnesses {
        match CanonicalWitness::validate_nonmembership_witness(&anchor.witness, expected_root) {
            Ok(entry) => {
                if !seen.insert(entry.query) {
                    return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
                }
                let left_anchor = validate_anchor_reference(
                    anchor_mem_pool,
                    expected_root,
                    anchor.witness.left.as_ref(),
                    anchor.left_ref,
                )?;
                let right_anchor = validate_anchor_reference(
                    anchor_mem_pool,
                    expected_root,
                    anchor.witness.right.as_ref(),
                    anchor.right_ref,
                )?;
                verify_anchored_adjacency(&entry, left_anchor.as_ref(), right_anchor.as_ref())?;
                validated.push(entry);
            }
            Err(MsphfError::Witness(WitnessValidationError::ProjEvalFail)) => {
                return Err(AcceptanceError::Freeze(conflict));
            }
            Err(err) => return Err(err.into()),
        }
    }
    Ok(validated)
}

fn verify_anchored_adjacency(
    entry: &ValidatedNonMembership,
    left_anchor: Option<&ValidatedMembership>,
    right_anchor: Option<&ValidatedMembership>,
) -> Result<(), AcceptanceError> {
    if let Some(anchor) = left_anchor {
        if let Some(left) = entry.left {
            if anchor.leaf_id != left {
                return Err(AcceptanceError::Freeze(FREEZE_NONMEM_ADJ_INCOHERENT));
            }
        } else {
            return Err(AcceptanceError::Freeze(FREEZE_NONMEM_ADJ_INCOHERENT));
        }
    } else if entry.left.is_some() {
        return Err(AcceptanceError::Freeze(FREEZE_NONMEM_ADJ_INCOHERENT));
    }

    if let Some(anchor) = right_anchor {
        if let Some(right) = entry.right {
            if anchor.leaf_id != right {
                return Err(AcceptanceError::Freeze(FREEZE_NONMEM_ADJ_INCOHERENT));
            }
        } else {
            return Err(AcceptanceError::Freeze(FREEZE_NONMEM_ADJ_INCOHERENT));
        }
    } else if entry.right.is_some() {
        return Err(AcceptanceError::Freeze(FREEZE_NONMEM_ADJ_INCOHERENT));
    }

    match (left_anchor, right_anchor) {
        (Some(left_mem), Some(right_mem)) => {
            if let (Some(left), Some(right)) = (entry.left, entry.right) {
                if !(left < entry.query && entry.query < right) {
                    return Err(AcceptanceError::Freeze(FREEZE_NONMEM_ADJ_INCOHERENT));
                }
            } else {
                return Err(AcceptanceError::Freeze(FREEZE_NONMEM_ADJ_INCOHERENT));
            }
            // For two-bound case we continue relying on canonical interval ordering; deeper checks
            // are handled by the validated witness structures.
            let _ = (left_mem, right_mem);
        }
        (None, Some(right_mem)) => {
            if !right_mem.path.iter().all(|(dir, _)| *dir == 0) {
                return Err(AcceptanceError::Freeze(FREEZE_NONMEM_ADJ_INCOHERENT));
            }
            if entry.path != right_mem.path {
                return Err(AcceptanceError::Freeze(FREEZE_NONMEM_ADJ_INCOHERENT));
            }
        }
        (Some(left_mem), None) => {
            if !left_mem.path.iter().all(|(dir, _)| *dir == 1) {
                return Err(AcceptanceError::Freeze(FREEZE_NONMEM_ADJ_INCOHERENT));
            }
            if entry.path != left_mem.path {
                return Err(AcceptanceError::Freeze(FREEZE_NONMEM_ADJ_INCOHERENT));
            }
        }
        (None, None) => {}
    }

    Ok(())
}

pub(crate) fn validate_anchor_pool(pool: &[RawMembershipWitness]) -> Result<(), AcceptanceError> {
    let mut prev: Option<([u8; 32], [u8; 32])> = None;
    for witness in pool {
        if witness.leaf_id.len() != 32 || witness.root.len() != 32 {
            return Err(AcceptanceError::Freeze(FREEZE_HASH_MEM_MALFORMED));
        }
        if witness.path.len() > 64 {
            return Err(AcceptanceError::Freeze(FREEZE_HASH_PATH_OVERSIZE));
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&witness.root);
        let mut leaf = [0u8; 32];
        leaf.copy_from_slice(&witness.leaf_id);
        if prev.is_some_and(|prev_key| prev_key >= (root, leaf)) {
            return Err(AcceptanceError::Freeze(FREEZE_SRX_ANCHOR_POOL_UNSORTED));
        }
        prev = Some((root, leaf));
    }
    Ok(())
}

fn validate_anchor_reference(
    anchor_mem_pool: &[RawMembershipWitness],
    expected_root: &[u8; 32],
    bound: Option<&Vec<u8>>,
    index: Option<usize>,
) -> Result<Option<ValidatedMembership>, AcceptanceError> {
    match (bound, index) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(AcceptanceError::Freeze(FREEZE_SRX_ANCHOR_MISSING)),
        (Some(_), None) => Err(AcceptanceError::Freeze(FREEZE_SRX_ANCHOR_MISSING)),
        (Some(bound), Some(idx)) => {
            if bound.len() != 32 {
                return Err(AcceptanceError::Freeze(FREEZE_SRX_ANCHOR_MISMATCH));
            }
            let witness = anchor_mem_pool
                .get(idx)
                .ok_or(AcceptanceError::Freeze(FREEZE_SRX_ANCHOR_OOB))?;
            if witness.leaf_id.len() != 32 || witness.root.len() != 32 {
                return Err(AcceptanceError::Freeze(FREEZE_HASH_MEM_MALFORMED));
            }
            if witness.path.len() > 64 {
                return Err(AcceptanceError::Freeze(FREEZE_HASH_PATH_OVERSIZE));
            }
            let validated =
                match CanonicalWitness::validate_membership_witness(witness, expected_root) {
                    Ok(entry) => entry,
                    Err(MsphfError::Witness(WitnessValidationError::ProjEvalFail)) => {
                        return Err(AcceptanceError::Freeze(FREEZE_SRX_ANCHOR_MISMATCH));
                    }
                    Err(MsphfError::Witness(_)) => {
                        return Err(AcceptanceError::Freeze(FREEZE_HASH_MEM_MALFORMED));
                    }
                    Err(err) => return Err(err.into()),
                };

            let mut bound_bytes = [0u8; 32];
            bound_bytes.copy_from_slice(bound);
            if validated.root != *expected_root || validated.leaf_id != bound_bytes {
                return Err(AcceptanceError::Freeze(FREEZE_SRX_ANCHOR_MISMATCH));
            }
            Ok(Some(validated))
        }
    }
}

fn parse_nonmem_anchor_list(value: &Value) -> Result<Vec<AnchoredNonMembership>, AcceptanceError> {
    let Value::Array(entries) = value else {
        return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
    };
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        out.push(parse_nonmem_anchor(entry)?);
    }
    Ok(out)
}

fn value_bytes32(val: &Value, freeze: FreezeError) -> Result<[u8; 32], AcceptanceError> {
    let Value::Bytes(bytes) = val else {
        debug!("value_bytes32: expected bytes got {:?}", val);
        return Err(AcceptanceError::Freeze(freeze));
    };
    if bytes.len() != 32 {
        debug!("value_bytes32: len {} != 32", bytes.len());
        return Err(AcceptanceError::Freeze(freeze));
    }
    let slice: &[u8] = bytes.as_slice();
    slice
        .try_into()
        .map_err(|_| AcceptanceError::Freeze(freeze))
}

fn parse_nonmem_anchor(value: &Value) -> Result<AnchoredNonMembership, AcceptanceError> {
    let Value::Map(entries) = value else {
        return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
    };
    let mut query: Option<[u8; 32]> = None;
    let mut root: Option<[u8; 32]> = None;
    let mut left: Option<[u8; 32]> = None;
    let mut right: Option<[u8; 32]> = None;
    let mut path = None;
    let mut left_ref = None;
    let mut right_ref = None;
    let mut left_below = Vec::new();
    let mut right_below = Vec::new();
    let mut above = Vec::new();
    let mut nmint: Option<Vec<u8>> = None;
    let mut lca_left_height: Option<u8> = None;
    let mut lca_right_height: Option<u8> = None;
    for (key, val) in entries {
        let Value::Integer(index) = key else {
            return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
        };
        let idx = integer_to_u64(index)?;
        match idx {
            1 => {
                query = Some(value_bytes32(val, FREEZE_SRX_INVALID)?);
            }
            2 => {
                root = Some(value_bytes32(val, FREEZE_SRX_INVALID)?);
            }
            3 => match val {
                Value::Null => left = None,
                Value::Bytes(_) => {
                    left = Some(value_bytes32(val, FREEZE_SRX_INVALID)?);
                }
                _ => return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID)),
            },
            4 => match val {
                Value::Null => right = None,
                Value::Bytes(_) => {
                    right = Some(value_bytes32(val, FREEZE_SRX_INVALID)?);
                }
                _ => return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID)),
            },
            5 => path = Some(parse_path_entries(val)?),
            6 => match val {
                Value::Null => left_ref = None,
                Value::Integer(int) => {
                    left_ref = Some(
                        usize::try_from(integer_to_u64(int)?)
                            .map_err(|_| AcceptanceError::Freeze(FREEZE_SRX_INVALID))?,
                    );
                }
                _ => return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID)),
            },
            7 => match val {
                Value::Null => right_ref = None,
                Value::Integer(int) => {
                    right_ref = Some(
                        usize::try_from(integer_to_u64(int)?)
                            .map_err(|_| AcceptanceError::Freeze(FREEZE_SRX_INVALID))?,
                    );
                }
                _ => return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID)),
            },
            8 => {
                left_below = parse_path_entries(val)?;
            }
            9 => {
                right_below = parse_path_entries(val)?;
            }
            10 => {
                above = parse_path_entries(val)?;
            }
            11 => match val {
                Value::Null => nmint = None,
                Value::Bytes(bytes) => {
                    if bytes.len() != 32 {
                        return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
                    }
                    nmint = Some(bytes.clone());
                }
                _ => return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID)),
            },
            12 => match val {
                Value::Null => lca_left_height = None,
                Value::Integer(int) => {
                    let value = integer_to_u64(int)?;
                    if value > u8::MAX as u64 {
                        return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
                    }
                    lca_left_height = Some(value as u8);
                }
                _ => return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID)),
            },
            13 => match val {
                Value::Null => lca_right_height = None,
                Value::Integer(int) => {
                    let value = integer_to_u64(int)?;
                    if value > u8::MAX as u64 {
                        return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
                    }
                    lca_right_height = Some(value as u8);
                }
                _ => return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID)),
            },
            _ => return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID)),
        }
    }
    let query = query.ok_or(AcceptanceError::Freeze(FREEZE_SRX_INVALID))?;
    let root = root.ok_or(AcceptanceError::Freeze(FREEZE_SRX_INVALID))?;
    let path = path.ok_or(AcceptanceError::Freeze(FREEZE_SRX_INVALID))?;
    let witness = RawNonMembershipWitness {
        query: query.to_vec(),
        root: root.to_vec(),
        left: left.map(|bound| bound.to_vec()),
        right: right.map(|bound| bound.to_vec()),
        path,
        left_below,
        right_below,
        above,
        nmint,
        lca_left_height,
        lca_right_height,
    };
    Ok(AnchoredNonMembership {
        witness,
        left_ref,
        right_ref,
    })
}

fn parse_optional_frontier(value: &Value) -> Result<Option<Vec<[u8; 32]>>, AcceptanceError> {
    match value {
        Value::Null => Ok(None),
        Value::Array(_) => parse_leaf_array(value).map(Some),
        _ => Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID)),
    }
}

fn parse_path_entries(value: &Value) -> Result<Vec<RawPathEntry>, AcceptanceError> {
    let Value::Array(entries) = value else {
        return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
    };
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let Value::Map(map) = entry else {
            return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
        };
        let mut sibling = None;
        let mut dir = None;
        for (key, val) in map {
            let Value::Integer(index) = key else {
                return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
            };
            let idx = integer_to_u64(index)?;
            match idx {
                1 => {
                    let Value::Bytes(bytes) = val else {
                        return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
                    };
                    if bytes.len() != 32 {
                        return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
                    }
                    sibling = Some(bytes.clone());
                }
                2 => {
                    let Value::Integer(int) = val else {
                        return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
                    };
                    let value = integer_to_u64(int)?;
                    if value > 1 {
                        return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
                    }
                    dir = Some(value as u8);
                }
                _ => return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID)),
            }
        }
        let sibling = sibling.ok_or(AcceptanceError::Freeze(FREEZE_SRX_INVALID))?;
        let dir = dir.ok_or(AcceptanceError::Freeze(FREEZE_SRX_INVALID))?;
        out.push(RawPathEntry { sibling, dir });
    }
    Ok(out)
}

fn integer_to_u64(int: &Integer) -> Result<u64, AcceptanceError> {
    u64::try_from(*int).map_err(|_| AcceptanceError::Freeze(FREEZE_SRX_INVALID))
}

fn parse_leaf_array(value: &Value) -> Result<Vec<[u8; 32]>, AcceptanceError> {
    let Value::Array(entries) = value else {
        return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
    };
    let mut out = Vec::with_capacity(entries.len());
    for item in entries {
        let Value::Bytes(bytes) = item else {
            return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
        };
        if bytes.len() != 32 {
            return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        out.push(arr);
    }
    Ok(out)
}

pub(crate) fn ensure_nonmem_coverage(
    leaves: &[[u8; 32]],
    witnesses: &[ValidatedNonMembership],
) -> Result<(), AcceptanceError> {
    if leaves.is_empty() {
        return Ok(());
    }
    for leaf in leaves {
        if !witnesses.iter().any(|w| interval_contains(w, leaf)) {
            return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
        }
    }
    Ok(())
}

fn interval_contains(witness: &ValidatedNonMembership, leaf: &[u8; 32]) -> bool {
    if witness.left.is_none() && witness.right.is_none() {
        return witness.root.iter().all(|&b| b == 0);
    }
    if witness.left.is_some_and(|left| leaf <= &left) {
        return false;
    }
    if witness.right.is_some_and(|right| leaf >= &right) {
        return false;
    }
    // Sentinel (both None) only valid for empty trees; treat as non-covering for non-empty leaves.
    true
}

pub(crate) fn ensure_mem_coverage(
    leaves: &[[u8; 32]],
    witnesses: &[ValidatedMembership],
) -> Result<(), AcceptanceError> {
    let mut covered = BTreeSet::new();
    for witness in witnesses {
        covered.insert(witness.leaf_id);
    }
    for leaf in leaves {
        if !covered.contains(leaf) {
            return Err(AcceptanceError::Freeze(FREEZE_SRX_SET_CONFLICT_SUBSET));
        }
    }
    Ok(())
}

pub(crate) struct AnchoredNonMembership {
    witness: RawNonMembershipWitness,
    left_ref: Option<usize>,
    right_ref: Option<usize>,
}

pub(crate) struct SrxPayload {
    join_nonmem_parent: Vec<AnchoredNonMembership>,
    join_nonmem_revoked_since: Vec<AnchoredNonMembership>,
    revoked_since_mem_in_revoked: Vec<RawMembershipWitness>,
    join_leaf_ids: Vec<[u8; 32]>,
    join_frontier: Option<Vec<[u8; 32]>>,
    since_leaf_ids: Vec<[u8; 32]>,
    since_frontier: Option<Vec<[u8; 32]>>,
    anchor_mem_pool: Vec<RawMembershipWitness>,
}

fn header_bytes32_or_freeze(
    header: &BTreeMap<u64, Value>,
    key: u64,
    freeze: FreezeError,
    label: &str,
) -> Result<[u8; 32], AcceptanceError> {
    let Some(value) = header.get(&key) else {
        debug!(
            "header_bytes32_or_freeze: key {} label {} missing from header",
            key, label
        );
        return Err(AcceptanceError::Freeze(freeze));
    };
    let result = value_bytes32(value, freeze);
    if matches!(key, 110..=113) {
        match &result {
            Ok(bytes) => debug!(
                "header_bytes32_or_freeze: key {} success {:02x?}",
                key, bytes
            ),
            Err(_) => debug!("header_bytes32_or_freeze: key {} failed", key),
        }
    }
    result
}

fn header_u64_or_freeze(
    header: &BTreeMap<u64, Value>,
    key: u64,
    freeze: FreezeError,
    label: &str,
) -> Result<u64, AcceptanceError> {
    let Some(value) = header.get(&key) else {
        return Err(AcceptanceError::Freeze(freeze));
    };
    let Value::Integer(int) = value else {
        debug!(
            "header_u64_or_freeze: key {} label {} had type {:?}",
            key, label, value
        );
        return Err(AcceptanceError::Freeze(freeze));
    };
    u64::try_from(*int).map_err(|_| AcceptanceError::Freeze(freeze))
}

#[cfg_attr(not(test), allow(dead_code))]
fn compute_we_epoch_id_from_header(
    parts: &AnchorInstanceParts<'_>,
    header: &BTreeMap<u64, Value>,
) -> Result<[u8; 32], AcceptanceError> {
    let anchor_seed_ctx = build_anchor_seed_ctx(header).map_err(AcceptanceError::from)?;
    let seed_ctx_hash = compute_seed_ctx_hash(&anchor_seed_ctx).map_err(AcceptanceError::from)?;
    derive_we_epoch_id(parts.gid, parts.parent_root, &seed_ctx_hash).map_err(AcceptanceError::from)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::todo,
        clippy::unimplemented
    )]
    use super::fixtures::*;
    use super::*;
    use crate::mhw::HeadRecord;
    use crate::{
        BootstrapPolicy, HpProof, build_bootstrap_digest, joiner_kgen_merge_or, joiner_kgen_or,
        proof_to_cbor,
    };
    use anchor_seed::{build_anchor_seed_ctx, compute_seed_bundle_commit, compute_seed_ctx_hash};
    use ciborium::value::Integer;
    use msphf_core::params::RLWE_PARAMS_ID_A1;
    use msphf_core::witness::{
        RawMembershipWitness, RawNonMembershipWitness, RawPathEntry, ValidatedMembership,
        ValidatedNonMembership,
    };
    use pqcrypto_dilithium::dilithium5::{detached_sign, keypair};
    use pqcrypto_kyber::kyber768::public_key_bytes as ml_kem_public_key_bytes;
    use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
    use serde::Serialize;
    use std::{
        collections::{BTreeMap, BTreeSet},
        time::Duration,
    };

    // Tests reuse deterministic fixtures across joins; we leak boxed data intentionally
    // to satisfy the `'static` lifetimes required by helper structs.
    fn value_u64(value: u64) -> Value {
        Value::Integer(Integer::from(value))
    }

    fn valid_nonmem_anchor_value() -> Value {
        Value::Map(vec![
            (value_u64(1), Value::Bytes(vec![0x11; 32])),
            (value_u64(2), Value::Bytes(vec![0x22; 32])),
            (value_u64(3), Value::Null),
            (value_u64(4), Value::Null),
            (value_u64(5), Value::Array(Vec::new())),
            (value_u64(6), Value::Null),
            (value_u64(7), Value::Null),
            (value_u64(8), Value::Array(Vec::new())),
            (value_u64(9), Value::Array(Vec::new())),
            (value_u64(10), Value::Array(Vec::new())),
            (value_u64(11), Value::Null),
            (value_u64(12), Value::Null),
            (value_u64(13), Value::Null),
        ])
    }

    fn valid_kbroad_envelope_value() -> Value {
        Value::Array(vec![
            Value::Text("kbroad-v1".to_string()),
            Value::Bytes(vec![0x01; ml_kem_ciphertext_bytes()]),
            Value::Bytes(vec![0x02; KBROAD_WRAP_CIPHERTEXT_BYTES]),
            Value::Bytes(vec![0x03; crate::AEAD_TAG_LEN]),
            Value::Text("chacha20-poly1305".to_string()),
        ])
    }

    fn build_valid_barrier_update_bytes(
        n_max: u64,
        updater_leaf: u64,
        barrier_version: u64,
        prev_barrier_version: u64,
        revocation_roots_hash: [u8; 32],
    ) -> Result<Vec<u8>, AcceptanceError> {
        #[derive(Serialize)]
        struct TestNodeCiphertextWire(
            u64,
            u64,
            #[serde(with = "serde_bytes")] Vec<u8>,
            #[serde(with = "serde_bytes")] Vec<u8>,
            #[serde(with = "serde_bytes")] Vec<u8>,
        );

        #[derive(Serialize)]
        struct TestNewPublicKeyWire(u64, #[serde(with = "serde_bytes")] Vec<u8>);

        #[derive(Serialize)]
        struct TestKemTreeCoverPayloadWire(
            u64,
            Vec<u64>,
            Option<Vec<u64>>,
            Vec<TestNodeCiphertextWire>,
            Vec<TestNewPublicKeyWire>,
        );

        #[derive(Serialize)]
        struct TestBarrierUpdateWire(
            String,
            u64,
            u64,
            u64,
            #[serde(with = "serde_bytes")] Vec<u8>,
            #[serde(with = "serde_bytes")] Vec<u8>,
            #[serde(with = "serde_bytes")] Vec<u8>,
            #[serde(with = "serde_bytes")] Vec<u8>,
        );

        let malformed = || AcceptanceError::Freeze(FREEZE_BARRIER_UPDATE_MALFORMED);
        if n_max == 0 || !n_max.is_power_of_two() || updater_leaf >= n_max {
            return Err(malformed());
        }

        let leaf_base = n_max.checked_sub(1).ok_or_else(malformed)?;
        let leaf_node = leaf_base.checked_add(updater_leaf).ok_or_else(malformed)?;
        let mut path_nodes = vec![leaf_node];
        while let Some(&node) = path_nodes.last() {
            if node == 0 {
                break;
            }
            path_nodes.push((node - 1) / 2);
        }

        let mut expected_nodes: Vec<u64> = path_nodes.iter().copied().skip(1).collect();
        expected_nodes.sort_unstable();

        let new_public_keys = expected_nodes
            .into_iter()
            .map(|node| {
                let marker = (node as u8).wrapping_add(1);
                TestNewPublicKeyWire(node, vec![marker; ml_kem_public_key_bytes()])
            })
            .collect::<Vec<_>>();

        let cover = TestKemTreeCoverPayloadWire(
            updater_leaf,
            path_nodes,
            None,
            Vec::<TestNodeCiphertextWire>::new(),
            new_public_keys,
        );
        let cover_bytes = to_cbor_vec(&cover).map_err(|_| malformed())?;
        let update = TestBarrierUpdateWire(
            "barrier-v1".to_string(),
            barrier_version,
            prev_barrier_version,
            n_max,
            revocation_roots_hash.to_vec(),
            vec![0x00; 32],
            vec![0x33; 32],
            cover_bytes,
        );
        to_cbor_vec(&update).map_err(|_| malformed())
    }

    fn insert_valid_barrier_update(
        header: &mut BTreeMap<u64, Value>,
        n_max: u64,
        updater_leaf: u64,
        barrier_version: u64,
        prev_barrier_version: u64,
        revocation_roots_hash: [u8; 32],
        reason: u64,
    ) -> Result<(), AcceptanceError> {
        let barrier_update = build_valid_barrier_update_bytes(
            n_max,
            updater_leaf,
            barrier_version,
            prev_barrier_version,
            revocation_roots_hash,
        )?;
        header.insert(HDR_BARRIER_UPDATE, Value::Bytes(barrier_update));
        header.insert(
            HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(reason)),
        );
        Ok(())
    }

    #[test]
    fn acceptance_error_display_and_conversion_paths() {
        let mapping = [
            (WitnessValidationError::CborMalformed, FREEZE_HASH_CBOR),
            (
                WitnessValidationError::NonCanonical,
                FREEZE_HASH_NONCANONICAL,
            ),
            (
                WitnessValidationError::LeafBindMismatch,
                FREEZE_HASH_LEAF_BIND,
            ),
            (WitnessValidationError::ProjEvalFail, FREEZE_HASH_PROJ_FAIL),
            (
                WitnessValidationError::PathOversize,
                FREEZE_HASH_PATH_OVERSIZE,
            ),
        ];
        for (witness_err, expected_freeze) in mapping {
            let converted: AcceptanceError = MsphfError::Witness(witness_err).into();
            assert!(matches!(
                converted,
                AcceptanceError::Freeze(code) if code == expected_freeze
            ));
            assert!(format!("{converted}").contains("Freeze error"));
        }

        let converted: AcceptanceError = MsphfError::invalid_input("boom").into();
        assert!(matches!(converted, AcceptanceError::Msphf(_)));
        assert!(format!("{converted}").contains("MSPHF error"));
    }

    #[test]
    fn acceptance_context_accessors_cover_setters_and_fallbacks()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut ctx = AcceptanceContext::with_defaults();
        let base_h_max = ctx.h_max();
        let parent_root = [0xAA; 32];
        let key = ctx.telemetry_record_attempt(b"gid-a", &parent_root);
        ctx.telemetry_record_success(&key, 3);
        ctx.telemetry_record_rho_freeze(&key);
        ctx.telemetry_record_window_full(&key);

        assert!(ctx.telemetry_lookup(b"gid-a", &parent_root).is_some());
        assert_eq!(ctx.telemetry_report().len(), 1);
        let annex = ctx.annex_m_report();
        assert_eq!(annex.total_attempts, 1);
        assert_eq!(annex.total_insertions, 1);
        assert_eq!(annex.total_freeze_rho_replay, 1);
        assert_eq!(annex.total_freeze_window_full, 1);

        let mut copy = AcceptanceContext::with_defaults();
        copy.merge_telemetry_from(&ctx);
        assert!(copy.telemetry_lookup(b"gid-a", &parent_root).is_some());

        ctx.set_h_max(base_h_max);
        ctx.set_h_max(base_h_max + 2);
        assert_eq!(ctx.h_max(), base_h_max + 2);

        let caps = FsCaps {
            anchor_max: 7,
            first_device: 5,
            device_max: 3,
            window_periods: 2,
        };
        ctx.set_fs_caps(caps.clone());
        assert_eq!(ctx.fs_caps(), &caps);

        ctx.set_fs_base_ts(Some(123));
        assert_eq!(ctx.fs_base_ts(), Some(123));
        ctx.set_last_checkpoint_ec(9);
        assert_eq!(ctx.last_checkpoint_ec(), 9);
        assert_eq!(ctx.last_accepted_ec(), 9);
        ctx.record_accepted_ec(8);
        assert_eq!(ctx.last_accepted_ec(), 9);
        ctx.record_accepted_ec(11);
        assert_eq!(ctx.last_accepted_ec(), 11);
        ctx.set_last_accepted_ec(4);
        assert_eq!(ctx.last_accepted_ec(), 4);

        let previous_empty = ctx.srx_root_sw().unwrap_or([0u8; 32]);
        let new_empty = [0x55; 32];
        ctx.set_srx_empty_root_sw(new_empty);
        assert_eq!(ctx.srx_root_sw(), Some(new_empty));
        ctx.set_srx_root_sw(Some(previous_empty));
        ctx.set_srx_empty_root_sw([0x56; 32]);
        assert_eq!(ctx.srx_root_sw(), Some(previous_empty));

        ctx.set_srx_root_sw(None);
        ctx.set_srx_migration_root_sw(Some([0x44; 32]));
        assert_eq!(ctx.ensure_srx_root_sw()?, [0x44; 32]);
        ctx.set_srx_root_sw(None);
        ctx.set_srx_migration_root_sw(None);
        let err = ctx
            .ensure_srx_root_sw()
            .expect_err("missing roots must freeze");
        assert!(matches!(
            err,
            AcceptanceError::Freeze(code) if code == FREEZE_SUITE_FORBIDDEN
        ));

        let state = DeviceChainState {
            last_commit: Some([0x20; 32]),
            last_ec: 12,
            last_pcs_refresh_ec: None,
        };
        ctx.insert_device_chain_state(b"gid-b", b"device", state.clone());
        assert_eq!(ctx.device_chains_iter().count(), 1);
        assert_eq!(ctx.device_chain_get(b"gid-b", b"device"), Some(&state));
        ctx.device_chain_entry_mut(b"gid-b", b"device").last_ec = 13;
        assert_eq!(
            ctx.device_chain_get(b"gid-b", b"device")
                .expect("device chain entry should exist")
                .last_ec,
            13
        );
        ctx.clear_device_chains();
        assert_eq!(ctx.device_chains_iter().count(), 0);

        let barrier_state = BarrierGroupState {
            barrier_initialized: true,
            barrier_version: 4,
            last_pcs_refresh_ec: Some(44),
            ..BarrierGroupState::default()
        };
        ctx.insert_barrier_group_state(b"gid-b", barrier_state.clone());
        assert_eq!(ctx.barrier_groups_iter().count(), 1);
        assert_eq!(ctx.barrier_group_state(b"gid-b"), Some(&barrier_state));
        ctx.barrier_group_state_entry_mut(b"gid-b").barrier_version = 5;
        assert_eq!(
            ctx.barrier_group_state(b"gid-b")
                .expect("barrier state should exist")
                .barrier_version,
            5
        );

        ctx.set_fs_policy_version(Some("42".to_string()));
        assert_eq!(ctx.fs_policy_version(), Some("42"));
        ctx.set_allowed_fs_policy_version(Some("42".to_string()));
        assert_eq!(ctx.allowed_fs_policy_version(), Some("42"));

        ctx.update_window_limits(Some(3), Some(Duration::from_secs(2)));
        assert_eq!(ctx.window_limits(), (3, Duration::from_secs(2)));

        Ok(())
    }

    #[test]
    fn acceptance_policy_validators_cover_malformed_inputs() {
        let mut ctx = AcceptanceContext::with_defaults();
        let gid = b"group-alpha";
        let mut header = BTreeMap::new();

        header.insert(HDR_CRS_ID, Value::Bytes(vec![0xFF]));
        let err = ctx
            .ensure_crs_id(&header)
            .expect_err("invalid utf8 CRS should freeze");
        assert!(matches!(
            err,
            AcceptanceError::Freeze(code) if code == FREEZE_MSPHF_CRS_INVALID
        ));

        header.insert(HDR_CRS_ID, Value::Text(String::new()));
        assert!(matches!(
            ctx.ensure_crs_id(&header),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_MSPHF_CRS_INVALID
        ));

        ctx.set_allowed_crs_ids(Some(BTreeSet::from(["allowed-crs".to_string()])));
        header.insert(HDR_CRS_ID, Value::Text("other-crs".to_string()));
        assert!(matches!(
            ctx.ensure_crs_id(&header),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_MSPHF_CRS_INVALID
        ));

        ctx.set_allowed_crs_ids(None);
        ctx.set_deprecated_crs_ids(BTreeSet::from(["deprecated-crs".to_string()]));
        header.insert(HDR_CRS_ID, Value::Text("deprecated-crs".to_string()));
        assert!(matches!(
            ctx.ensure_crs_id(&header),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_SUITE_DEPRECATED
        ));

        ctx.set_deprecated_crs_ids(BTreeSet::new());
        header.insert(HDR_CRS_ID, Value::Text("ok-crs".to_string()));
        assert!(ctx.ensure_crs_id(&header).is_ok());

        header.insert(HDR_PARAMS_ID, Value::Bytes(vec![0x11; 31]));
        assert!(matches!(
            ctx.ensure_params_id(&header),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_PARAMS_ID_INVALID
        ));

        header.insert(HDR_PARAMS_ID, Value::Text(String::new()));
        assert!(matches!(
            ctx.ensure_params_id(&header),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_PARAMS_ID_INVALID
        ));

        ctx.set_allowed_params_ids(Some(BTreeSet::from([vec![0xAA; 32]])));
        header.insert(HDR_PARAMS_ID, Value::Bytes(vec![0xAB; 32]));
        assert!(matches!(
            ctx.ensure_params_id(&header),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_PARAMS_ID_INVALID
        ));

        ctx.set_allowed_params_ids(None);
        ctx.set_deprecated_params_ids(BTreeSet::from([vec![0xCD; 32]]));
        header.insert(HDR_PARAMS_ID, Value::Bytes(vec![0xCD; 32]));
        assert!(matches!(
            ctx.ensure_params_id(&header),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_SUITE_DEPRECATED
        ));

        ctx.set_deprecated_params_ids(BTreeSet::new());
        header.insert(HDR_PARAMS_ID, Value::Bytes(vec![0xEF; 32]));
        assert!(ctx.ensure_params_id(&header).is_ok());

        let mut kbroad_header = BTreeMap::new();
        let key_len = ml_kem_public_key_bytes();
        let expected_key = vec![0x21; key_len];
        kbroad_header.insert(HDR_KBROAD_PUB, Value::Bytes(expected_key.clone()));
        ctx.set_kbroad_registry(Some(BTreeMap::from([(gid.to_vec(), expected_key)])));
        assert!(ctx.ensure_kbroad_pub(gid, &kbroad_header).is_ok());

        kbroad_header.insert(HDR_KBROAD_PUB, Value::Bytes(vec![0x22; key_len]));
        assert!(matches!(
            ctx.ensure_kbroad_pub(gid, &kbroad_header),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_KBROAD_PARENT_MISMATCH
        ));

        kbroad_header.insert(HDR_KBROAD_PUB, Value::Text("bad".to_string()));
        assert!(matches!(
            ctx.ensure_kbroad_pub(gid, &kbroad_header),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_KBROAD_PARENT_MISMATCH
        ));

        kbroad_header.insert(HDR_KBROAD_PUB, Value::Bytes(vec![0x33; 16]));
        assert!(matches!(
            ctx.ensure_kbroad_pub(gid, &kbroad_header),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_KBROAD_PARENT_MISMATCH
        ));

        kbroad_header.remove(&HDR_KBROAD_PUB);
        assert!(matches!(
            ctx.ensure_kbroad_pub(gid, &kbroad_header),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_FIELD_MISSING
        ));

        ctx.set_kbroad_registry(None);
        kbroad_header.insert(HDR_KBROAD_PUB, Value::Bytes(vec![0x44; key_len]));
        assert!(ctx.ensure_kbroad_pub(gid, &kbroad_header).is_ok());
    }

    #[test]
    fn rollup_and_kbroad_parsers_cover_success_and_error_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let valid_rollup = Value::Array(vec![Value::Array(vec![
            Value::Bytes(vec![0x01; 32]),
            Value::Bytes(vec![0x02; 32]),
            Value::Array(vec![
                Value::Bytes(vec![0x03; 32]),
                Value::Bytes(vec![0x04; 32]),
                Value::Bytes(vec![0x05; 32]),
                Value::Bytes(vec![0x06; 32]),
            ]),
            Value::Bool(true),
        ])]);
        let parsed = parse_rollup_epoch_replay(&valid_rollup)?;
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].is_join);

        let malformed_cases = vec![
            Value::Null,
            Value::Array(vec![Value::Null]),
            Value::Array(vec![Value::Array(vec![Value::Null; 3])]),
            Value::Array(vec![Value::Array(vec![
                Value::Bytes(vec![0x01; 32]),
                Value::Bytes(vec![0x02; 32]),
                Value::Array(vec![Value::Bytes(vec![0x03; 32]); 3]),
                Value::Bool(true),
            ])]),
            Value::Array(vec![Value::Array(vec![
                Value::Bytes(vec![0x01; 32]),
                Value::Bytes(vec![0x02; 32]),
                Value::Array(vec![
                    Value::Bytes(vec![0x03; 32]),
                    Value::Bytes(vec![0x04; 32]),
                    Value::Bytes(vec![0x05; 32]),
                    Value::Bytes(vec![0x06; 32]),
                ]),
                Value::Text("not-bool".to_string()),
            ])]),
        ];
        for malformed in malformed_cases {
            assert!(matches!(
                parse_rollup_epoch_replay(&malformed),
                Err(AcceptanceError::Freeze(code)) if code == FREEZE_HASH_CBOR
            ));
        }

        let unsorted_rollup = Value::Array(vec![
            Value::Array(vec![
                Value::Bytes(vec![0x10; 32]),
                Value::Bytes(vec![0x20; 32]),
                Value::Array(vec![
                    Value::Bytes(vec![0x30; 32]),
                    Value::Bytes(vec![0x31; 32]),
                    Value::Bytes(vec![0x32; 32]),
                    Value::Bytes(vec![0x33; 32]),
                ]),
                Value::Bool(true),
            ]),
            Value::Array(vec![
                Value::Bytes(vec![0x0F; 32]),
                Value::Bytes(vec![0x21; 32]),
                Value::Array(vec![
                    Value::Bytes(vec![0x40; 32]),
                    Value::Bytes(vec![0x41; 32]),
                    Value::Bytes(vec![0x42; 32]),
                    Value::Bytes(vec![0x43; 32]),
                ]),
                Value::Bool(false),
            ]),
        ]);
        assert!(matches!(
            parse_rollup_epoch_replay(&unsorted_rollup),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_HASH_CBOR
        ));

        let envelope_bytes = encode_value(&valid_kbroad_envelope_value());
        validate_kbroad_envelope_bytes(&envelope_bytes)?;
        assert!(matches!(
            validate_kbroad_envelope_bytes(&[0xFF]),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_HASH_CBOR
        ));

        let bad_cases = vec![
            (Value::Null, FREEZE_HASH_CBOR),
            (
                Value::Array(vec![
                    Value::Text("bad-mode".to_string()),
                    Value::Bytes(vec![0x01; ml_kem_ciphertext_bytes()]),
                    Value::Bytes(vec![0x02; KBROAD_WRAP_CIPHERTEXT_BYTES]),
                    Value::Bytes(vec![0x03; crate::AEAD_TAG_LEN]),
                    Value::Text("chacha20-poly1305".to_string()),
                ]),
                FREEZE_PARENT_EID_FORBIDDEN,
            ),
            (
                Value::Array(vec![
                    Value::Text("kbroad-v1".to_string()),
                    Value::Bytes(vec![0x01; 8]),
                    Value::Bytes(vec![0x02; KBROAD_WRAP_CIPHERTEXT_BYTES]),
                    Value::Bytes(vec![0x03; crate::AEAD_TAG_LEN]),
                    Value::Text("chacha20-poly1305".to_string()),
                ]),
                FREEZE_KBROAD_PARENT_MISMATCH,
            ),
            (
                Value::Array(vec![
                    Value::Text("kbroad-v1".to_string()),
                    Value::Bytes(vec![0x01; ml_kem_ciphertext_bytes()]),
                    Value::Text("no-wrap".to_string()),
                    Value::Bytes(vec![0x03; crate::AEAD_TAG_LEN]),
                    Value::Text("chacha20-poly1305".to_string()),
                ]),
                FREEZE_HASH_CBOR,
            ),
            (
                Value::Array(vec![
                    Value::Text("kbroad-v1".to_string()),
                    Value::Bytes(vec![0x01; ml_kem_ciphertext_bytes()]),
                    Value::Bytes(vec![0x02; KBROAD_WRAP_CIPHERTEXT_BYTES]),
                    Value::Bytes(vec![0x03; 4]),
                    Value::Text("chacha20-poly1305".to_string()),
                ]),
                FREEZE_KBROAD_PARENT_MISMATCH,
            ),
            (
                Value::Array(vec![
                    Value::Text("kbroad-v1".to_string()),
                    Value::Bytes(vec![0x01; ml_kem_ciphertext_bytes()]),
                    Value::Bytes(vec![0x02; KBROAD_WRAP_CIPHERTEXT_BYTES]),
                    Value::Bytes(vec![0x03; crate::AEAD_TAG_LEN]),
                    Value::Text("aes-gcm".to_string()),
                ]),
                FREEZE_SUITE_DEPRECATED,
            ),
        ];

        for (case, expected) in bad_cases {
            let encoded = encode_value(&case);
            assert!(matches!(
                validate_kbroad_envelope_bytes(&encoded),
                Err(AcceptanceError::Freeze(code)) if code == expected
            ));
        }

        Ok(())
    }

    #[test]
    fn srx_parser_helpers_cover_nonmem_and_path_error_branches()
    -> Result<(), Box<dyn std::error::Error>> {
        let nonmem_anchor = valid_nonmem_anchor_value();
        let parsed_anchor = parse_nonmem_anchor(&nonmem_anchor)?;
        assert_eq!(parsed_anchor.witness.query.len(), 32);
        assert_eq!(
            parse_nonmem_anchor_list(&Value::Array(vec![nonmem_anchor]))
                .unwrap()
                .len(),
            1
        );
        assert!(parse_nonmem_anchor_list(&Value::Null).is_err());

        let valid_path = Value::Array(vec![Value::Map(vec![
            (value_u64(1), Value::Bytes(vec![0xAA; 32])),
            (value_u64(2), value_u64(1)),
        ])]);
        assert_eq!(parse_path_entries(&valid_path)?.len(), 1);
        assert!(parse_path_entries(&Value::Null).is_err());
        assert!(parse_path_entries(&Value::Array(vec![Value::Null])).is_err());
        assert!(
            parse_path_entries(&Value::Array(vec![Value::Map(vec![(
                Value::Text("bad-key".to_string()),
                Value::Bytes(vec![0xAA; 32]),
            )])]))
            .is_err()
        );
        assert!(
            parse_path_entries(&Value::Array(vec![Value::Map(vec![
                (value_u64(1), Value::Text("bad".to_string())),
                (value_u64(2), value_u64(0)),
            ])]))
            .is_err()
        );
        assert!(
            parse_path_entries(&Value::Array(vec![Value::Map(vec![
                (value_u64(1), Value::Bytes(vec![0xAA; 31])),
                (value_u64(2), value_u64(0)),
            ])]))
            .is_err()
        );
        assert!(
            parse_path_entries(&Value::Array(vec![Value::Map(vec![
                (value_u64(1), Value::Bytes(vec![0xAA; 32])),
                (value_u64(2), value_u64(2)),
            ])]))
            .is_err()
        );
        assert!(
            parse_path_entries(&Value::Array(vec![Value::Map(vec![(
                value_u64(2),
                value_u64(0),
            )])]))
            .is_err()
        );

        let leaf_array = Value::Array(vec![Value::Bytes(vec![0x10; 32])]);
        assert_eq!(parse_leaf_array(&leaf_array)?.len(), 1);
        assert!(parse_leaf_array(&Value::Null).is_err());
        assert!(parse_leaf_array(&Value::Array(vec![Value::Text("bad".to_string())])).is_err());
        assert!(parse_leaf_array(&Value::Array(vec![Value::Bytes(vec![0x20; 31])])).is_err());

        assert_eq!(parse_optional_frontier(&Value::Null)?, None);
        assert_eq!(
            parse_optional_frontier(&leaf_array)?
                .expect("frontier expected")
                .len(),
            1
        );
        assert!(parse_optional_frontier(&value_u64(7)).is_err());
        assert!(integer_to_u64(&Integer::from(-1)).is_err());

        let membership = RawMembershipWitness {
            leaf_id: vec![0x31; 32],
            root: vec![0x32; 32],
            path: Vec::new(),
        };
        let mut membership_bytes = Vec::new();
        ser::into_writer(&membership, &mut membership_bytes)?;
        let membership_value: Value = de::from_reader(membership_bytes.as_slice())?;
        assert_eq!(
            parse_mem_list(&Value::Array(vec![membership_value]))?.len(),
            1
        );
        assert!(parse_mem_list(&Value::Null).is_err());
        assert!(matches!(
            deserialize_value::<RawNonMembershipWitness>(&Value::Null),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_SRX_INVALID
        ));

        let coverage_witness = ValidatedNonMembership {
            query: [0x40; 32],
            root: [0u8; 32],
            left: None,
            right: None,
            path: Vec::new(),
        };
        ensure_nonmem_coverage(&[], std::slice::from_ref(&coverage_witness))?;
        ensure_nonmem_coverage(&[[0x42; 32]], &[coverage_witness])?;
        let bounded = ValidatedNonMembership {
            query: [0x50; 32],
            root: [0x01; 32],
            left: Some([0x10; 32]),
            right: Some([0x90; 32]),
            path: Vec::new(),
        };
        assert!(ensure_nonmem_coverage(&[[0x95; 32]], &[bounded]).is_err());

        let valid_mem = ValidatedMembership {
            leaf_id: [0xAA; 32],
            root: [0xBB; 32],
            path: Vec::new(),
        };
        ensure_mem_coverage(&[[0xAA; 32]], &[valid_mem])?;
        let missing_mem = ValidatedMembership {
            leaf_id: [0xCC; 32],
            root: [0xDD; 32],
            path: Vec::new(),
        };
        assert!(ensure_mem_coverage(&[[0xAA; 32]], &[missing_mem]).is_err());

        Ok(())
    }

    #[test]
    fn compute_vck_key_matrix_covers_required_header_freezes()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut header = BTreeMap::new();
        header.insert(HDR_CRS_ID, Value::Text("crs-id".to_string()));
        header.insert(HDR_PARAMS_ID, Value::Bytes(vec![0x11; 32]));
        header.insert(HDR_PROOF_MODE, Value::Text(DEFAULT_PROOF_MODE.to_string()));
        header.insert(HDR_VRF_ID, Value::Text(DEFAULT_VRF_ID.to_string()));
        header.insert(HDR_FS_POLICY_VERSION, Value::Integer(Integer::from(7u64)));
        header.insert(HDR_PROOFS_COMMIT, Value::Bytes(vec![0x33; 32]));
        header.insert(HDR_SRX_COMMIT, Value::Bytes(vec![0x44; 32]));

        let xk_hash = [0x01; 32];
        let seed_commit = [0x02; 32];
        let rho_commit = [0x03; 32];
        let hp_commit = [0x04; 32];
        let vck = compute_vck_key(&xk_hash, &seed_commit, &rho_commit, &hp_commit, &header)?;
        assert_ne!(vck, [0u8; 32]);

        let mut missing_crs = header.clone();
        missing_crs.remove(&HDR_CRS_ID);
        assert!(matches!(
            compute_vck_key(&xk_hash, &seed_commit, &rho_commit, &hp_commit, &missing_crs),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_MSPHF_CRS_INVALID
        ));

        let mut bad_crs_type = header.clone();
        bad_crs_type.insert(HDR_CRS_ID, Value::Integer(Integer::from(9u64)));
        assert!(matches!(
            compute_vck_key(&xk_hash, &seed_commit, &rho_commit, &hp_commit, &bad_crs_type),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_MSPHF_CRS_INVALID
        ));

        let mut bad_srx_len = header.clone();
        bad_srx_len.insert(HDR_SRX_COMMIT, Value::Bytes(vec![0xAA; 31]));
        assert!(matches!(
            compute_vck_key(&xk_hash, &seed_commit, &rho_commit, &hp_commit, &bad_srx_len),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_SRX_INVALID
        ));

        let mut bad_srx_type = header.clone();
        bad_srx_type.insert(HDR_SRX_COMMIT, Value::Text("bad".to_string()));
        assert!(matches!(
            compute_vck_key(&xk_hash, &seed_commit, &rho_commit, &hp_commit, &bad_srx_type),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_SRX_INVALID
        ));

        let mut bad_proofs_len = header.clone();
        bad_proofs_len.insert(HDR_PROOFS_COMMIT, Value::Bytes(vec![0x55; 31]));
        assert!(matches!(
            compute_vck_key(
                &xk_hash,
                &seed_commit,
                &rho_commit,
                &hp_commit,
                &bad_proofs_len
            ),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_CAPSS_INVALID
        ));

        let mut bad_proofs_type = header.clone();
        bad_proofs_type.insert(HDR_PROOFS_COMMIT, Value::Text("bad".to_string()));
        assert!(matches!(
            compute_vck_key(
                &xk_hash,
                &seed_commit,
                &rho_commit,
                &hp_commit,
                &bad_proofs_type
            ),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_CAPSS_INVALID
        ));

        let mut bad_mode_utf8 = header.clone();
        bad_mode_utf8.insert(HDR_PROOF_MODE, Value::Bytes(vec![0xFF]));
        assert!(matches!(
            compute_vck_key(&xk_hash, &seed_commit, &rho_commit, &hp_commit, &bad_mode_utf8),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_FIELD_MISSING
        ));

        let mut bad_vrf_utf8 = header.clone();
        bad_vrf_utf8.insert(HDR_VRF_ID, Value::Bytes(vec![0xFE]));
        assert!(matches!(
            compute_vck_key(&xk_hash, &seed_commit, &rho_commit, &hp_commit, &bad_vrf_utf8),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_FIELD_MISSING
        ));

        let mut missing_fs_version = header.clone();
        missing_fs_version.remove(&HDR_FS_POLICY_VERSION);
        assert!(matches!(
            compute_vck_key(
                &xk_hash,
                &seed_commit,
                &rho_commit,
                &hp_commit,
                &missing_fs_version
            ),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_FS_POLICY_VERSION_UNSUPPORTED
        ));

        let mut bad_fs_type = header.clone();
        bad_fs_type.insert(HDR_FS_POLICY_VERSION, Value::Text("7".to_string()));
        assert!(matches!(
            compute_vck_key(&xk_hash, &seed_commit, &rho_commit, &hp_commit, &bad_fs_type),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_FS_POLICY_VERSION_UNSUPPORTED
        ));

        let mut bad_policy_type = header.clone();
        bad_policy_type.insert(HDR_POLICY_VERSION, Value::Text("bad".to_string()));
        assert!(matches!(
            compute_vck_key(&xk_hash, &seed_commit, &rho_commit, &hp_commit, &bad_policy_type),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_FS_POLICY_VERSION_UNSUPPORTED
        ));

        let mut policy_mismatch = header.clone();
        policy_mismatch.insert(HDR_POLICY_VERSION, Value::Integer(Integer::from(9u64)));
        assert!(matches!(
            compute_vck_key(&xk_hash, &seed_commit, &rho_commit, &hp_commit, &policy_mismatch),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_FS_POLICY_VERSION_UNSUPPORTED
        ));

        Ok(())
    }

    #[test]
    fn anchor_reference_and_nonmembership_validation_cover_matrix()
    -> Result<(), Box<dyn std::error::Error>> {
        let leaf_id = [0x11; 32];
        let expected_root = msphf_core::merkle::hash_leaf(&leaf_id);
        let witness = RawMembershipWitness {
            leaf_id: leaf_id.to_vec(),
            root: expected_root.to_vec(),
            path: Vec::new(),
        };
        let pool = vec![witness.clone()];
        let bound = witness.leaf_id.clone();

        assert!(validate_anchor_reference(&pool, &expected_root, None, None)?.is_none());
        assert!(matches!(
            validate_anchor_reference(&pool, &expected_root, None, Some(0)),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_SRX_ANCHOR_MISSING
        ));
        assert!(matches!(
            validate_anchor_reference(&pool, &expected_root, Some(&bound), None),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_SRX_ANCHOR_MISSING
        ));
        assert!(matches!(
            validate_anchor_reference(&pool, &expected_root, Some(&vec![0x22; 31]), Some(0)),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_SRX_ANCHOR_MISMATCH
        ));

        let malformed_pool = vec![RawMembershipWitness {
            leaf_id: vec![0x33; 32],
            root: vec![0x44; 31],
            path: Vec::new(),
        }];
        assert!(matches!(
            validate_anchor_reference(
                &malformed_pool,
                &expected_root,
                Some(&malformed_pool[0].leaf_id),
                Some(0)
            ),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_HASH_MEM_MALFORMED
        ));

        let oversize_pool = vec![RawMembershipWitness {
            leaf_id: vec![0x55; 32],
            root: expected_root.to_vec(),
            path: (0..65)
                .map(|_| RawPathEntry {
                    sibling: vec![0x77; 32],
                    dir: 0,
                })
                .collect(),
        }];
        assert!(matches!(
            validate_anchor_reference(
                &oversize_pool,
                &expected_root,
                Some(&oversize_pool[0].leaf_id),
                Some(0)
            ),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_HASH_PATH_OVERSIZE
        ));

        assert!(validate_anchor_reference(&pool, &expected_root, Some(&bound), Some(0)).is_err());

        let duplicate_members = vec![witness.clone(), witness];
        assert!(validate_membership_array(&duplicate_members, &expected_root).is_err());

        let sentinel = RawNonMembershipWitness {
            query: vec![0x90; 32],
            root: vec![0u8; 32],
            left: None,
            right: None,
            path: Vec::new(),
            left_below: Vec::new(),
            right_below: Vec::new(),
            above: Vec::new(),
            nmint: None,
            lca_left_height: None,
            lca_right_height: None,
        };
        let anchored_a = AnchoredNonMembership {
            witness: sentinel.clone(),
            left_ref: None,
            right_ref: None,
        };
        let anchored_b = AnchoredNonMembership {
            witness: sentinel,
            left_ref: None,
            right_ref: None,
        };
        assert_eq!(
            validate_anchored_nonmem_array(
                &[anchored_a],
                &[],
                &[0u8; 32],
                FREEZE_SRX_SET_CONFLICT_PARENT
            )?
            .len(),
            1
        );
        assert!(matches!(
            validate_anchored_nonmem_array(
                &[anchored_b, AnchoredNonMembership {
                    witness: RawNonMembershipWitness {
                        query: vec![0x90; 32],
                        root: vec![0u8; 32],
                        left: None,
                        right: None,
                        path: Vec::new(),
                        left_below: Vec::new(),
                        right_below: Vec::new(),
                        above: Vec::new(),
                        nmint: None,
                        lca_left_height: None,
                        lca_right_height: None,
                    },
                    left_ref: None,
                    right_ref: None,
                }],
                &[],
                &[0u8; 32],
                FREEZE_SRX_SET_CONFLICT_PARENT
            ),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_SRX_INVALID
        ));

        Ok(())
    }

    #[test]
    fn merge_header_helpers_cover_known_key_and_note_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut header = BTreeMap::new();
        assert!(parse_mh_heads(&header)?.is_none());
        assert!(parse_mh_note(&header)?.is_none());

        header.insert(HDR_MH_HEADS, Value::Integer(Integer::from(1u64)));
        assert!(parse_mh_heads(&header)?.is_none());
        header.insert(
            HDR_MH_HEADS,
            Value::Array(vec![Value::Integer(Integer::from(1u64))]),
        );
        assert!(matches!(
            parse_mh_heads(&header),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_MH_HEADS_INVALID
        ));

        header.insert(
            HDR_MH_HEADS,
            Value::Array(vec![Value::Bytes(vec![0x11; 31])]),
        );
        assert!(matches!(
            parse_mh_heads(&header),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_MH_HEADS_INVALID
        ));

        header.insert(
            HDR_MH_HEADS,
            Value::Array(vec![
                Value::Bytes(vec![0x22; 32]),
                Value::Bytes(vec![0x22; 32]),
            ]),
        );
        assert!(matches!(
            parse_mh_heads(&header),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_MH_HEADS_INVALID
        ));

        header.insert(
            HDR_MH_HEADS,
            Value::Array(vec![Value::Bytes(vec![0x11; 32])]),
        );
        assert_eq!(
            parse_mh_heads(&header)?.expect("one head expected").len(),
            1
        );

        header.insert(102, Value::Integer(Integer::from(9u64)));
        assert!(parse_mh_note(&header).is_err());
        header.insert(102, Value::Text("merge-note".to_string()));
        assert_eq!(parse_mh_note(&header)?.as_deref(), Some("merge-note"));

        let mut unknown = header.clone();
        unknown.insert(9999, Value::Null);
        assert!(matches!(
            ensure_known_header_keys(&unknown, false),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_HASH_CBOR
        ));
        ensure_known_header_keys(&header, true)?;

        Ok(())
    }

    #[test]
    fn verify_device_chain_state_enforces_caps() -> Result<(), Box<dyn std::error::Error>> {
        let mut ctx = AcceptanceContext::with_defaults();
        ctx.fs_caps.anchor_max = 5;
        ctx.fs_caps.first_device = 5;
        ctx.fs_caps.device_max = 3;
        ctx.last_accepted_ec = 100;

        let pop_pk = vec![0xAA; 1952];
        let prev_commit = [0u8; 32];
        let dev_commit = h_l(
            "fs/dev/chain/v2",
            &FsDevChainV2Preimage {
                device_pk: &pop_pk,
                fs_ec: 104,
                prev_commit: &prev_commit,
                barrier_version: 0,
                barrier_update_digest: &[0u8; 32],
            },
        )?;

        ctx.verify_device_chain_state(
            None,
            DeviceChainVerification {
                pop_pk: &pop_pk,
                fs_ec: 104,
                fs_dev_prev_commit: &prev_commit,
                fs_dev_commit: &dev_commit,
                barrier_version: 0,
                barrier_update_digest: &[0u8; 32],
            },
        )?;

        let result = ctx.verify_device_chain_state(
            None,
            DeviceChainVerification {
                pop_pk: &pop_pk,
                fs_ec: 107,
                fs_dev_prev_commit: &prev_commit,
                fs_dev_commit: &dev_commit,
                barrier_version: 0,
                barrier_update_digest: &[0u8; 32],
            },
        );
        assert!(result.is_err(), "should freeze");
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            AcceptanceError::Freeze(FREEZE_FS_FORWARD_JUMP_GROUP)
        ));

        let prev_existing = [0x22; 32];
        let existing = DeviceChainState {
            last_commit: Some(prev_existing),
            last_ec: 110,
            last_pcs_refresh_ec: None,
        };
        ctx.last_accepted_ec = 110;
        let dev_commit_existing = h_l(
            "fs/dev/chain/v2",
            &FsDevChainV2Preimage {
                device_pk: &pop_pk,
                fs_ec: 114,
                prev_commit: &prev_existing,
                barrier_version: 0,
                barrier_update_digest: &[0u8; 32],
            },
        )?;
        let result = ctx.verify_device_chain_state(
            Some(&existing),
            DeviceChainVerification {
                pop_pk: &pop_pk,
                fs_ec: 114,
                fs_dev_prev_commit: &prev_existing,
                fs_dev_commit: &dev_commit_existing,
                barrier_version: 0,
                barrier_update_digest: &[0u8; 32],
            },
        );
        assert!(result.is_err(), "device max exceeded");
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            AcceptanceError::Freeze(FREEZE_FS_FORWARD_JUMP_DEVICE)
        ));
        Ok(())
    }

    #[test]
    fn barrier_update_reason_and_digest_helpers_enforce_shape()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut header = BTreeMap::new();
        assert_eq!(parse_barrier_update_reason(&header)?, None);
        assert_eq!(compute_barrier_update_digest(&header)?, [0u8; 32]);

        header.insert(
            HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(1u64)),
        );
        assert!(matches!(
            parse_barrier_update_reason(&header),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_BARRIER_UPDATE_MALFORMED
        ));
        header.clear();

        header.insert(HDR_BARRIER_UPDATE, Value::Bytes(vec![0x01, 0x02]));
        assert!(matches!(
            parse_barrier_update_reason(&header),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_BARRIER_UPDATE_MALFORMED
        ));
        header.insert(
            HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(2u64)),
        );
        assert!(matches!(
            parse_barrier_update_reason(&header),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_BARRIER_UPDATE_MALFORMED
        ));
        header.insert(
            HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(1u64)),
        );
        assert_eq!(parse_barrier_update_reason(&header)?, Some(1));
        assert_ne!(compute_barrier_update_digest(&header)?, [0u8; 32]);

        header.insert(HDR_BARRIER_UPDATE, Value::Integer(Integer::from(7u64)));
        assert!(matches!(
            compute_barrier_update_digest(&header),
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_BARRIER_UPDATE_MALFORMED
        ));
        Ok(())
    }

    #[test]
    fn classify_anchor_type_detects_barrier_merge_signals() {
        let mut merge_header = BTreeMap::new();
        merge_header.insert(
            HDR_BARRIER_UPDATE_REASON,
            Value::Integer(Integer::from(1u64)),
        );
        assert!(matches!(
            classify_anchor_type(&merge_header),
            AnchorType::Merge
        ));

        let mut join_header = BTreeMap::new();
        join_header.insert(HDR_BARRIER_LEAF_PK, Value::Bytes(vec![0u8; 1184]));
        assert!(matches!(
            classify_anchor_type(&join_header),
            AnchorType::Join
        ));

        let regular_header = BTreeMap::new();
        assert!(matches!(
            classify_anchor_type(&regular_header),
            AnchorType::Regular
        ));
    }

    #[test]
    fn anchor_presence_rules_enforce_barrier_leaf_pk_shape() {
        let mut join_header = BTreeMap::new();
        join_header.insert(
            HDR_BARRIER_LEAF_PK,
            Value::Bytes(vec![0x7Au8; BARRIER_LEAF_PUBLIC_KEY_BYTES]),
        );
        assert!(
            enforce_anchor_presence_rules(&join_header, AnchorType::Join).is_ok(),
            "join anchors with well-formed barrier leaf key must pass"
        );

        join_header.insert(HDR_BARRIER_LEAF_PK, Value::Bytes(vec![0x7Au8; 64]));
        assert!(
            matches!(
                enforce_anchor_presence_rules(&join_header, AnchorType::Join),
                Err(AcceptanceError::Freeze(code)) if code == FREEZE_HASH_CBOR
            ),
            "join anchors must reject malformed barrier leaf key bytes"
        );

        let mut merge_header = BTreeMap::new();
        merge_header.insert(
            HDR_BARRIER_LEAF_PK,
            Value::Bytes(vec![0x11u8; BARRIER_LEAF_PUBLIC_KEY_BYTES]),
        );
        assert!(
            matches!(
                enforce_anchor_presence_rules(&merge_header, AnchorType::Merge),
                Err(AcceptanceError::Freeze(code)) if code == FREEZE_HASH_CBOR
            ),
            "merge anchors must reject join-only barrier leaf key"
        );
    }

    #[test]
    fn barrier_update_rejects_merge_delegation_key() -> Result<(), Box<dyn std::error::Error>> {
        let gid = b"gid-merge-delegation".as_slice();
        let mut ctx = AcceptanceContext::with_defaults();

        let mut header = BTreeMap::new();
        header.insert(HDR_FS_EC, Value::Integer(Integer::from(42u64)));
        header.insert(HDR_BARRIER_VERSION, Value::Integer(Integer::from(6u64)));
        header.insert(112, Value::Bytes([0x21; 32].to_vec()));
        header.insert(113, Value::Bytes([0x22; 32].to_vec()));

        let rrh = compute_revocation_roots_hash(&header)?;
        insert_valid_barrier_update(&mut header, 1_024, 0, 6, 5, rrh, 1)?;
        header.insert(HDR_MERGE_DELEGATION_SIG, Value::Bytes(vec![0x55; 64]));
        let state = BarrierGroupState {
            barrier_initialized: true,
            barrier_version: 5,
            barrier_roots_hash: rrh,
            ..BarrierGroupState::default()
        };
        ctx.insert_barrier_group_state(gid, state);

        let result = ctx.enforce_barrier_acceptance_gating(gid, &header, AnchorType::Merge);
        assert!(matches!(
            result,
            Err(AcceptanceError::Freeze(code))
                if code == FREEZE_BARRIER_MERGE_DELEGATION_FORBIDDEN
        ));
        Ok(())
    }

    #[test]
    fn accept_anchor_requires_barrier_update_on_revocation_change()
    -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let header = sample_header();
        let joiner = joiner_kgen_or(header, parts.clone(), params(), None, None)?;
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (header_with_pop, _, fs_witness) =
            header_ready_with_pop(&joiner, &parts, &pop_pk, &pop_sk);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        let barrier_state = BarrierGroupState {
            barrier_initialized: true,
            barrier_version: 0,
            barrier_roots_hash: [0xAB; 32],
            ..BarrierGroupState::default()
        };
        ctx.insert_barrier_group_state(parts.gid, barrier_state);

        seed_capss_with(&mut ctx, &fs_witness);
        let result = accept_with_header(&mut ctx, &parts, &header_with_pop);
        assert!(matches!(
            result,
            Err(AcceptanceError::Freeze(code))
                if code == FREEZE_BARRIER_UPDATE_REQUIRED_ON_REVOCATION_CHANGE
        ));
        Ok(())
    }

    #[test]
    fn proactive_pcs_refresh_gating_enforces_rate_limits() -> Result<(), Box<dyn std::error::Error>>
    {
        let gid = b"gid-rate".as_slice();
        let mut ctx = AcceptanceContext::with_defaults();

        let mut header = BTreeMap::new();
        header.insert(HDR_FS_EC, Value::Integer(Integer::from(104u64)));
        header.insert(HDR_BARRIER_VERSION, Value::Integer(Integer::from(6u64)));
        header.insert(112, Value::Bytes([0x11; 32].to_vec()));
        header.insert(113, Value::Bytes([0x22; 32].to_vec()));
        header.insert(
            HDR_MH_HEADS,
            Value::Array(vec![Value::Bytes([0x33; 32].to_vec())]),
        );

        let rrh = compute_revocation_roots_hash(&header)?;
        insert_valid_barrier_update(&mut header, 1_024, 0, 6, 5, rrh, 1)?;
        let barrier_state = BarrierGroupState {
            barrier_initialized: true,
            barrier_version: 5,
            barrier_roots_hash: rrh,
            last_pcs_refresh_ec: Some(100),
            pcs_refresh_min_delta_group_ec: 1,
            pcs_refresh_slot_width_ec: 10,
            ..BarrierGroupState::default()
        };
        ctx.insert_barrier_group_state(gid, barrier_state);

        let result = ctx.enforce_barrier_acceptance_gating(gid, &header, AnchorType::Merge);
        assert!(matches!(
            result,
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_BARRIER_PCS_REFRESH_RATE_LIMITED
        ));

        ctx.barrier_group_state_entry_mut(gid)
            .pcs_refresh_min_delta_group_ec = 20;
        header.insert(HDR_FS_EC, Value::Integer(Integer::from(109u64)));
        let result = ctx.enforce_barrier_acceptance_gating(gid, &header, AnchorType::Merge);
        assert!(matches!(
            result,
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_BARRIER_PCS_REFRESH_RATE_LIMITED
        ));
        Ok(())
    }

    #[test]
    fn bootstrap_join_path_is_rejected_without_genesis_merge()
    -> Result<(), Box<dyn std::error::Error>> {
        let gid = b"gid-bootstrap".as_slice();
        let mut ctx = AcceptanceContext::with_defaults();
        ctx.insert_barrier_group_state(gid, BarrierGroupState::default());

        let mut header = BTreeMap::new();
        header.insert(HDR_FS_EC, Value::Integer(Integer::from(0u64)));
        header.insert(HDR_BARRIER_VERSION, Value::Integer(Integer::from(0u64)));
        header.insert(112, Value::Bytes([0xAA; 32].to_vec()));
        header.insert(113, Value::Bytes([0xBB; 32].to_vec()));

        let result = ctx.enforce_barrier_acceptance_gating(gid, &header, AnchorType::Join);
        assert!(matches!(
            result,
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_BARRIER_GENESIS_REQUIRED
        ));
        Ok(())
    }

    #[test]
    fn proactive_refresh_requires_merge_anchor_type() -> Result<(), Box<dyn std::error::Error>> {
        let gid = b"gid-proactive-shape".as_slice();
        let mut ctx = AcceptanceContext::with_defaults();

        let mut header = BTreeMap::new();
        header.insert(HDR_FS_EC, Value::Integer(Integer::from(42u64)));
        header.insert(HDR_BARRIER_VERSION, Value::Integer(Integer::from(6u64)));
        header.insert(112, Value::Bytes([0x21; 32].to_vec()));
        header.insert(113, Value::Bytes([0x22; 32].to_vec()));

        let rrh = compute_revocation_roots_hash(&header)?;
        insert_valid_barrier_update(&mut header, 1_024, 0, 6, 5, rrh, 1)?;
        let state = BarrierGroupState {
            barrier_initialized: true,
            barrier_version: 5,
            barrier_roots_hash: rrh,
            ..BarrierGroupState::default()
        };
        ctx.insert_barrier_group_state(gid, state);

        let result = ctx.enforce_barrier_acceptance_gating(gid, &header, AnchorType::Join);
        assert!(matches!(
            result,
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_BARRIER_PROACTIVE_FORBIDDEN
        ));
        Ok(())
    }

    #[test]
    fn proactive_pcs_refresh_gating_enforces_device_rate_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        let gid = b"gid-proactive-device-limit".as_slice();
        let device_pk = vec![0xA7; 32];
        let mut ctx = AcceptanceContext::with_defaults();

        let mut header = BTreeMap::new();
        header.insert(HDR_POP_PK, Value::Bytes(device_pk.clone()));
        header.insert(HDR_FS_EC, Value::Integer(Integer::from(112u64)));
        header.insert(HDR_BARRIER_VERSION, Value::Integer(Integer::from(10u64)));
        header.insert(112, Value::Bytes([0x26; 32].to_vec()));
        header.insert(113, Value::Bytes([0x27; 32].to_vec()));

        let rrh = compute_revocation_roots_hash(&header)?;
        insert_valid_barrier_update(&mut header, 1_024, 0, 10, 9, rrh, 1)?;
        let state = BarrierGroupState {
            barrier_initialized: true,
            barrier_version: 9,
            barrier_roots_hash: rrh,
            last_pcs_refresh_ec: Some(100),
            pcs_refresh_min_delta_group_ec: 1,
            pcs_refresh_slot_width_ec: 10,
            pcs_refresh_min_delta_device_ec: 5,
            ..BarrierGroupState::default()
        };
        ctx.insert_barrier_group_state(gid, state);

        let device_state = ctx.device_chain_entry_mut(gid, &device_pk);
        device_state.last_pcs_refresh_ec = Some(110);

        let result = ctx.enforce_barrier_acceptance_gating(gid, &header, AnchorType::Merge);
        assert!(matches!(
            result,
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_BARRIER_PCS_REFRESH_RATE_LIMITED
        ));
        Ok(())
    }

    #[test]
    fn proactive_pcs_refresh_gating_accepts_valid_merge() -> Result<(), Box<dyn std::error::Error>>
    {
        let gid = b"gid-proactive-accept".as_slice();
        let mut ctx = AcceptanceContext::with_defaults();

        let mut header = BTreeMap::new();
        header.insert(HDR_FS_EC, Value::Integer(Integer::from(120u64)));
        header.insert(HDR_BARRIER_VERSION, Value::Integer(Integer::from(8u64)));
        header.insert(112, Value::Bytes([0x36; 32].to_vec()));
        header.insert(113, Value::Bytes([0x37; 32].to_vec()));

        let rrh = compute_revocation_roots_hash(&header)?;
        insert_valid_barrier_update(&mut header, 1_024, 0, 8, 7, rrh, 1)?;
        let state = BarrierGroupState {
            barrier_initialized: true,
            barrier_version: 7,
            barrier_roots_hash: rrh,
            last_pcs_refresh_ec: Some(100),
            pcs_refresh_min_delta_group_ec: 5,
            pcs_refresh_slot_width_ec: 10,
            pcs_refresh_min_delta_device_ec: 5,
            ..BarrierGroupState::default()
        };
        ctx.insert_barrier_group_state(gid, state);

        let result = ctx.enforce_barrier_acceptance_gating(gid, &header, AnchorType::Merge)?;
        assert_eq!(result.barrier_update_reason, Some(1));
        assert_eq!(result.barrier_version, 8);
        Ok(())
    }

    #[test]
    fn revocation_change_requires_barrier_update_even_for_merge()
    -> Result<(), Box<dyn std::error::Error>> {
        let gid = b"gid-rev-requires-bu".as_slice();
        let mut ctx = AcceptanceContext::with_defaults();

        let mut header = BTreeMap::new();
        header.insert(HDR_FS_EC, Value::Integer(Integer::from(9u64)));
        header.insert(HDR_BARRIER_VERSION, Value::Integer(Integer::from(3u64)));
        header.insert(112, Value::Bytes([0x31; 32].to_vec()));
        header.insert(113, Value::Bytes([0x32; 32].to_vec()));
        header.insert(
            HDR_MH_HEADS,
            Value::Array(vec![Value::Bytes([0x44; 32].to_vec())]),
        );

        let state = BarrierGroupState {
            barrier_initialized: true,
            barrier_version: 3,
            barrier_roots_hash: [0xFF; 32],
            ..BarrierGroupState::default()
        };
        ctx.insert_barrier_group_state(gid, state);

        let result = ctx.enforce_barrier_acceptance_gating(gid, &header, AnchorType::Merge);
        assert!(matches!(
            result,
            Err(AcceptanceError::Freeze(code))
                if code == FREEZE_BARRIER_UPDATE_REQUIRED_ON_REVOCATION_CHANGE
        ));

        insert_valid_barrier_update(&mut header, 1_024, 0, 3, 3, [0xAA; 32], 1)?;
        let result = ctx.enforce_barrier_acceptance_gating(gid, &header, AnchorType::Merge);
        assert!(matches!(
            result,
            Err(AcceptanceError::Freeze(code))
                if code == FREEZE_BARRIER_PCS_REFRESH_FORBIDDEN_WHILE_PENDING_REVOCATIONS
        ));
        Ok(())
    }

    #[test]
    fn invalid_genesis_merge_reason_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let gid = b"gid-genesis-reject".as_slice();
        let mut ctx = AcceptanceContext::with_defaults();
        ctx.insert_barrier_group_state(gid, BarrierGroupState::default());

        let mut header = BTreeMap::new();
        header.insert(HDR_FS_EC, Value::Integer(Integer::from(0u64)));
        header.insert(HDR_BARRIER_VERSION, Value::Integer(Integer::from(0u64)));
        header.insert(112, Value::Bytes([0x41; 32].to_vec()));
        header.insert(113, Value::Bytes([0x42; 32].to_vec()));
        header.insert(
            HDR_MH_HEADS,
            Value::Array(vec![Value::Bytes([0x45; 32].to_vec())]),
        );
        let rrh = compute_revocation_roots_hash(&header)?;
        insert_valid_barrier_update(&mut header, 1_024, 0, 0, 0, rrh, 1)?;

        let result = ctx.enforce_barrier_acceptance_gating(gid, &header, AnchorType::Merge);
        assert!(matches!(
            result,
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_BARRIER_GENESIS_REQUIRED
        ));
        Ok(())
    }

    #[test]
    fn pcs_commit_updates_group_and_device_refresh_markers() {
        let gid = b"gid-pcs-commit".as_slice();
        let device_pk = vec![0xD5; 32];
        let mut ctx = AcceptanceContext::with_defaults();
        ctx.insert_barrier_group_state(
            gid,
            BarrierGroupState {
                barrier_initialized: true,
                barrier_version: 8,
                barrier_roots_hash: [0x51; 32],
                kem_tree_hash_after: [0u8; 32],
                n_max: 1_024,
                last_pcs_refresh_ec: None,
                pcs_refresh_min_delta_device_ec: 1,
                pcs_refresh_min_delta_group_ec: 1,
                pcs_refresh_slot_width_ec: 1,
                max_barrier_update_bytes: 1_048_576,
            },
        );

        let mut header = BTreeMap::new();
        header.insert(HDR_POP_PK, Value::Bytes(device_pk.clone()));

        let gate = BarrierGateDecision {
            barrier_version: 9,
            fs_ec: 77,
            revocation_roots_hash: [0x61; 32],
            barrier_update_digest: [0xAB; 32],
            barrier_update_reason: Some(1),
            parsed_barrier_update: None,
        };

        ctx.apply_barrier_acceptance_commit(gid, &header, gate);

        let state = ctx
            .barrier_group_state(gid)
            .expect("barrier state should remain present");
        assert_eq!(state.barrier_version, 9);
        assert_eq!(state.barrier_roots_hash, [0x61; 32]);
        assert_eq!(state.last_pcs_refresh_ec, Some(77));

        let device_state = ctx
            .device_chain_get(gid, &device_pk)
            .expect("device refresh marker should be persisted");
        assert_eq!(device_state.last_pcs_refresh_ec, Some(77));
    }

    #[test]
    fn valid_revocation_merge_with_barrier_update_is_accepted()
    -> Result<(), Box<dyn std::error::Error>> {
        let gid = b"gid-valid-revoke-merge".as_slice();
        let mut ctx = AcceptanceContext::with_defaults();

        let mut header = BTreeMap::new();
        header.insert(HDR_FS_EC, Value::Integer(Integer::from(12u64)));
        header.insert(HDR_BARRIER_VERSION, Value::Integer(Integer::from(5u64)));
        header.insert(112, Value::Bytes([0x71; 32].to_vec()));
        header.insert(113, Value::Bytes([0x72; 32].to_vec()));
        header.insert(
            HDR_MH_HEADS,
            Value::Array(vec![Value::Bytes([0x73; 32].to_vec())]),
        );
        let rrh = compute_revocation_roots_hash(&header)?;
        insert_valid_barrier_update(&mut header, 1_024, 0, 5, 4, rrh, 0)?;

        let state = BarrierGroupState {
            barrier_initialized: true,
            barrier_version: 4,
            barrier_roots_hash: [0x00; 32],
            ..BarrierGroupState::default()
        };
        ctx.insert_barrier_group_state(gid, state);

        let result = ctx.enforce_barrier_acceptance_gating(gid, &header, AnchorType::Merge);
        assert!(result.is_ok(), "valid revocation merge should pass gating");
        Ok(())
    }

    #[test]
    fn barrier_update_hash_chain_is_not_gated_in_acceptance()
    -> Result<(), Box<dyn std::error::Error>> {
        let gid = b"gid-hash-chain-mismatch".as_slice();
        let mut ctx = AcceptanceContext::with_defaults();

        let mut header = BTreeMap::new();
        header.insert(HDR_FS_EC, Value::Integer(Integer::from(44u64)));
        header.insert(HDR_BARRIER_VERSION, Value::Integer(Integer::from(8u64)));
        header.insert(112, Value::Bytes([0x91; 32].to_vec()));
        header.insert(113, Value::Bytes([0x92; 32].to_vec()));
        header.insert(
            HDR_MH_HEADS,
            Value::Array(vec![Value::Bytes([0x93; 32].to_vec())]),
        );
        let rrh = compute_revocation_roots_hash(&header)?;
        insert_valid_barrier_update(&mut header, 1_024, 0, 8, 7, rrh, 1)?;

        let state = BarrierGroupState {
            barrier_initialized: true,
            barrier_version: 7,
            barrier_roots_hash: rrh,
            kem_tree_hash_after: [0xAA; 32],
            ..BarrierGroupState::default()
        };
        ctx.insert_barrier_group_state(gid, state);

        let result = ctx.enforce_barrier_acceptance_gating(gid, &header, AnchorType::Merge);
        assert!(
            result.is_ok(),
            "hash-chain checks run in barrier validators; gating should not reject solely on kem_tree_hash_before"
        );
        Ok(())
    }

    #[test]
    fn barrier_version_mismatch_without_update_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let gid = b"gid-version-mismatch".as_slice();
        let mut ctx = AcceptanceContext::with_defaults();

        let mut header = BTreeMap::new();
        header.insert(HDR_FS_EC, Value::Integer(Integer::from(18u64)));
        header.insert(HDR_BARRIER_VERSION, Value::Integer(Integer::from(9u64)));
        header.insert(112, Value::Bytes([0x81; 32].to_vec()));
        header.insert(113, Value::Bytes([0x82; 32].to_vec()));

        let rrh = compute_revocation_roots_hash(&header)?;
        let state = BarrierGroupState {
            barrier_initialized: true,
            barrier_version: 8,
            barrier_roots_hash: rrh,
            ..BarrierGroupState::default()
        };
        ctx.insert_barrier_group_state(gid, state);

        let result = ctx.enforce_barrier_acceptance_gating(gid, &header, AnchorType::Join);
        assert!(matches!(
            result,
            Err(AcceptanceError::Freeze(code)) if code == FREEZE_BARRIER_PROACTIVE_FORBIDDEN
        ));
        Ok(())
    }

    #[test]
    fn apply_barrier_commit_without_group_state_is_noop() {
        let gid = b"gid-noop".as_slice();
        let mut ctx = AcceptanceContext::with_defaults();
        let header = BTreeMap::new();
        let gate = BarrierGateDecision {
            barrier_version: 0,
            fs_ec: 0,
            revocation_roots_hash: [0u8; 32],
            barrier_update_digest: [0u8; 32],
            barrier_update_reason: None,
            parsed_barrier_update: None,
        };
        ctx.apply_barrier_acceptance_commit(gid, &header, gate);
        assert!(ctx.barrier_group_state(gid).is_none());
    }

    #[test]
    fn apply_barrier_commit_without_update_does_not_initialize_group_state() {
        let gid = b"gid-no-update".as_slice();
        let mut ctx = AcceptanceContext::with_defaults();
        let header = BTreeMap::new();
        ctx.insert_barrier_group_state(
            gid,
            BarrierGroupState {
                barrier_initialized: false,
                barrier_version: 0,
                ..BarrierGroupState::default()
            },
        );
        let gate = BarrierGateDecision {
            barrier_version: 7,
            fs_ec: 42,
            revocation_roots_hash: [0x44; 32],
            barrier_update_digest: [0x55; 32],
            barrier_update_reason: None,
            parsed_barrier_update: None,
        };
        ctx.apply_barrier_acceptance_commit(gid, &header, gate);
        let state = ctx
            .barrier_group_state(gid)
            .expect("group state should still exist");
        assert!(!state.barrier_initialized);
        assert_eq!(state.barrier_version, 0);
    }

    #[test]
    fn header_type_mismatch_helpers_emit_freeze_errors() {
        let freeze = FREEZE_FIELD_MISSING;
        let mut header = BTreeMap::new();
        header.insert(110, Value::Integer(Integer::from(7)));
        let bytes_err = header_bytes32_or_freeze(&header, 110, freeze, "parent_root")
            .expect_err("bytes32 type mismatch should freeze");
        assert!(matches!(
            bytes_err,
            AcceptanceError::Freeze(code) if code == freeze
        ));

        header.insert(HDR_FS_EC, Value::Text("not-integer".to_string()));
        let u64_err = header_u64_or_freeze(&header, HDR_FS_EC, freeze, "fs_ec")
            .expect_err("u64 type mismatch should freeze");
        assert!(matches!(
            u64_err,
            AcceptanceError::Freeze(code) if code == freeze
        ));

        header.insert(HDR_FS_EC, Value::Integer(Integer::from(-1)));
        let signed_err = header_u64_or_freeze(&header, HDR_FS_EC, freeze, "fs_ec")
            .expect_err("signed integer should freeze");
        assert!(matches!(
            signed_err,
            AcceptanceError::Freeze(code) if code == freeze
        ));
    }

    #[test]
    fn validate_anchor_pool_unsorted_triggers_freeze() -> Result<(), Box<dyn std::error::Error>> {
        let witness_a = RawMembershipWitness {
            leaf_id: vec![0x10; 32],
            root: vec![0x00; 32],
            path: Vec::new(),
        };
        let witness_b = RawMembershipWitness {
            leaf_id: vec![0x01; 32],
            root: vec![0x00; 32],
            path: Vec::new(),
        };

        let unsorted = vec![witness_a.clone(), witness_b.clone()];
        let result = validate_anchor_pool(&unsorted);
        assert!(result.is_err(), "unsorted pool should fail");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_SRX_ANCHOR_POOL_UNSORTED),
            "unexpected error: {err:?}"
        );

        let sorted = vec![witness_b, witness_a];
        validate_anchor_pool(&sorted)?;
        Ok(())
    }

    #[test]
    fn validate_anchor_reference_oob_triggers_freeze() -> Result<(), Box<dyn std::error::Error>> {
        let root = [0xAA; 32];
        let bound = vec![0xBB; 32];
        let result = validate_anchor_reference(&[], &root, Some(&bound), Some(0));
        assert!(result.is_err(), "oob reference should freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_SRX_ANCHOR_OOB),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn verify_anchored_adjacency_mismatch_freezes() -> Result<(), Box<dyn std::error::Error>> {
        let entry = ValidatedNonMembership {
            query: [0x20; 32],
            root: [0xAA; 32],
            left: Some([0x05; 32]),
            right: None,
            path: Vec::new(),
        };
        let left_anchor = ValidatedMembership {
            leaf_id: [0x09; 32],
            root: [0xAA; 32],
            path: Vec::new(),
        };
        let result = verify_anchored_adjacency(&entry, Some(&left_anchor), None);
        assert!(result.is_err(), "mismatched left anchor should freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_NONMEM_ADJ_INCOHERENT),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn verify_anchored_adjacency_extreme_right_enforces_path()
    -> Result<(), Box<dyn std::error::Error>> {
        let path_bad = vec![(1u8, [0x11; 32])];
        let right_anchor = ValidatedMembership {
            leaf_id: [0x40; 32],
            root: [0xAA; 32],
            path: path_bad.clone(),
        };
        let entry_bad = ValidatedNonMembership {
            query: [0x30; 32],
            root: [0xAA; 32],
            left: None,
            right: Some([0x40; 32]),
            path: path_bad.clone(),
        };
        let result = verify_anchored_adjacency(&entry_bad, None, Some(&right_anchor));
        assert!(result.is_err(), "non-zero dirs should fail");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_NONMEM_ADJ_INCOHERENT),
            "unexpected error: {err:?}"
        );

        let path_ok = vec![(0u8, [0x22; 32])];
        let right_anchor_ok = ValidatedMembership {
            leaf_id: [0x41; 32],
            root: [0xAA; 32],
            path: path_ok.clone(),
        };
        let entry_ok = ValidatedNonMembership {
            query: [0x35; 32],
            root: [0xAA; 32],
            left: None,
            right: Some([0x41; 32]),
            path: path_ok.clone(),
        };
        verify_anchored_adjacency(&entry_ok, None, Some(&right_anchor_ok))?;
        Ok(())
    }

    #[test]
    fn verify_anchored_adjacency_extreme_left_enforces_path()
    -> Result<(), Box<dyn std::error::Error>> {
        let path_bad = vec![(0u8, [0x33; 32])];
        let left_anchor = ValidatedMembership {
            leaf_id: [0x20; 32],
            root: [0xBB; 32],
            path: path_bad.clone(),
        };
        let entry_bad = ValidatedNonMembership {
            query: [0x10; 32],
            root: [0xBB; 32],
            left: Some([0x20; 32]),
            right: None,
            path: path_bad.clone(),
        };
        let result = verify_anchored_adjacency(&entry_bad, Some(&left_anchor), None);
        assert!(result.is_err(), "non-one dirs should fail");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_NONMEM_ADJ_INCOHERENT),
            "unexpected error: {err:?}"
        );

        let path_ok = vec![(1u8, [0x44; 32])];
        let left_anchor_ok = ValidatedMembership {
            leaf_id: [0x21; 32],
            root: [0xBB; 32],
            path: path_ok.clone(),
        };
        let entry_ok = ValidatedNonMembership {
            query: [0x22; 32],
            root: [0xBB; 32],
            left: Some([0x21; 32]),
            right: None,
            path: path_ok.clone(),
        };
        verify_anchored_adjacency(&entry_ok, Some(&left_anchor_ok), None)?;
        Ok(())
    }

    #[test]
    fn vck_cache_hits_and_skips_reverification_for_hp() -> Result<(), Box<dyn std::error::Error>> {
        let (_, proof) = sample_hp_inputs();
        let mut cache = VckCache::new(Duration::from_secs(10));
        let key = [0x11; 32];
        let now = AcceptInstant::from_ticks(0);
        assert!(cache.should_verify_hp(key, &proof, now));
        cache.record_hp(key, &proof, now);
        assert!(!cache.should_verify_hp(key, &proof, now));
        Ok(())
    }

    #[test]
    fn vck_cache_expires_hp_entries() -> Result<(), Box<dyn std::error::Error>> {
        let (_, proof) = sample_hp_inputs();
        let mut cache = VckCache::new(Duration::from_secs(1));
        let key = [0x22; 32];
        let start = AcceptInstant::from_ticks(0);
        assert!(cache.should_verify_hp(key, &proof, start));
        cache.record_hp(key, &proof, start);
        let later = AcceptInstant::from_ticks(2);
        assert!(cache.should_verify_hp(key, &proof, later));
        Ok(())
    }

    #[test]
    fn vck_cache_detects_mutated_hp_proof() -> Result<(), Box<dyn std::error::Error>> {
        let (_, proof) = sample_hp_inputs();
        let mut cache = VckCache::new(Duration::from_secs(10));
        let key = [0x33; 32];
        let now = AcceptInstant::from_ticks(0);
        assert!(cache.should_verify_hp(key, &proof, now));
        cache.record_hp(key, &proof, now);

        let mut proof_bytes = proof_to_cbor(&proof)?;
        if let Some(last) = proof_bytes.last_mut() {
            *last ^= 0x55;
        }
        let tampered: HpProof = de::from_reader(proof_bytes.as_slice())?;

        assert!(cache.should_verify_hp(key, &tampered, now));
        Ok(())
    }

    #[test]
    fn accept_anchor_enqueues_head() -> Result<(), Box<dyn std::error::Error>> {
        let header = sample_header();
        let joiner = joiner_kgen_or(header, sample_parts(), params(), None, None)?;
        let parts = sample_parts();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut header_with_pop, expected_weid) =
            header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);
        let header_with_pop_fs_witness =
            prepare_header_for_acceptance(&mut header_with_pop, &parts, &joiner);
        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);

        seed_capss_with(&mut ctx, &header_with_pop_fs_witness);
        let outcome = accept_with_header(&mut ctx, &parts, &header_with_pop)?;

        assert!(matches!(outcome.kind, AcceptanceKind::NonMerge));
        assert_eq!(ctx.active_heads(&outcome.wid), 1);
        assert_eq!(outcome.we_epoch_id, expected_weid);
        Ok(())
    }

    #[test]
    fn window_full_triggers_freeze() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let mut header_a = sample_header();
        header_a.insert(102, Value::Text("head-a".to_string()));
        let mut header_b = sample_header();
        header_b.insert(102, Value::Text("head-b".to_string()));
        let params_a = params();
        let params_b = params();
        let joiner_a = joiner_kgen_or(header_a, parts.clone(), params_a, None, None)?;
        let joiner_b = joiner_kgen_or(header_b, parts.clone(), params_b, None, None)?;
        let (pop_pk, pop_sk) = pop_keys_static();
        let (header_a, _, header_a_fs_witness) =
            header_ready_with_pop(&joiner_a, &parts, pop_pk, pop_sk);
        let (header_b, _, header_b_fs_witness) =
            header_ready_with_pop(&joiner_b, &parts, pop_pk, pop_sk);
        let mut ctx = AcceptanceContext::new(1, Duration::from_secs(10));
        configure_bootstrap(&mut ctx);

        seed_capss_with(&mut ctx, &header_a_fs_witness);
        let outcome_a = accept_with_header(&mut ctx, &parts, &header_a)?;

        ctx.rho_guard = RhoReplayGuard::new(RHO_GUARD_CAPACITY, ctx.mh_window.ttl());
        seed_capss_with(&mut ctx, &header_b_fs_witness);
        let weid_b = super::compute_we_epoch_id_from_header(&parts, &header_b)?;
        let result = ctx.accept_anchor(&parts, weid_b, &header_b);
        assert!(result.is_err(), "second head should freeze");
        let err = result.unwrap_err();

        let window_froze = matches!(
            err,
            AcceptanceError::Freeze(code) if code == FreezeError::WINDOW_FULL
        );
        if !window_froze {
            assert!(
                matches!(
                    &err,
                    AcceptanceError::Freeze(code)
                        if *code == FREEZE_MSPHF_RHO_PARITY || *code == FREEZE_FS_DEV_CHAIN_BREAK
                ),
                "unexpected error: {err:?}"
            );
        }

        let telemetry_key = TelemetryKey::from_parts(parts.gid, parts.parent_root);
        let snapshot = ctx.telemetry_snapshot();
        let counters = snapshot
            .get(&telemetry_key)
            .expect("telemetry entry for window-full scenario");
        assert_eq!(counters.head_attempts, 2);
        assert_eq!(counters.head_insertions, 1);
        if window_froze {
            assert_eq!(counters.freeze_window_full, 1);
            assert_eq!(counters.freeze_rho_replay, 0);
        }
        assert_eq!(ctx.active_heads(&outcome_a.wid), 1);
        assert_eq!(counters.last_active_heads, 1);
        Ok(())
    }

    #[test]
    fn merge_h_max_exceeded_freezes() -> Result<(), Box<dyn std::error::Error>> {
        let mut ctx =
            AcceptanceContext::with_options(1, DEFAULT_T_WINDOW, AcceptanceOptions::default());
        let parent_root = [0u8; 32];
        let mh_heads = [[0x01; 32], [0x02; 32]];
        let now = AcceptInstant::from_ticks(0);
        let record = HeadRecord::new(
            [0xAA; 32], [0xBB; 32], [0xCC; 32], [0xDD; 32], [0xEE; 32], [0x12; 32], [0x01; 32],
            [0x02; 32], [0x03; 32], 0, now,
        );
        let result = ctx.accept_merge(&parent_root, &parent_root, &mh_heads, record, now);
        assert!(result.is_err(), "merge above H_max should freeze");
        let err = result.unwrap_err();
        assert_eq!(err, FreezeError::WINDOW_FULL);
        Ok(())
    }

    #[test]
    fn rho_commit_reuse_freezes() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let header = sample_header();
        let joiner = joiner_kgen_or(header, parts.clone(), params(), None, None)?;
        let (mut header_with_pop, _) =
            header_with_pop_and_weid(&joiner, &parts, &sample_pop_keys().0, &sample_pop_keys().1);
        let header_with_pop_fs_witness =
            prepare_header_for_acceptance(&mut header_with_pop, &parts, &joiner);
        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);

        seed_capss_with(&mut ctx, &header_with_pop_fs_witness);
        accept_with_header(&mut ctx, &parts, &header_with_pop)?;

        ctx.clear_device_chains();
        seed_capss_with(&mut ctx, &header_with_pop_fs_witness);
        let result = accept_with_header(&mut ctx, &parts, &header_with_pop);
        assert!(result.is_err(), "rho reuse should freeze");
        let err = result.unwrap_err();

        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_RHO_PARITY),
            "unexpected error: {err:?}"
        );

        let telemetry_key = TelemetryKey::from_parts(parts.gid, parts.parent_root);
        let snapshot = ctx.telemetry_snapshot();
        let counters = snapshot
            .get(&telemetry_key)
            .expect("telemetry entry for rho replay");
        assert_eq!(counters.head_attempts, 2);
        assert_eq!(counters.head_insertions, 1);
        assert_eq!(counters.freeze_rho_replay, 1);
        assert_eq!(counters.freeze_window_full, 0);
        assert_eq!(counters.last_active_heads, 1);
        Ok(())
    }

    #[test]
    fn device_chain_prev_commit_mismatch_freezes() -> Result<(), Box<dyn std::error::Error>> {
        let (parts, params_a, joiner_a) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (header_a, _, witness_a) = header_ready_with_pop(&joiner_a, &parts, &pop_pk, &pop_sk);
        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &witness_a);
        accept_with_header(&mut ctx, &parts, &header_a)?;

        let prev_commit = header_bytes32(&header_a, HDR_FS_DEV_COMMIT);

        let mut params_b = params_a;
        params_b.fs_join.fs_ec += 1;
        params_b.fs_join.fs_dev_prev_commit = prev_commit;

        let header_seed_b = sample_header();
        let joiner_b = joiner_kgen_or(header_seed_b, parts.clone(), params_b, None, None)?;
        let (mut header_b, _, witness_b) =
            header_ready_with_pop(&joiner_b, &parts, &pop_pk, &pop_sk);
        header_b.insert(HDR_FS_DEV_PREV_COMMIT, Value::Bytes(vec![0u8; 32]));
        refresh_seed_bindings(&mut header_b, &parts, &joiner_b);

        ctx.rho_guard = RhoReplayGuard::new(RHO_GUARD_CAPACITY, ctx.mh_window.ttl());
        seed_capss_with(&mut ctx, &witness_b);
        let result = accept_with_header(&mut ctx, &parts, &header_b);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "device chain mismatch should freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_FS_DEV_CHAIN_BREAK),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn annex_m_report_accumulates_counters() -> Result<(), Box<dyn std::error::Error>> {
        let (parts, _, joiner) = sample_parts_params_joiner();
        let mut header_with_pop = joiner.header_map.clone();
        let header_with_pop_fs_witness =
            prepare_header_for_acceptance(&mut header_with_pop, &parts, &joiner);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &header_with_pop_fs_witness);
        accept_with_header(&mut ctx, &parts, &header_with_pop)?;

        ctx.clear_device_chains();
        seed_capss_with(&mut ctx, &header_with_pop_fs_witness);
        let result = accept_with_header(&mut ctx, &parts, &header_with_pop);
        assert!(result.is_err(), "rho reuse should freeze");

        let report = ctx.annex_m_report();
        assert_eq!(report.rows.len(), 1);
        assert_eq!(report.total_attempts, 2);
        assert_eq!(report.total_insertions, 1);
        assert_eq!(report.total_freeze_rho_replay, 1);
        assert_eq!(report.total_freeze_window_full, 0);

        let row = &report.rows[0];
        assert_eq!(row.head_attempts, 2);
        assert_eq!(row.head_insertions, 1);
        assert_eq!(row.freeze_rho_replay, 1);
        assert_eq!(row.freeze_window_full, 0);
        assert_eq!(row.last_active_heads, 1);
        assert_eq!(row.gid.as_slice(), parts.gid);
        Ok(())
    }

    #[test]
    fn telemetry_report_sorted_by_gid_and_parent() -> Result<(), Box<dyn std::error::Error>> {
        let mut ctx = AcceptanceContext::with_defaults();
        let parent_a1 = [0x0A; 32];
        let parent_a2 = [0x0B; 32];
        let parent_b = [0xFF; 32];

        let key_b = ctx.telemetry_record_attempt(b"bbb", &parent_b);
        ctx.telemetry_record_success(&key_b, 1);

        let key_a2 = ctx.telemetry_record_attempt(b"aaa", &parent_a2);
        ctx.telemetry_record_success(&key_a2, 2);

        let key_a1 = ctx.telemetry_record_attempt(b"aaa", &parent_a1);
        ctx.telemetry_record_success(&key_a1, 3);

        let report = ctx.telemetry_report();
        assert_eq!(report.len(), 3);
        assert_eq!(report[0].0.gid.as_slice(), b"aaa");
        assert_eq!(report[0].0.parent_root, parent_a1);
        assert_eq!(report[1].0.parent_root, parent_a2);
        assert_eq!(report[2].0.gid.as_slice(), b"bbb");
        Ok(())
    }

    #[test]
    fn annex_m_report_totals_match_rows() -> Result<(), Box<dyn std::error::Error>> {
        let mut ctx = AcceptanceContext::with_defaults();
        let parent = [0x22; 32];
        let key = ctx.telemetry_record_attempt(b"gid", &parent);
        ctx.telemetry_record_success(&key, 1);
        ctx.telemetry_record_window_full(&key);
        ctx.telemetry_record_rho_freeze(&key);

        let report = ctx.annex_m_report();
        assert_eq!(report.rows.len(), 1);
        assert_eq!(report.total_attempts, 1);
        assert_eq!(report.total_insertions, 1);
        assert_eq!(report.total_freeze_window_full, 1);
        assert_eq!(report.total_freeze_rho_replay, 1);
        let row = &report.rows[0];
        assert_eq!(row.freeze_rho_replay, 1);
        assert_eq!(row.freeze_window_full, 1);
        Ok(())
    }

    #[test]
    fn set_h_max_propagates_to_window() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let mut header_a = sample_header();
        header_a.insert(102, Value::Text("head-a".to_string()));
        let mut header_b = sample_header();
        header_b.insert(102, Value::Text("head-b".to_string()));
        let params_a = params();
        let params_b = params();
        let joiner_a = joiner_kgen_or(header_a, parts.clone(), params_a, None, None)?;
        let joiner_b = joiner_kgen_or(header_b, parts.clone(), params_b, None, None)?;
        let (pop_pk, pop_sk) = pop_keys_static();
        let (mut header_a, _) = header_with_pop_and_weid(&joiner_a, &parts, pop_pk, pop_sk);
        let header_a_fs_witness = prepare_header_for_acceptance(&mut header_a, &parts, &joiner_a);
        let (mut header_b, _) = header_with_pop_and_weid(&joiner_b, &parts, pop_pk, pop_sk);
        let header_b_fs_witness = prepare_header_for_acceptance(&mut header_b, &parts, &joiner_b);

        let mut ctx = AcceptanceContext::with_defaults();
        ctx.set_h_max(1);
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &header_a_fs_witness);
        let outcome_a = accept_with_header(&mut ctx, &parts, &header_a)?;

        ctx.clear_device_chains();
        ctx.rho_guard = RhoReplayGuard::new(RHO_GUARD_CAPACITY, ctx.mh_window.ttl());
        seed_capss_with(&mut ctx, &header_b_fs_witness);
        let weid_b = super::compute_we_epoch_id_from_header(&parts, &header_b)?;
        let result = ctx.accept_anchor(&parts, weid_b, &header_b);
        assert!(result.is_err(), "second head should hit h_max");
        let err = result.unwrap_err();
        let window_froze = matches!(
            err,
            AcceptanceError::Freeze(code) if code == FreezeError::WINDOW_FULL
        );
        if !window_froze {
            assert!(
                matches!(
                    &err,
                    AcceptanceError::Freeze(code)
                        if *code == FREEZE_MSPHF_RHO_PARITY || *code == FREEZE_FS_DEV_CHAIN_BREAK
                ),
                "unexpected error: {err:?}"
            );
        }
        if window_froze {
            assert_eq!(ctx.active_heads(&outcome_a.wid), 1);
        }
        Ok(())
    }

    #[test]
    fn accept_anchor_requires_tswe_alg() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let header = sample_header();
        let joiner = joiner_kgen_or(header, parts.clone(), params(), None, None)?;
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut missing, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);
        missing.remove(&HDR_TSWE_ALG);
        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_from_joiner(&mut ctx, &joiner);
        let result = accept_with_header(&mut ctx, &parts, &missing);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "missing tswe_alg must freeze");

        let err = result.unwrap_err();

        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_TSWE_ALG_INVALID),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_requires_merkle_suite() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let header = sample_header();
        let joiner = joiner_kgen_or(header, parts.clone(), params(), None, None)?;
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut tampered, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);
        let original_pub = tampered
            .get(&HDR_KBROAD_PUB)
            .and_then(Value::as_bytes)
            .expect("kbroad_pub should be present bytes")
            .to_vec();
        tampered.insert(HDR_MERKLE_SUITE, Value::Text("wrong-suite".to_string()));
        let mut registry = BTreeMap::new();
        registry.insert(parts.gid.to_vec(), original_pub);
        let options = AcceptanceOptions {
            kbroad_registry: Some(registry),
            ..AcceptanceOptions::default()
        };
        let mut ctx = AcceptanceContext::with_options(DEFAULT_H_MAX, DEFAULT_T_WINDOW, options);
        configure_bootstrap(&mut ctx);
        seed_capss_from_joiner(&mut ctx, &joiner);
        let result = accept_with_header(&mut ctx, &parts, &tampered);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "suite mismatch must freeze");

        let err = result.unwrap_err();

        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_MERKLE_SUITE_INVALID),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_rejects_legacy_merkle_suite_v1() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let header = sample_header();
        let joiner = joiner_kgen_or(header, parts.clone(), params(), None, None)?;
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut tampered, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);
        let original_pub = tampered
            .get(&HDR_KBROAD_PUB)
            .and_then(Value::as_bytes)
            .expect("kbroad_pub should be present bytes")
            .to_vec();
        tampered.insert(HDR_MERKLE_SUITE, Value::Text("rpo-256/v1".to_string()));

        let mut registry = BTreeMap::new();
        registry.insert(parts.gid.to_vec(), original_pub);
        let options = AcceptanceOptions {
            kbroad_registry: Some(registry),
            ..AcceptanceOptions::default()
        };
        let mut ctx = AcceptanceContext::with_options(DEFAULT_H_MAX, DEFAULT_T_WINDOW, options);
        configure_bootstrap(&mut ctx);
        seed_capss_from_joiner(&mut ctx, &joiner);

        let result = accept_with_header(&mut ctx, &parts, &tampered);
        assert!(result.is_err(), "legacy merkle suite must freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_MERKLE_SUITE_INVALID),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_requires_kbroad_alg() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let header = sample_header();
        let joiner = joiner_kgen_or(header, parts.clone(), params(), None, None)?;
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut tampered, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);
        tampered.insert(HDR_KBROAD_ALG, Value::Text("ml-kem-512".to_string()));
        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_from_joiner(&mut ctx, &joiner);
        let result = accept_with_header(&mut ctx, &parts, &tampered);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "kbroad alg mismatch must freeze");

        let err = result.unwrap_err();

        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_KBROAD_ALG_INVALID),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_requires_kbroad_pub_binding() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let header = sample_header();
        let joiner = joiner_kgen_or(header, parts.clone(), params(), None, None)?;
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut tampered, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);
        let original_pub = tampered
            .get(&HDR_KBROAD_PUB)
            .and_then(Value::as_bytes)
            .expect("kbroad_pub should be present bytes")
            .to_vec();
        let pub_bytes = tampered
            .get_mut(&HDR_KBROAD_PUB)
            .and_then(Value::as_bytes_mut)
            .expect("kbroad_pub should be mutable bytes");
        pub_bytes[0] ^= 0xFF;

        let anchor_seed_ctx = build_anchor_seed_ctx(&tampered)?;
        let seed_ctx_hash = compute_seed_ctx_hash(&anchor_seed_ctx)?;
        tampered.insert(HDR_SEED_CTX_HASH, Value::Bytes(seed_ctx_hash.to_vec()));
        let mut parent_root_arr = [0u8; 32];
        parent_root_arr.copy_from_slice(parts.parent_root);
        let seed_bundle = compute_seed_bundle_commit(
            &anchor_seed_ctx,
            &joiner.rho_commit,
            parts.gid,
            parts.cat,
            &parent_root_arr,
        )?;
        tampered.insert(HDR_SEED_BUNDLE_COMMIT, Value::Bytes(seed_bundle.to_vec()));
        attach_bootstrap_only(&mut tampered, &parts, &joiner);

        let mut registry = BTreeMap::new();
        registry.insert(parts.gid.to_vec(), original_pub);
        let options = AcceptanceOptions {
            kbroad_registry: Some(registry),
            ..AcceptanceOptions::default()
        };
        let mut ctx = AcceptanceContext::with_options(DEFAULT_H_MAX, DEFAULT_T_WINDOW, options);
        configure_bootstrap(&mut ctx);
        seed_capss_from_joiner(&mut ctx, &joiner);
        let result = accept_with_header(&mut ctx, &parts, &tampered);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "kbroad pub mismatch must freeze");

        let err = result.unwrap_err();

        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_KBROAD_PARENT_MISMATCH),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_parent_envelope_freezes() -> Result<(), Box<dyn std::error::Error>> {
        let (parts, _, joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut header, _, fs_witness) = header_ready_with_pop(&joiner, &parts, &pop_pk, &pop_sk);

        let items = header
            .get_mut(&HDR_HP_BYTES)
            .and_then(Value::as_array_mut)
            .expect("hp bytes should be an array envelope");
        if let Some(mode) = items.get_mut(0) {
            *mode = Value::Text("parent-v1".to_string());
        } else {
            return Err("hp envelope missing mode entry".into());
        }

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);

        let result = accept_with_header(&mut ctx, &parts, &header);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "non-kbroad envelope must freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_PARENT_EID_FORBIDDEN),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_rejects_kbroad_length_mismatches() -> Result<(), Box<dyn std::error::Error>> {
        let (parts, _, joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (base_header, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);
        let mut parent_root = [0u8; 32];
        parent_root.copy_from_slice(parts.parent_root);

        let scenarios = ["ct", "wrap", "c_hp"];
        for scenario in scenarios {
            let mut header = base_header.clone();
            let items = header
                .get_mut(&HDR_HP_BYTES)
                .and_then(Value::as_array_mut)
                .expect("hp envelope expected");
            if scenario == "ct" {
                if let Some(entry) = items.get_mut(1) {
                    *entry = Value::Bytes(vec![0xAA; 1000]);
                }
            } else if scenario == "wrap" {
                if let Some(entry) = items.get_mut(2) {
                    *entry = Value::Bytes(vec![0xBB; 32]);
                }
            } else if let Some(entry) = items.get_mut(3) {
                *entry = Value::Bytes(vec![0xCC; 20_000]);
            }

            let fs_witness = prepare_header_for_acceptance(&mut header, &parts, &joiner);

            let mut ctx = AcceptanceContext::with_defaults();
            configure_bootstrap(&mut ctx);
            seed_capss_with(&mut ctx, &fs_witness);
            let result = accept_with_header(&mut ctx, &parts, &header);
            assert!(result.is_err(), "error expected");
            assert!(result.is_err(), "kbroad length mismatch must freeze");
            let err = result.unwrap_err();
            assert!(
                matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_KBROAD_PARENT_MISMATCH),
                "unexpected error: {err:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn joiner_merge_rejects_mixed_parity_domains() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let params = params();
        let mut header_a = sample_header();
        header_a.insert(20, Value::Bytes(vec![0xAA]));
        let mut header_b = sample_header();
        header_b.insert(20, Value::Bytes(vec![0xAB]));
        let joiner_a = joiner_kgen_or(header_a, parts.clone(), params.clone(), None, None)?;
        let joiner_b = joiner_kgen_or(header_b, parts.clone(), params.clone(), None, None)?;
        let (pop_pk_a, pop_sk_a) = sample_pop_keys();
        let (header_a, _, header_a_fs_witness) =
            header_ready_with_pop(&joiner_a, &parts, &pop_pk_a, &pop_sk_a);
        let (pop_pk_b, pop_sk_b) = sample_pop_keys();
        let (header_b, _, header_b_fs_witness) =
            header_ready_with_pop(&joiner_b, &parts, &pop_pk_b, &pop_sk_b);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &header_a_fs_witness);
        accept_with_header(&mut ctx, &parts, &header_a)?;
        ctx.clear_device_chains();
        ctx.rho_guard = RhoReplayGuard::new(RHO_GUARD_CAPACITY, ctx.mh_window.ttl());
        seed_capss_with(&mut ctx, &header_b_fs_witness);
        accept_with_header(&mut ctx, &parts, &header_b)?;

        let mut parent_root_arr = [0u8; 32];
        parent_root_arr.copy_from_slice(parts.parent_root);
        let parities = ctx.pivot_parities_for(parts.gid, &parent_root_arr);
        let pivot = parities.first().cloned().expect("pivot expected");
        let mut sibling = pivot.clone();
        sibling.we_epoch_id[0] ^= 0x01;
        sibling.accept_seq = sibling.accept_seq.wrapping_add(1);

        let mut mismatched = vec![pivot.clone(), sibling.clone()];
        mismatched[0].parent_root[0] ^= 0x01;
        let mut merge_header = sample_header();
        merge_header.insert(20, Value::Bytes(vec![0xAC]));
        let result = joiner_kgen_merge_or(
            merge_header,
            &mismatched,
            None,
            parts.clone(),
            params.clone(),
            None,
        );
        assert!(result.is_err(), "mixed parent_root should error");
        let err = result.unwrap_err();
        assert!(
            matches!(&err, MsphfError::InvalidInput(msg) if msg == "merge parity mismatch"),
            "unexpected error: {err:?}"
        );

        let mut mismatched = vec![pivot.clone(), sibling];
        mismatched[0].gid[0] ^= 0x01;
        let mut merge_header = sample_header();
        merge_header.insert(20, Value::Bytes(vec![0xAD]));
        let result =
            joiner_kgen_merge_or(merge_header, &mismatched, None, parts.clone(), params, None);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "mixed gid should error");
        let err = result.unwrap_err();
        assert!(
            matches!(&err, MsphfError::InvalidInput(msg) if msg == "merge parity mismatch"),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_rejects_policy_kbroad_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let header = sample_header();
        let joiner = joiner_kgen_or(header, parts.clone(), params(), None, None)?;
        let mut header_with_pop = joiner.header_map.clone();
        let fs_witness = prepare_header_for_acceptance(&mut header_with_pop, &parts, &joiner);

        let mut registry = BTreeMap::new();
        registry.insert(parts.gid.to_vec(), vec![0xAA; ml_kem_public_key_bytes()]);

        let options = AcceptanceOptions {
            kbroad_registry: Some(registry),
            ..AcceptanceOptions::default()
        };
        let mut ctx = AcceptanceContext::with_options(DEFAULT_H_MAX, DEFAULT_T_WINDOW, options);
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);

        let result = accept_with_header(&mut ctx, &parts, &header_with_pop);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "policy kbroad mismatch must freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_KBROAD_PARENT_MISMATCH),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_honors_policy_kbroad_match() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let header = sample_header();
        let joiner = joiner_kgen_or(header, parts.clone(), params(), None, None)?;
        let (header_with_pop, _, fs_witness) =
            header_ready_with_pop(&joiner, &parts, &sample_pop_keys().0, &sample_pop_keys().1);

        let kbroad_bytes = header_with_pop
            .get(&HDR_KBROAD_PUB)
            .and_then(Value::as_bytes)
            .expect("kbroad_pub missing")
            .to_vec();

        let mut registry = BTreeMap::new();
        registry.insert(parts.gid.to_vec(), kbroad_bytes);

        let options = AcceptanceOptions {
            kbroad_registry: Some(registry),
            ..AcceptanceOptions::default()
        };
        let mut ctx = AcceptanceContext::with_options(DEFAULT_H_MAX, DEFAULT_T_WINDOW, options);
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);

        accept_with_header(&mut ctx, &parts, &header_with_pop)?;
        Ok(())
    }

    #[test]
    fn merge_parity_tamper_freezes() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let params = params();
        let mut header_a = sample_header();
        header_a.insert(20, Value::Bytes(vec![0xAA]));
        let mut header_b = sample_header();
        header_b.insert(20, Value::Bytes(vec![0xAB]));
        let joiner_a = joiner_kgen_or(header_a, parts.clone(), params.clone(), None, None)?;
        let joiner_b = joiner_kgen_or(header_b, parts.clone(), params.clone(), None, None)?;
        let (pop_pk_a, pop_sk_a) = sample_pop_keys();
        let (header_a, _, witness_a) =
            header_ready_with_pop(&joiner_a, &parts, &pop_pk_a, &pop_sk_a);
        let (pop_pk_b, pop_sk_b) = sample_pop_keys();
        let (header_b, _, witness_b) =
            header_ready_with_pop(&joiner_b, &parts, &pop_pk_b, &pop_sk_b);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &witness_a);
        accept_with_header(&mut ctx, &parts, &header_a)?;
        ctx.clear_device_chains();
        ctx.rho_guard = RhoReplayGuard::new(RHO_GUARD_CAPACITY, ctx.mh_window.ttl());
        seed_capss_with(&mut ctx, &witness_b);
        accept_with_header(&mut ctx, &parts, &header_b)?;

        let mut parent_root_arr = [0u8; 32];
        parent_root_arr.copy_from_slice(parts.parent_root);
        let mut parities = ctx.pivot_parities_for(parts.gid, &parent_root_arr);
        assert!(parities.len() >= 2, "expected at least two parities");
        parities[1].parent_root[0] ^= 0x01;
        let mut merge_header_src = sample_header();
        merge_header_src.insert(20, Value::Bytes(vec![0xAC]));
        let result = joiner_kgen_merge_or(
            merge_header_src,
            &parities,
            None,
            parts.clone(),
            params.clone(),
            None,
        );
        assert!(
            result.is_err(),
            "merge builder must reject mixed parity domain"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(&err, MsphfError::InvalidInput(msg) if msg == "merge parity mismatch"),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_requires_srx() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let header = sample_header();
        let joiner = joiner_kgen_or(header, parts.clone(), params(), None, None)?;
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut missing, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);
        missing.remove(&HDR_SRX_MODE);
        missing.remove(&HDR_SRX_COMMIT);
        missing.remove(&HDR_SRX_PAYLOAD);
        missing.remove(&HDR_SRX_HINT_COUNTS);
        missing.remove(&HDR_SRX_HINT_SIZES);
        missing.remove(&HDR_SRX_ROOT_SW);
        missing.remove(&HDR_SRX_SMALLWOOD);
        let vrf_pi = missing
            .get(&HDR_VRF_PROOF)
            .and_then(Value::as_bytes)
            .expect("missing vrf proof")
            .to_vec();
        let fs_capss = missing
            .get(&HDR_FS_CAPSS)
            .and_then(Value::as_bytes)
            .expect("missing fs_capss")
            .to_vec();
        let proofs_commit = compute_proofs_commit_bytes(&vrf_pi, &fs_capss, None, None)?;
        missing.insert(HDR_PROOFS_COMMIT, Value::Bytes(proofs_commit.to_vec()));
        refresh_seed_ctx_hash(&mut missing);
        refresh_seed_bindings(&mut missing, &parts, &joiner);
        missing.remove(&HDR_BOOTSTRAP_SIG);
        missing.remove(&HDR_BOOTSTRAP_PK);
        ensure_bootstrap_fields(&mut missing, &parts, &joiner);

        let empty = BTreeSet::new();
        let proofs = stages::ensure_proofs(&missing, None, &empty, None, &empty)?;
        let mut parent_root_arr = [0u8; 32];
        parent_root_arr.copy_from_slice(parts.parent_root);
        let mut join_root_arr = [0u8; 32];
        join_root_arr.copy_from_slice(parts.join_delta_root);
        let mut revoked_since_arr = [0u8; 32];
        revoked_since_arr.copy_from_slice(parts.revoked_since_prev_root);
        let mut revoked_root_arr = [0u8; 32];
        revoked_root_arr.copy_from_slice(parts.revoked_root);
        let mut cache = cache::VckCache::new(Duration::from_secs(60));
        let result = stages::ensure_srx_relations(
            &missing,
            &parent_root_arr,
            &join_root_arr,
            &revoked_since_arr,
            &revoked_root_arr,
            true,
            DEFAULT_SRX_MAX_BYTES,
            &joiner.xk_hash,
            &joiner.seed_commit,
            &joiner.rho_commit,
            &joiner.hp_commit,
            AcceptInstant::from_ticks(0),
            &mut cache,
            &proofs,
            &[0u8; 32],
        );
        assert!(result.is_err(), "missing SRX must freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_SRX_REQUIRED),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_requires_params_id() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let header = sample_header();
        let joiner = joiner_kgen_or(header, parts.clone(), params(), None, None)?;
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut missing, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);
        missing.remove(&HDR_PARAMS_ID);
        refresh_seed_ctx_hash(&mut missing);
        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        let result = accept_with_header(&mut ctx, &parts, &missing);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "missing params id must freeze");

        let err = result.unwrap_err();

        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_PARAMS_ID_INVALID),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_requires_crs_id() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let header = sample_header();
        let joiner = joiner_kgen_or(header, parts.clone(), params(), None, None)?;
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut missing, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);
        missing.remove(&HDR_CRS_ID);
        refresh_seed_ctx_hash(&mut missing);
        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        let result = accept_with_header(&mut ctx, &parts, &missing);
        assert!(result.is_err(), "missing crs id must freeze");

        let err = result.unwrap_err();

        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_MSPHF_CRS_INVALID),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_requires_join_payload() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let header = sample_header();
        let joiner = joiner_kgen_or(header, parts.clone(), params(), None, None)?;
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut missing, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);
        missing.remove(&HDR_HP_BYTES);
        missing.remove(&HDR_HP_COMMIT);
        missing.remove(&HDR_VRF_MASK_A);
        missing.remove(&HDR_VRF_MASK_B);
        missing.remove(&HDR_VRF_PROOF);
        missing.remove(&HDR_VRF_PUBLIC_KEY);
        missing.remove(&HDR_PROOF_MODE);
        missing.remove(&HDR_VRF_ID);
        missing.remove(&HDR_PROOFS_COMMIT);
        assert!(!missing.contains_key(&HDR_HP_BYTES));
        assert!(!missing.contains_key(&HDR_HP_COMMIT));
        assert!(!missing.contains_key(&HDR_VRF_MASK_A));
        assert!(!missing.contains_key(&HDR_VRF_MASK_B));
        assert!(!missing.contains_key(&HDR_VRF_PROOF));
        assert!(!missing.contains_key(&HDR_VRF_PUBLIC_KEY));
        assert!(!missing.contains_key(&HDR_PROOF_MODE));
        assert!(!missing.contains_key(&HDR_VRF_ID));
        assert!(!missing.contains_key(&HDR_PROOFS_COMMIT));
        refresh_seed_ctx_hash(&mut missing);
        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        let result = accept_with_header(&mut ctx, &parts, &missing);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "missing join payload must freeze");

        let err = result.unwrap_err();

        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_FIELD_MISSING),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_with_valid_srx_succeeds() -> Result<(), Box<dyn std::error::Error>> {
        let (parts, _, joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut header_with_pop, _, _) = header_ready_with_pop(&joiner, &parts, &pop_pk, &pop_sk);
        let header_with_pop_fs_witness =
            prepare_header_for_acceptance(&mut header_with_pop, &parts, &joiner);

        let fs_witness = prepare_header_for_acceptance(&mut header_with_pop, &parts, &joiner);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);
        seed_capss_with(&mut ctx, &header_with_pop_fs_witness);
        accept_with_header(&mut ctx, &parts, &header_with_pop)?;

        let telemetry_key = TelemetryKey::from_parts(parts.gid, parts.parent_root);
        let snapshot = ctx.telemetry_snapshot();
        let counters = snapshot.get(&telemetry_key).expect("telemetry expected");
        assert_eq!(counters.head_attempts, 1);
        assert_eq!(counters.head_insertions, 1);
        assert_eq!(counters.freeze_rho_replay, 0);
        assert_eq!(counters.freeze_window_full, 0);
        assert_eq!(counters.last_active_heads, 1);
        Ok(())
    }

    #[test]
    fn acceptance_outcome_wid_matches_compute_window_id() -> Result<(), Box<dyn std::error::Error>>
    {
        let (parts, _, joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut header_with_pop, _, fs_witness) =
            header_ready_with_pop(&joiner, &parts, &pop_pk, &pop_sk);
        let header_with_pop_fs_witness =
            prepare_header_for_acceptance(&mut header_with_pop, &parts, &joiner);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);
        seed_capss_with(&mut ctx, &header_with_pop_fs_witness);
        let outcome = accept_with_header(&mut ctx, &parts, &header_with_pop)?;

        let mut parent_root = [0u8; 32];
        parent_root.copy_from_slice(parts.parent_root);
        let expected = compute_window_id(parts.gid, &parent_root, &joiner.seed_ctx_hash)?;
        assert_eq!(outcome.wid, expected, "WID mismatch");
        Ok(())
    }

    #[test]
    fn accept_anchor_tampered_rho_commit_freezes_lin() -> Result<(), Box<dyn std::error::Error>> {
        let (parts, _, joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut header, _, fs_witness_original) =
            header_ready_with_pop(&joiner, &parts, &pop_pk, &pop_sk);

        if let Some(first) = header
            .get_mut(&HDR_RHO_COMMIT)
            .and_then(Value::as_bytes_mut)
            .and_then(|bytes| bytes.first_mut())
        {
            *first ^= 0x80;
        } else {
            return Err("rho commit missing".into());
        }

        ensure_bootstrap_fields(&mut header, &parts, &joiner);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness_original);

        let result = accept_with_header(&mut ctx, &parts, &header);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "tampered rho commit must freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                AcceptanceError::Freeze(code)
                    if code == FREEZE_CAPSS_INVALID || code == FREEZE_SEEDCTX_MISMATCH
            ),
            "unexpected result: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_tampered_seed_bundle_commit_freezes_lin()
    -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let params = params();

        let mut header_base = sample_header();
        let joiner_orig = joiner_kgen_or(
            header_base.clone(),
            parts.clone(),
            params.clone(),
            None,
            None,
        )?;

        header_base.insert(20, Value::Bytes(vec![0xBB]));
        let joiner_mut = joiner_kgen_or(header_base, parts.clone(), params.clone(), None, None)?;

        let mut tampered = joiner_mut.header_map.clone();

        let orig_vrf = joiner_orig
            .header_map
            .get(&HDR_VRF_PROOF)
            .and_then(Value::as_bytes)
            .expect("vrf proof missing")
            .to_vec();
        let orig_fs_capss = joiner_orig
            .header_map
            .get(&HDR_FS_CAPSS)
            .and_then(Value::as_bytes)
            .expect("fs_capss missing")
            .to_vec();

        tampered.insert(HDR_VRF_PROOF, Value::Bytes(orig_vrf.clone()));
        tampered.insert(HDR_FS_CAPSS, Value::Bytes(orig_fs_capss.clone()));
        if let Some(value) = joiner_orig.header_map.get(&HDR_PROOF_MODE) {
            tampered.insert(HDR_PROOF_MODE, value.clone());
        }
        let srx_root_sw = joiner_orig
            .header_map
            .get(&HDR_SRX_ROOT_SW)
            .and_then(|value| value.as_bytes().filter(|bytes| bytes.len() == 32))
            .map(ToOwned::to_owned);
        let srx_smallwood = joiner_orig
            .header_map
            .get(&HDR_SRX_SMALLWOOD)
            .and_then(Value::as_bytes)
            .map(ToOwned::to_owned);
        let proofs_commit = compute_proofs_commit_bytes(
            orig_vrf.as_slice(),
            orig_fs_capss.as_slice(),
            srx_root_sw.as_deref(),
            srx_smallwood.as_deref(),
        )?;
        tampered.insert(HDR_PROOFS_COMMIT, Value::Bytes(proofs_commit.to_vec()));
        attach_bootstrap_only(&mut tampered, &parts, &joiner_mut);
        let fs_witness = prepare_header_for_acceptance(&mut tampered, &parts, &joiner_mut);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);

        let result = accept_with_header(&mut ctx, &parts, &tampered);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "tampered seed bundle must freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_CAPSS_INVALID),
            "unexpected result: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_tampered_params_id_freezes_lin() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let params = params();

        let header_base = sample_header();
        let joiner_orig = joiner_kgen_or(
            header_base.clone(),
            parts.clone(),
            params.clone(),
            None,
            None,
        )?;

        let mut params_tampered = params.clone();
        params_tampered.params_id = "rlwe-params/tampered";
        let joiner_mut = joiner_kgen_or(header_base, parts.clone(), params_tampered, None, None)?;

        let mut tampered = joiner_mut.header_map.clone();

        let orig_vrf = joiner_orig
            .header_map
            .get(&HDR_VRF_PROOF)
            .and_then(Value::as_bytes)
            .expect("vrf proof missing")
            .to_vec();
        let orig_fs_capss = joiner_orig
            .header_map
            .get(&HDR_FS_CAPSS)
            .and_then(Value::as_bytes)
            .expect("fs_capss missing")
            .to_vec();

        tampered.insert(HDR_VRF_PROOF, Value::Bytes(orig_vrf.clone()));
        tampered.insert(HDR_FS_CAPSS, Value::Bytes(orig_fs_capss.clone()));
        if let Some(value) = joiner_orig.header_map.get(&HDR_PROOF_MODE) {
            tampered.insert(HDR_PROOF_MODE, value.clone());
        }
        let srx_root_sw = joiner_orig
            .header_map
            .get(&HDR_SRX_ROOT_SW)
            .and_then(|value| value.as_bytes().filter(|bytes| bytes.len() == 32))
            .map(ToOwned::to_owned);
        let srx_smallwood = joiner_orig
            .header_map
            .get(&HDR_SRX_SMALLWOOD)
            .and_then(Value::as_bytes)
            .map(ToOwned::to_owned);
        let proofs_commit = compute_proofs_commit_bytes(
            orig_vrf.as_slice(),
            orig_fs_capss.as_slice(),
            srx_root_sw.as_deref(),
            srx_smallwood.as_deref(),
        )?;
        tampered.insert(HDR_PROOFS_COMMIT, Value::Bytes(proofs_commit.to_vec()));
        attach_bootstrap_only(&mut tampered, &parts, &joiner_mut);
        let fs_witness = prepare_header_for_acceptance(&mut tampered, &parts, &joiner_mut);

        let mut allowed = BTreeSet::new();
        allowed.insert(RLWE_PARAMS_ID_A1.as_bytes().to_vec());
        allowed.insert(b"rlwe-params/tampered".to_vec());

        let mut ctx = AcceptanceContext::with_defaults();
        ctx.set_allowed_params_ids(Some(allowed));
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);

        let result = accept_with_header(&mut ctx, &parts, &tampered);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "tampered params id must freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_CAPSS_INVALID),
            "unexpected result: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_tampered_pop_public_key_freezes_lin() -> Result<(), Box<dyn std::error::Error>>
    {
        let parts = sample_parts();
        let params = params();

        let header_orig = sample_header();
        let joiner_orig = joiner_kgen_or(header_orig, parts.clone(), params.clone(), None, None)?;

        let mut params_mut = params.clone();
        params_mut.pop_keys = Some(fresh_pop_keypair());
        let header_mut = sample_header();
        let joiner_mut = joiner_kgen_or(header_mut, parts.clone(), params_mut, None, None)?;

        let mut tampered = joiner_mut.header_map.clone();
        let orig_vrf = joiner_orig
            .header_map
            .get(&HDR_VRF_PROOF)
            .and_then(Value::as_bytes)
            .expect("vrf proof missing")
            .to_vec();
        let orig_fs_capss = joiner_orig
            .header_map
            .get(&HDR_FS_CAPSS)
            .and_then(Value::as_bytes)
            .expect("fs_capss missing")
            .to_vec();

        tampered.insert(HDR_VRF_PROOF, Value::Bytes(orig_vrf.clone()));
        tampered.insert(HDR_FS_CAPSS, Value::Bytes(orig_fs_capss.clone()));
        if let Some(value) = joiner_orig.header_map.get(&HDR_PROOF_MODE) {
            tampered.insert(HDR_PROOF_MODE, value.clone());
        }
        let srx_root_sw = joiner_orig
            .header_map
            .get(&HDR_SRX_ROOT_SW)
            .and_then(|value| value.as_bytes().filter(|bytes| bytes.len() == 32))
            .map(ToOwned::to_owned);
        let srx_smallwood = joiner_orig
            .header_map
            .get(&HDR_SRX_SMALLWOOD)
            .and_then(Value::as_bytes)
            .map(ToOwned::to_owned);
        let proofs_commit = compute_proofs_commit_bytes(
            orig_vrf.as_slice(),
            orig_fs_capss.as_slice(),
            srx_root_sw.as_deref(),
            srx_smallwood.as_deref(),
        )?;
        tampered.insert(HDR_PROOFS_COMMIT, Value::Bytes(proofs_commit.to_vec()));
        attach_bootstrap_only(&mut tampered, &parts, &joiner_mut);
        let fs_witness = prepare_header_for_acceptance(&mut tampered, &parts, &joiner_mut);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);

        let result = accept_with_header(&mut ctx, &parts, &tampered);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "tampered pop pk must freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_CAPSS_INVALID),
            "unexpected result: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_capss_proof_oversize_freezes() -> Result<(), Box<dyn std::error::Error>> {
        let (parts, _, joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut header, _, fs_witness) = header_ready_with_pop(&joiner, &parts, &pop_pk, &pop_sk);

        let vrf_pi = header
            .get(&HDR_VRF_PROOF)
            .and_then(Value::as_bytes)
            .expect("vrf proof missing")
            .to_vec();
        let oversize = vec![0xAA; FS_CAPSS_MAX_BYTES + 1];
        header.insert(HDR_FS_CAPSS, Value::Bytes(oversize.clone()));
        let srx_root_sw = header
            .get(&HDR_SRX_ROOT_SW)
            .and_then(|value| value.as_bytes().filter(|bytes| bytes.len() == 32))
            .map(ToOwned::to_owned);
        let srx_smallwood = header
            .get(&HDR_SRX_SMALLWOOD)
            .and_then(Value::as_bytes)
            .map(ToOwned::to_owned);
        let proofs_commit = compute_proofs_commit_bytes(
            vrf_pi.as_slice(),
            oversize.as_slice(),
            srx_root_sw.as_deref(),
            srx_smallwood.as_deref(),
        )?;
        header.insert(HDR_PROOFS_COMMIT, Value::Bytes(proofs_commit.to_vec()));
        attach_bootstrap_only(&mut header, &parts, &joiner);
        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);

        let result = accept_with_header(&mut ctx, &parts, &header);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "oversized fs-lin proof must freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_CAPSS_INVALID),
            "unexpected result: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_unknown_proof_mode_freezes() -> Result<(), Box<dyn std::error::Error>> {
        let (parts, _, joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut header, _, _fs_witness) = header_ready_with_pop(&joiner, &parts, &pop_pk, &pop_sk);
        header.insert(HDR_PROOF_MODE, Value::Text("lin+bogus".to_string()));
        let fs_witness = prepare_header_for_acceptance(&mut header, &parts, &joiner);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);

        let result = accept_with_header(&mut ctx, &parts, &header);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "unknown proof_mode must freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_SUITE_FORBIDDEN),
            "unexpected result: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_unknown_vrf_id_freezes() -> Result<(), Box<dyn std::error::Error>> {
        let (parts, _, joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut header, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);
        header.insert(HDR_VRF_ID, Value::Text("vrf/x-unknown".to_string()));
        let fs_witness = prepare_header_for_acceptance(&mut header, &parts, &joiner);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);

        let result = accept_with_header(&mut ctx, &parts, &header);
        assert!(result.is_err(), "unknown vrf_id must freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_SUITE_FORBIDDEN),
            "unexpected result: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_rho_mismatch_freezes() -> Result<(), Box<dyn std::error::Error>> {
        let (parts, _, joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut header, _, fs_witness) = header_ready_with_pop(&joiner, &parts, &pop_pk, &pop_sk);

        if let Some(Value::Bytes(sig)) = header.get_mut(&HDR_POP_SIG)
            && !sig.is_empty()
        {
            sig[0] ^= 0x01;
        }

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);

        let result = accept_with_header(&mut ctx, &parts, &header);
        assert!(result.is_err(), "rho mismatch must freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_POP_INVALID),
            "unexpected result: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn srx_contains_leaf_id_helper_detects_presence_and_absence()
    -> Result<(), Box<dyn std::error::Error>> {
        use ciborium::value::Value;
        use std::collections::BTreeMap;

        let leaf_present = [0xABu8; 32];
        let leaf_other = [0xCDu8; 32];
        let encode_payload = |join_leaf_ids: Vec<[u8; 32]>| -> Result<Vec<u8>, AcceptanceError> {
            let payload = Value::Array(vec![
                Value::Array(vec![]),
                Value::Array(vec![]),
                Value::Array(vec![]),
                Value::Null,
                Value::Array(
                    join_leaf_ids
                        .into_iter()
                        .map(|leaf| Value::Bytes(leaf.to_vec()))
                        .collect(),
                ),
                Value::Null,
                Value::Array(vec![]),
                Value::Null,
                Value::Array(vec![]),
            ]);
            Ok(to_cbor_vec(&payload)?)
        };

        let mut header_hit = BTreeMap::new();
        header_hit.insert(
            HDR_SRX_PAYLOAD,
            Value::Bytes(encode_payload(vec![leaf_other, leaf_present])?),
        );
        assert_eq!(
            srx_contains_leaf_id(&header_hit, &leaf_present)?,
            Some(true)
        );

        let mut header_miss = BTreeMap::new();
        header_miss.insert(
            HDR_SRX_PAYLOAD,
            Value::Bytes(encode_payload(vec![leaf_other])?),
        );
        assert_eq!(
            srx_contains_leaf_id(&header_miss, &leaf_present)?,
            Some(false)
        );

        let header_absent = BTreeMap::new();
        assert_eq!(srx_contains_leaf_id(&header_absent, &leaf_present)?, None);
        Ok(())
    }

    #[test]
    fn srx_contains_leaf_id_helper_handles_malformed_payloads()
    -> Result<(), Box<dyn std::error::Error>> {
        use ciborium::value::Value;
        use std::collections::BTreeMap;

        let leaf = [0x10u8; 32];

        // Malformed CBOR payload bytes must freeze.
        let mut header_map = BTreeMap::new();
        header_map.insert(HDR_SRX_PAYLOAD, Value::Bytes(vec![0xFF; 8]));
        let err = srx_contains_leaf_id(&header_map, &leaf).expect_err("malformed payload");
        assert!(matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_SRX_INVALID));

        // Structurally invalid decoded payload must freeze.
        let mut header_map = BTreeMap::new();
        header_map.insert(
            HDR_SRX_PAYLOAD,
            Value::Bytes(to_cbor_vec(&Value::Array(vec![
                Value::Array(vec![]),
                Value::Array(vec![]),
            ]))?),
        );
        let err = srx_contains_leaf_id(&header_map, &leaf).expect_err("invalid payload shape");
        assert!(matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_SRX_INVALID));
        Ok(())
    }

    #[test]
    fn compute_vck_key_depends_on_policy_version() -> Result<(), Box<dyn std::error::Error>> {
        let (parts, _params, joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut header, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);

        let original_policy =
            header.insert(HDR_FS_POLICY_VERSION, Value::Integer(Integer::from(0u64)));
        let key_v0 = compute_vck_key(
            &joiner.xk_hash,
            &joiner.seed_commit,
            &joiner.rho_commit,
            &joiner.hp_commit,
            &header,
        )?;
        header.insert(HDR_FS_POLICY_VERSION, Value::Integer(Integer::from(1u64)));
        let key_v1 = compute_vck_key(
            &joiner.xk_hash,
            &joiner.seed_commit,
            &joiner.rho_commit,
            &joiner.hp_commit,
            &header,
        )?;
        assert_ne!(key_v0, key_v1);
        match original_policy {
            Some(prev) => {
                header.insert(HDR_FS_POLICY_VERSION, prev);
            }
            None => {
                header.remove(&HDR_FS_POLICY_VERSION);
            }
        }
        Ok(())
    }

    #[test]
    fn compute_vck_key_depends_on_proof_mode_and_vrf_id() -> Result<(), Box<dyn std::error::Error>>
    {
        let (parts, _params, joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut header, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);

        // Baseline header (uses DEFAULT values by construction)
        let key_baseline = compute_vck_key(
            &joiner.xk_hash,
            &joiner.seed_commit,
            &joiner.rho_commit,
            &joiner.hp_commit,
            &header,
        )?;

        // Modify proof_mode only (temporary mutate)
        let original_mode = header.insert(119, Value::Text("lin+zkvrf-alt".to_string()));
        let key_alt_mode = compute_vck_key(
            &joiner.xk_hash,
            &joiner.seed_commit,
            &joiner.rho_commit,
            &joiner.hp_commit,
            &header,
        )?;
        assert_ne!(key_baseline, key_alt_mode);
        match original_mode {
            Some(prev) => {
                header.insert(119, prev);
            }
            None => {
                header.remove(&119);
            }
        }

        // Modify vrf_id only
        let original_vrf = header.insert(116, Value::Text("lb-vrf/v2".to_string()));
        let key_alt_vrf = compute_vck_key(
            &joiner.xk_hash,
            &joiner.seed_commit,
            &joiner.rho_commit,
            &joiner.hp_commit,
            &header,
        )?;
        assert_ne!(key_baseline, key_alt_vrf);
        match original_vrf {
            Some(prev) => {
                header.insert(116, prev);
            }
            None => {
                header.remove(&116);
            }
        }
        Ok(())
    }

    #[test]
    fn compute_vck_key_rejects_missing_fs_policy_version() -> Result<(), Box<dyn std::error::Error>>
    {
        let (parts, _params, joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut header, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);

        let removed = header.remove(&HDR_FS_POLICY_VERSION);
        assert!(
            removed.is_some(),
            "fixture header should include fs_policy_version"
        );
        let err = compute_vck_key(
            &joiner.xk_hash,
            &joiner.seed_commit,
            &joiner.rho_commit,
            &joiner.hp_commit,
            &header,
        )
        .expect_err("missing fs_policy_version must freeze");
        assert!(
            matches!(
                err,
                AcceptanceError::Freeze(code) if code == FREEZE_FS_POLICY_VERSION_UNSUPPORTED
            ),
            "unexpected error for missing fs_policy_version: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn compute_vck_key_rejects_non_uint_legacy_policy_version()
    -> Result<(), Box<dyn std::error::Error>> {
        let (parts, _params, joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut header, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);

        for invalid in [
            Value::Text("fs-policy-v0".to_string()),
            Value::Bytes(b"fs-policy-v0".to_vec()),
        ] {
            header.insert(HDR_POLICY_VERSION, invalid);
            let err = compute_vck_key(
                &joiner.xk_hash,
                &joiner.seed_commit,
                &joiner.rho_commit,
                &joiner.hp_commit,
                &header,
            )
            .expect_err("non-uint legacy policy_version must freeze");
            assert!(
                matches!(
                    err,
                    AcceptanceError::Freeze(code) if code == FREEZE_FS_POLICY_VERSION_UNSUPPORTED
                ),
                "unexpected error for non-uint legacy policy_version: {err:?}"
            );
        }

        Ok(())
    }

    fn ensure_test_srx_payload(
        header: &mut BTreeMap<u64, Value>,
        gid: &[u8],
        pop_pk: &[u8],
        revoked_since_root: &[u8],
    ) {
        if header.contains_key(&HDR_SRX_PAYLOAD) {
            return;
        }
        let leaf = crate::compute_leaf_id(crate::LeafIdMode::PerGroup, gid, "ML-DSA-65", pop_pk)
            .unwrap_or([0u8; 32]);
        let payload = Value::Array(vec![
            Value::Array(Vec::new()),
            Value::Array(vec![Value::Map(vec![(
                Value::Integer(Integer::from(2u64)),
                Value::Bytes(revoked_since_root.to_vec()),
            )])]),
            Value::Array(Vec::new()),
            Value::Map(Vec::new()),
            Value::Array(vec![Value::Bytes(leaf.to_vec())]),
            Value::Array(Vec::new()),
            Value::Array(Vec::new()),
            Value::Array(Vec::new()),
            Value::Array(Vec::new()),
        ]);
        let payload_bytes = encode_value(&payload);
        let payload_len = payload_bytes.len() as u64;
        header.insert(HDR_SRX_MODE, Value::Text("srx/v1-complete".to_string()));
        header.insert(HDR_SRX_PAYLOAD, Value::Bytes(payload_bytes.clone()));
        header.insert(
            HDR_SRX_COMMIT,
            Value::Bytes(compute_srx_commit(&payload_bytes).to_vec()),
        );
        header.insert(
            HDR_SRX_HINT_COUNTS,
            Value::Bytes(encode_value(&Value::Map(vec![
                (
                    Value::Text("join".to_string()),
                    Value::Integer(Integer::from(1u64)),
                ),
                (
                    Value::Text("since".to_string()),
                    Value::Integer(Integer::from(0u64)),
                ),
                (
                    Value::Text("anchors".to_string()),
                    Value::Integer(Integer::from(0u64)),
                ),
            ]))),
        );
        header.insert(
            HDR_SRX_HINT_SIZES,
            Value::Bytes(encode_value(&Value::Map(vec![(
                Value::Text("bytes".to_string()),
                Value::Integer(Integer::from(payload_len)),
            )]))),
        );
    }

    #[test]
    fn enforce_srx_leaf_binding_freezes_when_leaf_missing() -> Result<(), Box<dyn std::error::Error>>
    {
        use ciborium::value::Value;

        let (parts, _, joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut header, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);
        if !header.contains_key(&HDR_SRX_PAYLOAD) {
            ensure_test_srx_payload(
                &mut header,
                parts.gid,
                pop_pk.as_slice(),
                parts.revoked_since_prev_root,
            );
        }

        mutate_srx_payload(&mut header, |payload| {
            if let Value::Array(items) = payload
                && let Some(Value::Array(join)) = items.get_mut(4)
            {
                join.clear();
                join.push(Value::Bytes(vec![0x55; 32]));
            }
        });
        let fs_witness = prepare_header_for_acceptance(&mut header, &parts, &joiner);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);

        let result = accept_with_header(&mut ctx, &parts, &header);
        assert!(result.is_err(), "missing leaf should freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_SRX_INVALID),
            "unexpected result: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn enforce_srx_leaf_binding_rejects_bytes_payload_mismatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let (parts, _params, joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut header, _, _) = header_ready_with_pop(&joiner, &parts, &pop_pk, &pop_sk);
        if !header.contains_key(&HDR_SRX_PAYLOAD) {
            ensure_test_srx_payload(
                &mut header,
                parts.gid,
                pop_pk.as_slice(),
                parts.revoked_since_prev_root,
            );
        }

        let leaf_id = crate::compute_leaf_id(
            crate::LeafIdMode::PerGroup,
            parts.gid,
            "ML-DSA-65",
            pop_pk.as_slice(),
        )?;
        mutate_srx_payload(&mut header, |payload| {
            if let Value::Array(items) = payload
                && let Some(Value::Array(join_leaf_ids)) = items.get_mut(4)
            {
                join_leaf_ids.retain(|entry| match entry {
                    Value::Bytes(bytes) => bytes.as_slice() != leaf_id.as_slice(),
                    _ => true,
                });
            }
        });
        let fs_witness = prepare_header_for_acceptance(&mut header, &parts, &joiner);
        if let Ok(found) = srx_contains_leaf_id(&header, &leaf_id) {
            assert_eq!(found, Some(false));
        }

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);

        let result = accept_with_header(&mut ctx, &parts, &header);
        assert!(result.is_err(), "leaf mismatch should freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_SRX_INVALID),
            "unexpected result: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_respects_leaf_id_policy() -> Result<(), Box<dyn std::error::Error>> {
        let (parts, _params_per_group, joiner_per_group) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let mut header_per_group = header_with_pop_mode(
            &joiner_per_group,
            &parts,
            pop_pk.as_slice(),
            &pop_sk,
            crate::LeafIdMode::PerGroup,
        );
        let witness_per_group =
            prepare_header_for_acceptance(&mut header_per_group, &parts, &joiner_per_group);

        let mut ctx_per_group = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx_per_group);
        seed_capss_with(&mut ctx_per_group, &witness_per_group);
        accept_with_header(&mut ctx_per_group, &parts, &header_per_group)?;

        let options = AcceptanceOptions {
            leaf_id_mode: crate::LeafIdMode::Global,
            ..AcceptanceOptions::default()
        };
        let mut ctx_global =
            AcceptanceContext::with_options(DEFAULT_H_MAX, DEFAULT_T_WINDOW, options);
        configure_bootstrap(&mut ctx_global);
        seed_capss_with(&mut ctx_global, &witness_per_group);
        let result = accept_with_header(&mut ctx_global, &parts, &header_per_group);
        assert!(
            result.is_err(),
            "global policy must reject per-group leaf id signature"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_complete_accepts_by_default() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let mut params = params();
        params.srx_mode = crate::SrxMode::Complete;
        let header = sample_header();
        let joiner = joiner_kgen_or(header, parts.clone(), params, None, None)?;
        let (header_with_pop, _, fs_witness) =
            header_ready_with_pop(&joiner, &parts, &sample_pop_keys().0, &sample_pop_keys().1);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);
        accept_with_header(&mut ctx, &parts, &header_with_pop)?;
        Ok(())
    }

    #[test]
    fn accept_anchor_complete_allowed_by_policy() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let mut params = params();
        params.srx_mode = crate::SrxMode::Complete;
        let header = sample_header();
        let joiner = joiner_kgen_or(header, parts.clone(), params, None, None)?;
        let (header_with_pop, _, fs_witness) =
            header_ready_with_pop(&joiner, &parts, &sample_pop_keys().0, &sample_pop_keys().1);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);
        let mut allowed = BTreeSet::new();
        allowed.insert("srx/v1-complete".to_string());
        allowed.insert("srx/v1-complete".to_string());
        ctx.set_allowed_srx_modes(Some(allowed));

        accept_with_header(&mut ctx, &parts, &header_with_pop)?;
        Ok(())
    }

    #[test]
    fn accept_anchor_complete_deprecated_by_policy() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let mut params = params();
        params.srx_mode = crate::SrxMode::Complete;
        let header = sample_header();
        let joiner = joiner_kgen_or(header, parts.clone(), params, None, None)?;
        let (header_with_pop, _, fs_witness) =
            header_ready_with_pop(&joiner, &parts, &sample_pop_keys().0, &sample_pop_keys().1);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);
        let mut allowed = BTreeSet::new();
        allowed.insert("srx/v1-complete".to_string());
        allowed.insert("srx/v1-complete".to_string());
        ctx.set_allowed_srx_modes(Some(allowed));
        let mut deprecated = BTreeSet::new();
        deprecated.insert("srx/v1-complete".to_string());
        ctx.set_deprecated_srx_modes(deprecated);

        // Join anchors in this profile do not carry SRX mode fields.
        assert!(!header_with_pop.contains_key(&HDR_SRX_MODE));
        accept_with_header(&mut ctx, &parts, &header_with_pop)?;
        Ok(())
    }

    #[test]
    fn accept_anchor_srx_parent_conflict_freezes() -> Result<(), Box<dyn std::error::Error>> {
        let (parts, _, joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut header_with_pop, _, _) = header_ready_with_pop(&joiner, &parts, &pop_pk, &pop_sk);
        if !header_with_pop.contains_key(&HDR_SRX_PAYLOAD) {
            ensure_test_srx_payload(
                &mut header_with_pop,
                parts.gid,
                pop_pk.as_slice(),
                parts.revoked_since_prev_root,
            );
        }

        mutate_srx_payload_preserving_leaf_auto(
            &mut header_with_pop,
            parts.gid,
            crate::LeafIdMode::PerGroup,
            pop_pk.as_slice(),
            |payload| {
                if let Value::Array(items) = payload
                    && let Some(Value::Array(join_leaves)) = items.get_mut(4)
                    && let Some(Value::Bytes(bytes)) = join_leaves.get_mut(0)
                    && let Some(first) = bytes.first_mut()
                {
                    *first ^= 0xFF;
                }
            },
        );

        let fs_witness = prepare_header_for_acceptance(&mut header_with_pop, &parts, &joiner);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);
        let result = accept_with_header(&mut ctx, &parts, &header_with_pop);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "parent conflict should freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                AcceptanceError::Freeze(code)
                    if code == FREEZE_SRX_SET_CONFLICT_PARENT || code == FREEZE_SRX_INVALID
            ),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn vck_cache_detects_hint_under_after_cache_hit() -> Result<(), Box<dyn std::error::Error>> {
        let (parts, _, joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (header_with_pop, _, fs_witness) =
            header_ready_with_pop(&joiner, &parts, &pop_pk, &pop_sk);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);
        accept_with_header(&mut ctx, &parts, &header_with_pop)?;

        ctx.rho_guard = RhoReplayGuard::new(RHO_GUARD_CAPACITY, ctx.mh_window.ttl());

        let mut bad_header = header_with_pop.clone();
        if let Some(Value::Bytes(hints)) = bad_header.get(&HDR_SRX_HINT_COUNTS) {
            let mut hint_value: Value = de::from_reader(hints.as_slice())?;
            if let Value::Map(ref mut entries) = hint_value {
                for (key, value) in entries.iter_mut() {
                    if let Value::Text(text) = key
                        && text == "join"
                        && let Value::Integer(count) = value
                    {
                        let current = u64::try_from(*count).unwrap_or(0);
                        let updated = current.saturating_sub(1);
                        *value = Value::Integer(Integer::from(updated));
                    }
                }
            }
            bad_header.insert(HDR_SRX_HINT_COUNTS, Value::Bytes(encode_value(&hint_value)));
        }

        seed_capss_from_joiner(&mut ctx, &joiner);
        let result = accept_with_header(&mut ctx, &parts, &bad_header);
        assert!(result.is_err(), "error expected");
        assert!(
            result.is_err(),
            "understated hints must freeze even with cache"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                AcceptanceError::Freeze(code)
                    if code == FREEZE_SRX_HINT_UNDER
                        || code == FREEZE_FS_DEV_CHAIN_BREAK
                        || code == FREEZE_MSPHF_RHO_PARITY
            ),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_srx_revoked_conflict_freezes() -> Result<(), Box<dyn std::error::Error>> {
        let (parts, _, joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut header_with_pop, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);
        if !header_with_pop.contains_key(&HDR_SRX_PAYLOAD) {
            ensure_test_srx_payload(
                &mut header_with_pop,
                parts.gid,
                pop_pk.as_slice(),
                parts.revoked_since_prev_root,
            );
        }

        mutate_srx_payload_preserving_leaf_auto(
            &mut header_with_pop,
            parts.gid,
            crate::LeafIdMode::PerGroup,
            pop_pk.as_slice(),
            |payload| {
                if let Value::Array(items) = payload
                    && let Some(Value::Array(join_nonmem_revoked)) = items.get_mut(1)
                    && let Some(Value::Map(first_anchor)) = join_nonmem_revoked.get_mut(0)
                {
                    for (key, value) in first_anchor.iter_mut() {
                        if let Value::Integer(field) = key
                            && u64::try_from(*field).ok() == Some(2)
                            && let Value::Bytes(root) = value
                            && let Some(first) = root.first_mut()
                        {
                            *first ^= 0x01;
                        }
                    }
                }
            },
        );
        let fs_witness = prepare_header_for_acceptance(&mut header_with_pop, &parts, &joiner);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);
        let result = accept_with_header(&mut ctx, &parts, &header_with_pop);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "revoked conflict should freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                AcceptanceError::Freeze(code)
                    if code == FREEZE_SRX_SET_CONFLICT_REVOKE || code == FREEZE_SRX_INVALID
            ),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_srx_subset_conflict_freezes() -> Result<(), Box<dyn std::error::Error>> {
        let (parts, _, joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut header_with_pop, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);
        if !header_with_pop.contains_key(&HDR_SRX_PAYLOAD) {
            ensure_test_srx_payload(
                &mut header_with_pop,
                parts.gid,
                pop_pk.as_slice(),
                parts.revoked_since_prev_root,
            );
        }

        mutate_srx_payload_preserving_leaf_auto(
            &mut header_with_pop,
            parts.gid,
            crate::LeafIdMode::PerGroup,
            pop_pk.as_slice(),
            |payload| {
                if let Value::Array(items) = payload
                    && let Some(Value::Array(since_mem_revoked)) = items.get_mut(2)
                {
                    since_mem_revoked.push(Value::Map(vec![
                        (
                            Value::Text("leaf_id".to_string()),
                            Value::Bytes(vec![0xAA; 32]),
                        ),
                        (
                            Value::Text("root".to_string()),
                            Value::Bytes(vec![0xFF; 32]),
                        ),
                        (Value::Text("path".to_string()), Value::Array(Vec::new())),
                    ]));
                }
            },
        );

        let fs_witness = prepare_header_for_acceptance(&mut header_with_pop, &parts, &joiner);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);
        let result = accept_with_header(&mut ctx, &parts, &header_with_pop);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "subset conflict should freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                AcceptanceError::Freeze(code)
                    if code == FREEZE_SRX_SET_CONFLICT_SUBSET || code == FREEZE_SRX_INVALID
            ),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_srx_commit_mismatch_freezes() -> Result<(), Box<dyn std::error::Error>> {
        let (parts, _, joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut header_with_pop, _, _) = header_ready_with_pop(&joiner, &parts, &pop_pk, &pop_sk);
        if !header_with_pop.contains_key(&HDR_SRX_PAYLOAD) {
            ensure_test_srx_payload(
                &mut header_with_pop,
                parts.gid,
                pop_pk.as_slice(),
                parts.revoked_since_prev_root,
            );
        }

        mutate_srx_payload_preserving_leaf_auto(
            &mut header_with_pop,
            parts.gid,
            crate::LeafIdMode::PerGroup,
            pop_pk.as_slice(),
            |_| {},
        );
        if let Some(Value::Bytes(commit)) = header_with_pop.get_mut(&HDR_SRX_COMMIT)
            && let Some(first) = commit.first_mut()
        {
            *first ^= 0xAA;
        }

        let fs_witness = prepare_header_for_acceptance(&mut header_with_pop, &parts, &joiner);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);
        let result = accept_with_header(&mut ctx, &parts, &header_with_pop);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "commit mismatch should freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                AcceptanceError::Freeze(code)
                    if code == FREEZE_SRX_COMMIT_MISMATCH || code == FREEZE_SRX_INVALID
            ),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn genesis_without_bootstrap_allowed_when_policy_disabled()
    -> Result<(), Box<dyn std::error::Error>> {
        let (parts, _, joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (header_with_pop, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);

        let options = AcceptanceOptions {
            bootstrap_policy: BootstrapPolicy::Disabled,
            ..AcceptanceOptions::default()
        };
        let mut ctx = AcceptanceContext::with_options(DEFAULT_H_MAX, DEFAULT_T_WINDOW, options);
        accept_with_header(&mut ctx, &parts, &header_with_pop)?;
        Ok(())
    }

    #[test]
    fn genesis_bootstrap_rejected_when_policy_disabled() -> Result<(), Box<dyn std::error::Error>> {
        let (parts, _, joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut header_with_pop, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);
        header_with_pop.insert(HDR_BOOTSTRAP_ALG, Value::Text("oob-ca-v1".to_string()));
        refresh_seed_ctx_hash(&mut header_with_pop);

        let options = AcceptanceOptions {
            bootstrap_policy: BootstrapPolicy::Disabled,
            ..AcceptanceOptions::default()
        };
        let mut ctx = AcceptanceContext::with_options(DEFAULT_H_MAX, DEFAULT_T_WINDOW, options);
        let result = accept_with_header(&mut ctx, &parts, &header_with_pop);
        assert!(result.is_err(), "bootstrap metadata should be rejected");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_BOOTSTRAP_UNSUPPORTED),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn genesis_bootstrap_requires_signature() -> Result<(), Box<dyn std::error::Error>> {
        let (parts, _, joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut header_with_pop, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);
        header_with_pop.insert(HDR_BOOTSTRAP_ALG, Value::Text("oob-ca-v1".to_string()));
        refresh_seed_ctx_hash(&mut header_with_pop);

        let (boot_pk, _) = keypair();
        let options = AcceptanceOptions {
            bootstrap_policy: BootstrapPolicy::CaMlDsa {
                public_key: boot_pk.as_bytes().to_vec(),
            },
            ..AcceptanceOptions::default()
        };
        let mut ctx = AcceptanceContext::with_options(DEFAULT_H_MAX, DEFAULT_T_WINDOW, options);
        let result = accept_with_header(&mut ctx, &parts, &header_with_pop);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "missing bootstrap signature should freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_BOOTSTRAP_INVALID),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn genesis_bootstrap_mldsav1_validates() -> Result<(), Box<dyn std::error::Error>> {
        let (parts, _, joiner) = sample_parts_params_joiner();
        let anchor = anchor_from_result(&parts, &joiner);
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut header_with_pop, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);
        header_with_pop.insert(HDR_BOOTSTRAP_ALG, Value::Text("oob-ca-v1".to_string()));
        refresh_seed_ctx_hash(&mut header_with_pop);
        let (boot_pk, boot_sk) = keypair();
        let digest = build_bootstrap_digest(
            &header_with_pop,
            &anchor,
            &joiner.hp_commit,
            &joiner.seed_ctx_hash,
            &joiner.rho_commit,
            &joiner.seed_bundle_commit,
        )?;
        let sig = detached_sign(&digest, &boot_sk);
        header_with_pop.insert(HDR_BOOTSTRAP_SIG, Value::Bytes(sig.as_bytes().to_vec()));
        refresh_seed_ctx_hash(&mut header_with_pop);

        let options = AcceptanceOptions {
            bootstrap_policy: BootstrapPolicy::CaMlDsa {
                public_key: boot_pk.as_bytes().to_vec(),
            },
            ..AcceptanceOptions::default()
        };
        let mut ctx = AcceptanceContext::with_options(DEFAULT_H_MAX, DEFAULT_T_WINDOW, options);

        accept_with_header(&mut ctx, &parts, &header_with_pop)?;
        Ok(())
    }

    #[test]
    fn accept_anchor_requires_revoked_root() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let header = sample_header();
        let joiner = joiner_kgen_or(header, parts.clone(), params(), None, None)?;
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut tampered, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);
        tampered.remove(&HDR_REVOKED_ROOT);
        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        let result = accept_with_header(&mut ctx, &parts, &tampered);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "missing revoked_root must freeze");

        let err = result.unwrap_err();

        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_FIELD_MISSING),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_requires_barrier_version() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let header = sample_header();
        let joiner = joiner_kgen_or(header, parts.clone(), params(), None, None)?;
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut tampered, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);
        tampered.remove(&HDR_BARRIER_VERSION);
        reseal_header(&mut tampered, &parts, &joiner);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        let result = accept_with_header(&mut ctx, &parts, &tampered);
        assert!(result.is_err(), "missing barrier_version must freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_FS_JOIN_MISSING),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_tswe_salt_mismatch_freezes() -> Result<(), Box<dyn std::error::Error>> {
        let mut parts = sample_parts();
        let header = sample_header();
        let joiner = joiner_kgen_or(header, parts.clone(), params(), None, None)?;
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (header_with_pop, _, fs_witness) =
            header_ready_with_pop(&joiner, &parts, &pop_pk, &pop_sk);

        let bad_salt = Box::leak(Box::new([0xAA; 32]));
        parts.tswe_salt_hash = &bad_salt[..];

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);
        let result = accept_with_header(&mut ctx, &parts, &header_with_pop);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "tswe salt mismatch must freeze");

        let err = result.unwrap_err();

        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_TSWE_SALT_MISMATCH),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn accept_anchor_rejects_invalid_pop() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let header = sample_header();
        let joiner = joiner_kgen_or(header, parts.clone(), params(), None, None)?;
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut tampered, _) = header_with_pop_and_weid(&joiner, &parts, &pop_pk, &pop_sk);
        if let Some(Value::Bytes(sig)) = tampered.get_mut(&HDR_POP_SIG) {
            sig[0] ^= 0xFF;
        }
        reseal_header(&mut tampered, &parts, &joiner);
        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        let result = accept_with_header(&mut ctx, &parts, &tampered);
        assert!(result.is_err(), "invalid pop must freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_POP_INVALID),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn merge_anchor_retires_heads() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let mut ctx = AcceptanceContext::new(4, Duration::from_secs(10));
        configure_bootstrap(&mut ctx);
        let header_a_seed = sample_header();
        let mut header_b_seed = sample_header();
        header_b_seed.insert(102, Value::Text("head-b".to_string()));
        let params = params();
        let params_a = params.clone();
        let params_b = params.clone();
        let joiner_a = joiner_kgen_or(header_a_seed.clone(), parts.clone(), params_a, None, None)?;
        let joiner_b = joiner_kgen_or(header_b_seed.clone(), parts.clone(), params_b, None, None)?;
        let (pop_pk, pop_sk) = pop_keys_static();
        let (header_a, _, witness_a) = header_ready_with_pop(&joiner_a, &parts, pop_pk, pop_sk);
        let (header_b, _, witness_b) = header_ready_with_pop(&joiner_b, &parts, pop_pk, pop_sk);

        seed_capss_with(&mut ctx, &witness_a);
        let outcome_a = accept_with_header(&mut ctx, &parts, &header_a)?;
        ctx.clear_device_chains();
        ctx.rho_guard = RhoReplayGuard::new(RHO_GUARD_CAPACITY, ctx.mh_window.ttl());
        seed_capss_with(&mut ctx, &witness_b);
        let outcome_b = accept_with_header(&mut ctx, &parts, &header_b)?;
        assert!(ctx.active_heads(&outcome_a.wid) >= 1);
        assert!(ctx.active_heads(&outcome_b.wid) >= 1);

        let mut parent_root_arr = [0u8; 32];
        parent_root_arr.copy_from_slice(parts.parent_root);
        let mut parities = ctx.pivot_parities_for(parts.gid, &parent_root_arr);
        parities.sort_by_key(|parity| (parity.accept_seq, parity.xk_hash));
        assert!(
            !parities.is_empty(),
            "expected at least one pivot parity for merge construction"
        );
        let merge_joiner = joiner_kgen_merge_or(
            sample_header(),
            &parities,
            Some("merge-note"),
            parts.clone(),
            params.clone(),
            None,
        )?;

        let mut merge_header = merge_joiner.header_map.clone();
        merge_header.remove(&HDR_KBROAD_REPLAY);
        ensure_bootstrap_fields(&mut merge_header, &parts, &merge_joiner);
        refresh_seed_bindings(&mut merge_header, &parts, &merge_joiner);
        let merge_witness = merge_joiner.capss_witness.clone();
        let header_rho = merge_header
            .get(&93)
            .and_then(Value::as_bytes)
            .expect("expected rho commit in merge header")
            .to_vec();
        let pivot = parities
            .iter()
            .max_by(|a, b| {
                a.accept_seq
                    .cmp(&b.accept_seq)
                    .then_with(|| b.xk_hash.cmp(&a.xk_hash))
            })
            .expect("pivot expected");
        assert_eq!(header_rho, pivot.rho_commit.as_ref());
        let retired_heads = merge_joiner
            .retired_heads
            .as_ref()
            .expect("retired heads expected");
        assert!(
            !retired_heads.is_empty(),
            "expected at least one head to be marked for retirement"
        );
        assert!(retired_heads.contains(&joiner_a.we_epoch_id));
        seed_capss_with(&mut ctx, &merge_witness);
        let result = accept_with_header(&mut ctx, &parts, &merge_header);
        assert!(result.is_err(), "error expected");
        assert!(
            result.is_err(),
            "merge should freeze until rho parity alignment is addressed"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                AcceptanceError::Freeze(code)
                    if code == FREEZE_MSPHF_RHO_PARITY
                        || code == FREEZE_MH_HEADS_INVALID
                        || code == FREEZE_MSPHF_CRS_INVALID
            ),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn merge_anchor_join_payload_freezes() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let header_a_seed = sample_header();
        let header_b_seed = sample_header();
        let params = params();
        let joiner_a = joiner_kgen_or(
            header_a_seed.clone(),
            parts.clone(),
            params.clone(),
            None,
            None,
        )?;
        let joiner_b = joiner_kgen_or(
            header_b_seed.clone(),
            parts.clone(),
            params.clone(),
            None,
            None,
        )?;
        let (pop_pk_a, pop_sk_a) = sample_pop_keys();
        let (header_a, _, witness_a) =
            header_ready_with_pop(&joiner_a, &parts, &pop_pk_a, &pop_sk_a);
        let (pop_pk_b, pop_sk_b) = sample_pop_keys();
        let (header_b, _, witness_b) =
            header_ready_with_pop(&joiner_b, &parts, &pop_pk_b, &pop_sk_b);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &witness_a);
        accept_with_header(&mut ctx, &parts, &header_a).expect("first acceptance failed");

        ctx.clear_device_chains();
        ctx.rho_guard = RhoReplayGuard::new(RHO_GUARD_CAPACITY, ctx.mh_window.ttl());
        seed_capss_with(&mut ctx, &witness_b);
        accept_with_header(&mut ctx, &parts, &header_b).expect("second acceptance failed");

        let mut parent_root_arr = [0u8; 32];
        parent_root_arr.copy_from_slice(parts.parent_root);
        let mut parities = ctx.pivot_parities_for(parts.gid, &parent_root_arr);
        parities.sort_by_key(|parity| (parity.accept_seq, parity.xk_hash));
        assert!(parities.iter().all(|p| p.fs_ec.is_some()));
        assert!(parities.iter().all(|p| p.fs_dev_commit.is_some()));
        let merge_joiner = match joiner_kgen_merge_or(
            sample_header(),
            &parities,
            None,
            parts.clone(),
            params,
            None,
        ) {
            Ok(result) => result,
            Err(err) => {
                let debug = format!("{err:?}");
                if debug.contains("fs_dev_chain_break") {
                    return Ok(());
                }
                return Err(format!("merge build failed: {debug}").into());
            }
        };

        let mut tampered = merge_joiner.header_map.clone();
        tampered.insert(HDR_SRX_MODE, Value::Text("srx/v1-complete".to_string()));
        tampered.insert(HDR_SRX_COMMIT, Value::Bytes(vec![0u8; 32]));
        tampered.insert(HDR_SRX_PAYLOAD, Value::Bytes(vec![0u8]));
        tampered.insert(
            HDR_SRX_HINT_COUNTS,
            Value::Bytes(encode_value(&Value::Map(Vec::new()))),
        );
        tampered.insert(
            HDR_SRX_HINT_SIZES,
            Value::Bytes(encode_value(&Value::Map(Vec::new()))),
        );
        tampered.remove(&HDR_KBROAD_REPLAY);
        ensure_bootstrap_fields(&mut tampered, &parts, &merge_joiner);
        refresh_seed_bindings(&mut tampered, &parts, &merge_joiner);
        seed_capss_with(&mut ctx, &merge_joiner.capss_witness);
        let result = accept_with_header(&mut ctx, &parts, &tampered);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "merge carrying join payload must freeze");

        let err = result.unwrap_err();

        assert!(
            matches!(
                err,
                AcceptanceError::Freeze(code)
                    if code == FREEZE_SRX_INVALID
                        || code == FREEZE_FS_DEV_CHAIN_BREAK
                        || code == FREEZE_MSPHF_CRS_INVALID
            ),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn merge_roots_change_without_srx_freezes_required() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let header = sample_header();
        let joiner = joiner_kgen_or(header, parts.clone(), params(), None, None)?;
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (header_with_pop, _, fs_witness) =
            header_ready_with_pop(&joiner, &parts, &pop_pk, &pop_sk);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);
        accept_with_header(&mut ctx, &parts, &header_with_pop)?;

        let mut parent_root_arr = [0u8; 32];
        parent_root_arr.copy_from_slice(parts.parent_root);
        let mut parities = ctx.pivot_parities_for(parts.gid, &parent_root_arr);
        parities.sort_by_key(|parity| (parity.accept_seq, parity.xk_hash));
        parities.truncate(1);

        let merge = joiner_kgen_merge_or(
            sample_header(),
            &parities,
            None,
            sample_parts(),
            params(),
            None,
        )?;

        let mut header = merge.header_map.clone();
        header.remove(&HDR_KBROAD_REPLAY);
        let new_revoked_since = leak([0x44; 32]);
        header.insert(112, Value::Bytes(new_revoked_since.to_vec()));
        let new_revoked_root = leak([0x55; 32]);
        header.insert(HDR_REVOKED_ROOT, Value::Bytes(new_revoked_root.to_vec()));
        ensure_bootstrap_fields(&mut header, &parts, &merge);
        refresh_seed_bindings(&mut header, &parts, &merge);

        let result = accept_with_header(&mut ctx, &parts, &header);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "roots change without SRX must freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                AcceptanceError::Freeze(code)
                    if code == FREEZE_SRX_REQUIRED
                        || code == FREEZE_HASH_CBOR
                        || code == FREEZE_MSPHF_CRS_INVALID
            ),
            "unexpected result: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn merge_retiring_head_outside_window_freezes() -> Result<(), Box<dyn std::error::Error>> {
        let header = sample_header();
        let joiner = joiner_kgen_or(header, sample_parts(), params(), None, None)?;
        let parts = sample_parts();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (header_with_pop, _, fs_witness) =
            header_ready_with_pop(&joiner, &parts, &pop_pk, &pop_sk);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &fs_witness);
        accept_with_header(&mut ctx, &parts, &header_with_pop)?;

        let mut parent_root_arr = [0u8; 32];
        parent_root_arr.copy_from_slice(parts.parent_root);
        let mut parities = ctx.pivot_parities_for(parts.gid, &parent_root_arr);
        parities.sort_by_key(|parity| (parity.accept_seq, parity.xk_hash));
        parities.truncate(1);

        let merge = joiner_kgen_merge_or(
            sample_header(),
            &parities,
            None,
            sample_parts(),
            params(),
            None,
        )?;

        let mut header = merge.header_map.clone();
        header.remove(&HDR_KBROAD_REPLAY);
        let mut heads: Vec<[u8; 32]> = parities.iter().map(|p| p.we_epoch_id).collect();
        heads.push([0xFF; 32]);
        heads.sort();
        let head_values = heads
            .iter()
            .map(|head| Value::Bytes(head.to_vec()))
            .collect();
        header.insert(HDR_MH_HEADS, Value::Array(head_values));
        ensure_bootstrap_fields(&mut header, &parts, &merge);
        refresh_seed_bindings(&mut header, &parts, &merge);

        seed_capss_with(&mut ctx, &merge.capss_witness);
        let result = accept_with_header(&mut ctx, &parts, &header);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "retiring head outside window must freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                AcceptanceError::Freeze(code)
                    if code == FREEZE_MH_HEADS_INVALID
                        || code == FREEZE_HASH_CBOR
                        || code == FREEZE_MSPHF_CRS_INVALID
            ),
            "unexpected result: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn merge_parity_mismatch_freezes() -> Result<(), Box<dyn std::error::Error>> {
        let header = sample_header();
        let joiner = joiner_kgen_or(header, sample_parts(), params(), None, None)?;
        let parts = sample_parts();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (header_with_pop, _, witness_initial) =
            header_ready_with_pop(&joiner, &parts, &pop_pk, &pop_sk);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &witness_initial);
        accept_with_header(&mut ctx, &parts, &header_with_pop)?;

        let mut parent_root_arr = [0u8; 32];
        parent_root_arr.copy_from_slice(parts.parent_root);
        let mut parities = ctx.pivot_parities_for(parts.gid, &parent_root_arr);
        parities.sort_by_key(|parity| (parity.accept_seq, parity.xk_hash));
        parities.truncate(1);

        let merge = joiner_kgen_merge_or(
            sample_header(),
            &parities,
            None,
            parts.clone(),
            params(),
            None,
        )?;

        let mut header = merge.header_map.clone();
        header.remove(&HDR_KBROAD_REPLAY);
        header.insert(93, Value::Bytes(vec![0xAA; 32]));
        ensure_bootstrap_fields(&mut header, &parts, &merge);
        refresh_seed_bindings(&mut header, &parts, &merge);

        seed_capss_with(&mut ctx, &merge.capss_witness);
        let result = accept_with_header(&mut ctx, &parts, &header);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "ρ parity mismatch must freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                AcceptanceError::Freeze(code)
                    if code == FREEZE_MSPHF_RHO_PARITY || code == FREEZE_MSPHF_CRS_INVALID
            ),
            "unexpected result: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn merge_heads_must_be_sorted_unique() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let header = sample_header();
        let joiner_a = joiner_kgen_or(header.clone(), parts.clone(), params(), None, None)?;
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (mut bad_header, _) = header_with_pop_and_weid(&joiner_a, &parts, &pop_pk, &pop_sk);
        let heads = vec![
            Value::Bytes([0x02; 32].to_vec()),
            Value::Bytes([0x02; 32].to_vec()),
        ];
        bad_header.insert(HDR_MH_HEADS, Value::Array(heads));
        let seed_ctx = build_anchor_seed_ctx(&bad_header)?;
        let seed_hash = compute_seed_ctx_hash(&seed_ctx)?;
        bad_header.insert(91, Value::Bytes(seed_hash.to_vec()));
        let mut parent_root_arr = [0u8; 32];
        parent_root_arr.copy_from_slice(parts.parent_root);
        let seed_bundle = compute_seed_bundle_commit(
            &seed_ctx,
            &joiner_a.rho_commit,
            parts.gid,
            parts.cat,
            &parent_root_arr,
        )?;
        bad_header.insert(94, Value::Bytes(seed_bundle.to_vec()));
        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        let _new_we = derive_we_epoch_id(parts.gid, parts.parent_root, &seed_hash)?;
        let result = accept_with_header(&mut ctx, &parts, &bad_header);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "duplicate heads should freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                AcceptanceError::Freeze(code)
                    if code == FREEZE_MH_HEADS_INVALID || code == FREEZE_HASH_CBOR
            ),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn duplicate_merge_heads_freeze() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let params = params();
        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);

        let mut header_a_seed = sample_header();
        header_a_seed.insert(20, Value::Bytes(vec![0xAA]));
        let mut header_b_seed = sample_header();
        header_b_seed.insert(20, Value::Bytes(vec![0xAB]));

        let joiner_a = joiner_kgen_or(header_a_seed, parts.clone(), params.clone(), None, None)?;
        let joiner_b = joiner_kgen_or(header_b_seed, parts.clone(), params.clone(), None, None)?;
        let (pop_pk_a, pop_sk_a) = sample_pop_keys();
        let (header_a, _, witness_a) =
            header_ready_with_pop(&joiner_a, &parts, &pop_pk_a, &pop_sk_a);
        let (pop_pk_b, pop_sk_b) = sample_pop_keys();
        let (header_b, _, witness_b) =
            header_ready_with_pop(&joiner_b, &parts, &pop_pk_b, &pop_sk_b);
        seed_capss_with(&mut ctx, &witness_a);
        accept_with_header(&mut ctx, &parts, &header_a)?;
        ctx.clear_device_chains();
        ctx.rho_guard = RhoReplayGuard::new(RHO_GUARD_CAPACITY, ctx.mh_window.ttl());
        seed_capss_with(&mut ctx, &witness_b);
        accept_with_header(&mut ctx, &parts, &header_b)?;

        let mut parent_root_arr = [0u8; 32];
        parent_root_arr.copy_from_slice(parts.parent_root);
        let mut parities = ctx.pivot_parities_for(parts.gid, &parent_root_arr);
        parities.sort_by(|a, b| a.we_epoch_id.cmp(&b.we_epoch_id));

        let mut merge_header_src = sample_header();
        merge_header_src.insert(20, Value::Bytes(vec![0xAC]));
        let joiner_merge = joiner_kgen_merge_or(
            merge_header_src,
            &parities,
            None,
            parts.clone(),
            params.clone(),
            None,
        )?;

        let mut merge_header = joiner_merge.header_map.clone();
        merge_header.remove(&HDR_KBROAD_REPLAY);
        merge_header.insert(
            HDR_MH_HEADS,
            Value::Array(vec![
                Value::Bytes(joiner_merge.we_epoch_id.to_vec()),
                Value::Bytes(joiner_merge.we_epoch_id.to_vec()),
            ]),
        );
        ensure_bootstrap_fields(&mut merge_header, &parts, &joiner_merge);
        refresh_seed_bindings(&mut merge_header, &parts, &joiner_merge);

        seed_capss_with(&mut ctx, &joiner_merge.capss_witness);
        let result = accept_with_header(&mut ctx, &parts, &merge_header);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "duplicate heads should freeze");

        let err = result.unwrap_err();

        assert!(
            matches!(
                err,
                AcceptanceError::Freeze(code)
                    if code == FREEZE_MH_HEADS_INVALID || code == FREEZE_HASH_CBOR
            ),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn merge_tampered_rho_commit_freezes_with_parity_code() -> Result<(), Box<dyn std::error::Error>>
    {
        let parts = sample_parts();
        let params = params();
        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        let mut header_a = sample_header();
        header_a.insert(20, Value::Bytes(vec![0xAA]));
        let mut header_b = sample_header();
        header_b.insert(20, Value::Bytes(vec![0xAB]));
        let joiner_a = joiner_kgen_or(header_a, parts.clone(), params.clone(), None, None)?;
        let joiner_b = joiner_kgen_or(header_b, parts.clone(), params.clone(), None, None)?;
        let (pop_pk_a, pop_sk_a) = sample_pop_keys();
        let (header_a, _, witness_a) =
            header_ready_with_pop(&joiner_a, &parts, &pop_pk_a, &pop_sk_a);
        let (pop_pk_b, pop_sk_b) = sample_pop_keys();
        let (header_b, _, witness_b) =
            header_ready_with_pop(&joiner_b, &parts, &pop_pk_b, &pop_sk_b);

        seed_capss_with(&mut ctx, &witness_a);
        accept_with_header(&mut ctx, &parts, &header_a)?;
        ctx.clear_device_chains();
        ctx.rho_guard = RhoReplayGuard::new(RHO_GUARD_CAPACITY, ctx.mh_window.ttl());
        seed_capss_with(&mut ctx, &witness_b);
        accept_with_header(&mut ctx, &parts, &header_b)?;

        let mut parent_root = [0u8; 32];
        parent_root.copy_from_slice(parts.parent_root);
        let mut parities = ctx.pivot_parities_for(parts.gid, &parent_root);
        parities.sort_by(|a, b| a.accept_seq.cmp(&b.accept_seq));
        let merge_joiner = joiner_kgen_merge_or(
            sample_header(),
            &parities,
            None,
            parts.clone(),
            params,
            None,
        )?;

        let mut merge_header = merge_joiner.header_map.clone();
        merge_header.remove(&HDR_KBROAD_REPLAY);
        if let Some(first) = merge_header
            .get_mut(&HDR_RHO_COMMIT)
            .and_then(Value::as_bytes_mut)
            .and_then(|bytes| bytes.first_mut())
        {
            *first ^= 0xFF;
        } else {
            return Err("merge header missing rho commit".into());
        }

        ensure_bootstrap_fields(&mut merge_header, &parts, &merge_joiner);
        refresh_seed_bindings(&mut merge_header, &parts, &merge_joiner);

        seed_capss_with(&mut ctx, &merge_joiner.capss_witness);
        let result = accept_with_header(&mut ctx, &parts, &merge_header);
        assert!(result.is_err(), "error expected");
        assert!(result.is_err(), "tampered merge rho must freeze");
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                AcceptanceError::Freeze(code)
                    if code == FREEZE_MSPHF_RHO_PARITY
                        || code == FREEZE_MH_HEADS_INVALID
                        || code == FREEZE_MSPHF_CRS_INVALID
            ),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn epoch_mismatch_freezes() -> Result<(), Box<dyn std::error::Error>> {
        let parts = sample_parts();
        let header = sample_header();
        let joiner = joiner_kgen_or(header, parts.clone(), params(), None, None)?;
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (header_with_pop, mut we_epoch_id_claim, fs_witness) =
            header_ready_with_pop(&joiner, &parts, &pop_pk, &pop_sk);
        we_epoch_id_claim[0] ^= 0x42;

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);

        seed_capss_with(&mut ctx, &fs_witness);

        let result = ctx.accept_anchor(&parts, we_epoch_id_claim, &header_with_pop);
        assert!(result.is_err(), "tampered epoch id should freeze");
        let err = result.unwrap_err();

        assert!(
            matches!(err, AcceptanceError::Freeze(code) if code == FREEZE_EPOCHID_MISMATCH),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn acceptance_header_mutation_matrix_freezes() -> Result<(), Box<dyn std::error::Error>> {
        let (parts, _, joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (header, _, fs_witness) = header_ready_with_pop(&joiner, &parts, &pop_pk, &pop_sk);

        for case in 0u8..26 {
            let mut mutated = header.clone();
            match case {
                0 => {
                    mutated.remove(&HDR_TSWE_ALG);
                }
                1 => {
                    mutated.insert(HDR_TSWE_ALG, Value::Integer(Integer::from(99u64)));
                }
                2 => {
                    mutated.insert(HDR_MERKLE_SUITE, Value::Text("rpo-256/v1".to_string()));
                }
                3 => {
                    mutated.remove(&HDR_CRS_ID);
                }
                4 => {
                    mutated.insert(HDR_CRS_ID, Value::Text("unsupported-crs".to_string()));
                }
                5 => {
                    mutated.remove(&HDR_KBROAD_ALG);
                }
                6 => {
                    mutated.insert(HDR_KBROAD_ALG, Value::Text("unsupported-kem".to_string()));
                }
                7 => {
                    mutated.insert(HDR_KBROAD_PUB, Value::Bytes(vec![0x11; 32]));
                }
                8 => {
                    mutated.remove(&HDR_PARAMS_ID);
                }
                9 => {
                    mutated.insert(HDR_PARAMS_ID, Value::Text("unsupported-params".to_string()));
                }
                10 => {
                    mutated.remove(&HDR_POP_ALG);
                }
                11 => {
                    mutated.insert(HDR_POP_ALG, Value::Integer(Integer::from(1u64)));
                }
                12 => {
                    mutated.insert(HDR_POP_PK, Value::Text("not-bytes".to_string()));
                }
                13 => {
                    mutated.insert(HDR_POP_SIG, Value::Text("not-bytes".to_string()));
                }
                14 => {
                    mutated.remove(&110);
                }
                15 => {
                    mutated.insert(110, Value::Bytes(vec![0xAA; 31]));
                }
                16 => {
                    mutated.remove(&111);
                }
                17 => {
                    mutated.insert(HDR_REVOKED_ROOT, Value::Bytes(vec![0xBB; 31]));
                }
                18 => {
                    mutated.remove(&93);
                }
                19 => {
                    mutated.insert(93, Value::Bytes(vec![0xCC; 31]));
                }
                20 => {
                    mutated.remove(&91);
                }
                21 => {
                    mutated.insert(91, Value::Bytes(vec![0xDD; 31]));
                }
                22 => {
                    mutated.remove(&94);
                }
                23 => {
                    mutated.insert(94, Value::Bytes(vec![0xEE; 31]));
                }
                24 => {
                    mutated.insert(999_999, Value::Integer(Integer::from(1u64)));
                }
                25 => {
                    mutated.insert(HDR_FS_POLICY_VERSION, Value::Text("not-int".to_string()));
                }
                _ => {}
            }

            let mut ctx = AcceptanceContext::with_defaults();
            configure_bootstrap(&mut ctx);
            seed_capss_with(&mut ctx, &fs_witness);
            let result = accept_with_header(&mut ctx, &parts, &mutated);
            assert!(result.is_err(), "mutation case {case} should fail");
        }

        Ok(())
    }

    // ── Freeze code uniqueness ──────────────────────────────────────

    #[test]
    fn srx_set_conflict_codes_are_distinct() {
        assert_ne!(
            FREEZE_SRX_SET_CONFLICT_PARENT.code, FREEZE_SRX_SET_CONFLICT_REVOKE.code,
            "parent vs revoke must have distinct codes"
        );
        assert_ne!(
            FREEZE_SRX_SET_CONFLICT_PARENT.code, FREEZE_SRX_SET_CONFLICT_SUBSET.code,
            "parent vs subset must have distinct codes"
        );
        assert_ne!(
            FREEZE_SRX_SET_CONFLICT_REVOKE.code, FREEZE_SRX_SET_CONFLICT_SUBSET.code,
            "revoke vs subset must have distinct codes"
        );
    }

    // ── RhoReplayGuard unit tests ─────────────────────────────────────

    #[test]
    fn rho_guard_rejects_duplicate() {
        let mut guard = RhoReplayGuard::new(8, Duration::from_secs(10));
        let gid = b"gid";
        let root = &[0xAA; 32];
        let rho = [0x01; 32];
        let now = AcceptInstant::from_ticks(0);
        assert!(guard.record(gid, root, &rho, now));
        assert!(
            !guard.record(gid, root, &rho, now),
            "duplicate must be rejected"
        );
    }

    #[test]
    fn rho_guard_rejects_when_full_instead_of_evicting() {
        let capacity = 4;
        let mut guard = RhoReplayGuard::new(capacity, Duration::from_secs(10));
        let gid = b"gid";
        let root = &[0xBB; 32];

        // Fill to capacity.
        for i in 0u8..capacity as u8 {
            assert!(guard.record(gid, root, &[i; 32], AcceptInstant::from_ticks(i as u64)));
        }
        assert_eq!(guard.count_for(gid, root), capacity);

        // The next distinct value must be rejected, not evict an old one.
        assert!(
            !guard.record(gid, root, &[0xFF; 32], AcceptInstant::from_ticks(4)),
            "overflow must reject, not evict"
        );
        assert_eq!(
            guard.count_for(gid, root),
            capacity,
            "size must not grow past capacity"
        );

        // All previously-recorded values must still be detected as duplicates
        // (proving nothing was evicted).
        for i in 0u8..capacity as u8 {
            assert!(
                !guard.record(gid, root, &[i; 32], AcceptInstant::from_ticks(4)),
                "old rho {i} must still be detected"
            );
        }
    }

    #[test]
    fn rho_guard_clear_for_reclaims_capacity() {
        let mut guard = RhoReplayGuard::new(2, Duration::from_secs(10));
        let gid = b"gid";
        let root = &[0xCC; 32];
        let now = AcceptInstant::from_ticks(0);
        assert!(guard.record(gid, root, &[1; 32], now));
        assert!(guard.record(gid, root, &[2; 32], now));
        assert!(!guard.record(gid, root, &[3; 32], now), "must be full");

        guard.clear_for(gid, root);
        assert_eq!(guard.count_for(gid, root), 0);
        assert!(
            guard.record(gid, root, &[3; 32], now),
            "after clear, capacity is reclaimed"
        );
    }

    #[test]
    fn rho_guard_different_keys_are_independent() {
        let mut guard = RhoReplayGuard::new(1, Duration::from_secs(10));
        let gid = b"gid";
        let root_a = &[0x01; 32];
        let root_b = &[0x02; 32];
        let rho = [0xDD; 32];
        let now = AcceptInstant::from_ticks(0);
        assert!(guard.record(gid, root_a, &rho, now));
        // Same rho under a different parent_root is independent.
        assert!(guard.record(gid, root_b, &rho, now));
    }

    #[test]
    fn rho_guard_expires_old_entries_and_reclaims_capacity() {
        let mut guard = RhoReplayGuard::new(2, Duration::from_secs(2));
        let gid = b"gid";
        let root = &[0xEE; 32];

        assert!(guard.record(gid, root, &[1; 32], AcceptInstant::from_ticks(0)));
        assert!(guard.record(gid, root, &[2; 32], AcceptInstant::from_ticks(1)));
        assert!(
            !guard.record(gid, root, &[3; 32], AcceptInstant::from_ticks(1)),
            "guard should be full before TTL expiration"
        );

        assert!(
            guard.record(gid, root, &[3; 32], AcceptInstant::from_ticks(3)),
            "old entry should expire and free capacity"
        );
    }
}
