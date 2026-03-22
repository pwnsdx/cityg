//! Lightweight client helpers for producing City-G epoch bundles.
//!
//! This crate provides client-side operations for the City-G protocol:
//!
//! - **Epoch generation**: Create anchors for joins, merges, and revocations
//! - **Witness creation**: Merkle proofs and SRX witness bundles
//! - **Proof generation**: CAPSS Smallwood + ZK-VRF proofs
//! - **Forward secrecy**: Pivot rotation and epoch key derivation
//! - **KBROAD encryption**: Server-blind delivery of hash projection keys
//!
//! # Security
//!
//! This crate handles secrets that **must never reach the server**:
//! - `hp` (hash projection key) - Encrypted in KBROAD before transmission
//! - `Y*` (VRF output) - Hidden via zero-knowledge proofs
//! - `E_k` (epoch key) - Derived locally, never transmitted
//!
//! All sensitive values implement `Zeroize` and are cleared on drop.
//!
//! # Quick Start
//!
//! ```ignore
//! use cityg_client::CityGClient;
//! use msphf_orchestrator::{AnchorInstanceParts, ForwardSecrecyState, OrchestrationParams};
//! use std::collections::BTreeMap;
//!
//! // 1. Set up anchor parameters
//! let parts = AnchorInstanceParts {
//!     gid: b"my-room",
//!     cat: b"category",
//!     parent_root: &current_merkle_root,
//!     join_delta_root: &new_merkle_root,
//!     // ... other fields
//! };
//!
//! // 2. Configure cryptographic parameters
//! let params = OrchestrationParams {
//!     msphf_crs_id: "rlwe-merkle/v1",
//!     params_id: "rlwe-params/mock",
//!     proof_mode: "lin+zkvrf",
//!     barrier_version: 0,
//!     // ... other fields
//! };
//!
//! // 3. Initialize forward secrecy state
//! let mut fs_state = ForwardSecrecyState::new(device_commitment);
//!
//! // 4. Generate epoch bundle
//! let bundle = CityGClient::generate_epoch(
//!     BTreeMap::new(),  // header
//!     parts,
//!     params,
//!     &mut fs_state,
//!     None,  // witness
//! )?;
//!
//! // 5. Submit to server
//! let cbor_bytes = bundle.to_cbor()?;
//! // POST to /v1/accept_epoch
//! ```
//!
//! # Performance
//!
//! Typical epoch generation times (Apple M1):
//! - Witness generation: ~1ms (O(log N))
//! - CAPSS Smallwood proof: ~50ms
//! - ZK-VRF proof: ~30ms
//! - KBROAD encryption: ~5ms
//! - **Total**: ~90ms
//!
//! # See Also
//!
//! - [`witness`] module for Merkle witness creation
//! - [`pivot`] module for forward secrecy rotation
//! - [Client Operations](../../docs/protocol/08-client-operations.md) protocol documentation

pub mod pivot;
pub mod witness;

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    convert::TryInto,
    fmt,
    io::Cursor,
};

use ciborium::value::Value;
use msphf_core::{
    MsphfError, hash::eid_from_epoch, instance::AnchorInstance, serde_utils::to_cbor_vec,
};
use msphf_orchestrator::{
    AnchorInstanceParts, CapssWitnessBundle, ForwardSecrecyState, HpBindingInputs,
    HpEnvelopeBinding, HpProof, JoinerKGenResult, LeafIdMode, LocalHpEnvelopeMaterial,
    OrchestrationParams, PivotParity, extract_epoch_msphf_or,
    hdr::{
        HDR_FS_EC, HDR_HP_BYTES, HDR_MERGE_DELEGATION_SIG, HDR_MH_HEADS, HDR_POP_ALG, HDR_POP_PK,
        HDR_ROLLUP_EPOCH_REPLAY, HDR_ROLLUP_FS_MODE, HDR_ROLLUP_PIVOT_WEID,
        HDR_ROLLUP_PROVENANCE_COMMIT, HDR_ROLLUP_VCK_COMMIT,
    },
    joiner_kgen_merge_or_with_state, joiner_kgen_or, prove_hp_k,
    rebind_local_hp_envelope_with_barrier_key as rebuild_local_hp_envelope_with_barrier_key,
    recover_barrier_hp_material_from_header,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const MAX_BUNDLE_CBOR_BYTES: usize = 4 * 1024 * 1024;

fn validate_deterministic_cbor_invariants(value: &Value) -> Result<(), CityGError> {
    fn walk(value: &Value, path: &str) -> Result<(), CityGError> {
        match value {
            Value::Float(_) => Err(CityGError::InvalidInput("bundle contains float value")),
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    walk(item, format!("{path}[{index}]").as_str())?;
                }
                Ok(())
            }
            Value::Map(entries) => {
                let mut seen_keys = HashSet::new();
                for (index, (key, map_value)) in entries.iter().enumerate() {
                    let key_bytes = to_cbor_vec(key)
                        .map_err(|_| CityGError::InvalidInput("bundle decode failed"))?;
                    if !seen_keys.insert(key_bytes) {
                        return Err(CityGError::InvalidInput(
                            "bundle contains duplicate map key",
                        ));
                    }
                    walk(key, format!("{path}[{index}].key").as_str())?;
                    walk(map_value, format!("{path}[{index}].value").as_str())?;
                }
                Ok(())
            }
            Value::Tag(_, tagged) => walk(tagged.as_ref(), format!("{path}.tag").as_str()),
            _ => Ok(()),
        }
    }

    walk(value, "$")
}

/// Unified error type for City-G client operations.
///
/// This enum wraps all possible error types that can occur during
/// client-side epoch generation, witness creation, and proof generation.
///
/// # Variants
///
/// - [`Msphf`](CityGError::Msphf) - Core cryptographic errors (RLWE, Merkle, etc.)
/// - [`Acceptance`](CityGError::Acceptance) - Validation errors from orchestrator
/// - [`Receiver`](CityGError::Receiver) - Decryption or message processing errors
/// - [`Io`](CityGError::Io) - File I/O or serialization errors
/// - [`InvalidInput`](CityGError::InvalidInput) - Invalid parameters or configuration
#[derive(Debug)]
pub enum CityGError {
    /// Core MSPHF cryptographic error
    Msphf(MsphfError),
    /// Orchestrator acceptance error
    Acceptance(msphf_orchestrator::AcceptanceError),
    /// Receiver decryption error
    Receiver(msphf_orchestrator::receiver::ReceiverError),
    /// I/O or serialization error
    Io(std::io::Error),
    /// Invalid input parameter
    InvalidInput(&'static str),
}

impl fmt::Display for CityGError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CityGError::Msphf(err) => write!(f, "MSPHF error: {err}"),
            CityGError::Acceptance(err) => write!(f, "acceptance error: {err:?}"),
            CityGError::Receiver(err) => write!(f, "receiver error: {err:?}"),
            CityGError::Io(err) => write!(f, "io error: {err}"),
            CityGError::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
        }
    }
}

impl std::error::Error for CityGError {}

impl From<MsphfError> for CityGError {
    fn from(err: MsphfError) -> Self {
        CityGError::Msphf(err)
    }
}

impl From<msphf_orchestrator::AcceptanceError> for CityGError {
    fn from(err: msphf_orchestrator::AcceptanceError) -> Self {
        CityGError::Acceptance(err)
    }
}

impl From<msphf_orchestrator::receiver::ReceiverError> for CityGError {
    fn from(err: msphf_orchestrator::receiver::ReceiverError) -> Self {
        CityGError::Receiver(err)
    }
}

impl From<std::io::Error> for CityGError {
    fn from(err: std::io::Error) -> Self {
        CityGError::Io(err)
    }
}

/// High-level client API for City-G epoch bundle generation.
///
/// `CityGClient` provides a simple interface for creating epoch bundles
/// that can be submitted to a City-G server for validation. All cryptographic
/// operations (SPHF, VRF, CAPSS proofs) are handled internally.
///
/// # Thread Safety
///
/// This is a stateless facade - all state is passed via method parameters.
/// Safe to share across threads.
///
/// # Examples
///
/// See crate-level documentation for usage examples.
#[derive(Debug, Default)]
pub struct CityGClient;

impl CityGClient {
    /// Generate a full epoch bundle ready to be submitted to a City-G server.
    ///
    /// This method performs the complete client-side epoch generation pipeline:
    /// 1. Derives hash projection key (`hp`) via RLWE-HPS
    /// 2. Computes VRF output (`Y*`) via ME-OR construction
    /// 3. Generates CAPSS Smallwood proof (~12KB)
    /// 4. Generates ZK-VRF proof (~8KB max, typically smaller)
    /// 5. Encrypts `hp` in KBROAD envelope
    /// 6. Builds complete CBOR anchor header
    /// 7. Updates forward secrecy state with new `τ` value
    ///
    /// # Arguments
    ///
    /// * `header` - Initial anchor header map (normalized internally)
    /// * `parts` - Anchor identity inputs (gid, parent roots, deltas, etc.)
    /// * `params` - Cryptographic profile (CRS ID, proof mode, VRF ID, etc.)
    /// * `fs_state` - Forward secrecy state (mutable, updated after generation)
    /// * `witness` - Optional canonical witness bytes for SRX validation
    ///
    /// # Returns
    ///
    /// Returns [`ClientEpochBundle`] containing:
    /// - `we_epoch_id`: 32-byte unique epoch identifier
    /// - `epoch_key`: Derived E_k for message encryption
    /// - `bundle_cbor`: Complete serialized anchor for server submission
    /// - Membership delta (who joined/left)
    ///
    /// # Errors
    ///
    /// Returns [`CityGError`] if:
    /// - Merkle witness validation fails
    /// - Proof generation fails (CAPSS or VRF)
    /// - KBROAD encryption fails
    /// - CBOR serialization fails
    ///
    /// # Security
    ///
    /// This method handles sensitive cryptographic material:
    /// - `hp` is encrypted before inclusion in the bundle
    /// - `Y*` is hidden via zero-knowledge proof
    /// - `E_k` is derived locally and never transmitted
    ///
    /// The server can validate the bundle but remains cryptographically blind
    /// to all epoch secrets.
    ///
    /// # Performance
    ///
    /// Typical execution time: ~90ms (Apple M1)
    /// - First call adds ~500ms for CRS loading
    /// - Dominated by polynomial operations in proof generation
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let bundle = CityGClient::generate_epoch(
    ///     BTreeMap::new(),
    ///     parts,
    ///     params,
    ///     &mut fs_state,
    ///     Some(&witness_bytes),
    /// )?;
    ///
    /// // Submit to server
    /// api.accept_epoch(&bundle.bundle_cbor).await?;
    /// ```
    pub fn generate_epoch<'a>(
        header: BTreeMap<u64, Value>,
        parts: AnchorInstanceParts<'a>,
        params: OrchestrationParams<'a>,
        fs_state: &mut ForwardSecrecyState,
        witness: Option<&'a [u8]>,
    ) -> Result<ClientEpochBundle, CityGError> {
        let anchor_bundle = AnchorBundle::try_from_parts(&parts)?;
        let params_snapshot = ParamsSnapshot::from(&params);
        let witness_bytes = witness.map(|bytes| bytes.to_vec());

        fs_state.set_epoch_base_ts(params.fs_epoch_base_ts);
        fs_state.autonomic_evolve();

        let result = joiner_kgen_or(header, parts, params, Some(fs_state), witness)?;
        if let Some(tau) = result.fs_tau
            && let Some(fs_ec) = extract_fs_ec(&result.header_map)
        {
            fs_state.record_tau(&result.we_epoch_id, fs_ec, tau);
        }
        ClientEpochBundle::from_joiner_result(anchor_bundle, params_snapshot, witness_bytes, result)
    }

    /// Generate a merge anchor bundle using previously accepted pivot parities.
    ///
    /// Use this method when an existing member needs to resync after being offline
    /// or wants to create a new epoch with fresh forward secrecy parameters.
    ///
    /// Unlike [`generate_epoch`](Self::generate_epoch), this method accepts
    /// pre-computed pivot parities from a merge ticket, allowing the member
    /// to rejoin without generating new cryptographic material from scratch.
    ///
    /// # Arguments
    ///
    /// * `header` - Initial anchor header map
    /// * `parts` - Anchor identity inputs (same parent and join_delta roots for pure merge)
    /// * `params` - Cryptographic profile
    /// * `parities` - Pivot parities from merge ticket (contains fresh FS state)
    /// * `note` - Optional human-readable note (not cryptographically bound)
    /// * `witness` - Optional canonical witness bytes
    ///
    /// # Returns
    ///
    /// Returns [`ClientEpochBundle`] ready for server submission.
    ///
    /// # Errors
    ///
    /// Same error conditions as [`generate_epoch`](Self::generate_epoch).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Fetch merge ticket from server
    /// let merge_ticket = api.merge_ticket(room_id, leaf_id).await?;
    ///
    /// // Generate merge bundle
    /// let bundle = CityGClient::generate_merge(
    ///     BTreeMap::new(),
    ///     parts,
    ///     params,
    ///     &merge_ticket.parities,
    ///     Some("Rejoining after offline"),
    ///     Some(&witness_bytes),
    /// )?;
    /// ```
    pub fn generate_merge<'a>(
        header: BTreeMap<u64, Value>,
        parts: AnchorInstanceParts<'a>,
        params: OrchestrationParams<'a>,
        parities: &[PivotParity],
        note: Option<&'a str>,
        witness: Option<&'a [u8]>,
    ) -> Result<ClientEpochBundle, CityGError> {
        Self::generate_merge_with_forward_state(
            header, parts, params, None, parities, note, witness,
        )
    }

    pub fn generate_merge_with_forward_state<'a>(
        header: BTreeMap<u64, Value>,
        parts: AnchorInstanceParts<'a>,
        params: OrchestrationParams<'a>,
        mut fs_state: Option<&mut ForwardSecrecyState>,
        parities: &[PivotParity],
        note: Option<&'a str>,
        witness: Option<&'a [u8]>,
    ) -> Result<ClientEpochBundle, CityGError> {
        let anchor_bundle = AnchorBundle::try_from_parts(&parts)?;
        let params_snapshot = ParamsSnapshot::from(&params);
        let witness_bytes = witness.map(|bytes| bytes.to_vec());

        if let Some(state) = fs_state.as_deref_mut() {
            state.set_epoch_base_ts(params.fs_epoch_base_ts);
            state.autonomic_evolve();
        }

        let result = joiner_kgen_merge_or_with_state(
            header, parities, note, parts, params, fs_state, witness,
        )?;

        ClientEpochBundle::from_joiner_result(anchor_bundle, params_snapshot, witness_bytes, result)
    }
}

/// Complete epoch bundle ready for server submission.
///
/// This struct contains all cryptographic material needed for a City-G server
/// to validate an epoch without learning secrets. It includes:
///
/// - Anchor instance data (gid, roots, etc.)
/// - Cryptographic proofs (CAPSS, VRF)
/// - Encrypted hash projection key (KBROAD envelope)
/// - Merkle witnesses
/// - Derived keys for local use
///
/// # Server Submission
///
/// The bundle can be serialized to CBOR and submitted via:
/// ```ignore
/// let cbor_bytes = bundle.to_cbor()?;
/// api.accept_epoch(&cbor_bytes).await?;
/// ```
///
/// # Security
///
/// All server-visible fields are either:
/// - Public (gid, roots, leaf IDs)
/// - Commitments/hashes (xk_hash, eid)
/// - Encrypted (hp_ciphertext)
/// - Zero-knowledge proofs (ZK-VRF)
///
/// The server cannot derive `Y*` or `E_k` from this bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientEpochBundle {
    /// Anchor instance data (gid, cat, roots)
    pub anchor: AnchorBundle,
    /// Complete CBOR header map (normalized)
    pub header_map: BTreeMap<u64, Value>,
    /// Hash projection proof (CAPSS Smallwood)
    pub hp_proof: HpProof,
    /// HP binding material (commitments)
    pub hp_binding: BindingMaterial,
    /// Canonical SRX witness bytes (optional)
    pub witness: Option<Vec<u8>>,
    /// CAPSS witness bundle for FS proof
    pub capss_witness: CapssWitnessBundle,
    /// Witness extraction epoch ID (32 bytes)
    pub we_epoch_id: [u8; 32],
    /// Derived epoch key E_k for message encryption (local use only)
    #[serde(default, skip_serializing, skip_deserializing)]
    pub epoch_key: [u8; 32],
    /// Epoch ID (eid) derived from xk_hash and Y*
    #[serde(default, skip_serializing, skip_deserializing)]
    pub eid: [u8; 32],
    /// KBROAD ciphertext (encrypted hp)
    pub hp_ciphertext: Vec<u8>,
    /// HP AEAD key (derived, for local decryption)
    #[serde(default, skip_serializing, skip_deserializing)]
    pub hp_aead_key: [u8; 32],
}

impl Drop for ClientEpochBundle {
    fn drop(&mut self) {
        self.clear_local_secrets();
    }
}

impl ClientEpochBundle {
    fn clear_local_secrets(&mut self) {
        self.epoch_key.zeroize();
        self.eid.zeroize();
        self.hp_aead_key.zeroize();
    }

    fn from_joiner_result(
        mut anchor: AnchorBundle,
        params_snapshot: ParamsSnapshot,
        witness: Option<Vec<u8>>,
        result: JoinerKGenResult,
    ) -> Result<Self, CityGError> {
        let JoinerKGenResult {
            hp_k: _hp_k,
            hp_commit,
            seed_ctx_hash,
            seed_commit,
            seed_bundle_commit,
            rho_commit,
            xk_hash,
            we_epoch_id,
            epoch_key,
            eid,
            anchor_hdr_ctx,
            retired_heads: _,
            mh_note: _,
            hp_proof,
            header_map,
            capss_witness,
            hp_ciphertext,
            hp_aead_key,
            fs_epoch_secret: _fs_epoch_secret,
            fs_tau: _fs_tau,
        } = result;

        anchor.anchor_hdr_ctx = anchor_hdr_ctx;

        let binding = BindingMaterial {
            msphf_crs_id: params_snapshot.msphf_crs_id,
            params_id: params_snapshot.params_id,
            seed_ctx_hash,
            seed_commit,
            rho_commit,
            xk_hash,
            hp_commit,
            seed_bundle_commit,
        };

        Ok(Self {
            anchor,
            header_map,
            hp_proof,
            hp_binding: binding,
            witness,
            capss_witness,
            we_epoch_id,
            epoch_key,
            eid,
            hp_ciphertext,
            hp_aead_key,
        })
    }

    /// Return the group identifier for this bundle.
    pub fn gid(&self) -> &[u8] {
        &self.anchor.gid
    }

    /// Decode the membership delta represented by this bundle.
    ///
    /// - If SRX payload bytes are present, decode them directly.
    /// - If SRX payload bytes are absent for merge-mode headers, return an empty delta.
    /// - If SRX payload bytes are absent for join-mode headers, derive the joined
    ///   leaf from POP fields (per-group leaf id).
    pub fn membership_delta(&self) -> Result<MembershipDelta, CityGError> {
        let payload_bytes = match self
            .header_map
            .get(&msphf_orchestrator::hdr::HDR_SRX_PAYLOAD)
        {
            Some(Value::Bytes(bytes)) => bytes,
            Some(_) => return Err(CityGError::InvalidInput("srx_payload must be bytes")),
            None => {
                if is_merge_header(&self.header_map) {
                    return Ok(MembershipDelta::default());
                }

                let pop_alg = match self.header_map.get(&HDR_POP_ALG) {
                    Some(Value::Text(text)) if !text.is_empty() => text.as_str(),
                    Some(_) => return Err(CityGError::InvalidInput("pop_alg must be text")),
                    None => return Err(CityGError::InvalidInput("missing pop_alg")),
                };
                let pop_pk = match self.header_map.get(&HDR_POP_PK) {
                    Some(Value::Bytes(bytes)) if !bytes.is_empty() => bytes.as_slice(),
                    Some(_) => return Err(CityGError::InvalidInput("pop_pk must be bytes")),
                    None => return Err(CityGError::InvalidInput("missing pop_pk")),
                };
                let joined = msphf_orchestrator::compute_leaf_id(
                    LeafIdMode::PerGroup,
                    self.gid(),
                    pop_alg,
                    pop_pk,
                )?;
                return Ok(MembershipDelta {
                    joined: vec![joined],
                    revoked: Vec::new(),
                });
            }
        };

        let payload: Value = ciborium::de::from_reader(payload_bytes.as_slice())
            .map_err(|_| CityGError::InvalidInput("unable to decode srx payload"))?;
        parse_srx_complete_membership(&payload)
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>, CityGError> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf)
            .map_err(|_| CityGError::InvalidInput("bundle encode failed"))?;
        Ok(buf)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CityGError> {
        if bytes.len() > MAX_BUNDLE_CBOR_BYTES {
            return Err(CityGError::InvalidInput("bundle payload too large"));
        }
        let value: Value = ciborium::de::from_reader(Cursor::new(bytes))
            .map_err(|_| CityGError::InvalidInput("bundle decode failed"))?;
        validate_deterministic_cbor_invariants(&value)?;
        let canonical =
            to_cbor_vec(&value).map_err(|_| CityGError::InvalidInput("bundle encode failed"))?;
        if canonical.as_slice() != bytes {
            return Err(CityGError::InvalidInput("bundle is not deterministic cbor"));
        }
        ciborium::de::from_reader(Cursor::new(bytes))
            .map_err(|_| CityGError::InvalidInput("bundle decode failed"))
    }

    /// Build a borrowing `AnchorInstance` view for server-side verification.
    pub fn anchor_instance(&self) -> AnchorInstance<'_> {
        AnchorInstance {
            gid: &self.anchor.gid,
            cat: &self.anchor.cat,
            we_epoch_id: self.we_epoch_id,
            anchor_hdr_ctx: &self.anchor.anchor_hdr_ctx,
            tswe_salt_hash: &self.anchor.tswe_salt_hash,
            parent_root: &self.anchor.parent_root,
            join_delta_root: &self.anchor.join_delta_root,
            revoked_since_prev_root: &self.anchor.revoked_since_prev_root,
            revoked_root: &self.anchor.revoked_root,
            pox_r_commit: self.anchor.pox_r_commit.as_ref().map(|v| v.as_slice()),
            msphf_hp_commit: Some(&self.hp_binding.hp_commit),
        }
    }

    /// Borrowing view over the binding inputs needed for HP proof verification.
    pub fn hp_binding_inputs(&self) -> HpBindingInputs<'_> {
        self.hp_binding.as_inputs()
    }

    /// Returns the canonical witness bytes, if any were supplied.
    pub fn witness_bytes(&self) -> Option<&[u8]> {
        self.witness.as_deref()
    }

    /// Recompute the epoch key and EID locally using the bundle's retained HP
    /// material. This is the fast path for locally-authored bundles.
    pub fn derive_epoch_secrets(&self) -> Result<([u8; 32], [u8; 32]), CityGError> {
        if self.hp_aead_key == [0u8; 32] {
            return Err(CityGError::InvalidInput(
                "bundle missing local hp key; use derive_epoch_secrets_with_barrier_key",
            ));
        }
        self.derive_epoch_secrets_with_material(&self.hp_ciphertext, &self.hp_aead_key)
    }

    pub fn derive_epoch_secrets_with_barrier_key(
        &self,
        barrier_key: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32]), CityGError> {
        if self.hp_aead_key != [0u8; 32] {
            return self.derive_epoch_secrets_with_material(&self.hp_ciphertext, &self.hp_aead_key);
        }

        let (hp_ciphertext, hp_key) = recover_barrier_hp_material_from_header(
            &self.header_map,
            &self.hp_binding.xk_hash,
            &self.hp_binding.hp_commit,
            barrier_key,
        )?;
        self.derive_epoch_secrets_with_material(&hp_ciphertext, &hp_key)
    }

    pub fn rebind_local_hp_envelope_with_barrier_key(
        &mut self,
        barrier_key: &[u8; 32],
    ) -> Result<(), CityGError> {
        if self.hp_aead_key == [0u8; 32] {
            return Err(CityGError::InvalidInput(
                "bundle missing local hp key; cannot rebuild barrier envelope",
            ));
        }
        let rebound = rebuild_local_hp_envelope_with_barrier_key(
            &self.header_map,
            HpEnvelopeBinding {
                xk_hash: &self.hp_binding.xk_hash,
                hp_commit: &self.hp_binding.hp_commit,
            },
            LocalHpEnvelopeMaterial {
                hp_ciphertext: &self.hp_ciphertext,
                hp_aead_key: &self.hp_aead_key,
            },
            barrier_key,
            HpEnvelopeBinding {
                xk_hash: &self.hp_binding.xk_hash,
                hp_commit: &self.hp_binding.hp_commit,
            },
        )?;
        self.header_map.insert(HDR_HP_BYTES, rebound.envelope);
        self.hp_ciphertext = rebound.hp_ciphertext;
        self.hp_aead_key = rebound.hp_aead_key;
        self.hp_proof = prove_hp_k(&self.hp_binding.as_inputs())?;
        let (epoch_key, eid) = self.derive_epoch_secrets()?;
        self.epoch_key = epoch_key;
        self.eid = eid;
        Ok(())
    }

    pub fn seal_local_hp_header_with_barrier_key(
        &mut self,
        barrier_key: &[u8; 32],
    ) -> Result<(), CityGError> {
        if self.hp_aead_key == [0u8; 32] {
            return Err(CityGError::InvalidInput(
                "bundle missing local hp key; cannot seal barrier envelope",
            ));
        }
        let rebound = rebuild_local_hp_envelope_with_barrier_key(
            &self.header_map,
            HpEnvelopeBinding {
                xk_hash: &self.hp_binding.xk_hash,
                hp_commit: &self.hp_binding.hp_commit,
            },
            LocalHpEnvelopeMaterial {
                hp_ciphertext: &self.hp_ciphertext,
                hp_aead_key: &self.hp_aead_key,
            },
            barrier_key,
            HpEnvelopeBinding {
                xk_hash: &self.hp_binding.xk_hash,
                hp_commit: &self.hp_binding.hp_commit,
            },
        )?;
        self.header_map.insert(HDR_HP_BYTES, rebound.envelope);
        self.hp_proof = prove_hp_k(&self.hp_binding.as_inputs())?;
        let (epoch_key, eid) = self.derive_epoch_secrets()?;
        self.epoch_key = epoch_key;
        self.eid = eid;
        Ok(())
    }

    fn derive_epoch_secrets_with_material(
        &self,
        hp_ciphertext: &[u8],
        hp_key: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32]), CityGError> {
        let anchor = self.anchor_instance();
        let binding_inputs = self.hp_binding.as_inputs();
        let witness = self.witness_bytes().unwrap_or(&[]);
        let epoch_key = extract_epoch_msphf_or(
            &anchor,
            &self.hp_binding.xk_hash,
            hp_ciphertext,
            hp_key,
            &self.hp_proof,
            &binding_inputs,
            witness,
        )?;
        let eid = eid_from_epoch(&epoch_key)?;
        if (self.epoch_key != [0u8; 32] && epoch_key != self.epoch_key)
            || (self.eid != [0u8; 32] && eid != self.eid)
        {
            return Err(CityGError::InvalidInput("epoch secrets mismatch"));
        }
        Ok((epoch_key, eid))
    }
}

fn extract_fs_ec(header: &BTreeMap<u64, Value>) -> Option<u64> {
    match header.get(&HDR_FS_EC)? {
        Value::Integer(int) => (*int).try_into().ok(),
        Value::Bytes(bytes) if bytes.len() == 8 => {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(bytes);
            Some(u64::from_be_bytes(buf))
        }
        _ => None,
    }
}

/// Anchor fields captured from `AnchorInstanceParts`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorBundle {
    pub gid: Vec<u8>,
    pub cat: Vec<u8>,
    pub tswe_salt_hash: Vec<u8>,
    pub parent_root: [u8; 32],
    pub join_delta_root: [u8; 32],
    pub revoked_since_prev_root: [u8; 32],
    pub revoked_root: [u8; 32],
    pub pox_r_commit: Option<[u8; 32]>,
    pub anchor_hdr_ctx: Vec<u8>,
}

impl AnchorBundle {
    fn try_from_parts(parts: &AnchorInstanceParts<'_>) -> Result<Self, CityGError> {
        Ok(Self {
            gid: parts.gid.to_vec(),
            cat: parts.cat.to_vec(),
            tswe_salt_hash: parts.tswe_salt_hash.to_vec(),
            parent_root: slice_to_array(parts.parent_root)?,
            join_delta_root: slice_to_array(parts.join_delta_root)?,
            revoked_since_prev_root: slice_to_array(parts.revoked_since_prev_root)?,
            revoked_root: slice_to_array(parts.revoked_root)?,
            pox_r_commit: parts.pox_r_commit.map(slice_to_array).transpose()?,
            anchor_hdr_ctx: Vec::new(),
        })
    }
}

/// Minimal snapshot of CRS/parameter identifiers.
#[derive(Debug, Clone)]
struct ParamsSnapshot {
    msphf_crs_id: String,
    params_id: String,
}

impl<'a> From<&OrchestrationParams<'a>> for ParamsSnapshot {
    fn from(params: &OrchestrationParams<'a>) -> Self {
        Self {
            msphf_crs_id: params.msphf_crs_id.to_string(),
            params_id: params.params_id.to_string(),
        }
    }
}

/// Material required for HP proof verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingMaterial {
    pub msphf_crs_id: String,
    pub params_id: String,
    pub seed_ctx_hash: [u8; 32],
    pub seed_commit: [u8; 32],
    pub rho_commit: [u8; 32],
    pub xk_hash: [u8; 32],
    pub hp_commit: [u8; 32],
    pub seed_bundle_commit: [u8; 32],
}

impl BindingMaterial {
    pub fn as_inputs(&self) -> HpBindingInputs<'_> {
        HpBindingInputs {
            msphf_crs_id: self.msphf_crs_id.as_str(),
            params_id: self.params_id.as_str(),
            seed_ctx_hash: &self.seed_ctx_hash,
            seed_commit: &self.seed_commit,
            rho_commit: &self.rho_commit,
            xk_hash: &self.xk_hash,
            hp_commit: &self.hp_commit,
        }
    }
}

fn slice_to_array(slice: &[u8]) -> Result<[u8; 32], CityGError> {
    slice
        .try_into()
        .map_err(|_| CityGError::InvalidInput("expected 32-byte array"))
}

fn parse_leaf_array(value: &Value) -> Result<Vec<[u8; 32]>, CityGError> {
    let Value::Array(entries) = value else {
        return Err(CityGError::InvalidInput("expected leaf array"));
    };
    let mut out = Vec::with_capacity(entries.len());
    for leaf in entries {
        match leaf {
            Value::Bytes(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                out.push(arr);
            }
            _ => return Err(CityGError::InvalidInput("leaf entry must be 32 bytes")),
        }
    }
    Ok(out)
}

fn parse_srx_complete_membership(value: &Value) -> Result<MembershipDelta, CityGError> {
    let Value::Array(items) = value else {
        return Err(CityGError::InvalidInput("srx payload must be array"));
    };
    if items.len() != 9 {
        return Err(CityGError::InvalidInput("srx complete payload arity"));
    }

    let joined = parse_leaf_array(&items[4])?;
    let revoked = parse_leaf_array(&items[6])?;

    Ok(MembershipDelta { joined, revoked })
}

fn is_merge_header(header: &BTreeMap<u64, Value>) -> bool {
    [
        HDR_MH_HEADS,
        HDR_ROLLUP_PIVOT_WEID,
        HDR_ROLLUP_PROVENANCE_COMMIT,
        HDR_ROLLUP_EPOCH_REPLAY,
        HDR_ROLLUP_VCK_COMMIT,
        HDR_MERGE_DELEGATION_SIG,
        msphf_orchestrator::hdr::HDR_KBROAD_REPLAY,
        HDR_ROLLUP_FS_MODE,
        msphf_orchestrator::hdr::HDR_FS_EVOLUTION_BOUNDARY,
        msphf_orchestrator::hdr::HDR_FS_PURGE_TIMES,
        msphf_orchestrator::hdr::HDR_FS_CHECKPOINT_EC,
    ]
    .iter()
    .any(|key| header.contains_key(key))
}

/// Join/revoke change-set extracted from an SRX payload.
#[derive(Debug, Clone, Default)]
pub struct MembershipDelta {
    pub joined: Vec<[u8; 32]>,
    pub revoked: Vec<[u8; 32]>,
}

/// Incremental membership tracker that applies SRX deltas.
#[derive(Debug, Clone, Default)]
pub struct GroupMembership {
    members: BTreeSet<[u8; 32]>,
}

impl GroupMembership {
    pub fn new() -> Self {
        Self {
            members: BTreeSet::new(),
        }
    }

    pub fn apply_delta(&mut self, delta: &MembershipDelta) {
        for leaf in &delta.revoked {
            self.members.remove(leaf);
        }
        for leaf in &delta.joined {
            self.members.insert(*leaf);
        }
    }

    pub fn apply_delta_checked(&mut self, delta: &MembershipDelta) -> Result<(), CityGError> {
        for leaf in &delta.revoked {
            if !self.members.remove(leaf) {
                return Err(CityGError::InvalidInput("revoking non-member"));
            }
        }
        for leaf in &delta.joined {
            self.members.insert(*leaf);
        }
        Ok(())
    }

    pub fn members(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.members.iter()
    }

    pub fn contains(&self, leaf: &[u8; 32]) -> bool {
        self.members.contains(leaf)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::demo::{
        demo_bundle, demo_bundle_alice, demo_bundle_bob, demo_member_leaf, kbroad_public,
    };
    use crate::witness::{
        build_branch_b_artifacts, demo_pox_commit, join_delta_root, sequential_leaf,
        witness_to_cbor,
    };
    use msphf_core::{instance::tswe_salt_hash, merkle::canonical_set_root, params::*};
    use msphf_orchestrator::{DEFAULT_POLICY_VERSION, DEFAULT_PROOF_MODE, DEFAULT_VRF_ID};
    use msphf_orchestrator::{
        FsJoinInputs, FsMergeInputs, LeafIdMode, OrchestrationParams, PivotParity, PopKeypair,
        SrxMode,
    };
    use pqcrypto_dilithium::dilithium5::keypair;
    use pqcrypto_traits::sign::PublicKey as _;
    use std::sync::OnceLock;

    fn test_vrf_keys() -> (&'static [u8], &'static [u8]) {
        static VRF_KEYS: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
        let pair = VRF_KEYS.get_or_init(|| {
            let params = match msphf_orchestrator::lb::generate_parameters([0u8; 32]) {
                Ok(params) => params,
                Err(_) => unreachable!("deterministic test VRF params must be derivable"),
            };
            match msphf_orchestrator::lb::generate_keypair(&params, [1u8; 32]) {
                Ok(pair) => pair,
                Err(_) => unreachable!("deterministic test VRF keypair must be derivable"),
            }
        });
        (&pair.0, &pair.1)
    }

    fn demo_barrier_key() -> [u8; 32] {
        [0x77; 32]
    }

    #[test]
    fn slice_to_array_rejects_short_input() {
        let err = slice_to_array(&[0u8; 31]).expect_err("short slice should fail");
        assert!(matches!(err, CityGError::InvalidInput(_)));
    }

    #[test]
    fn params_snapshot_copies_strings() {
        let params = OrchestrationParams {
            msphf_crs_id: "crs",
            params_id: "params",
            srx: None,
            srx_mode: SrxMode::Complete,
            pop_keys: None,
            leaf_id_mode: LeafIdMode::PerGroup,
            proof_mode: "mode",
            vrf_id: "vrf",
            policy_version: "v0",
            vrf_secret_key: None,
            vrf_public_key: None,
            fs_policy_version: "7",
            fs_epoch_base_ts: 0,
            barrier_version: 0,
            fs_join: FsJoinInputs::default(),
            fs_merge: FsMergeInputs::default(),
        };
        let snapshot = ParamsSnapshot::from(&params);
        assert_eq!(snapshot.msphf_crs_id, "crs");
        assert_eq!(snapshot.params_id, "params");
    }

    #[test]
    fn anchor_bundle_from_parts_handles_missing_pox() -> Result<(), Box<dyn std::error::Error>> {
        let parts = AnchorInstanceParts {
            gid: b"gid",
            cat: b"cat",
            tswe_salt_hash: &[0xAA; 32],
            parent_root: &[0x11; 32],
            join_delta_root: &[0x22; 32],
            revoked_since_prev_root: &[0x33; 32],
            revoked_root: &[0x44; 32],
            pox_r_commit: None,
        };
        let bundle = AnchorBundle::try_from_parts(&parts)?;
        assert_eq!(bundle.parent_root, [0x11; 32]);
        assert!(bundle.pox_r_commit.is_none());
        Ok(())
    }

    #[test]
    fn membership_delta_extracts_demo_micro() -> Result<(), Box<dyn std::error::Error>> {
        let bundle = demo_bundle_alice()?;
        let delta = bundle.membership_delta()?;
        assert_eq!(delta.joined, vec![demo_member_leaf("alice")]);
        assert!(delta.revoked.is_empty());
        Ok(())
    }

    #[test]
    fn membership_delta_handles_non_genesis_parent() -> Result<(), Box<dyn std::error::Error>> {
        let genesis = demo_bundle("alice")?;
        let bundle = demo_bundle_bob()?;
        assert_ne!(bundle.anchor.parent_root, [0u8; 32]);
        assert_eq!(bundle.anchor.parent_root, genesis.anchor.join_delta_root);
        let delta = bundle.membership_delta()?;
        assert_eq!(delta.joined, vec![demo_member_leaf("bob")]);
        assert!(delta.revoked.is_empty());
        Ok(())
    }

    #[test]
    fn membership_delta_rejects_invalid_payload_type() -> Result<(), Box<dyn std::error::Error>> {
        let mut bundle = demo_bundle_alice()?;
        bundle.header_map.insert(
            msphf_orchestrator::hdr::HDR_SRX_PAYLOAD,
            Value::Text("bad".to_string()),
        );
        let err = bundle
            .membership_delta()
            .expect_err("invalid payload type should fail");
        assert!(matches!(err, CityGError::InvalidInput(_)));
        Ok(())
    }

    #[test]
    fn membership_delta_ignores_legacy_mode_field() -> Result<(), Box<dyn std::error::Error>> {
        let mut bundle = demo_bundle_alice()?;
        bundle.header_map.insert(
            msphf_orchestrator::hdr::HDR_SRX_MODE,
            Value::Text("srx/vX".to_string()),
        );
        let delta = bundle.membership_delta()?;
        assert_eq!(delta.joined, vec![demo_member_leaf("alice")]);
        assert!(delta.revoked.is_empty());
        Ok(())
    }

    #[test]
    fn group_membership_applies_join_and_revoke() {
        let mut group = GroupMembership::new();
        let delta = MembershipDelta {
            joined: vec![[1; 32], [2; 32]],
            revoked: Vec::new(),
        };
        group.apply_delta(&delta);
        assert!(group.contains(&[1; 32]));
        assert!(group.contains(&[2; 32]));

        let revoke = MembershipDelta {
            joined: Vec::new(),
            revoked: vec![[1; 32]],
        };
        group.apply_delta(&revoke);
        assert!(!group.contains(&[1; 32]));
        assert!(group.contains(&[2; 32]));
    }

    #[test]
    fn wire_bundle_redacts_local_secrets() -> Result<(), Box<dyn std::error::Error>> {
        let bundle = demo_bundle_alice()?;
        let bytes = bundle.to_cbor()?;
        let decoded = ClientEpochBundle::from_cbor(&bytes)?;
        assert_eq!(decoded.epoch_key, [0u8; 32]);
        assert_eq!(decoded.eid, [0u8; 32]);
        assert_eq!(decoded.hp_aead_key, [0u8; 32]);
        Ok(())
    }

    #[test]
    fn from_cbor_rejects_oversized_bundle_payload() {
        let oversized = vec![0u8; MAX_BUNDLE_CBOR_BYTES + 1];
        let err = ClientEpochBundle::from_cbor(&oversized)
            .expect_err("oversized bundle payload must fail");
        assert!(matches!(
            err,
            CityGError::InvalidInput("bundle payload too large")
        ));
    }

    #[test]
    fn from_cbor_rejects_duplicate_map_keys() -> Result<(), Box<dyn std::error::Error>> {
        let bundle = demo_bundle_alice()?;
        let bytes = bundle.to_cbor()?;
        let mut value: Value = ciborium::de::from_reader(Cursor::new(bytes))?;
        let Value::Map(entries) = &mut value else {
            return Err("bundle cbor must decode to map".into());
        };
        let Some((first_key, first_value)) = entries.first().cloned() else {
            return Err("bundle map must not be empty".into());
        };
        entries.push((first_key, first_value));

        let mut non_deterministic = Vec::new();
        ciborium::ser::into_writer(&value, &mut non_deterministic)?;
        let err = ClientEpochBundle::from_cbor(&non_deterministic)
            .expect_err("duplicate map keys must be rejected");
        assert!(matches!(
            err,
            CityGError::InvalidInput("bundle contains duplicate map key")
        ));
        Ok(())
    }

    #[test]
    fn from_cbor_rejects_float_values() -> Result<(), Box<dyn std::error::Error>> {
        let bundle = demo_bundle_alice()?;
        let bytes = bundle.to_cbor()?;
        let mut value: Value = ciborium::de::from_reader(Cursor::new(bytes))?;
        let Value::Map(entries) = &mut value else {
            return Err("bundle cbor must decode to map".into());
        };
        entries.push((Value::Text("float_probe".to_string()), Value::Float(1.5)));

        let mut non_deterministic = Vec::new();
        ciborium::ser::into_writer(&value, &mut non_deterministic)?;
        let err = ClientEpochBundle::from_cbor(&non_deterministic)
            .expect_err("float values must be rejected");
        assert!(matches!(
            err,
            CityGError::InvalidInput("bundle contains float value")
        ));
        Ok(())
    }

    #[test]
    fn clear_local_secrets_zeroizes_bundle_material() -> Result<(), Box<dyn std::error::Error>> {
        let mut bundle = demo_bundle_alice()?;
        assert_ne!(bundle.epoch_key, [0u8; 32]);
        assert_ne!(bundle.eid, [0u8; 32]);
        assert_ne!(bundle.hp_aead_key, [0u8; 32]);

        bundle.clear_local_secrets();
        assert_eq!(bundle.epoch_key, [0u8; 32]);
        assert_eq!(bundle.eid, [0u8; 32]);
        assert_eq!(bundle.hp_aead_key, [0u8; 32]);
        Ok(())
    }

    #[test]
    fn derive_with_barrier_key_works_for_wire_bundle() -> Result<(), Box<dyn std::error::Error>> {
        let mut bundle = demo_bundle_bob()?;
        let barrier_key = demo_barrier_key();
        bundle.seal_local_hp_header_with_barrier_key(&barrier_key)?;
        let bytes = bundle.to_cbor()?;
        let decoded = ClientEpochBundle::from_cbor(&bytes)?;

        let (epoch_key, eid) = decoded.derive_epoch_secrets_with_barrier_key(&barrier_key)?;
        assert_eq!(epoch_key, bundle.epoch_key);
        assert_eq!(eid, bundle.eid);
        Ok(())
    }

    #[test]
    fn cityg_error_display_and_conversion_paths() {
        let msphf_err = MsphfError::invalid_input("bad input");
        let converted: CityGError = msphf_err.into();
        assert!(format!("{converted}").contains("MSPHF error"));

        let acceptance = msphf_orchestrator::AcceptanceError::Msphf(MsphfError::invalid_input("x"));
        let converted: CityGError = acceptance.into();
        assert!(format!("{converted}").contains("acceptance error"));

        let receiver = msphf_orchestrator::receiver::ReceiverError::UnknownHead;
        let converted: CityGError = receiver.into();
        assert!(format!("{converted}").contains("receiver error"));

        let io_err = std::io::Error::other("io");
        let converted: CityGError = io_err.into();
        assert!(format!("{converted}").contains("io error"));

        let invalid = CityGError::InvalidInput("oops");
        assert_eq!(format!("{invalid}"), "invalid input: oops");
    }

    #[test]
    fn membership_delta_parser_handles_missing_and_malformed_variants()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut bundle = demo_bundle_alice()?;
        let original_pop_alg = bundle
            .header_map
            .get(&HDR_POP_ALG)
            .cloned()
            .expect("demo bundle should include pop_alg");
        let original_pop_pk = bundle
            .header_map
            .get(&HDR_POP_PK)
            .cloned()
            .expect("demo bundle should include pop_pk");

        bundle
            .header_map
            .remove(&msphf_orchestrator::hdr::HDR_SRX_PAYLOAD);
        assert_eq!(
            bundle.membership_delta()?.joined,
            vec![demo_member_leaf("alice")]
        );

        bundle
            .header_map
            .insert(HDR_POP_ALG, Value::Bytes(vec![1, 2, 3]));
        assert!(bundle.membership_delta().is_err());
        bundle.header_map.remove(&HDR_POP_ALG);
        assert!(bundle.membership_delta().is_err());
        bundle
            .header_map
            .insert(HDR_POP_ALG, original_pop_alg.clone());

        bundle
            .header_map
            .insert(HDR_POP_PK, Value::Text("bad-pop".to_string()));
        assert!(bundle.membership_delta().is_err());
        bundle.header_map.remove(&HDR_POP_PK);
        assert!(bundle.membership_delta().is_err());
        bundle
            .header_map
            .insert(HDR_POP_PK, original_pop_pk.clone());

        bundle.header_map.insert(
            msphf_orchestrator::hdr::HDR_MH_HEADS,
            Value::Array(Vec::new()),
        );
        assert!(bundle.membership_delta()?.joined.is_empty());
        bundle
            .header_map
            .remove(&msphf_orchestrator::hdr::HDR_MH_HEADS);

        bundle.header_map.insert(
            msphf_orchestrator::hdr::HDR_SRX_PAYLOAD,
            Value::Bytes(vec![0xFF, 0x00]),
        );
        assert!(bundle.membership_delta().is_err());

        let bad_payload = Value::Array(vec![Value::Integer(1.into())]);
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&bad_payload, &mut encoded)?;
        bundle.header_map.insert(
            msphf_orchestrator::hdr::HDR_SRX_PAYLOAD,
            Value::Bytes(encoded),
        );
        assert!(bundle.membership_delta().is_err());

        let non_array_payload = Value::Text("bad".to_string());
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&non_array_payload, &mut encoded)?;
        bundle.header_map.insert(
            msphf_orchestrator::hdr::HDR_SRX_PAYLOAD,
            Value::Bytes(encoded),
        );
        assert!(bundle.membership_delta().is_err());

        let bad_leaf_payload = Value::Array(vec![
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Array(vec![Value::Integer(9.into())]),
            Value::Null,
            Value::Array(vec![]),
            Value::Null,
            Value::Null,
        ]);
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&bad_leaf_payload, &mut encoded)?;
        bundle.header_map.insert(
            msphf_orchestrator::hdr::HDR_SRX_PAYLOAD,
            Value::Bytes(encoded),
        );
        assert!(bundle.membership_delta().is_err());

        let non_array_leaf_payload = Value::Array(vec![
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Text("bad".to_string()),
            Value::Null,
            Value::Array(vec![]),
            Value::Null,
            Value::Null,
        ]);
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&non_array_leaf_payload, &mut encoded)?;
        bundle.header_map.insert(
            msphf_orchestrator::hdr::HDR_SRX_PAYLOAD,
            Value::Bytes(encoded),
        );
        assert!(bundle.membership_delta().is_err());
        Ok(())
    }

    #[test]
    fn derive_epoch_secrets_and_header_helpers_cover_error_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let bundle = demo_bundle_bob()?;
        let (epoch_key, eid) = bundle.derive_epoch_secrets()?;
        assert_eq!(epoch_key, bundle.epoch_key);
        assert_eq!(eid, bundle.eid);
        assert_eq!(bundle.gid(), bundle.anchor.gid.as_slice());

        let wire_bytes = bundle.to_cbor()?;
        let mut wire = ClientEpochBundle::from_cbor(&wire_bytes)?;
        assert!(wire.derive_epoch_secrets().is_err());

        wire.epoch_key = [0xAA; 32];
        let mismatch = wire.derive_epoch_secrets_with_barrier_key(&demo_barrier_key());
        assert!(mismatch.is_err());

        wire.epoch_key = [0u8; 32];
        wire.eid = [0xBB; 32];
        let mismatch = wire.derive_epoch_secrets_with_barrier_key(&demo_barrier_key());
        assert!(mismatch.is_err());

        let mut header = BTreeMap::new();
        header.insert(HDR_FS_EC, Value::Integer(7.into()));
        assert_eq!(extract_fs_ec(&header), Some(7));
        header.insert(HDR_FS_EC, Value::Bytes(7u64.to_be_bytes().to_vec()));
        assert_eq!(extract_fs_ec(&header), Some(7));
        header.insert(HDR_FS_EC, Value::Bytes(vec![1, 2, 3]));
        assert_eq!(extract_fs_ec(&header), None);
        header.insert(HDR_FS_EC, Value::Text("bad".to_string()));
        assert_eq!(extract_fs_ec(&header), None);
        Ok(())
    }

    #[test]
    fn anchor_and_group_membership_checked_paths() -> Result<(), Box<dyn std::error::Error>> {
        let parts = AnchorInstanceParts {
            gid: b"gid2",
            cat: b"cat2",
            tswe_salt_hash: &[0xAA; 32],
            parent_root: &[0x11; 32],
            join_delta_root: &[0x22; 32],
            revoked_since_prev_root: &[0x33; 32],
            revoked_root: &[0x44; 32],
            pox_r_commit: Some(&[0x55; 32]),
        };
        let bundle = AnchorBundle::try_from_parts(&parts)?;
        assert_eq!(bundle.pox_r_commit, Some([0x55; 32]));

        let mut group = GroupMembership::new();
        let join = MembershipDelta {
            joined: vec![[0x10; 32], [0x20; 32]],
            revoked: vec![],
        };
        group.apply_delta_checked(&join)?;
        let collected: Vec<[u8; 32]> = group.members().copied().collect();
        assert_eq!(collected.len(), 2);
        assert!(group.contains(&[0x10; 32]));

        let revoke_missing = MembershipDelta {
            joined: vec![],
            revoked: vec![[0x99; 32]],
        };
        assert!(group.apply_delta_checked(&revoke_missing).is_err());
        Ok(())
    }

    #[test]
    fn apply_delta_checked_rejects_missing_member_directly() {
        let mut group = GroupMembership::new();
        let delta = MembershipDelta {
            joined: vec![],
            revoked: vec![[0xAA; 32]],
        };
        let err = group
            .apply_delta_checked(&delta)
            .expect_err("revoking absent member must fail");
        assert!(matches!(err, CityGError::InvalidInput(_)));
    }

    #[test]
    fn apply_delta_checked_revokes_existing_member() {
        let mut group = GroupMembership::new();
        group
            .apply_delta_checked(&MembershipDelta {
                joined: vec![[0xAB; 32]],
                revoked: vec![],
            })
            .expect("initial join should succeed");
        group
            .apply_delta_checked(&MembershipDelta {
                joined: vec![],
                revoked: vec![[0xAB; 32]],
            })
            .expect("revoking existing member should succeed");
        assert!(!group.contains(&[0xAB; 32]));
    }

    #[test]
    fn generate_epoch_records_tau_and_exposes_binding_inputs()
    -> Result<(), Box<dyn std::error::Error>> {
        let gid = [0x43; 32];
        let cat = [0x21; 32];
        let parent_leaves: Vec<[u8; 32]> = Vec::new();
        let join_leaves = vec![sequential_leaf(77)];
        let parent_root = canonical_set_root(&parent_leaves)?;
        let tswe_salt = tswe_salt_hash(&gid, &parent_root)?;
        let join_root = join_delta_root(&join_leaves)?;
        let revoked_root = [0u8; 32];
        let revoked_since_root = [0u8; 32];
        let (canonical_witness, srx_owned) = build_branch_b_artifacts(
            &parent_leaves,
            &join_leaves,
            parent_root,
            revoked_since_root,
        )
        .expect("branch-b artifact generation should succeed");
        let witness_bytes = witness_to_cbor(&canonical_witness)?;
        let srx_inputs = srx_owned.into_srx_inputs();
        let pox_commit = demo_pox_commit();

        let parts = AnchorInstanceParts {
            gid: &gid,
            cat: &cat,
            tswe_salt_hash: tswe_salt.as_ref(),
            parent_root: &parent_root,
            join_delta_root: join_root.as_ref(),
            revoked_since_prev_root: &revoked_since_root,
            revoked_root: &revoked_root,
            pox_r_commit: Some(pox_commit.as_ref()),
        };

        let (pop_pk, pop_sk) = keypair();
        let (vrf_secret_key, vrf_public_key) = test_vrf_keys();
        let params = OrchestrationParams {
            msphf_crs_id: RLWE_CRS_ID_DEFAULT,
            params_id: RLWE_PARAMS_ID_MOCK,
            srx: Some(srx_inputs),
            srx_mode: SrxMode::Complete,
            pop_keys: Some(PopKeypair {
                algorithm: "ML-DSA-65",
                public_key: pop_pk.as_bytes(),
                secret_key: &pop_sk,
            }),
            leaf_id_mode: LeafIdMode::PerGroup,
            proof_mode: DEFAULT_PROOF_MODE,
            vrf_id: DEFAULT_VRF_ID,
            policy_version: DEFAULT_POLICY_VERSION,
            vrf_secret_key: Some(vrf_secret_key),
            vrf_public_key: Some(vrf_public_key),
            fs_policy_version: "7",
            fs_epoch_base_ts: 0,
            barrier_version: 0,
            fs_join: FsJoinInputs::default(),
            fs_merge: FsMergeInputs::default(),
        };

        let mut fs_state = ForwardSecrecyState::new([0xAA; 32]);
        let mut header = BTreeMap::new();
        header.insert(
            msphf_orchestrator::hdr::HDR_KBROAD_ALG,
            Value::Text("ml-kem-768".to_string()),
        );
        header.insert(
            msphf_orchestrator::hdr::HDR_KBROAD_PUB,
            Value::Bytes(kbroad_public().to_vec()),
        );
        let bundle =
            CityGClient::generate_epoch(header, parts, params, &mut fs_state, Some(&witness_bytes))
                .expect("generate_epoch should succeed");

        let fs_ec = extract_fs_ec(&bundle.header_map).ok_or("missing fs_ec in generated header")?;
        assert!(fs_state.cached_tau(&bundle.we_epoch_id, fs_ec).is_some());
        let binding_inputs = bundle.hp_binding_inputs();
        assert_eq!(binding_inputs.xk_hash, &bundle.hp_binding.xk_hash);
        Ok(())
    }

    #[test]
    fn generate_merge_path_with_accepted_parity() -> Result<(), Box<dyn std::error::Error>> {
        let source = demo_bundle_bob()?;
        let binding_inputs = source.hp_binding_inputs();
        assert_eq!(binding_inputs.hp_commit, &source.hp_binding.hp_commit);
        let parity = PivotParity {
            gid: source.anchor.gid.clone(),
            cat: source.anchor.cat.clone(),
            parent_root: source.anchor.parent_root,
            we_epoch_id: source.we_epoch_id,
            rho_commit: source.hp_binding.rho_commit,
            seed_ctx_hash: source.hp_binding.seed_ctx_hash,
            seed_commit: source.hp_binding.seed_commit,
            hp_commit: source.hp_binding.hp_commit,
            xk_hash: source.hp_binding.xk_hash,
            join_delta_root: source.anchor.join_delta_root,
            revoked_since_root: source.anchor.revoked_since_prev_root,
            revoked_root: source.anchor.revoked_root,
            accept_seq: 1,
            crs_id: source.hp_binding.msphf_crs_id.as_bytes().to_vec(),
            params_id: source.hp_binding.params_id.as_bytes().to_vec(),
            policy_version: DEFAULT_POLICY_VERSION.to_string(),
            proof_mode: DEFAULT_PROOF_MODE.to_string(),
            vrf_id: DEFAULT_VRF_ID.to_string(),
            vrf_proof: vec![0x01],
            vrf_public: vec![0x02],
            mask_a: [0xAA; 32],
            mask_b: [0xBB; 32],
            fs_capss: vec![0x03],
            proofs_commit: [0x44; 32],
            srx_commit: None,
            srx_root_sw: None,
            is_join: false,
            hp_envelope: std::sync::Arc::from(
                to_cbor_vec(
                    source
                        .header_map
                        .get(&HDR_HP_BYTES)
                        .expect("demo bundle should contain hp envelope"),
                )
                .expect("demo envelope must encode")
                .into_boxed_slice(),
            ),
            fs_epoch_commit: Some([0x55; 32]),
            fs_ec: Some(0),
            fs_dev_commit: Some([0u8; 32]),
        };

        let parts = AnchorInstanceParts {
            gid: source.anchor.gid.as_slice(),
            cat: source.anchor.cat.as_slice(),
            tswe_salt_hash: source.anchor.tswe_salt_hash.as_slice(),
            parent_root: &source.anchor.parent_root,
            join_delta_root: &source.anchor.join_delta_root,
            revoked_since_prev_root: &source.anchor.revoked_since_prev_root,
            revoked_root: &source.anchor.revoked_root,
            pox_r_commit: source
                .anchor
                .pox_r_commit
                .as_ref()
                .map(|value| value.as_slice()),
        };

        let (pop_pk, pop_sk) = keypair();
        let (vrf_secret_key, vrf_public_key) = test_vrf_keys();
        let params = OrchestrationParams {
            msphf_crs_id: RLWE_CRS_ID_DEFAULT,
            params_id: RLWE_PARAMS_ID_MOCK,
            srx: None,
            srx_mode: SrxMode::Complete,
            pop_keys: Some(PopKeypair {
                algorithm: "ML-DSA-65",
                public_key: pop_pk.as_bytes(),
                secret_key: &pop_sk,
            }),
            leaf_id_mode: LeafIdMode::PerGroup,
            proof_mode: DEFAULT_PROOF_MODE,
            vrf_id: DEFAULT_VRF_ID,
            policy_version: DEFAULT_POLICY_VERSION,
            vrf_secret_key: Some(vrf_secret_key),
            vrf_public_key: Some(vrf_public_key),
            fs_policy_version: "7",
            fs_epoch_base_ts: 0,
            barrier_version: 0,
            fs_join: FsJoinInputs::default(),
            fs_merge: FsMergeInputs::default(),
        };

        let mut header = BTreeMap::new();
        header.insert(
            msphf_orchestrator::hdr::HDR_KBROAD_ALG,
            Value::Text("ml-kem-768".to_string()),
        );
        header.insert(
            msphf_orchestrator::hdr::HDR_KBROAD_PUB,
            Value::Bytes(kbroad_public().to_vec()),
        );
        let merged = CityGClient::generate_merge(
            header,
            parts,
            params,
            &[parity],
            Some("merge-note"),
            source.witness_bytes(),
        )
        .expect("generate_merge should succeed");
        assert_eq!(merged.gid(), source.gid());
        assert!(
            merged
                .header_map
                .contains_key(&msphf_orchestrator::hdr::HDR_MH_HEADS)
        );
        Ok(())
    }

    #[test]
    fn rebound_merge_hp_envelope_derives_epoch_key() -> Result<(), Box<dyn std::error::Error>> {
        let source = demo_bundle_bob()?;
        let parity = PivotParity {
            gid: source.anchor.gid.clone(),
            cat: source.anchor.cat.clone(),
            parent_root: source.anchor.parent_root,
            we_epoch_id: source.we_epoch_id,
            rho_commit: source.hp_binding.rho_commit,
            seed_ctx_hash: source.hp_binding.seed_ctx_hash,
            seed_commit: source.hp_binding.seed_commit,
            hp_commit: source.hp_binding.hp_commit,
            xk_hash: source.hp_binding.xk_hash,
            join_delta_root: source.anchor.join_delta_root,
            revoked_since_root: source.anchor.revoked_since_prev_root,
            revoked_root: source.anchor.revoked_root,
            accept_seq: 1,
            crs_id: source.hp_binding.msphf_crs_id.as_bytes().to_vec(),
            params_id: source.hp_binding.params_id.as_bytes().to_vec(),
            policy_version: DEFAULT_POLICY_VERSION.to_string(),
            proof_mode: DEFAULT_PROOF_MODE.to_string(),
            vrf_id: DEFAULT_VRF_ID.to_string(),
            vrf_proof: vec![0x01],
            vrf_public: vec![0x02],
            mask_a: [0xAA; 32],
            mask_b: [0xBB; 32],
            fs_capss: vec![0x03],
            proofs_commit: [0x44; 32],
            srx_commit: None,
            srx_root_sw: None,
            is_join: false,
            hp_envelope: std::sync::Arc::from(
                to_cbor_vec(
                    source
                        .header_map
                        .get(&HDR_HP_BYTES)
                        .expect("demo bundle should contain hp envelope"),
                )?
                .into_boxed_slice(),
            ),
            fs_epoch_commit: Some([0x55; 32]),
            fs_ec: Some(0),
            fs_dev_commit: Some([0u8; 32]),
        };
        let parts = AnchorInstanceParts {
            gid: source.anchor.gid.as_slice(),
            cat: source.anchor.cat.as_slice(),
            tswe_salt_hash: source.anchor.tswe_salt_hash.as_slice(),
            parent_root: &source.anchor.parent_root,
            join_delta_root: &source.anchor.join_delta_root,
            revoked_since_prev_root: &source.anchor.revoked_since_prev_root,
            revoked_root: &source.anchor.revoked_root,
            pox_r_commit: source
                .anchor
                .pox_r_commit
                .as_ref()
                .map(|value| value.as_slice()),
        };
        let (pop_pk, pop_sk) = keypair();
        let (vrf_secret_key, vrf_public_key) = test_vrf_keys();
        let params = OrchestrationParams {
            msphf_crs_id: RLWE_CRS_ID_DEFAULT,
            params_id: RLWE_PARAMS_ID_MOCK,
            srx: None,
            srx_mode: SrxMode::Complete,
            pop_keys: Some(PopKeypair {
                algorithm: "ML-DSA-65",
                public_key: pop_pk.as_bytes(),
                secret_key: &pop_sk,
            }),
            leaf_id_mode: LeafIdMode::PerGroup,
            proof_mode: DEFAULT_PROOF_MODE,
            vrf_id: DEFAULT_VRF_ID,
            policy_version: DEFAULT_POLICY_VERSION,
            vrf_secret_key: Some(vrf_secret_key),
            vrf_public_key: Some(vrf_public_key),
            fs_policy_version: "7",
            fs_epoch_base_ts: 0,
            barrier_version: 0,
            fs_join: FsJoinInputs::default(),
            fs_merge: FsMergeInputs::default(),
        };
        let mut header = BTreeMap::new();
        header.insert(
            msphf_orchestrator::hdr::HDR_KBROAD_ALG,
            Value::Text("ml-kem-768".to_string()),
        );
        header.insert(
            msphf_orchestrator::hdr::HDR_KBROAD_PUB,
            Value::Bytes(kbroad_public().to_vec()),
        );
        let mut merged = CityGClient::generate_merge(
            header,
            parts,
            params,
            std::slice::from_ref(&parity),
            Some("merge-note"),
            source.witness_bytes(),
        )?;
        let (epoch_key, eid) = merged.derive_epoch_secrets()?;
        assert_ne!(epoch_key, [0u8; 32]);
        assert_ne!(eid, [0u8; 32]);
        merged.rebind_local_hp_envelope_with_barrier_key(&demo_barrier_key())?;
        let (epoch_key, eid) = merged.derive_epoch_secrets()?;
        assert_eq!(epoch_key, merged.epoch_key);
        assert_eq!(eid, merged.eid);
        assert!(merged.header_map.contains_key(&HDR_HP_BYTES));
        Ok(())
    }

    #[test]
    fn rebind_local_barrier_hp_envelope_works_for_generated_merge()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = demo_bundle_bob()?;
        let parity = PivotParity {
            gid: source.anchor.gid.clone(),
            cat: source.anchor.cat.clone(),
            parent_root: source.anchor.parent_root,
            we_epoch_id: source.we_epoch_id,
            rho_commit: source.hp_binding.rho_commit,
            seed_ctx_hash: source.hp_binding.seed_ctx_hash,
            seed_commit: source.hp_binding.seed_commit,
            hp_commit: source.hp_binding.hp_commit,
            xk_hash: source.hp_binding.xk_hash,
            join_delta_root: source.anchor.join_delta_root,
            revoked_since_root: source.anchor.revoked_since_prev_root,
            revoked_root: source.anchor.revoked_root,
            accept_seq: 1,
            crs_id: source.hp_binding.msphf_crs_id.as_bytes().to_vec(),
            params_id: source.hp_binding.params_id.as_bytes().to_vec(),
            policy_version: DEFAULT_POLICY_VERSION.to_string(),
            proof_mode: DEFAULT_PROOF_MODE.to_string(),
            vrf_id: DEFAULT_VRF_ID.to_string(),
            vrf_proof: vec![0x01],
            vrf_public: vec![0x02],
            mask_a: [0xAA; 32],
            mask_b: [0xBB; 32],
            fs_capss: vec![0x03],
            proofs_commit: [0x44; 32],
            srx_commit: None,
            srx_root_sw: None,
            is_join: false,
            hp_envelope: std::sync::Arc::from(
                to_cbor_vec(
                    source
                        .header_map
                        .get(&HDR_HP_BYTES)
                        .expect("demo bundle should contain hp envelope"),
                )?
                .into_boxed_slice(),
            ),
            fs_epoch_commit: Some([0x55; 32]),
            fs_ec: Some(0),
            fs_dev_commit: Some([0u8; 32]),
        };
        let parts = AnchorInstanceParts {
            gid: source.anchor.gid.as_slice(),
            cat: source.anchor.cat.as_slice(),
            tswe_salt_hash: source.anchor.tswe_salt_hash.as_slice(),
            parent_root: &source.anchor.parent_root,
            join_delta_root: &source.anchor.join_delta_root,
            revoked_since_prev_root: &source.anchor.revoked_since_prev_root,
            revoked_root: &source.anchor.revoked_root,
            pox_r_commit: source
                .anchor
                .pox_r_commit
                .as_ref()
                .map(|value| value.as_slice()),
        };
        let (pop_pk, pop_sk) = keypair();
        let (vrf_secret_key, vrf_public_key) = test_vrf_keys();
        let params = OrchestrationParams {
            msphf_crs_id: RLWE_CRS_ID_DEFAULT,
            params_id: RLWE_PARAMS_ID_MOCK,
            srx: None,
            srx_mode: SrxMode::Complete,
            pop_keys: Some(PopKeypair {
                algorithm: "ML-DSA-65",
                public_key: pop_pk.as_bytes(),
                secret_key: &pop_sk,
            }),
            leaf_id_mode: LeafIdMode::PerGroup,
            proof_mode: DEFAULT_PROOF_MODE,
            vrf_id: DEFAULT_VRF_ID,
            policy_version: DEFAULT_POLICY_VERSION,
            vrf_secret_key: Some(vrf_secret_key),
            vrf_public_key: Some(vrf_public_key),
            fs_policy_version: "7",
            fs_epoch_base_ts: 0,
            barrier_version: 1,
            fs_join: FsJoinInputs::default(),
            fs_merge: FsMergeInputs::default(),
        };
        let mut header = BTreeMap::new();
        header.insert(
            msphf_orchestrator::hdr::HDR_KBROAD_ALG,
            Value::Text("ml-kem-768".to_string()),
        );
        header.insert(
            msphf_orchestrator::hdr::HDR_KBROAD_PUB,
            Value::Bytes(kbroad_public().to_vec()),
        );
        header.insert(
            msphf_orchestrator::hdr::HDR_BARRIER_VERSION,
            Value::Integer(1u64.into()),
        );
        header.insert(
            msphf_orchestrator::hdr::HDR_BARRIER_UPDATE_REASON,
            Value::Integer(2u64.into()),
        );
        let mut merged = CityGClient::generate_merge(
            header,
            parts,
            params,
            &[parity],
            Some("merge-note"),
            source.witness_bytes(),
        )?;

        merged.rebind_local_hp_envelope_with_barrier_key(&[0x77; 32])?;
        let (epoch_key, eid) = merged.derive_epoch_secrets()?;
        assert_eq!(epoch_key, merged.epoch_key);
        assert_eq!(eid, merged.eid);
        Ok(())
    }

    #[test]
    fn derive_with_barrier_key_prefers_local_material() -> Result<(), Box<dyn std::error::Error>> {
        let bundle = demo_bundle_bob()?;
        let bad_key = [0xFF; 32];
        let (epoch_key, eid) = bundle.derive_epoch_secrets_with_barrier_key(&bad_key)?;
        assert_eq!(epoch_key, bundle.epoch_key);
        assert_eq!(eid, bundle.eid);
        Ok(())
    }

    #[test]
    fn derive_with_barrier_key_rejects_wrong_key_for_wire_bundle()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut bundle = demo_bundle_bob()?;
        let barrier_key = demo_barrier_key();
        bundle.seal_local_hp_header_with_barrier_key(&barrier_key)?;
        let bytes = bundle.to_cbor()?;
        let wire_bundle = ClientEpochBundle::from_cbor(&bytes)?;
        let bad_secret = [0xCD; 32];
        assert!(
            wire_bundle
                .derive_epoch_secrets_with_barrier_key(&bad_secret)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn derive_epoch_secrets_rejects_mismatched_hp_binding() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut bundle = demo_bundle_bob()?;
        bundle.hp_binding.xk_hash = [0xEE; 32];
        assert!(bundle.derive_epoch_secrets().is_err());
        Ok(())
    }
}

pub mod demo;
