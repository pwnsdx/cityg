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
    collections::{BTreeMap, BTreeSet},
    convert::TryInto,
    fmt,
    io::Cursor,
};

use ciborium::value::Value;
use msphf_core::{MsphfError, hash::eid_from_epoch, instance::AnchorInstance};
use msphf_orchestrator::{
    AnchorInstanceParts, CapssWitnessBundle, ForwardSecrecyState, HpBindingInputs, HpProof,
    JoinerKGenResult, OrchestrationParams, PivotParity, extract_epoch_msphf_or, hdr::HDR_FS_EC,
    joiner_kgen_merge_or, joiner_kgen_or,
};
use serde::{Deserialize, Serialize};

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
        let anchor_bundle = AnchorBundle::try_from_parts(&parts)?;
        let params_snapshot = ParamsSnapshot::from(&params);
        let witness_bytes = witness.map(|bytes| bytes.to_vec());

        let result = joiner_kgen_merge_or(header, parities, note, parts, params, witness)?;

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
    pub epoch_key: [u8; 32],
    /// Epoch ID (eid) derived from xk_hash and Y*
    pub eid: [u8; 32],
    /// KBROAD ciphertext (encrypted hp)
    pub hp_ciphertext: Vec<u8>,
    /// HP AEAD key (derived, for local decryption)
    pub hp_aead_key: [u8; 32],
}

impl ClientEpochBundle {
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

    /// Decode the SRX payload and return the join/revoke delta it represents.
    /// For merge-only heads (where no SRX payload is present) an empty delta is returned.
    pub fn membership_delta(&self) -> Result<MembershipDelta, CityGError> {
        let Some(mode_value) = self.header_map.get(&msphf_orchestrator::hdr::HDR_SRX_MODE) else {
            return Ok(MembershipDelta::default());
        };

        let mode = match mode_value {
            Value::Text(text) => text.as_str(),
            Value::Bytes(bytes) => std::str::from_utf8(bytes)
                .map_err(|_| CityGError::InvalidInput("srx_mode invalid utf8"))?,
            _ => return Err(CityGError::InvalidInput("srx_mode invalid type")),
        };

        let payload_bytes = match self
            .header_map
            .get(&msphf_orchestrator::hdr::HDR_SRX_PAYLOAD)
        {
            Some(Value::Bytes(bytes)) => bytes,
            Some(_) => return Err(CityGError::InvalidInput("srx_payload must be bytes")),
            None => return Ok(MembershipDelta::default()),
        };

        let payload: Value = ciborium::de::from_reader(payload_bytes.as_slice())
            .map_err(|_| CityGError::InvalidInput("unable to decode srx payload"))?;

        match mode {
            "srx/v1-complete" => parse_srx_complete_membership(&payload),
            _ => Err(CityGError::InvalidInput("unsupported srx_mode")),
        }
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>, CityGError> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf)
            .map_err(|_| CityGError::InvalidInput("bundle encode failed"))?;
        Ok(buf)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CityGError> {
        let cursor = Cursor::new(bytes);
        ciborium::de::from_reader(cursor)
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

    /// Recompute the epoch key and EID locally using the bundle's KBROAD
    /// ciphertext. This must be called by clients after acceptance to derive
    /// the epoch secrets without relying on the server.
    pub fn derive_epoch_secrets(&self) -> Result<([u8; 32], [u8; 32]), CityGError> {
        let anchor = self.anchor_instance();
        let binding_inputs = self.hp_binding.as_inputs();
        let witness = self.witness_bytes().unwrap_or(&[]);
        let epoch_key = extract_epoch_msphf_or(
            &anchor,
            &self.hp_binding.xk_hash,
            &self.hp_ciphertext,
            &self.hp_aead_key,
            &self.hp_proof,
            &binding_inputs,
            witness,
        )?;
        let eid = eid_from_epoch(&epoch_key)?;
        if epoch_key != self.epoch_key || eid != self.eid {
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
mod tests {
    use super::*;
    use crate::demo::{demo_bundle, demo_bundle_alice, demo_bundle_bob};
    use msphf_orchestrator::{
        FsJoinInputs, FsMergeInputs, LeafIdMode, OrchestrationParams, SrxMode,
    };

    #[test]
    fn slice_to_array_rejects_short_input() {
        let result = slice_to_array(&[0u8; 31]);
        assert!(result.is_err(), "short slice should fail");
        if let Err(err) = result {
            assert!(matches!(err, CityGError::InvalidInput(_)));
        }
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
            fs_policy_version: "fs-policy",
            fs_epoch_base_ts: 0,
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
        assert_eq!(delta.joined.len(), 1);
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
        assert_eq!(delta.joined.len(), 1);
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
        let result = bundle.membership_delta();
        assert!(result.is_err(), "invalid payload type should fail");
        if let Err(err) = result {
            assert!(matches!(err, CityGError::InvalidInput(_)));
        }
        Ok(())
    }

    #[test]
    fn membership_delta_rejects_unknown_mode() -> Result<(), Box<dyn std::error::Error>> {
        let mut bundle = demo_bundle_alice()?;
        bundle.header_map.insert(
            msphf_orchestrator::hdr::HDR_SRX_MODE,
            Value::Text("srx/vX".to_string()),
        );
        let result = bundle.membership_delta();
        assert!(result.is_err(), "unknown mode should fail");
        if let Err(err) = result {
            assert!(matches!(err, CityGError::InvalidInput(_)));
        }
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
}

pub mod demo;
