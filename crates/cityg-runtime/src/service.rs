use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, SystemTime},
};

use ciborium::ser::into_writer;
use cityg_client::{CityGError, ClientEpochBundle};
use cityg_server::{
    BarrierJoinLeafRecord, BarrierPublicTreeSnapshot, CityGServer,
    JoinProvisioningAuthorityArtifacts, JoinTicketBundle, MergeAcceptanceRecord, MergeTicketBundle,
    MergeTicketIntent, ResolvedJoins, ResolvedRevokedLeaves, ServerOutcome,
};
use msphf_core::hash::h_l;
use msphf_orchestrator::{PivotParity, hdr};
use serde::Serialize;
use serde_bytes::ByteBuf;
use thiserror::Error;

use crate::{
    AliasLeafEntry, AliasLeafLookup, EpochScope, RoomVolatileState, StoredBundle, StoredMessage,
    aligned_fs_epoch_base_ts,
};

/// Maximum accepted chat ciphertext payload size.
pub const MAX_MESSAGE_CIPHERTEXT_BYTES: usize = 1_048_640;

/// Shared retention policy for room-local volatile backlogs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoomRetentionPolicy {
    pub retention: Duration,
    pub prune_interval_ms: u64,
}

/// Accepted bundle metadata needed to update shared room indexes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleIndexUpdate {
    pub we_epoch_id: [u8; 32],
    pub bytes: Vec<u8>,
    pub membership_root: [u8; 32],
    pub timestamp_ms: u64,
}

/// Room-scoped chat payload ready to be stored in the volatile backlog.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomMessageWrite {
    pub we_epoch_id: [u8; 32],
    pub sender_leaf: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub sender: Vec<u8>,
    pub timestamp_ms: u64,
}

/// Outcome of applying a bundle to the shared volatile room indexes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedBundleIndexes {
    pub gid: [u8; 32],
    pub we_epoch_id: [u8; 32],
    pub membership_root: [u8; 32],
    pub joined: Vec<[u8; 32]>,
    pub revoked: Vec<[u8; 32]>,
    pub timestamp_ms: u64,
}

/// Shared runtime-level errors for volatile room state mutations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RoomServiceError {
    #[error("invalid gid length in bundle")]
    InvalidGidLength,
    #[error("failed to compute membership delta: {0}")]
    MembershipDelta(String),
}

/// Shared runtime-level errors for room membership authorization.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RoomAuthorizationError {
    #[error("resource not found")]
    NotFound,
    #[error("leaf is not authorized")]
    Unauthorized,
}

/// Shared runtime-level errors for room-scoped message storage.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RoomMessageStoreError {
    #[error("resource not found")]
    NotFound,
    #[error("leaf is not a member for epoch")]
    EpochUnauthorized,
    #[error("leaf is not a member for room")]
    RoomUnauthorized,
}

/// Shared runtime-level errors for room member listings.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RoomMemberListingError {
    #[error("resource not found")]
    NotFound,
}

/// Shared runtime-level errors for multi-head window seeding.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RoomWindowSeedError {
    #[error("invalid gid length in bundle")]
    InvalidGidLength,
    #[error("failed to compute window id: {0}")]
    ComputeWindowId(String),
    #[error("failed to seed multi-head window: {0}")]
    AcceptHead(String),
}

/// Shared runtime-level errors for window configuration validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RoomWindowConfigError {
    #[error("h_max must be at least 1")]
    HMaxTooSmall,
    #[error("h_max too large")]
    HMaxTooLarge,
    #[error("ttl_ms must be positive")]
    NonPositiveTtl,
}

impl RoomWindowConfigError {
    #[must_use]
    pub const fn api_message(&self) -> &'static str {
        match self {
            Self::HMaxTooSmall => "h_max must be at least 1",
            Self::HMaxTooLarge => "h_max too large",
            Self::NonPositiveTtl => "ttl_ms must be positive",
        }
    }
}

/// Parsed room-window limit update that can be applied to one or more servers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoomWindowLimitUpdate {
    pub h_max: Option<usize>,
    pub ttl: Option<Duration>,
}

/// Effective room-window limits after applying an update.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoomWindowLimits {
    pub h_max: usize,
    pub ttl: Duration,
}

/// Shared snapshot of a multi-head window entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomWindowEntrySnapshot {
    pub wid: Vec<u8>,
    pub heads: Vec<RoomWindowHeadSnapshot>,
}

/// Shared snapshot of a single active multi-head window head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomWindowHeadSnapshot {
    pub we_epoch_id: [u8; 32],
    pub msphf_hp_commit: [u8; 32],
    pub seed_ctx_hash: [u8; 32],
    pub rho_commit: [u8; 32],
    pub seed_commit: [u8; 32],
    pub xk_hash: [u8; 32],
    pub accept_seq: u64,
    pub age_ms: u64,
}

/// Shared snapshot of a telemetry row derived from the acceptance engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomTelemetrySnapshotEntry {
    pub gid: Vec<u8>,
    pub parent_root: [u8; 32],
    pub head_attempts: u64,
    pub head_insertions: u64,
    pub freeze_window_full: u64,
    pub freeze_rho_replay: u64,
    pub last_active_heads: u64,
    pub barrier_n_max: u64,
    pub barrier_active_leaf_count: u64,
    pub barrier_revoked_leaf_count: u64,
    pub barrier_pending_join_ticket_count: u64,
    pub barrier_reserved_cover_leaf_count: u64,
    pub barrier_remaining_cover_leaf_slots: u64,
    pub barrier_leaf_utilization_basis_points: u64,
    pub barrier_leaf_capacity_warning_percent: u64,
    pub barrier_leaf_capacity_refusal_percent: u64,
}

/// Shared pagination result for room-member listings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaginatedMembers {
    pub members: Vec<[u8; 32]>,
    pub total_count: u64,
    pub next_offset: u64,
}

/// Shared runtime-level errors for accepted bundle materialization.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RoomBundleMaterializationError {
    #[error("accepted merge parity missing hp envelope for stored bundle")]
    MissingAcceptedParityEnvelope,
    #[error("accepted merge parity hp envelope malformed for stored bundle")]
    MalformedAcceptedParityEnvelope,
    #[error("accepted merge parity missing hp envelope for replayed stored bundle")]
    MissingReplayedParityEnvelope,
    #[error("accepted merge parity hp envelope malformed for replayed stored bundle")]
    MalformedReplayedParityEnvelope,
    #[error("failed to sanitize bundle: {0}")]
    Serialize(String),
    #[error("failed to sanitize replayed bundle: {0}")]
    ReplaySerialize(String),
}

/// Authoritative accept result after the room engine commits a bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedRoomEpoch {
    pub outcome: ServerOutcome,
    pub applied: AppliedBundleIndexes,
    pub stored_bundle_bytes: Vec<u8>,
}

/// Prepared accepted bundle payload that can be committed into room indexes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedAcceptedBundle {
    pub outcome: ServerOutcome,
    pub stored_bundle_bytes: Vec<u8>,
}

/// Shared runtime-level errors for authoritative room acceptance.
#[derive(Debug, Error)]
pub enum RoomAcceptEpochError {
    #[error(transparent)]
    Client(#[from] CityGError),
    #[error(transparent)]
    Materialization(#[from] RoomBundleMaterializationError),
    #[error(transparent)]
    Service(#[from] RoomServiceError),
}

impl RoomAcceptEpochError {
    pub fn client_error(&self) -> Option<&CityGError> {
        match self {
            Self::Client(err) => Some(err),
            Self::Materialization(_) | Self::Service(_) => None,
        }
    }
}

/// Shared runtime-level errors for room-scoped join/merge ticket preparation.
#[derive(Debug, Error)]
pub enum RoomTicketPreparationError {
    #[error(transparent)]
    Client(#[from] CityGError),
    #[error("missing committed barrier roots hash")]
    MissingCommittedBarrierRootsHash,
    #[error("join ticket current_join_records length overflow")]
    JoinRecordsLengthOverflow,
    #[error("join ticket current_revoked_leaf_indices length overflow")]
    RevokedLeafIndicesLengthOverflow,
    #[error("failed to encode pivot parity")]
    PivotParityEncode,
}

impl RoomTicketPreparationError {
    pub fn client_error(&self) -> Option<&CityGError> {
        match self {
            Self::Client(err) => Some(err),
            _ => None,
        }
    }
}

/// Shared runtime-level errors for barrier helper authority/profile envelopes.
#[derive(Debug, Error)]
pub enum RoomBarrierEnvelopeError {
    #[error(transparent)]
    Client(#[from] CityGError),
    #[error("group barrier_version missing")]
    MissingBarrierVersion,
    #[error("group barrier tree hash missing")]
    MissingBarrierTreeHash,
    #[error("group n_max missing")]
    MissingNMax,
    #[error("group max_barrier_update_bytes missing")]
    MissingMaxBarrierUpdateBytes,
}

impl RoomBarrierEnvelopeError {
    pub fn client_error(&self) -> Option<&CityGError> {
        match self {
            Self::Client(err) => Some(err),
            _ => None,
        }
    }
}

/// Neutral runtime payload for a prepared join ticket response.
#[derive(Debug)]
pub struct PreparedJoinTicket {
    pub bundle: JoinTicketBundle,
    pub policy_version: String,
    pub fs_policy_version: String,
    pub fs_epoch_base_ts: u64,
    pub bootstrap_public: Vec<u8>,
    pub history_authority_descriptor: Vec<u8>,
    pub current_global_history_attestation: Vec<u8>,
    pub current_join_records_completeness_attestation: Vec<u8>,
    pub current_revoked_leaf_indices_completeness_attestation: Vec<u8>,
    pub history_authority_extension: String,
    pub provisioning_artifact: Vec<u8>,
    pub deployment_profile_manifest: Vec<u8>,
}

/// Neutral runtime payload for a prepared merge ticket response.
pub struct PreparedMergeTicket {
    pub bundle: MergeTicketBundle,
    pub history_authority_descriptor: Vec<u8>,
    pub current_global_history_attestation: Vec<u8>,
    pub history_authority_extension: String,
    pub pivot_parity_cbor: Vec<Vec<u8>>,
    pub merge_ticket_artifact: Vec<u8>,
    pub deployment_profile_manifest: Vec<u8>,
}

/// Neutral runtime payload shared by barrier helper/current-state endpoints.
#[derive(Clone, Debug)]
pub struct PreparedBarrierEnvelope {
    pub history_authority_descriptor: Vec<u8>,
    pub global_history_attestation: Vec<u8>,
    pub history_authority_extension: String,
    pub n_max: u64,
    pub max_barrier_update_bytes: u64,
    pub fs_forward_leap_policy: cityg_server::FsForwardLeapPolicy,
    pub deployment_profile_manifest: Vec<u8>,
}

/// Page metadata shared by barrier helper responses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BarrierPage<T> {
    pub items: Vec<T>,
    pub page_offset: u32,
    pub next_page_offset: Option<u32>,
    pub total_entries: u32,
}

/// Shared runtime-level errors for barrier helper pagination.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BarrierPaginationError {
    #[error("max_entries exceeds MAX_BARRIER_HELPER_PAGE_ENTRIES")]
    MaxEntriesExceedsLimit,
    #[error("barrier helper total_entries overflow")]
    TotalEntriesOverflow,
    #[error("page_offset out of range")]
    PageOffsetOutOfRange,
    #[error("max_entries out of range")]
    MaxEntriesOutOfRange,
    #[error("barrier helper next_page_offset overflow")]
    NextPageOffsetOverflow,
}

/// Shared runtime-level errors for barrier helper preparation flows.
#[derive(Debug, Error)]
pub enum RoomBarrierHelperPreparationError {
    #[error(transparent)]
    Client(#[from] CityGError),
    #[error(transparent)]
    Envelope(#[from] RoomBarrierEnvelopeError),
    #[error(transparent)]
    Pagination(#[from] BarrierPaginationError),
}

impl RoomBarrierHelperPreparationError {
    pub fn client_error(&self) -> Option<&CityGError> {
        match self {
            Self::Client(err) => Some(err),
            Self::Envelope(err) => err.client_error(),
            Self::Pagination(_) => None,
        }
    }
}

/// Neutral runtime payload for `resolve_revoked_leaf_indices`.
#[derive(Clone, Debug)]
pub struct PreparedResolvedRevokedLeaves {
    pub resolved: ResolvedRevokedLeaves,
    pub page: BarrierPage<u32>,
    pub helper_completeness_attestation: Vec<u8>,
    pub barrier: PreparedBarrierEnvelope,
}

/// Neutral runtime payload for `resolve_joins_since`.
#[derive(Clone, Debug)]
pub struct PreparedResolvedJoins {
    pub resolved: ResolvedJoins,
    pub page: BarrierPage<BarrierJoinLeafRecord>,
    pub helper_completeness_attestation: Vec<u8>,
    pub barrier: PreparedBarrierEnvelope,
}

/// Neutral runtime payload for `fetch_barrier_public_tree`.
#[derive(Clone, Debug)]
pub struct PreparedBarrierPublicTree {
    pub snapshot: BarrierPublicTreeSnapshot,
    pub page: BarrierPage<Vec<u8>>,
    pub helper_completeness_attestation: Vec<u8>,
    pub barrier: PreparedBarrierEnvelope,
}

/// Neutral runtime payload for `lookup_merge_acceptance`.
#[derive(Clone, Debug)]
pub struct PreparedMergeAcceptanceLookup {
    pub record: MergeAcceptanceRecord,
    pub barrier: PreparedBarrierEnvelope,
}

/// Neutral runtime input for `issue_full_verification_witness`.
#[derive(Clone, Debug)]
pub struct FullVerificationWitnessRequest {
    pub author_leaf_id: [u8; 32],
    pub current_history_commitment: cityg_server::HistoryCommitment,
    pub joins_prev_barrier_version: u64,
    pub current_global_history_attestation: Vec<u8>,
    pub deployment_profile_manifest: Vec<u8>,
    pub merge_ticket_artifact: Vec<u8>,
    pub barrier_update_reason: u64,
    pub revocation_roots_hash: [u8; 32],
    pub revocation_target_leaf_id: Option<[u8; 32]>,
    pub join_records: Vec<BarrierJoinLeafRecord>,
    pub revoked_leaf_indices: Vec<u32>,
    pub barrier_update: Vec<u8>,
}

/// Shared runtime-level errors for full verification witness preparation.
#[derive(Debug, Error)]
pub enum RoomFullVerificationWitnessPreparationError {
    #[error(transparent)]
    Client(#[from] CityGError),
    #[error(transparent)]
    HelperClient(CityGError),
    #[error(transparent)]
    Ticket(#[from] RoomTicketPreparationError),
    #[error("group not found")]
    GroupNotFound,
    #[error("current_history_commitment mismatch with authenticated current state")]
    CurrentHistoryCommitmentMismatch,
    #[error("joins_prev_barrier_version mismatch with authenticated current state")]
    JoinsPrevBarrierVersionMismatch,
    #[error("current_global_history_attestation mismatch with authenticated current state")]
    GlobalHistoryAttestationMismatch,
    #[error("deployment_profile_manifest mismatch with authenticated current state")]
    DeploymentProfileManifestMismatch,
    #[error("merge_ticket_artifact mismatch with authenticated current state")]
    MergeTicketArtifactMismatch,
    #[error("revocation_roots_hash mismatch with authenticated current state")]
    RevocationRootsHashMismatch,
    #[error("join helper data mismatch with authenticated current state")]
    JoinHelperDataMismatch,
    #[error("revoked helper data mismatch with authenticated current state")]
    RevokedHelperDataMismatch,
    #[error("cover_leaf_index out of range")]
    CoverLeafIndexOutOfRange,
}

impl RoomFullVerificationWitnessPreparationError {
    pub fn client_error(&self) -> Option<&CityGError> {
        match self {
            Self::Client(err) | Self::HelperClient(err) => Some(err),
            Self::Ticket(err) => err.client_error(),
            _ => None,
        }
    }
}

/// Apply accepted bundle side effects to the shared volatile room state.
///
/// This intentionally covers only the shared runtime mutation logic:
/// epoch-scope indexing, member join/revoke bookkeeping, and stored bundle
/// retention. API-specific side effects such as WebSocket broadcast or alias
/// registry updates should be handled by the caller.
pub fn apply_bundle_indexes(
    room_state: &mut RoomVolatileState,
    bundle: &ClientEpochBundle,
    update: BundleIndexUpdate,
    retention_policy: RoomRetentionPolicy,
) -> Result<AppliedBundleIndexes, RoomServiceError> {
    let gid: [u8; 32] = bundle
        .gid()
        .try_into()
        .map_err(|_| RoomServiceError::InvalidGidLength)?;
    let delta = bundle
        .membership_delta()
        .map_err(|err| RoomServiceError::MembershipDelta(err.to_string()))?;
    let joined = delta.joined.clone();
    let revoked = delta.revoked.clone();

    room_state.record_epoch_scope(
        update.we_epoch_id,
        EpochScope {
            gid,
            membership_root: update.membership_root,
        },
    );
    for leaf in &joined {
        room_state.record_member_join(*leaf, update.we_epoch_id, update.timestamp_ms);
    }
    if !revoked.is_empty() {
        let _ = room_state.revoke_members(&revoked);
    }
    room_state.store_bundle(
        update.we_epoch_id,
        StoredBundle {
            bytes: update.bytes,
            stored_at_ms: update.timestamp_ms,
        },
        update.timestamp_ms,
        retention_policy.retention,
        retention_policy.prune_interval_ms,
    );

    Ok(AppliedBundleIndexes {
        gid,
        we_epoch_id: update.we_epoch_id,
        membership_root: update.membership_root,
        joined,
        revoked,
        timestamp_ms: update.timestamp_ms,
    })
}

/// Materialize the stored accepted bundle representation used by runtime adapters.
pub fn materialize_stored_bundle(
    server: &mut CityGServer,
    bundle: &ClientEpochBundle,
    outcome: &ServerOutcome,
) -> Result<Vec<u8>, RoomBundleMaterializationError> {
    let mut stored = bundle.clone();
    if !stored.header_map.contains_key(&hdr::HDR_HP_BYTES)
        && is_merge_bundle_header(&stored.header_map)
    {
        let parity = [outcome.new_root, outcome.parent_root]
            .into_iter()
            .find_map(|root| {
                server
                    .context_mut()
                    .pivot_parities_for(bundle.gid(), &root)
                    .into_iter()
                    .find(|parity| {
                        parity.we_epoch_id == outcome.we_epoch_id && !parity.hp_envelope.is_empty()
                    })
            })
            .ok_or(RoomBundleMaterializationError::MissingAcceptedParityEnvelope)?;
        let envelope: ciborium::value::Value =
            ciborium::de::from_reader(parity.hp_envelope.as_ref())
                .map_err(|_| RoomBundleMaterializationError::MalformedAcceptedParityEnvelope)?;
        stored.header_map.insert(hdr::HDR_HP_BYTES, envelope);
    }
    stored
        .to_cbor()
        .map_err(|err| RoomBundleMaterializationError::Serialize(err.to_string()))
}

/// Materialize the replayed stored bundle representation used during rehydration.
pub fn materialize_replayed_bundle(
    server: &mut CityGServer,
    bundle: &ClientEpochBundle,
    membership_root: [u8; 32],
) -> Result<Vec<u8>, RoomBundleMaterializationError> {
    let mut stored = bundle.clone();
    if !stored.header_map.contains_key(&hdr::HDR_HP_BYTES)
        && is_merge_bundle_header(&stored.header_map)
    {
        let parity = [membership_root, bundle.anchor.parent_root]
            .into_iter()
            .find_map(|root| {
                server
                    .context_mut()
                    .pivot_parities_for(bundle.gid(), &root)
                    .into_iter()
                    .find(|parity| {
                        parity.we_epoch_id == bundle.we_epoch_id && !parity.hp_envelope.is_empty()
                    })
            })
            .ok_or(RoomBundleMaterializationError::MissingReplayedParityEnvelope)?;
        let envelope: ciborium::value::Value =
            ciborium::de::from_reader(parity.hp_envelope.as_ref())
                .map_err(|_| RoomBundleMaterializationError::MalformedReplayedParityEnvelope)?;
        stored.header_map.insert(hdr::HDR_HP_BYTES, envelope);
    }
    stored
        .to_cbor()
        .map_err(|err| RoomBundleMaterializationError::ReplaySerialize(err.to_string()))
}

/// Apply the authoritative acceptance step without touching room-local indexes.
///
/// This split exists so runtimes with separate server/index locks can keep the
/// acceptance and volatile-index commit phases decoupled while still reusing
/// the same protocol transition logic.
pub fn prepare_accepted_bundle(
    server: &mut CityGServer,
    bundle: &ClientEpochBundle,
) -> Result<PreparedAcceptedBundle, RoomAcceptEpochError> {
    let outcome = server.accept_epoch(bundle)?;
    let stored_bundle_bytes = materialize_stored_bundle(server, bundle, &outcome)?;
    Ok(PreparedAcceptedBundle {
        outcome,
        stored_bundle_bytes,
    })
}

/// Commit a previously accepted bundle into the shared volatile room indexes.
pub fn commit_prepared_accepted_bundle(
    room_state: &mut RoomVolatileState,
    bundle: &ClientEpochBundle,
    prepared: PreparedAcceptedBundle,
    timestamp_ms: u64,
    retention_policy: RoomRetentionPolicy,
) -> Result<AcceptedRoomEpoch, RoomServiceError> {
    let applied = apply_bundle_indexes(
        room_state,
        bundle,
        BundleIndexUpdate {
            we_epoch_id: prepared.outcome.we_epoch_id,
            bytes: prepared.stored_bundle_bytes.clone(),
            membership_root: prepared.outcome.new_root,
            timestamp_ms,
        },
        retention_policy,
    )?;
    Ok(AcceptedRoomEpoch {
        outcome: prepared.outcome,
        applied,
        stored_bundle_bytes: prepared.stored_bundle_bytes,
    })
}

/// Apply an authoritative bundle acceptance and commit the derived room indexes.
pub fn accept_room_epoch(
    server: &mut CityGServer,
    room_state: &mut RoomVolatileState,
    bundle: &ClientEpochBundle,
    timestamp_ms: u64,
    retention_policy: RoomRetentionPolicy,
) -> Result<AcceptedRoomEpoch, RoomAcceptEpochError> {
    let prepared = prepare_accepted_bundle(server, bundle)?;
    commit_prepared_accepted_bundle(room_state, bundle, prepared, timestamp_ms, retention_policy)
        .map_err(RoomAcceptEpochError::from)
}

/// Build a join ticket and all authority/profile artifacts needed to serialize it.
pub fn prepare_join_ticket(
    server: &mut CityGServer,
    gid: &[u8; 32],
    requested_leaf_id: Option<[u8; 32]>,
    now: SystemTime,
    fs_epoch_period_seconds: u64,
    profile_version: &str,
) -> Result<PreparedJoinTicket, RoomTicketPreparationError> {
    let bundle = server.build_join_ticket_with_leaf(gid, requested_leaf_id)?;
    let policy_version = server.context().policy_version().to_string();
    let fs_policy_version = server
        .context()
        .fs_policy_version()
        .map(|value| value.to_string())
        .unwrap_or_else(|| "7".to_string());
    let fs_epoch_base_ts = match server.context().fs_base_ts() {
        Some(base_ts) => base_ts,
        None => {
            let base_ts = aligned_fs_epoch_base_ts(now, fs_epoch_period_seconds);
            server.context_mut().set_fs_base_ts(Some(base_ts));
            base_ts
        }
    };
    let bootstrap_public = server
        .context()
        .bootstrap_public_key()
        .map(|key| key.to_vec())
        .unwrap_or_default();
    let history_authority_descriptor = server.history_authority_descriptor_bytes()?;
    let current_global_history_attestation = server.global_history_attestation_bytes(
        gid,
        &bundle.current_history_commitment,
        bundle.barrier_version,
        &bundle.kem_tree_hash_after,
    )?;
    let current_join_records_completeness_attestation = server
        .helper_completeness_attestation_joins_bytes(
            &bundle.current_history_commitment,
            bundle.barrier_version.saturating_sub(1),
            0,
            u32::try_from(bundle.current_join_records.len())
                .map_err(|_| RoomTicketPreparationError::JoinRecordsLengthOverflow)?,
            bundle.current_join_records.as_slice(),
        )?;
    let committed_revocation_roots_hash = server
        .barrier_roots_hash(gid)
        .ok_or(RoomTicketPreparationError::MissingCommittedBarrierRootsHash)?;
    let current_revoked_leaf_indices_completeness_attestation = server
        .helper_completeness_attestation_revoked_bytes(
            &bundle.current_history_commitment,
            &committed_revocation_roots_hash,
            0,
            u32::try_from(bundle.current_revoked_leaf_indices.len())
                .map_err(|_| RoomTicketPreparationError::RevokedLeafIndicesLengthOverflow)?,
            bundle.current_revoked_leaf_indices.as_slice(),
        )?;
    let history_authority_extension = server.history_authority_extension_id().to_string();
    let provisioning_artifact = server.join_provisioning_artifact_bytes(
        &bundle,
        profile_version,
        JoinProvisioningAuthorityArtifacts {
            history_authority_extension: history_authority_extension.as_str(),
            history_authority_descriptor: history_authority_descriptor.as_slice(),
            current_global_history_attestation: current_global_history_attestation.as_slice(),
            current_join_records_completeness_attestation:
                current_join_records_completeness_attestation.as_slice(),
            current_revoked_leaf_indices_completeness_attestation:
                current_revoked_leaf_indices_completeness_attestation.as_slice(),
        },
    )?;
    let deployment_profile_manifest = server.deployment_profile_manifest_bytes(
        gid,
        profile_version,
        history_authority_extension.as_str(),
        bundle.n_max,
        bundle.max_barrier_update_bytes,
        bundle.fs_forward_leap_policy,
    )?;

    Ok(PreparedJoinTicket {
        bundle,
        policy_version,
        fs_policy_version,
        fs_epoch_base_ts,
        bootstrap_public,
        history_authority_descriptor,
        current_global_history_attestation,
        current_join_records_completeness_attestation,
        current_revoked_leaf_indices_completeness_attestation,
        history_authority_extension,
        provisioning_artifact,
        deployment_profile_manifest,
    })
}

/// Resolve the room member set for an optional authenticated parent root.
pub fn fetch_room_members(
    server: &CityGServer,
    gid: &[u8; 32],
    parent_root: Option<[u8; 32]>,
) -> Result<(Vec<[u8; 32]>, [u8; 32]), RoomMemberListingError> {
    let root = match parent_root {
        Some(root) => root,
        None => server
            .latest_parent_root(gid)
            .ok_or(RoomMemberListingError::NotFound)?,
    };
    let members = server
        .members_for_root(gid, &root)
        .ok_or(RoomMemberListingError::NotFound)?;
    Ok((members, root))
}

/// Filter room members by alias substring or leaf-id hex substring.
#[must_use]
pub fn filter_room_members_by_query(
    members: &[[u8; 32]],
    alias_lookup: &AliasLeafLookup,
    query: &str,
) -> Vec<[u8; 32]> {
    let query = query.to_lowercase();
    members
        .iter()
        .filter(|leaf| {
            if hex::encode(leaf).contains(&query) {
                return true;
            }
            alias_lookup
                .get(*leaf)
                .is_some_and(|entry| entry.alias.to_lowercase().contains(&query))
        })
        .copied()
        .collect()
}

/// Paginate a room-member list using the API's offset/limit semantics.
#[must_use]
pub fn paginate_room_members(members: &[[u8; 32]], offset: u64, limit: u32) -> PaginatedMembers {
    let total_count = members.len() as u64;
    let start = offset.min(total_count) as usize;
    let end = (start as u64 + u64::from(limit)).min(total_count) as usize;
    let next_offset = if end as u64 >= total_count {
        total_count
    } else {
        end as u64
    };

    PaginatedMembers {
        members: members[start..end].to_vec(),
        total_count,
        next_offset,
    }
}

/// Resolve the alias entry for a room-member listing.
#[must_use]
pub fn alias_entry_for_member<'a>(
    alias_lookup: &'a AliasLeafLookup,
    leaf_id: &[u8; 32],
) -> Option<&'a AliasLeafEntry> {
    alias_lookup.get(leaf_id)
}

/// Build a merge ticket and all authority/profile artifacts needed to serialize it.
pub fn prepare_merge_ticket(
    server: &mut CityGServer,
    gid: &[u8; 32],
    leaf_id: &[u8; 32],
    intent: MergeTicketIntent,
    profile_version: &str,
) -> Result<PreparedMergeTicket, RoomTicketPreparationError> {
    let bundle = match intent {
        MergeTicketIntent::Leave => server.build_merge_ticket(gid, leaf_id)?,
        MergeTicketIntent::Refresh => server.build_merge_ticket_for_refresh(gid, leaf_id)?,
    };
    prepare_merge_ticket_from_bundle(server, gid, bundle, profile_version)
}

/// Register a room and seed its first explicit room-admin key.
pub fn bootstrap_room_with_admin(
    server: &mut CityGServer,
    gid: &[u8; 32],
    kbroad_public: Vec<u8>,
    initial_room_admin_pop_key: Vec<u8>,
) -> Result<(), CityGError> {
    server.register_group_with_admin(gid, kbroad_public, initial_room_admin_pop_key)
}

/// Rotate a room's kbroad key under explicit room-admin authorization.
pub fn rotate_room_kbroad(
    server: &mut CityGServer,
    gid: &[u8; 32],
    kbroad_public: Vec<u8>,
    actor_pop_key: &[u8],
    replay_key: [u8; 32],
) -> Result<u64, CityGError> {
    server.rotate_group_kbroad_with_actor(gid, kbroad_public, actor_pop_key, replay_key)
}

/// Grant an explicit room-admin key under room-admin authorization.
pub fn grant_room_admin(
    server: &mut CityGServer,
    gid: &[u8; 32],
    actor_pop_key: &[u8],
    target_pop_public_key: Vec<u8>,
    replay_key: [u8; 32],
) -> Result<(bool, u64), CityGError> {
    server.grant_room_admin(gid, actor_pop_key, target_pop_public_key, replay_key)
}

/// Revoke an explicit room-admin key under room-admin authorization.
pub fn revoke_room_admin(
    server: &mut CityGServer,
    gid: &[u8; 32],
    actor_pop_key: &[u8],
    target_pop_public_key: &[u8],
    replay_key: [u8; 32],
) -> Result<(bool, u64), CityGError> {
    server.revoke_room_admin(gid, actor_pop_key, target_pop_public_key, replay_key)
}

/// List explicit room-admin keys under room-admin authorization.
pub fn list_room_admins(
    server: &CityGServer,
    gid: &[u8; 32],
    actor_pop_key: &[u8],
) -> Result<Vec<Vec<u8>>, CityGError> {
    server.list_room_admins(gid, actor_pop_key)
}

/// Build and serialize an expel-member ticket through the shared merge-ticket path.
pub fn prepare_expel_member_ticket(
    server: &mut CityGServer,
    gid: &[u8; 32],
    actor_pop_key: &[u8],
    author_leaf_id: &[u8; 32],
    target_leaf_id: &[u8; 32],
    replay_key: [u8; 32],
    profile_version: &str,
) -> Result<PreparedMergeTicket, RoomTicketPreparationError> {
    let bundle = server.build_admin_expel_ticket(
        gid,
        actor_pop_key,
        author_leaf_id,
        target_leaf_id,
        replay_key,
    )?;
    prepare_merge_ticket_from_bundle(server, gid, bundle, profile_version)
}

/// Prepare merge-ticket artifacts for an already constructed merge bundle.
pub fn prepare_merge_ticket_from_bundle(
    server: &CityGServer,
    gid: &[u8; 32],
    bundle: MergeTicketBundle,
    profile_version: &str,
) -> Result<PreparedMergeTicket, RoomTicketPreparationError> {
    let history_authority_descriptor = server.history_authority_descriptor_bytes()?;
    let current_global_history_attestation = server.global_history_attestation_bytes(
        gid,
        &bundle.current_history_commitment,
        bundle.barrier_version,
        &bundle.kem_tree_hash_after,
    )?;
    let history_authority_extension = server.history_authority_extension_id().to_string();
    let pivot_parity_cbor = bundle
        .parities
        .iter()
        .map(pivot_parity_to_cbor)
        .collect::<Result<Vec<_>, _>>()?;
    let merge_ticket_artifact = server.merge_ticket_artifact_bytes(
        &bundle,
        profile_version,
        history_authority_extension.as_str(),
        history_authority_descriptor.as_slice(),
        current_global_history_attestation.as_slice(),
        pivot_parity_cbor.as_slice(),
    )?;
    let deployment_profile_manifest = server.deployment_profile_manifest_bytes(
        gid,
        profile_version,
        history_authority_extension.as_str(),
        bundle.n_max,
        bundle.max_barrier_update_bytes,
        bundle.fs_forward_leap_policy,
    )?;

    Ok(PreparedMergeTicket {
        bundle,
        history_authority_descriptor,
        current_global_history_attestation,
        history_authority_extension,
        pivot_parity_cbor,
        merge_ticket_artifact,
        deployment_profile_manifest,
    })
}

/// Prepare a full verification witness against the room's authenticated current state.
pub fn prepare_full_verification_witness(
    server: &mut CityGServer,
    gid: &[u8; 32],
    request: FullVerificationWitnessRequest,
    profile_version: &str,
) -> Result<Vec<u8>, RoomFullVerificationWitnessPreparationError> {
    let bundle = if request.barrier_update_reason == 0 {
        match request.revocation_target_leaf_id {
            Some(target_leaf_id) if target_leaf_id != request.author_leaf_id => server
                .build_merge_ticket_for_targeted_revocation(
                    gid,
                    &request.author_leaf_id,
                    &target_leaf_id,
                )?,
            _ => server.build_merge_ticket(gid, &request.author_leaf_id)?,
        }
    } else {
        server.build_merge_ticket_for_refresh(gid, &request.author_leaf_id)?
    };
    let PreparedMergeTicket {
        bundle,
        current_global_history_attestation: expected_attestation,
        merge_ticket_artifact: expected_merge_ticket_artifact,
        deployment_profile_manifest: expected_manifest,
        ..
    } = prepare_merge_ticket_from_bundle(server, gid, bundle, profile_version)?;
    let committed_revocation_roots_hash = server
        .barrier_roots_hash(gid)
        .ok_or(RoomFullVerificationWitnessPreparationError::GroupNotFound)?;

    if bundle.current_history_commitment != request.current_history_commitment {
        return Err(RoomFullVerificationWitnessPreparationError::CurrentHistoryCommitmentMismatch);
    }
    if request.joins_prev_barrier_version != bundle.barrier_version {
        return Err(RoomFullVerificationWitnessPreparationError::JoinsPrevBarrierVersionMismatch);
    }
    if request.current_global_history_attestation != expected_attestation {
        return Err(RoomFullVerificationWitnessPreparationError::GlobalHistoryAttestationMismatch);
    }
    if request.deployment_profile_manifest != expected_manifest {
        return Err(RoomFullVerificationWitnessPreparationError::DeploymentProfileManifestMismatch);
    }
    if request.merge_ticket_artifact != expected_merge_ticket_artifact {
        return Err(RoomFullVerificationWitnessPreparationError::MergeTicketArtifactMismatch);
    }

    let expected_revocation_roots_hash = if request.barrier_update_reason == 0 {
        compute_api_revocation_roots_hash(&bundle.revoked_since_root, &bundle.revoked_root)?
    } else {
        committed_revocation_roots_hash
    };
    if request.revocation_roots_hash != expected_revocation_roots_hash {
        return Err(RoomFullVerificationWitnessPreparationError::RevocationRootsHashMismatch);
    }

    let resolved_joins = server
        .resolve_joins_since(gid, request.joins_prev_barrier_version)
        .map_err(RoomFullVerificationWitnessPreparationError::HelperClient)?;
    if resolved_joins.history_commitment != bundle.current_history_commitment
        || request.join_records != resolved_joins.records
    {
        return Err(RoomFullVerificationWitnessPreparationError::JoinHelperDataMismatch);
    }

    let expected_revoked_leaf_indices = if request.barrier_update_reason == 0 {
        let mut leaf_indices = server
            .resolve_revoked_leaf_indices(gid, &committed_revocation_roots_hash)
            .map_err(RoomFullVerificationWitnessPreparationError::HelperClient)?
            .leaf_indices;
        let cover_leaf_index = u32::try_from(bundle.cover_leaf_index)
            .map_err(|_| RoomFullVerificationWitnessPreparationError::CoverLeafIndexOutOfRange)?;
        if let Err(insert_at) = leaf_indices.binary_search(&cover_leaf_index) {
            leaf_indices.insert(insert_at, cover_leaf_index);
        }
        leaf_indices
    } else {
        let resolved_revoked = server
            .resolve_revoked_leaf_indices(gid, &request.revocation_roots_hash)
            .map_err(RoomFullVerificationWitnessPreparationError::HelperClient)?;
        if resolved_revoked.history_commitment != bundle.current_history_commitment {
            return Err(RoomFullVerificationWitnessPreparationError::RevokedHelperDataMismatch);
        }
        resolved_revoked.leaf_indices
    };
    if request.revoked_leaf_indices != expected_revoked_leaf_indices {
        return Err(RoomFullVerificationWitnessPreparationError::RevokedHelperDataMismatch);
    }

    server
        .full_verification_witness_bytes(
            gid,
            &bundle.current_history_commitment,
            bundle.barrier_version,
            &bundle.kem_tree_hash_after,
            &request.author_leaf_id,
            request.barrier_update_reason,
            bundle.cover_leaf_index,
            request.barrier_update.as_slice(),
            request.joins_prev_barrier_version,
            request.join_records.as_slice(),
            &request.revocation_roots_hash,
            expected_revoked_leaf_indices.as_slice(),
            request.deployment_profile_manifest.as_slice(),
        )
        .map_err(Into::into)
}

fn compute_api_revocation_roots_hash(
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

/// Encode a merge ticket's pivot parities in the response CBOR format.
pub fn encode_pivot_parity_cbor(
    parities: &[PivotParity],
) -> Result<Vec<Vec<u8>>, RoomTicketPreparationError> {
    parities
        .iter()
        .map(pivot_parity_to_cbor)
        .collect::<Result<Vec<_>, _>>()
}

/// Paginate a barrier helper collection using the shared API/Worker semantics.
pub fn paginate_barrier_helper_slice<T: Clone>(
    items: &[T],
    page_offset: u32,
    max_entries: u32,
    max_page_entries: u32,
) -> Result<BarrierPage<T>, BarrierPaginationError> {
    let page_len = if max_entries == 0 {
        max_page_entries
    } else {
        max_entries
    };
    if page_len == 0 || page_len > max_page_entries {
        return Err(BarrierPaginationError::MaxEntriesExceedsLimit);
    }
    let total_entries =
        u32::try_from(items.len()).map_err(|_| BarrierPaginationError::TotalEntriesOverflow)?;
    if total_entries == 0 {
        if page_offset != 0 {
            return Err(BarrierPaginationError::PageOffsetOutOfRange);
        }
        return Ok(BarrierPage {
            items: Vec::new(),
            page_offset: 0,
            next_page_offset: None,
            total_entries: 0,
        });
    }
    if page_offset >= total_entries {
        return Err(BarrierPaginationError::PageOffsetOutOfRange);
    }
    let start =
        usize::try_from(page_offset).map_err(|_| BarrierPaginationError::PageOffsetOutOfRange)?;
    let page_len =
        usize::try_from(page_len).map_err(|_| BarrierPaginationError::MaxEntriesOutOfRange)?;
    let end = items.len().min(start.saturating_add(page_len));
    let next_page_offset = if end < items.len() {
        Some(u32::try_from(end).map_err(|_| BarrierPaginationError::NextPageOffsetOverflow)?)
    } else {
        None
    };

    Ok(BarrierPage {
        items: items[start..end].to_vec(),
        page_offset,
        next_page_offset,
        total_entries,
    })
}

/// Prepare the common authority/profile envelope for a concrete barrier snapshot.
pub fn prepare_barrier_envelope(
    server: &CityGServer,
    gid: &[u8; 32],
    history_commitment: &cityg_server::HistoryCommitment,
    barrier_version: u64,
    kem_tree_hash_after: &[u8; 32],
    n_max: u64,
    profile_version: &str,
) -> Result<PreparedBarrierEnvelope, RoomBarrierEnvelopeError> {
    let history_authority_descriptor = server.history_authority_descriptor_bytes()?;
    let global_history_attestation = server.global_history_attestation_bytes(
        gid,
        history_commitment,
        barrier_version,
        kem_tree_hash_after,
    )?;
    let max_barrier_update_bytes = server
        .barrier_max_barrier_update_bytes(gid)
        .ok_or(RoomBarrierEnvelopeError::MissingMaxBarrierUpdateBytes)?;
    let fs_forward_leap_policy = server.fs_forward_leap_policy();
    let history_authority_extension = server.history_authority_extension_id().to_string();
    let deployment_profile_manifest = server.deployment_profile_manifest_bytes(
        gid,
        profile_version,
        history_authority_extension.as_str(),
        n_max,
        max_barrier_update_bytes,
        fs_forward_leap_policy,
    )?;

    Ok(PreparedBarrierEnvelope {
        history_authority_descriptor,
        global_history_attestation,
        history_authority_extension,
        n_max,
        max_barrier_update_bytes,
        fs_forward_leap_policy,
        deployment_profile_manifest,
    })
}

/// Prepare the common authority/profile envelope using the group's latest committed barrier state.
pub fn prepare_current_barrier_envelope(
    server: &CityGServer,
    gid: &[u8; 32],
    history_commitment: &cityg_server::HistoryCommitment,
    profile_version: &str,
) -> Result<PreparedBarrierEnvelope, RoomBarrierEnvelopeError> {
    let barrier_version = server
        .barrier_version(gid)
        .ok_or(RoomBarrierEnvelopeError::MissingBarrierVersion)?;
    let kem_tree_hash_after = server
        .barrier_kem_tree_hash_after(gid)
        .ok_or(RoomBarrierEnvelopeError::MissingBarrierTreeHash)?;
    let n_max = server
        .barrier_n_max(gid)
        .ok_or(RoomBarrierEnvelopeError::MissingNMax)?;
    prepare_barrier_envelope(
        server,
        gid,
        history_commitment,
        barrier_version,
        &kem_tree_hash_after,
        n_max,
        profile_version,
    )
}

/// Resolve revoked leaves, paginate them, and prepare the shared helper envelope.
pub fn prepare_resolved_revoked_leaves(
    server: &mut CityGServer,
    gid: &[u8; 32],
    revocation_roots_hash: &[u8; 32],
    page_offset: u32,
    max_entries: u32,
    max_page_entries: u32,
    profile_version: &str,
) -> Result<PreparedResolvedRevokedLeaves, RoomBarrierHelperPreparationError> {
    let resolved = server.resolve_revoked_leaf_indices(gid, revocation_roots_hash)?;
    let page = paginate_barrier_helper_slice(
        resolved.leaf_indices.as_slice(),
        page_offset,
        max_entries,
        max_page_entries,
    )?;
    let helper_completeness_attestation = server.helper_completeness_attestation_revoked_bytes(
        &resolved.history_commitment,
        revocation_roots_hash,
        page.page_offset,
        page.total_entries,
        page.items.as_slice(),
    )?;
    let barrier = prepare_current_barrier_envelope(
        server,
        gid,
        &resolved.history_commitment,
        profile_version,
    )?;

    Ok(PreparedResolvedRevokedLeaves {
        resolved,
        page,
        helper_completeness_attestation,
        barrier,
    })
}

/// Resolve joins since a barrier version, paginate them, and prepare the shared helper envelope.
pub fn prepare_resolved_joins(
    server: &mut CityGServer,
    gid: &[u8; 32],
    prev_barrier_version: u64,
    page_offset: u32,
    max_entries: u32,
    max_page_entries: u32,
    profile_version: &str,
) -> Result<PreparedResolvedJoins, RoomBarrierHelperPreparationError> {
    let resolved = server.resolve_joins_since(gid, prev_barrier_version)?;
    let page = paginate_barrier_helper_slice(
        resolved.records.as_slice(),
        page_offset,
        max_entries,
        max_page_entries,
    )?;
    let helper_completeness_attestation = server.helper_completeness_attestation_joins_bytes(
        &resolved.history_commitment,
        prev_barrier_version,
        page.page_offset,
        page.total_entries,
        page.items.as_slice(),
    )?;
    let barrier = prepare_current_barrier_envelope(
        server,
        gid,
        &resolved.history_commitment,
        profile_version,
    )?;

    Ok(PreparedResolvedJoins {
        resolved,
        page,
        helper_completeness_attestation,
        barrier,
    })
}

/// Fetch a public barrier tree snapshot, paginate the entries, and prepare the shared helper envelope.
pub fn prepare_barrier_public_tree(
    server: &mut CityGServer,
    gid: &[u8; 32],
    kem_tree_hash_after: &[u8; 32],
    page_offset: u32,
    max_entries: u32,
    max_page_entries: u32,
    profile_version: &str,
) -> Result<PreparedBarrierPublicTree, RoomBarrierHelperPreparationError> {
    let snapshot = server.fetch_barrier_public_tree(gid, kem_tree_hash_after)?;
    let page = paginate_barrier_helper_slice(
        snapshot.pk_entries.as_slice(),
        page_offset,
        max_entries,
        max_page_entries,
    )?;
    let helper_completeness_attestation = server.helper_completeness_attestation_tree_bytes(
        &snapshot.history_commitment,
        &snapshot.kem_tree_hash_after,
        page.page_offset,
        page.total_entries,
        page.items.as_slice(),
    )?;
    let barrier = prepare_barrier_envelope(
        server,
        gid,
        &snapshot.history_commitment,
        snapshot.barrier_version,
        &snapshot.kem_tree_hash_after,
        snapshot.n_max,
        profile_version,
    )?;

    Ok(PreparedBarrierPublicTree {
        snapshot,
        page,
        helper_completeness_attestation,
        barrier,
    })
}

/// Look up merge acceptance and prepare the shared current-state barrier envelope.
pub fn prepare_merge_acceptance_lookup(
    server: &mut CityGServer,
    gid: &[u8; 32],
    pending_barrier_version: u64,
    pending_barrier_update_digest: &[u8; 32],
    pending_we_epoch_id: &[u8; 32],
    profile_version: &str,
) -> Result<PreparedMergeAcceptanceLookup, RoomBarrierHelperPreparationError> {
    let record = server.lookup_merge_acceptance(
        gid,
        pending_barrier_version,
        pending_barrier_update_digest,
        pending_we_epoch_id,
    )?;
    let barrier =
        prepare_current_barrier_envelope(server, gid, &record.history_commitment, profile_version)?;

    Ok(PreparedMergeAcceptanceLookup { record, barrier })
}

/// Ensure a leaf is a member for the specific accepted epoch.
pub fn ensure_leaf_member_for_epoch(
    server: &CityGServer,
    room_state: &RoomVolatileState,
    we_epoch_id: &[u8; 32],
    leaf_id: [u8; 32],
) -> Result<EpochScope, RoomAuthorizationError> {
    let scope = room_state
        .epoch_scope_for_weid(we_epoch_id)
        .ok_or(RoomAuthorizationError::NotFound)?;
    let members = server
        .members_for_root(&scope.gid, &scope.membership_root)
        .ok_or(RoomAuthorizationError::NotFound)?;
    if members.iter().any(|member| member == &leaf_id) {
        Ok(scope)
    } else {
        Err(RoomAuthorizationError::Unauthorized)
    }
}

/// Ensure a leaf is a member of the latest room state.
pub fn ensure_leaf_member_for_room(
    server: &CityGServer,
    gid: &[u8; 32],
    leaf_id: [u8; 32],
) -> Result<(), RoomAuthorizationError> {
    let latest_root = server
        .latest_parent_root(gid)
        .ok_or(RoomAuthorizationError::NotFound)?;
    let members = server
        .members_for_root(gid, &latest_root)
        .ok_or(RoomAuthorizationError::NotFound)?;
    if members.iter().any(|member| member == &leaf_id) {
        Ok(())
    } else {
        Err(RoomAuthorizationError::Unauthorized)
    }
}

/// Parse and validate a room-window configuration update.
pub fn parse_room_window_limit_update(
    h_max: Option<u32>,
    ttl_ms: Option<u32>,
) -> Result<RoomWindowLimitUpdate, RoomWindowConfigError> {
    let h_max = h_max
        .map(|value| {
            if value == 0 {
                Err(RoomWindowConfigError::HMaxTooSmall)
            } else if value > 1024 {
                Err(RoomWindowConfigError::HMaxTooLarge)
            } else {
                Ok(value as usize)
            }
        })
        .transpose()?;
    let ttl = ttl_ms
        .map(|value| {
            if value == 0 {
                Err(RoomWindowConfigError::NonPositiveTtl)
            } else {
                Ok(Duration::from_millis(u64::from(value)))
            }
        })
        .transpose()?;

    Ok(RoomWindowLimitUpdate { h_max, ttl })
}

/// Apply a room-window configuration update and return the effective limits.
#[must_use]
pub fn apply_room_window_limit_update(
    server: &mut CityGServer,
    update: RoomWindowLimitUpdate,
) -> RoomWindowLimits {
    server.update_window_limits(update.h_max, update.ttl);
    let (h_max, ttl) = server.window_limits();
    RoomWindowLimits { h_max, ttl }
}

/// Snapshot the current multi-head window state for one room engine.
#[must_use]
pub fn snapshot_room_window(server: &CityGServer) -> Vec<RoomWindowEntrySnapshot> {
    let now = server.context().current_time();
    server
        .context()
        .mh_window
        .snapshot()
        .into_iter()
        .map(|(wid, heads)| RoomWindowEntrySnapshot {
            wid,
            heads: heads
                .into_iter()
                .map(|record| RoomWindowHeadSnapshot {
                    we_epoch_id: record.we_epoch_id,
                    msphf_hp_commit: record.msphf_hp_commit,
                    seed_ctx_hash: record.seed_ctx_hash,
                    rho_commit: record.rho_commit,
                    seed_commit: record.seed_commit,
                    xk_hash: record.xk_hash,
                    accept_seq: record.accept_seq,
                    age_ms: now
                        .duration_since(record.accept_time())
                        .as_millis()
                        .min(u64::MAX as u128) as u64,
                })
                .collect(),
        })
        .collect()
}

/// Snapshot the current acceptance telemetry rows for one room engine.
#[must_use]
pub fn snapshot_room_telemetry(server: &CityGServer) -> Vec<RoomTelemetrySnapshotEntry> {
    let mut entries = BTreeMap::new();
    let mut gids_with_acceptance_telemetry = BTreeSet::new();
    let barrier_leaf_capacity_warning_percent =
        u64::from(server.barrier_leaf_capacity_warning_percent());
    let barrier_leaf_capacity_refusal_percent =
        u64::from(server.barrier_leaf_capacity_refusal_percent());

    for (key, counters) in server.context().telemetry_report() {
        let gid = key.gid.as_slice().to_vec();
        gids_with_acceptance_telemetry.insert(gid.clone());
        let capacity = <[u8; 32]>::try_from(gid.as_slice())
            .ok()
            .and_then(|gid32| server.barrier_leaf_capacity(&gid32));
        let utilization_basis_points = capacity
            .map(|capacity| {
                if capacity.n_max == 0 {
                    0
                } else {
                    capacity
                        .reserved_cover_leaf_count
                        .saturating_mul(10_000)
                        .saturating_div(capacity.n_max)
                }
            })
            .unwrap_or(0);
        let entry =
            entries
                .entry((gid.clone(), key.parent_root))
                .or_insert(RoomTelemetrySnapshotEntry {
                    gid,
                    parent_root: key.parent_root,
                    head_attempts: 0,
                    head_insertions: 0,
                    freeze_window_full: 0,
                    freeze_rho_replay: 0,
                    last_active_heads: 0,
                    barrier_n_max: capacity.map(|value| value.n_max).unwrap_or(0),
                    barrier_active_leaf_count: capacity
                        .map(|value| value.active_leaf_count)
                        .unwrap_or(0),
                    barrier_revoked_leaf_count: capacity
                        .map(|value| value.revoked_leaf_count)
                        .unwrap_or(0),
                    barrier_pending_join_ticket_count: capacity
                        .map(|value| value.pending_join_ticket_count)
                        .unwrap_or(0),
                    barrier_reserved_cover_leaf_count: capacity
                        .map(|value| value.reserved_cover_leaf_count)
                        .unwrap_or(0),
                    barrier_remaining_cover_leaf_slots: capacity
                        .map(|value| value.remaining_cover_leaf_slots)
                        .unwrap_or(0),
                    barrier_leaf_utilization_basis_points: utilization_basis_points,
                    barrier_leaf_capacity_warning_percent,
                    barrier_leaf_capacity_refusal_percent,
                });
        entry.head_attempts = counters.head_attempts;
        entry.head_insertions = counters.head_insertions;
        entry.freeze_window_full = counters.freeze_window_full;
        entry.freeze_rho_replay = counters.freeze_rho_replay;
        entry.last_active_heads = counters.last_active_heads as u64;
    }

    for (gid, capacity) in server.barrier_leaf_capacity_report() {
        if gids_with_acceptance_telemetry.contains(&gid) {
            continue;
        }
        let parent_root = server
            .latest_parent_root(gid.as_slice())
            .unwrap_or([0u8; 32]);
        let utilization_basis_points = if capacity.n_max == 0 {
            0
        } else {
            capacity
                .reserved_cover_leaf_count
                .saturating_mul(10_000)
                .saturating_div(capacity.n_max)
        };
        entries.insert(
            (gid.clone(), parent_root),
            RoomTelemetrySnapshotEntry {
                gid,
                parent_root,
                head_attempts: 0,
                head_insertions: 0,
                freeze_window_full: 0,
                freeze_rho_replay: 0,
                last_active_heads: 0,
                barrier_n_max: capacity.n_max,
                barrier_active_leaf_count: capacity.active_leaf_count,
                barrier_revoked_leaf_count: capacity.revoked_leaf_count,
                barrier_pending_join_ticket_count: capacity.pending_join_ticket_count,
                barrier_reserved_cover_leaf_count: capacity.reserved_cover_leaf_count,
                barrier_remaining_cover_leaf_slots: capacity.remaining_cover_leaf_slots,
                barrier_leaf_utilization_basis_points: utilization_basis_points,
                barrier_leaf_capacity_warning_percent,
                barrier_leaf_capacity_refusal_percent,
            },
        );
    }

    entries.into_values().collect()
}

/// Fetch room-scoped chat messages after verifying epoch membership.
pub fn fetch_room_messages(
    server: &CityGServer,
    room_state: &mut RoomVolatileState,
    we_epoch_id: &[u8; 32],
    leaf_id: [u8; 32],
    now_ms: u64,
    retention: Duration,
    prune_interval_ms: u64,
) -> Result<Vec<StoredMessage>, RoomAuthorizationError> {
    ensure_leaf_member_for_epoch(server, room_state, we_epoch_id, leaf_id)?;
    Ok(room_state.messages_for_epoch(we_epoch_id, now_ms, retention, prune_interval_ms))
}

/// Fetch a cached accepted bundle for the given accepted epoch.
#[must_use]
pub fn fetch_room_bundle(
    room_state: &mut RoomVolatileState,
    we_epoch_id: &[u8; 32],
    now_ms: u64,
    retention: Duration,
    prune_interval_ms: u64,
) -> Option<StoredBundle> {
    room_state.bundle(we_epoch_id, now_ms, retention, prune_interval_ms)
}

/// Store a room-scoped chat message after validating current membership.
pub fn store_room_message(
    server: &CityGServer,
    room_state: &mut RoomVolatileState,
    message: RoomMessageWrite,
    retention_policy: RoomRetentionPolicy,
) -> Result<EpochScope, RoomMessageStoreError> {
    let scope = ensure_leaf_member_for_epoch(
        server,
        room_state,
        &message.we_epoch_id,
        message.sender_leaf,
    )
    .map_err(|error| match error {
        RoomAuthorizationError::NotFound => RoomMessageStoreError::NotFound,
        RoomAuthorizationError::Unauthorized => RoomMessageStoreError::EpochUnauthorized,
    })?;
    ensure_leaf_member_for_room(server, &scope.gid, message.sender_leaf).map_err(|error| {
        match error {
            RoomAuthorizationError::NotFound => RoomMessageStoreError::NotFound,
            RoomAuthorizationError::Unauthorized => RoomMessageStoreError::RoomUnauthorized,
        }
    })?;

    room_state.store_message(
        message.we_epoch_id,
        StoredMessage {
            we_epoch_id: message.we_epoch_id,
            ciphertext: message.ciphertext,
            sender: message.sender,
            timestamp_ms: message.timestamp_ms,
        },
        message.timestamp_ms,
        retention_policy.retention,
        retention_policy.prune_interval_ms,
    );
    room_state.touch_member(message.sender_leaf, message.timestamp_ms);
    Ok(scope)
}

/// Seed a room's multi-head window with a validated bundle head.
pub fn seed_room_window_head(
    server: &mut CityGServer,
    bundle: &ClientEpochBundle,
) -> Result<(), RoomWindowSeedError> {
    use msphf_orchestrator::mhw::HeadRecord;

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
    )
    .map_err(|err| RoomWindowSeedError::ComputeWindowId(err.to_string()))?;

    let _: [u8; 32] = bundle
        .gid()
        .try_into()
        .map_err(|_| RoomWindowSeedError::InvalidGidLength)?;
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
        .map_err(|err| RoomWindowSeedError::AcceptHead(err.reason.to_string()))?;
    Ok(())
}

/// Apply the room refresh-pivot transition using the shared runtime room core.
pub fn refresh_room_pivot(
    server: &mut CityGServer,
    bundle: &ClientEpochBundle,
) -> Result<(), CityGError> {
    server.refresh_pivot(bundle)
}

/// Classify the known conflict reasons returned by refresh-pivot validation.
pub fn classify_refresh_pivot_conflict(message: &str) -> Option<&'static str> {
    let reason = message.strip_prefix("invalid input: ").unwrap_or(message);
    match reason {
        "pivot parity missing for refresh" => Some("pivot_parity_missing"),
        "pivot head missing" => Some("pivot_head_missing"),
        "refresh payload diverges from stored parity" => Some("payload_diverges"),
        _ => None,
    }
}

fn is_merge_bundle_header(
    header: &std::collections::BTreeMap<u64, ciborium::value::Value>,
) -> bool {
    header.contains_key(&hdr::HDR_BARRIER_UPDATE)
        || header.contains_key(&hdr::HDR_BARRIER_UPDATE_REASON)
        || [
            hdr::HDR_MH_HEADS,
            hdr::HDR_ROLLUP_PIVOT_WEID,
            hdr::HDR_ROLLUP_PROVENANCE_COMMIT,
            hdr::HDR_ROLLUP_EPOCH_REPLAY,
            hdr::HDR_ROLLUP_VCK_COMMIT,
            hdr::HDR_MERGE_DELEGATION_SIG,
            hdr::HDR_KBROAD_REPLAY,
            hdr::HDR_ROLLUP_FS_MODE,
            hdr::HDR_FS_EVOLUTION_BOUNDARY,
            hdr::HDR_FS_PURGE_TIMES,
            hdr::HDR_FS_CHECKPOINT_EC,
        ]
        .into_iter()
        .any(|key| header.contains_key(&key))
}

fn pivot_parity_to_cbor(parity: &PivotParity) -> Result<Vec<u8>, RoomTicketPreparationError> {
    #[derive(Serialize)]
    struct PivotParitySerializable {
        gid: ByteBuf,
        cat: ByteBuf,
        parent_root: ByteBuf,
        we_epoch_id: ByteBuf,
        rho_commit: ByteBuf,
        seed_ctx_hash: ByteBuf,
        seed_commit: ByteBuf,
        hp_commit: ByteBuf,
        xk_hash: ByteBuf,
        join_delta_root: ByteBuf,
        revoked_since_root: ByteBuf,
        revoked_root: ByteBuf,
        accept_seq: u64,
        crs_id: ByteBuf,
        params_id: ByteBuf,
        policy_version: String,
        proof_mode: String,
        vrf_id: String,
        vrf_proof: ByteBuf,
        vrf_public: ByteBuf,
        mask_a: ByteBuf,
        mask_b: ByteBuf,
        fs_capss: ByteBuf,
        proofs_commit: ByteBuf,
        srx_commit: Option<ByteBuf>,
        srx_root_sw: Option<ByteBuf>,
        is_join: bool,
        hp_envelope: ByteBuf,
        fs_epoch_commit: Option<ByteBuf>,
        fs_ec: Option<u64>,
        fs_dev_commit: Option<ByteBuf>,
    }

    let serializable = PivotParitySerializable {
        gid: ByteBuf::from(parity.gid.clone()),
        cat: ByteBuf::from(parity.cat.clone()),
        parent_root: ByteBuf::from(parity.parent_root.to_vec()),
        we_epoch_id: ByteBuf::from(parity.we_epoch_id.to_vec()),
        rho_commit: ByteBuf::from(parity.rho_commit.to_vec()),
        seed_ctx_hash: ByteBuf::from(parity.seed_ctx_hash.to_vec()),
        seed_commit: ByteBuf::from(parity.seed_commit.to_vec()),
        hp_commit: ByteBuf::from(parity.hp_commit.to_vec()),
        xk_hash: ByteBuf::from(parity.xk_hash.to_vec()),
        join_delta_root: ByteBuf::from(parity.join_delta_root.to_vec()),
        revoked_since_root: ByteBuf::from(parity.revoked_since_root.to_vec()),
        revoked_root: ByteBuf::from(parity.revoked_root.to_vec()),
        accept_seq: parity.accept_seq,
        crs_id: ByteBuf::from(parity.crs_id.clone()),
        params_id: ByteBuf::from(parity.params_id.clone()),
        policy_version: parity.policy_version.clone(),
        proof_mode: parity.proof_mode.clone(),
        vrf_id: parity.vrf_id.clone(),
        vrf_proof: ByteBuf::from(parity.vrf_proof.clone()),
        vrf_public: ByteBuf::from(parity.vrf_public.clone()),
        mask_a: ByteBuf::from(parity.mask_a.to_vec()),
        mask_b: ByteBuf::from(parity.mask_b.to_vec()),
        fs_capss: ByteBuf::from(parity.fs_capss.clone()),
        proofs_commit: ByteBuf::from(parity.proofs_commit.to_vec()),
        srx_commit: parity
            .srx_commit
            .map(|commit| ByteBuf::from(commit.to_vec())),
        srx_root_sw: parity.srx_root_sw.map(|root| ByteBuf::from(root.to_vec())),
        is_join: parity.is_join,
        hp_envelope: ByteBuf::from(parity.hp_envelope.as_ref().to_vec()),
        fs_epoch_commit: parity
            .fs_epoch_commit
            .map(|commit| ByteBuf::from(commit.to_vec())),
        fs_ec: parity.fs_ec,
        fs_dev_commit: parity
            .fs_dev_commit
            .map(|commit| ByteBuf::from(commit.to_vec())),
    };

    let mut buf = Vec::new();
    into_writer(&serializable, &mut buf)
        .map_err(|_| RoomTicketPreparationError::PivotParityEncode)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use std::collections::BTreeMap;

    use super::*;
    use crate::{AliasLeafEntry, AliasLeafLookup};
    use cityg_client::demo::{
        DEMO_GID, bootstrap_public, demo_bundle, demo_member_leaf, kbroad_public,
    };
    use cityg_server::ServerConfig;
    use msphf_orchestrator::{AcceptanceOptions, BootstrapPolicy};

    fn test_server() -> CityGServer {
        let mut kbroad_registry = BTreeMap::new();
        kbroad_registry.insert(DEMO_GID.to_vec(), kbroad_public().to_vec());

        let mut config = ServerConfig::new();
        config.acceptance_options = Some(AcceptanceOptions {
            bootstrap_policy: BootstrapPolicy::CaMlDsa {
                public_key: bootstrap_public().to_vec(),
            },
            kbroad_registry: Some(kbroad_registry),
            ..AcceptanceOptions::default()
        });
        CityGServer::new(config)
    }

    #[test]
    fn apply_bundle_indexes_updates_room_state() {
        let bundle = demo_bundle("runtime-apply-indexes").expect("demo bundle");
        let mut room_state = RoomVolatileState::default();
        let result = apply_bundle_indexes(
            &mut room_state,
            &bundle,
            BundleIndexUpdate {
                we_epoch_id: bundle.we_epoch_id,
                bytes: bundle.to_cbor().expect("bundle cbor"),
                membership_root: [0x44; 32],
                timestamp_ms: 55,
            },
            RoomRetentionPolicy {
                retention: Duration::from_secs(60),
                prune_interval_ms: 1_000,
            },
        )
        .expect("apply bundle indexes");

        assert_eq!(result.we_epoch_id, bundle.we_epoch_id);
        assert_eq!(
            room_state.epoch_scope_for_weid(&bundle.we_epoch_id),
            Some(EpochScope {
                gid: bundle.gid().try_into().expect("gid"),
                membership_root: [0x44; 32],
            })
        );
    }

    #[test]
    fn classify_refresh_pivot_conflict_maps_known_reasons() {
        assert_eq!(
            classify_refresh_pivot_conflict("invalid input: pivot parity missing for refresh"),
            Some("pivot_parity_missing")
        );
        assert_eq!(
            classify_refresh_pivot_conflict("pivot head missing"),
            Some("pivot_head_missing")
        );
        assert_eq!(classify_refresh_pivot_conflict("something else"), None);
    }

    #[test]
    fn fetch_room_messages_reuses_epoch_authorization_and_backlog_lookup() {
        let bundle = demo_bundle("alice").expect("demo bundle");
        let bundle_bytes = bundle.to_cbor().expect("bundle cbor");
        let mut server = test_server();
        let outcome = server.accept_epoch(&bundle).expect("accept bundle");

        let mut room_state = RoomVolatileState::default();
        apply_bundle_indexes(
            &mut room_state,
            &bundle,
            BundleIndexUpdate {
                we_epoch_id: bundle.we_epoch_id,
                bytes: bundle_bytes,
                membership_root: outcome.new_root,
                timestamp_ms: 55,
            },
            RoomRetentionPolicy {
                retention: Duration::from_secs(60),
                prune_interval_ms: 1_000,
            },
        )
        .expect("apply bundle indexes");
        room_state.store_message(
            bundle.we_epoch_id,
            StoredMessage {
                we_epoch_id: bundle.we_epoch_id,
                ciphertext: vec![1, 2, 3],
                sender: demo_member_leaf("alice").to_vec(),
                timestamp_ms: 60,
            },
            60,
            Duration::from_secs(60),
            1_000,
        );

        let messages = fetch_room_messages(
            &server,
            &mut room_state,
            &bundle.we_epoch_id,
            demo_member_leaf("alice"),
            61,
            Duration::from_secs(60),
            1_000,
        )
        .expect("authorized fetch");
        assert_eq!(messages.len(), 1);

        let err = fetch_room_messages(
            &server,
            &mut room_state,
            &bundle.we_epoch_id,
            demo_member_leaf("bob"),
            61,
            Duration::from_secs(60),
            1_000,
        )
        .expect_err("outsider should be rejected");
        assert_eq!(err, RoomAuthorizationError::Unauthorized);
    }

    #[test]
    fn fetch_room_bundle_reuses_shared_bundle_backlog_lookup() {
        let we_epoch_id = [0x44; 32];
        let mut room_state = RoomVolatileState::default();
        room_state.store_bundle(
            we_epoch_id,
            StoredBundle {
                bytes: vec![9, 8, 7],
                stored_at_ms: 12,
            },
            12,
            Duration::from_secs(60),
            1_000,
        );

        let bundle = fetch_room_bundle(
            &mut room_state,
            &we_epoch_id,
            13,
            Duration::from_secs(60),
            1_000,
        )
        .expect("stored bundle");
        assert_eq!(bundle.bytes, vec![9, 8, 7]);
    }

    #[test]
    fn store_room_message_updates_backlog_and_last_seen() {
        let bundle = demo_bundle("alice").expect("demo bundle");
        let bundle_bytes = bundle.to_cbor().expect("bundle cbor");
        let mut server = test_server();
        let outcome = server.accept_epoch(&bundle).expect("accept bundle");

        let mut room_state = RoomVolatileState::default();
        apply_bundle_indexes(
            &mut room_state,
            &bundle,
            BundleIndexUpdate {
                we_epoch_id: bundle.we_epoch_id,
                bytes: bundle_bytes,
                membership_root: outcome.new_root,
                timestamp_ms: 55,
            },
            RoomRetentionPolicy {
                retention: Duration::from_secs(60),
                prune_interval_ms: 1_000,
            },
        )
        .expect("apply bundle indexes");

        let scope = store_room_message(
            &server,
            &mut room_state,
            RoomMessageWrite {
                we_epoch_id: bundle.we_epoch_id,
                sender_leaf: demo_member_leaf("alice"),
                ciphertext: vec![1, 2, 3],
                sender: demo_member_leaf("alice").to_vec(),
                timestamp_ms: 60,
            },
            RoomRetentionPolicy {
                retention: Duration::from_secs(60),
                prune_interval_ms: 1_000,
            },
        )
        .expect("store message");

        let gid: [u8; 32] = bundle.gid().try_into().expect("gid");
        assert_eq!(scope.gid, gid);
        assert_eq!(
            room_state
                .messages_for_epoch(&bundle.we_epoch_id, 61, Duration::from_secs(60), 1_000)
                .len(),
            1
        );
        assert_eq!(
            room_state.member_metadata()[&demo_member_leaf("alice")].last_seen_timestamp_ms,
            60
        );
    }

    #[test]
    fn seed_room_window_head_records_demo_bundle_in_window_state() {
        let bundle = demo_bundle("alice").expect("demo bundle");
        let mut server = test_server();

        seed_room_window_head(&mut server, &bundle).expect("seed window head");

        let wid = server
            .context()
            .mh_window
            .find_head_window(&bundle.we_epoch_id)
            .expect("seeded window id");
        assert_eq!(server.context().mh_window.active_heads(wid.as_slice()), 1);
    }

    #[test]
    fn parse_room_window_limit_update_validates_bounds() {
        assert_eq!(
            parse_room_window_limit_update(Some(0), None),
            Err(RoomWindowConfigError::HMaxTooSmall)
        );
        assert_eq!(
            parse_room_window_limit_update(Some(2048), None),
            Err(RoomWindowConfigError::HMaxTooLarge)
        );
        assert_eq!(
            parse_room_window_limit_update(None, Some(0)),
            Err(RoomWindowConfigError::NonPositiveTtl)
        );

        let update = parse_room_window_limit_update(Some(9), Some(4_321)).expect("valid update");
        assert_eq!(update.h_max, Some(9));
        assert_eq!(update.ttl, Some(Duration::from_millis(4_321)));
    }

    #[test]
    fn apply_room_window_limit_update_returns_effective_limits() {
        let mut server = test_server();
        let update = parse_room_window_limit_update(Some(9), Some(4_321)).expect("valid update");

        let effective = apply_room_window_limit_update(&mut server, update);
        assert_eq!(effective.h_max, 9);
        assert_eq!(effective.ttl, Duration::from_millis(4_321));
    }

    #[test]
    fn snapshot_room_window_returns_age_and_head_payloads() {
        let bundle = demo_bundle("alice").expect("demo bundle");
        let mut server = test_server();

        seed_room_window_head(&mut server, &bundle).expect("seed window head");

        let snapshot = snapshot_room_window(&server);
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].heads.len(), 1);
        let head = &snapshot[0].heads[0];
        assert_eq!(head.we_epoch_id, bundle.we_epoch_id);
        assert_eq!(head.msphf_hp_commit, bundle.hp_binding.hp_commit);
        assert_eq!(head.seed_ctx_hash, bundle.hp_binding.seed_ctx_hash);
        assert_eq!(head.rho_commit, bundle.hp_binding.rho_commit);
        assert_eq!(head.seed_commit, bundle.hp_binding.seed_commit);
        assert_eq!(head.xk_hash, bundle.hp_binding.xk_hash);
        assert_eq!(head.accept_seq, 0);
        assert_eq!(head.age_ms, 0);
    }

    #[test]
    fn snapshot_room_telemetry_returns_acceptance_counters() {
        let bundle = demo_bundle("alice").expect("demo bundle");
        let mut server = test_server();

        server.accept_epoch(&bundle).expect("accept bundle");

        let telemetry = snapshot_room_telemetry(&server);
        assert_eq!(telemetry.len(), 1);
        let entry = &telemetry[0];
        assert_eq!(entry.gid, bundle.gid());
        assert_eq!(entry.parent_root, bundle.anchor.parent_root);
        assert_eq!(entry.head_attempts, 1);
        assert_eq!(entry.head_insertions, 1);
        assert_eq!(entry.freeze_window_full, 0);
        assert_eq!(entry.freeze_rho_replay, 0);
        assert!(entry.last_active_heads >= 1);
        assert_eq!(entry.barrier_n_max, 1024);
        assert_eq!(entry.barrier_active_leaf_count, 1);
        assert_eq!(entry.barrier_revoked_leaf_count, 0);
        assert_eq!(entry.barrier_pending_join_ticket_count, 0);
        assert_eq!(entry.barrier_reserved_cover_leaf_count, 1);
        assert_eq!(entry.barrier_remaining_cover_leaf_slots, 1023);
        assert_eq!(entry.barrier_leaf_utilization_basis_points, 9);
        assert_eq!(entry.barrier_leaf_capacity_warning_percent, 80);
        assert_eq!(entry.barrier_leaf_capacity_refusal_percent, 100);
    }

    #[test]
    fn snapshot_room_telemetry_includes_capacity_for_registered_room_without_accepts() {
        let mut server = CityGServer::new(ServerConfig::new());
        let gid = [0x61; 32];
        server
            .register_group(&gid, vec![0x55; 16])
            .expect("register group");

        let telemetry = snapshot_room_telemetry(&server);
        assert_eq!(telemetry.len(), 1);
        let entry = &telemetry[0];
        assert_eq!(entry.gid, gid.to_vec());
        assert_eq!(entry.parent_root, [0u8; 32]);
        assert_eq!(entry.head_attempts, 0);
        assert_eq!(entry.head_insertions, 0);
        assert_eq!(entry.barrier_n_max, 1024);
        assert_eq!(entry.barrier_active_leaf_count, 0);
        assert_eq!(entry.barrier_revoked_leaf_count, 0);
        assert_eq!(entry.barrier_pending_join_ticket_count, 0);
        assert_eq!(entry.barrier_reserved_cover_leaf_count, 0);
        assert_eq!(entry.barrier_remaining_cover_leaf_slots, 1024);
        assert_eq!(entry.barrier_leaf_utilization_basis_points, 0);
        assert_eq!(entry.barrier_leaf_capacity_warning_percent, 80);
        assert_eq!(entry.barrier_leaf_capacity_refusal_percent, 100);
    }

    #[test]
    fn prepare_and_commit_accepted_bundle_supports_split_room_locking() {
        let bundle = demo_bundle("alice").expect("demo bundle");
        let gid: [u8; 32] = bundle.gid().try_into().expect("gid");
        let mut server = test_server();

        let prepared =
            prepare_accepted_bundle(&mut server, &bundle).expect("prepare accepted bundle");
        let mut room_state = RoomVolatileState::default();
        let accepted = commit_prepared_accepted_bundle(
            &mut room_state,
            &bundle,
            prepared,
            55,
            RoomRetentionPolicy {
                retention: Duration::from_secs(60),
                prune_interval_ms: 1_000,
            },
        )
        .expect("commit accepted bundle");

        assert_eq!(accepted.outcome.we_epoch_id, bundle.we_epoch_id);
        assert_eq!(accepted.applied.gid, gid);
        assert_eq!(
            room_state
                .epoch_scope_for_weid(&bundle.we_epoch_id)
                .expect("epoch scope")
                .membership_root,
            accepted.outcome.new_root
        );
        assert_eq!(
            room_state
                .bundle(&bundle.we_epoch_id, 56, Duration::from_secs(60), 1_000)
                .expect("stored bundle")
                .bytes,
            accepted.stored_bundle_bytes
        );
        assert!(server.members(&gid).contains(&demo_member_leaf("alice")));
    }

    #[test]
    fn paginate_room_members_clamps_offset_and_advances_next_offset() {
        let members = vec![[0x01; 32], [0x02; 32], [0x03; 32]];

        let page = paginate_room_members(members.as_slice(), 1, 1);
        assert_eq!(page.members, vec![[0x02; 32]]);
        assert_eq!(page.total_count, 3);
        assert_eq!(page.next_offset, 2);

        let clamped = paginate_room_members(members.as_slice(), 99, 10);
        assert!(clamped.members.is_empty());
        assert_eq!(clamped.total_count, 3);
        assert_eq!(clamped.next_offset, 3);
    }

    #[test]
    fn filter_room_members_by_query_matches_alias_and_leaf_hex() {
        let alice = [0xAA; 32];
        let bob = [0xBB; 32];
        let members = vec![alice, bob];
        let mut alias_lookup = AliasLeafLookup::default();
        alias_lookup.insert(
            alice,
            AliasLeafEntry {
                alias: "special-user".to_string(),
                pop_public_key: vec![0x11; 8],
            },
        );

        let alias_matches =
            filter_room_members_by_query(members.as_slice(), &alias_lookup, "SPECIAL");
        assert_eq!(alias_matches, vec![alice]);

        let hex_matches = filter_room_members_by_query(
            members.as_slice(),
            &alias_lookup,
            &hex::encode([0xBB; 4]),
        );
        assert_eq!(hex_matches, vec![bob]);
    }

    #[test]
    fn alias_entry_for_member_returns_matching_entry() {
        let alice = [0xAA; 32];
        let mut alias_lookup = AliasLeafLookup::default();
        alias_lookup.insert(
            alice,
            AliasLeafEntry {
                alias: "alice".to_string(),
                pop_public_key: vec![0x22; 8],
            },
        );

        let entry = alias_entry_for_member(&alias_lookup, &alice).expect("alias entry");
        assert_eq!(entry.alias, "alice");
        assert_eq!(entry.pop_public_key, vec![0x22; 8]);
        assert!(alias_entry_for_member(&alias_lookup, &[0xFF; 32]).is_none());
    }
}
