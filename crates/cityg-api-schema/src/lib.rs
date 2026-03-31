#![forbid(unsafe_code)]

#[allow(dead_code)]
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/cityg.api.v1.rs"));
}

use std::convert::TryInto;

use ciborium::ser::into_writer;
use cityg_client::{CityGError as ClientError, ClientEpochBundle};
use cityg_pqc::{
    ML_DSA_65_ALGORITHM, ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES,
    verify_ml_dsa_65_detached_signature,
};
use cityg_runtime::{
    AliasLeafEntry, FullVerificationWitnessRequest as RuntimeFullVerificationWitnessRequest,
    MemberMetadata, PreparedBarrierEnvelope, PreparedBarrierPublicTree, PreparedJoinTicket,
    PreparedMergeAcceptanceLookup, PreparedMergeTicket, PreparedResolvedJoins,
    PreparedResolvedRevokedLeaves, RoomTelemetrySnapshotEntry, RoomWindowEntrySnapshot,
};
use cityg_server::{
    BarrierJoinLeafRecord as ServerBarrierJoinLeafRecord,
    FsForwardLeapPolicy as ServerFsForwardLeapPolicy, HistoryCommitment as ServerHistoryCommitment,
    MergeAcceptanceStatus as ServerMergeAcceptanceStatus,
};
use msphf_core::{
    hash::h_l,
    params::{RLWE_CRS_ID_DEFAULT, RLWE_PARAMS_ID_MOCK},
};
use msphf_orchestrator::{DEFAULT_PROOF_MODE, DEFAULT_VRF_ID};
use prost::Message;
use serde::Serialize;
use serde_bytes::ByteBuf;
use thiserror::Error;

pub use pb::*;

/// Wire-level API profile version returned by room-scoped responses.
pub const API_PROFILE_VERSION: &str = "v0.1.4";

/// Maximum number of records returned by barrier helper pagination endpoints.
pub const MAX_BARRIER_HELPER_PAGE_ENTRIES: u32 = 512;
pub const MEMBERS_DEFAULT_PAGE_SIZE: u32 = 256;
pub const MEMBERS_MAX_PAGE_SIZE: u32 = 2000;
pub const ML_KEM_768_PUBLIC_KEY_BYTES: usize = 1_184;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedIdentityBinding {
    pub confirmed_binding: pb::IdentityBinding,
    pub requested_leaf_id: [u8; 32],
}

/// Encode a prepared join-ticket response using the shared protobuf schema.
#[must_use]
pub fn encode_prepared_join_ticket_response(
    prepared: PreparedJoinTicket,
    confirmed_binding: Option<pb::IdentityBinding>,
) -> Vec<u8> {
    let PreparedJoinTicket {
        bundle: ticket,
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
    } = prepared;

    let response = pb::JoinTicketResponse {
        gid: ticket.gid.to_vec(),
        cat: ticket.cat.to_vec(),
        parent_root: ticket.parent_root.to_vec(),
        revoked_root: ticket.revoked_root.to_vec(),
        revoked_since_root: ticket.revoked_since_root.to_vec(),
        tswe_salt_hash: ticket.tswe_salt_hash.to_vec(),
        join_delta_root: ticket.join_delta_root.to_vec(),
        leaf_id: ticket.leaf_id.to_vec(),
        pox_r_commit: ticket.pox_r_commit.to_vec(),
        witness_cbor: ticket.witness_cbor,
        srx_cbor: ticket.srx_cbor,
        msphf_crs_id: RLWE_CRS_ID_DEFAULT.to_string(),
        msphf_params_id: RLWE_PARAMS_ID_MOCK.to_string(),
        proof_mode: DEFAULT_PROOF_MODE.to_string(),
        vrf_id: DEFAULT_VRF_ID.to_string(),
        policy_version,
        fs_policy_version,
        fs_epoch_base_ts,
        kbroad_public: ticket.kbroad_public,
        bootstrap_public,
        confirmed_binding,
        kbroad_generation: ticket.kbroad_generation,
        barrier_version: ticket.barrier_version,
        profile_version: API_PROFILE_VERSION.to_string(),
        cover_leaf_index: ticket.cover_leaf_index,
        kem_tree_hash_after: ticket.kem_tree_hash_after.to_vec(),
        n_max: ticket.n_max,
        max_barrier_update_bytes: ticket.max_barrier_update_bytes,
        current_history_view_id: ticket.current_history_view_id.to_vec(),
        current_history_commitment: Some(pb::HistoryCommitment {
            history_view_id: ticket.current_history_commitment.history_view_id.to_vec(),
            history_commitment_id: ticket
                .current_history_commitment
                .history_commitment_id
                .to_vec(),
            prev_history_commitment_id: ticket
                .current_history_commitment
                .prev_history_commitment_id
                .to_vec(),
            history_seq: ticket.current_history_commitment.history_seq,
        }),
        current_barrier_update: ticket.current_barrier_update,
        current_predecessor_kem_tree_hash_after: ticket
            .current_predecessor_kem_tree_hash_after
            .to_vec(),
        current_join_records: ticket
            .current_join_records
            .into_iter()
            .map(|record| pb::BarrierJoinLeafRecord {
                device_pk: record.device_pk,
                leaf_index: record.leaf_index,
                ek_leaf: record.ek_leaf,
            })
            .collect(),
        current_revoked_leaf_indices: ticket.current_revoked_leaf_indices,
        join_finalize_auth_token: ticket.join_finalize_auth_token.to_vec(),
        provisioning_nonce: ticket.provisioning_nonce.to_vec(),
        provisioning_issued_at_ms: ticket.provisioning_issued_at_ms,
        provisioning_expires_at_ms: ticket.provisioning_expires_at_ms,
        fs_forward_leap_policy: Some(pb::FsForwardLeapPolicy {
            h: ticket.fs_forward_leap_policy.h,
            checkpoint_interval: ticket.fs_forward_leap_policy.checkpoint_interval,
            slack_anchor: ticket.fs_forward_leap_policy.slack_anchor,
            slack_first_device: ticket.fs_forward_leap_policy.slack_first_device,
            slack_device: ticket.fs_forward_leap_policy.slack_device,
        }),
        last_accepted_ec: ticket.last_accepted_ec,
        history_authority_descriptor,
        current_global_history_attestation,
        current_join_records_completeness_attestation,
        current_revoked_leaf_indices_completeness_attestation,
        history_authority_extension,
        provisioning_artifact,
        deployment_profile_manifest,
    };

    response.encode_to_vec()
}

/// Encode a prepared merge-ticket response using the shared protobuf schema.
#[must_use]
pub fn encode_prepared_merge_ticket_response(prepared: PreparedMergeTicket) -> Vec<u8> {
    let PreparedMergeTicket {
        bundle,
        history_authority_descriptor,
        current_global_history_attestation,
        history_authority_extension,
        pivot_parity_cbor,
        merge_ticket_artifact,
        deployment_profile_manifest,
    } = prepared;

    let response = pb::MergeTicketResponse {
        we_epoch_id: bundle.pivot_we_epoch_id.to_vec(),
        pivot_parity_cbor,
        witness_cbor: bundle.witness_cbor,
        proof_mode: bundle.proof_mode,
        vrf_id: bundle.vrf_id,
        policy_version: bundle.policy_version,
        kbroad_public: bundle.kbroad_public,
        cat: bundle.cat.to_vec(),
        parent_root: bundle.parent_root.to_vec(),
        join_delta_root: bundle.join_delta_root.to_vec(),
        revoked_since_root: bundle.revoked_since_root.to_vec(),
        revoked_root: bundle.revoked_root.to_vec(),
        tswe_salt_hash: bundle.tswe_salt_hash.to_vec(),
        pox_r_commit: bundle.pox_r_commit.to_vec(),
        srx_cbor: bundle.srx_cbor,
        msphf_crs_id: bundle.msphf_crs_id,
        msphf_params_id: bundle.msphf_params_id,
        fs_policy_version: bundle.fs_policy_version,
        fs_epoch_base_ts: bundle.fs_epoch_base_ts,
        kbroad_generation: bundle.kbroad_generation,
        barrier_version: bundle.barrier_version,
        profile_version: API_PROFILE_VERSION.to_string(),
        cover_leaf_index: bundle.cover_leaf_index,
        kem_tree_hash_after: bundle.kem_tree_hash_after.to_vec(),
        n_max: bundle.n_max,
        max_barrier_update_bytes: bundle.max_barrier_update_bytes,
        current_history_view_id: bundle.current_history_view_id.to_vec(),
        current_history_commitment: Some(pb::HistoryCommitment {
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
        }),
        fs_forward_leap_policy: Some(pb::FsForwardLeapPolicy {
            h: bundle.fs_forward_leap_policy.h,
            checkpoint_interval: bundle.fs_forward_leap_policy.checkpoint_interval,
            slack_anchor: bundle.fs_forward_leap_policy.slack_anchor,
            slack_first_device: bundle.fs_forward_leap_policy.slack_first_device,
            slack_device: bundle.fs_forward_leap_policy.slack_device,
        }),
        last_accepted_ec: bundle.last_accepted_ec,
        history_authority_descriptor,
        current_global_history_attestation,
        history_authority_extension,
        merge_ticket_artifact,
        deployment_profile_manifest,
    };

    response.encode_to_vec()
}

#[must_use]
pub fn encode_prepared_resolved_revoked_leaves_response(
    prepared: PreparedResolvedRevokedLeaves,
) -> Vec<u8> {
    let PreparedResolvedRevokedLeaves {
        resolved,
        page,
        helper_completeness_attestation,
        barrier,
    } = prepared;
    let PreparedBarrierEnvelope {
        history_authority_descriptor,
        global_history_attestation,
        history_authority_extension,
        n_max,
        max_barrier_update_bytes,
        fs_forward_leap_policy,
        deployment_profile_manifest,
    } = barrier;

    let response = pb::BarrierResolveRevokedLeavesResponse {
        leaf_indices: page.items,
        history_view_id: resolved.history_view_id.to_vec(),
        history_commitment: Some(pb_history_commitment(resolved.history_commitment)),
        page_offset: page.page_offset,
        next_page_offset: page.next_page_offset,
        total_entries: page.total_entries,
        helper_completeness_attestation,
        history_authority_descriptor,
        global_history_attestation,
        history_authority_extension,
        profile_version: API_PROFILE_VERSION.to_string(),
        n_max,
        max_barrier_update_bytes,
        fs_forward_leap_policy: Some(pb_fs_forward_leap_policy(fs_forward_leap_policy)),
        deployment_profile_manifest,
    };

    response.encode_to_vec()
}

#[must_use]
pub fn encode_prepared_resolved_joins_response(prepared: PreparedResolvedJoins) -> Vec<u8> {
    let PreparedResolvedJoins {
        resolved,
        page,
        helper_completeness_attestation,
        barrier,
    } = prepared;
    let PreparedBarrierEnvelope {
        history_authority_descriptor,
        global_history_attestation,
        history_authority_extension,
        n_max,
        max_barrier_update_bytes,
        fs_forward_leap_policy,
        deployment_profile_manifest,
    } = barrier;

    let response = pb::BarrierResolveJoinsSinceResponse {
        records: page
            .items
            .into_iter()
            .map(pb_barrier_join_leaf_record)
            .collect(),
        history_view_id: resolved.history_view_id.to_vec(),
        history_commitment: Some(pb_history_commitment(resolved.history_commitment)),
        page_offset: page.page_offset,
        next_page_offset: page.next_page_offset,
        total_entries: page.total_entries,
        helper_completeness_attestation,
        history_authority_descriptor,
        global_history_attestation,
        history_authority_extension,
        profile_version: API_PROFILE_VERSION.to_string(),
        n_max,
        max_barrier_update_bytes,
        fs_forward_leap_policy: Some(pb_fs_forward_leap_policy(fs_forward_leap_policy)),
        deployment_profile_manifest,
    };

    response.encode_to_vec()
}

#[must_use]
pub fn encode_prepared_barrier_public_tree_response(
    prepared: PreparedBarrierPublicTree,
) -> Vec<u8> {
    let PreparedBarrierPublicTree {
        snapshot,
        page,
        helper_completeness_attestation,
        barrier,
    } = prepared;
    let PreparedBarrierEnvelope {
        history_authority_descriptor,
        global_history_attestation,
        history_authority_extension,
        n_max: _,
        max_barrier_update_bytes,
        fs_forward_leap_policy,
        deployment_profile_manifest,
    } = barrier;

    let response = pb::BarrierFetchPublicTreeResponse {
        n_max: snapshot.n_max,
        kem_tree_hash_after: snapshot.kem_tree_hash_after.to_vec(),
        pk_entries: page.items,
        history_view_id: snapshot.history_view_id.to_vec(),
        history_commitment: Some(pb_history_commitment(snapshot.history_commitment)),
        entry_offset: page.page_offset,
        next_entry_offset: page.next_page_offset,
        total_entries: page.total_entries,
        helper_completeness_attestation,
        history_authority_descriptor,
        global_history_attestation,
        history_authority_extension,
        profile_version: API_PROFILE_VERSION.to_string(),
        max_barrier_update_bytes,
        fs_forward_leap_policy: Some(pb_fs_forward_leap_policy(fs_forward_leap_policy)),
        deployment_profile_manifest,
    };

    response.encode_to_vec()
}

#[must_use]
pub fn encode_prepared_merge_acceptance_lookup_response(
    prepared: PreparedMergeAcceptanceLookup,
) -> Vec<u8> {
    let PreparedMergeAcceptanceLookup { record, barrier } = prepared;
    let PreparedBarrierEnvelope {
        history_authority_descriptor,
        global_history_attestation,
        history_authority_extension,
        n_max,
        max_barrier_update_bytes,
        fs_forward_leap_policy,
        deployment_profile_manifest,
    } = barrier;

    let response = pb::BarrierLookupMergeAcceptanceResponse {
        status: pb_merge_acceptance_status(record.status),
        history_view_id: record.history_view_id.to_vec(),
        accepted_barrier_version: record.accepted_barrier_version,
        accepted_fs_ec: record.accepted_fs_ec,
        accepted_reason: record.accepted_reason,
        accepted_digest: record.accepted_digest.map(|digest| digest.to_vec()),
        history_commitment: Some(pb_history_commitment(record.history_commitment)),
        history_authority_descriptor,
        global_history_attestation,
        history_authority_extension,
        profile_version: API_PROFILE_VERSION.to_string(),
        n_max,
        max_barrier_update_bytes,
        fs_forward_leap_policy: Some(pb_fs_forward_leap_policy(fs_forward_leap_policy)),
        deployment_profile_manifest,
    };

    response.encode_to_vec()
}

#[must_use]
pub fn encode_full_verification_witness_response(full_verification_witness: Vec<u8>) -> Vec<u8> {
    pb::BarrierIssueFullVerificationWitnessResponse {
        full_verification_witness,
    }
    .encode_to_vec()
}

#[must_use]
pub fn encode_bootstrap_room_response(status: &str) -> Vec<u8> {
    pb::BootstrapRoomResponse {
        status: status.to_string(),
    }
    .encode_to_vec()
}

#[must_use]
pub fn encode_rotate_room_kbroad_response(status: &str, kbroad_generation: u64) -> Vec<u8> {
    pb::RotateRoomKbroadResponse {
        status: status.to_string(),
        kbroad_generation,
    }
    .encode_to_vec()
}

#[must_use]
pub fn encode_room_admin_mutation_response(status: &str, admin_count: u64) -> Vec<u8> {
    pb::RoomAdminMutationResponse {
        status: status.to_string(),
        admin_count,
    }
    .encode_to_vec()
}

#[must_use]
pub fn encode_list_room_admins_response(admin_pop_public_keys: Vec<Vec<u8>>) -> Vec<u8> {
    pb::ListRoomAdminsResponse {
        admin_pop_public_keys,
    }
    .encode_to_vec()
}

#[must_use]
pub fn encode_members_response(
    members: Vec<pb::Member>,
    root: [u8; 32],
    total_count: u64,
    next_offset: u64,
) -> Vec<u8> {
    pb::MembersResponse {
        members,
        root: root.to_vec(),
        total_count,
        next_offset,
    }
    .encode_to_vec()
}

#[must_use]
pub fn encode_search_members_response(
    members: Vec<pb::Member>,
    root: [u8; 32],
    total_count: u64,
    next_offset: u64,
) -> Vec<u8> {
    pb::SearchMembersResponse {
        members,
        root: root.to_vec(),
        total_count,
        next_offset,
    }
    .encode_to_vec()
}

/// Encode a multi-head window snapshot using the shared protobuf schema.
#[must_use]
pub fn encode_window_snapshot_response(entries: Vec<RoomWindowEntrySnapshot>) -> Vec<u8> {
    let response = pb::GetWindowResponse {
        entries: entries
            .into_iter()
            .map(|entry| pb::WindowEntry {
                wid: entry.wid,
                heads: entry
                    .heads
                    .into_iter()
                    .map(|head| pb::WindowHead {
                        we_epoch_id: head.we_epoch_id.to_vec(),
                        msphf_hp_commit: head.msphf_hp_commit.to_vec(),
                        seed_ctx_hash: head.seed_ctx_hash.to_vec(),
                        rho_commit: head.rho_commit.to_vec(),
                        seed_commit: head.seed_commit.to_vec(),
                        xk_hash: head.xk_hash.to_vec(),
                        accept_seq: head.accept_seq,
                        age_ms: head.age_ms,
                    })
                    .collect(),
            })
            .collect(),
    };

    response.encode_to_vec()
}

fn pb_barrier_join_leaf_record(record: ServerBarrierJoinLeafRecord) -> pb::BarrierJoinLeafRecord {
    pb::BarrierJoinLeafRecord {
        device_pk: record.device_pk,
        leaf_index: record.leaf_index,
        ek_leaf: record.ek_leaf,
    }
}

fn pb_merge_acceptance_status(status: ServerMergeAcceptanceStatus) -> i32 {
    match status {
        ServerMergeAcceptanceStatus::Pending => pb::MergeAcceptanceStatus::Pending as i32,
        ServerMergeAcceptanceStatus::Accepted => pb::MergeAcceptanceStatus::Accepted as i32,
        ServerMergeAcceptanceStatus::Superseded => pb::MergeAcceptanceStatus::Superseded as i32,
        ServerMergeAcceptanceStatus::FinalRejected => {
            pb::MergeAcceptanceStatus::FinalRejected as i32
        }
    }
}

/// Encode an acceptance telemetry snapshot using the shared protobuf schema.
#[must_use]
pub fn encode_telemetry_snapshot_response(
    entries: Vec<RoomTelemetrySnapshotEntry>,
    freeze_stats: Vec<(u32, String, u64)>,
) -> Vec<u8> {
    let response = pb::GetTelemetryResponse {
        entries: entries
            .into_iter()
            .map(|entry| pb::TelemetryEntry {
                gid: entry.gid,
                parent_root: entry.parent_root.to_vec(),
                head_attempts: entry.head_attempts,
                head_insertions: entry.head_insertions,
                freeze_window_full: entry.freeze_window_full,
                freeze_rho_replay: entry.freeze_rho_replay,
                last_active_heads: entry.last_active_heads,
            })
            .collect(),
        freeze_stats: freeze_stats
            .into_iter()
            .map(|(code, reason, count)| pb::FreezeStat {
                code,
                reason,
                count,
            })
            .collect(),
    };

    response.encode_to_vec()
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityBindingValidationError {
    #[error("invalid pop_public_key length")]
    InvalidPublicKeyLength,
    #[error("invalid signature length")]
    InvalidSignatureLength,
    #[error("alias cannot be empty")]
    EmptyAlias,
    #[error("failed to encode message for verification")]
    EncodeMessage,
    #[error("invalid pop_public_key")]
    InvalidPublicKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("signature verification failed")]
    VerificationFailed,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PreparedIdentityBindingError {
    #[error(transparent)]
    Validation(#[from] IdentityBindingValidationError),
    #[error("failed to compute leaf_id: {0}")]
    ComputeLeaf(String),
}

/// Verifies an identity binding signature over `CBOR([alias, pop_public_key])`.
pub fn verify_identity_binding(
    binding: &pb::IdentityBinding,
) -> Result<(), IdentityBindingValidationError> {
    if binding.pop_public_key.len() != ML_DSA_65_PUBLIC_KEY_BYTES {
        return Err(IdentityBindingValidationError::InvalidPublicKeyLength);
    }
    if binding.signature.len() != ML_DSA_65_SIGNATURE_BYTES {
        return Err(IdentityBindingValidationError::InvalidSignatureLength);
    }
    if binding.alias.is_empty() {
        return Err(IdentityBindingValidationError::EmptyAlias);
    }

    let message_data = (
        ByteBuf::from(binding.alias.as_bytes().to_vec()),
        ByteBuf::from(binding.pop_public_key.clone()),
    );
    let mut message = Vec::new();
    into_writer(&message_data, &mut message)
        .map_err(|_| IdentityBindingValidationError::EncodeMessage)?;

    match verify_ml_dsa_65_detached_signature(&binding.pop_public_key, &message, &binding.signature)
    {
        Ok(()) => {}
        Err(cityg_pqc::MlDsa65VerifyError::InvalidPublicKey) => {
            return Err(IdentityBindingValidationError::InvalidPublicKey);
        }
        Err(cityg_pqc::MlDsa65VerifyError::InvalidSignature) => {
            return Err(IdentityBindingValidationError::InvalidSignature);
        }
        Err(
            cityg_pqc::MlDsa65VerifyError::InvalidPublicKeyLength
            | cityg_pqc::MlDsa65VerifyError::InvalidSignatureLength,
        ) => {
            return Err(IdentityBindingValidationError::VerificationFailed);
        }
        Err(cityg_pqc::MlDsa65VerifyError::VerificationFailed) => {
            return Err(IdentityBindingValidationError::VerificationFailed);
        }
    }

    Ok(())
}

pub fn prepare_identity_binding(
    gid: &[u8; 32],
    binding: Option<&pb::IdentityBinding>,
) -> Result<Option<PreparedIdentityBinding>, PreparedIdentityBindingError> {
    let Some(binding) = binding else {
        return Ok(None);
    };

    verify_identity_binding(binding)?;
    let requested_leaf_id = msphf_orchestrator::compute_leaf_id(
        msphf_orchestrator::LeafIdMode::PerGroup,
        gid,
        ML_DSA_65_ALGORITHM,
        &binding.pop_public_key,
    )
    .map_err(|error| PreparedIdentityBindingError::ComputeLeaf(error.to_string()))?;

    Ok(Some(PreparedIdentityBinding {
        confirmed_binding: binding.clone(),
        requested_leaf_id,
    }))
}

#[must_use]
pub fn pb_member(
    leaf_id: &[u8; 32],
    alias_entry: Option<&AliasLeafEntry>,
    metadata: Option<&MemberMetadata>,
) -> pb::Member {
    pb::Member {
        leaf_id: leaf_id.to_vec(),
        alias: alias_entry.map(|entry| entry.alias.clone()),
        pop_public_key: alias_entry.map(|entry| entry.pop_public_key.clone()),
        join_date: metadata.map(|entry| entry.join_timestamp_ms),
        last_seen: metadata.map(|entry| entry.last_seen_timestamp_ms),
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HistoryCommitmentDecodeError {
    #[error("current_history_commitment must be provided")]
    Missing,
    #[error("current_history_commitment fields must be 32 bytes")]
    InvalidLength,
}

impl HistoryCommitmentDecodeError {
    #[must_use]
    pub const fn api_message(&self) -> &'static str {
        match self {
            Self::Missing => "current_history_commitment must be provided",
            Self::InvalidLength => "current_history_commitment fields must be 32 bytes",
        }
    }
}

#[must_use]
pub fn pb_history_commitment(commitment: ServerHistoryCommitment) -> pb::HistoryCommitment {
    pb::HistoryCommitment {
        history_view_id: commitment.history_view_id.to_vec(),
        history_commitment_id: commitment.history_commitment_id.to_vec(),
        prev_history_commitment_id: commitment.prev_history_commitment_id.to_vec(),
        history_seq: commitment.history_seq,
    }
}

pub fn parse_pb_history_commitment(
    commitment: Option<pb::HistoryCommitment>,
) -> Result<ServerHistoryCommitment, HistoryCommitmentDecodeError> {
    let commitment = commitment.ok_or(HistoryCommitmentDecodeError::Missing)?;
    if commitment.history_view_id.len() != 32
        || commitment.history_commitment_id.len() != 32
        || commitment.prev_history_commitment_id.len() != 32
    {
        return Err(HistoryCommitmentDecodeError::InvalidLength);
    }
    let mut history_view_id = [0u8; 32];
    history_view_id.copy_from_slice(&commitment.history_view_id);
    let mut history_commitment_id = [0u8; 32];
    history_commitment_id.copy_from_slice(&commitment.history_commitment_id);
    let mut prev_history_commitment_id = [0u8; 32];
    prev_history_commitment_id.copy_from_slice(&commitment.prev_history_commitment_id);
    Ok(ServerHistoryCommitment {
        history_view_id,
        history_commitment_id,
        prev_history_commitment_id,
        history_seq: commitment.history_seq,
    })
}

#[must_use]
pub fn pb_fs_forward_leap_policy(policy: ServerFsForwardLeapPolicy) -> pb::FsForwardLeapPolicy {
    pb::FsForwardLeapPolicy {
        h: policy.h,
        checkpoint_interval: policy.checkpoint_interval,
        slack_anchor: policy.slack_anchor,
        slack_first_device: policy.slack_first_device,
        slack_device: policy.slack_device,
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FullVerificationWitnessRequestDecodeError {
    #[error("author_leaf_id must be 32 bytes")]
    InvalidAuthorLeafId,
    #[error("current_global_history_attestation must be provided")]
    MissingCurrentGlobalHistoryAttestation,
    #[error("deployment_profile_manifest must be provided")]
    MissingDeploymentProfileManifest,
    #[error("merge_ticket_artifact must be provided")]
    MissingMergeTicketArtifact,
    #[error("barrier_update_reason must be 0 or 1 for full verification witness")]
    InvalidBarrierUpdateReason,
    #[error("revocation_roots_hash must be 32 bytes")]
    InvalidRevocationRootsHash,
    #[error("revocation_target_leaf_id must be 32 bytes when provided")]
    InvalidRevocationTargetLeafId,
    #[error(transparent)]
    HistoryCommitment(#[from] HistoryCommitmentDecodeError),
}

impl FullVerificationWitnessRequestDecodeError {
    #[must_use]
    pub const fn api_message(&self) -> &'static str {
        match self {
            Self::InvalidAuthorLeafId => "author_leaf_id must be 32 bytes",
            Self::MissingCurrentGlobalHistoryAttestation => {
                "current_global_history_attestation must be provided"
            }
            Self::MissingDeploymentProfileManifest => {
                "deployment_profile_manifest must be provided"
            }
            Self::MissingMergeTicketArtifact => "merge_ticket_artifact must be provided",
            Self::InvalidBarrierUpdateReason => {
                "barrier_update_reason must be 0 or 1 for full verification witness"
            }
            Self::InvalidRevocationRootsHash => "revocation_roots_hash must be 32 bytes",
            Self::InvalidRevocationTargetLeafId => {
                "revocation_target_leaf_id must be 32 bytes when provided"
            }
            Self::HistoryCommitment(error) => error.api_message(),
        }
    }
}

pub fn decode_full_verification_witness_request(
    request: pb::BarrierIssueFullVerificationWitnessRequest,
) -> Result<RuntimeFullVerificationWitnessRequest, FullVerificationWitnessRequestDecodeError> {
    if request.author_leaf_id.len() != 32 {
        return Err(FullVerificationWitnessRequestDecodeError::InvalidAuthorLeafId);
    }
    if request.current_global_history_attestation.is_empty() {
        return Err(
            FullVerificationWitnessRequestDecodeError::MissingCurrentGlobalHistoryAttestation,
        );
    }
    if request.deployment_profile_manifest.is_empty() {
        return Err(FullVerificationWitnessRequestDecodeError::MissingDeploymentProfileManifest);
    }
    if request.merge_ticket_artifact.is_empty() {
        return Err(FullVerificationWitnessRequestDecodeError::MissingMergeTicketArtifact);
    }
    if request.barrier_update_reason != 0 && request.barrier_update_reason != 1 {
        return Err(FullVerificationWitnessRequestDecodeError::InvalidBarrierUpdateReason);
    }
    if request.revocation_roots_hash.len() != 32 {
        return Err(FullVerificationWitnessRequestDecodeError::InvalidRevocationRootsHash);
    }
    if !request.revocation_target_leaf_id.is_empty()
        && request.revocation_target_leaf_id.len() != 32
    {
        return Err(FullVerificationWitnessRequestDecodeError::InvalidRevocationTargetLeafId);
    }

    let current_history_commitment =
        parse_pb_history_commitment(request.current_history_commitment)?;
    let mut author_leaf_id = [0u8; 32];
    author_leaf_id.copy_from_slice(&request.author_leaf_id);
    let mut revocation_roots_hash = [0u8; 32];
    revocation_roots_hash.copy_from_slice(&request.revocation_roots_hash);
    let revocation_target_leaf_id = if request.revocation_target_leaf_id.is_empty() {
        None
    } else {
        let mut leaf_id = [0u8; 32];
        leaf_id.copy_from_slice(&request.revocation_target_leaf_id);
        Some(leaf_id)
    };
    let join_records = request
        .join_records
        .into_iter()
        .map(|record| ServerBarrierJoinLeafRecord {
            device_pk: record.device_pk,
            leaf_index: record.leaf_index,
            ek_leaf: record.ek_leaf,
        })
        .collect();

    Ok(RuntimeFullVerificationWitnessRequest {
        author_leaf_id,
        current_history_commitment,
        joins_prev_barrier_version: request.joins_prev_barrier_version,
        current_global_history_attestation: request.current_global_history_attestation,
        deployment_profile_manifest: request.deployment_profile_manifest,
        merge_ticket_artifact: request.merge_ticket_artifact,
        barrier_update_reason: request.barrier_update_reason,
        revocation_roots_hash,
        revocation_target_leaf_id,
        join_records,
        revoked_leaf_indices: request.revoked_leaf_indices,
        barrier_update: request.barrier_update,
    })
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BarrierHelperRequestDecodeError {
    #[error("revocation_roots_hash must be 32 bytes")]
    InvalidRevocationRootsHash,
    #[error("kem_tree_hash_after must be 32 bytes")]
    InvalidKemTreeHashAfter,
    #[error("pending_barrier_update_digest must be 32 bytes")]
    InvalidPendingBarrierUpdateDigest,
    #[error("pending_we_epoch_id must be 32 bytes")]
    InvalidPendingWeEpochId,
}

impl BarrierHelperRequestDecodeError {
    #[must_use]
    pub const fn api_message(&self) -> &'static str {
        match self {
            Self::InvalidRevocationRootsHash => "revocation_roots_hash must be 32 bytes",
            Self::InvalidKemTreeHashAfter => "kem_tree_hash_after must be 32 bytes",
            Self::InvalidPendingBarrierUpdateDigest => {
                "pending_barrier_update_digest must be 32 bytes"
            }
            Self::InvalidPendingWeEpochId => "pending_we_epoch_id must be 32 bytes",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedBarrierResolveRevokedLeavesRequest {
    pub revocation_roots_hash: [u8; 32],
    pub page_offset: u32,
    pub max_entries: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedBarrierFetchPublicTreeRequest {
    pub kem_tree_hash_after: [u8; 32],
    pub entry_offset: u32,
    pub max_entries: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedBarrierLookupMergeAcceptanceRequest {
    pub pending_barrier_version: u64,
    pub pending_barrier_update_digest: [u8; 32],
    pub pending_we_epoch_id: [u8; 32],
}

pub fn decode_barrier_resolve_revoked_leaves_request(
    request: pb::BarrierResolveRevokedLeavesRequest,
) -> Result<DecodedBarrierResolveRevokedLeavesRequest, BarrierHelperRequestDecodeError> {
    if request.revocation_roots_hash.len() != 32 {
        return Err(BarrierHelperRequestDecodeError::InvalidRevocationRootsHash);
    }
    let mut revocation_roots_hash = [0u8; 32];
    revocation_roots_hash.copy_from_slice(&request.revocation_roots_hash);
    Ok(DecodedBarrierResolveRevokedLeavesRequest {
        revocation_roots_hash,
        page_offset: request.page_offset,
        max_entries: request.max_entries,
    })
}

pub fn decode_barrier_fetch_public_tree_request(
    request: pb::BarrierFetchPublicTreeRequest,
) -> Result<DecodedBarrierFetchPublicTreeRequest, BarrierHelperRequestDecodeError> {
    if request.kem_tree_hash_after.len() != 32 {
        return Err(BarrierHelperRequestDecodeError::InvalidKemTreeHashAfter);
    }
    let mut kem_tree_hash_after = [0u8; 32];
    kem_tree_hash_after.copy_from_slice(&request.kem_tree_hash_after);
    Ok(DecodedBarrierFetchPublicTreeRequest {
        kem_tree_hash_after,
        entry_offset: request.entry_offset,
        max_entries: request.max_entries,
    })
}

pub fn decode_barrier_lookup_merge_acceptance_request(
    request: pb::BarrierLookupMergeAcceptanceRequest,
) -> Result<DecodedBarrierLookupMergeAcceptanceRequest, BarrierHelperRequestDecodeError> {
    if request.pending_barrier_update_digest.len() != 32 {
        return Err(BarrierHelperRequestDecodeError::InvalidPendingBarrierUpdateDigest);
    }
    if request.pending_we_epoch_id.len() != 32 {
        return Err(BarrierHelperRequestDecodeError::InvalidPendingWeEpochId);
    }
    let mut pending_barrier_update_digest = [0u8; 32];
    pending_barrier_update_digest.copy_from_slice(&request.pending_barrier_update_digest);
    let mut pending_we_epoch_id = [0u8; 32];
    pending_we_epoch_id.copy_from_slice(&request.pending_we_epoch_id);
    Ok(DecodedBarrierLookupMergeAcceptanceRequest {
        pending_barrier_version: request.pending_barrier_version,
        pending_barrier_update_digest,
        pending_we_epoch_id,
    })
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RoomAdminProofValidationError {
    #[error("invalid room admin public key length")]
    InvalidPublicKeyLength,
    #[error("invalid room admin signature length")]
    InvalidSignatureLength,
    #[error("room_id must be provided")]
    MissingRoomId,
    #[error("failed to encode room admin proof message")]
    EncodeProofMessage,
    #[error("invalid room admin public key")]
    InvalidPublicKey,
    #[error("invalid room admin signature")]
    InvalidSignature,
    #[error("room admin proof verification failed")]
    VerificationFailed,
    #[error("kbroad_public must be provided")]
    MissingKbroadPublic,
    #[error("failed to encode room admin proof payload")]
    EncodePayload,
    #[error("failed to derive room admin proof replay key: {0}")]
    ReplayKey(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RoomAdminRequestValidationError {
    #[error("room_id must be provided")]
    MissingRoomId,
    #[error("kbroad_public must be provided")]
    MissingKbroadPublic,
    #[error("kbroad_public has unexpected length")]
    InvalidKbroadPublicLength,
    #[error("target_pop_public_key has unexpected length")]
    InvalidTargetPopPublicKeyLength,
    #[error("room admin proof is required")]
    MissingAdminProof,
}

impl RoomAdminRequestValidationError {
    #[must_use]
    pub const fn is_unauthorized(&self) -> bool {
        matches!(self, Self::MissingAdminProof)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedRoomKbroadRequest {
    pub room_id: String,
    pub kbroad_public: Vec<u8>,
    pub admin_proof: pb::RoomAdminProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedRoomAdminMutationRequest {
    pub room_id: String,
    pub target_pop_public_key: Vec<u8>,
    pub admin_proof: pb::RoomAdminProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedListRoomAdminsRequest {
    pub room_id: String,
    pub admin_proof: pb::RoomAdminProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedExpelMemberTicketRequest {
    pub room_id: String,
    pub author_leaf_id: [u8; 32],
    pub target_leaf_id: [u8; 32],
    pub admin_proof: pb::RoomAdminProof,
}

fn validate_room_kbroad_request(
    room_id: String,
    kbroad_public: Vec<u8>,
    admin_proof: Option<pb::RoomAdminProof>,
) -> Result<ValidatedRoomKbroadRequest, RoomAdminRequestValidationError> {
    if room_id.is_empty() {
        return Err(RoomAdminRequestValidationError::MissingRoomId);
    }
    if kbroad_public.is_empty() {
        return Err(RoomAdminRequestValidationError::MissingKbroadPublic);
    }
    if kbroad_public.len() != ML_KEM_768_PUBLIC_KEY_BYTES {
        return Err(RoomAdminRequestValidationError::InvalidKbroadPublicLength);
    }
    let admin_proof = admin_proof.ok_or(RoomAdminRequestValidationError::MissingAdminProof)?;

    Ok(ValidatedRoomKbroadRequest {
        room_id,
        kbroad_public,
        admin_proof,
    })
}

pub fn validate_bootstrap_room_request(
    request: pb::BootstrapRoomRequest,
) -> Result<ValidatedRoomKbroadRequest, RoomAdminRequestValidationError> {
    validate_room_kbroad_request(request.room_id, request.kbroad_public, request.admin_proof)
}

pub fn validate_rotate_room_kbroad_request(
    request: pb::RotateRoomKbroadRequest,
) -> Result<ValidatedRoomKbroadRequest, RoomAdminRequestValidationError> {
    validate_room_kbroad_request(request.room_id, request.kbroad_public, request.admin_proof)
}

pub fn validate_room_admin_mutation_request(
    request: pb::RoomAdminMutationRequest,
) -> Result<ValidatedRoomAdminMutationRequest, RoomAdminRequestValidationError> {
    if request.room_id.is_empty() {
        return Err(RoomAdminRequestValidationError::MissingRoomId);
    }
    if request.target_pop_public_key.len() != ML_DSA_65_PUBLIC_KEY_BYTES {
        return Err(RoomAdminRequestValidationError::InvalidTargetPopPublicKeyLength);
    }
    let admin_proof = request
        .admin_proof
        .ok_or(RoomAdminRequestValidationError::MissingAdminProof)?;

    Ok(ValidatedRoomAdminMutationRequest {
        room_id: request.room_id,
        target_pop_public_key: request.target_pop_public_key,
        admin_proof,
    })
}

pub fn validate_list_room_admins_request(
    request: pb::ListRoomAdminsRequest,
) -> Result<ValidatedListRoomAdminsRequest, RoomAdminRequestValidationError> {
    if request.room_id.is_empty() {
        return Err(RoomAdminRequestValidationError::MissingRoomId);
    }
    let admin_proof = request
        .admin_proof
        .ok_or(RoomAdminRequestValidationError::MissingAdminProof)?;

    Ok(ValidatedListRoomAdminsRequest {
        room_id: request.room_id,
        admin_proof,
    })
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExpelMemberTicketRequestValidationError {
    #[error("room_id must be provided")]
    MissingRoomId,
    #[error("author_leaf_id must be 32 bytes")]
    InvalidAuthorLeafId,
    #[error("target_leaf_id must be 32 bytes")]
    InvalidTargetLeafId,
    #[error("author_leaf_id and target_leaf_id must differ; use controlled leave instead")]
    MatchingLeafIds,
    #[error("room admin proof is required")]
    MissingAdminProof,
}

impl ExpelMemberTicketRequestValidationError {
    #[must_use]
    pub const fn is_unauthorized(&self) -> bool {
        matches!(self, Self::MissingAdminProof)
    }
}

pub fn validate_expel_member_ticket_request(
    request: pb::ExpelMemberTicketRequest,
) -> Result<ValidatedExpelMemberTicketRequest, ExpelMemberTicketRequestValidationError> {
    if request.room_id.is_empty() {
        return Err(ExpelMemberTicketRequestValidationError::MissingRoomId);
    }
    let author_leaf_id: [u8; 32] = request
        .author_leaf_id
        .as_slice()
        .try_into()
        .map_err(|_| ExpelMemberTicketRequestValidationError::InvalidAuthorLeafId)?;
    let target_leaf_id: [u8; 32] = request
        .target_leaf_id
        .as_slice()
        .try_into()
        .map_err(|_| ExpelMemberTicketRequestValidationError::InvalidTargetLeafId)?;
    if author_leaf_id == target_leaf_id {
        return Err(ExpelMemberTicketRequestValidationError::MatchingLeafIds);
    }
    let admin_proof = request
        .admin_proof
        .ok_or(ExpelMemberTicketRequestValidationError::MissingAdminProof)?;

    Ok(ValidatedExpelMemberTicketRequest {
        room_id: request.room_id,
        author_leaf_id,
        target_leaf_id,
        admin_proof,
    })
}

/// Verify a room-admin proof over `(operation, room_id, payload)`.
pub fn verify_room_admin_proof_payload(
    proof: &pb::RoomAdminProof,
    operation: &'static str,
    room_id: &str,
    payload: &[u8],
) -> Result<Vec<u8>, RoomAdminProofValidationError> {
    if proof.pop_public_key.len() != ML_DSA_65_PUBLIC_KEY_BYTES {
        return Err(RoomAdminProofValidationError::InvalidPublicKeyLength);
    }
    if proof.signature.len() != ML_DSA_65_SIGNATURE_BYTES {
        return Err(RoomAdminProofValidationError::InvalidSignatureLength);
    }
    if room_id.is_empty() {
        return Err(RoomAdminProofValidationError::MissingRoomId);
    }

    let message_data = (operation, room_id, ByteBuf::from(payload.to_vec()));
    let mut message = Vec::new();
    into_writer(&message_data, &mut message)
        .map_err(|_| RoomAdminProofValidationError::EncodeProofMessage)?;

    match verify_ml_dsa_65_detached_signature(&proof.pop_public_key, &message, &proof.signature) {
        Ok(()) => {}
        Err(cityg_pqc::MlDsa65VerifyError::InvalidPublicKey) => {
            return Err(RoomAdminProofValidationError::InvalidPublicKey);
        }
        Err(cityg_pqc::MlDsa65VerifyError::InvalidSignature) => {
            return Err(RoomAdminProofValidationError::InvalidSignature);
        }
        Err(
            cityg_pqc::MlDsa65VerifyError::InvalidPublicKeyLength
            | cityg_pqc::MlDsa65VerifyError::InvalidSignatureLength,
        ) => {
            return Err(RoomAdminProofValidationError::VerificationFailed);
        }
        Err(cityg_pqc::MlDsa65VerifyError::VerificationFailed) => {
            return Err(RoomAdminProofValidationError::VerificationFailed);
        }
    }

    Ok(proof.pop_public_key.clone())
}

/// Verify a room-admin proof using `kbroad_public` as the authenticated payload.
pub fn verify_room_admin_proof(
    proof: &pb::RoomAdminProof,
    operation: &'static str,
    room_id: &str,
    kbroad_public: &[u8],
) -> Result<Vec<u8>, RoomAdminProofValidationError> {
    if kbroad_public.is_empty() {
        return Err(RoomAdminProofValidationError::MissingKbroadPublic);
    }
    verify_room_admin_proof_payload(proof, operation, room_id, kbroad_public)
}

#[derive(Serialize)]
struct RoomAdminProofReplayKeyInput<'a> {
    #[serde(with = "serde_bytes")]
    pop_public_key: &'a [u8],
    #[serde(with = "serde_bytes")]
    signature: &'a [u8],
}

/// Derive the replay-protection key for a room-admin proof.
pub fn room_admin_proof_replay_key(
    proof: &pb::RoomAdminProof,
) -> Result<[u8; 32], RoomAdminProofValidationError> {
    h_l(
        "room-admin/replay-key",
        &RoomAdminProofReplayKeyInput {
            pop_public_key: &proof.pop_public_key,
            signature: &proof.signature,
        },
    )
    .map_err(|err| RoomAdminProofValidationError::ReplayKey(err.to_string()))
}

/// Encode the `(author_leaf_id, target_leaf_id)` room-admin proof payload.
pub fn encode_room_admin_leaf_pair_payload(
    author_leaf_id: &[u8; 32],
    target_leaf_id: &[u8; 32],
) -> Result<Vec<u8>, RoomAdminProofValidationError> {
    let payload = (
        ByteBuf::from(author_leaf_id.to_vec()),
        ByteBuf::from(target_leaf_id.to_vec()),
    );
    let mut payload_bytes = Vec::new();
    into_writer(&payload, &mut payload_bytes)
        .map_err(|_| RoomAdminProofValidationError::EncodePayload)?;
    Ok(payload_bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoomScopedApiRoute {
    AcceptEpoch,
    Members,
    SearchMembers,
    SendMessage,
    FetchMessages,
    GetBundle,
    BootstrapRoom,
    RotateRoomKbroad,
    GrantRoomAdmin,
    RevokeRoomAdmin,
    ListRoomAdmins,
    ExpelMemberTicket,
    JoinTicket,
    MergeTicket,
    BarrierResolveRevokedLeaves,
    BarrierResolveJoinsSince,
    BarrierFetchPublicTree,
    BarrierIssueFullVerificationWitness,
    BarrierLookupMergeAcceptance,
    RefreshPivot,
}

impl RoomScopedApiRoute {
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::AcceptEpoch => "/v1/accept_epoch",
            Self::Members => "/v1/members",
            Self::SearchMembers => "/v1/members/search",
            Self::SendMessage => "/v1/send_message",
            Self::FetchMessages => "/v1/messages",
            Self::GetBundle => "/v1/bundle",
            Self::BootstrapRoom => "/v1/rooms/bootstrap",
            Self::RotateRoomKbroad => "/v1/rooms/rotate_kbroad",
            Self::GrantRoomAdmin => "/v1/rooms/grant_admin",
            Self::RevokeRoomAdmin => "/v1/rooms/revoke_admin",
            Self::ListRoomAdmins => "/v1/rooms/list_admins",
            Self::ExpelMemberTicket => "/v1/rooms/expel_member_ticket",
            Self::JoinTicket => "/v1/rooms/join_ticket",
            Self::MergeTicket => "/v1/rooms/merge_ticket",
            Self::BarrierResolveRevokedLeaves => "/v1/barrier/resolve_revoked_leaves",
            Self::BarrierResolveJoinsSince => "/v1/barrier/resolve_joins_since",
            Self::BarrierFetchPublicTree => "/v1/barrier/fetch_public_tree",
            Self::BarrierIssueFullVerificationWitness => {
                "/v1/barrier/issue_full_verification_witness"
            }
            Self::BarrierLookupMergeAcceptance => "/v1/barrier/lookup_merge_acceptance",
            Self::RefreshPivot => "/v1/pivot/refresh",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoomScopedRoutingKey {
    Gid([u8; 32]),
    WeEpochId([u8; 32]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoomScopedRequestTarget {
    pub route: RoomScopedApiRoute,
    pub key: RoomScopedRoutingKey,
}

#[derive(Debug, Error)]
pub enum RoomScopedRouteParseError {
    #[error("failed to decode {path} request: {source}")]
    Decode {
        path: &'static str,
        #[source]
        source: prost::DecodeError,
    },
    #[error("{field} must be provided")]
    MissingField { field: &'static str },
    #[error("{field} must be 32 bytes")]
    InvalidLength { field: &'static str },
    #[error("room_id must be 64 hex characters")]
    InvalidRoomIdEncoding,
    #[error("room_id must be 32 bytes")]
    InvalidRoomIdLength,
    #[error("failed to decode bundle for {path}: {message}")]
    InvalidBundle { path: &'static str, message: String },
}

#[must_use]
pub fn is_room_scoped_api_path(path: &str) -> bool {
    match_room_scoped_route(path).is_some()
}

pub fn extract_room_scoped_request_target(
    path: &str,
    body: &[u8],
) -> Result<Option<RoomScopedRequestTarget>, RoomScopedRouteParseError> {
    let Some(route) = match_room_scoped_route(path) else {
        return Ok(None);
    };

    let key = match route {
        RoomScopedApiRoute::AcceptEpoch => {
            let request = decode::<pb::AcceptEpochRequest>(route, body)?;
            RoomScopedRoutingKey::Gid(bundle_gid(route, &request.bundle_cbor)?)
        }
        RoomScopedApiRoute::Members => {
            let request = decode::<pb::MembersRequest>(route, body)?;
            RoomScopedRoutingKey::Gid(parse_bytes_32("gid", request.gid.as_slice())?)
        }
        RoomScopedApiRoute::SearchMembers => {
            let request = decode::<pb::SearchMembersRequest>(route, body)?;
            RoomScopedRoutingKey::Gid(parse_bytes_32("gid", request.gid.as_slice())?)
        }
        RoomScopedApiRoute::SendMessage => {
            let request = decode::<pb::SendMessageRequest>(route, body)?;
            RoomScopedRoutingKey::WeEpochId(parse_bytes_32(
                "we_epoch_id",
                request.we_epoch_id.as_slice(),
            )?)
        }
        RoomScopedApiRoute::FetchMessages => {
            let request = decode::<pb::FetchMessagesRequest>(route, body)?;
            RoomScopedRoutingKey::WeEpochId(parse_bytes_32(
                "we_epoch_id",
                request.we_epoch_id.as_slice(),
            )?)
        }
        RoomScopedApiRoute::GetBundle => {
            let request = decode::<pb::GetBundleRequest>(route, body)?;
            RoomScopedRoutingKey::WeEpochId(parse_bytes_32(
                "we_epoch_id",
                request.we_epoch_id.as_slice(),
            )?)
        }
        RoomScopedApiRoute::BootstrapRoom => {
            let request = decode::<pb::BootstrapRoomRequest>(route, body)?;
            RoomScopedRoutingKey::Gid(parse_room_id(request.room_id.as_str())?)
        }
        RoomScopedApiRoute::RotateRoomKbroad => {
            let request = decode::<pb::RotateRoomKbroadRequest>(route, body)?;
            RoomScopedRoutingKey::Gid(parse_room_id(request.room_id.as_str())?)
        }
        RoomScopedApiRoute::GrantRoomAdmin | RoomScopedApiRoute::RevokeRoomAdmin => {
            let request = decode::<pb::RoomAdminMutationRequest>(route, body)?;
            RoomScopedRoutingKey::Gid(parse_room_id(request.room_id.as_str())?)
        }
        RoomScopedApiRoute::ListRoomAdmins => {
            let request = decode::<pb::ListRoomAdminsRequest>(route, body)?;
            RoomScopedRoutingKey::Gid(parse_room_id(request.room_id.as_str())?)
        }
        RoomScopedApiRoute::ExpelMemberTicket => {
            let request = decode::<pb::ExpelMemberTicketRequest>(route, body)?;
            RoomScopedRoutingKey::Gid(parse_room_id(request.room_id.as_str())?)
        }
        RoomScopedApiRoute::JoinTicket => {
            let request = decode::<pb::JoinTicketRequest>(route, body)?;
            RoomScopedRoutingKey::Gid(parse_room_id(request.room_id.as_str())?)
        }
        RoomScopedApiRoute::MergeTicket => {
            let request = decode::<pb::MergeTicketRequest>(route, body)?;
            RoomScopedRoutingKey::Gid(parse_room_id(request.room_id.as_str())?)
        }
        RoomScopedApiRoute::BarrierResolveRevokedLeaves => {
            let request = decode::<pb::BarrierResolveRevokedLeavesRequest>(route, body)?;
            RoomScopedRoutingKey::Gid(parse_room_id(request.room_id.as_str())?)
        }
        RoomScopedApiRoute::BarrierResolveJoinsSince => {
            let request = decode::<pb::BarrierResolveJoinsSinceRequest>(route, body)?;
            RoomScopedRoutingKey::Gid(parse_room_id(request.room_id.as_str())?)
        }
        RoomScopedApiRoute::BarrierFetchPublicTree => {
            let request = decode::<pb::BarrierFetchPublicTreeRequest>(route, body)?;
            RoomScopedRoutingKey::Gid(parse_room_id(request.room_id.as_str())?)
        }
        RoomScopedApiRoute::BarrierIssueFullVerificationWitness => {
            let request = decode::<pb::BarrierIssueFullVerificationWitnessRequest>(route, body)?;
            RoomScopedRoutingKey::Gid(parse_room_id(request.room_id.as_str())?)
        }
        RoomScopedApiRoute::BarrierLookupMergeAcceptance => {
            let request = decode::<pb::BarrierLookupMergeAcceptanceRequest>(route, body)?;
            RoomScopedRoutingKey::Gid(parse_room_id(request.room_id.as_str())?)
        }
        RoomScopedApiRoute::RefreshPivot => {
            let request = decode::<pb::RefreshPivotRequest>(route, body)?;
            RoomScopedRoutingKey::Gid(bundle_gid(route, &request.bundle_cbor)?)
        }
    };

    Ok(Some(RoomScopedRequestTarget { route, key }))
}

pub fn parse_room_id(room_id: &str) -> Result<[u8; 32], RoomScopedRouteParseError> {
    if room_id.is_empty() {
        return Err(RoomScopedRouteParseError::MissingField { field: "room_id" });
    }
    let bytes =
        hex::decode(room_id).map_err(|_| RoomScopedRouteParseError::InvalidRoomIdEncoding)?;
    bytes
        .try_into()
        .map_err(|_| RoomScopedRouteParseError::InvalidRoomIdLength)
}

fn match_room_scoped_route(path: &str) -> Option<RoomScopedApiRoute> {
    match path {
        "/v1/accept_epoch" => Some(RoomScopedApiRoute::AcceptEpoch),
        "/v1/members" => Some(RoomScopedApiRoute::Members),
        "/v1/members/search" => Some(RoomScopedApiRoute::SearchMembers),
        "/v1/send_message" => Some(RoomScopedApiRoute::SendMessage),
        "/v1/messages" => Some(RoomScopedApiRoute::FetchMessages),
        "/v1/bundle" => Some(RoomScopedApiRoute::GetBundle),
        "/v1/rooms/bootstrap" => Some(RoomScopedApiRoute::BootstrapRoom),
        "/v1/rooms/rotate_kbroad" => Some(RoomScopedApiRoute::RotateRoomKbroad),
        "/v1/rooms/grant_admin" => Some(RoomScopedApiRoute::GrantRoomAdmin),
        "/v1/rooms/revoke_admin" => Some(RoomScopedApiRoute::RevokeRoomAdmin),
        "/v1/rooms/list_admins" => Some(RoomScopedApiRoute::ListRoomAdmins),
        "/v1/rooms/expel_member_ticket" => Some(RoomScopedApiRoute::ExpelMemberTicket),
        "/v1/rooms/join_ticket" => Some(RoomScopedApiRoute::JoinTicket),
        "/v1/rooms/merge_ticket" => Some(RoomScopedApiRoute::MergeTicket),
        "/v1/barrier/resolve_revoked_leaves" => {
            Some(RoomScopedApiRoute::BarrierResolveRevokedLeaves)
        }
        "/v1/barrier/resolve_joins_since" => Some(RoomScopedApiRoute::BarrierResolveJoinsSince),
        "/v1/barrier/fetch_public_tree" => Some(RoomScopedApiRoute::BarrierFetchPublicTree),
        "/v1/barrier/issue_full_verification_witness" => {
            Some(RoomScopedApiRoute::BarrierIssueFullVerificationWitness)
        }
        "/v1/barrier/lookup_merge_acceptance" => {
            Some(RoomScopedApiRoute::BarrierLookupMergeAcceptance)
        }
        "/v1/pivot/refresh" => Some(RoomScopedApiRoute::RefreshPivot),
        _ => None,
    }
}

fn decode<M: Message + Default>(
    route: RoomScopedApiRoute,
    body: &[u8],
) -> Result<M, RoomScopedRouteParseError> {
    M::decode(body).map_err(|source| RoomScopedRouteParseError::Decode {
        path: route.path(),
        source,
    })
}

fn parse_bytes_32(
    field: &'static str,
    bytes: &[u8],
) -> Result<[u8; 32], RoomScopedRouteParseError> {
    if bytes.is_empty() {
        return Err(RoomScopedRouteParseError::MissingField { field });
    }
    bytes
        .try_into()
        .map_err(|_| RoomScopedRouteParseError::InvalidLength { field })
}

fn bundle_gid(
    route: RoomScopedApiRoute,
    bundle_cbor: &[u8],
) -> Result<[u8; 32], RoomScopedRouteParseError> {
    let bundle = ClientEpochBundle::from_cbor(bundle_cbor).map_err(|err| match err {
        ClientError::InvalidInput(message) => RoomScopedRouteParseError::InvalidBundle {
            path: route.path(),
            message: message.to_string(),
        },
        other => RoomScopedRouteParseError::InvalidBundle {
            path: route.path(),
            message: other.to_string(),
        },
    })?;
    parse_bytes_32("bundle gid", bundle.gid())
}

#[cfg(test)]
mod tests {
    use cityg_client::demo::{DEMO_GID, demo_bundle};
    use cityg_runtime::{AliasLeafEntry, MemberMetadata};
    use pqcrypto_dilithium::dilithium5;
    use pqcrypto_traits::sign::{DetachedSignature as DetachedSignatureTrait, PublicKey as _};
    use prost::Message;
    use serde_bytes::ByteBuf;

    use super::*;

    #[test]
    fn extract_join_ticket_room_target_from_room_id() {
        let request = pb::JoinTicketRequest {
            room_id: hex::encode(DEMO_GID),
            alias: "alice".to_string(),
            identity_binding: None,
        };

        let target = extract_room_scoped_request_target(
            RoomScopedApiRoute::JoinTicket.path(),
            &request.encode_to_vec(),
        )
        .expect("parse request")
        .expect("room target");

        assert_eq!(target.route, RoomScopedApiRoute::JoinTicket);
        assert_eq!(target.key, RoomScopedRoutingKey::Gid(DEMO_GID));
    }

    #[test]
    fn extract_accept_epoch_room_target_from_bundle() {
        let bundle = demo_bundle("alice").expect("demo bundle");
        let request = pb::AcceptEpochRequest {
            bundle_cbor: bundle.to_cbor().expect("bundle cbor"),
        };

        let target = extract_room_scoped_request_target(
            RoomScopedApiRoute::AcceptEpoch.path(),
            &request.encode_to_vec(),
        )
        .expect("parse request")
        .expect("room target");

        assert_eq!(target.route, RoomScopedApiRoute::AcceptEpoch);
        assert_eq!(target.key, RoomScopedRoutingKey::Gid(DEMO_GID));
    }

    #[test]
    fn extract_send_message_target_from_we_epoch_id() {
        let request = pb::SendMessageRequest {
            we_epoch_id: [0x44; 32].to_vec(),
            ciphertext: vec![1, 2, 3],
            sender: [0x55; 32].to_vec(),
        };

        let target = extract_room_scoped_request_target(
            RoomScopedApiRoute::SendMessage.path(),
            &request.encode_to_vec(),
        )
        .expect("parse request")
        .expect("room target");

        assert_eq!(target.route, RoomScopedApiRoute::SendMessage);
        assert_eq!(target.key, RoomScopedRoutingKey::WeEpochId([0x44; 32]));
    }

    #[test]
    fn non_room_scoped_paths_return_none() {
        assert_eq!(
            extract_room_scoped_request_target("/health", &[]).expect("parse"),
            None
        );
        assert!(!is_room_scoped_api_path("/health"));
    }

    #[test]
    fn prepare_identity_binding_derives_requested_leaf() {
        let (public_key, secret_key) = dilithium5::keypair();
        let binding = signed_identity_binding("alice", public_key.as_bytes(), &secret_key);

        let prepared = prepare_identity_binding(&DEMO_GID, Some(&binding))
            .expect("prepare binding")
            .expect("prepared binding");

        assert_eq!(prepared.confirmed_binding, binding);
        assert_eq!(
            prepared.requested_leaf_id,
            msphf_orchestrator::compute_leaf_id(
                msphf_orchestrator::LeafIdMode::PerGroup,
                &DEMO_GID,
                "ML-DSA-65",
                public_key.as_bytes(),
            )
            .expect("compute leaf"),
        );
    }

    #[test]
    fn prepare_identity_binding_rejects_invalid_signature() {
        let (public_key, _) = dilithium5::keypair();
        let binding = pb::IdentityBinding {
            alias: "alice".to_string(),
            pop_public_key: public_key.as_bytes().to_vec(),
            signature: vec![0x42; dilithium5::signature_bytes()],
        };

        let error =
            prepare_identity_binding(&DEMO_GID, Some(&binding)).expect_err("invalid binding");
        assert!(matches!(
            error,
            PreparedIdentityBindingError::Validation(
                IdentityBindingValidationError::InvalidSignature
                    | IdentityBindingValidationError::VerificationFailed
            )
        ));
    }

    #[test]
    fn pb_member_projects_alias_and_metadata() {
        let leaf_id = [0xAB; 32];
        let member = pb_member(
            &leaf_id,
            Some(&AliasLeafEntry {
                alias: "alice".to_string(),
                pop_public_key: vec![0x11; 8],
            }),
            Some(&MemberMetadata {
                join_timestamp_ms: 10,
                last_seen_timestamp_ms: 20,
            }),
        );

        assert_eq!(member.leaf_id, leaf_id.to_vec());
        assert_eq!(member.alias.as_deref(), Some("alice"));
        assert_eq!(member.pop_public_key, Some(vec![0x11; 8]));
        assert_eq!(member.join_date, Some(10));
        assert_eq!(member.last_seen, Some(20));
    }

    #[test]
    fn history_commitment_round_trips_between_server_and_pb() {
        let commitment = ServerHistoryCommitment {
            history_view_id: [0x11; 32],
            history_commitment_id: [0x22; 32],
            prev_history_commitment_id: [0x33; 32],
            history_seq: 44,
        };

        let decoded =
            parse_pb_history_commitment(Some(pb_history_commitment(commitment))).expect("decode");

        assert_eq!(decoded, commitment);
    }

    #[test]
    fn parse_pb_history_commitment_validates_presence_and_lengths() {
        assert_eq!(
            parse_pb_history_commitment(None),
            Err(HistoryCommitmentDecodeError::Missing)
        );
        assert_eq!(
            parse_pb_history_commitment(Some(pb::HistoryCommitment {
                history_view_id: vec![0x11; 31],
                history_commitment_id: vec![0x22; 32],
                prev_history_commitment_id: vec![0x33; 32],
                history_seq: 1,
            })),
            Err(HistoryCommitmentDecodeError::InvalidLength)
        );
    }

    #[test]
    fn decode_full_verification_witness_request_projects_runtime_shape() {
        let decoded = decode_full_verification_witness_request(
            pb::BarrierIssueFullVerificationWitnessRequest {
                room_id: hex::encode(DEMO_GID),
                author_leaf_id: vec![0x11; 32],
                current_history_commitment: Some(pb::HistoryCommitment {
                    history_view_id: vec![0x21; 32],
                    history_commitment_id: vec![0x22; 32],
                    prev_history_commitment_id: vec![0x23; 32],
                    history_seq: 24,
                }),
                joins_prev_barrier_version: 25,
                current_global_history_attestation: vec![0x31],
                deployment_profile_manifest: vec![0x32],
                merge_ticket_artifact: vec![0x33],
                barrier_update_reason: 1,
                revocation_roots_hash: vec![0x41; 32],
                revocation_target_leaf_id: vec![0x42; 32],
                join_records: vec![pb::BarrierJoinLeafRecord {
                    device_pk: vec![0x51],
                    leaf_index: 52,
                    ek_leaf: vec![0x53],
                }],
                revoked_leaf_indices: vec![61],
                barrier_update: vec![0x62],
            },
        )
        .expect("decode witness request");

        assert_eq!(decoded.author_leaf_id, [0x11; 32]);
        assert_eq!(
            decoded.current_history_commitment.history_view_id,
            [0x21; 32]
        );
        assert_eq!(decoded.joins_prev_barrier_version, 25);
        assert_eq!(decoded.current_global_history_attestation, vec![0x31]);
        assert_eq!(decoded.deployment_profile_manifest, vec![0x32]);
        assert_eq!(decoded.merge_ticket_artifact, vec![0x33]);
        assert_eq!(decoded.barrier_update_reason, 1);
        assert_eq!(decoded.revocation_roots_hash, [0x41; 32]);
        assert_eq!(decoded.revocation_target_leaf_id, Some([0x42; 32]));
        assert_eq!(decoded.join_records.len(), 1);
        assert_eq!(decoded.join_records[0].leaf_index, 52);
        assert_eq!(decoded.revoked_leaf_indices, vec![61]);
        assert_eq!(decoded.barrier_update, vec![0x62]);
    }

    #[test]
    fn decode_full_verification_witness_request_rejects_invalid_reason() {
        let error = decode_full_verification_witness_request(
            pb::BarrierIssueFullVerificationWitnessRequest {
                room_id: hex::encode(DEMO_GID),
                author_leaf_id: vec![0x11; 32],
                current_history_commitment: Some(pb::HistoryCommitment {
                    history_view_id: vec![0x21; 32],
                    history_commitment_id: vec![0x22; 32],
                    prev_history_commitment_id: vec![0x23; 32],
                    history_seq: 24,
                }),
                joins_prev_barrier_version: 25,
                current_global_history_attestation: vec![0x31],
                deployment_profile_manifest: vec![0x32],
                merge_ticket_artifact: vec![0x33],
                barrier_update_reason: 9,
                revocation_roots_hash: vec![0x41; 32],
                revocation_target_leaf_id: vec![],
                join_records: Vec::new(),
                revoked_leaf_indices: Vec::new(),
                barrier_update: Vec::new(),
            },
        )
        .expect_err("invalid reason must fail");

        assert_eq!(
            error,
            FullVerificationWitnessRequestDecodeError::InvalidBarrierUpdateReason
        );
    }

    #[test]
    fn encode_full_verification_witness_response_round_trips() {
        let payload = vec![0xAA, 0xBB, 0xCC];
        let decoded = pb::BarrierIssueFullVerificationWitnessResponse::decode(
            encode_full_verification_witness_response(payload.clone()).as_slice(),
        )
        .expect("decode response");

        assert_eq!(decoded.full_verification_witness, payload);
    }

    #[test]
    fn encode_room_admin_responses_round_trip() {
        let decoded_bootstrap = pb::BootstrapRoomResponse::decode(
            encode_bootstrap_room_response("registered").as_slice(),
        )
        .expect("decode bootstrap response");
        assert_eq!(decoded_bootstrap.status, "registered");

        let decoded_rotate = pb::RotateRoomKbroadResponse::decode(
            encode_rotate_room_kbroad_response("rotated", 42).as_slice(),
        )
        .expect("decode rotate response");
        assert_eq!(decoded_rotate.status, "rotated");
        assert_eq!(decoded_rotate.kbroad_generation, 42);

        let decoded_mutation = pb::RoomAdminMutationResponse::decode(
            encode_room_admin_mutation_response("granted", 7).as_slice(),
        )
        .expect("decode mutation response");
        assert_eq!(decoded_mutation.status, "granted");
        assert_eq!(decoded_mutation.admin_count, 7);

        let admin_pop_public_keys = vec![vec![0x11; 4], vec![0x22; 4]];
        let decoded_list = pb::ListRoomAdminsResponse::decode(
            encode_list_room_admins_response(admin_pop_public_keys.clone()).as_slice(),
        )
        .expect("decode list-admins response");
        assert_eq!(decoded_list.admin_pop_public_keys, admin_pop_public_keys);
    }

    #[test]
    fn validate_room_admin_requests_projects_required_fields() {
        let proof = pb::RoomAdminProof {
            pop_public_key: vec![0x11; ML_DSA_65_PUBLIC_KEY_BYTES],
            signature: vec![0x22; ML_DSA_65_SIGNATURE_BYTES],
        };

        let bootstrap = validate_bootstrap_room_request(pb::BootstrapRoomRequest {
            room_id: hex::encode(DEMO_GID),
            kbroad_public: vec![0x33; ML_KEM_768_PUBLIC_KEY_BYTES],
            admin_proof: Some(proof.clone()),
        })
        .expect("validate bootstrap");
        assert_eq!(bootstrap.kbroad_public.len(), ML_KEM_768_PUBLIC_KEY_BYTES);

        let mutation = validate_room_admin_mutation_request(pb::RoomAdminMutationRequest {
            room_id: hex::encode(DEMO_GID),
            target_pop_public_key: vec![0x44; ML_DSA_65_PUBLIC_KEY_BYTES],
            admin_proof: Some(proof.clone()),
        })
        .expect("validate mutation");
        assert_eq!(
            mutation.target_pop_public_key.len(),
            ML_DSA_65_PUBLIC_KEY_BYTES
        );

        let listed = validate_list_room_admins_request(pb::ListRoomAdminsRequest {
            room_id: hex::encode(DEMO_GID),
            admin_proof: Some(proof),
        })
        .expect("validate list admins");
        assert_eq!(listed.room_id, hex::encode(DEMO_GID));
    }

    #[test]
    fn validate_room_admin_requests_reject_missing_required_fields() {
        assert_eq!(
            validate_bootstrap_room_request(pb::BootstrapRoomRequest::default()),
            Err(RoomAdminRequestValidationError::MissingRoomId)
        );
        assert_eq!(
            validate_room_admin_mutation_request(pb::RoomAdminMutationRequest {
                room_id: hex::encode(DEMO_GID),
                target_pop_public_key: vec![0x11; ML_DSA_65_PUBLIC_KEY_BYTES - 1],
                admin_proof: None,
            }),
            Err(RoomAdminRequestValidationError::InvalidTargetPopPublicKeyLength)
        );
        assert_eq!(
            validate_list_room_admins_request(pb::ListRoomAdminsRequest {
                room_id: hex::encode(DEMO_GID),
                admin_proof: None,
            }),
            Err(RoomAdminRequestValidationError::MissingAdminProof)
        );
    }

    #[test]
    fn validate_expel_member_ticket_request_projects_required_fields() {
        let proof = pb::RoomAdminProof {
            pop_public_key: vec![0x11; ML_DSA_65_PUBLIC_KEY_BYTES],
            signature: vec![0x22; ML_DSA_65_SIGNATURE_BYTES],
        };
        let validated = validate_expel_member_ticket_request(pb::ExpelMemberTicketRequest {
            room_id: hex::encode(DEMO_GID),
            author_leaf_id: vec![0x33; 32],
            target_leaf_id: vec![0x44; 32],
            admin_proof: Some(proof),
        })
        .expect("validate expel request");

        assert_eq!(validated.author_leaf_id, [0x33; 32]);
        assert_eq!(validated.target_leaf_id, [0x44; 32]);
    }

    #[test]
    fn validate_expel_member_ticket_request_rejects_invalid_shape() {
        assert_eq!(
            validate_expel_member_ticket_request(pb::ExpelMemberTicketRequest::default()),
            Err(ExpelMemberTicketRequestValidationError::MissingRoomId)
        );
        assert_eq!(
            validate_expel_member_ticket_request(pb::ExpelMemberTicketRequest {
                room_id: hex::encode(DEMO_GID),
                author_leaf_id: vec![0x11; 31],
                target_leaf_id: vec![0x22; 32],
                admin_proof: None,
            }),
            Err(ExpelMemberTicketRequestValidationError::InvalidAuthorLeafId)
        );
        assert_eq!(
            validate_expel_member_ticket_request(pb::ExpelMemberTicketRequest {
                room_id: hex::encode(DEMO_GID),
                author_leaf_id: vec![0x11; 32],
                target_leaf_id: vec![0x11; 32],
                admin_proof: Some(pb::RoomAdminProof::default()),
            }),
            Err(ExpelMemberTicketRequestValidationError::MatchingLeafIds)
        );
    }

    #[test]
    fn encode_member_listing_responses_round_trip() {
        let members = vec![pb::Member {
            leaf_id: vec![0x11; 32],
            alias: Some("alice".to_string()),
            pop_public_key: Some(vec![0x22; 4]),
            join_date: Some(33),
            last_seen: Some(44),
        }];
        let root = [0x55; 32];

        let decoded_members = pb::MembersResponse::decode(
            encode_members_response(members.clone(), root, 7, 8).as_slice(),
        )
        .expect("decode members response");
        assert_eq!(decoded_members.members, members);
        assert_eq!(decoded_members.root, root.to_vec());
        assert_eq!(decoded_members.total_count, 7);
        assert_eq!(decoded_members.next_offset, 8);

        let decoded_search = pb::SearchMembersResponse::decode(
            encode_search_members_response(members.clone(), root, 9, 10).as_slice(),
        )
        .expect("decode search members response");
        assert_eq!(decoded_search.members, members);
        assert_eq!(decoded_search.root, root.to_vec());
        assert_eq!(decoded_search.total_count, 9);
        assert_eq!(decoded_search.next_offset, 10);
    }

    #[test]
    fn decode_barrier_helper_requests_project_fixed_width_fields() {
        let revoked =
            decode_barrier_resolve_revoked_leaves_request(pb::BarrierResolveRevokedLeavesRequest {
                room_id: hex::encode(DEMO_GID),
                revocation_roots_hash: vec![0x11; 32],
                page_offset: 12,
                max_entries: 13,
            })
            .expect("decode revoked helper request");
        assert_eq!(revoked.revocation_roots_hash, [0x11; 32]);
        assert_eq!(revoked.page_offset, 12);
        assert_eq!(revoked.max_entries, 13);

        let tree = decode_barrier_fetch_public_tree_request(pb::BarrierFetchPublicTreeRequest {
            room_id: hex::encode(DEMO_GID),
            kem_tree_hash_after: vec![0x21; 32],
            entry_offset: 22,
            max_entries: 23,
        })
        .expect("decode tree helper request");
        assert_eq!(tree.kem_tree_hash_after, [0x21; 32]);
        assert_eq!(tree.entry_offset, 22);
        assert_eq!(tree.max_entries, 23);

        let merge = decode_barrier_lookup_merge_acceptance_request(
            pb::BarrierLookupMergeAcceptanceRequest {
                room_id: hex::encode(DEMO_GID),
                pending_barrier_version: 31,
                pending_barrier_update_digest: vec![0x32; 32],
                pending_we_epoch_id: vec![0x33; 32],
            },
        )
        .expect("decode merge helper request");
        assert_eq!(merge.pending_barrier_version, 31);
        assert_eq!(merge.pending_barrier_update_digest, [0x32; 32]);
        assert_eq!(merge.pending_we_epoch_id, [0x33; 32]);
    }

    fn signed_identity_binding(
        alias: &str,
        pop_public_key: &[u8],
        secret_key: &dilithium5::SecretKey,
    ) -> pb::IdentityBinding {
        let message = {
            let message_data = (
                ByteBuf::from(alias.as_bytes().to_vec()),
                ByteBuf::from(pop_public_key.to_vec()),
            );
            let mut message = Vec::new();
            into_writer(&message_data, &mut message).expect("encode message");
            message
        };
        let signature = dilithium5::detached_sign(&message, secret_key);
        pb::IdentityBinding {
            alias: alias.to_string(),
            pop_public_key: pop_public_key.to_vec(),
            signature: signature.as_bytes().to_vec(),
        }
    }
}
