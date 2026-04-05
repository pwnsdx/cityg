use std::convert::TryInto;

use ciborium::ser::into_writer;
use cityg_api_schema::pb::{
    FsForwardLeapPolicy as PbFsForwardLeapPolicy, HistoryCommitment as PbHistoryCommitment,
    JoinTicketResponse, MergeAcceptanceStatus as PbMergeAcceptanceStatus, MergeTicketResponse,
};
use msphf_core::hash::h_l;
use pqcrypto_dilithium::dilithium5;
use serde::{Deserialize, Serialize};

use crate::{
    BarrierJoinOccupancyRecord, BarrierRevokedOccupancyRecord, EXPECTED_MSPHF_CRS_ID,
    EXPECTED_MSPHF_PARAMS_ID, EXPECTED_PROFILE_VERSION, EXPECTED_PROOF_MODE, EXPECTED_VRF_ID,
    Error, FsForwardLeapPolicy, FullVerificationWitness, GLOBAL_HISTORY_ATTESTATION_FINALITY_KIND,
    GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID, GlobalHistoryAttestation, HELPER_KIND_FETCH_PUBLIC_TREE,
    HELPER_KIND_JOIN_OCCUPANCIES_SINCE, HELPER_KIND_REVOKED_OCCUPANCIES,
    HelperCompletenessAttestation, HistoryAuthorityDescriptor, HistoryAuthorityExtension,
    HistoryCommitment, LOCAL_HISTORY_ATTESTATION_FINALITY_KIND,
    LOCAL_HISTORY_AUTHORITY_EXTENSION_ID, MAX_BARRIER_N_MAX, MergeAcceptanceStatus, SlotLease,
};

#[derive(Serialize, Deserialize)]
pub(crate) struct HistoryAuthorityDescriptorWire(
    #[serde(with = "serde_bytes")] pub(crate) Vec<u8>,
    #[serde(with = "serde_bytes")] pub(crate) Vec<u8>,
);

#[derive(Serialize, Deserialize)]
pub(crate) struct GlobalHistoryAttestationWire(
    #[serde(with = "serde_bytes")] pub(crate) Vec<u8>,
    #[serde(with = "serde_bytes")] pub(crate) Vec<u8>,
    #[serde(with = "serde_bytes")] pub(crate) Vec<u8>,
    #[serde(with = "serde_bytes")] pub(crate) Vec<u8>,
    #[serde(with = "serde_bytes")] pub(crate) Vec<u8>,
    pub(crate) u64,
    pub(crate) u64,
    #[serde(with = "serde_bytes")] pub(crate) Vec<u8>,
    #[serde(with = "serde_bytes")] pub(crate) Vec<u8>,
    pub(crate) String,
    #[serde(with = "serde_bytes")] pub(crate) Vec<u8>,
);

#[derive(Serialize, Deserialize)]
pub(crate) struct FullVerificationWitnessWire {
    #[serde(with = "serde_bytes")]
    pub(crate) scope_id: Vec<u8>,
    pub(crate) history_authority_extension: String,
    #[serde(with = "serde_bytes")]
    pub(crate) gid: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) history_view_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) history_commitment_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) prev_history_commitment_id: Vec<u8>,
    pub(crate) history_seq: u64,
    pub(crate) barrier_version: u64,
    #[serde(with = "serde_bytes")]
    pub(crate) kem_tree_hash_after: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) author_leaf_id: Vec<u8>,
    pub(crate) barrier_update_reason: u64,
    pub(crate) updater_slot_index: u64,
    pub(crate) updater_slot_generation: u64,
    #[serde(with = "serde_bytes")]
    pub(crate) barrier_update_digest: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) joins_digest: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) revoked_digest: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) deployment_profile_manifest_digest: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct JoinProvisioningArtifactWire {
    #[serde(with = "serde_bytes")]
    pub(crate) scope_id: Vec<u8>,
    pub(crate) history_authority_extension: String,
    #[serde(with = "serde_bytes")]
    pub(crate) gid: Vec<u8>,
    pub(crate) profile_version: String,
    #[serde(with = "serde_bytes")]
    pub(crate) leaf_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) history_view_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) history_commitment_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) prev_history_commitment_id: Vec<u8>,
    pub(crate) history_seq: u64,
    pub(crate) barrier_version: u64,
    pub(crate) slot_index: u64,
    pub(crate) slot_generation: u64,
    pub(crate) n_max: u64,
    pub(crate) max_barrier_update_bytes: u64,
    #[serde(with = "serde_bytes")]
    pub(crate) kem_tree_hash_after: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) current_predecessor_kem_tree_hash_after: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) join_finalize_auth_token: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) provisioning_nonce: Vec<u8>,
    pub(crate) provisioning_issued_at_ms: u64,
    pub(crate) provisioning_expires_at_ms: u64,
    pub(crate) fs_forward_leap_h: u64,
    pub(crate) fs_forward_leap_checkpoint_interval: u64,
    pub(crate) fs_forward_leap_slack_anchor: u64,
    pub(crate) fs_forward_leap_slack_first_device: u64,
    pub(crate) fs_forward_leap_slack_device: u64,
    pub(crate) last_accepted_ec: u64,
    #[serde(with = "serde_bytes")]
    pub(crate) signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct MergeTicketArtifactWire {
    #[serde(with = "serde_bytes")]
    pub(crate) scope_id: Vec<u8>,
    pub(crate) history_authority_extension: String,
    pub(crate) profile_version: String,
    #[serde(with = "serde_bytes")]
    pub(crate) gid: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) leaf_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) history_view_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) history_commitment_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) prev_history_commitment_id: Vec<u8>,
    pub(crate) history_seq: u64,
    pub(crate) barrier_version: u64,
    pub(crate) slot_index: u64,
    pub(crate) slot_generation: u64,
    pub(crate) n_max: u64,
    pub(crate) max_barrier_update_bytes: u64,
    #[serde(with = "serde_bytes")]
    pub(crate) kem_tree_hash_after: Vec<u8>,
    pub(crate) fs_forward_leap_h: u64,
    pub(crate) fs_forward_leap_checkpoint_interval: u64,
    pub(crate) fs_forward_leap_slack_anchor: u64,
    pub(crate) fs_forward_leap_slack_first_device: u64,
    pub(crate) fs_forward_leap_slack_device: u64,
    pub(crate) last_accepted_ec: u64,
    #[serde(with = "serde_bytes")]
    pub(crate) history_authority_descriptor: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) current_global_history_attestation: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) we_epoch_id: Vec<u8>,
    pub(crate) pivot_parity_cbor: Vec<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub(crate) witness_cbor: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) srx_cbor: Vec<u8>,
    pub(crate) proof_mode: String,
    pub(crate) vrf_id: String,
    pub(crate) policy_version: String,
    #[serde(with = "serde_bytes")]
    pub(crate) cat: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) parent_root: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) join_delta_root: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) revoked_since_root: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) revoked_root: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) tswe_salt_hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) pox_r_commit: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) kbroad_public: Vec<u8>,
    pub(crate) msphf_crs_id: String,
    pub(crate) msphf_params_id: String,
    pub(crate) fs_policy_version: String,
    pub(crate) fs_epoch_base_ts: u64,
    pub(crate) kbroad_generation: u64,
    #[serde(with = "serde_bytes")]
    pub(crate) signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct DeploymentProfileManifestWire {
    #[serde(with = "serde_bytes")]
    pub(crate) scope_id: Vec<u8>,
    pub(crate) history_authority_extension: String,
    #[serde(with = "serde_bytes")]
    pub(crate) gid: Vec<u8>,
    pub(crate) profile_version: String,
    pub(crate) n_max: u64,
    pub(crate) max_barrier_update_bytes: u64,
    pub(crate) fs_forward_leap_h: u64,
    pub(crate) fs_forward_leap_checkpoint_interval: u64,
    pub(crate) fs_forward_leap_slack_anchor: u64,
    pub(crate) fs_forward_leap_slack_first_device: u64,
    pub(crate) fs_forward_leap_slack_device: u64,
    #[serde(with = "serde_bytes")]
    pub(crate) signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct HelperCompletenessAttestationWire(
    #[serde(with = "serde_bytes")] pub(crate) Vec<u8>,
    pub(crate) String,
    #[serde(with = "serde_bytes")] pub(crate) Vec<u8>,
);

#[derive(Serialize)]
pub(crate) struct GlobalHistoryAttestationSignedPayload<'a>(
    pub(crate) &'static str,
    #[serde(with = "serde_bytes")] pub(crate) &'a [u8; 32],
    #[serde(with = "serde_bytes")] pub(crate) &'a [u8; 32],
    #[serde(with = "serde_bytes")] pub(crate) &'a [u8; 32],
    #[serde(with = "serde_bytes")] pub(crate) &'a [u8; 32],
    #[serde(with = "serde_bytes")] pub(crate) &'a [u8; 32],
    pub(crate) u64,
    pub(crate) u64,
    #[serde(with = "serde_bytes")] pub(crate) &'a [u8; 32],
    #[serde(with = "serde_bytes")] pub(crate) &'a [u8; 32],
    pub(crate) &'a str,
);

#[derive(Serialize)]
pub(crate) struct JoinProvisioningArtifactSignedPayload<'a> {
    pub(crate) label: &'static str,
    #[serde(with = "serde_bytes")]
    pub(crate) scope_id: &'a [u8; 32],
    pub(crate) history_authority_extension: &'a str,
    #[serde(with = "serde_bytes")]
    pub(crate) gid: &'a [u8; 32],
    pub(crate) profile_version: &'a str,
    #[serde(with = "serde_bytes")]
    pub(crate) leaf_id: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) history_view_id: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) history_commitment_id: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) prev_history_commitment_id: &'a [u8; 32],
    pub(crate) history_seq: u64,
    pub(crate) barrier_version: u64,
    pub(crate) slot_index: u64,
    pub(crate) slot_generation: u64,
    pub(crate) n_max: u64,
    pub(crate) max_barrier_update_bytes: u64,
    #[serde(with = "serde_bytes")]
    pub(crate) kem_tree_hash_after: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) current_predecessor_kem_tree_hash_after: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) join_finalize_auth_token: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) provisioning_nonce: &'a [u8; 32],
    pub(crate) provisioning_issued_at_ms: u64,
    pub(crate) provisioning_expires_at_ms: u64,
    pub(crate) fs_forward_leap_h: u64,
    pub(crate) fs_forward_leap_checkpoint_interval: u64,
    pub(crate) fs_forward_leap_slack_anchor: u64,
    pub(crate) fs_forward_leap_slack_first_device: u64,
    pub(crate) fs_forward_leap_slack_device: u64,
    pub(crate) last_accepted_ec: u64,
    #[serde(with = "serde_bytes")]
    pub(crate) history_authority_descriptor: &'a [u8],
    #[serde(with = "serde_bytes")]
    pub(crate) current_global_history_attestation: &'a [u8],
    #[serde(with = "serde_bytes")]
    pub(crate) current_join_occupancies_completeness_attestation: &'a [u8],
    #[serde(with = "serde_bytes")]
    pub(crate) current_revoked_occupancies_completeness_attestation: &'a [u8],
    #[serde(with = "serde_bytes")]
    pub(crate) current_barrier_update: &'a [u8],
    pub(crate) current_join_occupancies: &'a [BarrierJoinOccupancyRecord],
    pub(crate) current_revoked_occupancies: &'a [BarrierRevokedOccupancyRecord],
}

#[derive(Serialize)]
pub(crate) struct MergeTicketArtifactSignedPayload<'a> {
    pub(crate) label: &'static str,
    #[serde(with = "serde_bytes")]
    pub(crate) scope_id: &'a [u8; 32],
    pub(crate) history_authority_extension: &'a str,
    pub(crate) profile_version: &'a str,
    #[serde(with = "serde_bytes")]
    pub(crate) gid: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) leaf_id: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) history_view_id: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) history_commitment_id: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) prev_history_commitment_id: &'a [u8; 32],
    pub(crate) history_seq: u64,
    pub(crate) barrier_version: u64,
    pub(crate) slot_index: u64,
    pub(crate) slot_generation: u64,
    pub(crate) n_max: u64,
    pub(crate) max_barrier_update_bytes: u64,
    #[serde(with = "serde_bytes")]
    pub(crate) kem_tree_hash_after: &'a [u8; 32],
    pub(crate) fs_forward_leap_h: u64,
    pub(crate) fs_forward_leap_checkpoint_interval: u64,
    pub(crate) fs_forward_leap_slack_anchor: u64,
    pub(crate) fs_forward_leap_slack_first_device: u64,
    pub(crate) fs_forward_leap_slack_device: u64,
    pub(crate) last_accepted_ec: u64,
    #[serde(with = "serde_bytes")]
    pub(crate) history_authority_descriptor: &'a [u8],
    #[serde(with = "serde_bytes")]
    pub(crate) current_global_history_attestation: &'a [u8],
    #[serde(with = "serde_bytes")]
    pub(crate) we_epoch_id: &'a [u8; 32],
    pub(crate) pivot_parity_cbor: &'a [Vec<u8>],
    #[serde(with = "serde_bytes")]
    pub(crate) witness_cbor: &'a [u8],
    #[serde(with = "serde_bytes")]
    pub(crate) srx_cbor: &'a [u8],
    pub(crate) proof_mode: &'a str,
    pub(crate) vrf_id: &'a str,
    pub(crate) policy_version: &'a str,
    #[serde(with = "serde_bytes")]
    pub(crate) cat: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) parent_root: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) join_delta_root: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) revoked_since_root: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) revoked_root: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) tswe_salt_hash: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) pox_r_commit: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) kbroad_public: &'a [u8],
    pub(crate) msphf_crs_id: &'a str,
    pub(crate) msphf_params_id: &'a str,
    pub(crate) fs_policy_version: &'a str,
    pub(crate) fs_epoch_base_ts: u64,
    pub(crate) kbroad_generation: u64,
}

#[derive(Serialize)]
pub(crate) struct DeploymentProfileManifestSignedPayload<'a> {
    pub(crate) label: &'static str,
    #[serde(with = "serde_bytes")]
    pub(crate) scope_id: &'a [u8; 32],
    pub(crate) history_authority_extension: &'a str,
    #[serde(with = "serde_bytes")]
    pub(crate) gid: &'a [u8; 32],
    pub(crate) profile_version: &'a str,
    pub(crate) n_max: u64,
    pub(crate) max_barrier_update_bytes: u64,
    pub(crate) fs_forward_leap_h: u64,
    pub(crate) fs_forward_leap_checkpoint_interval: u64,
    pub(crate) fs_forward_leap_slack_anchor: u64,
    pub(crate) fs_forward_leap_slack_first_device: u64,
    pub(crate) fs_forward_leap_slack_device: u64,
}

#[derive(Serialize)]
pub(crate) struct FullVerificationWitnessSignedPayload<'a> {
    pub(crate) label: &'static str,
    #[serde(with = "serde_bytes")]
    pub(crate) scope_id: &'a [u8; 32],
    pub(crate) history_authority_extension: &'a str,
    #[serde(with = "serde_bytes")]
    pub(crate) gid: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) history_view_id: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) history_commitment_id: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) prev_history_commitment_id: &'a [u8; 32],
    pub(crate) history_seq: u64,
    pub(crate) barrier_version: u64,
    #[serde(with = "serde_bytes")]
    pub(crate) kem_tree_hash_after: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) author_leaf_id: &'a [u8; 32],
    pub(crate) barrier_update_reason: u64,
    pub(crate) updater_slot_index: u64,
    pub(crate) updater_slot_generation: u64,
    #[serde(with = "serde_bytes")]
    pub(crate) barrier_update_digest: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) joins_digest: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) revoked_digest: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) deployment_profile_manifest_digest: &'a [u8; 32],
}

#[derive(Serialize)]
pub(crate) struct HelperCompletenessSignedPayload<'a, T> {
    pub(crate) label: &'static str,
    #[serde(with = "serde_bytes")]
    pub(crate) scope_id: &'a [u8; 32],
    pub(crate) helper_kind: &'a str,
    #[serde(with = "serde_bytes")]
    pub(crate) history_view_id: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    pub(crate) history_commitment_id: &'a [u8; 32],
    pub(crate) page_offset: u32,
    pub(crate) total_entries: u32,
    pub(crate) selector: T,
}

#[derive(Serialize)]
pub(crate) struct RevokedLeavesSelector<'a> {
    #[serde(with = "serde_bytes")]
    pub(crate) revocation_roots_hash: &'a [u8; 32],
    pub(crate) records: &'a [BarrierRevokedOccupancyRecord],
}

#[derive(Serialize)]
pub(crate) struct JoinsSinceSelector<'a> {
    pub(crate) prev_barrier_version: u64,
    pub(crate) records: &'a [BarrierJoinOccupancyRecord],
}

#[derive(Serialize)]
pub(crate) struct FetchPublicTreeSelector<'a> {
    #[serde(with = "serde_bytes")]
    pub(crate) kem_tree_hash_after: &'a [u8; 32],
    pub(crate) pk_entries: &'a [Vec<u8>],
}

pub(crate) struct MergeTicketArtifactContext<'a> {
    pub(crate) requested_leaf_id: &'a [u8; 32],
    pub(crate) response: &'a MergeTicketResponse,
    pub(crate) slot_lease: SlotLease,
    pub(crate) current_history_commitment: &'a HistoryCommitment,
    pub(crate) current_global_history_attestation: &'a GlobalHistoryAttestation,
    pub(crate) fs_forward_leap_policy: &'a FsForwardLeapPolicy,
}

pub(crate) struct DeploymentProfileManifestContext<'a> {
    pub(crate) gid: &'a [u8; 32],
    pub(crate) profile_version: &'a str,
    pub(crate) n_max: u64,
    pub(crate) max_barrier_update_bytes: u64,
    pub(crate) fs_forward_leap_policy: &'a FsForwardLeapPolicy,
    pub(crate) context: &'static str,
}

pub(crate) fn array32(bytes: &[u8]) -> Result<[u8; 32], Error> {
    bytes
        .try_into()
        .map_err(|_| Error::Parse("invalid 32-byte field".to_string()))
}

pub(crate) fn parse_room_id_gid(room_id: &str) -> Result<[u8; 32], Error> {
    if room_id.len() != 64 {
        return Err(Error::Parse(
            "room_id must be 64 hex characters".to_string(),
        ));
    }
    let mut gid = [0u8; 32];
    for (index, chunk) in room_id.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk)
            .map_err(|_| Error::Parse("room_id must be 64 hex characters".to_string()))?;
        gid[index] = u8::from_str_radix(pair, 16)
            .map_err(|_| Error::Parse("room_id must be 64 hex characters".to_string()))?;
    }
    Ok(gid)
}

pub(crate) fn optional_array32(bytes: Option<Vec<u8>>) -> Result<Option<[u8; 32]>, Error> {
    bytes.as_deref().map(array32).transpose()
}

pub(crate) fn parse_history_commitment(
    history_view_id: [u8; 32],
    commitment: Option<PbHistoryCommitment>,
) -> Result<HistoryCommitment, Error> {
    let commitment =
        commitment.ok_or_else(|| Error::Parse("missing history_commitment".to_string()))?;
    let commitment_view_id = array32(&commitment.history_view_id)?;
    if commitment_view_id != history_view_id {
        return Err(Error::Parse(
            "history_commitment.history_view_id mismatch".to_string(),
        ));
    }
    Ok(HistoryCommitment {
        history_view_id,
        history_commitment_id: array32(&commitment.history_commitment_id)?,
        prev_history_commitment_id: array32(&commitment.prev_history_commitment_id)?,
        history_seq: commitment.history_seq,
    })
}

pub(crate) fn pb_history_commitment(commitment: HistoryCommitment) -> PbHistoryCommitment {
    PbHistoryCommitment {
        history_view_id: commitment.history_view_id.to_vec(),
        history_commitment_id: commitment.history_commitment_id.to_vec(),
        prev_history_commitment_id: commitment.prev_history_commitment_id.to_vec(),
        history_seq: commitment.history_seq,
    }
}

pub(crate) fn encode_cbor_det<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    into_writer(value, &mut bytes)
        .map_err(|err| Error::Parse(format!("encode deterministic cbor: {err}")))?;
    Ok(bytes)
}

pub(crate) fn decode_cbor_det<T>(label: &'static str, raw: &[u8]) -> Result<T, Error>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let decoded: T = ciborium::de::from_reader(raw)
        .map_err(|err| Error::Parse(format!("parse {label}: {err}")))?;
    let canonical = encode_cbor_det(&decoded)?;
    if canonical.as_slice() != raw {
        return Err(Error::Parse(format!("non-canonical {label}")));
    }
    Ok(decoded)
}

pub(crate) fn verify_ml_dsa_signature(
    message: &[u8],
    public_key: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let pk = <dilithium5::PublicKey as pqcrypto_traits::sign::PublicKey>::from_bytes(public_key)
        .map_err(|_| Error::Parse("invalid history authority public key".to_string()))?;
    let sig =
        <dilithium5::DetachedSignature as pqcrypto_traits::sign::DetachedSignature>::from_bytes(
            signature,
        )
        .map_err(|_| Error::Parse("invalid history authority signature".to_string()))?;
    dilithium5::verify_detached_signature(&sig, message, &pk)
        .map_err(|_| Error::Parse("history authority signature verification failed".to_string()))
}

pub(crate) fn compute_full_verification_barrier_update_digest(
    barrier_update: &[u8],
) -> Result<[u8; 32], Error> {
    #[derive(Serialize)]
    struct Preimage<'a> {
        #[serde(with = "serde_bytes")]
        barrier_update: &'a [u8],
    }
    h_l(
        "cityg/full-verification-witness/barrier-update",
        &Preimage { barrier_update },
    )
    .map_err(|err| Error::Parse(format!("compute barrier_update digest: {err}")))
}

pub(crate) fn compute_full_verification_joins_digest(
    prev_barrier_version: u64,
    join_records: &[BarrierJoinOccupancyRecord],
) -> Result<[u8; 32], Error> {
    #[derive(Serialize)]
    struct Preimage<'a> {
        prev_barrier_version: u64,
        records: &'a [BarrierJoinOccupancyRecord],
    }
    h_l(
        "cityg/full-verification-witness/joins",
        &Preimage {
            prev_barrier_version,
            records: join_records,
        },
    )
    .map_err(|err| Error::Parse(format!("compute joins digest: {err}")))
}

pub(crate) fn compute_full_verification_revoked_digest(
    revocation_roots_hash: &[u8; 32],
    revoked_records: &[BarrierRevokedOccupancyRecord],
) -> Result<[u8; 32], Error> {
    #[derive(Serialize)]
    struct Preimage<'a> {
        #[serde(with = "serde_bytes")]
        revocation_roots_hash: &'a [u8; 32],
        records: &'a [BarrierRevokedOccupancyRecord],
    }
    h_l(
        "cityg/full-verification-witness/revoked",
        &Preimage {
            revocation_roots_hash,
            records: revoked_records,
        },
    )
    .map_err(|err| Error::Parse(format!("compute revoked digest: {err}")))
}

pub(crate) fn compute_full_verification_deployment_manifest_digest(
    deployment_profile_manifest: &[u8],
) -> Result<[u8; 32], Error> {
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
    .map_err(|err| Error::Parse(format!("compute deployment manifest digest: {err}")))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_full_verification_witness(
    raw: &[u8],
    authority: &HistoryAuthorityDescriptor,
    history_authority_extension: HistoryAuthorityExtension,
    gid: &[u8; 32],
    current_history_commitment: &HistoryCommitment,
    barrier_version: u64,
    kem_tree_hash_after: &[u8; 32],
    author_leaf_id: &[u8; 32],
    barrier_update_reason: u64,
    updater_slot_lease: SlotLease,
    barrier_update: &[u8],
    joins_prev_barrier_version: u64,
    join_records: &[BarrierJoinOccupancyRecord],
    revocation_roots_hash: &[u8; 32],
    revoked_records: &[BarrierRevokedOccupancyRecord],
    deployment_profile_manifest: &[u8],
) -> Result<FullVerificationWitness, Error> {
    let witness: FullVerificationWitnessWire = decode_cbor_det("full verification witness", raw)?;
    let parsed = FullVerificationWitness {
        scope_id: array32(&witness.scope_id)?,
        history_authority_extension: witness.history_authority_extension.clone(),
        gid: array32(&witness.gid)?,
        history_commitment: HistoryCommitment {
            history_view_id: array32(&witness.history_view_id)?,
            history_commitment_id: array32(&witness.history_commitment_id)?,
            prev_history_commitment_id: array32(&witness.prev_history_commitment_id)?,
            history_seq: witness.history_seq,
        },
        barrier_version: witness.barrier_version,
        kem_tree_hash_after: array32(&witness.kem_tree_hash_after)?,
        author_leaf_id: array32(&witness.author_leaf_id)?,
        barrier_update_reason: witness.barrier_update_reason,
        updater_slot_lease: SlotLease {
            slot_index: witness.updater_slot_index,
            slot_generation: witness.updater_slot_generation,
        },
        barrier_update_digest: array32(&witness.barrier_update_digest)?,
        joins_digest: array32(&witness.joins_digest)?,
        revoked_digest: array32(&witness.revoked_digest)?,
        deployment_profile_manifest_digest: array32(&witness.deployment_profile_manifest_digest)?,
        signature: witness.signature,
    };
    if parsed.scope_id != authority.scope_id
        || parsed.history_authority_extension != history_authority_extension.as_str()
        || parsed.gid != *gid
        || parsed.history_commitment != *current_history_commitment
        || parsed.barrier_version != barrier_version
        || parsed.kem_tree_hash_after != *kem_tree_hash_after
        || parsed.author_leaf_id != *author_leaf_id
        || parsed.barrier_update_reason != barrier_update_reason
        || parsed.updater_slot_lease != updater_slot_lease
    {
        return Err(Error::Parse(
            "full verification witness fields mismatch".to_string(),
        ));
    }
    let expected_barrier_update_digest =
        compute_full_verification_barrier_update_digest(barrier_update)?;
    let expected_joins_digest =
        compute_full_verification_joins_digest(joins_prev_barrier_version, join_records)?;
    let expected_revoked_digest =
        compute_full_verification_revoked_digest(revocation_roots_hash, revoked_records)?;
    let expected_manifest_digest =
        compute_full_verification_deployment_manifest_digest(deployment_profile_manifest)?;
    if parsed.barrier_update_digest != expected_barrier_update_digest {
        return Err(Error::Parse(
            "full verification witness barrier_update digest mismatch".to_string(),
        ));
    }
    if parsed.joins_digest != expected_joins_digest {
        return Err(Error::Parse(
            "full verification witness joins digest mismatch".to_string(),
        ));
    }
    if parsed.revoked_digest != expected_revoked_digest {
        return Err(Error::Parse(
            "full verification witness revoked digest mismatch".to_string(),
        ));
    }
    if parsed.deployment_profile_manifest_digest != expected_manifest_digest {
        return Err(Error::Parse(
            "full verification witness deployment_profile_manifest digest mismatch".to_string(),
        ));
    }
    let payload = encode_cbor_det(&FullVerificationWitnessSignedPayload {
        label: "cityg/full-verification-witness-v1",
        scope_id: &parsed.scope_id,
        history_authority_extension: history_authority_extension.as_str(),
        gid,
        history_view_id: &current_history_commitment.history_view_id,
        history_commitment_id: &current_history_commitment.history_commitment_id,
        prev_history_commitment_id: &current_history_commitment.prev_history_commitment_id,
        history_seq: current_history_commitment.history_seq,
        barrier_version,
        kem_tree_hash_after,
        author_leaf_id,
        barrier_update_reason,
        updater_slot_index: updater_slot_lease.slot_index,
        updater_slot_generation: updater_slot_lease.slot_generation,
        barrier_update_digest: &expected_barrier_update_digest,
        joins_digest: &expected_joins_digest,
        revoked_digest: &expected_revoked_digest,
        deployment_profile_manifest_digest: &expected_manifest_digest,
    })?;
    verify_ml_dsa_signature(
        payload.as_slice(),
        authority.public_key.as_slice(),
        parsed.signature.as_slice(),
    )?;
    Ok(parsed)
}

pub(crate) fn verify_join_provisioning_artifact(
    raw: &[u8],
    authority: &HistoryAuthorityDescriptor,
    history_authority_extension: HistoryAuthorityExtension,
    response: &JoinTicketResponse,
    current_history_commitment: &HistoryCommitment,
    fs_forward_leap_policy: &FsForwardLeapPolicy,
) -> Result<(), Error> {
    if raw.is_empty() {
        return Err(Error::Parse(
            "join ticket missing provisioning_artifact".to_string(),
        ));
    }
    let artifact: JoinProvisioningArtifactWire =
        decode_cbor_det("join provisioning artifact", raw)?;
    if array32(&artifact.scope_id)? != authority.scope_id {
        return Err(Error::Parse(
            "join provisioning artifact scope_id mismatch".to_string(),
        ));
    }
    if artifact.history_authority_extension != history_authority_extension.as_str() {
        return Err(Error::Parse(
            "join provisioning artifact history_authority_extension mismatch".to_string(),
        ));
    }
    if array32(&artifact.gid)? != array32(&response.gid)? {
        return Err(Error::Parse(
            "join provisioning artifact gid mismatch".to_string(),
        ));
    }
    if artifact.profile_version != response.profile_version {
        return Err(Error::Parse(
            "join provisioning artifact profile_version mismatch".to_string(),
        ));
    }
    if array32(&artifact.leaf_id)? != array32(&response.leaf_id)? {
        return Err(Error::Parse(
            "join provisioning artifact leaf_id mismatch".to_string(),
        ));
    }
    if array32(&artifact.history_view_id)? != current_history_commitment.history_view_id
        || array32(&artifact.history_commitment_id)?
            != current_history_commitment.history_commitment_id
        || array32(&artifact.prev_history_commitment_id)?
            != current_history_commitment.prev_history_commitment_id
        || artifact.history_seq != current_history_commitment.history_seq
    {
        return Err(Error::Parse(
            "join provisioning artifact history_commitment mismatch".to_string(),
        ));
    }
    if artifact.barrier_version != response.barrier_version
        || artifact.slot_index != response.slot_index
        || artifact.slot_generation != response.slot_generation
        || artifact.n_max != response.n_max
        || artifact.max_barrier_update_bytes != response.max_barrier_update_bytes
        || array32(&artifact.kem_tree_hash_after)? != array32(&response.kem_tree_hash_after)?
    {
        return Err(Error::Parse(
            "join provisioning artifact barrier state mismatch".to_string(),
        ));
    }
    let expected_predecessor = if response.current_predecessor_kem_tree_hash_after.is_empty() {
        [0u8; 32]
    } else {
        array32(&response.current_predecessor_kem_tree_hash_after)?
    };
    if array32(&artifact.current_predecessor_kem_tree_hash_after)? != expected_predecessor {
        return Err(Error::Parse(
            "join provisioning artifact predecessor hash mismatch".to_string(),
        ));
    }
    if array32(&artifact.join_finalize_auth_token)? != array32(&response.join_finalize_auth_token)?
        || array32(&artifact.provisioning_nonce)? != array32(&response.provisioning_nonce)?
        || artifact.provisioning_issued_at_ms != response.provisioning_issued_at_ms
        || artifact.provisioning_expires_at_ms != response.provisioning_expires_at_ms
    {
        return Err(Error::Parse(
            "join provisioning artifact token or expiry mismatch".to_string(),
        ));
    }
    if artifact.fs_forward_leap_h != fs_forward_leap_policy.h
        || artifact.fs_forward_leap_checkpoint_interval
            != fs_forward_leap_policy.checkpoint_interval
        || artifact.fs_forward_leap_slack_anchor != fs_forward_leap_policy.slack_anchor
        || artifact.fs_forward_leap_slack_first_device != fs_forward_leap_policy.slack_first_device
        || artifact.fs_forward_leap_slack_device != fs_forward_leap_policy.slack_device
        || artifact.last_accepted_ec != response.last_accepted_ec
    {
        return Err(Error::Parse(
            "join provisioning artifact fs policy mismatch".to_string(),
        ));
    }
    let gid = array32(&response.gid)?;
    let leaf_id = array32(&response.leaf_id)?;
    let kem_tree_hash_after = array32(&response.kem_tree_hash_after)?;
    let join_finalize_auth_token = array32(&response.join_finalize_auth_token)?;
    let provisioning_nonce = array32(&response.provisioning_nonce)?;
    let join_records = response
        .current_join_occupancies
        .iter()
        .map(|record| BarrierJoinOccupancyRecord {
            device_pk: record.device_pk.clone(),
            leaf_index: record.slot_index,
            slot_generation: record.slot_generation,
            ek_leaf: record.ek_leaf.clone(),
        })
        .collect::<Vec<_>>();
    let revoked_records = response
        .current_revoked_occupancies
        .iter()
        .map(|record| BarrierRevokedOccupancyRecord {
            leaf_index: record.slot_index,
            slot_generation: record.slot_generation,
        })
        .collect::<Vec<_>>();
    let payload = encode_cbor_det(&JoinProvisioningArtifactSignedPayload {
        label: "cityg/join-provisioning-artifact-v2",
        scope_id: &authority.scope_id,
        history_authority_extension: history_authority_extension.as_str(),
        gid: &gid,
        profile_version: response.profile_version.as_str(),
        leaf_id: &leaf_id,
        history_view_id: &current_history_commitment.history_view_id,
        history_commitment_id: &current_history_commitment.history_commitment_id,
        prev_history_commitment_id: &current_history_commitment.prev_history_commitment_id,
        history_seq: current_history_commitment.history_seq,
        barrier_version: response.barrier_version,
        slot_index: response.slot_index,
        slot_generation: response.slot_generation,
        n_max: response.n_max,
        max_barrier_update_bytes: response.max_barrier_update_bytes,
        kem_tree_hash_after: &kem_tree_hash_after,
        current_predecessor_kem_tree_hash_after: &expected_predecessor,
        join_finalize_auth_token: &join_finalize_auth_token,
        provisioning_nonce: &provisioning_nonce,
        provisioning_issued_at_ms: response.provisioning_issued_at_ms,
        provisioning_expires_at_ms: response.provisioning_expires_at_ms,
        fs_forward_leap_h: fs_forward_leap_policy.h,
        fs_forward_leap_checkpoint_interval: fs_forward_leap_policy.checkpoint_interval,
        fs_forward_leap_slack_anchor: fs_forward_leap_policy.slack_anchor,
        fs_forward_leap_slack_first_device: fs_forward_leap_policy.slack_first_device,
        fs_forward_leap_slack_device: fs_forward_leap_policy.slack_device,
        last_accepted_ec: response.last_accepted_ec,
        history_authority_descriptor: response.history_authority_descriptor.as_slice(),
        current_global_history_attestation: response.current_global_history_attestation.as_slice(),
        current_join_occupancies_completeness_attestation: response
            .current_join_occupancies_completeness_attestation
            .as_slice(),
        current_revoked_occupancies_completeness_attestation: response
            .current_revoked_occupancies_completeness_attestation
            .as_slice(),
        current_barrier_update: response.current_barrier_update.as_slice(),
        current_join_occupancies: join_records.as_slice(),
        current_revoked_occupancies: revoked_records.as_slice(),
    })?;
    verify_ml_dsa_signature(
        payload.as_slice(),
        authority.public_key.as_slice(),
        artifact.signature.as_slice(),
    )
}

pub(crate) fn verify_merge_ticket_artifact(
    raw: &[u8],
    authority: &HistoryAuthorityDescriptor,
    history_authority_extension: HistoryAuthorityExtension,
    context: MergeTicketArtifactContext<'_>,
) -> Result<(), Error> {
    let MergeTicketArtifactContext {
        requested_leaf_id,
        response,
        slot_lease,
        current_history_commitment,
        current_global_history_attestation,
        fs_forward_leap_policy,
    } = context;
    if raw.is_empty() {
        return Err(Error::Parse(
            "merge ticket missing merge_ticket_artifact".to_string(),
        ));
    }
    let artifact: MergeTicketArtifactWire = decode_cbor_det("merge ticket artifact", raw)?;
    if array32(&artifact.scope_id)? != authority.scope_id {
        return Err(Error::Parse(
            "merge ticket artifact scope_id mismatch".to_string(),
        ));
    }
    if artifact.history_authority_extension != history_authority_extension.as_str() {
        return Err(Error::Parse(
            "merge ticket artifact history_authority_extension mismatch".to_string(),
        ));
    }
    if artifact.profile_version != response.profile_version {
        return Err(Error::Parse(
            "merge ticket artifact profile_version mismatch".to_string(),
        ));
    }
    if array32(&artifact.gid)? != current_global_history_attestation.gid {
        return Err(Error::Parse(
            "merge ticket artifact gid mismatch".to_string(),
        ));
    }
    if array32(&artifact.leaf_id)? != *requested_leaf_id {
        return Err(Error::Parse(
            "merge ticket artifact leaf_id mismatch".to_string(),
        ));
    }
    if array32(&artifact.history_view_id)? != current_history_commitment.history_view_id
        || array32(&artifact.history_commitment_id)?
            != current_history_commitment.history_commitment_id
        || array32(&artifact.prev_history_commitment_id)?
            != current_history_commitment.prev_history_commitment_id
        || artifact.history_seq != current_history_commitment.history_seq
    {
        return Err(Error::Parse(
            "merge ticket artifact history_commitment mismatch".to_string(),
        ));
    }
    if artifact.barrier_version != response.barrier_version
        || artifact.slot_index != slot_lease.slot_index
        || artifact.slot_generation != slot_lease.slot_generation
        || artifact.n_max != response.n_max
        || artifact.max_barrier_update_bytes != response.max_barrier_update_bytes
        || array32(&artifact.kem_tree_hash_after)? != array32(&response.kem_tree_hash_after)?
    {
        return Err(Error::Parse(
            "merge ticket artifact barrier state mismatch".to_string(),
        ));
    }
    if artifact.fs_forward_leap_h != fs_forward_leap_policy.h
        || artifact.fs_forward_leap_checkpoint_interval
            != fs_forward_leap_policy.checkpoint_interval
        || artifact.fs_forward_leap_slack_anchor != fs_forward_leap_policy.slack_anchor
        || artifact.fs_forward_leap_slack_first_device != fs_forward_leap_policy.slack_first_device
        || artifact.fs_forward_leap_slack_device != fs_forward_leap_policy.slack_device
        || artifact.last_accepted_ec != response.last_accepted_ec
    {
        return Err(Error::Parse(
            "merge ticket artifact fs policy mismatch".to_string(),
        ));
    }
    if artifact.history_authority_descriptor != response.history_authority_descriptor
        || artifact.current_global_history_attestation
            != response.current_global_history_attestation
        || artifact.we_epoch_id != response.we_epoch_id
        || artifact.pivot_parity_cbor != response.pivot_parity_cbor
        || artifact.witness_cbor != response.witness_cbor
        || artifact.srx_cbor != response.srx_cbor
        || artifact.proof_mode != response.proof_mode
        || artifact.vrf_id != response.vrf_id
        || artifact.policy_version != response.policy_version
        || artifact.cat != response.cat
        || artifact.parent_root != response.parent_root
        || artifact.join_delta_root != response.join_delta_root
        || artifact.revoked_since_root != response.revoked_since_root
        || artifact.revoked_root != response.revoked_root
        || artifact.tswe_salt_hash != response.tswe_salt_hash
        || artifact.pox_r_commit != response.pox_r_commit
        || artifact.kbroad_public != response.kbroad_public
        || artifact.msphf_crs_id != response.msphf_crs_id
        || artifact.msphf_params_id != response.msphf_params_id
        || artifact.fs_policy_version != response.fs_policy_version
        || artifact.fs_epoch_base_ts != response.fs_epoch_base_ts
        || artifact.kbroad_generation != response.kbroad_generation
    {
        return Err(Error::Parse(
            "merge ticket artifact response field mismatch".to_string(),
        ));
    }
    let gid = current_global_history_attestation.gid;
    let leaf_id = array32(&artifact.leaf_id)?;
    let we_epoch_id = array32(&response.we_epoch_id)?;
    let kem_tree_hash_after = array32(&response.kem_tree_hash_after)?;
    let cat = array32(&response.cat)?;
    let parent_root = array32(&response.parent_root)?;
    let join_delta_root = array32(&response.join_delta_root)?;
    let revoked_since_root = array32(&response.revoked_since_root)?;
    let revoked_root = array32(&response.revoked_root)?;
    let tswe_salt_hash = array32(&response.tswe_salt_hash)?;
    let pox_r_commit = array32(&response.pox_r_commit)?;
    let payload = encode_cbor_det(&MergeTicketArtifactSignedPayload {
        label: "cityg/merge-ticket-artifact-v2",
        scope_id: &authority.scope_id,
        history_authority_extension: history_authority_extension.as_str(),
        profile_version: response.profile_version.as_str(),
        gid: &gid,
        leaf_id: &leaf_id,
        history_view_id: &current_history_commitment.history_view_id,
        history_commitment_id: &current_history_commitment.history_commitment_id,
        prev_history_commitment_id: &current_history_commitment.prev_history_commitment_id,
        history_seq: current_history_commitment.history_seq,
        barrier_version: response.barrier_version,
        slot_index: response.slot_index,
        slot_generation: response.slot_generation,
        n_max: response.n_max,
        max_barrier_update_bytes: response.max_barrier_update_bytes,
        kem_tree_hash_after: &kem_tree_hash_after,
        fs_forward_leap_h: fs_forward_leap_policy.h,
        fs_forward_leap_checkpoint_interval: fs_forward_leap_policy.checkpoint_interval,
        fs_forward_leap_slack_anchor: fs_forward_leap_policy.slack_anchor,
        fs_forward_leap_slack_first_device: fs_forward_leap_policy.slack_first_device,
        fs_forward_leap_slack_device: fs_forward_leap_policy.slack_device,
        last_accepted_ec: response.last_accepted_ec,
        history_authority_descriptor: response.history_authority_descriptor.as_slice(),
        current_global_history_attestation: response.current_global_history_attestation.as_slice(),
        we_epoch_id: &we_epoch_id,
        pivot_parity_cbor: response.pivot_parity_cbor.as_slice(),
        witness_cbor: response.witness_cbor.as_slice(),
        srx_cbor: response.srx_cbor.as_slice(),
        proof_mode: response.proof_mode.as_str(),
        vrf_id: response.vrf_id.as_str(),
        policy_version: response.policy_version.as_str(),
        cat: &cat,
        parent_root: &parent_root,
        join_delta_root: &join_delta_root,
        revoked_since_root: &revoked_since_root,
        revoked_root: &revoked_root,
        tswe_salt_hash: &tswe_salt_hash,
        pox_r_commit: &pox_r_commit,
        kbroad_public: response.kbroad_public.as_slice(),
        msphf_crs_id: response.msphf_crs_id.as_str(),
        msphf_params_id: response.msphf_params_id.as_str(),
        fs_policy_version: response.fs_policy_version.as_str(),
        fs_epoch_base_ts: response.fs_epoch_base_ts,
        kbroad_generation: response.kbroad_generation,
    })?;
    verify_ml_dsa_signature(
        payload.as_slice(),
        authority.public_key.as_slice(),
        artifact.signature.as_slice(),
    )
}

pub(crate) fn verify_deployment_profile_manifest(
    raw: &[u8],
    authority: &HistoryAuthorityDescriptor,
    history_authority_extension: HistoryAuthorityExtension,
    context: DeploymentProfileManifestContext<'_>,
) -> Result<(), Error> {
    let DeploymentProfileManifestContext {
        gid,
        profile_version,
        n_max,
        max_barrier_update_bytes,
        fs_forward_leap_policy,
        context,
    } = context;
    if raw.is_empty() {
        return Err(Error::Parse(format!(
            "{context} missing deployment_profile_manifest"
        )));
    }
    let manifest: DeploymentProfileManifestWire =
        decode_cbor_det("deployment profile manifest", raw)?;
    if array32(&manifest.scope_id)? != authority.scope_id {
        return Err(Error::Parse(format!(
            "{context} deployment_profile_manifest scope_id mismatch"
        )));
    }
    if manifest.history_authority_extension != history_authority_extension.as_str() {
        return Err(Error::Parse(format!(
            "{context} deployment_profile_manifest history_authority_extension mismatch"
        )));
    }
    if array32(&manifest.gid)? != *gid {
        return Err(Error::Parse(format!(
            "{context} deployment_profile_manifest gid mismatch"
        )));
    }
    if manifest.profile_version != profile_version {
        return Err(Error::Parse(format!(
            "{context} deployment_profile_manifest profile_version mismatch"
        )));
    }
    if manifest.n_max != n_max || manifest.max_barrier_update_bytes != max_barrier_update_bytes {
        return Err(Error::Parse(format!(
            "{context} deployment_profile_manifest barrier config mismatch"
        )));
    }
    if manifest.fs_forward_leap_h != fs_forward_leap_policy.h
        || manifest.fs_forward_leap_checkpoint_interval
            != fs_forward_leap_policy.checkpoint_interval
        || manifest.fs_forward_leap_slack_anchor != fs_forward_leap_policy.slack_anchor
        || manifest.fs_forward_leap_slack_first_device != fs_forward_leap_policy.slack_first_device
        || manifest.fs_forward_leap_slack_device != fs_forward_leap_policy.slack_device
    {
        return Err(Error::Parse(format!(
            "{context} deployment_profile_manifest fs policy mismatch"
        )));
    }
    let payload = encode_cbor_det(&DeploymentProfileManifestSignedPayload {
        label: "cityg/deployment-profile-manifest-v1",
        scope_id: &authority.scope_id,
        history_authority_extension: history_authority_extension.as_str(),
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
    verify_ml_dsa_signature(
        payload.as_slice(),
        authority.public_key.as_slice(),
        manifest.signature.as_slice(),
    )
}

pub(crate) fn parse_history_authority_extension(
    raw: &str,
    carries_extension_bytes: bool,
) -> Result<Option<HistoryAuthorityExtension>, Error> {
    if raw.is_empty() {
        if carries_extension_bytes {
            return Err(Error::Parse(
                "history authority extension bytes present without negotiated extension"
                    .to_string(),
            ));
        }
        return Ok(None);
    }

    match raw {
        LOCAL_HISTORY_AUTHORITY_EXTENSION_ID => {
            Ok(Some(HistoryAuthorityExtension::LocalHistoryAuthorityV1))
        }
        GLOBAL_HISTORY_AUTHORITY_EXTENSION_ID => {
            Ok(Some(HistoryAuthorityExtension::GlobalHistoryAuthorityV1))
        }
        other => Err(Error::Parse(format!(
            "unsupported history authority extension: {other}"
        ))),
    }
}

pub(crate) fn require_base_profile_global_history_authority_extension(
    extension: Option<HistoryAuthorityExtension>,
    context: &str,
) -> Result<HistoryAuthorityExtension, Error> {
    match extension {
        Some(HistoryAuthorityExtension::GlobalHistoryAuthorityV1) => {
            Ok(HistoryAuthorityExtension::GlobalHistoryAuthorityV1)
        }
        Some(HistoryAuthorityExtension::LocalHistoryAuthorityV1) => Err(Error::Parse(format!(
            "{context} must carry global-history-authority-v1 in the base profile"
        ))),
        None => Err(Error::Parse(format!(
            "{context} missing required global-history-authority-v1 in the base profile"
        ))),
    }
}

pub(crate) fn require_history_authority_descriptor_for_extension(
    extension: Option<HistoryAuthorityExtension>,
    authority: &Option<HistoryAuthorityDescriptor>,
    context: &str,
) -> Result<(), Error> {
    if extension.is_some() && authority.is_none() {
        return Err(Error::Parse(format!(
            "{context} carries history authority extension without authority descriptor"
        )));
    }
    Ok(())
}

pub(crate) fn validate_local_history_attestation_kind(
    extension: Option<HistoryAuthorityExtension>,
    attestation: &GlobalHistoryAttestation,
    context: &str,
) -> Result<(), Error> {
    match extension {
        Some(HistoryAuthorityExtension::LocalHistoryAuthorityV1)
            if attestation.finality_kind != LOCAL_HISTORY_ATTESTATION_FINALITY_KIND =>
        {
            return Err(Error::Parse(format!(
                "{context} global_history_attestation finality_kind mismatch"
            )));
        }
        Some(HistoryAuthorityExtension::GlobalHistoryAuthorityV1)
            if attestation.finality_kind != GLOBAL_HISTORY_ATTESTATION_FINALITY_KIND =>
        {
            return Err(Error::Parse(format!(
                "{context} global_history_attestation finality_kind mismatch"
            )));
        }
        _ => {}
    }
    Ok(())
}

pub fn parse_history_authority_descriptor_bytes(
    raw: &[u8],
) -> Result<Option<HistoryAuthorityDescriptor>, Error> {
    if raw.is_empty() {
        return Ok(None);
    }
    let HistoryAuthorityDescriptorWire(scope_id, public_key) =
        decode_cbor_det("history_authority_descriptor", raw)?;
    if public_key.len() != dilithium5::public_key_bytes() {
        return Err(Error::Parse(
            "history_authority_descriptor public_key length mismatch".to_string(),
        ));
    }
    Ok(Some(HistoryAuthorityDescriptor {
        scope_id: array32(&scope_id)?,
        public_key,
    }))
}

pub fn parse_global_history_attestation_bytes(
    raw: &[u8],
    expected_authority: Option<&HistoryAuthorityDescriptor>,
) -> Result<Option<GlobalHistoryAttestation>, Error> {
    if raw.is_empty() {
        return Ok(None);
    }
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
    ) = decode_cbor_det("global_history_attestation", raw)?;
    let scope_id = array32(&scope_id)?;
    let gid = array32(&gid)?;
    let history_view_id = array32(&history_view_id)?;
    let history_commitment = HistoryCommitment {
        history_view_id,
        history_commitment_id: array32(&history_commitment_id)?,
        prev_history_commitment_id: array32(&prev_history_commitment_id)?,
        history_seq,
    };
    let attestation = GlobalHistoryAttestation {
        scope_id,
        gid,
        history_commitment,
        barrier_version,
        kem_tree_hash_after: array32(&kem_tree_hash_after)?,
        parent_attestation_id: array32(&parent_attestation_id)?,
        finality_kind,
        signature,
    };
    if let Some(authority) = expected_authority {
        if authority.scope_id != attestation.scope_id {
            return Err(Error::Parse(
                "global_history_attestation scope_id mismatch".to_string(),
            ));
        }
        let payload = encode_cbor_det(&GlobalHistoryAttestationSignedPayload(
            "cityg/global-history-attestation-v1",
            &attestation.scope_id,
            &attestation.gid,
            &attestation.history_commitment.history_view_id,
            &attestation.history_commitment.history_commitment_id,
            &attestation.history_commitment.prev_history_commitment_id,
            attestation.history_commitment.history_seq,
            attestation.barrier_version,
            &attestation.kem_tree_hash_after,
            &attestation.parent_attestation_id,
            attestation.finality_kind.as_str(),
        ))?;
        verify_ml_dsa_signature(
            payload.as_slice(),
            authority.public_key.as_slice(),
            attestation.signature.as_slice(),
        )?;
    }
    Ok(Some(attestation))
}

pub(crate) fn parse_helper_completeness_attestation_bytes(
    raw: &[u8],
    authority: &HistoryAuthorityDescriptor,
    helper_kind: &'static str,
) -> Result<Option<HelperCompletenessAttestation>, Error> {
    if raw.is_empty() {
        return Ok(None);
    }
    let HelperCompletenessAttestationWire(scope_id, decoded_helper_kind, signature) =
        decode_cbor_det("helper_completeness_attestation", raw)?;
    let scope_id = array32(&scope_id)?;
    if scope_id != authority.scope_id {
        return Err(Error::Parse(
            "helper_completeness_attestation scope_id mismatch".to_string(),
        ));
    }
    if decoded_helper_kind != helper_kind {
        return Err(Error::Parse(
            "helper_completeness_attestation helper_kind mismatch".to_string(),
        ));
    }
    Ok(Some(HelperCompletenessAttestation {
        scope_id,
        helper_kind: decoded_helper_kind,
        signature,
    }))
}

pub fn parse_revoked_occupancies_completeness_attestation_bytes(
    raw: &[u8],
    authority: &HistoryAuthorityDescriptor,
) -> Result<Option<HelperCompletenessAttestation>, Error> {
    parse_helper_completeness_attestation_bytes(raw, authority, HELPER_KIND_REVOKED_OCCUPANCIES)
}

pub fn parse_join_occupancies_since_completeness_attestation_bytes(
    raw: &[u8],
    authority: &HistoryAuthorityDescriptor,
) -> Result<Option<HelperCompletenessAttestation>, Error> {
    parse_helper_completeness_attestation_bytes(raw, authority, HELPER_KIND_JOIN_OCCUPANCIES_SINCE)
}

pub fn parse_fetch_public_tree_completeness_attestation_bytes(
    raw: &[u8],
    authority: &HistoryAuthorityDescriptor,
) -> Result<Option<HelperCompletenessAttestation>, Error> {
    parse_helper_completeness_attestation_bytes(raw, authority, HELPER_KIND_FETCH_PUBLIC_TREE)
}

pub fn verify_revoked_occupancies_completeness_attestation(
    attestation: &HelperCompletenessAttestation,
    authority: &HistoryAuthorityDescriptor,
    history_commitment: &HistoryCommitment,
    revocation_roots_hash: &[u8; 32],
    page_offset: u32,
    total_entries: u32,
    records: &[BarrierRevokedOccupancyRecord],
) -> Result<(), Error> {
    let payload = encode_cbor_det(&HelperCompletenessSignedPayload {
        label: "cityg/helper-completeness-attestation-v1",
        scope_id: &attestation.scope_id,
        helper_kind: attestation.helper_kind.as_str(),
        history_view_id: &history_commitment.history_view_id,
        history_commitment_id: &history_commitment.history_commitment_id,
        page_offset,
        total_entries,
        selector: RevokedLeavesSelector {
            revocation_roots_hash,
            records,
        },
    })?;
    verify_ml_dsa_signature(
        payload.as_slice(),
        authority.public_key.as_slice(),
        attestation.signature.as_slice(),
    )
}

pub fn verify_join_occupancies_since_completeness_attestation(
    attestation: &HelperCompletenessAttestation,
    authority: &HistoryAuthorityDescriptor,
    history_commitment: &HistoryCommitment,
    prev_barrier_version: u64,
    page_offset: u32,
    total_entries: u32,
    records: &[BarrierJoinOccupancyRecord],
) -> Result<(), Error> {
    let payload = encode_cbor_det(&HelperCompletenessSignedPayload {
        label: "cityg/helper-completeness-attestation-v1",
        scope_id: &attestation.scope_id,
        helper_kind: attestation.helper_kind.as_str(),
        history_view_id: &history_commitment.history_view_id,
        history_commitment_id: &history_commitment.history_commitment_id,
        page_offset,
        total_entries,
        selector: JoinsSinceSelector {
            prev_barrier_version,
            records,
        },
    })?;
    verify_ml_dsa_signature(
        payload.as_slice(),
        authority.public_key.as_slice(),
        attestation.signature.as_slice(),
    )
}

pub fn verify_fetch_public_tree_completeness_attestation(
    attestation: &HelperCompletenessAttestation,
    authority: &HistoryAuthorityDescriptor,
    history_commitment: &HistoryCommitment,
    kem_tree_hash_after: &[u8; 32],
    entry_offset: u32,
    total_entries: u32,
    pk_entries: &[Vec<u8>],
) -> Result<(), Error> {
    let payload = encode_cbor_det(&HelperCompletenessSignedPayload {
        label: "cityg/helper-completeness-attestation-v1",
        scope_id: &attestation.scope_id,
        helper_kind: attestation.helper_kind.as_str(),
        history_view_id: &history_commitment.history_view_id,
        history_commitment_id: &history_commitment.history_commitment_id,
        page_offset: entry_offset,
        total_entries,
        selector: FetchPublicTreeSelector {
            kem_tree_hash_after,
            pk_entries,
        },
    })?;
    verify_ml_dsa_signature(
        payload.as_slice(),
        authority.public_key.as_slice(),
        attestation.signature.as_slice(),
    )
}

pub(crate) fn parse_fs_forward_leap_policy(
    policy: Option<PbFsForwardLeapPolicy>,
) -> Result<FsForwardLeapPolicy, Error> {
    let policy =
        policy.ok_or_else(|| Error::Parse("missing fs_forward_leap_policy".to_string()))?;
    if policy.h == 0 {
        return Err(Error::Parse(
            "fs_forward_leap_policy.h must be > 0".to_string(),
        ));
    }
    if policy.checkpoint_interval < policy.h {
        return Err(Error::Parse(
            "fs_forward_leap_policy.checkpoint_interval must be >= h".to_string(),
        ));
    }
    Ok(FsForwardLeapPolicy {
        h: policy.h,
        checkpoint_interval: policy.checkpoint_interval,
        slack_anchor: policy.slack_anchor,
        slack_first_device: policy.slack_first_device,
        slack_device: policy.slack_device,
    })
}

pub(crate) fn parse_merge_acceptance_status(status: i32) -> Result<MergeAcceptanceStatus, Error> {
    match PbMergeAcceptanceStatus::try_from(status) {
        Ok(PbMergeAcceptanceStatus::Pending) => Ok(MergeAcceptanceStatus::Pending),
        Ok(PbMergeAcceptanceStatus::Accepted) => Ok(MergeAcceptanceStatus::Accepted),
        Ok(PbMergeAcceptanceStatus::Superseded) => Ok(MergeAcceptanceStatus::Superseded),
        Ok(PbMergeAcceptanceStatus::FinalRejected) => Ok(MergeAcceptanceStatus::FinalRejected),
        Err(_) => Err(Error::Parse(format!(
            "invalid merge acceptance status: {status}"
        ))),
    }
}

pub(crate) fn parse_barrier_helper_total_entries(total_entries: u32) -> Result<usize, Error> {
    usize::try_from(total_entries)
        .map_err(|_| Error::Parse("barrier helper total_entries overflow".to_string()))
}

pub(crate) fn ensure_barrier_helper_history_page(
    expected: &mut Option<([u8; 32], HistoryCommitment, usize)>,
    history_view_id: [u8; 32],
    history_commitment: HistoryCommitment,
    total_entries: usize,
) -> Result<(), Error> {
    match expected {
        Some((expected_view_id, expected_commitment, expected_total_entries)) => {
            if *expected_view_id != history_view_id {
                return Err(Error::Parse(
                    "barrier helper pagination history_view_id mismatch".to_string(),
                ));
            }
            if *expected_commitment != history_commitment {
                return Err(Error::Parse(
                    "barrier helper pagination history_commitment mismatch".to_string(),
                ));
            }
            if *expected_total_entries != total_entries {
                return Err(Error::Parse(
                    "barrier helper pagination total_entries mismatch".to_string(),
                ));
            }
        }
        None => {
            *expected = Some((history_view_id, history_commitment, total_entries));
        }
    }
    Ok(())
}

pub(crate) fn ensure_profile_version(version: &str) -> Result<(), Error> {
    if version == EXPECTED_PROFILE_VERSION {
        return Ok(());
    }
    Err(Error::Parse(format!(
        "profile_version mismatch: expected {EXPECTED_PROFILE_VERSION}, got {version}"
    )))
}

pub(crate) fn ensure_profile_suite_registry(
    context: &str,
    proof_mode: &str,
    vrf_id: &str,
    msphf_crs_id: &str,
    msphf_params_id: &str,
) -> Result<(), Error> {
    if proof_mode != EXPECTED_PROOF_MODE {
        return Err(Error::Parse(format!(
            "{context} proof_mode mismatch: expected {EXPECTED_PROOF_MODE}, got {proof_mode}"
        )));
    }
    if vrf_id != EXPECTED_VRF_ID {
        return Err(Error::Parse(format!(
            "{context} vrf_id mismatch: expected {EXPECTED_VRF_ID}, got {vrf_id}"
        )));
    }
    if msphf_crs_id != EXPECTED_MSPHF_CRS_ID {
        return Err(Error::Parse(format!(
            "{context} msphf_crs_id mismatch: expected {EXPECTED_MSPHF_CRS_ID}, got {msphf_crs_id}"
        )));
    }
    if msphf_params_id != EXPECTED_MSPHF_PARAMS_ID {
        return Err(Error::Parse(format!(
            "{context} msphf_params_id mismatch: expected {EXPECTED_MSPHF_PARAMS_ID}, got {msphf_params_id}"
        )));
    }
    Ok(())
}

pub(crate) fn validate_barrier_n_max(n_max: u64) -> Result<u64, Error> {
    if n_max == 0 || !n_max.is_power_of_two() {
        return Err(Error::Parse(
            "barrier n_max must be a non-zero power of two".to_string(),
        ));
    }
    if n_max > MAX_BARRIER_N_MAX {
        return Err(Error::Parse(format!(
            "barrier n_max exceeds MAX_BARRIER_N_MAX: {n_max} > {MAX_BARRIER_N_MAX}"
        )));
    }
    Ok(n_max)
}
