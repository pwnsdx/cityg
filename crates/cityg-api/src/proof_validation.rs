#[cfg(test)]
use cityg_api_schema::pb::IdentityBinding;
use cityg_api_schema::pb::RoomAdminProof;
#[cfg(test)]
use cityg_api_schema::verify_identity_binding as schema_verify_identity_binding;
use cityg_api_schema::{
    encode_room_admin_leaf_pair_payload as schema_encode_room_admin_leaf_pair_payload,
    room_admin_proof_replay_key as schema_room_admin_proof_replay_key,
    verify_room_admin_proof as schema_verify_room_admin_proof,
    verify_room_admin_proof_payload as schema_verify_room_admin_proof_payload,
};

use crate::{ApiError, map_room_admin_proof_validation_error};

/// Verifies an identity binding signature.
/// The signature should be over CBOR([alias, pop_public_key])
#[cfg(test)]
pub(crate) fn verify_identity_binding(binding: &IdentityBinding) -> Result<(), ApiError> {
    schema_verify_identity_binding(binding)
        .map_err(|error| ApiError::InvalidRequest(error.api_message()))
}

pub(crate) fn verify_room_admin_proof_payload(
    proof: &RoomAdminProof,
    operation: &'static str,
    room_id: &str,
    payload: &[u8],
) -> Result<Vec<u8>, ApiError> {
    schema_verify_room_admin_proof_payload(proof, operation, room_id, payload)
        .map_err(map_room_admin_proof_validation_error)
}

pub(crate) fn verify_room_admin_proof(
    proof: &RoomAdminProof,
    operation: &'static str,
    room_id: &str,
    kbroad_public: &[u8],
) -> Result<Vec<u8>, ApiError> {
    schema_verify_room_admin_proof(proof, operation, room_id, kbroad_public)
        .map_err(map_room_admin_proof_validation_error)
}

pub(crate) fn room_admin_proof_replay_key(proof: &RoomAdminProof) -> Result<[u8; 32], ApiError> {
    schema_room_admin_proof_replay_key(proof).map_err(map_room_admin_proof_validation_error)
}

pub(crate) fn encode_room_admin_leaf_pair_payload(
    author_leaf_id: &[u8; 32],
    target_leaf_id: &[u8; 32],
) -> Result<Vec<u8>, ApiError> {
    schema_encode_room_admin_leaf_pair_payload(author_leaf_id, target_leaf_id)
        .map_err(map_room_admin_proof_validation_error)
}
