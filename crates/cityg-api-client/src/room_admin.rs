use ciborium::ser::into_writer;
use cityg_api_schema::pb::{
    BootstrapRoomRequest, BootstrapRoomResponse, ExpelMemberTicketRequest, ListRoomAdminsRequest,
    ListRoomAdminsResponse, MergeTicketResponse, RoomAdminMutationRequest,
    RoomAdminMutationResponse, RotateRoomKbroadRequest, RotateRoomKbroadResponse,
};
use cityg_client::{barrier_crypto::generate_kbroad_keypair, pivot::pivot_parity_from_cbor};
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use serde_bytes::ByteBuf;

use crate::{
    CitygApiClient, DeploymentProfileManifestContext, Error, IdentityBinding, MergeTicket,
    RoomAdminProof, SlotLease, array32, ensure_profile_version,
    parse_global_history_attestation_bytes, parse_history_authority_descriptor_bytes,
    parse_history_commitment, require_base_profile_global_history_authority_extension,
    require_history_authority_descriptor_for_extension, retry_ticket_request,
    validate_local_history_attestation_kind, verify_deployment_profile_manifest,
    verify_merge_ticket_artifact,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoomAdminOperation {
    Bootstrap,
    RotateKbroad,
    GrantAdmin,
    RevokeAdmin,
    ListAdmins,
    ExpelMember,
}

impl RoomAdminOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap_room_v1",
            Self::RotateKbroad => "rotate_room_kbroad_v1",
            Self::GrantAdmin => "grant_room_admin_v1",
            Self::RevokeAdmin => "revoke_room_admin_v1",
            Self::ListAdmins => "list_room_admins_v1",
            Self::ExpelMember => "expel_room_member_v1",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomAdminIdentity {
    pub pop_public_key: Vec<u8>,
    pub pop_secret_key: Vec<u8>,
}

impl RoomAdminIdentity {
    pub fn new(pop_public_key: Vec<u8>, pop_secret_key: Vec<u8>) -> Self {
        Self {
            pop_public_key,
            pop_secret_key,
        }
    }

    pub fn from_slices(pop_public_key: &[u8], pop_secret_key: &[u8]) -> Self {
        Self::new(pop_public_key.to_vec(), pop_secret_key.to_vec())
    }

    pub fn build_identity_binding(&self, alias: &str) -> Result<IdentityBinding, Error> {
        crate::build_identity_binding(alias, &self.pop_public_key, &self.pop_secret_key)
    }

    pub fn parse_secret_key(&self) -> Result<dilithium5::SecretKey, Error> {
        parse_room_admin_secret_key(&self.pop_secret_key)
    }

    pub fn build_kbroad_proof(
        &self,
        operation: RoomAdminOperation,
        room_id: &str,
        kbroad_public: &[u8],
    ) -> Result<RoomAdminProof, Error> {
        build_room_admin_proof(
            operation,
            room_id,
            kbroad_public,
            &self.pop_public_key,
            &self.pop_secret_key,
        )
    }

    pub fn build_target_proof(
        &self,
        operation: RoomAdminOperation,
        room_id: &str,
        target_pop_public_key: &[u8],
    ) -> Result<RoomAdminProof, Error> {
        build_room_admin_target_proof(
            operation,
            room_id,
            target_pop_public_key,
            &self.pop_public_key,
            &self.pop_secret_key,
        )
    }

    pub fn build_listing_proof(&self, room_id: &str) -> Result<RoomAdminProof, Error> {
        build_room_admin_listing_proof(room_id, &self.pop_public_key, &self.pop_secret_key)
    }

    pub fn build_leaf_pair_proof(
        &self,
        operation: RoomAdminOperation,
        room_id: &str,
        author_leaf_id: &[u8; 32],
        target_leaf_id: &[u8; 32],
    ) -> Result<RoomAdminProof, Error> {
        build_room_admin_leaf_pair_proof(
            operation,
            room_id,
            author_leaf_id,
            target_leaf_id,
            &self.pop_public_key,
            &self.pop_secret_key,
        )
    }
}

fn build_room_admin_proof_payload(
    operation: RoomAdminOperation,
    room_id: &str,
    payload: &[u8],
    pop_public_key: &[u8],
    pop_secret_key: &[u8],
) -> Result<RoomAdminProof, Error> {
    let secret_key = dilithium5::SecretKey::from_bytes(pop_secret_key)
        .map_err(|_| Error::Parse("invalid room admin secret key".to_string()))?;
    let message = (operation.as_str(), room_id, ByteBuf::from(payload.to_vec()));
    let mut payload_bytes = Vec::new();
    into_writer(&message, &mut payload_bytes)
        .map_err(|err| Error::Parse(format!("encode room admin proof payload: {err}")))?;
    let signature = dilithium5::detached_sign(&payload_bytes, &secret_key);
    Ok(RoomAdminProof {
        pop_public_key: pop_public_key.to_vec(),
        signature: signature.as_bytes().to_vec(),
    })
}

pub fn generate_room_admin_keypair() -> (Vec<u8>, Vec<u8>) {
    let (public_key, secret_key) = dilithium5::keypair();
    (
        public_key.as_bytes().to_vec(),
        secret_key.as_bytes().to_vec(),
    )
}

pub fn room_admin_public_key_bytes() -> usize {
    dilithium5::public_key_bytes()
}

pub fn generate_room_admin_identity() -> RoomAdminIdentity {
    let (pop_public_key, pop_secret_key) = generate_room_admin_keypair();
    RoomAdminIdentity::new(pop_public_key, pop_secret_key)
}

pub fn parse_room_admin_secret_key(bytes: &[u8]) -> Result<dilithium5::SecretKey, Error> {
    dilithium5::SecretKey::from_bytes(bytes)
        .map_err(|_| Error::Parse("invalid room admin secret key".to_string()))
}

pub fn build_room_admin_proof(
    operation: RoomAdminOperation,
    room_id: &str,
    kbroad_public: &[u8],
    pop_public_key: &[u8],
    pop_secret_key: &[u8],
) -> Result<RoomAdminProof, Error> {
    build_room_admin_proof_payload(
        operation,
        room_id,
        kbroad_public,
        pop_public_key,
        pop_secret_key,
    )
}

pub fn build_room_admin_target_proof(
    operation: RoomAdminOperation,
    room_id: &str,
    target_pop_public_key: &[u8],
    pop_public_key: &[u8],
    pop_secret_key: &[u8],
) -> Result<RoomAdminProof, Error> {
    build_room_admin_proof_payload(
        operation,
        room_id,
        target_pop_public_key,
        pop_public_key,
        pop_secret_key,
    )
}

pub fn build_room_admin_listing_proof(
    room_id: &str,
    pop_public_key: &[u8],
    pop_secret_key: &[u8],
) -> Result<RoomAdminProof, Error> {
    build_room_admin_proof_payload(
        RoomAdminOperation::ListAdmins,
        room_id,
        &[],
        pop_public_key,
        pop_secret_key,
    )
}

pub fn build_room_admin_leaf_pair_proof(
    operation: RoomAdminOperation,
    room_id: &str,
    author_leaf_id: &[u8; 32],
    target_leaf_id: &[u8; 32],
    pop_public_key: &[u8],
    pop_secret_key: &[u8],
) -> Result<RoomAdminProof, Error> {
    let payload = (
        ByteBuf::from(author_leaf_id.to_vec()),
        ByteBuf::from(target_leaf_id.to_vec()),
    );
    let mut payload_bytes = Vec::new();
    into_writer(&payload, &mut payload_bytes)
        .map_err(|err| Error::Parse(format!("encode room admin leaf-pair payload: {err}")))?;
    build_room_admin_proof_payload(
        operation,
        room_id,
        &payload_bytes,
        pop_public_key,
        pop_secret_key,
    )
}

impl CitygApiClient {
    pub async fn bootstrap_room_for_join(
        &self,
        room_id: &str,
        pop_public_key: &[u8],
        pop_secret_key: &[u8],
        kbroad_public: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, Error> {
        let kbroad_public = kbroad_public.unwrap_or_else(|| generate_kbroad_keypair().0);
        let admin_proof = build_room_admin_proof(
            RoomAdminOperation::Bootstrap,
            room_id,
            &kbroad_public,
            pop_public_key,
            pop_secret_key,
        )?;

        match self
            .bootstrap_room_as_admin(room_id, &kbroad_public, admin_proof)
            .await
        {
            Ok(()) => Ok(kbroad_public),
            Err(Error::HttpStatus {
                status, message, ..
            }) if status.is_server_error() && message.contains("kbroad key already registered") => {
                Ok(kbroad_public)
            }
            Err(err) => Err(err),
        }
    }

    pub async fn bootstrap_room(&self, room_id: &str, kbroad_public: &[u8]) -> Result<(), Error> {
        let _ = (room_id, kbroad_public);
        Err(Error::Parse(
            "bootstrap_room without RoomAdminProof has been removed; use bootstrap_room_as_admin"
                .to_string(),
        ))
    }

    pub async fn bootstrap_room_as_admin(
        &self,
        room_id: &str,
        kbroad_public: &[u8],
        admin_proof: RoomAdminProof,
    ) -> Result<(), Error> {
        let request = BootstrapRoomRequest {
            room_id: room_id.to_string(),
            kbroad_public: kbroad_public.to_vec(),
            admin_proof: Some(admin_proof),
        };
        let _: BootstrapRoomResponse = self.post_proto("/v1/rooms/bootstrap", request).await?;
        Ok(())
    }

    pub async fn rotate_room_kbroad(
        &self,
        room_id: &str,
        kbroad_public: &[u8],
    ) -> Result<u64, Error> {
        let _ = (room_id, kbroad_public);
        Err(Error::Parse(
            "rotate_room_kbroad without RoomAdminProof has been removed; use rotate_room_kbroad_as_admin"
                .to_string(),
        ))
    }

    pub async fn rotate_room_kbroad_as_admin(
        &self,
        room_id: &str,
        kbroad_public: &[u8],
        admin_proof: RoomAdminProof,
    ) -> Result<u64, Error> {
        let request = RotateRoomKbroadRequest {
            room_id: room_id.to_string(),
            kbroad_public: kbroad_public.to_vec(),
            admin_proof: Some(admin_proof),
        };
        let response: RotateRoomKbroadResponse =
            self.post_proto("/v1/rooms/rotate_kbroad", request).await?;
        Ok(response.kbroad_generation)
    }

    pub async fn grant_room_admin(
        &self,
        room_id: &str,
        target_pop_public_key: &[u8],
        admin_proof: RoomAdminProof,
    ) -> Result<RoomAdminMutationResponse, Error> {
        let request = RoomAdminMutationRequest {
            room_id: room_id.to_string(),
            target_pop_public_key: target_pop_public_key.to_vec(),
            admin_proof: Some(admin_proof),
        };
        self.post_proto("/v1/rooms/grant_admin", request).await
    }

    pub async fn revoke_room_admin(
        &self,
        room_id: &str,
        target_pop_public_key: &[u8],
        admin_proof: RoomAdminProof,
    ) -> Result<RoomAdminMutationResponse, Error> {
        let request = RoomAdminMutationRequest {
            room_id: room_id.to_string(),
            target_pop_public_key: target_pop_public_key.to_vec(),
            admin_proof: Some(admin_proof),
        };
        self.post_proto("/v1/rooms/revoke_admin", request).await
    }

    pub async fn list_room_admins(
        &self,
        room_id: &str,
        admin_proof: RoomAdminProof,
    ) -> Result<ListRoomAdminsResponse, Error> {
        let request = ListRoomAdminsRequest {
            room_id: room_id.to_string(),
            admin_proof: Some(admin_proof),
        };
        self.post_proto("/v1/rooms/list_admins", request).await
    }

    pub async fn expel_member_ticket(
        &self,
        room_id: &str,
        author_leaf_id: &[u8; 32],
        target_leaf_id: &[u8; 32],
        admin_proof: RoomAdminProof,
    ) -> Result<MergeTicket, Error> {
        let request = ExpelMemberTicketRequest {
            room_id: room_id.to_string(),
            author_leaf_id: author_leaf_id.to_vec(),
            target_leaf_id: target_leaf_id.to_vec(),
            admin_proof: Some(admin_proof),
        };
        let response: MergeTicketResponse = self
            .post_proto("/v1/rooms/expel_member_ticket", request)
            .await?;
        ensure_profile_version(&response.profile_version)?;

        let we_epoch_id = array32(&response.we_epoch_id)?;
        let mut parities = Vec::with_capacity(response.pivot_parity_cbor.len());
        for entry in &response.pivot_parity_cbor {
            parities.push(pivot_parity_from_cbor(entry).map_err(Error::from)?);
        }

        let cat = array32(&response.cat)?;
        let parent_root = array32(&response.parent_root)?;
        let join_delta_root = array32(&response.join_delta_root)?;
        let revoked_since_root = array32(&response.revoked_since_root)?;
        let revoked_root = array32(&response.revoked_root)?;
        let tswe_salt_hash = array32(&response.tswe_salt_hash)?;
        let pox_r_commit = array32(&response.pox_r_commit)?;
        let n_max = crate::validate_barrier_n_max(response.n_max)?;
        let current_history_view_id = array32(&response.current_history_view_id)?;
        let current_history_commitment = parse_history_commitment(
            current_history_view_id,
            response.current_history_commitment.clone(),
        )?;
        let history_authority_extension = require_base_profile_global_history_authority_extension(
            crate::parse_history_authority_extension(
                response.history_authority_extension.as_str(),
                !response.history_authority_descriptor.is_empty()
                    || !response.current_global_history_attestation.is_empty(),
            )?,
            "merge ticket",
        )?;
        let history_authority = parse_history_authority_descriptor_bytes(
            response.history_authority_descriptor.as_slice(),
        )?;
        require_history_authority_descriptor_for_extension(
            Some(history_authority_extension),
            &history_authority,
            "merge ticket",
        )?;
        let current_global_history_attestation = match history_authority.as_ref() {
            Some(authority) => {
                let attestation = parse_global_history_attestation_bytes(
                    response.current_global_history_attestation.as_slice(),
                    Some(authority),
                )?
                .ok_or_else(|| {
                    Error::Parse(
                        "merge ticket missing current_global_history_attestation for history authority"
                            .to_string(),
                    )
                })?;
                if attestation.history_commitment != current_history_commitment {
                    return Err(Error::Parse(
                        "merge ticket current_global_history_attestation commitment mismatch"
                            .to_string(),
                    ));
                }
                if attestation.barrier_version != response.barrier_version {
                    return Err(Error::Parse(
                        "merge ticket current_global_history_attestation barrier_version mismatch"
                            .to_string(),
                    ));
                }
                if attestation.kem_tree_hash_after != array32(&response.kem_tree_hash_after)? {
                    return Err(Error::Parse(
                        "merge ticket current_global_history_attestation tree hash mismatch"
                            .to_string(),
                    ));
                }
                validate_local_history_attestation_kind(
                    Some(history_authority_extension),
                    &attestation,
                    "merge ticket",
                )?;
                Some(attestation)
            }
            None => {
                if !response.current_global_history_attestation.is_empty() {
                    return Err(Error::Parse(
                        "merge ticket carries global history attestation without authority descriptor"
                            .to_string(),
                    ));
                }
                None
            }
        };
        let fs_forward_leap_policy =
            crate::parse_fs_forward_leap_policy(response.fs_forward_leap_policy)?;
        if response.cover_leaf_index >= n_max {
            return Err(Error::Parse(format!(
                "merge ticket cover_leaf_index out of range: {} >= {}",
                response.cover_leaf_index, n_max
            )));
        }
        if let (Some(authority), Some(attestation)) = (
            history_authority.as_ref(),
            current_global_history_attestation.as_ref(),
        ) {
            verify_deployment_profile_manifest(
                response.deployment_profile_manifest.as_slice(),
                authority,
                history_authority_extension,
                DeploymentProfileManifestContext {
                    gid: &attestation.gid,
                    profile_version: response.profile_version.as_str(),
                    n_max: response.n_max,
                    max_barrier_update_bytes: response.max_barrier_update_bytes,
                    fs_forward_leap_policy: &fs_forward_leap_policy,
                    context: "merge ticket",
                },
            )?;
            verify_merge_ticket_artifact(
                response.merge_ticket_artifact.as_slice(),
                authority,
                history_authority_extension,
                crate::MergeTicketArtifactContext {
                    requested_leaf_id: author_leaf_id,
                    response: &response,
                    slot_lease: SlotLease {
                        slot_index: response.cover_leaf_index,
                        slot_generation: response.slot_generation,
                    },
                    current_history_commitment: &current_history_commitment,
                    current_global_history_attestation: attestation,
                    fs_forward_leap_policy: &fs_forward_leap_policy,
                },
            )?;
        } else if !response.merge_ticket_artifact.is_empty()
            || !response.deployment_profile_manifest.is_empty()
        {
            return Err(Error::Parse(
                "merge ticket carries merge_ticket_artifact without history authority".to_string(),
            ));
        }

        Ok(MergeTicket {
            author_leaf_id: *author_leaf_id,
            we_epoch_id,
            parities,
            witness_cbor: response.witness_cbor,
            srx_cbor: response.srx_cbor,
            proof_mode: response.proof_mode,
            vrf_id: response.vrf_id,
            policy_version: response.policy_version,
            cat,
            parent_root,
            join_delta_root,
            revoked_since_root,
            revoked_root,
            tswe_salt_hash,
            pox_r_commit,
            kbroad_public: response.kbroad_public,
            msphf_crs_id: response.msphf_crs_id,
            msphf_params_id: response.msphf_params_id,
            fs_policy_version: response.fs_policy_version,
            fs_epoch_base_ts: response.fs_epoch_base_ts,
            fs_forward_leap_policy,
            last_accepted_ec: response.last_accepted_ec,
            kbroad_generation: response.kbroad_generation,
            barrier_version: response.barrier_version,
            slot_lease: SlotLease {
                slot_index: response.cover_leaf_index,
                slot_generation: response.slot_generation,
            },
            kem_tree_hash_after: array32(&response.kem_tree_hash_after)?,
            current_history_commitment,
            history_authority_extension: Some(history_authority_extension),
            history_authority_descriptor_bytes: response.history_authority_descriptor,
            history_authority,
            current_global_history_attestation_bytes: response.current_global_history_attestation,
            current_global_history_attestation,
            merge_ticket_artifact_bytes: response.merge_ticket_artifact,
            deployment_profile_manifest_bytes: response.deployment_profile_manifest,
            n_max: response.n_max,
            max_barrier_update_bytes: response.max_barrier_update_bytes,
        })
    }

    pub async fn expel_member_ticket_with_retry(
        &self,
        room_id: &str,
        author_leaf_id: &[u8; 32],
        target_leaf_id: &[u8; 32],
        admin_proof: RoomAdminProof,
    ) -> Result<MergeTicket, Error> {
        retry_ticket_request("expel_member_ticket", || {
            self.expel_member_ticket(room_id, author_leaf_id, target_leaf_id, admin_proof.clone())
        })
        .await
    }
}
