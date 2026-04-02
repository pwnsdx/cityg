use super::*;
use cityg_api_schema::pb::{MergeTicketRequest, MergeTicketResponse};
use cityg_client::pivot::pivot_parity_from_cbor;

impl CitygApiClient {
    /// Requests a merge ticket for a leaving member.
    pub async fn merge_ticket(
        &self,
        room_id: &str,
        leaf_id: &[u8; 32],
    ) -> Result<MergeTicket, Error> {
        self.merge_ticket_with_intent(room_id, leaf_id, MergeTicketIntent::Leave)
            .await
    }

    /// Requests a merge ticket for a non-leaving PCS refresh.
    pub async fn merge_ticket_refresh(
        &self,
        room_id: &str,
        leaf_id: &[u8; 32],
    ) -> Result<MergeTicket, Error> {
        self.merge_ticket_with_intent(room_id, leaf_id, MergeTicketIntent::Refresh)
            .await
    }

    /// Requests a merge ticket with explicit intent.
    pub async fn merge_ticket_with_intent(
        &self,
        room_id: &str,
        leaf_id: &[u8; 32],
        intent: MergeTicketIntent,
    ) -> Result<MergeTicket, Error> {
        let request = MergeTicketRequest {
            room_id: room_id.to_string(),
            leaf_id: leaf_id.to_vec(),
            intent: intent.as_proto(),
        };
        let response: MergeTicketResponse =
            self.post_proto("/v1/rooms/merge_ticket", request).await?;
        ensure_profile_version(&response.profile_version)?;
        ensure_profile_suite_registry(
            "merge ticket",
            response.proof_mode.as_str(),
            response.vrf_id.as_str(),
            response.msphf_crs_id.as_str(),
            response.msphf_params_id.as_str(),
        )?;

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
        let n_max = validate_barrier_n_max(response.n_max)?;
        let current_history_view_id = array32(&response.current_history_view_id)?;
        let current_history_commitment = parse_history_commitment(
            current_history_view_id,
            response.current_history_commitment.clone(),
        )?;
        let history_authority_extension = require_base_profile_global_history_authority_extension(
            parse_history_authority_extension(
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
        let fs_forward_leap_policy = parse_fs_forward_leap_policy(response.fs_forward_leap_policy)?;
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
                MergeTicketArtifactContext {
                    requested_leaf_id: leaf_id,
                    response: &response,
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
            author_leaf_id: *leaf_id,
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
            cover_leaf_index: response.cover_leaf_index,
            kem_tree_hash_after: array32(&response.kem_tree_hash_after)?,
            current_history_commitment,
            history_authority_extension: Some(history_authority_extension),
            history_authority_descriptor_bytes: response.history_authority_descriptor,
            history_authority,
            current_global_history_attestation_bytes: response.current_global_history_attestation,
            current_global_history_attestation,
            merge_ticket_artifact_bytes: response.merge_ticket_artifact,
            deployment_profile_manifest_bytes: response.deployment_profile_manifest,
            n_max,
            max_barrier_update_bytes: response.max_barrier_update_bytes,
        })
    }

    /// Requests a leave-intent merge ticket and retries transient concurrency/rate-limit failures.
    pub async fn merge_ticket_with_retry(
        &self,
        room_id: &str,
        leaf_id: &[u8; 32],
    ) -> Result<MergeTicket, Error> {
        retry_ticket_request("merge_ticket", || self.merge_ticket(room_id, leaf_id)).await
    }

    /// Requests a refresh-intent merge ticket and retries transient concurrency/rate-limit failures.
    pub async fn merge_ticket_refresh_with_retry(
        &self,
        room_id: &str,
        leaf_id: &[u8; 32],
    ) -> Result<MergeTicket, Error> {
        retry_ticket_request("merge_ticket_refresh", || {
            self.merge_ticket_refresh(room_id, leaf_id)
        })
        .await
    }
}
