use super::*;
use cityg_api_schema::pb::{JoinTicketRequest, JoinTicketResponse};

impl CitygApiClient {
    /// Requests a join ticket for a new member.
    pub async fn join_ticket(
        &self,
        room_id: &str,
        alias: &str,
        identity_binding: Option<IdentityBinding>,
    ) -> Result<JoinTicketResponse, Error> {
        let request = JoinTicketRequest {
            room_id: room_id.to_string(),
            alias: alias.to_string(),
            identity_binding,
        };
        let response: JoinTicketResponse =
            self.post_proto("/v1/rooms/join_ticket", request).await?;
        ensure_profile_version(&response.profile_version)?;
        ensure_profile_suite_registry(
            "join ticket",
            response.proof_mode.as_str(),
            response.vrf_id.as_str(),
            response.msphf_crs_id.as_str(),
            response.msphf_params_id.as_str(),
        )?;
        let gid = array32(&response.gid)?;
        let n_max = validate_barrier_n_max(response.n_max)?;
        let current_history_view_id = array32(&response.current_history_view_id)?;
        let parent_root = if response.parent_root.is_empty() {
            [0u8; 32]
        } else {
            array32(&response.parent_root)?
        };
        let current_history_commitment = response
            .current_history_commitment
            .clone()
            .map(|commitment| parse_history_commitment(current_history_view_id, Some(commitment)))
            .transpose()?;
        let history_authority_extension = require_base_profile_global_history_authority_extension(
            parse_history_authority_extension(
                response.history_authority_extension.as_str(),
                !response.history_authority_descriptor.is_empty()
                    || !response.current_global_history_attestation.is_empty()
                    || !response
                        .current_join_records_completeness_attestation
                        .is_empty()
                    || !response
                        .current_revoked_leaf_indices_completeness_attestation
                        .is_empty(),
            )?,
            "join ticket",
        )?;
        let fs_forward_leap_policy = parse_fs_forward_leap_policy(response.fs_forward_leap_policy)?;
        let current_predecessor_kem_tree_hash_after =
            if response.current_predecessor_kem_tree_hash_after.is_empty() {
                [0u8; 32]
            } else {
                array32(&response.current_predecessor_kem_tree_hash_after)?
            };
        let requires_bootstrap_artifact = response.barrier_version > 0 || parent_root != [0u8; 32];
        if requires_bootstrap_artifact {
            if current_history_commitment.is_none() {
                return Err(Error::Parse(
                    "join ticket missing current_history_commitment for existing group".to_string(),
                ));
            }
            if response.current_barrier_update.is_empty() {
                return Err(Error::Parse(
                    "join ticket missing current_barrier_update for existing group".to_string(),
                ));
            }
            if current_predecessor_kem_tree_hash_after == [0u8; 32] {
                return Err(Error::Parse(
                    "join ticket missing current_predecessor_kem_tree_hash_after for existing group"
                        .to_string(),
                ));
            }
        }
        if response.join_finalize_auth_token.len() != 32 {
            return Err(Error::Parse(
                "join ticket missing join_finalize_auth_token".to_string(),
            ));
        }
        if response.provisioning_nonce.len() != 32 {
            return Err(Error::Parse(
                "join ticket missing provisioning_nonce".to_string(),
            ));
        }
        if response.provisioning_expires_at_ms < response.provisioning_issued_at_ms {
            return Err(Error::Parse(
                "join ticket provisioning expiry precedes issuance".to_string(),
            ));
        }
        let now_ms = current_timestamp_ms();
        if response.provisioning_issued_at_ms
            > now_ms.saturating_add(JOIN_PROVISIONING_CLOCK_SKEW_MS)
        {
            return Err(Error::Parse(
                "join ticket provisioning issuance is too far in the future".to_string(),
            ));
        }
        let history_authority = parse_history_authority_descriptor_bytes(
            response.history_authority_descriptor.as_slice(),
        )?;
        require_history_authority_descriptor_for_extension(
            Some(history_authority_extension),
            &history_authority,
            "join ticket",
        )?;
        if let Some(authority) = history_authority.as_ref() {
            let attestation = parse_global_history_attestation_bytes(
                response.current_global_history_attestation.as_slice(),
                Some(authority),
            )?
            .ok_or_else(|| {
                Error::Parse(
                    "join ticket missing current_global_history_attestation for history authority"
                        .to_string(),
                )
            })?;
            if attestation.gid != gid {
                return Err(Error::Parse(
                    "join ticket current_global_history_attestation gid mismatch".to_string(),
                ));
            }
            if let Some(commitment) = current_history_commitment
                && attestation.history_commitment != commitment
            {
                return Err(Error::Parse(
                    "join ticket current_global_history_attestation commitment mismatch"
                        .to_string(),
                ));
            }
            if attestation.barrier_version != response.barrier_version {
                return Err(Error::Parse(
                    "join ticket current_global_history_attestation barrier_version mismatch"
                        .to_string(),
                ));
            }
            if attestation.kem_tree_hash_after != array32(&response.kem_tree_hash_after)? {
                return Err(Error::Parse(
                    "join ticket current_global_history_attestation tree hash mismatch".to_string(),
                ));
            }
            validate_local_history_attestation_kind(
                Some(history_authority_extension),
                &attestation,
                "join ticket",
            )?;
            if let Some(commitment) = current_history_commitment.as_ref() {
                verify_deployment_profile_manifest(
                    response.deployment_profile_manifest.as_slice(),
                    authority,
                    history_authority_extension,
                    DeploymentProfileManifestContext {
                        gid: &gid,
                        profile_version: response.profile_version.as_str(),
                        n_max: response.n_max,
                        max_barrier_update_bytes: response.max_barrier_update_bytes,
                        fs_forward_leap_policy: &fs_forward_leap_policy,
                        context: "join ticket",
                    },
                )?;
                verify_join_provisioning_artifact(
                    response.provisioning_artifact.as_slice(),
                    authority,
                    history_authority_extension,
                    &response,
                    commitment,
                    &fs_forward_leap_policy,
                )?;
                let join_attestation = parse_helper_completeness_attestation_bytes(
                    response
                        .current_join_records_completeness_attestation
                        .as_slice(),
                    authority,
                    HELPER_KIND_JOINS_SINCE,
                )?
                .ok_or_else(|| {
                    Error::Parse(
                        "join ticket missing current_join_records_completeness_attestation"
                            .to_string(),
                    )
                })?;
                let join_records = response
                    .current_join_records
                    .iter()
                    .map(|record| BarrierJoinRecord {
                        device_pk: record.device_pk.clone(),
                        leaf_index: record.leaf_index,
                        ek_leaf: record.ek_leaf.clone(),
                    })
                    .collect::<Vec<_>>();
                verify_joins_since_completeness_attestation(
                    &join_attestation,
                    authority,
                    commitment,
                    response.barrier_version.saturating_sub(1),
                    0,
                    u32::try_from(join_records.len()).map_err(|_| {
                        Error::Parse("join ticket current_join_records length overflow".to_string())
                    })?,
                    join_records.as_slice(),
                )?;
                let revoked_attestation = parse_helper_completeness_attestation_bytes(
                    response
                        .current_revoked_leaf_indices_completeness_attestation
                        .as_slice(),
                    authority,
                    HELPER_KIND_REVOKED_LEAVES,
                )?
                .ok_or_else(|| {
                    Error::Parse(
                        "join ticket missing current_revoked_leaf_indices_completeness_attestation"
                            .to_string(),
                    )
                })?;
                let _ = revoked_attestation;
            }
        } else if !response.current_global_history_attestation.is_empty()
            || !response
                .current_join_records_completeness_attestation
                .is_empty()
            || !response
                .current_revoked_leaf_indices_completeness_attestation
                .is_empty()
            || !response.deployment_profile_manifest.is_empty()
            || !response.provisioning_artifact.is_empty()
        {
            return Err(Error::Parse(
                "join ticket carries history extension bytes without authority descriptor"
                    .to_string(),
            ));
        }
        if now_ms
            > response
                .provisioning_expires_at_ms
                .saturating_add(JOIN_PROVISIONING_CLOCK_SKEW_MS)
        {
            return Err(Error::Parse(
                "join ticket provisioning artifact expired".to_string(),
            ));
        }
        if response.cover_leaf_index >= n_max {
            return Err(Error::Parse(format!(
                "join ticket cover_leaf_index out of range: {} >= {}",
                response.cover_leaf_index, n_max
            )));
        }
        Ok(response)
    }

    /// Requests a join ticket and retries transient concurrency/rate-limit failures.
    pub async fn join_ticket_with_retry(
        &self,
        room_id: &str,
        alias: &str,
        identity_binding: Option<IdentityBinding>,
    ) -> Result<JoinTicketResponse, Error> {
        retry_ticket_request("join_ticket", || {
            self.join_ticket(room_id, alias, identity_binding.clone())
        })
        .await
    }
}
