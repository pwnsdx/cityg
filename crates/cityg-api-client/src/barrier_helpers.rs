use super::*;
use cityg_api_schema::pb;
use cityg_api_schema::pb::{
    BarrierFetchPublicTreeRequest, BarrierFetchPublicTreeResponse,
    BarrierIssueFullVerificationWitnessRequest, BarrierIssueFullVerificationWitnessResponse,
    BarrierLookupMergeAcceptanceRequest, BarrierLookupMergeAcceptanceResponse,
    BarrierResolveJoinsSinceRequest, BarrierResolveJoinsSinceResponse,
    BarrierResolveRevokedLeavesRequest, BarrierResolveRevokedLeavesResponse,
};

impl CitygApiClient {
    pub async fn barrier_fetch_snapshot_dependencies(
        &self,
        room_id: &str,
        barrier_version: u64,
        snapshot_hash: &[u8; 32],
        committed_revocation_roots_hash: &[u8; 32],
        expected_view_id: Option<&[u8; 32]>,
        expected_commitment: &HistoryCommitment,
        context: &str,
    ) -> Result<BarrierSnapshotDependencies, Error> {
        let public_tree = self
            .barrier_fetch_public_tree(room_id, snapshot_hash)
            .await?;
        let joins = self
            .barrier_resolve_joins_since(room_id, barrier_version)
            .await?;
        let revoked = self
            .barrier_resolve_revoked_leaves(room_id, committed_revocation_roots_hash)
            .await?;
        ensure_matching_barrier_history_dependencies(
            context,
            expected_view_id,
            expected_commitment,
            &public_tree,
            &joins,
            &revoked,
        )?;
        Ok(BarrierSnapshotDependencies {
            public_tree,
            joins,
            revoked,
        })
    }

    /// Requests a full-verification witness for a barrier update.
    #[allow(clippy::too_many_arguments)]
    pub async fn barrier_issue_full_verification_witness(
        &self,
        room_id: &str,
        author_leaf_id: &[u8; 32],
        revocation_target_leaf_id: Option<&[u8; 32]>,
        merge_ticket_artifact: &[u8],
        barrier_update_reason: u64,
        barrier_update: &[u8],
        n_max: u64,
        current_history_commitment: &HistoryCommitment,
        history_authority_extension: HistoryAuthorityExtension,
        history_authority: &HistoryAuthorityDescriptor,
        current_global_history_attestation: &[u8],
        barrier_version: u64,
        kem_tree_hash_after: &[u8; 32],
        joins_prev_barrier_version: u64,
        join_records: &[BarrierJoinRecord],
        revocation_roots_hash: &[u8; 32],
        revoked_leaf_indices: &[u32],
        deployment_profile_manifest: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if barrier_update_reason != 0 && barrier_update_reason != 1 {
            return Err(Error::Parse(
                "full verification witness only applies to barrier_update reason 0/1".to_string(),
            ));
        }
        let request = BarrierIssueFullVerificationWitnessRequest {
            room_id: room_id.to_string(),
            author_leaf_id: author_leaf_id.to_vec(),
            barrier_update_reason,
            barrier_update: barrier_update.to_vec(),
            current_history_commitment: Some(pb_history_commitment(*current_history_commitment)),
            current_global_history_attestation: current_global_history_attestation.to_vec(),
            joins_prev_barrier_version,
            join_records: join_records
                .iter()
                .map(|record| pb::BarrierJoinLeafRecord {
                    device_pk: record.device_pk.clone(),
                    leaf_index: record.leaf_index,
                    ek_leaf: record.ek_leaf.clone(),
                })
                .collect(),
            revocation_roots_hash: revocation_roots_hash.to_vec(),
            revoked_leaf_indices: revoked_leaf_indices.to_vec(),
            deployment_profile_manifest: deployment_profile_manifest.to_vec(),
            revocation_target_leaf_id: revocation_target_leaf_id
                .map(|leaf_id| leaf_id.to_vec())
                .unwrap_or_default(),
            merge_ticket_artifact: merge_ticket_artifact.to_vec(),
        };
        let response: BarrierIssueFullVerificationWitnessResponse = self
            .post_proto("/v1/barrier/issue_full_verification_witness", request)
            .await?;
        let updater_leaf =
            cover_leaf_index_for_n_max(revocation_target_leaf_id.unwrap_or(author_leaf_id), n_max);
        verify_full_verification_witness(
            response.full_verification_witness.as_slice(),
            history_authority,
            history_authority_extension,
            &parse_room_id_gid(room_id)?,
            current_history_commitment,
            barrier_version,
            kem_tree_hash_after,
            author_leaf_id,
            barrier_update_reason,
            updater_leaf,
            barrier_update,
            joins_prev_barrier_version,
            join_records,
            revocation_roots_hash,
            revoked_leaf_indices,
            deployment_profile_manifest,
        )?;
        Ok(response.full_verification_witness)
    }

    /// Resolves revoked cover leaf indices for a committed revocation roots hash.
    pub async fn barrier_resolve_revoked_leaves(
        &self,
        room_id: &str,
        revocation_roots_hash: &[u8; 32],
    ) -> Result<BarrierResolvedRevokedLeaves, Error> {
        let gid = parse_room_id_gid(room_id)?;
        let mut page_offset = 0u32;
        let mut expected_history = None;
        let mut expected_extension: Option<HistoryAuthorityExtension> = None;
        let mut expected_authority: Option<HistoryAuthorityDescriptor> = None;
        let mut expected_global_attestation: Option<GlobalHistoryAttestation> = None;
        let mut expected_deployment_profile_manifest: Option<Vec<u8>> = None;
        let mut leaf_indices = Vec::new();

        loop {
            let request = BarrierResolveRevokedLeavesRequest {
                room_id: room_id.to_string(),
                revocation_roots_hash: revocation_roots_hash.to_vec(),
                page_offset,
                max_entries: MAX_BARRIER_HELPER_PAGE_ENTRIES,
            };
            let response: BarrierResolveRevokedLeavesResponse = self
                .post_proto("/v1/barrier/resolve_revoked_leaves", request)
                .await?;
            if response.page_offset != page_offset {
                return Err(Error::Parse(
                    "barrier helper pagination page_offset mismatch".to_string(),
                ));
            }
            if response.leaf_indices.len() > MAX_BARRIER_HELPER_PAGE_ENTRIES as usize {
                return Err(Error::Parse(
                    "barrier helper pagination page too large".to_string(),
                ));
            }
            let history_view_id = array32(&response.history_view_id)?;
            let history_commitment =
                parse_history_commitment(history_view_id, response.history_commitment)?;
            ensure_profile_version(&response.profile_version)?;
            let n_max = validate_barrier_n_max(response.n_max)?;
            let fs_forward_leap_policy =
                parse_fs_forward_leap_policy(response.fs_forward_leap_policy)?;
            let history_authority_extension =
                require_base_profile_global_history_authority_extension(
                    parse_history_authority_extension(
                        response.history_authority_extension.as_str(),
                        !response.history_authority_descriptor.is_empty()
                            || !response.global_history_attestation.is_empty()
                            || !response.helper_completeness_attestation.is_empty()
                            || !response.deployment_profile_manifest.is_empty(),
                    )?,
                    "revoked leaves response",
                )?;
            let history_authority = parse_history_authority_descriptor_bytes(
                response.history_authority_descriptor.as_slice(),
            )?;
            require_history_authority_descriptor_for_extension(
                Some(history_authority_extension),
                &history_authority,
                "revoked leaves response",
            )?;
            let global_history_attestation = match history_authority.as_ref() {
                Some(authority) => {
                    let attestation = parse_global_history_attestation_bytes(
                        response.global_history_attestation.as_slice(),
                        Some(authority),
                    )?
                    .ok_or_else(|| {
                        Error::Parse(
                            "revoked leaves response missing global_history_attestation"
                                .to_string(),
                        )
                    })?;
                    if attestation.history_commitment != history_commitment {
                        return Err(Error::Parse(
                            "revoked leaves response global_history_attestation commitment mismatch"
                                .to_string(),
                        ));
                    }
                    validate_local_history_attestation_kind(
                        Some(history_authority_extension),
                        &attestation,
                        "revoked leaves response",
                    )?;
                    verify_deployment_profile_manifest(
                        response.deployment_profile_manifest.as_slice(),
                        authority,
                        history_authority_extension,
                        DeploymentProfileManifestContext {
                            gid: &gid,
                            profile_version: response.profile_version.as_str(),
                            n_max,
                            max_barrier_update_bytes: response.max_barrier_update_bytes,
                            fs_forward_leap_policy: &fs_forward_leap_policy,
                            context: "revoked leaves response",
                        },
                    )?;
                    Some(attestation)
                }
                None => {
                    if !response.global_history_attestation.is_empty()
                        || !response.helper_completeness_attestation.is_empty()
                        || !response.deployment_profile_manifest.is_empty()
                    {
                        return Err(Error::Parse(
                            "revoked leaves response carries history extension bytes without authority descriptor"
                                .to_string(),
                        ));
                    }
                    None
                }
            };
            if let Some(authority) = history_authority.as_ref() {
                let attestation = parse_helper_completeness_attestation_bytes(
                    response.helper_completeness_attestation.as_slice(),
                    authority,
                    HELPER_KIND_REVOKED_LEAVES,
                )?
                .ok_or_else(|| {
                    Error::Parse(
                        "revoked leaves response missing helper_completeness_attestation"
                            .to_string(),
                    )
                })?;
                verify_revoked_leaves_completeness_attestation(
                    &attestation,
                    authority,
                    &history_commitment,
                    revocation_roots_hash,
                    response.page_offset,
                    response.total_entries,
                    response.leaf_indices.as_slice(),
                )?;
            }
            let total_entries = parse_barrier_helper_total_entries(response.total_entries)?;
            ensure_barrier_helper_history_page(
                &mut expected_history,
                history_view_id,
                history_commitment,
                total_entries,
            )?;
            match expected_extension {
                Some(expected) if expected != history_authority_extension => {
                    return Err(Error::Parse(
                        "revoked leaves response history authority extension mismatch across pages"
                            .to_string(),
                    ));
                }
                None => expected_extension = Some(history_authority_extension),
                _ => {}
            }
            match (&expected_authority, &history_authority) {
                (Some(expected), Some(actual)) if expected != actual => {
                    return Err(Error::Parse(
                        "revoked leaves response history authority mismatch across pages"
                            .to_string(),
                    ));
                }
                (None, Some(actual)) => expected_authority = Some(actual.clone()),
                _ => {}
            }
            match (&expected_global_attestation, &global_history_attestation) {
                (Some(expected), Some(actual)) if expected != actual => {
                    return Err(Error::Parse(
                        "revoked leaves response global history attestation mismatch across pages"
                            .to_string(),
                    ));
                }
                (None, Some(actual)) => expected_global_attestation = Some(actual.clone()),
                _ => {}
            }
            match &expected_deployment_profile_manifest {
                Some(expected)
                    if expected.as_slice() != response.deployment_profile_manifest.as_slice() =>
                {
                    return Err(Error::Parse(
                        "revoked leaves response deployment_profile_manifest mismatch across pages"
                            .to_string(),
                    ));
                }
                None => {
                    expected_deployment_profile_manifest =
                        Some(response.deployment_profile_manifest.clone())
                }
                _ => {}
            }
            leaf_indices.extend(response.leaf_indices);
            match response.next_page_offset {
                Some(next_page_offset) => {
                    if next_page_offset <= page_offset
                        || usize::try_from(next_page_offset).map_err(|_| {
                            Error::Parse(
                                "barrier helper pagination next_page_offset overflow".to_string(),
                            )
                        })? != leaf_indices.len()
                    {
                        return Err(Error::Parse(
                            "barrier helper pagination next_page_offset mismatch".to_string(),
                        ));
                    }
                    page_offset = next_page_offset;
                }
                None => break,
            }
        }

        let (history_view_id, history_commitment, total_entries) =
            expected_history.ok_or_else(|| {
                Error::Parse("barrier helper pagination missing first page".to_string())
            })?;
        if leaf_indices.len() != total_entries {
            return Err(Error::Parse(
                "barrier helper pagination truncated revoked leaves".to_string(),
            ));
        }
        Ok(BarrierResolvedRevokedLeaves {
            history_view_id,
            history_commitment,
            history_authority_extension: expected_extension,
            history_authority: expected_authority,
            global_history_attestation: expected_global_attestation,
            leaf_indices,
        })
    }

    /// Resolves join records that became active after `prev_barrier_version`.
    pub async fn barrier_resolve_joins_since(
        &self,
        room_id: &str,
        prev_barrier_version: u64,
    ) -> Result<BarrierResolvedJoins, Error> {
        let gid = parse_room_id_gid(room_id)?;
        let mut page_offset = 0u32;
        let mut expected_history = None;
        let mut expected_extension: Option<HistoryAuthorityExtension> = None;
        let mut expected_authority: Option<HistoryAuthorityDescriptor> = None;
        let mut expected_global_attestation: Option<GlobalHistoryAttestation> = None;
        let mut expected_deployment_profile_manifest: Option<Vec<u8>> = None;
        let mut records = Vec::new();

        loop {
            let request = BarrierResolveJoinsSinceRequest {
                room_id: room_id.to_string(),
                prev_barrier_version,
                page_offset,
                max_entries: MAX_BARRIER_HELPER_PAGE_ENTRIES,
            };
            let response: BarrierResolveJoinsSinceResponse = self
                .post_proto("/v1/barrier/resolve_joins_since", request)
                .await?;
            if response.page_offset != page_offset {
                return Err(Error::Parse(
                    "barrier helper pagination page_offset mismatch".to_string(),
                ));
            }
            if response.records.len() > MAX_BARRIER_HELPER_PAGE_ENTRIES as usize {
                return Err(Error::Parse(
                    "barrier helper pagination page too large".to_string(),
                ));
            }
            let history_view_id = array32(&response.history_view_id)?;
            let history_commitment =
                parse_history_commitment(history_view_id, response.history_commitment)?;
            ensure_profile_version(&response.profile_version)?;
            let n_max = validate_barrier_n_max(response.n_max)?;
            let fs_forward_leap_policy =
                parse_fs_forward_leap_policy(response.fs_forward_leap_policy)?;
            let history_authority_extension =
                require_base_profile_global_history_authority_extension(
                    parse_history_authority_extension(
                        response.history_authority_extension.as_str(),
                        !response.history_authority_descriptor.is_empty()
                            || !response.global_history_attestation.is_empty()
                            || !response.helper_completeness_attestation.is_empty()
                            || !response.deployment_profile_manifest.is_empty(),
                    )?,
                    "joins since response",
                )?;
            let history_authority = parse_history_authority_descriptor_bytes(
                response.history_authority_descriptor.as_slice(),
            )?;
            require_history_authority_descriptor_for_extension(
                Some(history_authority_extension),
                &history_authority,
                "joins since response",
            )?;
            let page_records = response
                .records
                .iter()
                .map(|record| BarrierJoinRecord {
                    device_pk: record.device_pk.clone(),
                    leaf_index: record.leaf_index,
                    ek_leaf: record.ek_leaf.clone(),
                })
                .collect::<Vec<_>>();
            let global_history_attestation = match history_authority.as_ref() {
                Some(authority) => {
                    let attestation = parse_global_history_attestation_bytes(
                        response.global_history_attestation.as_slice(),
                        Some(authority),
                    )?
                    .ok_or_else(|| {
                        Error::Parse(
                            "joins since response missing global_history_attestation".to_string(),
                        )
                    })?;
                    if attestation.history_commitment != history_commitment {
                        return Err(Error::Parse(
                            "joins since response global_history_attestation commitment mismatch"
                                .to_string(),
                        ));
                    }
                    validate_local_history_attestation_kind(
                        Some(history_authority_extension),
                        &attestation,
                        "joins since response",
                    )?;
                    verify_deployment_profile_manifest(
                        response.deployment_profile_manifest.as_slice(),
                        authority,
                        history_authority_extension,
                        DeploymentProfileManifestContext {
                            gid: &gid,
                            profile_version: response.profile_version.as_str(),
                            n_max,
                            max_barrier_update_bytes: response.max_barrier_update_bytes,
                            fs_forward_leap_policy: &fs_forward_leap_policy,
                            context: "joins since response",
                        },
                    )?;
                    let helper_attestation = parse_helper_completeness_attestation_bytes(
                        response.helper_completeness_attestation.as_slice(),
                        authority,
                        HELPER_KIND_JOINS_SINCE,
                    )?
                    .ok_or_else(|| {
                        Error::Parse(
                            "joins since response missing helper_completeness_attestation"
                                .to_string(),
                        )
                    })?;
                    verify_joins_since_completeness_attestation(
                        &helper_attestation,
                        authority,
                        &history_commitment,
                        prev_barrier_version,
                        response.page_offset,
                        response.total_entries,
                        page_records.as_slice(),
                    )?;
                    Some(attestation)
                }
                None => {
                    if !response.global_history_attestation.is_empty()
                        || !response.helper_completeness_attestation.is_empty()
                        || !response.deployment_profile_manifest.is_empty()
                    {
                        return Err(Error::Parse(
                            "joins since response carries history extension bytes without authority descriptor"
                                .to_string(),
                        ));
                    }
                    None
                }
            };
            let total_entries = parse_barrier_helper_total_entries(response.total_entries)?;
            ensure_barrier_helper_history_page(
                &mut expected_history,
                history_view_id,
                history_commitment,
                total_entries,
            )?;
            match expected_extension {
                Some(expected) if expected != history_authority_extension => {
                    return Err(Error::Parse(
                        "joins since response history authority extension mismatch across pages"
                            .to_string(),
                    ));
                }
                None => expected_extension = Some(history_authority_extension),
                _ => {}
            }
            match (&expected_authority, &history_authority) {
                (Some(expected), Some(actual)) if expected != actual => {
                    return Err(Error::Parse(
                        "joins since response history authority mismatch across pages".to_string(),
                    ));
                }
                (None, Some(actual)) => expected_authority = Some(actual.clone()),
                _ => {}
            }
            match (&expected_global_attestation, &global_history_attestation) {
                (Some(expected), Some(actual)) if expected != actual => {
                    return Err(Error::Parse(
                        "joins since response global history attestation mismatch across pages"
                            .to_string(),
                    ));
                }
                (None, Some(actual)) => expected_global_attestation = Some(actual.clone()),
                _ => {}
            }
            match &expected_deployment_profile_manifest {
                Some(expected)
                    if expected.as_slice() != response.deployment_profile_manifest.as_slice() =>
                {
                    return Err(Error::Parse(
                        "joins since response deployment_profile_manifest mismatch across pages"
                            .to_string(),
                    ));
                }
                None => {
                    expected_deployment_profile_manifest =
                        Some(response.deployment_profile_manifest.clone())
                }
                _ => {}
            }
            records.extend(page_records);
            match response.next_page_offset {
                Some(next_page_offset) => {
                    if next_page_offset <= page_offset
                        || usize::try_from(next_page_offset).map_err(|_| {
                            Error::Parse(
                                "barrier helper pagination next_page_offset overflow".to_string(),
                            )
                        })? != records.len()
                    {
                        return Err(Error::Parse(
                            "barrier helper pagination next_page_offset mismatch".to_string(),
                        ));
                    }
                    page_offset = next_page_offset;
                }
                None => break,
            }
        }

        let (history_view_id, history_commitment, total_entries) =
            expected_history.ok_or_else(|| {
                Error::Parse("barrier helper pagination missing first page".to_string())
            })?;
        if records.len() != total_entries {
            return Err(Error::Parse(
                "barrier helper pagination truncated joins".to_string(),
            ));
        }
        Ok(BarrierResolvedJoins {
            history_view_id,
            history_commitment,
            history_authority_extension: expected_extension,
            history_authority: expected_authority,
            global_history_attestation: expected_global_attestation,
            records,
        })
    }

    /// Fetches a barrier public-tree snapshot for a committed tree hash.
    pub async fn barrier_fetch_public_tree(
        &self,
        room_id: &str,
        kem_tree_hash_after: &[u8; 32],
    ) -> Result<BarrierFetchedPublicTree, Error> {
        let gid = parse_room_id_gid(room_id)?;
        let mut entry_offset = 0u32;
        let mut expected_history = None;
        let mut expected_extension: Option<HistoryAuthorityExtension> = None;
        let mut expected_authority: Option<HistoryAuthorityDescriptor> = None;
        let mut expected_global_attestation: Option<GlobalHistoryAttestation> = None;
        let mut expected_deployment_profile_manifest: Option<Vec<u8>> = None;
        let mut expected_n_max = None;
        let mut expected_tree_hash = None;
        let mut expected_total_entries = None;
        let mut pk_entries = Vec::new();

        loop {
            let request = BarrierFetchPublicTreeRequest {
                room_id: room_id.to_string(),
                kem_tree_hash_after: kem_tree_hash_after.to_vec(),
                entry_offset,
                max_entries: MAX_BARRIER_HELPER_PAGE_ENTRIES,
            };
            let response: BarrierFetchPublicTreeResponse = self
                .post_proto("/v1/barrier/fetch_public_tree", request)
                .await?;
            if response.entry_offset != entry_offset {
                return Err(Error::Parse(
                    "barrier helper pagination entry_offset mismatch".to_string(),
                ));
            }
            if response.pk_entries.len() > MAX_BARRIER_HELPER_PAGE_ENTRIES as usize {
                return Err(Error::Parse(
                    "barrier helper pagination page too large".to_string(),
                ));
            }
            let n_max = validate_barrier_n_max(response.n_max)?;
            let history_view_id = array32(&response.history_view_id)?;
            let history_commitment =
                parse_history_commitment(history_view_id, response.history_commitment)?;
            ensure_profile_version(&response.profile_version)?;
            let fs_forward_leap_policy =
                parse_fs_forward_leap_policy(response.fs_forward_leap_policy)?;
            let history_authority_extension =
                require_base_profile_global_history_authority_extension(
                    parse_history_authority_extension(
                        response.history_authority_extension.as_str(),
                        !response.history_authority_descriptor.is_empty()
                            || !response.global_history_attestation.is_empty()
                            || !response.helper_completeness_attestation.is_empty()
                            || !response.deployment_profile_manifest.is_empty(),
                    )?,
                    "fetch public tree response",
                )?;
            let history_authority = parse_history_authority_descriptor_bytes(
                response.history_authority_descriptor.as_slice(),
            )?;
            require_history_authority_descriptor_for_extension(
                Some(history_authority_extension),
                &history_authority,
                "fetch public tree response",
            )?;
            let response_tree_hash = array32(&response.kem_tree_hash_after)?;
            if response_tree_hash != *kem_tree_hash_after {
                return Err(Error::Parse(
                    "fetch public tree response tree hash mismatch with requested hash".to_string(),
                ));
            }
            let global_history_attestation = match history_authority.as_ref() {
                Some(authority) => {
                    let attestation = parse_global_history_attestation_bytes(
                        response.global_history_attestation.as_slice(),
                        Some(authority),
                    )?
                    .ok_or_else(|| {
                        Error::Parse(
                            "fetch public tree response missing global_history_attestation"
                                .to_string(),
                        )
                    })?;
                    if attestation.history_commitment != history_commitment {
                        return Err(Error::Parse(
                            "fetch public tree response global_history_attestation commitment mismatch"
                                .to_string(),
                        ));
                    }
                    if attestation.kem_tree_hash_after != response_tree_hash {
                        return Err(Error::Parse(
                            "fetch public tree response global_history_attestation tree hash mismatch"
                                .to_string(),
                        ));
                    }
                    validate_local_history_attestation_kind(
                        Some(history_authority_extension),
                        &attestation,
                        "fetch public tree response",
                    )?;
                    verify_deployment_profile_manifest(
                        response.deployment_profile_manifest.as_slice(),
                        authority,
                        history_authority_extension,
                        DeploymentProfileManifestContext {
                            gid: &gid,
                            profile_version: response.profile_version.as_str(),
                            n_max,
                            max_barrier_update_bytes: response.max_barrier_update_bytes,
                            fs_forward_leap_policy: &fs_forward_leap_policy,
                            context: "fetch public tree response",
                        },
                    )?;
                    let helper_attestation = parse_helper_completeness_attestation_bytes(
                        response.helper_completeness_attestation.as_slice(),
                        authority,
                        HELPER_KIND_FETCH_PUBLIC_TREE,
                    )?
                    .ok_or_else(|| {
                        Error::Parse(
                            "fetch public tree response missing helper_completeness_attestation"
                                .to_string(),
                        )
                    })?;
                    verify_fetch_public_tree_completeness_attestation(
                        &helper_attestation,
                        authority,
                        &history_commitment,
                        &response_tree_hash,
                        response.entry_offset,
                        response.total_entries,
                        response.pk_entries.as_slice(),
                    )?;
                    Some(attestation)
                }
                None => {
                    if !response.global_history_attestation.is_empty()
                        || !response.helper_completeness_attestation.is_empty()
                        || !response.deployment_profile_manifest.is_empty()
                    {
                        return Err(Error::Parse(
                            "fetch public tree response carries history extension bytes without authority descriptor"
                                .to_string(),
                        ));
                    }
                    None
                }
            };
            let total_entries = parse_barrier_helper_total_entries(response.total_entries)?;
            ensure_barrier_helper_history_page(
                &mut expected_history,
                history_view_id,
                history_commitment,
                total_entries,
            )?;
            match expected_extension {
                Some(expected) if expected != history_authority_extension => {
                    return Err(Error::Parse(
                        "fetch public tree response history authority extension mismatch across pages"
                            .to_string(),
                    ));
                }
                None => expected_extension = Some(history_authority_extension),
                _ => {}
            }
            match expected_n_max {
                Some(expected) if expected != n_max => {
                    return Err(Error::Parse(
                        "barrier helper pagination n_max mismatch".to_string(),
                    ));
                }
                None => expected_n_max = Some(n_max),
                _ => {}
            }
            match expected_tree_hash {
                Some(expected) if expected != response_tree_hash => {
                    return Err(Error::Parse(
                        "barrier helper pagination tree hash mismatch".to_string(),
                    ));
                }
                None => expected_tree_hash = Some(response_tree_hash),
                _ => {}
            }
            let expected_tree_entries = usize::try_from(n_max)
                .map_err(|_| Error::Parse("barrier n_max too large".to_string()))?
                .checked_mul(2)
                .and_then(|value| value.checked_sub(1))
                .ok_or_else(|| Error::Parse("barrier tree size overflow".to_string()))?;
            match expected_total_entries {
                Some(expected) if expected != total_entries => {
                    return Err(Error::Parse(
                        "barrier helper pagination total_entries mismatch".to_string(),
                    ));
                }
                None => expected_total_entries = Some(total_entries),
                _ => {}
            }
            if total_entries != expected_tree_entries {
                return Err(Error::Parse(
                    "barrier helper pagination total_entries does not match n_max".to_string(),
                ));
            }
            match (&expected_authority, &history_authority) {
                (Some(expected), Some(actual)) if expected != actual => {
                    return Err(Error::Parse(
                        "fetch public tree response history authority mismatch across pages"
                            .to_string(),
                    ));
                }
                (None, Some(actual)) => expected_authority = Some(actual.clone()),
                _ => {}
            }
            match (&expected_global_attestation, &global_history_attestation) {
                (Some(expected), Some(actual)) if expected != actual => {
                    return Err(Error::Parse(
                        "fetch public tree response global history attestation mismatch across pages"
                            .to_string(),
                    ));
                }
                (None, Some(actual)) => expected_global_attestation = Some(actual.clone()),
                _ => {}
            }
            match &expected_deployment_profile_manifest {
                Some(expected)
                    if expected.as_slice() != response.deployment_profile_manifest.as_slice() =>
                {
                    return Err(Error::Parse(
                        "fetch public tree response deployment_profile_manifest mismatch across pages"
                            .to_string(),
                    ));
                }
                None => {
                    expected_deployment_profile_manifest =
                        Some(response.deployment_profile_manifest.clone())
                }
                _ => {}
            }
            pk_entries.extend(response.pk_entries);
            match response.next_entry_offset {
                Some(next_entry_offset) => {
                    if next_entry_offset <= entry_offset
                        || usize::try_from(next_entry_offset).map_err(|_| {
                            Error::Parse(
                                "barrier helper pagination next_entry_offset overflow".to_string(),
                            )
                        })? != pk_entries.len()
                    {
                        return Err(Error::Parse(
                            "barrier helper pagination next_entry_offset mismatch".to_string(),
                        ));
                    }
                    entry_offset = next_entry_offset;
                }
                None => break,
            }
        }

        let (history_view_id, history_commitment, total_entries) =
            expected_history.ok_or_else(|| {
                Error::Parse("barrier helper pagination missing first page".to_string())
            })?;
        if pk_entries.len() != total_entries {
            return Err(Error::Parse(
                "barrier helper pagination truncated tree snapshot".to_string(),
            ));
        }
        Ok(BarrierFetchedPublicTree {
            history_view_id,
            history_commitment,
            history_authority_extension: expected_extension,
            history_authority: expected_authority,
            global_history_attestation: expected_global_attestation,
            tree: BarrierPublicTree {
                n_max: expected_n_max.ok_or_else(|| {
                    Error::Parse("barrier helper pagination missing n_max".to_string())
                })?,
                kem_tree_hash_after: expected_tree_hash.ok_or_else(|| {
                    Error::Parse("barrier helper pagination missing tree hash".to_string())
                })?,
                pk_entries,
            },
        })
    }

    /// Looks up authenticated acceptance status for a persisted pending merge locator.
    pub async fn barrier_lookup_merge_acceptance(
        &self,
        room_id: &str,
        pending_barrier_version: u64,
        pending_barrier_update_digest: &[u8; 32],
        pending_we_epoch_id: &[u8; 32],
    ) -> Result<MergeAcceptanceLookup, Error> {
        let gid = parse_room_id_gid(room_id)?;
        let request = BarrierLookupMergeAcceptanceRequest {
            room_id: room_id.to_string(),
            pending_barrier_version,
            pending_barrier_update_digest: pending_barrier_update_digest.to_vec(),
            pending_we_epoch_id: pending_we_epoch_id.to_vec(),
        };
        let response: BarrierLookupMergeAcceptanceResponse = self
            .post_proto("/v1/barrier/lookup_merge_acceptance", request)
            .await?;
        let history_view_id = array32(&response.history_view_id)?;
        let history_commitment =
            parse_history_commitment(history_view_id, response.history_commitment)?;
        ensure_profile_version(&response.profile_version)?;
        let n_max = validate_barrier_n_max(response.n_max)?;
        let fs_forward_leap_policy = parse_fs_forward_leap_policy(response.fs_forward_leap_policy)?;
        let history_authority_extension = require_base_profile_global_history_authority_extension(
            parse_history_authority_extension(
                response.history_authority_extension.as_str(),
                !response.history_authority_descriptor.is_empty()
                    || !response.global_history_attestation.is_empty()
                    || !response.deployment_profile_manifest.is_empty(),
            )?,
            "lookup merge acceptance",
        )?;
        let history_authority = parse_history_authority_descriptor_bytes(
            response.history_authority_descriptor.as_slice(),
        )?;
        require_history_authority_descriptor_for_extension(
            Some(history_authority_extension),
            &history_authority,
            "lookup merge acceptance",
        )?;
        let global_history_attestation = match history_authority.as_ref() {
            Some(authority) => {
                let attestation = parse_global_history_attestation_bytes(
                    response.global_history_attestation.as_slice(),
                    Some(authority),
                )?
                .ok_or_else(|| {
                    Error::Parse(
                        "lookup merge acceptance missing global_history_attestation".to_string(),
                    )
                })?;
                if attestation.history_commitment != history_commitment {
                    return Err(Error::Parse(
                        "lookup merge acceptance global_history_attestation commitment mismatch"
                            .to_string(),
                    ));
                }
                validate_local_history_attestation_kind(
                    Some(history_authority_extension),
                    &attestation,
                    "lookup merge acceptance",
                )?;
                verify_deployment_profile_manifest(
                    response.deployment_profile_manifest.as_slice(),
                    authority,
                    history_authority_extension,
                    DeploymentProfileManifestContext {
                        gid: &gid,
                        profile_version: response.profile_version.as_str(),
                        n_max,
                        max_barrier_update_bytes: response.max_barrier_update_bytes,
                        fs_forward_leap_policy: &fs_forward_leap_policy,
                        context: "lookup merge acceptance",
                    },
                )?;
                Some(attestation)
            }
            None => {
                if !response.global_history_attestation.is_empty()
                    || !response.deployment_profile_manifest.is_empty()
                {
                    return Err(Error::Parse(
                        "lookup merge acceptance carries history extension bytes without authority descriptor"
                            .to_string(),
                    ));
                }
                None
            }
        };
        Ok(MergeAcceptanceLookup {
            status: parse_merge_acceptance_status(response.status)?,
            history_view_id,
            history_commitment,
            history_authority_extension: Some(history_authority_extension),
            history_authority,
            global_history_attestation,
            accepted_barrier_version: response.accepted_barrier_version,
            accepted_fs_ec: response.accepted_fs_ec,
            accepted_reason: response.accepted_reason,
            accepted_digest: optional_array32(response.accepted_digest)?,
        })
    }
}
