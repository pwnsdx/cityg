use super::*;

pub(super) struct BarrierMergePublishInputs<'a> {
    pub(super) mode: BarrierMergeMode,
    pub(super) client: &'a CitygApiClient,
    pub(super) persist_request: &'a LeaveRequest,
    pub(super) gid: &'a [u8; 32],
    pub(super) barrier_version: u64,
    pub(super) next_barrier_version: u64,
    pub(super) fs_ec: u64,
    pub(super) fs_dev_prev_commit: [u8; 32],
    pub(super) k_fs_current: &'a [u8; 32],
    pub(super) header: BTreeMap<u64, Value>,
    pub(super) cat_arr: [u8; 32],
    pub(super) parent_root_arr: [u8; 32],
    pub(super) params: OrchestrationParams<'a>,
    pub(super) parts: AnchorInstanceParts<'a>,
    pub(super) parities: &'a [PivotParity],
    pub(super) witness_bytes: Option<&'a [u8]>,
    pub(super) pivot: &'a PivotParity,
    pub(super) snapshot_hash: [u8; 32],
    pub(super) committed_revocation_roots_hash: [u8; 32],
    pub(super) revocation_roots_hash: [u8; 32],
    pub(super) ticket_history_commitment: HistoryCommitment,
    pub(super) ticket_history_authority_extension: Option<HistoryAuthorityExtension>,
    pub(super) current_global_history_attestation_bytes: Vec<u8>,
    pub(super) barrier_update: BarrierUpdateBuildResult,
    pub(super) forward_state: ForwardSecrecyState,
    pub(super) fs_forward_leap_policy: FsForwardLeapPolicy,
    pub(super) last_accepted_ec: u64,
}

#[derive(Clone)]
struct PreparedBarrierMerge {
    bundle: ClientEpochBundle,
    pending_barrier_state: BarrierPendingState,
    forward_state_after: ForwardSecrecyState,
}

pub(super) async fn publish_barrier_merge(
    inputs: BarrierMergePublishInputs<'_>,
) -> Result<PublishedBarrierMerge> {
    let BarrierMergePublishInputs {
        mode,
        client,
        persist_request,
        gid,
        barrier_version,
        next_barrier_version,
        fs_ec,
        fs_dev_prev_commit,
        k_fs_current,
        header,
        cat_arr,
        parent_root_arr,
        params,
        parts,
        parities,
        witness_bytes,
        pivot,
        snapshot_hash,
        committed_revocation_roots_hash,
        revocation_roots_hash,
        ticket_history_commitment,
        ticket_history_authority_extension,
        current_global_history_attestation_bytes,
        barrier_update,
        forward_state,
        fs_forward_leap_policy,
        last_accepted_ec,
    } = inputs;

    let pending_barrier_state = BarrierPendingState {
        barrier_version: next_barrier_version,
        we_epoch_id: [0u8; 32],
        fs_ec,
        next_forward_fs_ec: 0,
        next_forward_fs_dev_commit: [0u8; 32],
        next_forward_last_weid: [0u8; 32],
        revocation_roots_hash,
        kem_tree_hash_after: barrier_update.kem_tree_hash_after,
        k_barrier_new: barrier_update.k_barrier_new.clone(),
        k_fs_after_pcs: None,
        barrier_update_reason: Some(mode.reason()),
        barrier_update_digest: barrier_update.barrier_update_digest,
        on_path_key_material: barrier_update.on_path_key_material.clone(),
        activation_source: Some(BarrierPendingActivationSource {
            barrier_version,
            barrier_roots_hash: committed_revocation_roots_hash,
            kem_tree_hash_after: snapshot_hash,
            current_history_commitment: Some(ticket_history_commitment),
            current_history_authority_extension: ticket_history_authority_extension,
            current_global_history_attestation_bytes: current_global_history_attestation_bytes
                .clone(),
            fs_ec,
            fs_dev_prev_commit,
        }),
    };

    let pending_barrier_state_template = pending_barrier_state.clone();
    let build_published_merge = |mut forward_state: ForwardSecrecyState,
                                 disable_autonomic_evolve: bool|
     -> Result<PreparedBarrierMerge> {
        let mut bundle = if disable_autonomic_evolve {
            CityGClient::generate_merge_with_forward_state_without_evolve(
                header.clone(),
                parts.clone(),
                params.clone(),
                Some(&mut forward_state),
                parities,
                None,
                witness_bytes,
            )
        } else {
            CityGClient::generate_merge_with_forward_state(
                header.clone(),
                parts.clone(),
                params.clone(),
                Some(&mut forward_state),
                parities,
                None,
                witness_bytes,
            )
        }
        .context(mode.build_bundle_context())?;

        strip_rollup_metadata(&mut bundle.header_map);
        apply_pivot_alignment(&mut bundle.header_map, pivot);
        let anchor_ctx =
            build_anchor_seed_ctx(&bundle.header_map).context("compute anchor seed ctx")?;
        let seed_ctx_hash = compute_seed_ctx_hash(&anchor_ctx).context("compute seed_ctx_hash")?;
        let seed_commit = compute_seed_commit(
            &anchor_ctx,
            &SeedCommitFields {
                gid,
                cat: cat_arr.as_slice(),
                we_epoch_id: bundle.we_epoch_id,
            },
        )
        .context("compute seed_commit")?;
        let seed_bundle_commit = compute_seed_bundle_commit(
            &anchor_ctx,
            &bundle.hp_binding.rho_commit,
            gid,
            cat_arr.as_slice(),
            &parent_root_arr,
        )
        .context("compute seed_bundle_commit")?;
        let derived_we_epoch_id = derive_we_epoch_id(gid, &parent_root_arr, &seed_ctx_hash)
            .context("derive we_epoch_id")?;
        let observed_fs_ec = header_u64(&bundle.header_map, hdr::HDR_FS_EC)
            .ok_or_else(|| anyhow!("{} merge bundle missing fs_ec", mode.label()))?;
        let k_fs_after_pcs = if mode.reseeds_k_fs() {
            Some(derive_k_fs_after_pcs(
                k_fs_current,
                &derived_we_epoch_id,
                observed_fs_ec,
                next_barrier_version,
                &barrier_update.k_barrier_new,
            )?)
        } else {
            None
        };

        bundle.anchor.anchor_hdr_ctx = anchor_ctx.clone();
        bundle.hp_binding.seed_ctx_hash = seed_ctx_hash;
        bundle.hp_binding.seed_commit = seed_commit;
        bundle.hp_binding.seed_bundle_commit = seed_bundle_commit;
        bundle.we_epoch_id = derived_we_epoch_id;
        let has_local_hp_material =
            !bundle.hp_ciphertext.is_empty() && bundle.hp_aead_key != [0u8; 32];
        if has_local_hp_material {
            if mode.reason() == 2 {
                bundle
                    .seal_local_hp_header_with_barrier_key(&barrier_update.k_barrier_new)
                    .context(format!("seal merge HP envelope for {}", mode.label()))?;
            } else {
                bundle
                    .rebind_local_hp_envelope_with_barrier_key(&barrier_update.k_barrier_new)
                    .context(format!("rebind merge HP envelope for {}", mode.label()))?;
            }
        } else {
            return Err(anyhow!(
                "{} merge bundle missing local HP material",
                mode.label()
            ));
        }
        let mut pending_barrier_state = pending_barrier_state_template.clone();
        pending_barrier_state.we_epoch_id = bundle.we_epoch_id;
        pending_barrier_state.fs_ec = observed_fs_ec;
        let next_forward = forward_state.snapshot();
        pending_barrier_state.next_forward_fs_ec = next_forward.fs_ec;
        pending_barrier_state.next_forward_fs_dev_commit = next_forward.fs_dev_commit;
        pending_barrier_state.next_forward_last_weid = next_forward.last_weid;
        if let Some(k_fs_after_pcs) = k_fs_after_pcs {
            pending_barrier_state.k_fs_after_pcs = Some(Zeroizing::new(k_fs_after_pcs));
        }
        bundle
            .header_map
            .insert(hdr::HDR_SEED_CTX_HASH, Value::Bytes(seed_ctx_hash.to_vec()));
        bundle.header_map.insert(
            hdr::HDR_RHO_COMMIT,
            Value::Bytes(bundle.hp_binding.rho_commit.to_vec()),
        );
        bundle.header_map.insert(
            hdr::HDR_SEED_BUNDLE_COMMIT,
            Value::Bytes(seed_bundle_commit.to_vec()),
        );

        if let Some(commit) = recompute_srx_commit(&bundle.header_map)? {
            bundle
                .header_map
                .insert(hdr::HDR_SRX_COMMIT, Value::Bytes(commit.to_vec()));
        }

        if let Some(recomputed) = recompute_proofs_commit(&bundle.header_map)
            .ok()
            .map(|arr| arr.to_vec())
        {
            bundle
                .header_map
                .insert(hdr::HDR_PROOFS_COMMIT, Value::Bytes(recomputed));
        }

        Ok(PreparedBarrierMerge {
            bundle,
            pending_barrier_state,
            forward_state_after: forward_state,
        })
    };

    let pristine_forward_state = forward_state.clone();
    let mut prepared = build_published_merge(forward_state, false)?;

    persist_pending_barrier_state_before_publish(
        persist_request,
        prepared.pending_barrier_state.clone(),
    )?;

    #[cfg(test)]
    if mode == BarrierMergeMode::JoinFinalize {
        fault_injection::trigger_fault(FaultInjectionCutPoint::BeforePublishJoinFinalize, None)?;
    }

    match client.refresh_pivot(&prepared.bundle).await {
        Ok(_) => {}
        Err(ApiClientError::HttpStatus {
            status, message, ..
        }) if is_refresh_pivot_conflict(status.as_u16(), &message) => {
            debug!(status = status.as_u16(), "refresh pivot skipped: {message}");
        }
        Err(err) => return Err(err).context("refresh pivot parity"),
    }

    match client.accept_epoch_bundle(&prepared.bundle).await {
        Ok(_) => {}
        Err(ApiClientError::HttpStatus {
            freeze_code,
            freeze_reason,
            ..
        }) if is_fs_forward_jump_group_http_error(freeze_code, freeze_reason.as_deref()) => {
            prepared = build_published_merge(pristine_forward_state, true)?;
            persist_pending_barrier_state_before_publish(
                persist_request,
                prepared.pending_barrier_state.clone(),
            )?;
            match client.refresh_pivot(&prepared.bundle).await {
                Ok(_) => {}
                Err(ApiClientError::HttpStatus {
                    status, message, ..
                }) if is_refresh_pivot_conflict(status.as_u16(), &message) => {
                    debug!(
                        status = status.as_u16(),
                        "refresh pivot skipped after stale-group retry: {message}"
                    );
                }
                Err(err) => {
                    return Err(err).context("refresh pivot parity after stale-group retry");
                }
            }
            client
                .accept_epoch_bundle(&prepared.bundle)
                .await
                .context(mode.accept_bundle_context())?;
        }
        Err(err) => return Err(err).context(mode.accept_bundle_context()),
    }

    Ok(PublishedBarrierMerge {
        bundle: prepared.bundle,
        pending_barrier_state: prepared.pending_barrier_state,
        pre_publish_barrier_version: barrier_version,
        pre_publish_barrier_roots_hash: committed_revocation_roots_hash,
        pre_publish_kem_tree_hash_after: snapshot_hash,
        pre_publish_current_history_commitment: ticket_history_commitment,
        pre_publish_current_history_authority_extension: ticket_history_authority_extension,
        pre_publish_current_global_history_attestation_bytes:
            current_global_history_attestation_bytes,
        forward_state_after: prepared.forward_state_after,
        fs_forward_leap_policy,
        last_accepted_ec,
        current_public_tree: barrier_update.snapshot_post.clone(),
    })
}
