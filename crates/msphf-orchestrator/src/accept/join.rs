//! Join acceptance path: apply structural gates, FLG caps, and proof verification.

use std::sync::Arc;

use crate::proofs::capss;

use super::*;

impl AcceptanceContext {
    pub(crate) fn accept_anchor_join(
        &mut self,
        parts: &AnchorInstanceParts<'_>,
        we_epoch_id_claim: [u8; 32],
        header_map: &BTreeMap<u64, Value>,
        mh_note: Option<String>,
        barrier_update_digest: [u8; 32],
        now: AcceptInstant,
    ) -> Result<AcceptanceOutcome, AcceptanceError> {
        ensure_tswe_alg(header_map)?;
        ensure_merkle_suite(header_map)?;
        self.ensure_crs_id(header_map)?;
        ensure_kbroad_alg(header_map)?;
        self.ensure_kbroad_pub(parts.gid, header_map)?;
        self.ensure_params_id(header_map)?;
        ensure_join_srx_keys_absent(header_map)?;
        let Some(Value::Bytes(barrier_leaf_pk)) = header_map.get(&HDR_BARRIER_LEAF_PK) else {
            return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
        };
        if barrier_leaf_pk.len() != BARRIER_LEAF_PUBLIC_KEY_BYTES {
            return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
        }

        let parent_root = header_bytes32_or_freeze(
            header_map,
            HDR_PARENT_ROOT,
            FREEZE_FIELD_MISSING,
            "parent_root",
        )?;
        if parts.parent_root != parent_root.as_slice() {
            return Err(AcceptanceError::Freeze(FREEZE_FIELD_MISSING));
        }
        let join_delta_root = header_bytes32_or_freeze(
            header_map,
            HDR_JOIN_DELTA_ROOT,
            FREEZE_FIELD_MISSING,
            "join_delta_root",
        )?;
        if parts.join_delta_root != join_delta_root.as_slice() {
            return Err(AcceptanceError::Freeze(FREEZE_FIELD_MISSING));
        }
        let revoked_since_root = header_bytes32_or_freeze(
            header_map,
            112,
            FREEZE_FIELD_MISSING,
            "revoked_since_prev_root",
        )?;
        if parts.revoked_since_prev_root != revoked_since_root.as_slice() {
            return Err(AcceptanceError::Freeze(FREEZE_FIELD_MISSING));
        }
        let revoked_root = header_bytes32_or_freeze(
            header_map,
            HDR_REVOKED_ROOT,
            FREEZE_FIELD_MISSING,
            "revoked_root",
        )?;
        if parts.revoked_root != revoked_root.as_slice() {
            return Err(AcceptanceError::Freeze(FREEZE_FIELD_MISSING));
        }

        let telemetry_key = self.telemetry_record_attempt(parts.gid, parts.parent_root);

        let rho_commit =
            header_bytes32_or_freeze(header_map, 93, FREEZE_RHO_PARITY, "msphf_kgen_rho_commit")?;
        if !self
            .rho_guard
            .record(parts.gid, parts.parent_root, &rho_commit, now)
        {
            self.telemetry_record_rho_freeze(&telemetry_key);
            return Err(AcceptanceError::Freeze(FREEZE_RHO_PARITY));
        }
        let provided_seed_ctx_hash = header_bytes32_or_freeze(
            header_map,
            91,
            FREEZE_SEEDCTX_MISMATCH,
            "msphf_seed_ctx_hash",
        )?;
        let hp_commit =
            header_bytes32_or_freeze(header_map, 99, FREEZE_FIELD_MISSING, "msphf_hp_commit")?;

        let anchor_seed_ctx = build_anchor_seed_ctx(header_map)?;
        let seed_ctx_hash = compute_seed_ctx_hash(&anchor_seed_ctx)?;
        if seed_ctx_hash != provided_seed_ctx_hash {
            return Err(AcceptanceError::Freeze(FREEZE_SEEDCTX_MISMATCH));
        }

        let provided_seed_bundle = header_bytes32_or_freeze(
            header_map,
            94,
            FREEZE_SEEDCTX_MISMATCH,
            "seed_bundle_commit",
        )?;
        let expected_seed_bundle = compute_seed_bundle_commit(
            &anchor_seed_ctx,
            &rho_commit,
            parts.gid,
            parts.cat,
            &parent_root,
        )?;
        if expected_seed_bundle != provided_seed_bundle {
            return Err(AcceptanceError::Freeze(FREEZE_SEEDCTX_MISMATCH));
        }

        let pop_pk_bytes = header_bytes_or_freeze(header_map, HDR_POP_PK, "pop_public_key")?;
        #[allow(unused_assignments)]
        let mut fs_epoch_commit_opt: Option<[u8; 32]> = None;
        #[allow(unused_assignments)]
        let mut fs_ec_opt: Option<u64> = None;
        #[allow(unused_assignments)]
        #[allow(unused_assignments)]
        let mut fs_dev_commit_opt: Option<[u8; 32]> = None;
        #[allow(unused_assignments)]
        let mut fs_dev_prev_commit_opt: Option<[u8; 32]> = None;
        let barrier_version: u64;

        {
            let _ = header_map
                .get(&HDR_FS_EC)
                .ok_or(AcceptanceError::Freeze(FREEZE_FS_JOIN_MISSING))?;

            let fs_policy_version = match header_map.get(&HDR_FS_POLICY_VERSION) {
                Some(Value::Integer(int)) => u64::try_from(*int)
                    .map_err(|_| AcceptanceError::Freeze(FREEZE_FS_JOIN_MISSING))?,
                Some(_) => return Err(AcceptanceError::Freeze(FREEZE_FS_JOIN_MISSING)),
                None => return Err(AcceptanceError::Freeze(FREEZE_FS_JOIN_MISSING)),
            };
            let fs_policy_version_str = fs_policy_version.to_string();
            self.ensure_fs_policy_version_allowed(&fs_policy_version_str)?;
            if self
                .fs_policy_version()
                .is_some_and(|existing| existing != fs_policy_version_str)
            {
                return Err(AcceptanceError::Freeze(
                    FREEZE_FS_POLICY_VERSION_UNSUPPORTED,
                ));
            }
            self.set_fs_policy_version(Some(fs_policy_version_str.clone()));

            let fs_ec =
                header_u64_or_freeze(header_map, HDR_FS_EC, FREEZE_FS_JOIN_MISSING, "fs_ec")?;
            let fs_epoch_commit = header_bytes32_or_freeze(
                header_map,
                HDR_FS_EPOCH_COMMIT,
                FREEZE_FS_JOIN_MISSING,
                "fs_epoch_commit",
            )?;
            let fs_base_ts_value = header_u64_or_freeze(
                header_map,
                HDR_FS_EPOCH_BASE_TS,
                FREEZE_FS_JOIN_MISSING,
                "fs_epoch_base_ts",
            )?;
            match self.fs_base_ts() {
                Some(stored) if stored != fs_base_ts_value => {
                    return Err(AcceptanceError::Freeze(FREEZE_FS_BASE_MISMATCH));
                }
                None => self.set_fs_base_ts(Some(fs_base_ts_value)),
                _ => {}
            }

            if self.fs_caps.window_periods == 0 {
                return Err(AcceptanceError::Freeze(
                    FREEZE_FS_POLICY_WINDOW_INCOMPATIBLE,
                ));
            }

            let fs_dev_prev_commit = header_bytes32_or_freeze(
                header_map,
                HDR_FS_DEV_PREV_COMMIT,
                FREEZE_FS_JOIN_MISSING,
                "fs_dev_prev_commit",
            )?;
            let fs_dev_commit = header_bytes32_or_freeze(
                header_map,
                HDR_FS_DEV_COMMIT,
                FREEZE_FS_JOIN_MISSING,
                "fs_dev_commit",
            )?;
            barrier_version = header_u64_or_freeze(
                header_map,
                HDR_BARRIER_VERSION,
                FREEZE_FS_JOIN_MISSING,
                "barrier_version",
            )?;

            let device_key_state = self.device_chain_get(parts.gid, &pop_pk_bytes);
            self.verify_device_chain_state(
                parts.gid,
                device_key_state,
                DeviceChainVerification {
                    pop_pk: &pop_pk_bytes,
                    fs_ec,
                    fs_dev_prev_commit: &fs_dev_prev_commit,
                    fs_dev_commit: &fs_dev_commit,
                    barrier_version,
                    barrier_update_digest: &barrier_update_digest,
                },
            )?;

            fs_epoch_commit_opt = Some(fs_epoch_commit);
            fs_ec_opt = Some(fs_ec);
            fs_dev_commit_opt = Some(fs_dev_commit);
            fs_dev_prev_commit_opt = Some(fs_dev_prev_commit);
        }

        let fs_epoch_commit =
            fs_epoch_commit_opt.ok_or(AcceptanceError::Freeze(FREEZE_FS_JOIN_MISSING))?;
        let fs_ec = fs_ec_opt.ok_or(AcceptanceError::Freeze(FREEZE_FS_JOIN_MISSING))?;
        let fs_dev_commit =
            fs_dev_commit_opt.ok_or(AcceptanceError::Freeze(FREEZE_FS_JOIN_MISSING))?;
        let fs_dev_prev_commit =
            fs_dev_prev_commit_opt.ok_or(AcceptanceError::Freeze(FREEZE_FS_JOIN_MISSING))?;

        fs_epoch_commit_opt = Some(fs_epoch_commit);
        fs_ec_opt = Some(fs_ec);
        fs_dev_commit_opt = Some(fs_dev_commit);

        if parts.tswe_salt_hash.len() != 32 {
            return Err(AcceptanceError::Freeze(FREEZE_FIELD_MISSING));
        }
        let expected_tswe_salt =
            msphf_core::instance::tswe_salt_hash(parts.gid, parent_root.as_slice())
                .map_err(AcceptanceError::from)?;
        if parts.tswe_salt_hash != expected_tswe_salt.as_slice() {
            return Err(AcceptanceError::Freeze(FREEZE_TSWE_SALT_MISMATCH));
        }

        let derived_we_epoch_id = derive_we_epoch_id(parts.gid, parts.parent_root, &seed_ctx_hash)?;
        if derived_we_epoch_id != we_epoch_id_claim {
            return Err(AcceptanceError::Freeze(FREEZE_EPOCHID_MISMATCH));
        }

        let seed_commit = compute_seed_commit(
            &anchor_seed_ctx,
            &SeedCommitFields {
                gid: parts.gid,
                cat: parts.cat,
                we_epoch_id: derived_we_epoch_id,
            },
        )?;

        let wid = compute_window_id(parts.gid, &parent_root, &seed_ctx_hash)
            .map_err(AcceptanceError::from)?;

        let anchor_instance = AnchorInstance {
            gid: parts.gid,
            cat: parts.cat,
            we_epoch_id: derived_we_epoch_id,
            anchor_hdr_ctx: anchor_seed_ctx.as_slice(),
            tswe_salt_hash: parts.tswe_salt_hash,
            parent_root: parts.parent_root,
            join_delta_root: parts.join_delta_root,
            revoked_since_prev_root: parts.revoked_since_prev_root,
            revoked_root: parts.revoked_root,
            pox_r_commit: parts.pox_r_commit,
            msphf_hp_commit: Some(&hp_commit),
        };

        let xk_hash = anchor_instance.xk_hash().map_err(AcceptanceError::from)?;
        let accept_seq = {
            let seq = self.next_accept_seq;
            self.next_accept_seq = self.next_accept_seq.wrapping_add(1);
            seq
        };

        let is_genesis = barrier_version == 0
            && is_all_zero(parts.parent_root)
            && is_all_zero(parts.revoked_since_prev_root)
            && is_all_zero(parts.revoked_root);

        if is_genesis {
            validate_bootstrap(
                header_map,
                &anchor_instance,
                &hp_commit,
                &seed_ctx_hash,
                &rho_commit,
                &provided_seed_bundle,
                self.bootstrap_policy.clone(),
            )?;
        } else {
            ensure_bootstrap_absent(header_map)?;
        }

        ensure_join_pop(header_map, &anchor_instance, self.leaf_id_mode)?;
        let pop_sig = extract_pop_signature(header_map)?;
        verify_join_payload_hp_envelope(
            self,
            header_map,
            None,
            crate::BARRIER_HP_CONTEXT_AUTHOR_LOCAL,
            &xk_hash,
            &hp_commit,
        )?;
        let proofs = ensure_proofs(
            header_map,
            self.allowed_proof_modes.as_ref(),
            &self.deprecated_proof_modes,
            self.allowed_vrf_ids.as_ref(),
            &self.deprecated_vrf_ids,
        )?;
        let pending_fs_witness = self.take_pending_capss_witness();
        let crs_id = header_string_or_freeze(header_map, 98)?;
        let params_id = header_string_or_freeze(header_map, 106)?;
        let capss_inputs = capss::Inputs {
            seed_commit: &seed_commit,
            seed_bundle_commit: &provided_seed_bundle,
            rho_commit: &rho_commit,
            hp_commit: &hp_commit,
            bind: capss::BindingInputs {
                xk_hash: &xk_hash,
                crs_id: crs_id.as_str(),
                params_id: params_id.as_str(),
                proof_mode: proofs.proof_mode.as_str(),
                fs_policy_version: proofs.fs_policy_version,
                vrf_id: proofs.vrf_id.as_str(),
                parent_root: parts.parent_root,
                join_delta_root: parts.join_delta_root,
                revoked_since_prev_root: parts.revoked_since_prev_root,
                revoked_root: parts.revoked_root,
                fs_epoch_commit: &fs_epoch_commit,
                fs_ec,
                fs_dev_prev_commit: &fs_dev_prev_commit,
                fs_dev_commit: &fs_dev_commit,
            },
        };
        let capss_proof = capss::Proof::from_bytes(proofs.fs_capss.clone())?;
        capss::verify(&capss_inputs, &capss_proof)?;
        let pop_alg = header_string_or_freeze(header_map, 107)?;
        let pop_pk = pop_pk_bytes.clone();
        let leaf_id = crate::compute_leaf_id(self.leaf_id_mode, parts.gid, &pop_alg, &pop_pk)
            .map_err(AcceptanceError::from)?;

        let expected_rho = derive_rho_commit_from_pop(&pop_sig, &xk_hash)?;
        if expected_rho != rho_commit {
            return Err(AcceptanceError::Freeze(FREEZE_CAPSS_INVALID));
        }

        if leaf_id.len() == 32 {
            let mut leaf_arr = [0u8; 32];
            leaf_arr.copy_from_slice(&leaf_id);
            if let Some(false) = srx_contains_leaf_id(header_map, &leaf_arr)? {
                return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
            }
        }

        let strict_inputs = CapssStrictInputs {
            crs_id: &crs_id,
            params_id: &params_id,
            seed_commit: &seed_commit,
            seed_ctx_hash: &seed_ctx_hash,
            xk_hash: &xk_hash,
            rho_commit: &rho_commit,
            pop_alg: &pop_alg,
            pop_pk: pop_pk.as_slice(),
            anchor: &anchor_instance,
            leaf_id: leaf_id.as_ref(),
            pop_sig,
        };
        let strict_witness = match recompute_capss_witness(strict_inputs) {
            Ok(w) => w,
            Err(MsphfError::WitnessReplayMismatch(_)) => {
                return Err(AcceptanceError::Freeze(FREEZE_CAPSS_INVALID));
            }
            Err(other) => return Err(AcceptanceError::from(other)),
        };
        if pending_fs_witness.is_some_and(|pending| pending != strict_witness) {
            return Err(AcceptanceError::Freeze(FREEZE_CAPSS_INVALID));
        }

        // Step 3 (spec §12.2): Verify proofs in order: Smallwood (FS) → VRF → SRX
        // VRF verification (output-hiding, binds hp_commit → Y* correctness)
        if proofs.vrf_pi.len() > MAX_VRF_PROOF_BYTES {
            return Err(AcceptanceError::Freeze(FREEZE_VRF_INVALID));
        }

        let vrf_ctx = VrfCtx {
            xk_hash: &xk_hash,
            rho_commit: &rho_commit,
            seed_bundle_commit: &provided_seed_bundle,
            crs_id: crs_id.as_str(),
            hp_commit: &hp_commit,
            params_id: params_id.as_str(),
            parent_root: parts.parent_root,
            join_delta_root: parts.join_delta_root,
            revoked_since_prev_root: parts.revoked_since_prev_root,
            revoked_root: parts.revoked_root,
            proof_mode: proofs.proof_mode.as_str(),
            profile_version: crate::BASE_PROFILE_VERSION,
            fs_policy_version: proofs.fs_policy_version,
            meor_vrf_id: proofs.vrf_id.as_str(),
            fs_epoch_commit: &fs_epoch_commit,
            fs_ec,
            fs_dev_prev_commit: &fs_dev_prev_commit,
            fs_dev_commit: &fs_dev_commit,
            srx_root_sw: None,
            we_epoch_id: &derived_we_epoch_id,
        };
        let vrf_public_payload = proofs.vrf_public.as_slice();

        let vrf_proof = VrfProof {
            bytes: proofs.vrf_pi.clone(),
        };
        match zk_vrf_impl::verify_result(
            vrf_public_payload,
            &vrf_ctx,
            (&proofs.mask_a, &proofs.mask_b),
            &vrf_proof,
        ) {
            Ok(true) => {}
            Ok(false) => {
                tracing::debug!(target = "accept", "vrf: proof mathematically invalid");
                return Err(AcceptanceError::Freeze(FREEZE_VRF_INVALID));
            }
            Err(err) => {
                tracing::debug!(target = "accept", vrf_error = %err, "vrf: verification error");
                return Err(AcceptanceError::Freeze(FREEZE_VRF_INVALID));
            }
        }

        let fresh_device_state = self.device_chain_get(parts.gid, &pop_pk_bytes);
        self.verify_device_chain_state(
            parts.gid,
            fresh_device_state,
            DeviceChainVerification {
                pop_pk: &pop_pk_bytes,
                fs_ec,
                fs_dev_prev_commit: &fs_dev_prev_commit,
                fs_dev_commit: &fs_dev_commit,
                barrier_version,
                barrier_update_digest: &barrier_update_digest,
            },
        )?;
        {
            let entry = self.device_chain_entry_mut(parts.gid, &pop_pk_bytes);
            entry.last_commit = Some(fs_dev_commit);
            entry.last_ec = fs_ec;
        }
        self.record_accepted_ec(parts.gid, fs_ec);

        let join_delta_root_arr = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(parts.join_delta_root);
            arr
        };
        let revoked_since_root_arr = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(parts.revoked_since_prev_root);
            arr
        };
        let revoked_root_arr = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(parts.revoked_root);
            arr
        };

        let record = HeadRecord::new(
            derived_we_epoch_id,
            hp_commit,
            seed_ctx_hash,
            rho_commit,
            seed_commit,
            xk_hash,
            join_delta_root_arr,
            revoked_since_root_arr,
            revoked_root_arr,
            accept_seq,
            now,
        );
        match self.accept_non_merge(&wid, record.clone(), now) {
            Ok(()) => {
                let active_heads = self.active_heads(&wid);
                self.telemetry_record_success(&telemetry_key, active_heads);
            }
            Err(err) => {
                if err == FreezeError::WINDOW_FULL {
                    self.telemetry_record_window_full(&telemetry_key);
                }
                return Err(AcceptanceError::Freeze(err));
            }
        }
        let crs_id =
            header_value_bytes(header_map, HDR_CRS_ID, FREEZE_MSPHF_CRS_INVALID)?.into_owned();
        let params_id =
            header_value_bytes(header_map, HDR_PARAMS_ID, FREEZE_PARAMS_ID_INVALID)?.into_owned();
        let srx_commit = match header_map.get(&HDR_SRX_COMMIT) {
            Some(Value::Bytes(bytes)) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                Some(arr)
            }
            Some(Value::Bytes(_)) | Some(_) => {
                return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
            }
            None => None,
        };

        let parity = PivotParity {
            gid: parts.gid.to_vec(),
            cat: parts.cat.to_vec(),
            parent_root,
            we_epoch_id: derived_we_epoch_id,
            rho_commit,
            seed_ctx_hash,
            seed_commit,
            hp_commit,
            xk_hash,
            join_delta_root: join_delta_root_arr,
            revoked_since_root: revoked_since_root_arr,
            revoked_root: revoked_root_arr,
            accept_seq,
            crs_id,
            params_id,
            policy_version: proofs.fs_policy_version.to_string(),
            proof_mode: proofs.proof_mode.clone(),
            vrf_id: proofs.vrf_id.clone(),
            vrf_proof: proofs.vrf_pi.clone(),
            vrf_public: proofs.vrf_public.clone(),
            mask_a: proofs.mask_a,
            mask_b: proofs.mask_b,
            fs_capss: proofs.fs_capss.clone(),
            proofs_commit: proofs.commit,
            srx_commit,
            srx_root_sw: self.group_srx_root_sw(parts.gid),
            is_join: true,
            hp_envelope: header_map
                .get(&HDR_HP_BYTES)
                .and_then(|value| to_cbor_vec(value).ok())
                .map(|bytes| Arc::from(bytes.into_boxed_slice()))
                .unwrap_or_else(|| Arc::from([] as [u8; 0])),
            fs_epoch_commit: fs_epoch_commit_opt,
            fs_ec: fs_ec_opt,
            fs_dev_commit: fs_dev_commit_opt,
        };
        self.pivot_store.insert(parity, now);

        Ok(AcceptanceOutcome {
            kind: AcceptanceKind::NonMerge,
            we_epoch_id: derived_we_epoch_id,
            wid,
            seed_ctx_hash,
            seed_commit,
            rho_commit,
            hp_commit,
            xk_hash,
            accept_seq,
            accept_time: now,
            mh_note,
            fs_epoch_commit: Some(fs_epoch_commit),
            fs_ec: Some(fs_ec),
            fs_dev_commit: Some(fs_dev_commit),
        })
    }
}
