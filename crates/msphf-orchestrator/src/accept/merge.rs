//! Merge acceptance path: validates purge metadata and checkpoint state.

use std::sync::Arc;

use super::*;
use tracing::debug;

impl AcceptanceContext {
    pub(crate) fn accept_anchor_merge(
        &mut self,
        parts: &AnchorInstanceParts<'_>,
        we_epoch_id_claim: [u8; 32],
        header_map: &BTreeMap<u64, Value>,
        mh_heads: Vec<[u8; 32]>,
        mh_note: Option<String>,
        now: AcceptInstant,
    ) -> Result<AcceptanceOutcome, AcceptanceError> {
        ensure_tswe_alg(header_map)?;
        ensure_merkle_suite(header_map)?;
        self.ensure_crs_id(header_map)?;
        ensure_kbroad_alg(header_map)?;
        self.ensure_kbroad_pub(parts.gid, header_map)?;
        self.ensure_params_id(header_map)?;
        ensure_merge_join_keys_absent(header_map)?;
        debug!("merge: join keys absent");

        if header_map.contains_key(&HDR_KBROAD_REPLAY) {
            return Err(AcceptanceError::Freeze(FREEZE_FS_KBROAD_PRESENT));
        }

        let fs_policy_version = match header_map.get(&HDR_FS_POLICY_VERSION) {
            Some(Value::Text(text)) => text.clone(),
            Some(Value::Integer(int)) => u64::try_from(*int)
                .map_err(|_| AcceptanceError::Freeze(FREEZE_FS_JOIN_MISSING))?
                .to_string(),
            Some(_) => return Err(AcceptanceError::Freeze(FREEZE_FS_JOIN_MISSING)),
            None => return Err(AcceptanceError::Freeze(FREEZE_FS_JOIN_MISSING)),
        };
        self.ensure_fs_policy_version_allowed(&fs_policy_version)?;
        if let Some(existing) = self.fs_policy_version() {
            if existing != fs_policy_version {
                return Err(AcceptanceError::Freeze(
                    FREEZE_FS_POLICY_VERSION_UNSUPPORTED,
                ));
            }
        } else {
            self.set_fs_policy_version(Some(fs_policy_version.clone()));
        }

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

        let fs_checkpoint_ec = header_u64_or_freeze(
            header_map,
            HDR_FS_CHECKPOINT_EC,
            FREEZE_FS_JOIN_MISSING,
            "fs_checkpoint_ec",
        )?;

        let fs_evolution_boundary = match header_map.get(&HDR_FS_EVOLUTION_BOUNDARY) {
            Some(Value::Bool(flag)) => *flag,
            Some(_) => return Err(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID)),
            None => return Err(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID)),
        };
        if !fs_evolution_boundary {
            return Err(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID));
        }

        match header_map.get(&HDR_ROLLUP_FS_MODE) {
            Some(Value::Text(mode)) if mode == "fs-purge" => {}
            _ => return Err(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID)),
        }
        debug!("merge: fs mode fs-purge confirmed");

        if header_map
            .get(&HDR_FS_PURGE_TIMES)
            .is_some_and(|value| !matches!(value, Value::Map(_)))
        {
            debug!("merge: fs_purge_times malformed CBOR");
            return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
        }
        debug!("merge: fs purge metadata ok");

        debug!("merge: extracting parent root");
        let parent_root =
            header_bytes32_or_freeze(header_map, 110, FREEZE_FIELD_MISSING, "parent_root")?;
        if parts.parent_root != parent_root.as_slice() {
            return Err(AcceptanceError::Freeze(FREEZE_FIELD_MISSING));
        }
        debug!("merge: parent root ok");
        let join_delta_root =
            header_bytes32_or_freeze(header_map, 111, FREEZE_FIELD_MISSING, "join_delta_root")?;
        if parts.join_delta_root != join_delta_root.as_slice() {
            return Err(AcceptanceError::Freeze(FREEZE_FIELD_MISSING));
        }
        debug!("merge: join delta root ok");
        let revoked_since_root = header_bytes32_or_freeze(
            header_map,
            112,
            FREEZE_FIELD_MISSING,
            "revoked_since_prev_root",
        )?;
        if parts.revoked_since_prev_root != revoked_since_root.as_slice() {
            return Err(AcceptanceError::Freeze(FREEZE_FIELD_MISSING));
        }
        debug!("merge: revoked-since root ok");
        let revoked_root = header_bytes32_or_freeze(
            header_map,
            HDR_REVOKED_ROOT,
            FREEZE_FIELD_MISSING,
            "revoked_root",
        )?;
        if parts.revoked_root != revoked_root.as_slice() {
            return Err(AcceptanceError::Freeze(FREEZE_FIELD_MISSING));
        }
        debug!("merge: revoked root ok");
        debug!("merge: anchor roots validated");

        let telemetry_key = self.telemetry_record_attempt(parts.gid, parts.parent_root);

        let rho_commit =
            header_bytes32_or_freeze(header_map, 93, FREEZE_RHO_PARITY, "msphf_kgen_rho_commit")?;
        let provided_seed_ctx_hash = header_bytes32_or_freeze(
            header_map,
            91,
            FREEZE_SEEDCTX_MISMATCH,
            "msphf_seed_ctx_hash",
        )?;

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

        let wid_new = compute_window_id(parts.gid, &parent_root, &seed_ctx_hash)
            .map_err(AcceptanceError::from)?;

        let Some(first_head) = mh_heads.first() else {
            return Err(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID));
        };
        let wid_old_vec = self
            .mh_window
            .find_head_window(first_head)
            .ok_or(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID))?;

        for head in &mh_heads {
            if self
                .mh_window
                .find_head(wid_old_vec.as_slice(), head)
                .is_none()
            {
                return Err(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID));
            }
        }

        let pivot_weid = header_bytes32_or_freeze(
            header_map,
            HDR_ROLLUP_PIVOT_WEID,
            FREEZE_MH_HEADS_INVALID,
            "pivot_weid",
        )?;
        if mh_heads.binary_search(&pivot_weid).is_err() {
            return Err(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID));
        }

        let pivot_record = self
            .mh_window
            .find_head(wid_old_vec.as_slice(), &pivot_weid)
            .cloned()
            .ok_or(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID))?;
        if rho_commit != pivot_record.rho_commit {
            return Err(AcceptanceError::Freeze(FREEZE_MSPHF_RHO_PARITY));
        }

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
        debug!("merge: seed commitments validated");

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
            msphf_hp_commit: None,
        };

        let xk_hash = anchor_instance.xk_hash().map_err(AcceptanceError::from)?;
        let accept_seq = {
            let seq = self.next_accept_seq;
            self.next_accept_seq = self.next_accept_seq.wrapping_add(1);
            seq
        };

        ensure_bootstrap_absent(header_map)?;

        let proofs = ensure_proofs(
            header_map,
            self.allowed_proof_modes.as_ref(),
            &self.deprecated_proof_modes,
            self.allowed_vrf_ids.as_ref(),
            &self.deprecated_vrf_ids,
        )?;
        if proofs.vrf_pi.len() > MAX_VRF_PROOF_BYTES {
            return Err(AcceptanceError::Freeze(FREEZE_VRF_INVALID));
        }

        let stored_parities = self.pivot_store.list(parts.gid, &parent_root, now);
        let parity_map: BTreeMap<_, _> = stored_parities
            .into_iter()
            .map(|parity| (parity.we_epoch_id, parity))
            .collect();
        let pivot_parity = parity_map
            .get(&pivot_weid)
            .cloned()
            .ok_or(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID))?;

        let pivot_envelope_value = if pivot_parity.hp_envelope.is_empty() {
            return Err(AcceptanceError::Freeze(FREEZE_FIELD_MISSING));
        } else {
            ciborium::de::from_reader(pivot_parity.hp_envelope.as_ref()).map_err(|_| {
                debug!("merge: pivot envelope CBOR malformed");
                AcceptanceError::Freeze(FREEZE_HASH_CBOR)
            })?
        };

        verify_join_payload_kbroad(
            self,
            header_map,
            Some(&pivot_envelope_value),
            &pivot_parity.xk_hash,
            &pivot_parity.hp_commit,
        )?;

        if proofs.fs_capss != pivot_parity.fs_capss {
            return Err(AcceptanceError::Freeze(FREEZE_CAPSS_INVALID));
        }
        if proofs.vrf_pi != pivot_parity.vrf_proof
            || proofs.mask_a != pivot_parity.mask_a
            || proofs.mask_b != pivot_parity.mask_b
            || proofs.vrf_public != pivot_parity.vrf_public
        {
            return Err(AcceptanceError::Freeze(FREEZE_VRF_INVALID));
        }
        if proofs.commit != pivot_parity.proofs_commit {
            return Err(AcceptanceError::Freeze(FREEZE_VRF_INVALID));
        }
        if proofs.policy_version != pivot_parity.policy_version
            || proofs.proof_mode != pivot_parity.proof_mode
            || proofs.vrf_id != pivot_parity.vrf_id
        {
            return Err(AcceptanceError::Freeze(FREEZE_SUITE_FORBIDDEN));
        }

        let mut max_fs_ec: Option<u64> = None;
        for head in &mh_heads {
            let parity = parity_map
                .get(head)
                .ok_or(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID))?;
            let fs_ec = parity
                .fs_ec
                .ok_or(AcceptanceError::Freeze(FREEZE_FS_JOIN_MISSING))?;
            max_fs_ec = Some(max_fs_ec.map_or(fs_ec, |current| current.max(fs_ec)));
        }
        let max_fs_ec_value = max_fs_ec.ok_or(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID))?;
        if fs_checkpoint_ec != max_fs_ec_value {
            return Err(AcceptanceError::Freeze(FREEZE_FS_CHECKPOINT_BACKDATE));
        }
        if fs_checkpoint_ec < self.last_checkpoint_ec() {
            return Err(AcceptanceError::Freeze(FREEZE_FS_CHECKPOINT_MONOTONICITY));
        }
        if fs_checkpoint_ec > self.last_accepted_ec() {
            return Err(AcceptanceError::Freeze(FREEZE_FS_CHECKPOINT_BACKDATE));
        }

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

        let hp_envelope_candidate = header_map
            .get(&HDR_HP_BYTES)
            .and_then(|value| to_cbor_vec(value).ok())
            .and_then(|bytes| {
                if bytes.is_empty() {
                    None
                } else {
                    Some(Arc::from(bytes.into_boxed_slice()))
                }
            });
        let srx_present = header_map.contains_key(&HDR_SRX_MODE);
        let roots_changed = pivot_record.join_delta_root != join_delta_root_arr
            || pivot_record.revoked_since_root != revoked_since_root_arr
            || pivot_record.revoked_root != revoked_root_arr;
        if roots_changed {
            if !srx_present {
                return Err(AcceptanceError::Freeze(FREEZE_SRX_REQUIRED));
            }
        } else if srx_present {
            return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
        }
        if !roots_changed {
            for key in [
                HDR_SRX_COMMIT,
                HDR_SRX_PAYLOAD,
                HDR_SRX_HINT_COUNTS,
                HDR_SRX_HINT_SIZES,
            ] {
                if header_map.contains_key(&key) {
                    return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
                }
            }
        }
        if roots_changed {
            ensure_srx_relations(
                header_map,
                &parent_root,
                &join_delta_root_arr,
                &revoked_since_root_arr,
                &revoked_root_arr,
                roots_changed,
                self.srx_max_bytes,
                &xk_hash,
                &seed_commit,
                &rho_commit,
                &pivot_record.msphf_hp_commit,
                self.allowed_srx_modes.as_ref(),
                &self.deprecated_srx_modes,
                now,
                &mut self.vck_cache,
                &proofs,
            )
            .inspect_err(|_err| {
                debug!("merge: ensure_srx_relations failed");
            })?;
        }

        let provenance_commit = match header_map.get(&HDR_ROLLUP_PROVENANCE_COMMIT) {
            Some(Value::Bytes(bytes)) if bytes.len() == 32 => Some(bytes.clone()),
            Some(Value::Bytes(_)) | Some(_) => {
                debug!("merge: rollup provenance root malformed");
                return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
            }
            None => None,
        };

        let epoch_replay_entries = match header_map.get(&HDR_ROLLUP_EPOCH_REPLAY) {
            Some(value) => Some(parse_rollup_epoch_replay(value).inspect_err(|_err| {
                debug!("merge: rollup epoch replay malformed");
            })?),
            None => None,
        };

        let vck_rollup_commit = match header_map.get(&HDR_ROLLUP_VCK_COMMIT) {
            Some(Value::Bytes(bytes)) if bytes.len() == 32 => Some(bytes.clone()),
            Some(Value::Bytes(_)) | Some(_) => {
                debug!("merge: rollup vck root malformed");
                return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
            }
            None => None,
        };

        if vck_rollup_commit.is_some() && provenance_commit.is_none() {
            return Err(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID));
        }

        let has_rollup = provenance_commit.is_some()
            || epoch_replay_entries.is_some()
            || vck_rollup_commit.is_some();

        if has_rollup && (provenance_commit.is_none() || epoch_replay_entries.is_none()) {
            return Err(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID));
        }

        if let Some(entries) = &epoch_replay_entries {
            if entries.len() != mh_heads.len() {
                return Err(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID));
            }
            for (expected_weid, replay) in mh_heads.iter().zip(entries) {
                if &replay.weid != expected_weid {
                    debug!("merge: rollup replay ordering mismatch");
                    return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
                }
                let parity = parity_map
                    .get(expected_weid)
                    .ok_or(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID))?;
                if parity.xk_hash != replay.xk_hash
                    || parity.parent_root != replay.parent_root
                    || parity.join_delta_root != replay.join_delta_root
                    || parity.revoked_since_root != replay.revoked_since_root
                    || parity.revoked_root != replay.revoked_root
                {
                    return Err(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID));
                }
                if parity.is_join != replay.is_join {
                    return Err(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID));
                }
                if replay.is_join {
                    validate_kbroad_envelope_bytes(&parity.hp_envelope)?;
                    if parity.hp_envelope.is_empty() {
                        return Err(AcceptanceError::Freeze(FREEZE_FIELD_MISSING));
                    }
                }
            }
        }

        if let Some(commit_bytes) = &provenance_commit {
            let mut canonical_entries = Vec::with_capacity(mh_heads.len());
            let mut vcks = Vec::with_capacity(mh_heads.len());
            for weid in &mh_heads {
                let parity = parity_map
                    .get(weid)
                    .ok_or(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID))?;
                let vck = compute_vck_from_parity(parity)?;
                canonical_entries.push(Value::Array(vec![
                    Value::Bytes(weid.to_vec()),
                    Value::Bytes(vck.to_vec()),
                    Value::Bytes(parity.xk_hash.to_vec()),
                ]));
                vcks.push(vck);
            }
            let canonical_value = Value::Array(canonical_entries);
            let mut encoded = Vec::new();
            ser::into_writer(&canonical_value, &mut encoded).map_err(|_| {
                debug!("merge: provenance canonical encoding failed");
                AcceptanceError::Freeze(FREEZE_HASH_CBOR)
            })?;
            let computed =
                h_l("msphf/rollup/prov", &RollupCommit(&encoded)).map_err(AcceptanceError::from)?;
            if computed.as_slice() != commit_bytes.as_slice() {
                return Err(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID));
            }
            if let Some(vck_commit_bytes) = &vck_rollup_commit {
                let mut vck_values = Vec::with_capacity(vcks.len());
                for vck in &vcks {
                    vck_values.push(Value::Bytes(vck.to_vec()));
                }
                let canonical_vck_value = Value::Array(vck_values);
                let mut vck_encoded = Vec::new();
                ser::into_writer(&canonical_vck_value, &mut vck_encoded).map_err(|_| {
                    debug!("merge: vck canonical encoding failed");
                    AcceptanceError::Freeze(FREEZE_HASH_CBOR)
                })?;
                let computed_vck = h_l("msphf/rollup/vck", &RollupCommit(&vck_encoded))
                    .map_err(AcceptanceError::from)?;
                if computed_vck.as_slice() != vck_commit_bytes.as_slice() {
                    return Err(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID));
                }
            }
        } else if has_rollup {
            return Err(AcceptanceError::Freeze(FREEZE_MH_HEADS_INVALID));
        }

        // Consume any witness seeded by the joiner; merge acceptance relies on cached pivot proofs.
        self.take_pending_capss_witness();

        let record = HeadRecord::new(
            derived_we_epoch_id,
            pivot_record.msphf_hp_commit,
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
        match self.accept_merge(
            wid_old_vec.as_slice(),
            wid_new.as_slice(),
            mh_heads.as_slice(),
            record.clone(),
            now,
        ) {
            Ok(()) => {
                let active_heads = self.active_heads(&wid_new);
                self.telemetry_record_success(&telemetry_key, active_heads);
            }
            Err(err) => {
                if err == FreezeError::WINDOW_FULL {
                    self.telemetry_record_window_full(&telemetry_key);
                }
                return Err(AcceptanceError::Freeze(err));
            }
        }

        self.pivot_store
            .retire(parts.gid, &parent_root, mh_heads.as_slice());

        let crs_id =
            header_value_bytes(header_map, HDR_CRS_ID, FREEZE_MSPHF_CRS_INVALID)?.into_owned();
        let params_id =
            header_value_bytes(header_map, HDR_PARAMS_ID, FREEZE_PARAMS_ID_INVALID)?.into_owned();
        let srx_commit = if roots_changed {
            let bytes = header_bytes32_or_freeze(
                header_map,
                HDR_SRX_COMMIT,
                FREEZE_SRX_INVALID,
                "srx_commit",
            )?;
            Some(bytes)
        } else {
            None
        };

        let fs_epoch_commit = header_map
            .get(&HDR_FS_EPOCH_COMMIT)
            .and_then(|value| match value {
                Value::Bytes(bytes) if bytes.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(bytes);
                    Some(arr)
                }
                _ => None,
            });
        let fs_dev_commit = header_map
            .get(&HDR_FS_DEV_COMMIT)
            .and_then(|value| match value {
                Value::Bytes(bytes) if bytes.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(bytes);
                    Some(arr)
                }
                _ => None,
            });
        let fs_ec_opt = header_map.get(&HDR_FS_EC).and_then(|value| match value {
            Value::Integer(int) => u64::try_from(*int).ok(),
            _ => None,
        });

        let parity = PivotParity {
            gid: parts.gid.to_vec(),
            cat: parts.cat.to_vec(),
            parent_root,
            we_epoch_id: derived_we_epoch_id,
            rho_commit,
            seed_ctx_hash,
            seed_commit,
            hp_commit: pivot_record.msphf_hp_commit,
            xk_hash,
            join_delta_root: join_delta_root_arr,
            revoked_since_root: revoked_since_root_arr,
            revoked_root: revoked_root_arr,
            accept_seq,
            crs_id,
            params_id,
            policy_version: proofs.policy_version.clone(),
            proof_mode: proofs.proof_mode.clone(),
            vrf_id: proofs.vrf_id.clone(),
            vrf_proof: proofs.vrf_pi.clone(),
            vrf_public: proofs.vrf_public.clone(),
            mask_a: proofs.mask_a,
            mask_b: proofs.mask_b,
            fs_capss: proofs.fs_capss.clone(),
            proofs_commit: proofs.commit,
            srx_commit,
            is_join: false,
            hp_envelope: hp_envelope_candidate.unwrap_or_else(|| pivot_parity.hp_envelope.clone()),
            fs_epoch_commit,
            fs_ec: fs_ec_opt,
            fs_dev_commit,
        };
        self.pivot_store.insert(parity, now);

        self.set_last_checkpoint_ec(fs_checkpoint_ec);
        self.record_accepted_ec(fs_checkpoint_ec);

        Ok(AcceptanceOutcome {
            kind: AcceptanceKind::Merge {
                retired_heads: mh_heads,
            },
            we_epoch_id: derived_we_epoch_id,
            wid: wid_new,
            seed_ctx_hash,
            seed_commit,
            rho_commit,
            hp_commit: pivot_record.msphf_hp_commit,
            xk_hash,
            accept_seq,
            accept_time: now,
            mh_note,
            fs_epoch_commit,
            fs_ec: fs_ec_opt,
            fs_dev_commit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accept::fixtures::{
        accept_with_header, configure_bootstrap, header_ready_with_pop, refresh_seed_bindings,
        sample_header, sample_parts_params_joiner, sample_pop_keys, seed_capss_with,
    };
    use crate::{
        JoinerKGenResult, OrchestrationParams, compute_proofs_commit_bytes, joiner_kgen_merge_or,
        mhw::HeadRecord,
    };
    use anyhow::{Result, anyhow, bail};
    use ciborium::value::Integer;
    use std::sync::Arc;

    type MergeFixture = (
        AcceptanceContext,
        AnchorInstanceParts<'static>,
        OrchestrationParams<'static>,
        JoinerKGenResult,
        Vec<[u8; 32]>,
    );

    type PreparedMergeHeader = (BTreeMap<u64, Value>, Vec<[u8; 32]>);

    fn build_merge_fixture() -> Result<MergeFixture> {
        let (parts, params, join_joiner) = sample_parts_params_joiner();
        let (pop_pk, pop_sk) = sample_pop_keys();
        let (header, _, witness) = header_ready_with_pop(&join_joiner, &parts, &pop_pk, &pop_sk);

        let mut ctx = AcceptanceContext::with_defaults();
        configure_bootstrap(&mut ctx);
        seed_capss_with(&mut ctx, &witness);
        accept_with_header(&mut ctx, &parts, &header)?;

        let mut parent_root = [0u8; 32];
        parent_root.copy_from_slice(parts.parent_root);
        let mut parities = ctx.pivot_parities_for(parts.gid, &parent_root);
        parities.sort_by_key(|parity| (parity.accept_seq, parity.xk_hash));
        assert!(
            !parities.is_empty(),
            "merge fixture requires at least one retired parity"
        );

        let merge_joiner = joiner_kgen_merge_or(
            sample_header(),
            &parities,
            Some("test-merge"),
            parts.clone(),
            params.clone(),
            None,
        )?;
        let retired_heads = match merge_joiner.retired_heads() {
            Some(val) => val.to_vec(),
            None => unreachable!("merge joiner retired heads"),
        };

        Ok((ctx, parts, params, merge_joiner, retired_heads))
    }

    fn recompute_proofs_commit(header: &mut BTreeMap<u64, Value>) -> Result<()> {
        let fs_capss = match header.get(&HDR_FS_CAPSS).and_then(|value| match value {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        }) {
            Some(val) => val,
            None => unreachable!("missing fs capss bytes"),
        };
        let vrf_pi = match header.get(&HDR_VRF_PROOF).and_then(|value| match value {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        }) {
            Some(val) => val,
            None => unreachable!("missing vrf proof"),
        };
        let srx_root = match header.get(&HDR_SRX_ROOT_SW) {
            Some(Value::Bytes(bytes)) if bytes.len() == 32 => Some(bytes.clone()),
            _ => None,
        };
        let srx_smallwood = match header.get(&HDR_SRX_SMALLWOOD) {
            Some(Value::Bytes(bytes)) => Some(bytes.clone()),
            _ => None,
        };
        let commit = compute_proofs_commit_bytes(
            &vrf_pi,
            &fs_capss,
            srx_root.as_deref(),
            srx_smallwood.as_deref(),
        )?;
        header.insert(HDR_PROOFS_COMMIT, Value::Bytes(commit.to_vec()));
        Ok(())
    }

    fn align_header_with_pivot(header: &mut BTreeMap<u64, Value>, pivot: &PivotParity) {
        header.insert(
            HDR_POLICY_VERSION,
            Value::Text(pivot.policy_version.clone()),
        );
        header.insert(HDR_PROOF_MODE, Value::Text(pivot.proof_mode.clone()));
        header.insert(HDR_VRF_ID, Value::Text(pivot.vrf_id.clone()));
        header.insert(HDR_VRF_PROOF, Value::Bytes(pivot.vrf_proof.clone()));
        header.insert(HDR_VRF_PUBLIC_KEY, Value::Bytes(pivot.vrf_public.clone()));
        header.insert(HDR_VRF_MASK_A, Value::Bytes(pivot.mask_a.to_vec()));
        header.insert(HDR_VRF_MASK_B, Value::Bytes(pivot.mask_b.to_vec()));
        header.insert(HDR_FS_CAPSS, Value::Bytes(pivot.fs_capss.clone()));
        match pivot.srx_commit {
            Some(commit) => {
                header.insert(HDR_SRX_COMMIT, Value::Bytes(commit.to_vec()));
            }
            None => {
                header.remove(&HDR_SRX_COMMIT);
                for key in [
                    HDR_SRX_MODE,
                    HDR_SRX_PAYLOAD,
                    HDR_SRX_HINT_COUNTS,
                    HDR_SRX_HINT_SIZES,
                    HDR_SRX_ROOT_SW,
                    HDR_SRX_SMALLWOOD,
                ] {
                    header.remove(&key);
                }
            }
        }
        header.insert(
            HDR_PROOFS_COMMIT,
            Value::Bytes(pivot.proofs_commit.to_vec()),
        );
    }

    fn pivot_parity_from_store(
        ctx: &mut AcceptanceContext,
        parts: &AnchorInstanceParts<'_>,
        weid: [u8; 32],
    ) -> Result<PivotParity> {
        let mut parent_root = [0u8; 32];
        parent_root.copy_from_slice(parts.parent_root);
        match ctx
            .pivot_parities_for(parts.gid, &parent_root)
            .into_iter()
            .find(|parity| parity.we_epoch_id == weid)
        {
            Some(val) => Ok(val),
            None => unreachable!("pivot parity present"),
        }
    }

    fn refresh_pivot_parity(
        ctx: &mut AcceptanceContext,
        _parts: &AnchorInstanceParts<'_>,
        parity: &PivotParity,
    ) -> Result<()> {
        let wid = match ctx.mh_window.find_head_window(&parity.we_epoch_id) {
            Some(val) => val,
            None => unreachable!("pivot window present"),
        };
        let old_record = match ctx.mh_window.find_head(wid.as_slice(), &parity.we_epoch_id) {
            Some(val) => val.clone(),
            None => unreachable!("pivot head present"),
        };
        let accept_time = old_record.accept_time();

        ctx.pivot_store.insert(parity.clone(), accept_time);

        let refreshed = HeadRecord::new(
            parity.we_epoch_id,
            parity.hp_commit,
            parity.seed_ctx_hash,
            parity.rho_commit,
            parity.seed_commit,
            parity.xk_hash,
            parity.join_delta_root,
            parity.revoked_since_root,
            parity.revoked_root,
            old_record.accept_seq,
            accept_time,
        );

        ctx.mh_window
            .accept_merge(
                wid.as_slice(),
                wid.as_slice(),
                &[parity.we_epoch_id],
                refreshed,
                accept_time,
            )
            .map_err(|e| anyhow!("update pivot head failed: {:?}", e))?;
        Ok(())
    }

    fn ready_merge_header(
        ctx: &mut AcceptanceContext,
        parts: &AnchorInstanceParts<'_>,
        merge_joiner: &JoinerKGenResult,
        retired_heads: &[[u8; 32]],
    ) -> Result<PreparedMergeHeader> {
        let mut header = merge_joiner.header_map.clone();
        recompute_proofs_commit(&mut header)?;

        let pivot_weid = match header
            .get(&HDR_ROLLUP_PIVOT_WEID)
            .and_then(|value| match value {
                Value::Bytes(bytes) if bytes.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(bytes);
                    Some(arr)
                }
                _ => None,
            }) {
            Some(val) => val,
            None => unreachable!("pivot weid missing"),
        };

        let mut pivot_parity = pivot_parity_from_store(ctx, parts, pivot_weid)?;
        align_header_with_pivot(&mut header, &pivot_parity);
        for key in [
            HDR_SRX_COMMIT,
            HDR_SRX_MODE,
            HDR_SRX_PAYLOAD,
            HDR_SRX_HINT_COUNTS,
            HDR_SRX_HINT_SIZES,
            HDR_SRX_ROOT_SW,
            HDR_SRX_SMALLWOOD,
            HDR_ROLLUP_PROVENANCE_COMMIT,
            HDR_ROLLUP_EPOCH_REPLAY,
            HDR_ROLLUP_VCK_COMMIT,
        ] {
            header.remove(&key);
        }
        pivot_parity.srx_commit = None;
        recompute_proofs_commit(&mut header)?;

        let proofs_commit = match header
            .get(&HDR_PROOFS_COMMIT)
            .and_then(|value| match value {
                Value::Bytes(bytes) if bytes.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(bytes);
                    Some(arr)
                }
                _ => None,
            }) {
            Some(val) => val,
            None => unreachable!("recomputed proofs commit missing"),
        };
        pivot_parity.proofs_commit = proofs_commit;
        refresh_pivot_parity(ctx, parts, &pivot_parity)?;

        let mut heads = retired_heads.to_vec();
        heads.sort();
        Ok((header, heads))
    }

    fn assert_freeze(err: AcceptanceError, expected: FreezeError) -> Result<()> {
        match err {
            AcceptanceError::Freeze(code) => {
                assert_eq!(code, expected);
                Ok(())
            }
            other => Err(anyhow!("unexpected error: {other:?}")),
        }
    }

    fn expect_merge_freeze(
        ctx: &mut AcceptanceContext,
        parts: &AnchorInstanceParts<'_>,
        joiner: &JoinerKGenResult,
        header: &BTreeMap<u64, Value>,
        retired_heads: Vec<[u8; 32]>,
        expected: FreezeError,
    ) -> Result<()> {
        seed_capss_with(ctx, &joiner.capss_witness);
        let now = ctx.next_accept_instant();
        let err = match ctx.accept_anchor_merge(
            parts,
            joiner.we_epoch_id,
            header,
            retired_heads,
            joiner.mh_note.clone(),
            now,
        ) {
            Ok(_) => bail!("expected merge freeze"),
            Err(err) => err,
        };
        assert_freeze(err, expected)
    }

    #[test]
    fn merge_anchor_rejects_invalid_purge_metadata() -> Result<()> {
        let (mut ctx, parts, _params, merge_joiner, retired_heads) = build_merge_fixture()?;
        let mut header = merge_joiner.header_map.clone();
        recompute_proofs_commit(&mut header)?;
        header.insert(HDR_FS_PURGE_TIMES, Value::Bytes(vec![0u8; 4]));
        seed_capss_with(&mut ctx, &merge_joiner.capss_witness);
        let now = ctx.next_accept_instant();

        let err = match ctx.accept_anchor_merge(
            &parts,
            merge_joiner.we_epoch_id,
            &header,
            retired_heads,
            merge_joiner.mh_note.clone(),
            now,
        ) {
            Ok(_) => bail!("non-map purge metadata should freeze"),
            Err(e) => e,
        };
        let AcceptanceError::Freeze(code) = err else {
            return Err(anyhow!("unexpected error"));
        };
        assert_eq!(code, FREEZE_HASH_CBOR);
        Ok(())
    }

    #[test]
    fn merge_anchor_rejects_pivot_mismatch() -> Result<()> {
        let (mut ctx, parts, _params, merge_joiner, mut retired_heads) = build_merge_fixture()?;
        let mut header = merge_joiner.header_map.clone();
        recompute_proofs_commit(&mut header)?;
        header.insert(HDR_ROLLUP_PIVOT_WEID, Value::Bytes([0xFFu8; 32].to_vec()));
        // The retired heads must remain sorted for the call; ensure we reuse original order.
        retired_heads.sort();
        seed_capss_with(&mut ctx, &merge_joiner.capss_witness);
        let now = ctx.next_accept_instant();

        let err = match ctx.accept_anchor_merge(
            &parts,
            merge_joiner.we_epoch_id,
            &header,
            retired_heads,
            merge_joiner.mh_note.clone(),
            now,
        ) {
            Ok(_) => bail!("pivot mismatch should freeze"),
            Err(e) => e,
        };
        let AcceptanceError::Freeze(code) = err else {
            return Err(anyhow!("unexpected error"));
        };
        assert_eq!(code, FREEZE_MH_HEADS_INVALID);
        Ok(())
    }

    #[test]
    fn merge_anchor_accepts_valid_payload() -> Result<()> {
        let (mut ctx, parts, _params, merge_joiner, retired_heads) = build_merge_fixture()?;
        seed_capss_with(&mut ctx, &merge_joiner.capss_witness);

        let (header, heads) = ready_merge_header(&mut ctx, &parts, &merge_joiner, &retired_heads)?;
        let now = ctx.next_accept_instant();

        let outcome = ctx
            .accept_anchor_merge(
                &parts,
                merge_joiner.we_epoch_id,
                &header,
                heads.clone(),
                merge_joiner.mh_note.clone(),
                now,
            )
            .map_err(|err| anyhow!("unexpected error: {err:?}"))?;

        match outcome.kind {
            AcceptanceKind::Merge {
                retired_heads: accepted,
            } => {
                assert_eq!(accepted, heads);
            }
            other => return Err(anyhow!("unexpected outcome {other:?}")),
        }
        assert_eq!(outcome.mh_note, merge_joiner.mh_note);
        assert_eq!(outcome.we_epoch_id, merge_joiner.we_epoch_id);
        assert_eq!(outcome.seed_ctx_hash, merge_joiner.seed_ctx_hash);
        Ok(())
    }

    #[test]
    fn merge_anchor_missing_fs_checkpoint_freezes() -> Result<()> {
        let (mut ctx, parts, _params, merge_joiner, retired_heads) = build_merge_fixture()?;
        seed_capss_with(&mut ctx, &merge_joiner.capss_witness);
        let (mut header, heads) =
            ready_merge_header(&mut ctx, &parts, &merge_joiner, &retired_heads)?;
        header.remove(&HDR_FS_CHECKPOINT_EC);
        let now = ctx.next_accept_instant();

        let err = match ctx.accept_anchor_merge(
            &parts,
            merge_joiner.we_epoch_id,
            &header,
            heads,
            merge_joiner.mh_note.clone(),
            now,
        ) {
            Ok(_) => bail!("missing checkpoint ec must freeze"),
            Err(e) => e,
        };
        assert_freeze(err, FREEZE_FS_JOIN_MISSING)?;
        Ok(())
    }

    #[test]
    fn merge_anchor_checkpoint_backdate_freezes() -> Result<()> {
        let (mut ctx, parts, _params, merge_joiner, retired_heads) = build_merge_fixture()?;
        seed_capss_with(&mut ctx, &merge_joiner.capss_witness);
        let (mut header, heads) =
            ready_merge_header(&mut ctx, &parts, &merge_joiner, &retired_heads)?;
        header.insert(
            HDR_FS_CHECKPOINT_EC,
            Value::Integer(Integer::from(u64::MAX)),
        );
        let now = ctx.next_accept_instant();

        let err = match ctx.accept_anchor_merge(
            &parts,
            merge_joiner.we_epoch_id,
            &header,
            heads,
            merge_joiner.mh_note.clone(),
            now,
        ) {
            Ok(_) => bail!("tampered checkpoint ec must freeze"),
            Err(e) => e,
        };
        assert_freeze(err, FREEZE_FS_CHECKPOINT_BACKDATE)?;
        Ok(())
    }

    #[test]
    fn merge_anchor_rejects_unexpected_srx_when_roots_same() -> Result<()> {
        let (mut ctx, parts, _params, merge_joiner, retired_heads) = build_merge_fixture()?;
        let mut header = merge_joiner.header_map.clone();
        recompute_proofs_commit(&mut header)?;
        header.insert(HDR_SRX_MODE, Value::Text("mock".to_string()));
        seed_capss_with(&mut ctx, &merge_joiner.capss_witness);
        let now = ctx.next_accept_instant();

        let err = match ctx.accept_anchor_merge(
            &parts,
            merge_joiner.we_epoch_id,
            &header,
            retired_heads,
            merge_joiner.mh_note.clone(),
            now,
        ) {
            Ok(_) => bail!("srx with unchanged roots should freeze"),
            Err(e) => e,
        };
        let AcceptanceError::Freeze(code) = err else {
            return Err(anyhow!("unexpected error"));
        };
        assert_eq!(code, FREEZE_SRX_SMALLWOOD_INVALID);
        Ok(())
    }

    #[test]
    fn merge_anchor_requires_provenance_when_vck_commit_present() -> Result<()> {
        let (mut ctx, parts, _params, merge_joiner, retired_heads) = build_merge_fixture()?;
        let mut header = merge_joiner.header_map.clone();
        recompute_proofs_commit(&mut header)?;
        header.remove(&HDR_ROLLUP_PROVENANCE_COMMIT);
        header.insert(HDR_ROLLUP_VCK_COMMIT, Value::Bytes(vec![0xAA; 32]));
        seed_capss_with(&mut ctx, &merge_joiner.capss_witness);
        let now = ctx.next_accept_instant();

        let err = match ctx.accept_anchor_merge(
            &parts,
            merge_joiner.we_epoch_id,
            &header,
            retired_heads,
            merge_joiner.mh_note.clone(),
            now,
        ) {
            Ok(_) => bail!("vck without provenance should freeze"),
            Err(e) => e,
        };
        let AcceptanceError::Freeze(code) = err else {
            return Err(anyhow!("unexpected error"));
        };
        assert_eq!(code, FREEZE_CAPSS_INVALID);
        Ok(())
    }

    #[test]
    fn merge_anchor_detects_capss_mismatch() -> Result<()> {
        let (mut ctx, parts, _params, merge_joiner, retired_heads) = build_merge_fixture()?;
        let mut header = merge_joiner.header_map.clone();
        if let Some(Value::Bytes(bytes)) = header.get_mut(&HDR_FS_CAPSS)
            && let Some(first) = bytes.first_mut()
        {
            *first ^= 0xFF;
        }
        recompute_proofs_commit(&mut header)?;
        seed_capss_with(&mut ctx, &merge_joiner.capss_witness);
        let now = ctx.next_accept_instant();

        let err = match ctx.accept_anchor_merge(
            &parts,
            merge_joiner.we_epoch_id,
            &header,
            retired_heads,
            merge_joiner.mh_note.clone(),
            now,
        ) {
            Ok(_) => bail!("capss mismatch should freeze"),
            Err(e) => e,
        };
        let AcceptanceError::Freeze(code) = err else {
            return Err(anyhow!("unexpected error"));
        };
        assert_eq!(code, FREEZE_CAPSS_INVALID);
        Ok(())
    }

    #[test]
    fn merge_anchor_rejects_kbroad_replay_header() -> Result<()> {
        let (mut ctx, parts, _params, merge_joiner, retired_heads) = build_merge_fixture()?;
        let (mut header, heads) =
            ready_merge_header(&mut ctx, &parts, &merge_joiner, &retired_heads)?;
        header.insert(HDR_KBROAD_REPLAY, Value::Bytes(vec![0u8; 4]));
        expect_merge_freeze(
            &mut ctx,
            &parts,
            &merge_joiner,
            &header,
            heads,
            FREEZE_FS_KBROAD_PRESENT,
        )
    }

    #[test]
    fn merge_anchor_rejects_invalid_fs_boundary_and_mode() -> Result<()> {
        let (mut ctx, parts, _params, merge_joiner, retired_heads) = build_merge_fixture()?;
        let (mut header, heads) =
            ready_merge_header(&mut ctx, &parts, &merge_joiner, &retired_heads)?;
        header.insert(HDR_FS_EVOLUTION_BOUNDARY, Value::Bool(false));
        expect_merge_freeze(
            &mut ctx,
            &parts,
            &merge_joiner,
            &header,
            heads.clone(),
            FREEZE_MH_HEADS_INVALID,
        )?;

        header.insert(HDR_FS_EVOLUTION_BOUNDARY, Value::Bool(true));
        header.insert(HDR_ROLLUP_FS_MODE, Value::Text("not-fs-purge".to_string()));
        expect_merge_freeze(
            &mut ctx,
            &parts,
            &merge_joiner,
            &header,
            heads,
            FREEZE_MH_HEADS_INVALID,
        )
    }

    #[test]
    fn merge_anchor_rejects_root_binding_mismatches() -> Result<()> {
        let (mut ctx, parts, _params, merge_joiner, retired_heads) = build_merge_fixture()?;
        let (mut header, heads) =
            ready_merge_header(&mut ctx, &parts, &merge_joiner, &retired_heads)?;
        header.insert(110, Value::Bytes([0xA1; 32].to_vec()));
        expect_merge_freeze(
            &mut ctx,
            &parts,
            &merge_joiner,
            &header,
            heads.clone(),
            FREEZE_FIELD_MISSING,
        )?;

        let (mut header, heads) =
            ready_merge_header(&mut ctx, &parts, &merge_joiner, &retired_heads)?;
        header.insert(111, Value::Bytes([0xB2; 32].to_vec()));
        expect_merge_freeze(
            &mut ctx,
            &parts,
            &merge_joiner,
            &header,
            heads,
            FREEZE_FIELD_MISSING,
        )
    }

    #[test]
    fn merge_anchor_rejects_seed_commit_mismatches() -> Result<()> {
        let (mut ctx, parts, _params, merge_joiner, retired_heads) = build_merge_fixture()?;
        let (mut header, heads) =
            ready_merge_header(&mut ctx, &parts, &merge_joiner, &retired_heads)?;
        header.insert(HDR_SEED_CTX_HASH, Value::Bytes([0xCC; 32].to_vec()));
        expect_merge_freeze(
            &mut ctx,
            &parts,
            &merge_joiner,
            &header,
            heads.clone(),
            FREEZE_SEEDCTX_MISMATCH,
        )?;

        let (mut header, heads) =
            ready_merge_header(&mut ctx, &parts, &merge_joiner, &retired_heads)?;
        header.insert(HDR_SEED_BUNDLE_COMMIT, Value::Bytes([0xDD; 32].to_vec()));
        expect_merge_freeze(
            &mut ctx,
            &parts,
            &merge_joiner,
            &header,
            heads,
            FREEZE_SEEDCTX_MISMATCH,
        )
    }

    #[test]
    fn merge_anchor_rejects_empty_or_unknown_retired_heads() -> Result<()> {
        let (mut ctx, parts, _params, merge_joiner, retired_heads) = build_merge_fixture()?;
        let (header, heads) = ready_merge_header(&mut ctx, &parts, &merge_joiner, &retired_heads)?;
        expect_merge_freeze(
            &mut ctx,
            &parts,
            &merge_joiner,
            &header,
            Vec::new(),
            FREEZE_MH_HEADS_INVALID,
        )?;

        let mut tampered_heads = heads.clone();
        tampered_heads.push([0xEF; 32]);
        tampered_heads.sort();
        expect_merge_freeze(
            &mut ctx,
            &parts,
            &merge_joiner,
            &header,
            tampered_heads,
            FREEZE_MH_HEADS_INVALID,
        )
    }

    #[test]
    fn merge_anchor_rejects_changed_roots_without_srx() -> Result<()> {
        let (mut ctx, parts, _params, merge_joiner, retired_heads) = build_merge_fixture()?;
        let (mut header, heads) =
            ready_merge_header(&mut ctx, &parts, &merge_joiner, &retired_heads)?;
        let mut mutated_join_root = [0u8; 32];
        mutated_join_root.copy_from_slice(parts.join_delta_root);
        mutated_join_root[0] ^= 0xFF;
        header.insert(111, Value::Bytes(mutated_join_root.to_vec()));
        let mutated_parts = AnchorInstanceParts {
            gid: parts.gid,
            cat: parts.cat,
            tswe_salt_hash: parts.tswe_salt_hash,
            parent_root: parts.parent_root,
            join_delta_root: &mutated_join_root,
            revoked_since_prev_root: parts.revoked_since_prev_root,
            revoked_root: parts.revoked_root,
            pox_r_commit: parts.pox_r_commit,
        };
        refresh_seed_bindings(&mut header, &mutated_parts, &merge_joiner);
        seed_capss_with(&mut ctx, &merge_joiner.capss_witness);
        let now = ctx.next_accept_instant();
        let weid_claim = compute_we_epoch_id_from_header(&mutated_parts, &header)?;
        let err = match ctx.accept_anchor_merge(
            &mutated_parts,
            weid_claim,
            &header,
            heads,
            merge_joiner.mh_note.clone(),
            now,
        ) {
            Ok(_) => bail!("expected roots-changed merge to freeze without SRX"),
            Err(err) => err,
        };
        assert_freeze(err, FREEZE_SRX_REQUIRED)
    }

    #[test]
    fn merge_anchor_rejects_rollup_incompleteness() -> Result<()> {
        let (mut ctx, parts, _params, merge_joiner, retired_heads) = build_merge_fixture()?;
        let (mut header, heads) =
            ready_merge_header(&mut ctx, &parts, &merge_joiner, &retired_heads)?;
        header.insert(HDR_ROLLUP_PROVENANCE_COMMIT, Value::Bytes(vec![0x11; 32]));
        expect_merge_freeze(
            &mut ctx,
            &parts,
            &merge_joiner,
            &header,
            heads,
            FREEZE_MH_HEADS_INVALID,
        )
    }

    #[test]
    fn merge_anchor_rejects_checkpoint_monotonicity_violations() -> Result<()> {
        let (mut ctx, parts, _params, merge_joiner, retired_heads) = build_merge_fixture()?;
        let (header, heads) = ready_merge_header(&mut ctx, &parts, &merge_joiner, &retired_heads)?;
        let checkpoint_ec = match header
            .get(&HDR_FS_CHECKPOINT_EC)
            .and_then(|value| match value {
                Value::Integer(int) => u64::try_from(*int).ok(),
                _ => None,
            }) {
            Some(ec) => ec,
            None => bail!("missing fs checkpoint ec"),
        };

        ctx.set_last_checkpoint_ec(checkpoint_ec.saturating_add(1));
        expect_merge_freeze(
            &mut ctx,
            &parts,
            &merge_joiner,
            &header,
            heads.clone(),
            FREEZE_FS_CHECKPOINT_MONOTONICITY,
        )
    }

    #[test]
    fn merge_anchor_rejects_invalid_pivot_envelope_bytes() -> Result<()> {
        let (mut ctx, parts, _params, merge_joiner, retired_heads) = build_merge_fixture()?;
        let (header, heads) = ready_merge_header(&mut ctx, &parts, &merge_joiner, &retired_heads)?;
        let pivot_weid = match header
            .get(&HDR_ROLLUP_PIVOT_WEID)
            .and_then(|value| match value {
                Value::Bytes(bytes) if bytes.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(bytes);
                    Some(arr)
                }
                _ => None,
            }) {
            Some(weid) => weid,
            None => bail!("missing pivot weid"),
        };

        let mut parity = pivot_parity_from_store(&mut ctx, &parts, pivot_weid)?;
        parity.hp_envelope = Arc::from(vec![0xFF].into_boxed_slice());
        refresh_pivot_parity(&mut ctx, &parts, &parity)?;
        expect_merge_freeze(
            &mut ctx,
            &parts,
            &merge_joiner,
            &header,
            heads.clone(),
            FREEZE_HASH_CBOR,
        )?;

        let mut parity = pivot_parity_from_store(&mut ctx, &parts, pivot_weid)?;
        parity.hp_envelope = Arc::from(Vec::<u8>::new().into_boxed_slice());
        refresh_pivot_parity(&mut ctx, &parts, &parity)?;
        expect_merge_freeze(
            &mut ctx,
            &parts,
            &merge_joiner,
            &header,
            heads,
            FREEZE_FIELD_MISSING,
        )
    }
}
