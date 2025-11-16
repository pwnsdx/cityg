//! Shared validation stages reused across join, merge, and burst handlers.

use super::{ml_dsa_public_key_bytes, ml_dsa_signature_bytes, verify_ml_dsa, *};
use crate::{
    KBROAD_ML_KEM_ALG, KBROAD_MODE, TSWE_ALG_CODE, TSWE_ALG_LABEL,
    proofs::srx_smallwood::{self, SRX_SMALLWOOD_MAX_BYTES},
};
use ciborium::de;
use msphf_core::ds::MSPHF_POP_MSG;
use serde::Serialize;
use tracing::debug;

pub(super) struct ProofArtifacts {
    pub(crate) commit: [u8; 32],
    pub(crate) vrf_pi: Vec<u8>,
    pub(crate) fs_capss: Vec<u8>,
    pub(crate) srx_root_sw: Option<[u8; 32]>,
    pub(crate) srx_smallwood: Option<Vec<u8>>,
    pub(crate) proof_mode: String,
    pub(crate) vrf_id: String,
    pub(crate) mask_a: MaskDigest,
    pub(crate) mask_b: MaskDigest,
    pub(crate) policy_version: String,
    pub(crate) vrf_public: Vec<u8>,
}

pub(super) fn ensure_merge_join_keys_absent(
    header: &BTreeMap<u64, Value>,
) -> Result<(), AcceptanceError> {
    for key in [
        super::HDR_HP_BYTES,
        super::HDR_POP_ALG,
        super::HDR_POP_PK,
        super::HDR_POP_SIG,
        super::HDR_BOOTSTRAP_ALG,
        super::HDR_BOOTSTRAP_SIG,
        super::HDR_BOOTSTRAP_PK,
    ] {
        if header.contains_key(&key) {
            debug!("ensure_merge_join_keys_absent: key {} present", key);
            return Err(AcceptanceError::Freeze(FREEZE_MERGE_JOIN_KEYS));
        }
    }
    Ok(())
}

pub(super) fn ensure_join_pop(
    header: &BTreeMap<u64, Value>,
    anchor: &AnchorInstance<'_>,
    leaf_id_mode: crate::LeafIdMode,
) -> Result<(), AcceptanceError> {
    const KEY_ALG: u64 = 107;
    const KEY_PK: u64 = 108;
    const KEY_SIG: u64 = 109;

    let alg_value = header
        .get(&KEY_ALG)
        .ok_or(AcceptanceError::Freeze(FREEZE_POP_INVALID))?;
    // Avoid allocating string - just compare directly
    let algorithm_matches = match alg_value {
        Value::Text(text) => text.as_str() == "ML-DSA-65",
        Value::Bytes(bytes) => std::str::from_utf8(bytes)
            .map(|s| s == "ML-DSA-65")
            .unwrap_or(false),
        _ => false,
    };
    if !algorithm_matches {
        return Err(AcceptanceError::Freeze(FREEZE_POP_INVALID));
    }

    let pk_bytes = match header.get(&KEY_PK) {
        Some(Value::Bytes(bytes)) if bytes.len() == ml_dsa_public_key_bytes() => bytes,
        _ => return Err(AcceptanceError::Freeze(FREEZE_POP_INVALID)),
    };
    let sig_bytes = match header.get(&KEY_SIG) {
        Some(Value::Bytes(bytes)) if bytes.len() == ml_dsa_signature_bytes() => bytes,
        _ => return Err(AcceptanceError::Freeze(FREEZE_POP_INVALID)),
    };

    let leaf_id = crate::compute_leaf_id(leaf_id_mode, anchor.gid, "ML-DSA-65", pk_bytes)
        .map_err(AcceptanceError::from)?;

    #[derive(Serialize)]
    struct PopMsg<'a> {
        #[serde(with = "serde_bytes")]
        xk: &'a [u8],
        #[serde(with = "serde_bytes")]
        leaf_id: &'a [u8],
        #[serde(with = "serde_bytes")]
        epoch: &'a [u8],
    }
    let xk_bytes = anchor.to_cbor_bytes().map_err(AcceptanceError::from)?;
    let msg = h_l(
        MSPHF_POP_MSG,
        &PopMsg {
            xk: &xk_bytes,
            leaf_id: &leaf_id,
            epoch: &anchor.we_epoch_id,
        },
    )
    .map_err(AcceptanceError::from)?;

    let pk = MlDsaPublicKey::from_bytes(pk_bytes.as_slice())
        .map_err(|_| AcceptanceError::Freeze(FREEZE_POP_INVALID))?;
    let sig = MlDsaDetachedSignature::from_bytes(sig_bytes.as_slice())
        .map_err(|_| AcceptanceError::Freeze(FREEZE_POP_INVALID))?;
    verify_ml_dsa(&sig, &msg, &pk).map_err(|_| AcceptanceError::Freeze(FREEZE_POP_INVALID))?;

    Ok(())
}
pub(super) fn ensure_bootstrap_absent(
    header: &BTreeMap<u64, Value>,
) -> Result<(), AcceptanceError> {
    if header.contains_key(&super::HDR_BOOTSTRAP_SIG) {
        return Err(AcceptanceError::Freeze(FREEZE_BOOTSTRAP_INVALID));
    }
    if header.contains_key(&super::HDR_BOOTSTRAP_ALG) {
        return Err(AcceptanceError::Freeze(FREEZE_BOOTSTRAP_INVALID));
    }
    if header.contains_key(&super::HDR_BOOTSTRAP_PK) {
        return Err(AcceptanceError::Freeze(FREEZE_BOOTSTRAP_INVALID));
    }
    Ok(())
}

pub(super) fn verify_join_payload_kbroad(
    _ctx: &AcceptanceContext,
    header: &BTreeMap<u64, Value>,
    envelope_override: Option<&Value>,
    _xk_hash: &[u8; 32],
    _hp_commit: &[u8; 32],
) -> Result<(), AcceptanceError> {
    let envelope_value = match envelope_override {
        Some(value) => value,
        None => header.get(&super::HDR_HP_BYTES).ok_or_else(|| {
            debug!("verify_join_payload_kbroad: missing HDR_HP_BYTES");
            AcceptanceError::Freeze(FREEZE_FIELD_MISSING)
        })?,
    };

    let Value::Array(items) = envelope_value else {
        debug!("verify_join_payload_kbroad: envelope not array");
        return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
    };
    if items.len() != 5 {
        debug!(
            "verify_join_payload_kbroad: envelope len {} != 5",
            items.len()
        );
        return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
    }

    let mode = match &items[0] {
        Value::Text(text) => text.as_str(),
        Value::Bytes(bytes) => std::str::from_utf8(bytes).map_err(|_| {
            debug!("verify_join_payload_kbroad: mode bytes invalid utf8");
            AcceptanceError::Freeze(FREEZE_HASH_CBOR)
        })?,
        _ => {
            debug!("verify_join_payload_kbroad: mode not bytes/text");
            return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
        }
    };
    if mode != KBROAD_MODE {
        return Err(AcceptanceError::Freeze(FREEZE_PARENT_EID_FORBIDDEN));
    }

    let expected_ct_len = super::ml_kem_ciphertext_bytes();
    match &items[1] {
        Value::Bytes(bytes) if bytes.len() == expected_ct_len => {}
        Value::Bytes(_) => {
            debug!(
                "verify_join_payload_kbroad: item[1] len {} != {}",
                items[1].as_bytes().map(|b| b.len()).unwrap_or_default(),
                expected_ct_len
            );
            return Err(AcceptanceError::Freeze(FREEZE_KBROAD_PARENT_MISMATCH));
        }
        _ => {
            debug!("verify_join_payload_kbroad: item[1] not bytes");
            return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
        }
    }
    match &items[2] {
        Value::Bytes(bytes) if bytes.len() == super::KBROAD_WRAP_CIPHERTEXT_BYTES => {}
        Value::Bytes(_) => {
            debug!(
                "verify_join_payload_kbroad: item[2] len {} != {}",
                items[2].as_bytes().map(|b| b.len()).unwrap_or_default(),
                super::KBROAD_WRAP_CIPHERTEXT_BYTES
            );
            return Err(AcceptanceError::Freeze(FREEZE_KBROAD_PARENT_MISMATCH));
        }
        _ => {
            debug!("verify_join_payload_kbroad: item[2] not bytes");
            return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
        }
    }
    match &items[3] {
        Value::Bytes(bytes)
            if bytes.len() >= crate::AEAD_TAG_LEN
                && bytes.len() <= super::KBROAD_HP_MAX_CIPHERTEXT_BYTES => {}
        Value::Bytes(_) => {
            debug!(
                "verify_join_payload_kbroad: item[3] len {} outside [{}, {}]",
                items[3].as_bytes().map(|b| b.len()).unwrap_or_default(),
                crate::AEAD_TAG_LEN,
                super::KBROAD_HP_MAX_CIPHERTEXT_BYTES
            );
            return Err(AcceptanceError::Freeze(FREEZE_KBROAD_PARENT_MISMATCH));
        }
        _ => {
            debug!("verify_join_payload_kbroad: item[3] not bytes");
            return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
        }
    }
    let aead = match &items[4] {
        Value::Text(text) => text.as_str(),
        Value::Bytes(bytes) => std::str::from_utf8(bytes).map_err(|_| {
            debug!("verify_join_payload_kbroad: item[4] invalid utf8");
            AcceptanceError::Freeze(FREEZE_HASH_CBOR)
        })?,
        _ => {
            debug!("verify_join_payload_kbroad: item[4] not bytes/text");
            return Err(AcceptanceError::Freeze(FREEZE_HASH_CBOR));
        }
    };
    if aead != "chacha20-poly1305" {
        return Err(AcceptanceError::Freeze(FREEZE_SUITE_DEPRECATED));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn ensure_srx_relations(
    header: &BTreeMap<u64, Value>,
    parent_root: &[u8; 32],
    join_delta_root: &[u8; 32],
    revoked_since_root: &[u8; 32],
    revoked_root: &[u8; 32],
    require: bool,
    srx_max_bytes: usize,
    xk_hash: &[u8; 32],
    seed_commit: &[u8; 32],
    rho_commit: &[u8; 32],
    hp_commit: &[u8; 32],
    allowed_srx_modes: Option<&BTreeSet<String>>,
    deprecated_srx_modes: &BTreeSet<String>,
    now: AcceptInstant,
    cache: &mut VckCache,
    proofs: &ProofArtifacts,
) -> Result<(), AcceptanceError> {
    let max_bytes = srx_max_bytes.max(MIN_SRX_MAX_BYTES);
    let has_mode = header.get(&super::HDR_SRX_MODE);
    if has_mode.is_none() {
        if require {
            debug!("ensure_srx_relations: missing mode but require=true");
            return Err(AcceptanceError::Freeze(FREEZE_SRX_REQUIRED));
        }
        if [121u64, 122, 123, 124]
            .into_iter()
            .any(|key| header.contains_key(&key))
        {
            debug!("ensure_srx_relations: stray SRX fields without mode");
            return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
        }
        return Ok(());
    }

    let srx_present = true;

    if !header.contains_key(&super::HDR_SRX_COMMIT)
        || !header.contains_key(&super::HDR_SRX_PAYLOAD)
        || !header.contains_key(&super::HDR_SRX_HINT_COUNTS)
        || !header.contains_key(&super::HDR_SRX_HINT_SIZES)
    {
        debug!("ensure_srx_relations: missing mandatory SRX fields");
        return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
    }

    let mode_value = match has_mode {
        Some(value) => value,
        None => {
            debug!("ensure_srx_relations: mode vanished unexpectedly");
            return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
        }
    };
    let mode_text = match mode_value {
        Value::Text(text) => text.as_str(),
        Value::Bytes(bytes) => std::str::from_utf8(bytes).map_err(|_| {
            debug!("ensure_srx_relations: mode not valid utf8");
            AcceptanceError::Freeze(FREEZE_SRX_INVALID)
        })?,
        _ => {
            debug!("ensure_srx_relations: mode not text/bytes");
            return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
        }
    };
    if allowed_srx_modes.is_some_and(|allowed| !allowed.contains(mode_text)) {
        debug!("ensure_srx_relations: mode {mode_text} not allowed");
        return Err(AcceptanceError::Freeze(FREEZE_SUITE_DEPRECATED));
    }
    if deprecated_srx_modes.contains(mode_text) {
        return Err(AcceptanceError::Freeze(FREEZE_SUITE_DEPRECATED));
    }
    let hint_counts_bytes = match header.get(&super::HDR_SRX_HINT_COUNTS) {
        Some(Value::Bytes(bytes)) => bytes.as_slice(),
        _ => {
            debug!("ensure_srx_relations: hint counts missing/invalid");
            return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
        }
    };
    let hint_counts_value: Value = de::from_reader(hint_counts_bytes).map_err(|_| {
        debug!("ensure_srx_relations: hint counts CBOR malformed");
        AcceptanceError::Freeze(FREEZE_SRX_INVALID)
    })?;
    let (hint_join_count, hint_since_count, hint_anchor_count) =
        parse_hint_counts(&hint_counts_value)?;

    let hint_sizes_bytes = match header.get(&super::HDR_SRX_HINT_SIZES) {
        Some(Value::Bytes(bytes)) => bytes.as_slice(),
        _ => {
            debug!("ensure_srx_relations: hint sizes missing/invalid");
            return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
        }
    };
    let hint_sizes_value: Value = de::from_reader(hint_sizes_bytes).map_err(|_| {
        debug!("ensure_srx_relations: hint sizes CBOR malformed");
        AcceptanceError::Freeze(FREEZE_SRX_INVALID)
    })?;
    let hint_payload_bytes = parse_hint_sizes(&hint_sizes_value)?;
    if hint_payload_bytes > max_bytes as u64 {
        return Err(AcceptanceError::Freeze(FREEZE_SRX_OVERSIZE_HINT));
    }

    let commit = header_bytes32_or_freeze(header, 121, FREEZE_SRX_INVALID, "srx_commit")?;
    let payload_bytes = match header.get(&super::HDR_SRX_PAYLOAD) {
        Some(Value::Bytes(bytes)) => bytes.as_slice(),
        _ => {
            debug!("ensure_srx_relations: payload missing/invalid");
            return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
        }
    };
    if payload_bytes.len() > max_bytes {
        return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
    }
    if payload_bytes.len() as u64 > hint_payload_bytes {
        return Err(AcceptanceError::Freeze(FREEZE_SRX_HINT_UNDER));
    }

    #[derive(Serialize)]
    struct SrxCommit<'a>(#[serde(with = "serde_bytes")] &'a [u8]);
    let recomputed = h_l(msphf_core::ds::MSPHF_SRX_COMMIT, &SrxCommit(payload_bytes))
        .map_err(AcceptanceError::from)?;
    if recomputed != commit {
        return Err(AcceptanceError::Freeze(FREEZE_SRX_COMMIT_MISMATCH));
    }

    let payload_value: Value = de::from_reader(payload_bytes).map_err(|_| {
        debug!("ensure_srx_relations: payload CBOR malformed");
        AcceptanceError::Freeze(FREEZE_SRX_INVALID)
    })?;
    let cache_key = compute_vck_key(xk_hash, seed_commit, rho_commit, hp_commit, header)?;
    let payload_len = payload_bytes.len();
    if cache.try_skip_srx(
        cache_key,
        hint_join_count,
        hint_since_count,
        hint_anchor_count,
        hint_payload_bytes,
        payload_len,
        now,
    )? {
        return Ok(());
    }

    let srx = match mode_text {
        "srx/v1-complete" => parse_srx_payload(&payload_value)?,
        _ => {
            debug!("ensure_srx_relations: unsupported mode {}", mode_text);
            return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
        }
    };

    validate_anchor_pool(&srx.anchor_mem_pool)?;

    if srx.join_leaf_ids.len() as u64 > hint_join_count
        || srx.since_leaf_ids.len() as u64 > hint_since_count
    {
        return Err(AcceptanceError::Freeze(FREEZE_SRX_HINT_UNDER));
    }

    if srx.anchor_mem_pool.len() as u64 > hint_anchor_count {
        return Err(AcceptanceError::Freeze(FREEZE_SRX_ANCHORS_OVERBUDGET));
    }

    let join_root_vec = canonical_set_root(&srx.join_leaf_ids)
        .map_err(|_| AcceptanceError::Freeze(FREEZE_SRX_INVALID))?;
    let join_root_arr: [u8; 32] = join_root_vec
        .as_slice()
        .try_into()
        .map_err(|_| AcceptanceError::Freeze(FREEZE_SRX_INVALID))?;
    if join_root_arr != *join_delta_root {
        return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
    }
    let since_root_vec = canonical_set_root(&srx.since_leaf_ids)
        .map_err(|_| AcceptanceError::Freeze(FREEZE_SRX_INVALID))?;
    let since_root_arr: [u8; 32] = since_root_vec
        .as_slice()
        .try_into()
        .map_err(|_| AcceptanceError::Freeze(FREEZE_SRX_INVALID))?;
    if since_root_arr != *revoked_since_root {
        return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
    }

    if let Some(frontier) = &srx.join_frontier {
        let expected = canonical_frontier(&srx.join_leaf_ids)
            .map_err(|_| AcceptanceError::Freeze(FREEZE_SRX_INVALID))?;
        if &expected != frontier {
            return Err(AcceptanceError::Freeze(FREEZE_SRX_FRONTIER_MISMATCH));
        }
    }
    if let Some(frontier) = &srx.since_frontier {
        let expected = canonical_frontier(&srx.since_leaf_ids)
            .map_err(|_| AcceptanceError::Freeze(FREEZE_SRX_INVALID))?;
        if &expected != frontier {
            return Err(AcceptanceError::Freeze(FREEZE_SRX_FRONTIER_MISMATCH));
        }
    }

    let validated_parent = validate_anchored_nonmem_array(
        &srx.join_nonmem_parent,
        &srx.anchor_mem_pool,
        parent_root,
        FREEZE_SRX_SET_CONFLICT_PARENT,
    )?;
    ensure_nonmem_coverage(&srx.join_leaf_ids, &validated_parent)?;

    let validated_revoked_since = validate_anchored_nonmem_array(
        &srx.join_nonmem_revoked_since,
        &srx.anchor_mem_pool,
        revoked_since_root,
        FREEZE_SRX_SET_CONFLICT_REVOKE,
    )?;
    ensure_nonmem_coverage(&srx.join_leaf_ids, &validated_revoked_since)?;

    let validated_subset =
        validate_membership_array(&srx.revoked_since_mem_in_revoked, revoked_root)?;
    ensure_mem_coverage(&srx.since_leaf_ids, &validated_subset)?;

    if let Some(root_sw) = proofs.srx_root_sw.as_ref() {
        let proof_bytes = proofs
            .srx_smallwood
            .as_ref()
            .ok_or(AcceptanceError::Freeze(FREEZE_SRX_SMALLWOOD_INVALID))?;

        let payload_digest = srx_smallwood::payload_digest(payload_bytes);

        let expected_shadow_after = srx_smallwood::compute_shadow_root(
            parent_root,
            &join_root_arr,
            revoked_since_root,
            revoked_root,
            Some(&commit),
            Some(&payload_digest),
        );
        if &expected_shadow_after != root_sw {
            return Err(AcceptanceError::Freeze(FREEZE_SRX_SMALLWOOD_INVALID));
        }

        let shadow_before = srx_smallwood::compute_shadow_root(
            parent_root,
            &join_root_arr,
            revoked_since_root,
            revoked_root,
            None,
            None,
        );

        let proof = srx_smallwood::Proof::from_bytes(proof_bytes.clone())?;
        let inputs = srx_smallwood::Inputs {
            shadow_root_before: &shadow_before,
            shadow_root_after: root_sw,
            parent_root,
            join_root: &join_root_arr,
            revoked_since_root,
            revoked_root,
            srx_commit: &commit,
            srx_mode: mode_text,
            proof_mode: proofs.proof_mode.as_str(),
            policy_version: proofs.policy_version.as_str(),
            vrf_id: proofs.vrf_id.as_str(),
            payload: payload_bytes,
            hint_counts_cbor: hint_counts_bytes,
            hint_sizes_cbor: hint_sizes_bytes,
        };
        srx_smallwood::verify(&inputs, &proof)?;
    } else if srx_present {
        return Err(AcceptanceError::Freeze(FREEZE_SRX_SMALLWOOD_INVALID));
    }

    cache.record_srx(
        cache_key,
        srx.join_leaf_ids.len() as u64,
        srx.since_leaf_ids.len() as u64,
        srx.anchor_mem_pool.len() as u64,
        payload_len,
        now,
    );

    Ok(())
}

pub(super) fn ensure_proofs(
    header: &BTreeMap<u64, Value>,
    allowed_proof_modes: Option<&BTreeSet<String>>,
    deprecated_proof_modes: &BTreeSet<String>,
    allowed_vrf_ids: Option<&BTreeSet<String>>,
    deprecated_vrf_ids: &BTreeSet<String>,
) -> Result<ProofArtifacts, AcceptanceError> {
    let proof_mode_owned = header_string_or_freeze(header, HDR_PROOF_MODE)?;
    if !is_supported_proof_mode(&proof_mode_owned) {
        return Err(AcceptanceError::Freeze(FREEZE_SUITE_FORBIDDEN));
    }
    let proof_mode = proof_mode_owned.as_str();
    if allowed_proof_modes.is_some_and(|allowed| !allowed.contains(proof_mode)) {
        return Err(AcceptanceError::Freeze(FREEZE_SUITE_FORBIDDEN));
    }
    if deprecated_proof_modes.contains(proof_mode) {
        return Err(AcceptanceError::Freeze(FREEZE_SUITE_DEPRECATED));
    }

    let vrf_id = header_string_or_freeze(header, HDR_VRF_ID)?;
    if !is_supported_vrf_id(&vrf_id) {
        return Err(AcceptanceError::Freeze(FREEZE_SUITE_FORBIDDEN));
    }
    if allowed_vrf_ids.is_some_and(|allowed| !allowed.contains(&vrf_id)) {
        return Err(AcceptanceError::Freeze(FREEZE_SUITE_FORBIDDEN));
    }
    if deprecated_vrf_ids.contains(&vrf_id) {
        return Err(AcceptanceError::Freeze(FREEZE_SUITE_DEPRECATED));
    }

    let policy_version_owned = match header.get(&HDR_POLICY_VERSION) {
        Some(Value::Text(text)) => text.clone(),
        Some(Value::Bytes(bytes)) => std::str::from_utf8(bytes)
            .map(|s| s.to_string())
            .map_err(|_| AcceptanceError::Freeze(FREEZE_FIELD_MISSING))?,
        _ => crate::DEFAULT_POLICY_VERSION.to_string(),
    };

    let mask_a = match header.get(&super::HDR_VRF_MASK_A) {
        Some(Value::Bytes(bytes)) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            arr
        }
        _ => return Err(AcceptanceError::Freeze(FREEZE_FIELD_MISSING)),
    };
    let mask_b = match header.get(&super::HDR_VRF_MASK_B) {
        Some(Value::Bytes(bytes)) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            arr
        }
        _ => return Err(AcceptanceError::Freeze(FREEZE_FIELD_MISSING)),
    };

    let vrf_pi = match header.get(&super::HDR_VRF_PROOF) {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => return Err(AcceptanceError::Freeze(FREEZE_FIELD_MISSING)),
    };
    let vrf_public = match header.get(&super::HDR_VRF_PUBLIC_KEY) {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => return Err(AcceptanceError::Freeze(FREEZE_FIELD_MISSING)),
    };
    let fs_capss = match header.get(&super::HDR_FS_CAPSS) {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => return Err(AcceptanceError::Freeze(FREEZE_FIELD_MISSING)),
    };

    let srx_present = header.contains_key(&super::HDR_SRX_MODE);
    let (srx_root_sw, srx_smallwood) = if srx_present {
        let root_bytes = match header.get(&super::HDR_SRX_ROOT_SW) {
            Some(Value::Bytes(bytes)) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                arr
            }
            _ => return Err(AcceptanceError::Freeze(FREEZE_SRX_SMALLWOOD_INVALID)),
        };
        let proof_bytes = match header.get(&super::HDR_SRX_SMALLWOOD) {
            Some(Value::Bytes(bytes)) => {
                if bytes.len() > SRX_SMALLWOOD_MAX_BYTES {
                    return Err(AcceptanceError::Freeze(FREEZE_SRX_SMALLWOOD_INVALID));
                }
                bytes.clone()
            }
            _ => return Err(AcceptanceError::Freeze(FREEZE_SRX_SMALLWOOD_INVALID)),
        };
        (Some(root_bytes), Some(proof_bytes))
    } else {
        if header.contains_key(&super::HDR_SRX_ROOT_SW)
            || header.contains_key(&super::HDR_SRX_SMALLWOOD)
        {
            return Err(AcceptanceError::Freeze(FREEZE_SRX_INVALID));
        }
        (None, None)
    };

    let stored_commit = header_bytes32_or_freeze(
        header,
        super::HDR_PROOFS_COMMIT,
        FREEZE_FIELD_MISSING,
        "proofs_commit",
    )?;
    if fs_capss.len() > FS_CAPSS_MAX_BYTES {
        return Err(AcceptanceError::Freeze(FREEZE_CAPSS_INVALID));
    }

    let recomputed = compute_proofs_commit_bytes(
        vrf_pi.as_slice(),
        fs_capss.as_slice(),
        srx_root_sw.as_ref().map(|arr| arr.as_slice()),
        srx_smallwood.as_deref(),
    )
    .map_err(AcceptanceError::from)?;
    if recomputed != stored_commit {
        return Err(AcceptanceError::Freeze(FREEZE_PROOFS_COMMIT_INVALID));
    }

    Ok(ProofArtifacts {
        commit: stored_commit,
        vrf_pi,
        fs_capss,
        srx_root_sw,
        srx_smallwood,
        proof_mode: proof_mode_owned,
        vrf_id,
        mask_a,
        mask_b,
        policy_version: policy_version_owned,
        vrf_public,
    })
}

pub(super) fn ensure_tswe_alg(header: &BTreeMap<u64, Value>) -> Result<(), AcceptanceError> {
    let Some(value) = header.get(&super::HDR_TSWE_ALG) else {
        return Err(AcceptanceError::Freeze(FREEZE_TSWE_ALG_INVALID));
    };
    let matches = match value {
        Value::Integer(_) => value
            .as_integer()
            .and_then(|int| u8::try_from(int).ok())
            .map(|code| code == TSWE_ALG_CODE)
            .unwrap_or(false),
        Value::Text(text) => text == TSWE_ALG_LABEL,
        Value::Bytes(bytes) => std::str::from_utf8(bytes)
            .map(|s| s == TSWE_ALG_LABEL)
            .unwrap_or(false),
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(AcceptanceError::Freeze(FREEZE_TSWE_ALG_INVALID))
    }
}

pub(super) fn ensure_merkle_suite(header: &BTreeMap<u64, Value>) -> Result<(), AcceptanceError> {
    let Some(value) = header.get(&super::HDR_MERKLE_SUITE) else {
        return Err(AcceptanceError::Freeze(FREEZE_MERKLE_SUITE_INVALID));
    };
    let matches = match value {
        Value::Text(text) => text == super::MERKLE_DS_ID,
        Value::Bytes(bytes) => std::str::from_utf8(bytes)
            .map(|s| s == super::MERKLE_DS_ID)
            .unwrap_or(false),
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(AcceptanceError::Freeze(FREEZE_MERKLE_SUITE_INVALID))
    }
}

pub(super) fn ensure_kbroad_alg(header: &BTreeMap<u64, Value>) -> Result<(), AcceptanceError> {
    let Some(value) = header.get(&super::HDR_KBROAD_ALG) else {
        return Err(AcceptanceError::Freeze(FREEZE_KBROAD_ALG_INVALID));
    };
    let matches = match value {
        Value::Text(text) => text == KBROAD_ML_KEM_ALG,
        Value::Bytes(bytes) => std::str::from_utf8(bytes)
            .map(|s| s == KBROAD_ML_KEM_ALG)
            .unwrap_or(false),
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(AcceptanceError::Freeze(FREEZE_KBROAD_ALG_INVALID))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Result, anyhow, bail};
    use pqcrypto_kyber::kyber768::ciphertext_bytes as ml_kem_ciphertext_bytes;

    fn base_header() -> BTreeMap<u64, Value> {
        BTreeMap::new()
    }

    #[test]
    fn verify_join_payload_kbroad_accepts_well_formed_envelope() -> Result<()> {
        let mut header = base_header();
        let envelope = Value::Array(vec![
            Value::Text(KBROAD_MODE.to_string()),
            Value::Bytes(vec![0u8; ml_kem_ciphertext_bytes()]),
            Value::Bytes(vec![0u8; super::KBROAD_WRAP_CIPHERTEXT_BYTES]),
            Value::Bytes(vec![0u8; crate::AEAD_TAG_LEN]),
            Value::Text("chacha20-poly1305".to_string()),
        ]);
        header.insert(super::HDR_HP_BYTES, envelope);

        verify_join_payload_kbroad(
            &AcceptanceContext::with_defaults(),
            &header,
            None,
            &[0u8; 32],
            &[0u8; 32],
        )?;
        Ok(())
    }

    #[test]
    fn verify_join_payload_kbroad_rejects_invalid_ciphertext_length() -> Result<()> {
        let mut header = base_header();
        let envelope = Value::Array(vec![
            Value::Text(KBROAD_MODE.to_string()),
            Value::Bytes(vec![0u8; ml_kem_ciphertext_bytes() - 1]),
            Value::Bytes(vec![0u8; super::KBROAD_WRAP_CIPHERTEXT_BYTES]),
            Value::Bytes(vec![0u8; crate::AEAD_TAG_LEN]),
            Value::Text("chacha20-poly1305".to_string()),
        ]);
        header.insert(super::HDR_HP_BYTES, envelope);

        let err = match verify_join_payload_kbroad(
            &AcceptanceContext::with_defaults(),
            &header,
            None,
            &[0u8; 32],
            &[0u8; 32],
        ) {
            Ok(_) => bail!("expected failure"),
            Err(e) => e,
        };
        let AcceptanceError::Freeze(code) = err else {
            return Err(anyhow!("unexpected error"));
        };
        assert_eq!(code, FREEZE_KBROAD_PARENT_MISMATCH);
        Ok(())
    }

    #[test]
    fn ensure_merge_join_keys_absent_flags_join_fields() -> Result<()> {
        let mut header = base_header();
        header.insert(super::HDR_HP_BYTES, Value::Bytes(vec![]));

        let err = match ensure_merge_join_keys_absent(&header) {
            Ok(_) => bail!("join keys must be rejected"),
            Err(e) => e,
        };
        let AcceptanceError::Freeze(code) = err else {
            return Err(anyhow!("unexpected error"));
        };
        assert_eq!(code, FREEZE_MERGE_JOIN_KEYS);
        Ok(())
    }

    #[test]
    fn ensure_tswe_alg_rejects_unexpected_code() -> Result<()> {
        let mut header = base_header();
        header.insert(
            super::HDR_TSWE_ALG,
            Value::Integer(Integer::from(u64::from(TSWE_ALG_CODE) + 1)),
        );

        let err = match ensure_tswe_alg(&header) {
            Ok(_) => bail!("wrong algorithm code should freeze"),
            Err(e) => e,
        };
        let AcceptanceError::Freeze(code) = err else {
            return Err(anyhow!("unexpected error"));
        };
        assert_eq!(code, FREEZE_TSWE_ALG_INVALID);
        Ok(())
    }

    fn dummy_proofs() -> ProofArtifacts {
        ProofArtifacts {
            commit: [0u8; 32],
            vrf_pi: Vec::new(),
            fs_capss: Vec::new(),
            srx_root_sw: None,
            srx_smallwood: None,
            proof_mode: String::new(),
            vrf_id: String::new(),
            mask_a: [0u8; 32],
            mask_b: [0u8; 32],
            policy_version: String::new(),
            vrf_public: Vec::new(),
        }
    }

    #[test]
    fn ensure_srx_relations_allows_absent_when_optional() -> Result<()> {
        let header = base_header();
        let mut cache = VckCache::new(Duration::from_secs(60));
        ensure_srx_relations(
            &header,
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            false,
            1024,
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            None,
            &BTreeSet::new(),
            AcceptInstant::from_ticks(0),
            &mut cache,
            &dummy_proofs(),
        )?;
        Ok(())
    }

    #[test]
    fn ensure_srx_relations_requires_payload_when_mandatory() -> Result<()> {
        let header = base_header();
        let mut cache = VckCache::new(Duration::from_secs(60));
        let err = match ensure_srx_relations(
            &header,
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            true,
            1024,
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            None,
            &BTreeSet::new(),
            AcceptInstant::from_ticks(0),
            &mut cache,
            &dummy_proofs(),
        ) {
            Ok(_) => bail!("required SRX should freeze when missing"),
            Err(e) => e,
        };
        let AcceptanceError::Freeze(code) = err else {
            return Err(anyhow!("unexpected error"));
        };
        assert_eq!(code, FREEZE_SRX_REQUIRED);
        Ok(())
    }

    #[test]
    fn ensure_srx_relations_detects_hint_without_mode() -> Result<()> {
        let mut header = base_header();
        header.insert(super::HDR_SRX_HINT_COUNTS, Value::Bytes(Vec::new()));
        let mut cache = VckCache::new(Duration::from_secs(60));
        let err = match ensure_srx_relations(
            &header,
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            false,
            1024,
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            None,
            &BTreeSet::new(),
            AcceptInstant::from_ticks(0),
            &mut cache,
            &dummy_proofs(),
        ) {
            Ok(_) => bail!("orphaned hints should freeze"),
            Err(e) => e,
        };
        let AcceptanceError::Freeze(code) = err else {
            return Err(anyhow!("unexpected error"));
        };
        assert_eq!(code, FREEZE_SRX_INVALID);
        Ok(())
    }
}
