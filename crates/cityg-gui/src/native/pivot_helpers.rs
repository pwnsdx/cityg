use super::*;

pub(super) fn strip_rollup_metadata(header: &mut BTreeMap<u64, Value>) {
    for key in [
        hdr::HDR_ROLLUP_PROVENANCE_COMMIT,
        hdr::HDR_ROLLUP_EPOCH_REPLAY,
        hdr::HDR_ROLLUP_VCK_COMMIT,
    ] {
        header.remove(&key);
    }
}

pub(super) fn hydrate_parities(
    parities: &[PivotParity],
    fs_ec: u64,
    fs_epoch_commit: [u8; 32],
    fs_dev_commit: [u8; 32],
) -> Vec<PivotParity> {
    parities
        .iter()
        .cloned()
        .map(|mut parity| {
            if parity.fs_ec.is_none() {
                parity.fs_ec = Some(fs_ec);
            }
            if parity.fs_epoch_commit.is_none() {
                parity.fs_epoch_commit = Some(fs_epoch_commit);
            }
            if parity.fs_dev_commit.is_none() {
                parity.fs_dev_commit = Some(fs_dev_commit);
            }
            parity
        })
        .collect()
}

pub(super) fn apply_pivot_alignment(header: &mut BTreeMap<u64, Value>, pivot: &PivotParity) {
    if let Ok(fs_policy_version) = pivot.policy_version.parse::<u64>() {
        header
            .entry(hdr::HDR_FS_POLICY_VERSION)
            .or_insert_with(|| Value::Integer(Integer::from(fs_policy_version)));
    }
    header
        .entry(hdr::HDR_PROOF_MODE)
        .or_insert_with(|| Value::Text(pivot.proof_mode.clone()));
    header
        .entry(hdr::HDR_VRF_ID)
        .or_insert_with(|| Value::Text(pivot.vrf_id.clone()));
    header
        .entry(hdr::HDR_VRF_PROOF)
        .or_insert_with(|| Value::Bytes(pivot.vrf_proof.clone()));
    header
        .entry(hdr::HDR_VRF_PUBLIC_KEY)
        .or_insert_with(|| Value::Bytes(pivot.vrf_public.clone()));
    header
        .entry(hdr::HDR_VRF_MASK_A)
        .or_insert_with(|| Value::Bytes(pivot.mask_a.to_vec()));
    header
        .entry(hdr::HDR_VRF_MASK_B)
        .or_insert_with(|| Value::Bytes(pivot.mask_b.to_vec()));
    header
        .entry(hdr::HDR_FS_CAPSS)
        .or_insert_with(|| Value::Bytes(pivot.fs_capss.clone()));
    header
        .entry(hdr::HDR_PROOFS_COMMIT)
        .or_insert_with(|| Value::Bytes(pivot.proofs_commit.to_vec()));

    if let Some(fs_ec) = pivot.fs_ec {
        header
            .entry(hdr::HDR_FS_EC)
            .or_insert_with(|| Value::Integer(Integer::from(fs_ec)));
        header
            .entry(hdr::HDR_FS_CHECKPOINT_EC)
            .or_insert_with(|| Value::Integer(Integer::from(fs_ec)));
    }
    if let Some(epoch_commit) = pivot.fs_epoch_commit {
        header
            .entry(hdr::HDR_FS_EPOCH_COMMIT)
            .or_insert_with(|| Value::Bytes(epoch_commit.to_vec()));
    }
    if let Some(dev_commit) = pivot.fs_dev_commit {
        header
            .entry(hdr::HDR_FS_DEV_PREV_COMMIT)
            .or_insert_with(|| Value::Bytes(dev_commit.to_vec()));
        header
            .entry(hdr::HDR_FS_DEV_COMMIT)
            .or_insert_with(|| Value::Bytes(dev_commit.to_vec()));
    }
}

pub(super) fn select_pivot_parity(parities: &[PivotParity]) -> Option<&PivotParity> {
    parities.iter().max_by(|a, b| {
        a.accept_seq
            .cmp(&b.accept_seq)
            .then_with(|| b.xk_hash.cmp(&a.xk_hash))
    })
}
