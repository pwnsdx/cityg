use std::{collections::BTreeMap, sync::Arc};

use ciborium::de::from_reader;
use ciborium::value::{Integer, Value};
use msphf_orchestrator::{MaskDigest, PivotParity, hdr};
use serde::Deserialize;
use serde_bytes::ByteBuf;

use crate::CityGError;

const MAX_PIVOT_PARITY_CBOR_BYTES: usize = 2 * 1024 * 1024;

#[derive(Deserialize)]
struct PivotParitySerializable {
    gid: ByteBuf,
    cat: ByteBuf,
    parent_root: ByteBuf,
    we_epoch_id: ByteBuf,
    rho_commit: ByteBuf,
    seed_ctx_hash: ByteBuf,
    seed_commit: ByteBuf,
    hp_commit: ByteBuf,
    xk_hash: ByteBuf,
    join_delta_root: ByteBuf,
    revoked_since_root: ByteBuf,
    revoked_root: ByteBuf,
    accept_seq: u64,
    crs_id: ByteBuf,
    params_id: ByteBuf,
    policy_version: String,
    proof_mode: String,
    vrf_id: String,
    vrf_proof: ByteBuf,
    vrf_public: ByteBuf,
    mask_a: ByteBuf,
    mask_b: ByteBuf,
    fs_capss: ByteBuf,
    proofs_commit: ByteBuf,
    srx_commit: Option<ByteBuf>,
    srx_root_sw: Option<ByteBuf>,
    is_join: bool,
    hp_envelope: ByteBuf,
    fs_epoch_commit: Option<ByteBuf>,
    fs_ec: Option<u64>,
    fs_dev_commit: Option<ByteBuf>,
}

pub fn pivot_parity_from_cbor(bytes: &[u8]) -> Result<PivotParity, CityGError> {
    if bytes.len() > MAX_PIVOT_PARITY_CBOR_BYTES {
        return Err(CityGError::InvalidInput("pivot parity payload too large"));
    }
    let serializable: PivotParitySerializable =
        from_reader(bytes).map_err(|_| CityGError::InvalidInput("invalid pivot parity"))?;

    Ok(PivotParity {
        gid: serializable.gid.into_vec(),
        cat: serializable.cat.into_vec(),
        parent_root: to_array32(serializable.parent_root)?,
        we_epoch_id: to_array32(serializable.we_epoch_id)?,
        rho_commit: to_array32(serializable.rho_commit)?,
        seed_ctx_hash: to_array32(serializable.seed_ctx_hash)?,
        seed_commit: to_array32(serializable.seed_commit)?,
        hp_commit: to_array32(serializable.hp_commit)?,
        xk_hash: to_array32(serializable.xk_hash)?,
        join_delta_root: to_array32(serializable.join_delta_root)?,
        revoked_since_root: to_array32(serializable.revoked_since_root)?,
        revoked_root: to_array32(serializable.revoked_root)?,
        accept_seq: serializable.accept_seq,
        crs_id: serializable.crs_id.into_vec(),
        params_id: serializable.params_id.into_vec(),
        policy_version: serializable.policy_version,
        proof_mode: serializable.proof_mode,
        vrf_id: serializable.vrf_id,
        vrf_proof: serializable.vrf_proof.into_vec(),
        vrf_public: serializable.vrf_public.into_vec(),
        mask_a: to_mask(serializable.mask_a)?,
        mask_b: to_mask(serializable.mask_b)?,
        fs_capss: serializable.fs_capss.into_vec(),
        proofs_commit: to_array32(serializable.proofs_commit)?,
        srx_commit: serializable.srx_commit.map(to_array32).transpose()?,
        srx_root_sw: serializable.srx_root_sw.map(to_array32).transpose()?,
        is_join: serializable.is_join,
        hp_envelope: Arc::from(serializable.hp_envelope.into_vec()),
        fs_epoch_commit: serializable.fs_epoch_commit.map(to_array32).transpose()?,
        fs_ec: serializable.fs_ec,
        fs_dev_commit: serializable.fs_dev_commit.map(to_array32).transpose()?,
    })
}

fn to_array32(buf: ByteBuf) -> Result<[u8; 32], CityGError> {
    let vec = buf.into_vec();
    match vec.try_into() {
        Ok(arr) => Ok(arr),
        Err(_) => Err(CityGError::InvalidInput("pivot parity field wrong length")),
    }
}

fn to_mask(buf: ByteBuf) -> Result<MaskDigest, CityGError> {
    to_array32(buf)
}

pub fn strip_rollup_metadata(header: &mut BTreeMap<u64, Value>) {
    for key in [
        hdr::HDR_ROLLUP_PROVENANCE_COMMIT,
        hdr::HDR_ROLLUP_EPOCH_REPLAY,
        hdr::HDR_ROLLUP_VCK_COMMIT,
    ] {
        header.remove(&key);
    }
}

pub fn hydrate_parities(
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

pub fn apply_pivot_alignment(header: &mut BTreeMap<u64, Value>, pivot: &PivotParity) {
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

pub fn select_pivot_parity(parities: &[PivotParity]) -> Option<&PivotParity> {
    parities.iter().max_by(|a, b| {
        a.accept_seq
            .cmp(&b.accept_seq)
            .then_with(|| b.xk_hash.cmp(&a.xk_hash))
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample_pivot_parity() -> PivotParity {
        PivotParity {
            gid: vec![0x11; 32],
            cat: vec![0x22; 32],
            parent_root: [0x33; 32],
            we_epoch_id: [0x44; 32],
            rho_commit: [0x45; 32],
            seed_ctx_hash: [0x46; 32],
            seed_commit: [0x47; 32],
            hp_commit: [0x48; 32],
            xk_hash: [0x49; 32],
            join_delta_root: [0x4A; 32],
            revoked_since_root: [0x4B; 32],
            revoked_root: [0x4C; 32],
            accept_seq: 7,
            crs_id: vec![0x4D],
            params_id: vec![0x4E],
            policy_version: "9".to_string(),
            proof_mode: "lin+zkvrf".to_string(),
            vrf_id: "lb-vrf/mock".to_string(),
            vrf_proof: vec![0x4F],
            vrf_public: vec![0x50],
            mask_a: [0x51; 32],
            mask_b: [0x52; 32],
            fs_capss: vec![0x53],
            proofs_commit: [0x54; 32],
            srx_commit: Some([0x55; 32]),
            srx_root_sw: Some([0x56; 32]),
            is_join: false,
            hp_envelope: Arc::from(vec![0x57]),
            fs_epoch_commit: Some([0x58; 32]),
            fs_ec: Some(59),
            fs_dev_commit: Some([0x5A; 32]),
        }
    }

    #[test]
    fn hydrate_and_select_pivot_parity_keep_newest() {
        let mut older = sample_pivot_parity();
        older.accept_seq = 4;
        older.fs_ec = None;
        older.fs_epoch_commit = None;
        older.fs_dev_commit = None;

        let mut newer = sample_pivot_parity();
        newer.accept_seq = 9;
        newer.xk_hash = [0xAA; 32];

        let hydrated = hydrate_parities(&[older, newer.clone()], 88, [0xAB; 32], [0xBC; 32]);
        assert_eq!(hydrated[0].fs_ec, Some(88));
        assert_eq!(hydrated[0].fs_epoch_commit, Some([0xAB; 32]));
        assert_eq!(hydrated[0].fs_dev_commit, Some([0xBC; 32]));
        assert_eq!(
            select_pivot_parity(&hydrated).unwrap().accept_seq,
            newer.accept_seq
        );
    }

    #[test]
    fn strip_rollup_metadata_removes_only_rollup_fields() {
        let mut header = BTreeMap::new();
        header.insert(hdr::HDR_ROLLUP_PROVENANCE_COMMIT, Value::Bytes(vec![1]));
        header.insert(hdr::HDR_ROLLUP_EPOCH_REPLAY, Value::Bytes(vec![2]));
        header.insert(hdr::HDR_ROLLUP_VCK_COMMIT, Value::Bytes(vec![3]));
        header.insert(hdr::HDR_VRF_ID, Value::Text("kept".to_string()));
        strip_rollup_metadata(&mut header);
        assert!(!header.contains_key(&hdr::HDR_ROLLUP_PROVENANCE_COMMIT));
        assert!(!header.contains_key(&hdr::HDR_ROLLUP_EPOCH_REPLAY));
        assert!(!header.contains_key(&hdr::HDR_ROLLUP_VCK_COMMIT));
        assert_eq!(
            header.get(&hdr::HDR_VRF_ID),
            Some(&Value::Text("kept".to_string()))
        );
    }
}
