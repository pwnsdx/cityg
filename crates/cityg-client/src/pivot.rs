use std::sync::Arc;

use ciborium::de::from_reader;
use msphf_orchestrator::{MaskDigest, PivotParity};
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
