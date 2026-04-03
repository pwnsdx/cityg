use anyhow::{Result, anyhow};
use ml_kem::{
    ExpandedDecapsulationKey as MlKemExpandedDecapsulationKey, Seed as MlKemSeed,
    kem::{Decapsulate as MlKemDecapsulate, KeyExport as MlKemKeyExport},
    ml_kem_768,
    ml_kem_768::DecapsulationKey as MlKem768DecapsulationKey,
};
use msphf_core::{hash::h_l, hkdf::hkdf_blake3};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
};
use serde::Serialize;

use crate::barrier::compute_barrier_pkhash;

pub const BARRIER_KEYGEN_D_INFO: &[u8] = b"city-g|barrier/keygen-d|v1";
pub const BARRIER_KEYGEN_Z_INFO: &[u8] = b"city-g|barrier/keygen-z|v1";
pub const FS_PCS_INFO: &[u8] = b"city-g|fs/pcs|v1";
pub const ML_KEM_SEED_BYTES: usize = 64;
pub const ML_KEM_EXPANDED_DK_BYTES: usize = 2400;

#[derive(Serialize)]
struct FsPcsSaltPreimage<'a>(#[serde(with = "serde_bytes")] &'a [u8; 32], u64, u64);

#[derive(Serialize)]
struct BarrierKeygenSaltPreimage<'a>(
    #[serde(with = "serde_bytes")] &'a [u8],
    u64,
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    u64,
    u64,
);

pub fn derive_k_fs_after_pcs(
    k_fs_before: &[u8; 32],
    weid: &[u8; 32],
    fs_ec: u64,
    barrier_version: u64,
    k_barrier_new: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(k_fs_before);
    ikm[32..].copy_from_slice(k_barrier_new);
    let salt = h_l(
        "fs/pcs/salt",
        &FsPcsSaltPreimage(weid, fs_ec, barrier_version),
    )
    .map_err(|err| anyhow!("derive fs pcs salt: {err}"))?;
    Ok(hkdf_blake3(&salt, &ikm, FS_PCS_INFO))
}

pub fn generate_kbroad_keypair() -> (Vec<u8>, Vec<u8>) {
    let (public, secret) = kyber768::keypair();
    (
        KemPublicKey::as_bytes(&public).to_vec(),
        KemSecretKey::as_bytes(&secret).to_vec(),
    )
}

pub fn barrier_leaf_public_key_bytes() -> usize {
    kyber768::public_key_bytes()
}

pub fn barrier_leaf_secret_key_bytes() -> usize {
    kyber768::secret_key_bytes()
}

pub fn generate_barrier_leaf_keypair() -> Result<(Vec<u8>, Vec<u8>, [u8; 32])> {
    let (public, secret) = kyber768::keypair();
    let public_key = KemPublicKey::as_bytes(&public).to_vec();
    let secret_key = KemSecretKey::as_bytes(&secret).to_vec();
    let pkhash = compute_barrier_pkhash(public_key.as_slice())?;
    Ok((public_key, secret_key, pkhash))
}

pub fn encapsulate_barrier_public_key(public_key_bytes: &[u8]) -> Result<([u8; 32], Vec<u8>)> {
    let public_key = kyber768::PublicKey::from_bytes(public_key_bytes)
        .map_err(|_| anyhow!("invalid barrier leaf public key"))?;
    let (shared_secret, ciphertext) = kyber768::encapsulate(&public_key);
    let mut ss = [0u8; 32];
    ss.copy_from_slice(shared_secret.as_bytes());
    Ok((ss, KemCiphertext::as_bytes(&ciphertext).to_vec()))
}

pub fn derive_internal_node_key_material(
    gid: &[u8],
    path_secret: &[u8; 32],
    barrier_version: u64,
    revocation_roots_hash: &[u8; 32],
    n_max: u64,
    node: u64,
) -> Result<(Vec<u8>, [u8; 32], Vec<u8>)> {
    let d_salt = h_l(
        "barrier/keygen/d_salt",
        &BarrierKeygenSaltPreimage(gid, barrier_version, revocation_roots_hash, n_max, node),
    )
    .map_err(|err| anyhow!("derive barrier keygen d_salt: {err}"))?;
    let z_salt = h_l(
        "barrier/keygen/z_salt",
        &BarrierKeygenSaltPreimage(gid, barrier_version, revocation_roots_hash, n_max, node),
    )
    .map_err(|err| anyhow!("derive barrier keygen z_salt: {err}"))?;
    let d = hkdf_blake3(&d_salt, path_secret, BARRIER_KEYGEN_D_INFO);
    let z = hkdf_blake3(&z_salt, path_secret, BARRIER_KEYGEN_Z_INFO);
    let mut seed_bytes = [0u8; ML_KEM_SEED_BYTES];
    seed_bytes[..32].copy_from_slice(&d);
    seed_bytes[32..].copy_from_slice(&z);

    let dk = MlKem768DecapsulationKey::from_seed(MlKemSeed::from(seed_bytes));
    #[allow(deprecated)]
    let dk_expanded =
        <MlKem768DecapsulationKey as ml_kem::ExpandedKeyEncoding>::to_expanded_bytes(&dk);
    let ek_bytes = dk.encapsulation_key().to_bytes();
    let pkhash = compute_barrier_pkhash(ek_bytes.as_slice())?;
    Ok((
        dk_expanded.as_slice().to_vec(),
        pkhash,
        ek_bytes.as_slice().to_vec(),
    ))
}

pub fn decapsulate_internal_node_shared_secret(
    dk_expanded_bytes: &[u8],
    kem_ct: &[u8],
) -> Result<[u8; 32]> {
    let expanded: MlKemExpandedDecapsulationKey<ml_kem_768::MlKem768> = dk_expanded_bytes
        .try_into()
        .map_err(|_| anyhow!("internal dk_n must be 2400 bytes"))?;
    #[allow(deprecated)]
    let dk =
        <MlKem768DecapsulationKey as ml_kem::ExpandedKeyEncoding>::from_expanded_bytes(&expanded)
            .map_err(|_| anyhow!("invalid internal dk_n encoding"))?;
    let shared = dk
        .decapsulate_slice(kem_ct)
        .map_err(|_| anyhow!("invalid internal node ciphertext"))?;
    let mut ss = [0u8; 32];
    ss.copy_from_slice(shared.as_slice());
    Ok(ss)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use ml_kem::kem::{Encapsulate as MlKemEncapsulate, TryKeyInit as MlKemTryKeyInit};

    #[test]
    fn derive_k_fs_after_pcs_is_stable() -> Result<()> {
        let out1 = derive_k_fs_after_pcs(&[0x11; 32], &[0x22; 32], 4, 9, &[0x33; 32])?;
        let out2 = derive_k_fs_after_pcs(&[0x11; 32], &[0x22; 32], 4, 9, &[0x33; 32])?;
        assert_eq!(out1, out2);
        Ok(())
    }

    #[test]
    fn internal_node_key_material_derives_roundtrip_secret() -> Result<()> {
        let path_secret = [0x41; 32];
        let (dk_bytes, pkhash, ek_bytes) =
            derive_internal_node_key_material(b"room", &path_secret, 7, &[0x55; 32], 8, 1)?;
        assert_eq!(pkhash, compute_barrier_pkhash(ek_bytes.as_slice())?);

        let ek = ml_kem_768::EncapsulationKey::new_from_slice(ek_bytes.as_slice())
            .map_err(|_| anyhow!("invalid derived encapsulation key"))?;
        let (ct, shared) = ek.encapsulate();
        let recovered =
            decapsulate_internal_node_shared_secret(dk_bytes.as_slice(), ct.as_slice())?;
        assert_eq!(recovered.as_slice(), shared.as_slice());
        Ok(())
    }

    #[test]
    fn generate_barrier_leaf_keypair_reports_matching_pkhash() -> Result<()> {
        let (public_key, _secret_key, pkhash) = generate_barrier_leaf_keypair()?;
        assert_eq!(pkhash, compute_barrier_pkhash(public_key.as_slice())?);
        Ok(())
    }
}
