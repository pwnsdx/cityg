//! Deterministic binding between the HP transcript commitments and published
//! metadata.
//!
//! The helper in this module therefore binds the
//! public commitments and context hashes only. It produces a digest that both
//! joiner and verifier can recompute without accessing the HP payload bytes.

use ciborium::ser::into_writer;
use msphf_core::{MsphfError, hash::hash_bytes_with_label, serde_utils::to_cbor_vec};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// Public inputs required by the hp_k proof harness.
#[derive(Debug)]
pub struct HpBindingInputs<'a> {
    pub msphf_crs_id: &'a str,
    pub params_id: &'a str,
    pub seed_ctx_hash: &'a [u8; 32],
    pub seed_commit: &'a [u8; 32],
    pub rho_commit: &'a [u8; 32],
    pub xk_hash: &'a [u8; 32],
    pub hp_commit: &'a [u8; 32],
}

/// Deterministic digest binding the public inputs to the committed HP payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HpProof {
    #[serde(with = "serde_bytes")]
    digest: Vec<u8>,
}

#[derive(Serialize)]
struct Transcript<'a> {
    msphf_crs_id: &'a str,
    params_id: &'a str,
    #[serde(with = "serde_bytes")]
    seed_ctx_hash: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    seed_commit: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    rho_commit: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    xk_hash: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    hp_commit: &'a [u8; 32],
}

/// Produce a deterministic digest representing the HP binding proof.
pub fn prove_hp_k(inputs: &HpBindingInputs<'_>) -> Result<HpProof, MsphfError> {
    let transcript = Transcript {
        msphf_crs_id: inputs.msphf_crs_id,
        params_id: inputs.params_id,
        seed_ctx_hash: inputs.seed_ctx_hash,
        seed_commit: inputs.seed_commit,
        rho_commit: inputs.rho_commit,
        xk_hash: inputs.xk_hash,
        hp_commit: inputs.hp_commit,
    };
    let digest = hash_bytes_with_label("msphf/hp-binding/proof", &to_cbor_vec(&transcript)?)?;
    Ok(HpProof {
        digest: digest.to_vec(),
    })
}

/// Verify the deterministic digest matches the expected transcript.
///
/// # Constant-Time Security
/// This function uses constant-time comparison (via `subtle::ConstantTimeEq`) to prevent
/// timing attacks. The comparison time does not depend on the position of the first
/// differing byte between the digests.
pub fn verify_hp_k(inputs: &HpBindingInputs<'_>, proof: &HpProof) -> Result<(), MsphfError> {
    let expected = prove_hp_k(inputs)?;

    // Use constant-time comparison to prevent timing side-channels
    // This ensures that the comparison time is independent of the content
    if expected.digest.ct_eq(proof.digest.as_slice()).into() {
        Ok(())
    } else {
        Err(MsphfError::invalid_input("hp_k proof mismatch"))
    }
}

/// Serialise a proof to CBOR.
pub fn proof_to_cbor(proof: &HpProof) -> Result<Vec<u8>, MsphfError> {
    let mut buf = Vec::new();
    into_writer(proof, &mut buf).map_err(MsphfError::serialization)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Result, bail};
    use msphf_core::params::{RLWE_CRS_ID_DEFAULT, RLWE_PARAMS_ID_MOCK};

    #[test]
    fn roundtrip_proof_digest() -> Result<()> {
        let inputs = HpBindingInputs {
            msphf_crs_id: RLWE_CRS_ID_DEFAULT,
            params_id: RLWE_PARAMS_ID_MOCK,
            seed_ctx_hash: &[0x01; 32],
            seed_commit: &[0x02; 32],
            rho_commit: &[0x03; 32],
            xk_hash: &[0x04; 32],
            hp_commit: &[0x05; 32],
        };
        let proof = prove_hp_k(&inputs)?;
        verify_hp_k(&inputs, &proof)?;
        Ok(())
    }

    #[test]
    fn different_commit_changes_digest() -> Result<()> {
        let base = HpBindingInputs {
            msphf_crs_id: RLWE_CRS_ID_DEFAULT,
            params_id: RLWE_PARAMS_ID_MOCK,
            seed_ctx_hash: &[0x10; 32],
            seed_commit: &[0x11; 32],
            rho_commit: &[0x12; 32],
            xk_hash: &[0x13; 32],
            hp_commit: &[0x14; 32],
        };
        let proof = prove_hp_k(&base)?;

        let mutated = HpBindingInputs {
            hp_commit: &[0x15; 32],
            ..base
        };
        if verify_hp_k(&mutated, &proof).is_ok() {
            bail!("verification should fail for mutated commit");
        }
        Ok(())
    }
}
