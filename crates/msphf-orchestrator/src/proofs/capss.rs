use crate::accept::{AcceptanceError, FREEZE_CAPSS_INVALID};
use anyhow::Error;
use capss::{
    CapssContext, CapssProver, CapssVerifier,
    config::CapssConfig,
    field::FieldElement,
    smallwood::SmallwoodProof,
    smallwood_prover, smallwood_verifier,
    types::{CapssProof, CapssPublicKey, CapssSignature, CapssStatement},
};
use ciborium::ser::into_writer;
use msphf_core::MsphfError;
use rand_core::{CryptoRng, RngCore};
use serde::Serialize;

#[derive(Clone)]
pub struct Inputs<'a> {
    #[allow(dead_code)]
    pub seed_commit: &'a [u8; 32],
    pub seed_bundle_commit: &'a [u8; 32],
    pub rho_commit: &'a [u8; 32],
    pub hp_commit: &'a [u8; 32],
    pub bind: BindingInputs<'a>,
}

#[derive(Clone)]
pub struct BindingInputs<'a> {
    pub xk_hash: &'a [u8; 32],
    pub crs_id: &'a str,
    pub params_id: &'a str,
    pub proof_mode: &'a str,
    pub policy_version: &'a str,
    pub vrf_id: &'a str,
    pub parent_root: &'a [u8],
    pub join_delta_root: &'a [u8],
    pub revoked_since_prev_root: &'a [u8],
    pub revoked_root: &'a [u8],
    pub fs_epoch_commit: &'a [u8; 32],
    pub fs_ec: u64,
    pub fs_dev_prev_commit: &'a [u8; 32],
    pub fs_dev_commit: &'a [u8; 32],
}

#[derive(Clone)]
pub struct Proof {
    transcript: Vec<u8>,
}

impl Proof {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, AcceptanceError> {
        let signature = signature_from_bytes(&bytes);
        SmallwoodProof::try_from(&signature).map_err(map_smallwood_decode_error)?;
        Ok(Self { transcript: bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.transcript
    }

    fn to_signature(&self) -> CapssSignature {
        signature_from_bytes(&self.transcript)
    }
}

pub fn prove<R: RngCore + CryptoRng>(_: &mut R, inputs: &Inputs<'_>) -> Result<Proof, MsphfError> {
    let (context, statement) = build_capss_components(inputs)?;
    let prover = smallwood_prover(context);
    let signature = prover
        .prove(&statement)
        .map_err(map_smallwood_prove_error)?;
    let CapssSignature {
        proof: CapssProof { bytes },
    } = signature;
    Ok(Proof { transcript: bytes })
}

pub fn verify(inputs: &Inputs<'_>, proof: &Proof) -> Result<(), AcceptanceError> {
    let (context, statement) = build_capss_components(inputs).map_err(AcceptanceError::from)?;
    let signature = proof.to_signature();
    smallwood_verifier(context)
        .verify(&statement, &signature)
        .map_err(map_smallwood_verify_error)
}

fn build_capss_components(
    inputs: &Inputs<'_>,
) -> Result<(CapssContext, CapssStatement), MsphfError> {
    let config = CapssConfig {
        fs_domain: "msphf/smallwood/chal".to_string(),
        ..Default::default()
    };

    let public_key = CapssPublicKey {
        iv: vec![FieldElement::from_bytes(*inputs.bind.fs_epoch_commit)],
        y: FieldElement::from_bytes(*inputs.hp_commit),
    };

    let message = build_public_tuple(inputs)?;
    let statement = CapssStatement {
        public_key: public_key.clone(),
        message,
    };

    let context = CapssContext::new(config, public_key);
    Ok((context, statement))
}

fn signature_from_bytes(bytes: &[u8]) -> CapssSignature {
    CapssSignature {
        proof: CapssProof {
            bytes: bytes.to_vec(),
        },
    }
}

fn build_public_tuple(inputs: &Inputs<'_>) -> Result<Vec<u8>, MsphfError> {
    encode_public_tuple(
        inputs.bind.xk_hash,
        inputs.rho_commit,
        inputs.seed_bundle_commit,
        inputs.bind.crs_id,
        inputs.hp_commit,
        inputs.bind.params_id,
        inputs.bind.parent_root,
        inputs.bind.join_delta_root,
        inputs.bind.revoked_since_prev_root,
        inputs.bind.revoked_root,
        inputs.bind.proof_mode,
        inputs.bind.policy_version,
        inputs.bind.vrf_id,
        inputs.bind.fs_epoch_commit,
        inputs.bind.fs_ec,
        inputs.bind.fs_dev_prev_commit,
        inputs.bind.fs_dev_commit,
    )
}

#[derive(Serialize)]
struct PublicTupleCbor<'a>(
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
    &'a str,
    #[serde(with = "serde_bytes")] &'a [u8],
    &'a str,
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
    &'a str,
    &'a str,
    &'a str,
    #[serde(with = "serde_bytes")] &'a [u8],
    u64,
    #[serde(with = "serde_bytes")] &'a [u8],
    #[serde(with = "serde_bytes")] &'a [u8],
);

#[allow(clippy::too_many_arguments)]
fn encode_public_tuple(
    xk_hash: &[u8],
    rho_commit: &[u8],
    seed_bundle_commit: &[u8],
    crs_id: &str,
    hp_commit: &[u8],
    params_id: &str,
    parent_root: &[u8],
    join_delta_root: &[u8],
    revoked_since_prev_root: &[u8],
    revoked_root: &[u8],
    proof_mode: &str,
    policy_version: &str,
    vrf_id: &str,
    fs_epoch_commit: &[u8],
    fs_ec: u64,
    fs_dev_prev_commit: &[u8],
    fs_dev_commit: &[u8],
) -> Result<Vec<u8>, MsphfError> {
    let tuple = PublicTupleCbor(
        xk_hash,
        rho_commit,
        seed_bundle_commit,
        crs_id,
        hp_commit,
        params_id,
        parent_root,
        join_delta_root,
        revoked_since_prev_root,
        revoked_root,
        proof_mode,
        policy_version,
        vrf_id,
        fs_epoch_commit,
        fs_ec,
        fs_dev_prev_commit,
        fs_dev_commit,
    );
    let mut buf = Vec::new();
    into_writer(&tuple, &mut buf).map_err(MsphfError::serialization)?;
    Ok(buf)
}

fn map_smallwood_decode_error(_: Error) -> AcceptanceError {
    AcceptanceError::Freeze(FREEZE_CAPSS_INVALID)
}

fn map_smallwood_prove_error(err: Error) -> MsphfError {
    MsphfError::invalid_input(format!("capss smallwood prove failed: {err}"))
}

fn map_smallwood_verify_error(_: Error) -> AcceptanceError {
    AcceptanceError::Freeze(FREEZE_CAPSS_INVALID)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Result, anyhow, bail};
    use rand_chacha::ChaCha20Rng;
    use rand_core::{OsRng, SeedableRng};

    const CRS_ID: &str = "crs/test";
    const PARAMS_ID: &str = "params/test";
    const PROOF_MODE: &str = "smallwood/v1";
    const POLICY_VERSION: &str = "v7";
    const VRF_ID: &str = "vrf/test";

    #[allow(clippy::too_many_arguments)]
    fn make_inputs<'a>(
        seed_commit: &'a [u8; 32],
        seed_bundle_commit: &'a [u8; 32],
        rho_commit: &'a [u8; 32],
        hp_commit: &'a [u8; 32],
        parent_root: &'a [u8; 32],
        join_delta_root: &'a [u8; 32],
        revoked_since_prev_root: &'a [u8; 32],
        revoked_root: &'a [u8; 32],
        fs_epoch_commit: &'a [u8; 32],
        fs_dev_prev_commit: &'a [u8; 32],
        fs_dev_commit: &'a [u8; 32],
    ) -> Inputs<'a> {
        Inputs {
            seed_commit,
            seed_bundle_commit,
            rho_commit,
            hp_commit,
            bind: BindingInputs {
                xk_hash: seed_commit,
                crs_id: CRS_ID,
                params_id: PARAMS_ID,
                proof_mode: PROOF_MODE,
                policy_version: POLICY_VERSION,
                vrf_id: VRF_ID,
                parent_root,
                join_delta_root,
                revoked_since_prev_root,
                revoked_root,
                fs_epoch_commit,
                fs_ec: 7,
                fs_dev_prev_commit,
                fs_dev_commit,
            },
        }
    }

    fn filled(bytes: u8) -> [u8; 32] {
        [bytes; 32]
    }

    #[test]
    fn proof_from_bytes_rejects_garbage() -> Result<()> {
        let err = match Proof::from_bytes(vec![0xAA, 0xBB]) {
            Ok(_) => bail!("should reject invalid capss proof"),
            Err(e) => e,
        };
        assert!(matches!(
            err,
            AcceptanceError::Freeze(code) if code == FREEZE_CAPSS_INVALID
        ));
        Ok(())
    }

    #[test]
    fn verify_rejects_modified_statement() -> Result<()> {
        let seed_commit = filled(0x11);
        let seed_bundle_commit = filled(0x22);
        let rho_commit = filled(0x33);
        let hp_commit = filled(0x44);
        let parent_root = filled(0x55);
        let join_delta_root = filled(0x66);
        let revoked_since_prev_root = filled(0x77);
        let revoked_root = filled(0x88);
        let fs_epoch_commit = filled(0x99);
        let fs_dev_prev_commit = filled(0xAA);
        let fs_dev_commit = filled(0xBB);

        let inputs = make_inputs(
            &seed_commit,
            &seed_bundle_commit,
            &rho_commit,
            &hp_commit,
            &parent_root,
            &join_delta_root,
            &revoked_since_prev_root,
            &revoked_root,
            &fs_epoch_commit,
            &fs_dev_prev_commit,
            &fs_dev_commit,
        );

        // Generate a valid proof.
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let proof = prove(&mut rng, &inputs)?;
        verify(&inputs, &proof)?;

        // Mutate the statement while keeping the proof fixed – verification must fail.
        let mut tampered_dev_commit = fs_dev_commit;
        tampered_dev_commit[0] ^= 0xFF;
        let bad_inputs = make_inputs(
            &seed_commit,
            &seed_bundle_commit,
            &rho_commit,
            &hp_commit,
            &parent_root,
            &join_delta_root,
            &revoked_since_prev_root,
            &revoked_root,
            &fs_epoch_commit,
            &fs_dev_prev_commit,
            &tampered_dev_commit,
        );

        let err = match verify(&bad_inputs, &proof) {
            Ok(_) => bail!("verify should fail when statement changes"),
            Err(e) => e,
        };
        assert!(matches!(
            err,
            AcceptanceError::Freeze(code) if code == FREEZE_CAPSS_INVALID
        ));
        Ok(())
    }

    #[test]
    fn proof_rehydrates_after_roundtrip() -> Result<()> {
        let seed_commit = filled(0x01);
        let seed_bundle_commit = filled(0x02);
        let rho_commit = filled(0x03);
        let hp_commit = filled(0x04);
        let parent_root = filled(0x05);
        let join_delta_root = filled(0x06);
        let revoked_since_prev_root = filled(0x07);
        let revoked_root = filled(0x08);
        let fs_epoch_commit = filled(0x09);
        let fs_dev_prev_commit = filled(0x0A);
        let fs_dev_commit = filled(0x0B);

        let inputs = make_inputs(
            &seed_commit,
            &seed_bundle_commit,
            &rho_commit,
            &hp_commit,
            &parent_root,
            &join_delta_root,
            &revoked_since_prev_root,
            &revoked_root,
            &fs_epoch_commit,
            &fs_dev_prev_commit,
            &fs_dev_commit,
        );

        let mut rng = OsRng;
        let proof = prove(&mut rng, &inputs)?;
        let bytes = proof.as_bytes().to_vec();
        let decoded = Proof::from_bytes(bytes.clone())?;
        assert_eq!(decoded.as_bytes(), bytes.as_slice());
        verify(&inputs, &decoded)?;
        Ok(())
    }

    #[test]
    fn helper_mappers_preserve_error_kinds() {
        let prove_err = map_smallwood_prove_error(anyhow!("boom"));
        assert!(matches!(prove_err, MsphfError::InvalidInput(_)));

        let decode_err = map_smallwood_decode_error(anyhow!("decode"));
        assert!(matches!(
            decode_err,
            AcceptanceError::Freeze(code) if code == FREEZE_CAPSS_INVALID
        ));

        let verify_err = map_smallwood_verify_error(anyhow!("verify"));
        assert!(matches!(
            verify_err,
            AcceptanceError::Freeze(code) if code == FREEZE_CAPSS_INVALID
        ));
    }
}
