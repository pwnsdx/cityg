use crate::{
    accept::{AcceptanceError, FREEZE_SRX_SMALLWOOD_INVALID},
    h_l,
};
use anyhow::Error;
use blake3::Hasher;
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

/// Maximum SRX Smallwood transcript size (16 KiB per spec).
pub const SRX_SMALLWOOD_MAX_BYTES: usize = 16_384;

#[derive(Clone)]
pub struct Inputs<'a> {
    pub shadow_root_before: &'a [u8; 32],
    pub shadow_root_after: &'a [u8; 32],
    pub parent_root: &'a [u8; 32],
    pub join_root: &'a [u8; 32],
    pub revoked_since_root: &'a [u8; 32],
    pub revoked_root: &'a [u8; 32],
    pub srx_commit: &'a [u8; 32],
    pub srx_payload_digest: &'a [u8; 32],
    pub srx_bridge_ctx: &'a [u8; 32],
    pub proof_mode: &'a str,
    pub fs_policy_version: u64,
    pub vrf_id: &'a str,
}

#[derive(Clone, Debug)]
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

    pub fn to_signature(&self) -> CapssSignature {
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
        label: "capss-srx-smallwood".to_string(),
        fs_domain: "msphf/srx_smallwood".to_string(),
        ..Default::default()
    };

    let public_key = CapssPublicKey {
        iv: vec![FieldElement::from_bytes(*inputs.shadow_root_before)],
        y: FieldElement::from_bytes(*inputs.shadow_root_after),
    };

    let message = encode_statement_payload(inputs)?;
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

fn encode_statement_payload(inputs: &Inputs<'_>) -> Result<Vec<u8>, MsphfError> {
    #[derive(Serialize)]
    struct StatementPayload<'a> {
        #[serde(with = "serde_bytes")]
        shadow_root_before: &'a [u8],
        #[serde(with = "serde_bytes")]
        shadow_root_after: &'a [u8],
        #[serde(with = "serde_bytes")]
        parent_root: &'a [u8],
        #[serde(with = "serde_bytes")]
        join_root: &'a [u8],
        #[serde(with = "serde_bytes")]
        revoked_since_root: &'a [u8],
        #[serde(with = "serde_bytes")]
        revoked_root: &'a [u8],
        #[serde(with = "serde_bytes")]
        srx_commit: &'a [u8],
        #[serde(with = "serde_bytes")]
        srx_payload_digest: &'a [u8],
        #[serde(with = "serde_bytes")]
        srx_bridge_ctx: &'a [u8],
        proof_mode: &'a str,
        fs_policy_version: u64,
        vrf_id: &'a str,
    }

    let payload = StatementPayload {
        shadow_root_before: &inputs.shadow_root_before[..],
        shadow_root_after: &inputs.shadow_root_after[..],
        parent_root: &inputs.parent_root[..],
        join_root: &inputs.join_root[..],
        revoked_since_root: &inputs.revoked_since_root[..],
        revoked_root: &inputs.revoked_root[..],
        srx_commit: &inputs.srx_commit[..],
        srx_payload_digest: &inputs.srx_payload_digest[..],
        srx_bridge_ctx: &inputs.srx_bridge_ctx[..],
        proof_mode: inputs.proof_mode,
        fs_policy_version: inputs.fs_policy_version,
        vrf_id: inputs.vrf_id,
    };

    let mut buf = Vec::new();
    into_writer(&payload, &mut buf).map_err(MsphfError::serialization)?;
    Ok(buf)
}

fn digest32(data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[derive(Serialize)]
struct SrxPayloadDigestInput<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

pub fn payload_digest(payload: &[u8]) -> Result<[u8; 32], MsphfError> {
    h_l("srx/payload/digest", &SrxPayloadDigestInput(payload))
}

#[derive(Serialize)]
struct SrxBridgeCtxInput<'a> {
    #[serde(with = "serde_bytes")]
    parent_root: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    join_root: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    revoked_since_root: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    revoked_root: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    srx_commit: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    srx_payload_digest: &'a [u8; 32],
    #[serde(with = "serde_bytes")]
    srx_root_sw: &'a [u8; 32],
}

#[allow(clippy::too_many_arguments)]
pub fn compute_bridge_ctx(
    parent_root: &[u8; 32],
    join_root: &[u8; 32],
    revoked_since_root: &[u8; 32],
    revoked_root: &[u8; 32],
    srx_commit: &[u8; 32],
    srx_payload_digest: &[u8; 32],
    srx_root_sw: &[u8; 32],
) -> Result<[u8; 32], MsphfError> {
    h_l(
        "srx/bridge/v1",
        &SrxBridgeCtxInput {
            parent_root,
            join_root,
            revoked_since_root,
            revoked_root,
            srx_commit,
            srx_payload_digest,
            srx_root_sw,
        },
    )
}

fn map_smallwood_decode_error(_: Error) -> AcceptanceError {
    AcceptanceError::Freeze(FREEZE_SRX_SMALLWOOD_INVALID)
}

fn map_smallwood_prove_error(err: Error) -> MsphfError {
    MsphfError::invalid_input(format!("srx smallwood prove failed: {err}"))
}

fn map_smallwood_verify_error(_: Error) -> AcceptanceError {
    AcceptanceError::Freeze(FREEZE_SRX_SMALLWOOD_INVALID)
}

/// Compute the field-friendly SRX shadow root used as the CAPSS public key component.
///
/// This hash binds the canonical rpo-256 roots alongside the SRX commitment and payload digest
/// into a single 32-byte value that can be interpreted in the CAPSS field.
pub fn compute_shadow_root(
    parent_root: &[u8; 32],
    join_root: &[u8; 32],
    revoked_since_root: &[u8; 32],
    revoked_root: &[u8; 32],
    srx_commit: Option<&[u8; 32]>,
    payload_digest: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"city-g|srx/shadow/v1|");
    hasher.update(parent_root);
    hasher.update(join_root);
    hasher.update(revoked_since_root);
    hasher.update(revoked_root);
    if let Some(commit) = srx_commit {
        hasher.update(commit);
    } else {
        hasher.update(&[0u8; 32]);
    }
    if let Some(digest) = payload_digest {
        hasher.update(digest);
    } else {
        hasher.update(&[0u8; 32]);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Result, bail};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    type SampledRoots = ([u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32]);

    fn sample_roots() -> SampledRoots {
        ([0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32], [0x55; 32])
    }

    #[test]
    fn compute_shadow_root_deterministic() {
        let (parent, join, revoked_since, revoked_root, commit) = sample_roots();
        let payload_digest = [0x66; 32];
        let first = compute_shadow_root(
            &parent,
            &join,
            &revoked_since,
            &revoked_root,
            Some(&commit),
            Some(&payload_digest),
        );
        let second = compute_shadow_root(
            &parent,
            &join,
            &revoked_since,
            &revoked_root,
            Some(&commit),
            Some(&payload_digest),
        );
        assert_eq!(first, second);
    }

    #[test]
    fn prove_verify_roundtrip() -> Result<()> {
        let (parent, join, revoked_since, revoked_root, commit) = sample_roots();
        let payload = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let payload_digest = payload_digest(&payload)?;

        let shadow_before =
            compute_shadow_root(&parent, &join, &revoked_since, &revoked_root, None, None);
        let shadow_after = compute_shadow_root(
            &parent,
            &join,
            &revoked_since,
            &revoked_root,
            Some(&commit),
            Some(&payload_digest),
        );
        let bridge_ctx = compute_bridge_ctx(
            &parent,
            &join,
            &revoked_since,
            &revoked_root,
            &commit,
            &payload_digest,
            &shadow_after,
        )?;

        let inputs = Inputs {
            shadow_root_before: &shadow_before,
            shadow_root_after: &shadow_after,
            parent_root: &parent,
            join_root: &join,
            revoked_since_root: &revoked_since,
            revoked_root: &revoked_root,
            srx_commit: &commit,
            srx_payload_digest: &payload_digest,
            srx_bridge_ctx: &bridge_ctx,
            proof_mode: "smallwood/v1",
            fs_policy_version: 1,
            vrf_id: "vrf/test",
        };

        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let proof = prove(&mut rng, &inputs)?;
        verify(&inputs, &proof)?;

        let parsed = Proof::from_bytes(proof.as_bytes().to_vec())?;
        assert_eq!(parsed.as_bytes(), proof.as_bytes());
        Ok(())
    }

    #[test]
    fn verify_rejects_tampered_bridge_context() -> Result<()> {
        let (parent, join, revoked_since, revoked_root, commit) = sample_roots();
        let payload = vec![0xAA, 0xBB, 0xCC];
        let payload_digest = payload_digest(&payload)?;

        let shadow_before =
            compute_shadow_root(&parent, &join, &revoked_since, &revoked_root, None, None);
        let shadow_after = compute_shadow_root(
            &parent,
            &join,
            &revoked_since,
            &revoked_root,
            Some(&commit),
            Some(&payload_digest),
        );
        let bridge_ctx = compute_bridge_ctx(
            &parent,
            &join,
            &revoked_since,
            &revoked_root,
            &commit,
            &payload_digest,
            &shadow_after,
        )?;

        let inputs = Inputs {
            shadow_root_before: &shadow_before,
            shadow_root_after: &shadow_after,
            parent_root: &parent,
            join_root: &join,
            revoked_since_root: &revoked_since,
            revoked_root: &revoked_root,
            srx_commit: &commit,
            srx_payload_digest: &payload_digest,
            srx_bridge_ctx: &bridge_ctx,
            proof_mode: "smallwood/v1",
            fs_policy_version: 1,
            vrf_id: "vrf/test",
        };

        let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
        let proof = prove(&mut rng, &inputs)?;

        let mut tampered_bridge = bridge_ctx;
        tampered_bridge[0] ^= 0xFF;
        let tampered_inputs = Inputs {
            shadow_root_before: &shadow_before,
            shadow_root_after: &shadow_after,
            parent_root: &parent,
            join_root: &join,
            revoked_since_root: &revoked_since,
            revoked_root: &revoked_root,
            srx_commit: &commit,
            srx_payload_digest: &payload_digest,
            srx_bridge_ctx: &tampered_bridge,
            proof_mode: "smallwood/v1",
            fs_policy_version: 1,
            vrf_id: "vrf/test",
        };

        let err = match verify(&tampered_inputs, &proof) {
            Ok(_) => bail!("verify should fail"),
            Err(e) => e,
        };
        match err {
            AcceptanceError::Freeze(code) => {
                assert_eq!(code, FREEZE_SRX_SMALLWOOD_INVALID);
                Ok(())
            }
            _ => bail!("unexpected verification error"),
        }
    }

    #[test]
    fn proof_from_bytes_rejects_garbage() -> Result<()> {
        let err = match Proof::from_bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]) {
            Ok(_) => bail!("should fail"),
            Err(e) => e,
        };
        match err {
            AcceptanceError::Freeze(code) => {
                assert_eq!(code, FREEZE_SRX_SMALLWOOD_INVALID);
                Ok(())
            }
            _ => bail!("unexpected proof parse error"),
        }
    }

    #[test]
    fn shadow_root_sample_vector() {
        let (parent, join, revoked_since, revoked_root, commit) = sample_roots();
        let payload_digest = [0x66; 32];
        let shadow_before =
            compute_shadow_root(&parent, &join, &revoked_since, &revoked_root, None, None);
        let shadow_after = compute_shadow_root(
            &parent,
            &join,
            &revoked_since,
            &revoked_root,
            Some(&commit),
            Some(&payload_digest),
        );
        assert_eq!(
            shadow_before,
            hex_literal::hex!("118855408a1269386421c00e9ed1ca7ff0580c92b6ee64daecce4ffe6a1f5814")
        );
        assert_eq!(
            shadow_after,
            hex_literal::hex!("42b3332a4002263ad346cbfceaf832dd44f4940537662808dcb1124e1e791a30")
        );
    }

    #[test]
    fn bridge_ctx_deterministic() -> Result<()> {
        let (parent, join, revoked_since, revoked_root, commit) = sample_roots();
        let payload_digest = payload_digest(b"payload")?;
        let shadow_root = [0x77; 32];
        let first = compute_bridge_ctx(
            &parent,
            &join,
            &revoked_since,
            &revoked_root,
            &commit,
            &payload_digest,
            &shadow_root,
        )?;
        let second = compute_bridge_ctx(
            &parent,
            &join,
            &revoked_since,
            &revoked_root,
            &commit,
            &payload_digest,
            &shadow_root,
        )?;
        assert_eq!(first, second);
        Ok(())
    }
}
