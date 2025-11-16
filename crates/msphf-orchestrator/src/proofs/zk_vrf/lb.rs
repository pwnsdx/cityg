use super::{MaskDigest, VrfCtx, VrfProof};
use ciborium::{
    ser::into_writer,
    value::{Integer, Value},
};
use msphf_lb_vrf::VRF;
use msphf_lb_vrf::{
    keypair::{MasterSecretKey as LbMasterSecretKey, PublicKey as LbPublicKey},
    lbvrf::{LBVRF, Proof as LbProof},
    param::Param as LbParam,
    serde::Serdes,
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use std::io::Cursor;
use std::sync::OnceLock;
use thiserror::Error;

const MESSAGE_DOMAIN: &[u8] = b"msphf/zk-vrf/lb/v1";

/// Maximum allowed VRF proof size in bytes.
/// Per Section 12 of the unified specification (docs/specs-unified-fs.md:222),
/// field #95 (vrf_proof) is capped at 8,192 bytes.
const MAX_VRF_PROOF_SIZE: usize = 8_192;

#[derive(Debug, Error)]
pub enum Error {
    #[error("serialization error: {0}")]
    Io(#[from] std::io::Error),
    #[error("lb-vrf error: {0}")]
    Lb(#[from] msphf_lb_vrf::error::Error),
    #[error("invalid key payload: {0}")]
    InvalidKey(&'static str),
    #[error("malformed proof: {0}")]
    MalformedProof(std::io::Error),
    #[error("proof size {0} exceeds maximum of {1} bytes")]
    ProofSizeExceeded(usize, usize),
}

type Result<T> = std::result::Result<T, Error>;

pub fn generate_parameters(seed: [u8; 32]) -> Result<Vec<u8>> {
    let params = LBVRF::paramgen(seed)?;
    serialize_param(&params)
}

pub fn generate_keypair(param_bytes: &[u8], seed: [u8; 32]) -> Result<(Vec<u8>, Vec<u8>)> {
    let params = deserialize_param(param_bytes)?;
    let mut rng = ChaCha20Rng::from_seed(seed);
    let master = LBVRF::master_keygen_with_rng(&mut rng);
    let (pk, _) = master.derive_epoch_keypair(&params, &[0u8; 32]);
    let secret = encode_secret_key(&params, &master)?;
    let public = encode_public_key(&params, &pk)?;
    Ok((secret, public))
}

#[allow(dead_code)]
pub fn public_for_epoch(secret_payload: &[u8], epoch_id: &[u8; 32]) -> Result<Vec<u8>> {
    let (params, master) = decode_secret_key(secret_payload)?;
    let (pk, _) = master.derive_epoch_keypair(&params, epoch_id);
    encode_public_key(&params, &pk)
}

pub fn prove(
    sk_payload: &[u8],
    ctx: &VrfCtx,
    masks: (&MaskDigest, &MaskDigest),
) -> Result<VrfProof> {
    prove_result(sk_payload, ctx, masks)
}

pub fn prove_result(
    sk_payload: &[u8],
    ctx: &VrfCtx,
    masks: (&MaskDigest, &MaskDigest),
) -> Result<VrfProof> {
    if sk_payload.is_empty() {
        return Err(Error::InvalidKey("empty secret key payload"));
    }
    let (params, master) = decode_secret_key(sk_payload)?;
    let (pk, sk) = master.derive_epoch_keypair(&params, ctx.we_epoch_id);
    let message = encode_message(ctx, masks)?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(blake3::hash(&message).as_bytes());
    let lb_proof = LBVRF::prove(message, params, pk, sk, seed)?;
    let proof_bytes = serialize_proof(&lb_proof)?;
    Ok(VrfProof { bytes: proof_bytes })
}

pub fn verify(
    pk_payload: &[u8],
    ctx: &VrfCtx,
    masks: (&MaskDigest, &MaskDigest),
    proof: &VrfProof,
) -> bool {
    verify_result(pk_payload, ctx, masks, proof).unwrap_or_default()
}

pub fn verify_result(
    pk_payload: &[u8],
    ctx: &VrfCtx,
    masks: (&MaskDigest, &MaskDigest),
    proof: &VrfProof,
) -> Result<bool> {
    if pk_payload.is_empty() {
        return Err(Error::InvalidKey("empty public key payload"));
    }
    // Enforce proof size limit to prevent DoS via oversized proofs
    if proof.bytes.len() > MAX_VRF_PROOF_SIZE {
        return Err(Error::ProofSizeExceeded(
            proof.bytes.len(),
            MAX_VRF_PROOF_SIZE,
        ));
    }
    let (params, pk) = decode_public_key(pk_payload)?;
    let lb_proof = deserialize_proof(&proof.bytes).map_err(Error::MalformedProof)?;
    let message = encode_message(ctx, masks)?;
    match LBVRF::verify(message, params, pk, lb_proof)? {
        Some(_) => Ok(true),
        None => Ok(false),
    }
}

fn encode_message(ctx: &VrfCtx<'_>, masks: (&MaskDigest, &MaskDigest)) -> Result<Vec<u8>> {
    // Encode the complete bind_fs context as specified in Section 11
    // bind_fs := CBOR_det([xk_hash, 93, 94, 98, 99, 106, 110, 111, 112, 113,
    //                      proof_mode, policy_version, meor_vrf_id,
    //                      fs_epoch_commit, fs_ec, fs_dev_prev_commit, fs_dev_commit,
    //                      (srx_root_sw when SRX applies)])

    let bind_fs_cbor = encode_bind_fs(ctx)?;

    let mut out = Vec::with_capacity(
        MESSAGE_DOMAIN.len() + bind_fs_cbor.len() + 2 * (4 + MaskDigest::default().len()),
    );
    out.extend_from_slice(MESSAGE_DOMAIN);
    out.extend_from_slice(&bind_fs_cbor);
    absorb_bytes(&mut out, masks.0);
    absorb_bytes(&mut out, masks.1);
    Ok(out)
}

fn encode_bind_fs(ctx: &VrfCtx<'_>) -> Result<Vec<u8>> {
    let mut fields = Vec::with_capacity(17 + usize::from(ctx.srx_root_sw.is_some()));

    fields.push(Value::Bytes(ctx.xk_hash.to_vec()));
    fields.push(Value::Bytes(ctx.rho_commit.to_vec()));
    fields.push(Value::Bytes(ctx.seed_bundle_commit.to_vec()));
    fields.push(Value::Text(ctx.crs_id.to_string()));
    fields.push(Value::Bytes(ctx.hp_commit.to_vec()));
    fields.push(Value::Text(ctx.params_id.to_string()));
    fields.push(Value::Bytes(ctx.parent_root.to_vec()));
    fields.push(Value::Bytes(ctx.join_delta_root.to_vec()));
    fields.push(Value::Bytes(ctx.revoked_since_prev_root.to_vec()));
    fields.push(Value::Bytes(ctx.revoked_root.to_vec()));
    fields.push(Value::Text(ctx.proof_mode.to_string()));
    fields.push(Value::Text(ctx.policy_version.to_string()));
    fields.push(Value::Text(ctx.meor_vrf_id.to_string()));
    fields.push(Value::Bytes(ctx.fs_epoch_commit.to_vec()));
    fields.push(Value::Integer(Integer::from(ctx.fs_ec)));
    fields.push(Value::Bytes(ctx.fs_dev_prev_commit.to_vec()));
    fields.push(Value::Bytes(ctx.fs_dev_commit.to_vec()));
    if let Some(root) = ctx.srx_root_sw {
        fields.push(Value::Bytes(root.to_vec()));
    }

    let mut buf = Vec::new();
    into_writer(&Value::Array(fields), &mut buf)
        .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
    Ok(buf)
}

fn absorb_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
}

fn serialize_param(param: &LbParam) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    param.serialize(&mut buf)?;
    Ok(buf)
}

fn deserialize_param(bytes: &[u8]) -> Result<LbParam> {
    let mut cursor = Cursor::new(bytes);
    LbParam::deserialize(&mut cursor).map_err(Error::Io)
}

fn serialize_public_key(pk: &LbPublicKey) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    pk.serialize(&mut buf)?;
    Ok(buf)
}

fn deserialize_public_key_bytes(bytes: &[u8]) -> Result<LbPublicKey> {
    let mut cursor = Cursor::new(bytes);
    LbPublicKey::deserialize(&mut cursor).map_err(Error::Io)
}

fn serialize_proof(proof: &LbProof) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    proof.serialize(&mut buf)?;
    Ok(buf)
}

fn deserialize_proof(bytes: &[u8]) -> std::result::Result<LbProof, std::io::Error> {
    let mut cursor = Cursor::new(bytes);
    LbProof::deserialize(&mut cursor)
}

fn encode_public_key(params: &LbParam, pk: &LbPublicKey) -> Result<Vec<u8>> {
    let param_bytes = serialize_param(params)?;
    let pk_bytes = serialize_public_key(pk)?;
    let mut out = Vec::with_capacity(param_bytes.len() + pk_bytes.len() + 8);
    push_length_prefixed(&mut out, &param_bytes);
    push_length_prefixed(&mut out, &pk_bytes);
    Ok(out)
}

fn encode_secret_key(params: &LbParam, master: &LbMasterSecretKey) -> Result<Vec<u8>> {
    let param_bytes = serialize_param(params)?;
    let mut out = Vec::with_capacity(param_bytes.len() + 8 + master.as_bytes().len());
    push_length_prefixed(&mut out, &param_bytes);
    push_length_prefixed(&mut out, master.as_bytes());
    Ok(out)
}

fn decode_public_key(payload: &[u8]) -> Result<(LbParam, LbPublicKey)> {
    let mut cursor = 0usize;
    let param_bytes = take_length_prefixed(payload, &mut cursor)?;
    let pk_bytes = take_length_prefixed(payload, &mut cursor)?;
    if cursor != payload.len() {
        return Err(Error::InvalidKey("unexpected trailing bytes in public key"));
    }
    let params = deserialize_param(param_bytes)?;
    let pk = deserialize_public_key_bytes(pk_bytes)?;
    Ok((params, pk))
}

fn decode_secret_key(payload: &[u8]) -> Result<(LbParam, LbMasterSecretKey)> {
    let mut cursor = 0usize;
    let param_bytes = take_length_prefixed(payload, &mut cursor)?;
    let master_bytes = take_length_prefixed(payload, &mut cursor)?;
    if cursor != payload.len() {
        return Err(Error::InvalidKey("unexpected trailing bytes in secret key"));
    }
    if master_bytes.len() != 32 {
        return Err(Error::InvalidKey("invalid master seed length"));
    }
    let params = deserialize_param(param_bytes)?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(master_bytes);
    Ok((params, LbMasterSecretKey::from_bytes(seed)))
}

fn push_length_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
}

fn take_length_prefixed<'a>(bytes: &'a [u8], cursor: &mut usize) -> Result<&'a [u8]> {
    if *cursor + 4 > bytes.len() {
        return Err(Error::InvalidKey("truncated length prefix"));
    }
    let len_bytes: [u8; 4] = match bytes[*cursor..*cursor + 4].try_into() {
        Ok(arr) => arr,
        Err(_) => unreachable!("slice length already validated to be exactly 4 bytes"),
    };
    let len = u32::from_le_bytes(len_bytes) as usize;
    *cursor += 4;
    if *cursor + len > bytes.len() {
        return Err(Error::InvalidKey("truncated key component"));
    }
    let chunk = &bytes[*cursor..*cursor + len];
    *cursor += len;
    Ok(chunk)
}

/// Deterministic key material (for tests and fixtures).
pub fn deterministic_key_material() -> (&'static [u8], &'static [u8]) {
    static MATERIAL: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    MATERIAL.get_or_init(|| {
        let params = match generate_parameters([0u8; 32]) {
            Ok(p) => p,
            Err(_) => {
                unreachable!("deterministic parameter generation with fixed seed cannot fail")
            }
        };
        match generate_keypair(&params, [1u8; 32]) {
            Ok(pair) => pair,
            Err(_) => unreachable!(
                "deterministic keypair generation with valid params and fixed seed cannot fail"
            ),
        }
    });
    let pair = match MATERIAL.get() {
        Some(p) => p,
        None => unreachable!("OnceLock was just initialized above"),
    };
    (&pair.0, &pair.1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Result, bail, ensure};

    fn demo_ctx() -> VrfCtx<'static> {
        VrfCtx {
            xk_hash: &[0u8; 32],
            rho_commit: &[1u8; 32],
            seed_bundle_commit: &[2u8; 32],
            crs_id: "test-crs",
            hp_commit: &[3u8; 32],
            params_id: "test-params",
            parent_root: &[4u8; 32],
            join_delta_root: &[5u8; 32],
            revoked_since_prev_root: &[6u8; 32],
            revoked_root: &[7u8; 32],
            proof_mode: "test-mode",
            policy_version: "v1",
            meor_vrf_id: "lb-vrf/v1",
            fs_epoch_commit: &[8u8; 32],
            fs_ec: 100,
            fs_dev_prev_commit: &[9u8; 32],
            fs_dev_commit: &[10u8; 32],
            srx_root_sw: None,
            we_epoch_id: &[11u8; 32],
        }
    }

    fn mask_pair() -> (MaskDigest, MaskDigest) {
        ([6u8; 32], [7u8; 32])
    }

    #[test]
    fn roundtrip_prove_verify() -> Result<()> {
        let params = generate_parameters([9u8; 32])?;
        let (secret, _public) = generate_keypair(&params, [10u8; 32])?;
        let ctx = demo_ctx();
        let derived_public = public_for_epoch(&secret, ctx.we_epoch_id)?;
        let masks = mask_pair();
        let proof = prove_result(&secret, &ctx, (&masks.0, &masks.1))?;
        ensure!(
            verify_result(&derived_public, &ctx, (&masks.0, &masks.1), &proof)?,
            "proof should verify"
        );
        Ok(())
    }

    #[test]
    fn empty_payload_rejected() {
        assert!(prove_result(&[], &demo_ctx(), (&mask_pair().0, &mask_pair().1)).is_err());
        assert!(
            verify_result(
                &[],
                &demo_ctx(),
                (&mask_pair().0, &mask_pair().1),
                &VrfProof { bytes: vec![] }
            )
            .is_err()
        );
    }

    #[test]
    fn reject_proof_with_mutated_bytes() -> Result<()> {
        let params = generate_parameters([11u8; 32])?;
        let (secret, _public) = generate_keypair(&params, [12u8; 32])?;
        let ctx = demo_ctx();
        let derived_public = public_for_epoch(&secret, ctx.we_epoch_id)?;
        let masks = mask_pair();
        let mut proof = prove_result(&secret, &ctx, (&masks.0, &masks.1))?;

        // Mutate a byte in the proof
        if !proof.bytes.is_empty() {
            let mid = proof.bytes.len() / 2;
            proof.bytes[mid] ^= 0x01;
        }

        // Verification should fail
        match verify_result(&derived_public, &ctx, (&masks.0, &masks.1), &proof) {
            Ok(false) | Err(_) => Ok(()),
            Ok(true) => bail!("mutated proof should be rejected"),
        }
    }

    #[test]
    fn reject_proof_with_wrong_epoch() -> Result<()> {
        let params = generate_parameters([13u8; 32])?;
        let (secret, _public) = generate_keypair(&params, [14u8; 32])?;
        let ctx1 = demo_ctx();
        let masks = mask_pair();
        let proof = prove_result(&secret, &ctx1, (&masks.0, &masks.1))?;

        // Create different epoch context
        let ctx2 = VrfCtx {
            we_epoch_id: &[99u8; 32], // Different epoch!
            ..ctx1
        };
        let public_for_wrong_epoch = public_for_epoch(&secret, ctx2.we_epoch_id)?;

        // Proof for ctx1 should not verify with ctx2
        match verify_result(&public_for_wrong_epoch, &ctx2, (&masks.0, &masks.1), &proof) {
            Ok(false) | Err(_) => Ok(()),
            Ok(true) => bail!("proof from different epoch should be rejected"),
        }
    }

    #[test]
    fn reject_proof_with_swapped_masks() -> Result<()> {
        let params = generate_parameters([15u8; 32])?;
        let (secret, _public) = generate_keypair(&params, [16u8; 32])?;
        let ctx = demo_ctx();
        let derived_public = public_for_epoch(&secret, ctx.we_epoch_id)?;
        let masks = mask_pair();
        let proof = prove_result(&secret, &ctx, (&masks.0, &masks.1))?;

        // Verify with swapped masks should fail
        match verify_result(&derived_public, &ctx, (&masks.1, &masks.0), &proof) {
            Ok(false) | Err(_) => Ok(()),
            Ok(true) => bail!("proof with swapped masks should be rejected"),
        }
    }

    #[test]
    fn reject_proof_with_wrong_context() -> Result<()> {
        let params = generate_parameters([17u8; 32])?;
        let (secret, _public) = generate_keypair(&params, [18u8; 32])?;
        let ctx1 = demo_ctx();
        let derived_public = public_for_epoch(&secret, ctx1.we_epoch_id)?;
        let masks = mask_pair();
        let proof = prove_result(&secret, &ctx1, (&masks.0, &masks.1))?;

        // Create context with different xk_hash
        let different_xk = [0xFFu8; 32];
        let ctx2 = VrfCtx {
            xk_hash: &different_xk,
            ..ctx1
        };

        // Proof should fail with different context
        match verify_result(&derived_public, &ctx2, (&masks.0, &masks.1), &proof) {
            Ok(false) | Err(_) => Ok(()),
            Ok(true) => bail!("proof with different xk_hash should be rejected"),
        }
    }

    #[test]
    fn reject_truncated_proof() -> Result<()> {
        let params = generate_parameters([19u8; 32])?;
        let (secret, _public) = generate_keypair(&params, [20u8; 32])?;
        let ctx = demo_ctx();
        let derived_public = public_for_epoch(&secret, ctx.we_epoch_id)?;
        let masks = mask_pair();
        let mut proof = prove_result(&secret, &ctx, (&masks.0, &masks.1))?;

        // Truncate the proof
        if proof.bytes.len() > 10 {
            proof.bytes.truncate(proof.bytes.len() - 10);
        }

        // Verification should fail (either error or false)
        let result = verify_result(&derived_public, &ctx, (&masks.0, &masks.1), &proof);
        match result {
            Ok(false) | Err(_) => Ok(()),
            Ok(true) => bail!("truncated proof should be rejected"),
        }
    }

    #[test]
    fn deterministic_proof_generation() -> Result<()> {
        let params = generate_parameters([21u8; 32])?;
        let (secret, _public) = generate_keypair(&params, [22u8; 32])?;
        let ctx = demo_ctx();
        let masks = mask_pair();

        // Generate proof twice with same inputs
        let proof1 = prove_result(&secret, &ctx, (&masks.0, &masks.1))?;
        let proof2 = prove_result(&secret, &ctx, (&masks.0, &masks.1))?;

        // Proofs should be identical (deterministic seeding)
        ensure!(
            proof1.bytes == proof2.bytes,
            "Proofs should be deterministic"
        );
        Ok(())
    }

    #[test]
    fn reject_proof_with_different_srx_root() -> Result<()> {
        let params = generate_parameters([25u8; 32])?;
        let (secret, _public) = generate_keypair(&params, [26u8; 32])?;
        let mut ctx1 = demo_ctx();
        let srx_root1 = [0xAAu8; 32];
        ctx1.srx_root_sw = Some(&srx_root1);
        let derived_public = public_for_epoch(&secret, ctx1.we_epoch_id)?;
        let masks = mask_pair();
        let proof = prove_result(&secret, &ctx1, (&masks.0, &masks.1))?;

        // Create context with different SRX root
        let srx_root2 = [0xBBu8; 32];
        let mut ctx2 = ctx1;
        ctx2.srx_root_sw = Some(&srx_root2);

        // Proof should fail with different SRX root
        match verify_result(&derived_public, &ctx2, (&masks.0, &masks.1), &proof) {
            Ok(false) | Err(_) => Ok(()),
            Ok(true) => bail!("proof with different srx_root should be rejected"),
        }
    }

    #[test]
    fn reject_proof_with_different_fs_epoch_commit() -> Result<()> {
        let params = generate_parameters([27u8; 32])?;
        let (secret, _public) = generate_keypair(&params, [28u8; 32])?;
        let ctx1 = demo_ctx();
        let derived_public = public_for_epoch(&secret, ctx1.we_epoch_id)?;
        let masks = mask_pair();
        let proof = prove_result(&secret, &ctx1, (&masks.0, &masks.1))?;

        // Create context with different fs_epoch_commit
        let different_fs_epoch_commit = [0xFFu8; 32];
        let mut ctx2 = ctx1;
        ctx2.fs_epoch_commit = &different_fs_epoch_commit;

        // Proof should fail with different fs_epoch_commit
        match verify_result(&derived_public, &ctx2, (&masks.0, &masks.1), &proof) {
            Ok(false) | Err(_) => Ok(()),
            Ok(true) => bail!("proof with different fs_epoch_commit should be rejected"),
        }
    }

    #[test]
    fn reject_proof_with_different_fs_ec() -> Result<()> {
        let params = generate_parameters([29u8; 32])?;
        let (secret, _public) = generate_keypair(&params, [30u8; 32])?;
        let ctx1 = demo_ctx();
        let derived_public = public_for_epoch(&secret, ctx1.we_epoch_id)?;
        let masks = mask_pair();
        let proof = prove_result(&secret, &ctx1, (&masks.0, &masks.1))?;

        // Create context with different fs_ec
        let mut ctx2 = ctx1;
        ctx2.fs_ec = 999; // Different from 100 in demo_ctx

        // Proof should fail with different fs_ec
        match verify_result(&derived_public, &ctx2, (&masks.0, &masks.1), &proof) {
            Ok(false) | Err(_) => Ok(()),
            Ok(true) => bail!("proof with different fs_ec should be rejected"),
        }
    }

    #[test]
    fn reject_proof_with_different_revocation_roots() -> Result<()> {
        let params = generate_parameters([31u8; 32])?;
        let (secret, _public) = generate_keypair(&params, [32u8; 32])?;
        let ctx1 = demo_ctx();
        let derived_public = public_for_epoch(&secret, ctx1.we_epoch_id)?;
        let masks = mask_pair();
        let proof = prove_result(&secret, &ctx1, (&masks.0, &masks.1))?;

        // Create context with different revoked_root
        let different_revoked_root = [0xEEu8; 32];
        let mut ctx2 = ctx1;
        ctx2.revoked_root = &different_revoked_root;

        // Proof should fail with different revoked_root
        match verify_result(&derived_public, &ctx2, (&masks.0, &masks.1), &proof) {
            Ok(false) | Err(_) => Ok(()),
            Ok(true) => bail!("proof with different revoked_root should be rejected"),
        }
    }

    #[test]
    fn accept_proof_without_srx_root() -> Result<()> {
        let params = generate_parameters([33u8; 32])?;
        let (secret, _public) = generate_keypair(&params, [34u8; 32])?;
        let mut ctx = demo_ctx();
        ctx.srx_root_sw = None;
        let derived_public = public_for_epoch(&secret, ctx.we_epoch_id)?;
        let masks = mask_pair();
        let proof = prove_result(&secret, &ctx, (&masks.0, &masks.1))?;

        // Proof should verify when SRX root is consistently absent
        ensure!(
            verify_result(&derived_public, &ctx, (&masks.0, &masks.1), &proof)?,
            "proof without srx_root should verify"
        );
        Ok(())
    }

    #[test]
    fn reject_proof_when_srx_root_added() -> Result<()> {
        let params = generate_parameters([35u8; 32])?;
        let (secret, _public) = generate_keypair(&params, [36u8; 32])?;
        let mut ctx1 = demo_ctx();
        ctx1.srx_root_sw = None; // Generate proof without SRX root
        let derived_public = public_for_epoch(&secret, ctx1.we_epoch_id)?;
        let masks = mask_pair();
        let proof = prove_result(&secret, &ctx1, (&masks.0, &masks.1))?;

        // Try to verify with SRX root present
        let srx_root = [0xCCu8; 32];
        let mut ctx2 = ctx1;
        ctx2.srx_root_sw = Some(&srx_root);

        // Proof should fail when SRX root is added
        match verify_result(&derived_public, &ctx2, (&masks.0, &masks.1), &proof) {
            Ok(false) | Err(_) => Ok(()),
            Ok(true) => bail!("proof should be rejected when srx_root is added"),
        }
    }

    #[test]
    fn reject_oversized_proof() -> Result<()> {
        let params = generate_parameters([23u8; 32])?;
        let (_secret, _public) = generate_keypair(&params, [24u8; 32])?;
        let ctx = demo_ctx();
        let derived_public = public_for_epoch(&_secret, ctx.we_epoch_id)?;

        // Create a proof with size exceeding MAX_VRF_PROOF_SIZE
        let oversized_proof = VrfProof {
            bytes: vec![0u8; super::MAX_VRF_PROOF_SIZE + 1],
        };

        // Verification should fail with ProofSizeExceeded error
        let result = verify_result(
            &derived_public,
            &ctx,
            (&mask_pair().0, &mask_pair().1),
            &oversized_proof,
        );
        let Err(err) = result else {
            bail!("oversized proof should be rejected");
        };
        match err {
            Error::ProofSizeExceeded(size, limit) => {
                ensure!(
                    size == super::MAX_VRF_PROOF_SIZE + 1,
                    "unexpected reported size"
                );
                ensure!(limit == super::MAX_VRF_PROOF_SIZE, "unexpected size limit");
                Ok(())
            }
            _ => bail!("expected ProofSizeExceeded error"),
        }
    }
}
