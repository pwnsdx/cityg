//! RLWE-based SPHF implementation for the `rlwe-merkle/v1` instantiation (profile A1).
//!
//! This module follows the Annex K RLWE profile from the unified City‑G specification. It derives all branch
//! artifacts deterministically from the branch sub-seed, encodes them via the
//! `HP_RLWE_A1_V1` tuple (CBOR), and produces the full/projective digests that
//! feed the ME-OR masking scheme.

use blake3::Hasher;
use ciborium::de::from_reader;
use msphf_core::{
    MsphfError, WitnessReplayField, ds,
    hash::{h_branch_bytes, h_l},
    instance::AnchorInstance,
    rlwe::{
        arithmetic::barrett_reduce,
        constants::{K, N, Q},
        matrix::{Matrix, expand_a},
        noise::cbd_eta2_poly,
        poly::Poly,
        polyvec::PolyVec,
    },
    serde_utils::to_cbor_vec,
    witness::{ValidatedWitness, WitnessMode},
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

const A_SEED_LABEL: &str = "hps/A-seed";
const SALT_LABEL: &str = "hps/salt";
const SEED_S_LABEL: &str = "hps/s";
const SEED_EB_LABEL: &str = "hps/eB";
const SEED_R_LABEL: &str = "hps/r";
const SEED_E1_LABEL: &str = "hps/e1";
const SEED_E2_LABEL: &str = "hps/e2";
const HPS_CTX_LABEL: &str = "hps/ctx";
const HPS_LINMASK_LABEL: &str = "hps/linmask";
const LIN_DESC_LABEL: &str = "root32-identity";

const POLY_LE_BYTES: usize = N * 2;
const POLYVEC_LE_BYTES: usize = K * POLY_LE_BYTES;

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct RlweSecretKey {
    seed: [u8; 32],
}

impl RlweSecretKey {
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }
}

#[derive(Debug, Clone)]
pub struct RlweProjectiveParams {
    hp_bytes: Vec<u8>,
}

impl RlweProjectiveParams {
    pub fn empty() -> Self {
        Self {
            hp_bytes: Vec::new(),
        }
    }

    pub fn new(bytes: Vec<u8>) -> Self {
        Self { hp_bytes: bytes }
    }

    pub fn hp_bytes(&self) -> &[u8] {
        &self.hp_bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.hp_bytes
    }

    fn decode(&self) -> Result<HpBranchOwned, MsphfError> {
        if self.hp_bytes.is_empty() {
            return Err(MsphfError::invalid_input("hp bytes not initialised"));
        }
        from_reader(self.hp_bytes.as_slice()).map_err(MsphfError::serialization)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CapssBranchWitness {
    pub branch_artifact: Vec<u8>,
    pub ctx_tag: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CapssWitnessBundle {
    pub branch_a: CapssBranchWitness,
    pub branch_b: CapssBranchWitness,
}

#[derive(Debug, Clone)]
pub struct FullHashResult {
    pub y_full: [u8; 32],
    pub projective: RlweProjectiveParams,
    pub capss_witness: CapssBranchWitness,
}

#[derive(Serialize)]
struct Drbg<'a> {
    #[serde(with = "serde_bytes")]
    seed_commit: &'a [u8],
    #[serde(with = "serde_bytes")]
    rho: &'a [u8],
    #[serde(with = "serde_bytes")]
    xk_hash: &'a [u8],
    #[serde(with = "serde_bytes")]
    seed_ctx_hash: &'a [u8],
}

pub fn derive_drbg_seed(
    seed_commit: &[u8; 32],
    rho_raw: &[u8; 32],
    xk_hash: &[u8; 32],
    seed_ctx_hash: &[u8; 32],
) -> Result<[u8; 32], MsphfError> {
    h_l(
        ds::MSPHF_DRBG,
        &Drbg {
            seed_commit: seed_commit.as_slice(),
            rho: rho_raw.as_slice(),
            xk_hash: xk_hash.as_slice(),
            seed_ctx_hash: seed_ctx_hash.as_slice(),
        },
    )
}

#[derive(Serialize)]
struct RhoSig<'a> {
    #[serde(with = "serde_bytes")]
    pop_sig: &'a [u8],
    #[serde(with = "serde_bytes")]
    xk_hash: &'a [u8; 32],
}

fn derive_rho_raw_from_pop(pop_sig: &[u8], xk_hash: &[u8; 32]) -> Result<[u8; 32], MsphfError> {
    h_l(ds::MSPHF_RHO_DER, &RhoSig { pop_sig, xk_hash })
}

#[derive(Clone)]
pub struct CapssStrictInputs<'a> {
    pub crs_id: &'a str,
    pub params_id: &'a str,
    pub seed_commit: &'a [u8; 32],
    pub seed_ctx_hash: &'a [u8; 32],
    pub xk_hash: &'a [u8; 32],
    pub rho_commit: &'a [u8; 32],
    pub pop_alg: &'a str,
    pub pop_pk: &'a [u8],
    pub anchor: &'a AnchorInstance<'a>,
    pub leaf_id: &'a [u8],
    pub pop_sig: Vec<u8>,
}

pub fn recompute_capss_witness(
    inputs: CapssStrictInputs<'_>,
) -> Result<CapssWitnessBundle, MsphfError> {
    #[derive(Serialize)]
    struct RhoCommit<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

    #[derive(Serialize)]
    struct SeedRef<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

    let _ = inputs.anchor.to_cbor_bytes()?;
    let anchor_xk_hash = inputs.anchor.xk_hash()?;
    if anchor_xk_hash != *inputs.xk_hash {
        return Err(MsphfError::WitnessReplayMismatch(
            WitnessReplayField::XkHash,
        ));
    }

    let rho_raw = derive_rho_raw_from_pop(&inputs.pop_sig, inputs.xk_hash)?;
    let rho_commit = h_l(ds::MSPHF_KGEN_RHO, &RhoCommit(rho_raw.as_slice()))?;

    if &rho_commit != inputs.rho_commit {
        return Err(MsphfError::WitnessReplayMismatch(
            WitnessReplayField::RhoCommit,
        ));
    }

    let seed_drbg = derive_drbg_seed(
        inputs.seed_commit,
        &rho_raw,
        inputs.xk_hash,
        inputs.seed_ctx_hash,
    )?;

    let seed_a = h_l(ds::MSPHF_KGEN_A, &SeedRef(seed_drbg.as_slice()))?;
    let seed_b = h_l(ds::MSPHF_KGEN_B, &SeedRef(seed_drbg.as_slice()))?;

    let (sk_a, _) = derive_branch_material(&seed_a, "branch-a")?;
    let (sk_b, _) = derive_branch_material(&seed_b, "branch-b")?;

    let full_a = hash_full(
        &sk_a,
        "A",
        inputs.crs_id,
        inputs.params_id,
        inputs.anchor,
        inputs.xk_hash,
    )?;
    let full_b = hash_full(
        &sk_b,
        "B",
        inputs.crs_id,
        inputs.params_id,
        inputs.anchor,
        inputs.xk_hash,
    )?;

    Ok(CapssWitnessBundle {
        branch_a: full_a.capss_witness,
        branch_b: full_b.capss_witness,
    })
}

pub fn derive_branch_material(
    seed_branch: &[u8; 32],
    _branch_label: &str,
) -> Result<(RlweSecretKey, RlweProjectiveParams), MsphfError> {
    Ok((
        RlweSecretKey::new(*seed_branch),
        RlweProjectiveParams::empty(),
    ))
}

pub fn hash_full(
    sk: &RlweSecretKey,
    branch: &str,
    crs_id: &str,
    params_id: &str,
    _instance: &AnchorInstance<'_>,
    xk_hash: &[u8; 32],
) -> Result<FullHashResult, MsphfError> {
    let artifacts = build_branch_artifact(sk.seed(), crs_id, params_id, xk_hash)?;
    let hp_bytes = to_cbor_vec(&artifacts)?;
    let witness_artifact = hp_bytes.clone();
    let digest = h_branch_bytes(
        ds::MSPHF_HASH,
        branch,
        crs_id,
        params_id,
        &[
            artifacts.ctx_tag.as_slice(),
            artifacts.u_vec.as_slice(),
            artifacts.v_vec.as_slice(),
        ],
    )?;
    let linmask_zero = linmask_zero()?;
    let y_full = xor_bytes(&digest, &linmask_zero);
    Ok(FullHashResult {
        y_full,
        projective: RlweProjectiveParams::new(hp_bytes),
        capss_witness: CapssBranchWitness {
            branch_artifact: witness_artifact,
            ctx_tag: artifacts.ctx_tag.clone(),
        },
    })
}

pub fn hash_proj(
    params: &RlweProjectiveParams,
    branch: &str,
    crs_id: &str,
    params_id: &str,
    instance: &AnchorInstance<'_>,
    witness: Option<&ValidatedWitness>,
) -> Result<[u8; 32], MsphfError> {
    let hp = params.decode()?;
    hp.validate()?;

    let base = h_branch_bytes(
        ds::MSPHF_HASH,
        branch,
        crs_id,
        params_id,
        &[
            hp.ctx_tag.as_slice(),
            hp.u_vec.as_slice(),
            hp.v_vec.as_slice(),
        ],
    )?;

    let delta = compute_delta(branch, instance, witness)?;
    let linmask = linmask_from_delta(&delta)?;
    Ok(xor_bytes(&base, &linmask))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HpBranchOwned {
    k: u8,
    n: u16,
    q: u16,
    #[serde(with = "serde_bytes")]
    a_seed: Vec<u8>,
    #[serde(with = "serde_bytes")]
    b_vec: Vec<u8>,
    #[serde(with = "serde_bytes")]
    u_vec: Vec<u8>,
    #[serde(with = "serde_bytes")]
    v_vec: Vec<u8>,
    #[serde(with = "serde_bytes")]
    salt_rlwe: Vec<u8>,
    lin_desc: LinDescOwned,
    #[serde(with = "serde_bytes")]
    ctx_tag: Vec<u8>,
    flags: HpFlagsOwned,
}

impl HpBranchOwned {
    fn validate(&self) -> Result<(), MsphfError> {
        if self.k as usize != K {
            return Err(MsphfError::invalid_input("hp_k mismatch"));
        }
        if self.n as usize != N {
            return Err(MsphfError::invalid_input("hp_n mismatch"));
        }
        if self.q as i16 != Q {
            return Err(MsphfError::invalid_input("hp_q mismatch"));
        }
        if self.a_seed.len() != 32 {
            return Err(MsphfError::invalid_input("A_seed length"));
        }
        if self.salt_rlwe.len() != 32 {
            return Err(MsphfError::invalid_input("salt length"));
        }
        if self.ctx_tag.len() != 32 {
            return Err(MsphfError::invalid_input("ctx_tag length"));
        }
        if self.b_vec.len() != POLYVEC_LE_BYTES
            || self.u_vec.len() != POLYVEC_LE_BYTES
            || self.v_vec.len() != POLYVEC_LE_BYTES
        {
            return Err(MsphfError::invalid_input("polyvec byte length"));
        }
        if self.lin_desc.0 != LIN_DESC_LABEL || self.lin_desc.1 != 32 || self.lin_desc.2 != 3329 {
            return Err(MsphfError::invalid_input("lin_desc mismatch"));
        }
        if self.flags.poly_encoding != "ntt-le16"
            || self.flags.coef_endian != "le16"
            || self.flags.ntt_order != "bitrev"
        {
            return Err(MsphfError::invalid_input("hp flags mismatch"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LinDescOwned(pub String, pub u32, pub u32);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HpFlagsOwned {
    poly_encoding: String,
    coef_endian: String,
    ntt_order: String,
}

struct ComputedBranch {
    a_seed: [u8; 32],
    salt: [u8; 32],
    ctx_tag: [u8; 32],
    b_ntt: PolyVec,
    u_ntt: PolyVec,
    v_ntt: PolyVec,
}

fn build_branch_artifact(
    seed: &[u8; 32],
    crs_id: &str,
    params_id: &str,
    xk_hash: &[u8; 32],
) -> Result<HpBranchOwned, MsphfError> {
    let computed = compute_rlwe_components(seed, crs_id, params_id, xk_hash)?;
    let b_vec = polyvec_to_le_bytes(&computed.b_ntt);
    let u_vec = polyvec_to_le_bytes(&computed.u_ntt);
    let v_vec = polyvec_to_le_bytes(&computed.v_ntt);

    Ok(HpBranchOwned {
        k: K as u8,
        n: N as u16,
        q: Q as u16,
        a_seed: computed.a_seed.to_vec(),
        b_vec,
        u_vec,
        v_vec,
        salt_rlwe: computed.salt.to_vec(),
        lin_desc: LinDescOwned(LIN_DESC_LABEL.to_string(), 32, 3329),
        ctx_tag: computed.ctx_tag.to_vec(),
        flags: HpFlagsOwned {
            poly_encoding: "ntt-le16".to_string(),
            coef_endian: "le16".to_string(),
            ntt_order: "bitrev".to_string(),
        },
    })
}

fn compute_rlwe_components(
    seed: &[u8; 32],
    crs_id: &str,
    params_id: &str,
    xk_hash: &[u8; 32],
) -> Result<ComputedBranch, MsphfError> {
    let a_seed = xof32(A_SEED_LABEL, seed);
    let salt = xof32(SALT_LABEL, seed);

    let mut a_matrix = expand_a(&a_seed);
    for row in a_matrix.iter_mut() {
        for poly in row.iter_mut() {
            poly.to_ntt();
        }
    }

    let mut e_b = sample_polyvec(seed, SEED_EB_LABEL)?;
    let mut e1 = sample_polyvec(seed, SEED_E1_LABEL)?;
    let mut e2 = sample_polyvec(seed, SEED_E2_LABEL)?;
    let mut s_ntt = sample_polyvec(seed, SEED_S_LABEL)?;
    s_ntt.ntt();
    let mut r_ntt = sample_polyvec(seed, SEED_R_LABEL)?;
    r_ntt.ntt();

    let b_ntt = mat_vec_mul(&a_matrix, &s_ntt, &mut e_b);
    let u_ntt = mat_vec_mul(&a_matrix, &r_ntt, &mut e1);
    let v_ntt = component_wise_mul(&b_ntt, &r_ntt, &mut e2);

    let ctx_tag = compute_ctx_tag(xk_hash, crs_id, params_id)?;

    Ok(ComputedBranch {
        a_seed,
        salt,
        ctx_tag,
        b_ntt,
        u_ntt,
        v_ntt,
    })
}

fn mat_vec_mul(matrix: &Matrix, vec_ntt: &PolyVec, error: &mut PolyVec) -> PolyVec {
    let mut acc_ntt = [Poly::zero(); K];
    for (i, acc) in acc_ntt.iter_mut().enumerate() {
        let mut row_iter = matrix[i].iter().zip(vec_ntt.polys.iter());
        if let Some((matrix_poly, vec_poly)) = row_iter.next() {
            let mut row_acc = matrix_poly.pointwise_mul(vec_poly);
            for (matrix_poly, vec_poly) in row_iter {
                let prod = matrix_poly.pointwise_mul(vec_poly);
                row_acc.add_assign(&prod);
            }
            row_acc.from_ntt();
            row_acc.add_assign(&error.polys[i]);
            row_acc.to_ntt();
            *acc = row_acc;
        }
    }
    PolyVec { polys: acc_ntt }
}

fn component_wise_mul(b_ntt: &PolyVec, r_ntt: &PolyVec, error: &mut PolyVec) -> PolyVec {
    let mut out = [Poly::zero(); K];
    for (i, out_poly) in out.iter_mut().enumerate() {
        let mut prod = b_ntt.polys[i].pointwise_mul(&r_ntt.polys[i]);
        prod.from_ntt();
        prod.add_assign(&error.polys[i]);
        prod.to_ntt();
        *out_poly = prod;
    }
    PolyVec { polys: out }
}

fn compute_ctx_tag(
    xk_hash: &[u8; 32],
    crs_id: &str,
    params_id: &str,
) -> Result<[u8; 32], MsphfError> {
    #[derive(Serialize)]
    struct Ctx<'a> {
        #[serde(with = "serde_bytes")]
        xk_hash: &'a [u8],
        crs: &'a str,
        params: &'a str,
    }
    h_l(
        HPS_CTX_LABEL,
        &Ctx {
            xk_hash,
            crs: crs_id,
            params: params_id,
        },
    )
}

fn compute_delta(
    branch: &str,
    instance: &AnchorInstance<'_>,
    witness: Option<&ValidatedWitness>,
) -> Result<[u16; 32], MsphfError> {
    if let Some(w) = witness {
        let expected_mode = match branch {
            "A" => WitnessMode::A,
            "B" => WitnessMode::B,
            _ => return Err(MsphfError::invalid_input("unknown branch")),
        };
        if w.mode != expected_mode {
            return Err(MsphfError::invalid_input("witness mode/branch mismatch"));
        }
        let u = map_root_to_field(&w.membership.root);
        let g_root = match branch {
            "A" => instance.parent_root,
            _ => instance.join_delta_root,
        };
        let g = map_root_to_field(slice_to_array(g_root)?);
        Ok(sub_field_vectors(&u, &g))
    } else {
        Ok([0u16; 32])
    }
}

fn slice_to_array(slice: &[u8]) -> Result<&[u8; 32], MsphfError> {
    slice
        .try_into()
        .map_err(|_| MsphfError::invalid_input("root length"))
}

fn map_root_to_field(root: &[u8; 32]) -> [u16; 32] {
    let mut out = [0u16; 32];
    for (i, byte) in root.iter().enumerate() {
        out[i] = (*byte as u16) % Q as u16;
    }
    out
}

fn sub_field_vectors(u: &[u16; 32], g: &[u16; 32]) -> [u16; 32] {
    let mut out = [0u16; 32];
    for i in 0..32 {
        let diff = (u[i] as i32 - g[i] as i32) % Q as i32;
        out[i] = if diff < 0 {
            (diff + Q as i32) as u16
        } else {
            diff as u16
        };
    }
    out
}

fn linmask_from_delta(delta: &[u16; 32]) -> Result<[u8; 32], MsphfError> {
    let mut buf = [0u8; 64];
    for (i, val) in delta.iter().enumerate() {
        buf[2 * i] = (*val & 0xFF) as u8;
        buf[2 * i + 1] = (*val >> 8) as u8;
    }
    #[derive(Serialize)]
    struct LinMask<'a> {
        desc: &'a str,
        #[serde(with = "serde_bytes")]
        delta: &'a [u8],
    }
    h_l(
        HPS_LINMASK_LABEL,
        &LinMask {
            desc: LIN_DESC_LABEL,
            delta: &buf,
        },
    )
}

fn linmask_zero() -> Result<[u8; 32], MsphfError> {
    linmask_from_delta(&[0u16; 32])
}

fn xor_bytes(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn polyvec_to_le_bytes(pv: &PolyVec) -> Vec<u8> {
    let mut out = vec![0u8; POLYVEC_LE_BYTES];
    for (i, poly) in pv.polys.iter().enumerate() {
        for (j, coeff) in poly.coeffs.iter().enumerate() {
            let mut val = *coeff as i32 % Q as i32;
            if val < 0 {
                val += Q as i32;
            }
            let val = val as u16;
            let idx = i * POLY_LE_BYTES + j * 2;
            out[idx] = (val & 0xFF) as u8;
            out[idx + 1] = (val >> 8) as u8;
        }
    }
    out
}

fn sample_polyvec(seed: &[u8; 32], label: &str) -> Result<PolyVec, MsphfError> {
    let mut reader = xof_reader(label, seed);
    let mut polys = [Poly::zero(); K];
    for poly in polys.iter_mut() {
        let mut buf = [0u8; POLY_LE_BYTES / 2];
        reader.fill(&mut buf);
        cbd_eta2_poly(&mut poly.coeffs, &buf)?;
        for coeff in poly.coeffs.iter_mut() {
            *coeff = barrett_reduce(*coeff as i32);
        }
    }
    Ok(PolyVec { polys })
}

fn xof_reader(label: &str, seed: &[u8; 32]) -> blake3::OutputReader {
    let mut hasher = Hasher::new();
    hasher.update(b"city-g|xof|");
    hasher.update(label.as_bytes());
    hasher.update(&[0u8]);
    hasher.update(seed);
    hasher.finalize_xof()
}

fn xof32(label: &str, seed: &[u8; 32]) -> [u8; 32] {
    let mut reader = xof_reader(label, seed);
    let mut out = [0u8; 32];
    reader.fill(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::ser;
    use msphf_core::hash::hash_bytes_with_label;
    use msphf_core::params::{RLWE_CRS_ID_DEFAULT, RLWE_PARAMS_ID_MOCK};
    use msphf_core::{
        merkle::{hash_leaf, hash_node},
        witness::{CanonicalWitness, RawMembershipWitness, RawPathEntry, WitnessVariants},
    };
    use pqcrypto_dilithium::dilithium5::{detached_sign, keypair};
    use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

    fn fixture() -> (AnchorInstance<'static>, ValidatedWitness, [u8; 32]) {
        fn leak(bytes: [u8; 32]) -> &'static [u8] {
            Box::leak(Box::new(bytes)).as_slice()
        }

        let leaf = hash_leaf(b"leaf0");
        let sibling = hash_leaf(b"leaf1");
        let root = hash_node(&leaf, &sibling);

        let witness = CanonicalWitness {
            inner: WitnessVariants::A {
                witness: RawMembershipWitness {
                    leaf_id: leaf.to_vec(),
                    root: root.to_vec(),
                    path: vec![RawPathEntry {
                        sibling: sibling.to_vec(),
                        dir: 0,
                    }],
                },
                pop: None,
            },
        };

        let mut witness_bytes = Vec::new();
        ser::into_writer(&witness, &mut witness_bytes).expect("serialize witness");
        let canonical: CanonicalWitness =
            ciborium::de::from_reader(witness_bytes.as_slice()).expect("deserialize witness");

        let anchor = AnchorInstance {
            gid: leak([0x11; 32]),
            cat: leak([0x22; 32]),
            we_epoch_id: [0x07; 32],
            anchor_hdr_ctx: leak([0x33; 32]),
            tswe_salt_hash: leak([0x44; 32]),
            parent_root: leak(root),
            join_delta_root: leak(hash_node(&leaf, &hash_leaf(b"leaf2"))),
            revoked_since_prev_root: leak(hash_node(&hash_leaf(b"leaf3"), &hash_leaf(b"leaf4"))),
            revoked_root: leak(hash_node(&hash_leaf(b"leaf5"), &hash_leaf(b"leaf6"))),
            pox_r_commit: None,
            msphf_hp_commit: None,
        };
        let validated = canonical
            .validate_against(&anchor)
            .expect("validate witness");
        let xk_hash = anchor.xk_hash().expect("xk hash");
        (anchor, validated, xk_hash)
    }

    fn params() -> (&'static str, &'static str) {
        (RLWE_CRS_ID_DEFAULT, RLWE_PARAMS_ID_MOCK)
    }

    #[test]
    fn hash_proj_matches_full_with_valid_witness() {
        let (anchor, witness, xk_hash) = fixture();
        let (crs_id, params_id) = params();
        let sk = RlweSecretKey::new([0xAA; 32]);

        let full = hash_full(&sk, "A", crs_id, params_id, &anchor, &xk_hash).expect("hash_full");
        let proj = hash_proj(
            &full.projective,
            "A",
            crs_id,
            params_id,
            &anchor,
            Some(&witness),
        )
        .expect("hash_proj with witness");
        assert_eq!(full.y_full, proj);
    }

    #[test]
    fn hash_proj_changes_when_witness_root_tampered() {
        let (anchor, mut witness, xk_hash) = fixture();
        let (crs_id, params_id) = params();
        let sk = RlweSecretKey::new([0x55; 32]);

        let full = hash_full(&sk, "A", crs_id, params_id, &anchor, &xk_hash).expect("hash_full");
        witness.membership.root[0] ^= 0x01;
        let proj = hash_proj(
            &full.projective,
            "A",
            crs_id,
            params_id,
            &anchor,
            Some(&witness),
        )
        .expect("hash_proj with witness tamper");
        assert_ne!(full.y_full, proj);
    }

    #[test]
    fn hash_proj_allows_missing_witness() {
        let (anchor, _, xk_hash) = fixture();
        let (crs_id, params_id) = params();
        let sk = RlweSecretKey::new([0x42; 32]);

        let full = hash_full(&sk, "A", crs_id, params_id, &anchor, &xk_hash).expect("hash_full");
        let proj = hash_proj(&full.projective, "A", crs_id, params_id, &anchor, None)
            .expect("hash_proj without witness");
        assert_eq!(full.y_full, proj);
    }

    fn strict_inputs_fixture() -> (
        CapssStrictInputs<'static>,
        &'static [u8; 32],
        &'static [u8; 32],
    ) {
        fn leak_array(arr: [u8; 32]) -> &'static [u8; 32] {
            Box::leak(Box::new(arr))
        }

        fn leak_bytes(bytes: Vec<u8>) -> &'static [u8] {
            Box::leak(bytes.into_boxed_slice())
        }

        let (anchor_owned, _, xk_hash_val) = fixture();
        let anchor_static: &'static AnchorInstance<'static> = Box::leak(Box::new(anchor_owned));
        let xk_hash_ref = leak_array(xk_hash_val);
        let seed_commit = leak_array([0x11; 32]);
        let seed_ctx_hash = leak_array([0x22; 32]);
        let leaf_id = leak_bytes(vec![0x33; 32]);
        let (pk, sk) = keypair();
        let pop_pk = leak_bytes(pk.as_bytes().to_vec());
        let pop_alg = "ML-DSA-65";

        #[derive(Serialize)]
        struct PopMsg<'a> {
            #[serde(with = "serde_bytes")]
            xk: &'a [u8],
            #[serde(with = "serde_bytes")]
            leaf_id: &'a [u8],
            #[serde(with = "serde_bytes")]
            epoch: &'a [u8],
        }

        let anchor_bytes = anchor_static.to_cbor_bytes().expect("anchor to cbor");
        let pop_msg = h_l(
            ds::MSPHF_POP_MSG,
            &PopMsg {
                xk: &anchor_bytes,
                leaf_id,
                epoch: &anchor_static.we_epoch_id,
            },
        )
        .expect("pop message hash");
        let pop_sig = detached_sign(&pop_msg, &sk);
        let pop_sig_vec = pop_sig.as_bytes().to_vec();

        let rho_raw =
            derive_rho_raw_from_pop(pop_sig.as_bytes(), xk_hash_ref).expect("rho raw derivation");
        let rho_commit_val =
            hash_bytes_with_label(ds::MSPHF_KGEN_RHO, &rho_raw).expect("rho commit");
        let rho_commit = leak_array(rho_commit_val);

        let inputs = CapssStrictInputs {
            crs_id: RLWE_CRS_ID_DEFAULT,
            params_id: RLWE_PARAMS_ID_MOCK,
            seed_commit,
            seed_ctx_hash,
            xk_hash: xk_hash_ref,
            rho_commit,
            pop_alg,
            pop_pk,
            anchor: anchor_static,
            leaf_id,
            pop_sig: pop_sig_vec,
        };

        (inputs, xk_hash_ref, rho_commit)
    }

    #[test]
    fn recompute_capss_witness_detects_xk_hash_mismatch() {
        let (inputs, xk_hash_ref, _) = strict_inputs_fixture();
        let witness = recompute_capss_witness(inputs.clone()).expect("baseline should succeed");
        assert!(!witness.branch_a.branch_artifact.is_empty());

        let mut bad_hash = *xk_hash_ref;
        bad_hash[0] ^= 0x01;
        let bad_hash_ref = Box::leak(Box::new(bad_hash));
        let mut bad_inputs = inputs;
        bad_inputs.xk_hash = bad_hash_ref;

        let err = recompute_capss_witness(bad_inputs).expect_err("xk hash tamper should fail");
        assert!(matches!(
            err,
            MsphfError::WitnessReplayMismatch(WitnessReplayField::XkHash)
        ));
    }

    #[test]
    fn recompute_capss_witness_detects_rho_commit_mismatch() {
        let (inputs, _, rho_commit_ref) = strict_inputs_fixture();
        recompute_capss_witness(inputs.clone()).expect("baseline should succeed");

        let mut bad_rho = *rho_commit_ref;
        bad_rho[0] ^= 0x80;
        let bad_rho_ref = Box::leak(Box::new(bad_rho));
        let mut bad_inputs = inputs;
        bad_inputs.rho_commit = bad_rho_ref;

        let err = recompute_capss_witness(bad_inputs).expect_err("rho commit tamper should fail");
        assert!(matches!(
            err,
            MsphfError::WitnessReplayMismatch(WitnessReplayField::RhoCommit)
        ));
    }

    #[test]
    fn recompute_capss_witness_detects_pop_sig_tamper() {
        let (inputs, _, _) = strict_inputs_fixture();
        let mut tampered_inputs = inputs.clone();
        let mut sig = tampered_inputs.pop_sig.clone();
        if !sig.is_empty() {
            sig[0] ^= 0x01;
        }
        tampered_inputs.pop_sig = sig;

        let err =
            recompute_capss_witness(tampered_inputs).expect_err("pop signature tamper should fail");
        assert!(matches!(
            err,
            MsphfError::WitnessReplayMismatch(WitnessReplayField::RhoCommit)
        ));
    }
}
