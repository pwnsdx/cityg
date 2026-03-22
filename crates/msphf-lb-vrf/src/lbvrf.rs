#![allow(clippy::many_single_char_names)]
// use crate::keypair::PublicKey;
use crate::VRF;
use crate::error::{Error, Result};
use crate::param::*;
use crate::poly::PolyArith;
use crate::poly32::Poly32;
use crate::poly32::poly32_inner_product;
use crate::poly256::*;
use crate::serde::Serdes;
use blake3::Hasher as Blake3Hasher;
use rand::{CryptoRng, Rng};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use sha2::{Digest, Sha512};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

#[derive(PartialEq, Clone, Copy, Debug)]
pub struct Proof {
    pub(crate) z: [Poly256; 9],
    pub(crate) c: Poly256,
    pub(crate) v: VRFOutput,
}

pub type VRFOutput = Poly32;

pub struct LBVRF;

impl VRF for LBVRF {
    type PubParam = Param;
    type PublicKey = crate::keypair::PublicKey;
    type SecretKey = crate::keypair::SecretKey;
    type Proof = crate::lbvrf::Proof;
    type VrfOutput = crate::lbvrf::VRFOutput;

    /// input some seed, generate public parameters
    fn paramgen(seed: [u8; 32]) -> Result<Self::PubParam> {
        let mut rng = ChaCha20Rng::from_seed(seed);
        Self::paramgen_with_rng(&mut rng)
    }
    /// input a seed and a parameter output a pair of keys
    fn keygen(seed: [u8; 32], pp: Self::PubParam) -> Result<(Self::PublicKey, Self::SecretKey)> {
        let mut rng = ChaCha20Rng::from_seed(seed);
        Self::keygen_with_rng(&mut rng, pp)
    }

    /// input a message, a public parameter, a pair of keys
    /// generate a vrf proof
    fn prove<Blob: AsRef<[u8]>>(
        message: Blob,
        pp: Self::PubParam,
        pk: Self::PublicKey,
        sk: Self::SecretKey,
        seed: [u8; 32],
    ) -> Result<Self::Proof> {
        let (proof, _rs) = prove_with_rs(message, pp, pk, sk, seed)?;
        Ok(proof)
    }

    /// input a message, a public parameter, the public key, and a proof
    /// generate an output if proof is valid
    fn verify<Blob: AsRef<[u8]>>(
        message: Blob,
        pp: Self::PubParam,
        pk: Self::PublicKey,
        proof: Self::Proof,
    ) -> Result<Option<Self::VrfOutput>> {
        // step 3: check the length of z
        if check_norm(&proof.z).is_err() {
            return Ok(None);
        }

        // step 0: rebuild b and z_p, c_p, v_p
        let mut hash_input: Vec<u8> = Vec::new();
        pk.serialize(&mut hash_input)?;
        let mut hasher = Sha512::new();
        hasher.update(pp.digest.as_ref());
        hasher.update(&hash_input);
        hasher.update(message.as_ref());
        let digest = hasher.finalize();
        hash_input.zeroize();
        let b = hash_to_new_basis(digest.as_ref());

        let z_p: Vec<Poly32> = proof.z.iter().map(|x| (*x).into()).collect();
        let c_p: Poly32 = proof.c.into();

        // step 1: compute w1_prime = A z - c t
        let mut w1 = [Poly256::zero(); 4];
        for (i, e) in w1.iter_mut().enumerate() {
            *e = poly256_inner_product(&pp.matrix[i], &proof.z);
            (*e).sub_assign(&Poly256::mul_trinary(&pk.t[i], &proof.c));
        }

        // step 2: compute w2_prime = <b, z> - cv
        let mut w2 = poly32_inner_product(&b, &z_p);
        w2.sub_assign(&Poly32::mul(&c_p, &proof.v));

        // step 3: check length of z -- done already

        // step 4: check c = hash(A, t, u, w1_prime, w2_prime, v)
        let mut hash_input: Vec<u8> = Vec::new();
        for e in w1.iter() {
            e.serialize(&mut hash_input)?;
        }
        w2.serialize(&mut hash_input)?;
        proof.v.serialize(&mut hash_input)?;
        let mut hasher = Sha512::new();
        hasher.update(&digest[..]);
        hasher.update(&hash_input);
        let digest = hasher.finalize();
        hash_input.zeroize();
        let c = hash_to_challenge(&digest);
        if bool::from(c.ct_eq(&proof.c)) {
            Ok(Some(proof.v))
        } else {
            Ok(None)
        }
    }
}

impl LBVRF {
    pub fn paramgen_with_rng<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> Result<Param> {
        Param::init(rng)
    }

    pub fn keygen_with_rng<R: Rng + CryptoRng + ?Sized>(
        rng: &mut R,
        pp: Param,
    ) -> Result<(crate::keypair::PublicKey, crate::keypair::SecretKey)> {
        Ok(keypair_from_rng(rng, pp))
    }

    pub fn master_keygen_with_rng<R: Rng + CryptoRng + ?Sized>(
        rng: &mut R,
    ) -> crate::keypair::MasterSecretKey {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        crate::keypair::MasterSecretKey::from_bytes(seed)
    }
}

pub fn derive_epoch_keypair(
    master: &crate::keypair::MasterSecretKey,
    params: &Param,
    epoch_id: &[u8; 32],
) -> (crate::keypair::PublicKey, crate::keypair::SecretKey) {
    let mut hasher = Blake3Hasher::new();
    hasher.update(b"msphf/lbvrf/epoch");
    hasher.update(master.as_bytes());
    hasher.update(epoch_id);
    let digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest.as_bytes()[..32]);
    let mut rng = ChaCha20Rng::from_seed(seed);
    keypair_from_rng(&mut rng, *params)
}

fn keypair_from_rng<R: Rng + CryptoRng + ?Sized>(
    rng: &mut R,
    pp: Param,
) -> (crate::keypair::PublicKey, crate::keypair::SecretKey) {
    let mut sk = crate::keypair::SecretKey {
        s: [Poly256::zero(); 9],
    };
    for e in sk.s.iter_mut() {
        *e = PolyArith::rand_trinary(rng);
    }
    let mut pk = crate::keypair::PublicKey {
        t: [Poly256::zero(); 4],
    };
    for i in 0..4 {
        pk.t[i] = poly256_inner_product_trinary(&pp.matrix[i], &sk.s);
    }
    (pk, sk)
}

impl crate::keypair::MasterSecretKey {
    pub fn derive_epoch_keypair(
        &self,
        params: &Param,
        epoch_id: &[u8; 32],
    ) -> (crate::keypair::PublicKey, crate::keypair::SecretKey) {
        derive_epoch_keypair(self, params, epoch_id)
    }
}

pub(crate) fn hash_to_new_basis(input: &[u8]) -> [Poly32; 9] {
    let mut hasher = Sha512::new();
    hasher.update(input);
    hasher.update(b"domain seperator: hash to basis");
    let digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest[0..32]);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut res = [Poly32::zero(); 9];
    for e in res.iter_mut() {
        *e = Poly32::uniform_random(&mut rng);
    }
    res
}

pub(crate) fn hash_to_challenge(input: &[u8]) -> Poly256 {
    let mut hasher = Sha512::new();
    hasher.update(input);
    hasher.update(b"domain seperator: hash to challenge");
    let digest = hasher.finalize();
    let mut res = [0i64; 256];
    let mut sign_pt = 0;
    let mut coeff_pt = 0;
    let mut ct = 0;
    let mut tmp = digest[63];
    for _i in 0..KAPPA {
        let coeff = tmp & 0b1;
        tmp >>= 1;
        ct += 1;
        if ct == 4 {
            ct = 0;
            sign_pt += 1;
            tmp = digest[64 - sign_pt - 1];
        }
        if res[digest[coeff_pt] as usize] != 0 {
            coeff_pt += 1;
        }
        res[digest[coeff_pt] as usize] = if coeff == 1 { 1 } else { -1 };
        coeff_pt += 1;

        if coeff_pt + sign_pt == 64 {
            debug_assert!(
                false,
                "hash_to_challenge exhausted entropy; check PRNG and domain separation"
            );
            break;
        }
    }

    Poly256 { coeff: res }
}

pub(crate) fn check_norm(z: &[Poly256; 9]) -> Result<()> {
    let mut ok = Choice::from(1u8);
    for poly in z.iter() {
        for coeff in poly.coeff.iter() {
            let abs = coeff.saturating_abs();
            let within = Choice::from((abs <= BETA_M_KAPPA) as u8);
            ok &= within;
        }
    }
    if bool::from(ok) {
        return Ok(());
    }
    for (poly_idx, poly) in z.iter().enumerate() {
        for (coeff_idx, coeff) in poly.coeff.iter().enumerate() {
            let abs = coeff.saturating_abs();
            if abs > BETA_M_KAPPA {
                return Err(Error::NormViolation {
                    poly: poly_idx,
                    coeff: coeff_idx,
                });
            }
        }
    }
    Err(Error::NormViolation { poly: 0, coeff: 0 })
}

/// input a message, a public parameter, a pair of keys
/// generate a vrf proof
pub(crate) fn prove_with_rs<Blob: AsRef<[u8]>>(
    message: Blob,
    pp: Param,
    pk: crate::keypair::PublicKey,
    sk: crate::keypair::SecretKey,
    seed: [u8; 32],
) -> Result<(Proof, usize)> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut y = [Poly256::zero(); 9];
    let mut rs = 0;
    // step 0: s_p = s mod (p, x^32+R)
    let mut s_p: Vec<Poly32> = sk.s.iter().map(|x| (*x).into()).collect();

    // step 1: b = hash_to_new_basis (pp, pk, message)
    let mut hash_input: Vec<u8> = Vec::new();
    pk.serialize(&mut hash_input)?;
    let mut hasher = Sha512::new();
    hasher.update(pp.digest.as_ref());
    hasher.update(&hash_input);
    hasher.update(message.as_ref());
    let digest = hasher.finalize();
    hash_input.zeroize();
    let b = hash_to_new_basis(digest.as_ref());

    // step 2: v = <b, s>
    let v = poly32_inner_product(&b, &s_p);

    // we start rejection sampling here
    loop {
        rs += 1;
        // step 3: sample y
        for e in y.iter_mut() {
            *e = Poly256::rand_mod_beta(&mut rng);
        }
        let y_p: Vec<Poly32> = y.iter().map(|x| (*x).into()).collect();

        // step 4: w1 = Ay, w2 = by
        let mut w1 = [Poly256::zero(); 4];
        for (i, e) in w1.iter_mut().enumerate() {
            *e = poly256_inner_product(&pp.matrix[i], &y);
        }
        let w2 = poly32_inner_product(&b, &y_p);

        // step 5: c = hash_to_challenge(pp, pk, message, w1, w2, v)
        let mut hash_input: Vec<u8> = Vec::new();

        for e in w1.iter() {
            e.serialize(&mut hash_input)?;
        }
        w2.serialize(&mut hash_input)?;
        v.serialize(&mut hash_input)?;
        let mut hasher = Sha512::new();
        hasher.update(&digest[..]);
        hasher.update(&hash_input);
        let digest = hasher.finalize();
        let c = hash_to_challenge(&digest);

        let mut z = y;
        for (i, e) in z.iter_mut().enumerate() {
            (*e).add_assign(&PolyArith::mul_trinary(&sk.s[i], &c));
        }
        for e in z.iter_mut() {
            (*e).centered();
        }
        // #[cfg(debug_assertions)]
        // println!("rejection sampling {} times", rs);
        // #[cfg(debug_assertions)]
        // println!("z:\n{:?}", z);
        if check_norm(&z).is_ok() {
            y.zeroize();
            for poly in s_p.iter_mut() {
                poly.zeroize();
            }
            return Ok((Proof { z, c, v }, rs));
        }
    }
}
