use crate::VRF;
use crate::error::Error;
use crate::lbvrf::*;
use crate::param::*;
use crate::poly::PolyArith;
use crate::poly256::Poly256;
use crate::rand::Rng;
use crate::serde::Serdes;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
#[test]
fn test_param_gen() {
    let p = LBVRF::paramgen([0; 32]);
    println!("{:?}", p);
}

#[test]
fn test_hash_to_challenge() {
    let input = "this is a random input for testing";
    let c = hash_to_challenge(input.as_ref());
    let mut sum = 0;
    for e in c.coeff.iter() {
        assert!((-1..=1).contains(e), "coefficients out of range {}", *e);
        if *e != 0 {
            sum += 1;
        }
    }
    assert_eq!(sum, KAPPA)
}

#[test]
fn hash_to_challenge_regression_keeps_full_weight_for_probe_input() {
    let c = hash_to_challenge(b"probe-8");
    let weight = c.coeff.iter().filter(|coeff| **coeff != 0).count();
    assert_eq!(weight, KAPPA, "challenge weight must remain exactly KAPPA");
}

#[test]
fn hash_to_challenge_keeps_full_weight_across_regression_range() {
    for idx in 0..128u32 {
        let input = format!("probe-{idx}");
        let c = hash_to_challenge(input.as_bytes());
        let weight = c.coeff.iter().filter(|coeff| **coeff != 0).count();
        assert_eq!(weight, KAPPA, "challenge weight drifted for {input}");
    }
}

#[test]
fn test_lbvrf() -> Result<(), Box<dyn std::error::Error>> {
    let seed = [0u8; 32];
    // let mut rng = rand::rng();
    // let param = Param::init(&mut rng);

    let param: Param = <LBVRF as VRF>::paramgen(seed)?;
    let (pk, sk) = <LBVRF as VRF>::keygen(seed, param)?;
    let message = "this is a message that vrf signs";
    let seed = [0u8; 32];
    let proof = <LBVRF as VRF>::prove(message, param, pk, sk, seed)?;

    let mut buf: Vec<u8> = vec![];
    assert!(proof.serialize(&mut buf).is_ok());
    println!("{:?}", buf);
    let proof2 = <LBVRF as VRF>::Proof::deserialize(&mut buf[..].as_ref())?;
    assert_eq!(proof, proof2);

    let res = <LBVRF as VRF>::verify(message, param, pk, proof)?;
    let vrf_output = match res {
        Some(output) => output,
        None => unreachable!("expected VRF output"),
    };
    assert_eq!(vrf_output, proof.v);
    Ok(())
}

#[test]
fn test_rs() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = rand::rng();
    let mut pp_seed = [0u8; 32];
    let mut key_seed = [0u8; 32];
    let mut vrf_seed = [0u8; 32];

    let mut t = 0;
    let total = 10;
    for _i in 0..total {
        rng.fill_bytes(&mut pp_seed);
        rng.fill_bytes(&mut key_seed);
        rng.fill_bytes(&mut vrf_seed);
        let param: Param = <LBVRF as VRF>::paramgen(pp_seed)?;
        let (pk, sk) = <LBVRF as VRF>::keygen(key_seed, param)?;
        let message = "this is a message that vrf signs";
        let (proof, rs) = prove_with_rs(message, param, pk, sk, vrf_seed)?;
        t += rs;
        assert!(
            rs <= MAX_REJECTION_SAMPLING_ATTEMPTS,
            "rejection sampling exceeded hard cap"
        );
        let res = <LBVRF as VRF>::verify(message, param, pk, proof)?;
        let vrf_output = match res {
            Some(output) => output,
            None => unreachable!("expected VRF output"),
        };
        assert_eq!(vrf_output, proof.v);
    }
    println!("rs times {} for {} vrfs", t, total);
    // assert!(false)
    Ok(())
}

#[test]
fn check_norm_accepts_boundary_coefficients() {
    let mut poly = Poly256::zero();
    for (idx, coeff) in poly.coeff.iter_mut().enumerate() {
        *coeff = if idx % 2 == 0 {
            BETA_M_KAPPA
        } else {
            -BETA_M_KAPPA
        };
    }
    let z = [poly; 9];
    assert!(check_norm(&z).is_ok());
}

#[test]
fn check_norm_rejects_out_of_range_coefficients() {
    let mut z = [Poly256::zero(); 9];
    let mut violating = Poly256::zero();
    violating.coeff[42] = BETA_M_KAPPA + 1;
    z[3] = violating;

    let result = check_norm(&z);
    assert!(result.is_err(), "expected norm violation");
    if let Err(err) = result {
        assert!(matches!(err, Error::NormViolation { .. }));
        if let Error::NormViolation { poly, coeff } = err {
            assert_eq!(poly, 3);
            assert_eq!(coeff, 42);
        }
    }
}

#[test]
fn check_norm_rejects_i64_min_coefficients() {
    let mut z = [Poly256::zero(); 9];
    z[4].coeff[17] = i64::MIN;

    let result = check_norm(&z);
    assert!(result.is_err(), "expected norm violation");
    if let Err(err) = result {
        assert!(matches!(err, Error::NormViolation { .. }));
        if let Error::NormViolation { poly, coeff } = err {
            assert_eq!(poly, 4);
            assert_eq!(coeff, 17);
        }
    }
}

#[test]
fn epoch_derivation_is_deterministic() -> Result<(), Box<dyn std::error::Error>> {
    let params = LBVRF::paramgen([0xA5; 32])?;
    let mut rng = ChaCha20Rng::from_seed([0x11; 32]);
    let master = LBVRF::master_keygen_with_rng(&mut rng);
    let epoch_id = [0x7Bu8; 32];
    let (pk1, sk1) = master.derive_epoch_keypair(&params, &epoch_id);
    let (pk2, sk2) = master.derive_epoch_keypair(&params, &epoch_id);
    assert_eq!(pk1, pk2);
    assert_eq!(sk1, sk2);
    Ok(())
}

#[test]
fn epoch_derivation_differs_by_epoch() -> Result<(), Box<dyn std::error::Error>> {
    let params = LBVRF::paramgen([0x3Cu8; 32])?;
    let mut rng = ChaCha20Rng::from_seed([0x55; 32]);
    let master = LBVRF::master_keygen_with_rng(&mut rng);
    let epoch_a = [0x01u8; 32];
    let epoch_b = [0x02u8; 32];
    let (pk_a, _sk_a) = master.derive_epoch_keypair(&params, &epoch_a);
    let (pk_b, _sk_b) = master.derive_epoch_keypair(&params, &epoch_b);
    assert_ne!(pk_a, pk_b);
    Ok(())
}

#[test]
fn proof_serialized_size_within_budget() -> Result<(), Box<dyn std::error::Error>> {
    let params = LBVRF::paramgen([0x24u8; 32])?;
    let (pk, sk) = LBVRF::keygen([0x42u8; 32], params)?;
    let message = b"msphf/lbvrf/proof-size";
    let proof = LBVRF::prove(message, params, pk, sk, [0x77u8; 32])?;

    let mut serialized = Vec::new();
    proof.serialize(&mut serialized)?;
    assert!(
        serialized.len() <= 6144,
        "expected proof <= 6144 bytes, got {}",
        serialized.len()
    );
    Ok(())
}

#[test]
fn proof_rejects_param_digest_mutation() -> Result<(), Box<dyn std::error::Error>> {
    let params = LBVRF::paramgen([0x10u8; 32])?;
    let (pk, sk) = LBVRF::keygen([0x99u8; 32], params)?;
    let message = b"msphf/lbvrf/transcript-binding";
    let proof = LBVRF::prove(message, params, pk, sk, [0x33u8; 32])?;

    let mut tampered = params;
    tampered.digest[0] ^= 0xFF;

    let verified = LBVRF::verify(message, tampered, pk, proof)?;
    assert!(
        verified.is_none(),
        "proof verification must fail when param digest changes"
    );
    Ok(())
}
