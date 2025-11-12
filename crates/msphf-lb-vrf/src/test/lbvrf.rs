use crate::VRF;
use crate::error::Error;
use crate::lbvrf::*;
use crate::param::*;
use crate::poly::PolyArith;
use crate::poly256::Poly256;
use crate::rand::RngCore;
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
        assert!(*e <= 1 || *e >= -1, "coefficients out of range {}", *e);
        if *e != 0 {
            sum += 1;
        }
    }
    assert_eq!(sum, KAPPA)
}

#[test]
fn test_lbvrf() {
    let seed = [0u8; 32];
    // let mut rng = rand::thread_rng();
    // let param = Param::init(&mut rng);

    let param: Param = <LBVRF as VRF>::paramgen(seed).expect("paramgen");
    let (pk, sk) = <LBVRF as VRF>::keygen(seed, param).expect("keygen");
    let message = "this is a message that vrf signs";
    let seed = [0u8; 32];
    let proof = <LBVRF as VRF>::prove(message, param, pk, sk, seed).expect("prove");

    let mut buf: Vec<u8> = vec![];
    assert!(proof.serialize(&mut buf).is_ok());
    println!("{:?}", buf);
    let proof2 =
        <LBVRF as VRF>::Proof::deserialize(&mut buf[..].as_ref()).expect("deserialize proof");
    assert_eq!(proof, proof2);

    let res = <LBVRF as VRF>::verify(message, param, pk, proof).expect("verify");
    let vrf_output = res.expect("expected VRF output");
    assert_eq!(vrf_output, proof.v);
}

#[test]
fn test_rs() {
    let mut rng = rand::thread_rng();
    let mut pp_seed = [0u8; 32];
    let mut key_seed = [0u8; 32];
    let mut vrf_seed = [0u8; 32];

    let mut t = 0;
    let total = 10;
    for _i in 0..total {
        rng.fill_bytes(&mut pp_seed);
        rng.fill_bytes(&mut key_seed);
        rng.fill_bytes(&mut vrf_seed);
        let param: Param = <LBVRF as VRF>::paramgen(pp_seed).expect("paramgen");
        let (pk, sk) = <LBVRF as VRF>::keygen(key_seed, param).expect("keygen");
        let message = "this is a message that vrf signs";
        let (proof, rs) = prove_with_rs(message, param, pk, sk, vrf_seed).expect("prove_with_rs");
        t += rs;
        let res = <LBVRF as VRF>::verify(message, param, pk, proof).expect("verify");
        let vrf_output = res.expect("expected VRF output");
        assert_eq!(vrf_output, proof.v);
    }
    println!("rs times {} for {} vrfs", t, total);
    // assert!(false)
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

    let err = check_norm(&z).expect_err("expected norm violation");
    assert!(matches!(err, Error::NormViolation { .. }));
    if let Error::NormViolation { poly, coeff } = err {
        assert_eq!(poly, 3);
        assert_eq!(coeff, 42);
    }
}

#[test]
fn epoch_derivation_is_deterministic() {
    let params = LBVRF::paramgen([0xA5; 32]).expect("paramgen");
    let mut rng = ChaCha20Rng::from_seed([0x11; 32]);
    let master = LBVRF::master_keygen_with_rng(&mut rng);
    let epoch_id = [0x7Bu8; 32];
    let (pk1, sk1) = master.derive_epoch_keypair(&params, &epoch_id);
    let (pk2, sk2) = master.derive_epoch_keypair(&params, &epoch_id);
    assert_eq!(pk1, pk2);
    assert_eq!(sk1, sk2);
}

#[test]
fn epoch_derivation_differs_by_epoch() {
    let params = LBVRF::paramgen([0x3Cu8; 32]).expect("paramgen");
    let mut rng = ChaCha20Rng::from_seed([0x55; 32]);
    let master = LBVRF::master_keygen_with_rng(&mut rng);
    let epoch_a = [0x01u8; 32];
    let epoch_b = [0x02u8; 32];
    let (pk_a, _sk_a) = master.derive_epoch_keypair(&params, &epoch_a);
    let (pk_b, _sk_b) = master.derive_epoch_keypair(&params, &epoch_b);
    assert_ne!(pk_a, pk_b);
}

#[test]
fn proof_serialized_size_within_budget() {
    let params = LBVRF::paramgen([0x24u8; 32]).expect("paramgen");
    let (pk, sk) = LBVRF::keygen([0x42u8; 32], params).expect("keygen");
    let message = b"msphf/lbvrf/proof-size";
    let proof = LBVRF::prove(message, params, pk, sk, [0x77u8; 32]).expect("prove");

    let mut serialized = Vec::new();
    proof.serialize(&mut serialized).expect("serialize proof");
    assert!(
        serialized.len() <= 6144,
        "expected proof <= 6144 bytes, got {}",
        serialized.len()
    );
}

#[test]
fn proof_rejects_param_digest_mutation() {
    let params = LBVRF::paramgen([0x10u8; 32]).expect("paramgen");
    let (pk, sk) = LBVRF::keygen([0x99u8; 32], params).expect("keygen");
    let message = b"msphf/lbvrf/transcript-binding";
    let proof = LBVRF::prove(message, params, pk, sk, [0x33u8; 32]).expect("prove");

    let mut tampered = params;
    tampered.digest[0] ^= 0xFF;

    let verified = LBVRF::verify(message, tampered, pk, proof).expect("verify");
    assert!(
        verified.is_none(),
        "proof verification must fail when param digest changes"
    );
}
