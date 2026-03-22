// use crate::keypair::{PublicKey, SecretKey};
use crate::VRF;
use crate::lbvrf::LBVRF;
use crate::param::Param;
use crate::serde::Serdes;
use rand::Rng;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

#[test]
fn test_keygen() -> Result<(), Box<dyn std::error::Error>> {
    let seed = [0u8; 32];
    // let mut rng = rand::rng();
    // let param = Param::init(&mut rng);

    let param: Param = <LBVRF as VRF>::paramgen(seed)?;
    let (_pk, _sk) = <LBVRF as VRF>::keygen(seed, param)?;
    Ok(())
}

#[test]
fn test_serdes_keygen() -> Result<(), Box<dyn std::error::Error>> {
    let seed = [0u8; 32];
    // let mut rng = rand::rng();
    // let param = Param::init(&mut rng);

    let param: Param = <LBVRF as VRF>::paramgen(seed)?;
    let (pk, sk) = <LBVRF as VRF>::keygen(seed, param)?;

    let mut buf: Vec<u8> = vec![];
    assert!(pk.serialize(&mut buf).is_ok());
    println!("{:?}", buf);
    let pk2 = <LBVRF as VRF>::PublicKey::deserialize(&mut buf[..].as_ref())?;
    assert_eq!(pk, pk2);

    let mut buf: Vec<u8> = vec![];
    assert!(sk.serialize(&mut buf).is_ok());
    println!("{:02x?}", buf);
    let sk2 = <LBVRF as VRF>::SecretKey::deserialize(&mut buf[..].as_ref())?;
    assert_eq!(sk, sk2);
    Ok(())
}

#[test]
fn keygen_with_rng_matches_seed_api() -> Result<(), Box<dyn std::error::Error>> {
    let seed = [0x24u8; 32];
    let param = <LBVRF as VRF>::paramgen(seed)?;
    let via_seed = <LBVRF as VRF>::keygen(seed, param)?;

    let mut rng = ChaCha20Rng::from_seed(seed);
    let via_rng = LBVRF::keygen_with_rng(&mut rng, param)?;

    assert_eq!(via_seed, via_rng);
    Ok(())
}

#[test]
fn keygen_with_rng_advances_rng_state() -> Result<(), Box<dyn std::error::Error>> {
    let seed = [0x11u8; 32];
    let param = <LBVRF as VRF>::paramgen(seed)?;
    let mut rng = ChaCha20Rng::from_seed(seed);
    let _ = LBVRF::keygen_with_rng(&mut rng, param)?;
    let after = rng.next_u32();

    let mut fresh = ChaCha20Rng::from_seed(seed);
    let baseline = fresh.next_u32();

    assert_ne!(after, baseline);
    Ok(())
}
