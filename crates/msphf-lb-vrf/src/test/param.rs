use crate::VRF;
use crate::lbvrf::LBVRF;
use crate::param::Param;
use crate::serde::Serdes;
use rand::RngCore;
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

#[test]
fn test_param() {
    let mut rng = rand::thread_rng();
    let _param = Param::init(&mut rng).ok();
}

#[test]
fn test_serdes_param() -> Result<(), Box<dyn std::error::Error>> {
    let seed = [0u8; 32];
    // let mut rng = rand::thread_rng();
    // let param = Param::init(&mut rng);

    let param: Param = <LBVRF as VRF>::paramgen(seed)?;
    let mut buf: Vec<u8> = vec![];
    assert!(param.serialize(&mut buf).is_ok());
    println!("{:02x?}", buf);
    let param2 = Param::deserialize(&mut buf[..].as_ref())?;
    assert_eq!(param, param2);
    Ok(())
}

#[test]
fn paramgen_with_rng_matches_seed_api() -> Result<(), Box<dyn std::error::Error>> {
    let seed = [0x42u8; 32];
    let via_seed = <LBVRF as VRF>::paramgen(seed)?;

    let mut rng = ChaCha20Rng::from_seed(seed);
    let via_rng = LBVRF::paramgen_with_rng(&mut rng)?;

    assert_eq!(via_seed, via_rng);
    Ok(())
}

#[test]
fn paramgen_with_rng_advances_rng_state() -> Result<(), Box<dyn std::error::Error>> {
    let seed = [0xA5u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let _ = LBVRF::paramgen_with_rng(&mut rng)?;
    let after = rng.next_u64();

    let mut fresh = ChaCha20Rng::from_seed(seed);
    let baseline = fresh.next_u64();

    assert_ne!(after, baseline);
    Ok(())
}
