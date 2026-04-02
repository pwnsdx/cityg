use anyhow::{Result, anyhow};
use rand::{Rng, rng};

pub fn generate_vrf_keys() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut params_seed = [0u8; 32];
    let mut key_seed = [0u8; 32];
    let mut rng = rng();
    rng.fill(&mut params_seed);
    rng.fill(&mut key_seed);
    let params = msphf_orchestrator::lb::generate_parameters(params_seed)
        .map_err(|err| anyhow!("generate VRF params: {err}"))?;
    msphf_orchestrator::lb::generate_keypair(&params, key_seed)
        .map_err(|err| anyhow!("generate VRF keypair: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_vrf_keys_are_not_deterministic() -> Result<()> {
        let (secret_a, public_a) = generate_vrf_keys()?;
        let (secret_b, public_b) = generate_vrf_keys()?;
        assert_ne!(secret_a, secret_b);
        assert_ne!(public_a, public_b);
        Ok(())
    }
}
