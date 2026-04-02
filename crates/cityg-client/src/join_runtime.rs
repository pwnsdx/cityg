use anyhow::Result;
use msphf_orchestrator::ForwardSecrecyState;
use rand::{Rng, rng};

use crate::{barrier_crypto::generate_barrier_leaf_keypair, vrf::generate_vrf_keys};

pub struct JoinRuntimeMaterial {
    pub barrier_leaf_public_key: Vec<u8>,
    pub barrier_leaf_secret_key: Vec<u8>,
    pub barrier_leaf_pkhash: [u8; 32],
    pub vrf_secret_key: Vec<u8>,
    pub vrf_public_key: Vec<u8>,
    pub forward_state: ForwardSecrecyState,
}

pub fn generate_join_runtime_material() -> Result<JoinRuntimeMaterial> {
    let (barrier_leaf_public_key, barrier_leaf_secret_key, barrier_leaf_pkhash) =
        generate_barrier_leaf_keypair()?;
    let (vrf_secret_key, vrf_public_key) = generate_vrf_keys()?;

    let mut k_fs = [0u8; 32];
    rng().fill(&mut k_fs);

    Ok(JoinRuntimeMaterial {
        barrier_leaf_public_key,
        barrier_leaf_secret_key,
        barrier_leaf_pkhash,
        vrf_secret_key,
        vrf_public_key,
        forward_state: ForwardSecrecyState::new(k_fs),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::barrier::compute_barrier_pkhash;

    #[test]
    fn generate_join_runtime_material_returns_consistent_leaf_hash() -> Result<()> {
        let runtime = generate_join_runtime_material()?;
        assert_eq!(
            runtime.barrier_leaf_pkhash,
            compute_barrier_pkhash(runtime.barrier_leaf_public_key.as_slice())?
        );
        assert!(!runtime.vrf_secret_key.is_empty());
        assert!(!runtime.vrf_public_key.is_empty());
        Ok(())
    }
}
