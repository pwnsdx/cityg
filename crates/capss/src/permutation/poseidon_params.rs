use anyhow::Result;
use ark_ff::PrimeField;
use ark_sponge::poseidon::PoseidonConfig;
use poseidon_bn128::{PoseidonParams, read_constants};
use scalarff::{Bn128FieldElement, FieldElement as ScalarFieldElement};

use crate::field::BaseField;

fn convert_element(elem: Bn128FieldElement) -> BaseField {
    let big = elem.to_biguint();
    let bytes = big.to_bytes_le();
    BaseField::from_le_bytes_mod_order(&bytes)
}

fn params_for_rate(rate: u8) -> Result<PoseidonParams> {
    read_constants(rate)
}

pub fn poseidon_config_rate_2() -> Result<PoseidonConfig<BaseField>> {
    let params = params_for_rate(2)?;
    let t = (2 + 1) as usize;
    let ark = params
        .c
        .chunks_exact(t)
        .map(|chunk| chunk.iter().copied().map(convert_element).collect())
        .collect();
    let mds = params
        .m
        .iter()
        .map(|row| row.iter().copied().map(convert_element).collect())
        .collect();

    Ok(PoseidonConfig::new(
        params.num_full_rounds,
        params.num_partial_rounds,
        5,
        mds,
        ark,
        2,
        1,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::BaseField;

    #[test]
    fn poseidon_config_rate_2_has_expected_dimensions() -> Result<(), Box<dyn std::error::Error>> {
        let config = poseidon_config_rate_2()?;
        assert_eq!(config.rate, 2);
        assert_eq!(config.capacity, 1);
        let width = config.rate + config.capacity;
        assert_eq!(config.ark.len(), config.full_rounds + config.partial_rounds);
        assert!(config.ark.iter().all(|row| row.len() == width));
        assert_eq!(config.mds.len(), width);
        assert!(config.mds.iter().all(|row| row.len() == width));
        assert_ne!(config.ark[0][0], BaseField::from(0u64));
        Ok(())
    }

    #[test]
    fn params_for_rate_reads_constants() -> Result<(), Box<dyn std::error::Error>> {
        let params = super::params_for_rate(2)?;
        assert!(params.num_full_rounds > 0);
        assert!(params.num_partial_rounds > 0);
        assert_eq!(params.c.len() % (2 + 1), 0);
        assert_eq!(params.m.len(), 2 + 1);
        Ok(())
    }
}
