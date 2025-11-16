//! Traits describing arithmetization-oriented permutations (Poseidon, Anemoi, ...).

use crate::field::FieldElement;

pub mod poseidon;
mod poseidon_params;

/// Lightweight trait capturing the operations the CAPSS framework needs from a permutation.
pub trait ArithPermutation {
    /// Number of field elements in the permutation state.
    fn width(&self) -> usize;

    /// Apply the permutation in place.
    fn apply(&self, state: &mut [FieldElement]);

    /// Domain separation helper, e.g. tweak constants per context.
    fn domain(&self) -> &'static str {
        "default"
    }
}

pub use poseidon::PoseidonPermutation;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trait_default_domain_matches_poseidon() -> Result<(), Box<dyn std::error::Error>> {
        let perm = PoseidonPermutation::new(2)?;
        assert_eq!(perm.domain(), "default");
        assert_eq!(perm.width(), 3);
        Ok(())
    }
}
