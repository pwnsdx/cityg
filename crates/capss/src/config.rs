//! Configuration knobs for CAPSS experiments.

use crate::smallwood::SmallwoodConfig;

/// CAPSS configuration bridging high-level parameters with the SmallWood proof settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapssConfig {
    /// Human readable label for the permutation family (e.g. "anemoi-128").
    pub label: String,
    /// Number of repetitions used in the argument (equivalent of soundness parameter).
    pub repetitions: u32,
    /// Target security level in bits (128, 192, ...).
    pub security_level: u16,
    /// Degree bound for the commitment polynomials.
    pub polynomial_degree: usize,
    /// Fiat–Shamir domain separator.
    pub fs_domain: String,
    /// Number of verifier queries per repetition.
    pub nb_queries: usize,
    /// Number of mask polynomials (rho).
    pub rho: usize,
}

impl Default for CapssConfig {
    fn default() -> Self {
        Self {
            label: "capss-smallwood".to_string(),
            repetitions: 1,
            security_level: 128,
            polynomial_degree: 4,
            fs_domain: "msphf/smallwood/chal".to_string(),
            nb_queries: 1,
            rho: 1,
        }
    }
}

impl CapssConfig {
    /// Translate the CAPSS configuration into the SmallWood prover/verifier parameters.
    pub fn smallwood_config(&self) -> SmallwoodConfig {
        SmallwoodConfig {
            repetitions: self.repetitions.max(1) as usize,
            security_level: self.security_level,
            polynomial_degree: self.polynomial_degree,
            fs_domain: self.fs_domain.clone(),
            nb_queries: self.nb_queries,
            rho: self.rho,
        }
    }
}
