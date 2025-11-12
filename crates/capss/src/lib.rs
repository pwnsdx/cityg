#![allow(unexpected_cfgs, non_local_definitions)]

//! CAPSS: A Framework for SNARK-Friendly Post-Quantum Signatures
//!
//! This crate implements CAPSS/Smallwood, a hash-based polynomial commitment scheme with
//! zero-knowledge proofs used for server-blind validation in City-G's forward secrecy protocol.
//!
//! ## Key Features
//!
//! - **Deterministic proof of knowledge**: Proves that `hp` was derived deterministically from a seed
//! - **Forward secrecy binding**: Cryptographically binds FS metadata to prevent tampering
//! - **Server-blind validation**: ~12KB proofs can be verified without learning secrets
//!
//! ## Implementation Note
//!
//! **This is a Rust port of a canonical Sage/Python reference implementation.**
//!
//! - Sage reference: `vendor/smallwood-python/` (git submodule; set `SMALLWOOD_PYTHON_PATH`
//!   to override)
//! - Rust port: This crate (performance-oriented)
//! - Cross-language fixture tests ensure bit-for-bit compatibility
//!
//! The crate provides the Smallwood proof pipeline that mirrors the Sage reference.
//!
//! For detailed documentation on the port relationship, testing workflow, and architecture,
//! see the [crate README](https://github.com/pwnsdx/cityg/tree/main/crates/capss#readme).

pub mod config;
pub mod field;
pub mod permutation;
pub mod prover;
pub mod smallwood;
pub mod transcript;
pub mod types;
pub mod verifier;

use crate::{
    config::CapssConfig,
    smallwood::SmallwoodConfig,
    types::{CapssPublicKey, CapssSignature, CapssStatement},
};

/// High level CAPSS prover trait. Concrete implementations (e.g. Anemoi-based SmallWood)
/// will satisfy this trait once the permutation arithmetic is wired in.
pub trait CapssProver {
    /// Generate a signature (proof of knowledge) for the provided statement.
    fn prove(&self, statement: &CapssStatement) -> anyhow::Result<CapssSignature>;
}

/// High level CAPSS verifier trait. Implementations validate signatures against the public
/// key and statement under a specific permutation family and parameter set.
pub trait CapssVerifier {
    /// Verify a signature, returning `Ok(())` when valid.
    fn verify(&self, statement: &CapssStatement, signature: &CapssSignature) -> anyhow::Result<()>;
}

/// Context storing the CAPSS configuration, public key, and derived SmallWood parameters.
#[derive(Clone, Debug)]
pub struct CapssContext {
    pub config: CapssConfig,
    pub public_key: CapssPublicKey,
    smallwood_config: SmallwoodConfig,
}

impl CapssContext {
    /// Build a context with the supplied configuration and public key.
    pub fn new(config: CapssConfig, public_key: CapssPublicKey) -> Self {
        let smallwood_config = config.smallwood_config();
        Self {
            config,
            public_key,
            smallwood_config,
        }
    }

    /// Return a borrowed view of the configuration.
    pub fn config(&self) -> &CapssConfig {
        &self.config
    }

    /// Return a borrowed view of the public key.
    pub fn public_key(&self) -> &CapssPublicKey {
        &self.public_key
    }

    /// Return the derived SmallWood configuration.
    pub fn smallwood_config(&self) -> &SmallwoodConfig {
        &self.smallwood_config
    }
}

/// Construct a SmallWood-backed CAPSS prover.
pub fn smallwood_prover(context: CapssContext) -> prover::SmallwoodProver {
    prover::SmallwoodProver::new(context)
}

/// Construct a SmallWood-backed CAPSS verifier.
pub fn smallwood_verifier(context: CapssContext) -> verifier::SmallwoodVerifier {
    verifier::SmallwoodVerifier::new(context)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_roundtrip() {
        let cfg = CapssConfig::default();
        let pk = CapssPublicKey::default();
        let ctx = CapssContext::new(cfg.clone(), pk.clone());
        assert_eq!(ctx.config(), &cfg);
        assert_eq!(ctx.public_key(), &pk);
    }

    #[test]
    fn smallwood_prove_verify() {
        let cfg = CapssConfig::default();
        let pk = CapssPublicKey::default();
        let ctx = CapssContext::new(cfg.clone(), pk.clone());
        let prover = crate::smallwood_prover(ctx.clone());
        let verifier = crate::smallwood_verifier(ctx);

        let statement = CapssStatement {
            public_key: pk,
            message: b"real smallwood".to_vec(),
        };

        let sig = prover.prove(&statement).expect("prove");
        verifier.verify(&statement, &sig).expect("verify");
    }
}
