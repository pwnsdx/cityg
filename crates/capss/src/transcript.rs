//! Transcript helpers for serialising/deserialising canonical CAPSS Smallwood proofs.

use anyhow::{Context, Result};

use crate::{
    smallwood::SmallwoodProof,
    types::{CapssProof, CapssSignature},
};

/// Encode a [`SmallwoodProof`] into the canonical byte representation carried in field 146.
///
/// The encoding matches the production specification (bincode over `SmallwoodProof`), ensuring that
/// proofs generated in Rust remain byte-for-byte compatible with the Sage/Python fixtures.
pub fn encode_proof(proof: &SmallwoodProof) -> Result<Vec<u8>> {
    bincode::serialize(proof).context("serialize Smallwood proof")
}

/// Decode a canonical proof byte string back into the structured [`SmallwoodProof`].
pub fn decode_proof(bytes: &[u8]) -> Result<SmallwoodProof> {
    bincode::deserialize(bytes).context("deserialize Smallwood proof")
}

/// Convert a [`SmallwoodProof`] into a [`CapssSignature`], preserving canonical encoding.
pub fn proof_to_signature(proof: SmallwoodProof) -> Result<CapssSignature> {
    let bytes = encode_proof(&proof)?;
    Ok(CapssSignature {
        proof: CapssProof { bytes },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::CapssConfig,
        smallwood,
        types::{CapssPublicKey, CapssStatement},
    };

    #[test]
    fn roundtrip_encode_decode() {
        let cfg = CapssConfig::default();
        let smallwood_cfg = cfg.smallwood_config();
        let statement = CapssStatement {
            public_key: CapssPublicKey::default(),
            message: b"testing-capss".to_vec(),
        };
        let proof = smallwood::prove(&smallwood_cfg, &statement).expect("prove");
        let encoded = encode_proof(&proof).expect("encode");
        let decoded = decode_proof(&encoded).expect("decode");
        assert_eq!(decoded, proof);
    }
}
