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
    let proof: SmallwoodProof =
        bincode::deserialize(bytes).context("deserialize Smallwood proof")?;
    let canonical = encode_proof(&proof).context("re-serialize canonical Smallwood proof")?;
    if canonical != bytes {
        anyhow::bail!("non-canonical Smallwood proof encoding");
    }
    Ok(proof)
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
    fn roundtrip_encode_decode() -> Result<(), Box<dyn std::error::Error>> {
        let cfg = CapssConfig::default();
        let smallwood_cfg = cfg.smallwood_config();
        let statement = CapssStatement {
            public_key: CapssPublicKey::default(),
            message: b"testing-capss".to_vec(),
        };
        let proof = smallwood::prove(&smallwood_cfg, &statement)?;
        let encoded = encode_proof(&proof)?;
        let decoded = decode_proof(&encoded)?;
        assert_eq!(decoded, proof);
        Ok(())
    }

    #[test]
    fn proof_to_signature_preserves_canonical_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let cfg = CapssConfig::default();
        let smallwood_cfg = cfg.smallwood_config();
        let statement = CapssStatement {
            public_key: CapssPublicKey::default(),
            message: b"capss-signature".to_vec(),
        };
        let proof = smallwood::prove(&smallwood_cfg, &statement)?;
        let signature = proof_to_signature(proof.clone())?;
        let decoded = decode_proof(&signature.proof.bytes)?;
        assert_eq!(decoded, proof);
        Ok(())
    }

    #[test]
    fn decode_proof_rejects_invalid_bytes() {
        let err = decode_proof(b"not-a-valid-proof");
        assert!(err.is_err(), "garbage proof bytes should fail decoding");
    }

    #[test]
    fn decode_proof_rejects_trailing_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let cfg = CapssConfig::default();
        let smallwood_cfg = cfg.smallwood_config();
        let statement = CapssStatement {
            public_key: CapssPublicKey::default(),
            message: b"capss-trailing".to_vec(),
        };
        let proof = smallwood::prove(&smallwood_cfg, &statement)?;
        let mut encoded = encode_proof(&proof)?;
        encoded.push(0);

        let err = decode_proof(&encoded);
        assert!(
            err.is_err(),
            "proof bytes with trailing garbage must fail canonical decode"
        );
        Ok(())
    }
}
