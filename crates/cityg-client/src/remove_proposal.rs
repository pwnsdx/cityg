//! Signed removal proposals (audit C-03, proposal P-3.c).
//!
//! A member never authors the barrier update that revokes itself: a departing
//! member would otherwise pick the post-revocation `K_barrier`. Instead it
//! signs a [`RemoveProposal`]; the server records it and another member commits
//! the revocation. A room admin may sign a proposal for another member.
//!
//! Wire form (deterministic CBOR array):
//! `["city-g/remove/v1", gid, target_leaf_id, target_slot_index,
//!   target_slot_generation, not_after_ms, signer_public_key, signature]`.
//! The signature is FIPS 204 ML-DSA-87 with context `city-g/remove/v1` over
//! the CBOR array of the first six elements.

use anyhow::{Context as AnyhowContext, Result, anyhow};
use cityg_pqc::SignatureContext;
use msphf_core::serde_utils::to_cbor_vec;
use msphf_orchestrator::{LeafIdMode, compute_leaf_id};
use serde::{Deserialize, Serialize};

pub const REMOVE_PROPOSAL_LABEL: &str = "city-g/remove/v1";
/// Longest lifetime a proposal may request (7 days).
pub const MAX_REMOVE_PROPOSAL_LIFETIME_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// Upper bound on the encoded size of a signed proposal.
pub const MAX_SIGNED_REMOVE_PROPOSAL_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoveProposal {
    pub gid: [u8; 32],
    pub target_leaf_id: [u8; 32],
    pub target_slot_index: u32,
    pub target_slot_generation: u64,
    pub not_after_ms: u64,
}

#[derive(Serialize)]
struct RemoveProposalTbs<'a>(
    &'a str,
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    #[serde(with = "serde_bytes")] &'a [u8; 32],
    u32,
    u64,
    u64,
);

#[derive(Serialize, Deserialize)]
struct SignedRemoveProposalWire(
    String,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    u32,
    u64,
    u64,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] Vec<u8>,
);

impl RemoveProposal {
    /// Bytes covered by the signature.
    pub fn to_be_signed(&self) -> Result<Vec<u8>> {
        to_cbor_vec(&RemoveProposalTbs(
            REMOVE_PROPOSAL_LABEL,
            &self.gid,
            &self.target_leaf_id,
            self.target_slot_index,
            self.target_slot_generation,
            self.not_after_ms,
        ))
        .map_err(|err| anyhow!("encode remove proposal: {err}"))
    }

    /// Whether the proposal is still valid at `now_ms`.
    #[must_use]
    pub fn is_live_at(&self, now_ms: u64) -> bool {
        now_ms <= self.not_after_ms
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRemoveProposal {
    pub proposal: RemoveProposal,
    pub signer_public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SignedRemoveProposal {
    /// Sign `proposal` with a serialized ML-DSA-87 secret key.
    pub fn sign(
        proposal: RemoveProposal,
        signer_public_key: &[u8],
        signer_secret_key: &[u8],
    ) -> Result<Self> {
        let secret_key = cityg_pqc::SecretKey::from_bytes(signer_secret_key)
            .map_err(|_| anyhow!("invalid ML-DSA-87 secret key"))?;
        if secret_key.public_key() != signer_public_key {
            return Err(anyhow!(
                "remove proposal signer public key does not match its secret key"
            ));
        }
        let signature = cityg_pqc::sign(
            &secret_key,
            SignatureContext::REMOVE_PROPOSAL,
            &proposal.to_be_signed()?,
        )
        .map_err(|err| anyhow!("sign remove proposal: {err}"))?;
        Ok(Self {
            proposal,
            signer_public_key: signer_public_key.to_vec(),
            signature,
        })
    }

    /// Check the signature under `signer_public_key`.
    pub fn verify_signature(&self) -> Result<()> {
        cityg_pqc::verify(
            &self.signer_public_key,
            SignatureContext::REMOVE_PROPOSAL,
            &self.proposal.to_be_signed()?,
            &self.signature,
        )
        .map_err(|err| anyhow!("remove proposal signature rejected: {err}"))
    }

    /// Leaf identifier of the signer in this group.
    pub fn signer_leaf_id(&self) -> Result<[u8; 32]> {
        compute_leaf_id(
            LeafIdMode::PerGroup,
            &self.proposal.gid,
            cityg_pqc::SIGNATURE_ALGORITHM,
            &self.signer_public_key,
        )
        .map_err(|err| anyhow!("derive remove proposal signer leaf: {err}"))
    }

    /// True when the target signed its own removal (voluntary leave).
    pub fn is_signed_by_target(&self) -> Result<bool> {
        Ok(self.signer_leaf_id()? == self.proposal.target_leaf_id)
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        to_cbor_vec(&SignedRemoveProposalWire(
            REMOVE_PROPOSAL_LABEL.to_string(),
            self.proposal.gid.to_vec(),
            self.proposal.target_leaf_id.to_vec(),
            self.proposal.target_slot_index,
            self.proposal.target_slot_generation,
            self.proposal.not_after_ms,
            self.signer_public_key.clone(),
            self.signature.clone(),
        ))
        .map_err(|err| anyhow!("encode signed remove proposal: {err}"))
    }

    /// Decode deterministic CBOR; the label and field sizes are checked, the
    /// signature is not (call [`Self::verify_signature`]).
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_SIGNED_REMOVE_PROPOSAL_BYTES {
            return Err(anyhow!("signed remove proposal too large"));
        }
        let wire: SignedRemoveProposalWire =
            ciborium::de::from_reader(bytes).context("decode signed remove proposal")?;
        let canonical = to_cbor_vec(&wire).map_err(|err| anyhow!("re-encode proposal: {err}"))?;
        if canonical != bytes {
            return Err(anyhow!("signed remove proposal is not deterministic CBOR"));
        }
        let SignedRemoveProposalWire(
            label,
            gid,
            target_leaf_id,
            target_slot_index,
            target_slot_generation,
            not_after_ms,
            signer_public_key,
            signature,
        ) = wire;
        if label != REMOVE_PROPOSAL_LABEL {
            return Err(anyhow!("unexpected remove proposal label"));
        }
        if !cityg_pqc::is_public_key_length(&signer_public_key) {
            return Err(anyhow!(
                "remove proposal signer public key has the wrong length"
            ));
        }
        if !cityg_pqc::is_signature_length(&signature) {
            return Err(anyhow!("remove proposal signature has the wrong length"));
        }
        Ok(Self {
            proposal: RemoveProposal {
                gid: array32(&gid, "gid")?,
                target_leaf_id: array32(&target_leaf_id, "target_leaf_id")?,
                target_slot_index,
                target_slot_generation,
                not_after_ms,
            },
            signer_public_key,
            signature,
        })
    }
}

fn array32(bytes: &[u8], field: &str) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("remove proposal {field} must be 32 bytes"))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn member() -> (Vec<u8>, Vec<u8>) {
        let (public_key, secret_key) = cityg_pqc::test_utils::keypair();
        (public_key, secret_key.to_bytes())
    }

    fn proposal_for(gid: [u8; 32], public_key: &[u8]) -> Result<RemoveProposal> {
        let target_leaf_id = compute_leaf_id(
            LeafIdMode::PerGroup,
            &gid,
            cityg_pqc::SIGNATURE_ALGORITHM,
            public_key,
        )?;
        Ok(RemoveProposal {
            gid,
            target_leaf_id,
            target_slot_index: 3,
            target_slot_generation: 2,
            not_after_ms: 1_000,
        })
    }

    #[test]
    fn self_signed_proposal_round_trips_and_verifies() -> Result<()> {
        let (public_key, secret_key) = member();
        let proposal = proposal_for([7u8; 32], &public_key)?;
        let signed = SignedRemoveProposal::sign(proposal, &public_key, &secret_key)?;
        signed.verify_signature()?;
        assert!(signed.is_signed_by_target()?);

        let bytes = signed.to_cbor()?;
        let decoded = SignedRemoveProposal::from_cbor(&bytes)?;
        assert_eq!(decoded, signed);
        decoded.verify_signature()?;
        assert!(decoded.proposal.is_live_at(1_000));
        assert!(!decoded.proposal.is_live_at(1_001));
        Ok(())
    }

    #[test]
    fn tampered_or_foreign_proposals_are_rejected() -> Result<()> {
        let (public_key, secret_key) = member();
        let (other_public_key, other_secret_key) = member();
        let proposal = proposal_for([9u8; 32], &public_key)?;

        let mut signed = SignedRemoveProposal::sign(proposal, &public_key, &secret_key)?;
        signed.proposal.target_slot_generation += 1;
        assert!(signed.verify_signature().is_err(), "tampered field");

        let foreign = SignedRemoveProposal::sign(proposal, &other_public_key, &other_secret_key)?;
        foreign.verify_signature()?;
        assert!(!foreign.is_signed_by_target()?, "signed by another member");

        assert!(
            SignedRemoveProposal::sign(proposal, &other_public_key, &secret_key).is_err(),
            "mismatched key pair"
        );

        let message_signature = cityg_pqc::sign(
            &cityg_pqc::SecretKey::from_bytes(&secret_key).map_err(|e| anyhow!("{e}"))?,
            SignatureContext::MESSAGE,
            &proposal.to_be_signed()?,
        )
        .map_err(|e| anyhow!("{e}"))?;
        let cross_context = SignedRemoveProposal {
            proposal,
            signer_public_key: public_key.clone(),
            signature: message_signature,
        };
        assert!(
            cross_context.verify_signature().is_err(),
            "a message-context signature must not authorize a removal"
        );
        Ok(())
    }

    #[test]
    fn malformed_encodings_are_rejected() -> Result<()> {
        let (public_key, secret_key) = member();
        let signed = SignedRemoveProposal::sign(
            proposal_for([1u8; 32], &public_key)?,
            &public_key,
            &secret_key,
        )?;
        let mut bytes = signed.to_cbor()?;
        assert!(SignedRemoveProposal::from_cbor(&bytes[..bytes.len() - 1]).is_err());

        let wrong_label = to_cbor_vec(&SignedRemoveProposalWire(
            "city-g/remove/v0".to_string(),
            vec![1; 32],
            vec![2; 32],
            0,
            0,
            0,
            signed.signer_public_key.clone(),
            signed.signature.clone(),
        ))
        .map_err(|e| anyhow!("{e}"))?;
        assert!(SignedRemoveProposal::from_cbor(&wrong_label).is_err());

        let short_gid = to_cbor_vec(&SignedRemoveProposalWire(
            REMOVE_PROPOSAL_LABEL.to_string(),
            vec![1; 31],
            vec![2; 32],
            0,
            0,
            0,
            signed.signer_public_key.clone(),
            signed.signature.clone(),
        ))
        .map_err(|e| anyhow!("{e}"))?;
        assert!(SignedRemoveProposal::from_cbor(&short_gid).is_err());

        let short_key = to_cbor_vec(&SignedRemoveProposalWire(
            REMOVE_PROPOSAL_LABEL.to_string(),
            vec![1; 32],
            vec![2; 32],
            0,
            0,
            0,
            vec![0; 5],
            signed.signature.clone(),
        ))
        .map_err(|e| anyhow!("{e}"))?;
        assert!(SignedRemoveProposal::from_cbor(&short_key).is_err());

        let short_signature = to_cbor_vec(&SignedRemoveProposalWire(
            REMOVE_PROPOSAL_LABEL.to_string(),
            vec![1; 32],
            vec![2; 32],
            0,
            0,
            0,
            signed.signer_public_key.clone(),
            vec![0; 5],
        ))
        .map_err(|e| anyhow!("{e}"))?;
        assert!(SignedRemoveProposal::from_cbor(&short_signature).is_err());

        assert!(SignedRemoveProposal::from_cbor(&vec![0u8; 9 * 1024]).is_err());
        bytes.push(0);
        assert!(
            SignedRemoveProposal::from_cbor(&bytes).is_err(),
            "trailing bytes"
        );
        Ok(())
    }
}
