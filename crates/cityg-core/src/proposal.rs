//! Removal proposals (audit C-03, P-3.c).
//!
//! ```text
//! RemoveProposal       := ["city-g/remove/v3", gid, target_leaf, target_since,
//!                          proposer_device_pk]
//! SignedRemoveProposal := [RemoveProposal..., signature]
//!     signature := ML-DSA-65.Sign(proposer_sk, CBOR_det(RemoveProposal),
//!                                 ctx = "city-g/remove/v3")
//! proposal_ref := H_L("proposal-ref", [SignedRemoveProposal])
//! ```
//!
//! A proposal is authorized when its target occupancy `[target_leaf,
//! target_since]` is current and its proposer is the target itself (a
//! voluntary leave) or an admin. A target never authors the commit that
//! removes it: removals are committed by another member or by a joiner, so
//! a departing member never chooses the secrets of the epoch that excludes
//! it. The occupancy pair makes every proposal single use: no later occupant
//! of the leaf has the same `since`.

use ciborium::value::Value;
use cityg_pqc::SignatureContext;
use rand_core::CryptoRngCore;

use crate::cbor::{bytes, expect_bytes, expect_bytes32, expect_u32, expect_uint, text, uint};
use crate::error::{CoreError, CoreResult};
use crate::hash::{Digest, h_l};
use crate::identity::{DeviceIdentity, check_device_key};
use crate::registry::Membership;
use crate::signed::{open_signed, sign_fields};
use crate::tree::LeafNode;

/// Label (first field) of a removal proposal.
pub const REMOVE_PROPOSAL_LABEL: &str = "city-g/remove/v3";
/// Upper bound on an encoded signed proposal.
pub const MAX_REMOVE_PROPOSAL_BYTES: usize = 8 * 1024;

/// `proposal_ref := H_L("proposal-ref", [encoded])`: the name of a signed
/// removal proposal or join request.
pub fn proposal_ref(encoded: &[u8]) -> CoreResult<Digest> {
    h_l("proposal-ref", vec![bytes(encoded)])
}

/// Proposal to end the occupancy `[target_leaf, target_since]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoveProposal {
    pub gid: Digest,
    pub target_leaf: u32,
    pub target_since: u64,
    pub proposer_device_pk: Vec<u8>,
}

impl RemoveProposal {
    /// Sign the proposal with the proposer's identity.
    pub fn sign(
        self,
        identity: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<SignedRemoveProposal> {
        if identity.public_key() != self.proposer_device_pk {
            return Err(CoreError::Invalid(
                "proposer key does not match the identity",
            ));
        }
        let encoded = sign_fields(
            vec![
                text(REMOVE_PROPOSAL_LABEL),
                bytes(&self.gid),
                uint(u64::from(self.target_leaf)),
                uint(self.target_since),
                bytes(&self.proposer_device_pk),
            ],
            identity,
            SignatureContext::REMOVE_PROPOSAL,
            rng,
        )?;
        SignedRemoveProposal::decode(&encoded)
    }
}

/// A removal proposal whose signature verifies under its proposer key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRemoveProposal {
    proposal: RemoveProposal,
    encoded: Vec<u8>,
}

impl SignedRemoveProposal {
    /// Decode a signed proposal and verify its signature.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let opened = open_signed(
            encoded,
            REMOVE_PROPOSAL_LABEL,
            5,
            MAX_REMOVE_PROPOSAL_BYTES,
            "remove proposal",
        )?;
        let mut fields = opened.fields.iter().skip(1).cloned();
        let mut next = || -> CoreResult<Value> {
            fields.next().ok_or(CoreError::Malformed("remove proposal"))
        };
        let gid = expect_bytes32(next()?, "remove proposal gid")?;
        let target_leaf = expect_u32(&next()?, "remove proposal leaf")?;
        let target_since = expect_uint(&next()?, "remove proposal since")?;
        let proposer_device_pk = expect_bytes(next()?, "remove proposal proposer")?;
        check_device_key(&proposer_device_pk, "remove proposal proposer")?;
        opened.verify(
            &proposer_device_pk,
            SignatureContext::REMOVE_PROPOSAL,
            "remove proposal",
        )?;
        Ok(Self {
            proposal: RemoveProposal {
                gid,
                target_leaf,
                target_since,
                proposer_device_pk,
            },
            encoded: encoded.to_vec(),
        })
    }

    /// The proposal content.
    #[must_use]
    pub fn proposal(&self) -> &RemoveProposal {
        &self.proposal
    }

    /// Deterministic encoding (signature included).
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// `proposal_ref` of the proposal.
    pub fn reference(&self) -> CoreResult<Digest> {
        proposal_ref(&self.encoded)
    }

    /// Whether the proposer is the target (a voluntary leave).
    #[must_use]
    pub fn is_self_removal(&self, target: &LeafNode) -> bool {
        target.device_pk == self.proposal.proposer_device_pk
    }

    /// Check the proposal against the membership of group `gid`: the target
    /// occupancy is current and the proposer is the target or an admin.
    /// Returns the target's record.
    pub fn authorize<'a>(
        &self,
        gid: &Digest,
        membership: &Membership<'a>,
    ) -> CoreResult<&'a LeafNode> {
        let proposal = &self.proposal;
        if &proposal.gid != gid {
            return Err(CoreError::Invalid("remove proposal for another group"));
        }
        let target = membership
            .member(proposal.target_leaf, proposal.target_since)
            .ok_or(CoreError::Invalid("remove proposal target is not current"))?;
        if !self.is_self_removal(target) && !membership.is_admin_key(&proposal.proposer_device_pk) {
            return Err(CoreError::Unauthorized(
                "removal proposed by neither the target nor an admin",
            ));
        }
        Ok(target)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::kem::KemSecret;
    use crate::registry::Registry;
    use crate::tree::PublicTree;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn add(tree: &mut PublicTree, identity: &DeviceIdentity, since: u64, rng: &mut ChaCha20Rng) {
        let leaf = tree.entry_leaf().unwrap();
        tree.add_leaf(
            leaf,
            LeafNode {
                device_pk: identity.public_key().to_vec(),
                since,
                encryption_key: KemSecret::generate(rng).public_key(),
                admission_hash: [leaf as u8; 32],
            },
        )
        .unwrap();
    }

    fn proposal(gid: &Digest, leaf: u32, since: u64, proposer: &DeviceIdentity) -> RemoveProposal {
        RemoveProposal {
            gid: *gid,
            target_leaf: leaf,
            target_since: since,
            proposer_device_pk: proposer.public_key().to_vec(),
        }
    }

    #[test]
    fn leave_and_admin_removals_are_authorized() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let alice = DeviceIdentity::from_seed(&[1; 32]);
        let bob = DeviceIdentity::from_seed(&[2; 32]);
        let carol = DeviceIdentity::from_seed(&[3; 32]);
        let gid = [9; 32];
        let mut tree = PublicTree::new(4).unwrap();
        add(&mut tree, &alice, 0, &mut rng);
        add(&mut tree, &bob, 1, &mut rng);
        add(&mut tree, &carol, 2, &mut rng);
        let registry = Registry::genesis(4).unwrap();
        let membership = Membership::new(&tree, &registry);

        let leave = proposal(&gid, 1, 1, &bob).sign(&bob, &mut rng).unwrap();
        let bob_record = tree.leaf(1).unwrap();
        assert!(leave.is_self_removal(bob_record));
        assert_eq!(leave.authorize(&gid, &membership).unwrap(), bob_record);
        assert_eq!(
            SignedRemoveProposal::decode(leave.encoded()).unwrap(),
            leave
        );
        assert_ne!(leave.reference().unwrap(), proposal_ref(b"").unwrap());

        let by_admin = proposal(&gid, 1, 1, &alice).sign(&alice, &mut rng).unwrap();
        by_admin.authorize(&gid, &membership).unwrap();

        let by_peer = proposal(&gid, 1, 1, &carol).sign(&carol, &mut rng).unwrap();
        assert!(matches!(
            by_peer.authorize(&gid, &membership),
            Err(CoreError::Unauthorized(_))
        ));
        assert!(leave.authorize(&[8; 32], &membership).is_err());

        // A proposal names one occupancy: once it ends, or for another
        // occupant of the leaf, the proposal is stale.
        let stale = proposal(&gid, 1, 0, &alice).sign(&alice, &mut rng).unwrap();
        assert_eq!(
            stale.authorize(&gid, &membership),
            Err(CoreError::Invalid("remove proposal target is not current"))
        );
        tree.remove_leaf(1).unwrap();
        let membership = Membership::new(&tree, &registry);
        assert!(leave.authorize(&gid, &membership).is_err());
    }

    #[test]
    fn signatures_and_encodings_are_checked() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let alice = DeviceIdentity::from_seed(&[1; 32]);
        let bob = DeviceIdentity::from_seed(&[2; 32]);
        let gid = [9; 32];
        assert!(proposal(&gid, 1, 1, &bob).sign(&alice, &mut rng).is_err());
        let signed = proposal(&gid, 1, 1, &bob).sign(&bob, &mut rng).unwrap();
        let mut tampered = signed.encoded().to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(SignedRemoveProposal::decode(&tampered).is_err());
        assert!(SignedRemoveProposal::decode(&[0x80]).is_err());
        assert_eq!(signed.proposal().target_leaf, 1);
    }
}
