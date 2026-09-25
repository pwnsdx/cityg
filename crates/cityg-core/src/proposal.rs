//! Removal proposals (audit C-03, P-3.c).
//!
//! ```text
//! RemoveProposal       := ["city-g/remove/v2", gid, target_leaf_id,
//!                          target_slot, target_generation, proposer_device_pk]
//! SignedRemoveProposal := [RemoveProposal..., signature]
//!     signature := ML-DSA-87.Sign(proposer_sk, CBOR_det(RemoveProposal),
//!                                 ctx = "city-g/remove/v1")
//! ```
//!
//! A proposal is authorized when its proposer is the target itself (a
//! voluntary leave) or an admin of the roster it applies to. A target never
//! authors the commit that removes it: removals are committed by another
//! member (or by the next joiner once no member is left), so a departing
//! member never chooses the secrets of the epoch that excludes it.
//!
//! The `(target_slot, target_generation)` pair makes every proposal single
//! use: once the occupancy ends, the proposal no longer matches the roster.

use cityg_pqc::SignatureContext;
use rand_core::CryptoRngCore;

use crate::cbor::{bytes, expect_bytes, expect_bytes32, expect_u32, expect_uint, text, uint};
use crate::error::{CoreError, CoreResult};
use crate::hash::Digest;
use crate::identity::{DeviceIdentity, check_device_key};
use crate::roster::{MemberRecord, Roster};
use crate::signed::{open_signed, sign_fields};

/// Label (first field) of a removal proposal.
pub const REMOVE_PROPOSAL_LABEL: &str = "city-g/remove/v2";
/// Upper bound on an encoded signed proposal.
pub const MAX_REMOVE_PROPOSAL_BYTES: usize = 12 * 1024;

/// Proposal to end the occupancy `(target_slot, target_generation)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoveProposal {
    pub gid: Digest,
    pub target_leaf_id: Digest,
    pub target_slot: u32,
    pub target_generation: u64,
    pub proposer_device_pk: Vec<u8>,
}

impl RemoveProposal {
    /// Proposal targeting `member`, proposed by `proposer_device_pk`.
    #[must_use]
    pub fn for_member(gid: &Digest, member: &MemberRecord, proposer_device_pk: &[u8]) -> Self {
        Self {
            gid: *gid,
            target_leaf_id: member.leaf_id,
            target_slot: member.slot,
            target_generation: member.generation,
            proposer_device_pk: proposer_device_pk.to_vec(),
        }
    }

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
                bytes(&self.target_leaf_id),
                uint(u64::from(self.target_slot)),
                uint(self.target_generation),
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
            6,
            MAX_REMOVE_PROPOSAL_BYTES,
            "remove proposal",
        )?;
        let mut fields = opened.fields.iter().skip(1).cloned();
        let mut next = || fields.next().ok_or(CoreError::Malformed("remove proposal"));
        let gid = expect_bytes32(next()?, "remove proposal gid")?;
        let target_leaf_id = expect_bytes32(next()?, "remove proposal target")?;
        let target_slot = expect_u32(&next()?, "remove proposal slot")?;
        let target_generation = expect_uint(&next()?, "remove proposal generation")?;
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
                target_leaf_id,
                target_slot,
                target_generation,
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

    /// Whether the proposer is the target (a voluntary leave).
    #[must_use]
    pub fn is_self_removal(&self, target: &MemberRecord) -> bool {
        target.device_pk == self.proposal.proposer_device_pk
    }

    /// Check the proposal against `roster` of group `gid`: the target
    /// occupancy is current and the proposer is the target or an admin.
    /// Returns the target record.
    pub fn authorize<'a>(&self, gid: &Digest, roster: &'a Roster) -> CoreResult<&'a MemberRecord> {
        let proposal = &self.proposal;
        if &proposal.gid != gid {
            return Err(CoreError::Invalid("remove proposal for another group"));
        }
        let target = roster
            .member_in_slot(proposal.target_slot)
            .filter(|member| {
                member.generation == proposal.target_generation
                    && member.leaf_id == proposal.target_leaf_id
            })
            .ok_or(CoreError::Invalid("remove proposal target is not current"))?;
        if !self.is_self_removal(target) && !roster.is_admin(&proposal.proposer_device_pk) {
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
    use crate::identity::leaf_id;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn member(gid: &Digest, identity: &DeviceIdentity, slot: u32) -> MemberRecord {
        MemberRecord {
            leaf_id: leaf_id(gid, identity.public_key()).unwrap(),
            device_pk: identity.public_key().to_vec(),
            slot,
            generation: 1,
            admission_hash: [0; 32],
        }
    }

    #[test]
    fn leave_and_admin_removals_are_authorized() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let alice = DeviceIdentity::from_seed(&[1; 32]);
        let bob = DeviceIdentity::from_seed(&[2; 32]);
        let carol = DeviceIdentity::from_seed(&[3; 32]);
        let gid = [9; 32];
        let mut roster = Roster::genesis(&gid, alice.public_key()).unwrap();
        roster.add_member(member(&gid, &bob, 1)).unwrap();
        roster.add_member(member(&gid, &carol, 2)).unwrap();
        let bob_record = roster.member_in_slot(1).unwrap().clone();

        let leave = RemoveProposal::for_member(&gid, &bob_record, bob.public_key())
            .sign(&bob, &mut rng)
            .unwrap();
        assert!(leave.is_self_removal(&bob_record));
        assert_eq!(leave.authorize(&gid, &roster).unwrap(), &bob_record);
        assert_eq!(
            SignedRemoveProposal::decode(leave.encoded()).unwrap(),
            leave
        );

        let by_admin = RemoveProposal::for_member(&gid, &bob_record, alice.public_key())
            .sign(&alice, &mut rng)
            .unwrap();
        by_admin.authorize(&gid, &roster).unwrap();

        let by_peer = RemoveProposal::for_member(&gid, &bob_record, carol.public_key())
            .sign(&carol, &mut rng)
            .unwrap();
        assert!(matches!(
            by_peer.authorize(&gid, &roster),
            Err(CoreError::Unauthorized(_))
        ));
        assert!(leave.authorize(&[8; 32], &roster).is_err());

        // Once the occupancy ends the proposal is stale.
        roster.remove_member(1, 1).unwrap();
        assert!(leave.authorize(&gid, &roster).is_err());
        roster
            .add_member(MemberRecord {
                generation: 2,
                ..bob_record.clone()
            })
            .unwrap();
        assert!(leave.authorize(&gid, &roster).is_err(), "single use");
    }

    #[test]
    fn signatures_and_encodings_are_checked() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let alice = DeviceIdentity::from_seed(&[1; 32]);
        let bob = DeviceIdentity::from_seed(&[2; 32]);
        let gid = [9; 32];
        let record = member(&gid, &bob, 1);
        assert!(
            RemoveProposal::for_member(&gid, &record, bob.public_key())
                .sign(&alice, &mut rng)
                .is_err()
        );
        let signed = RemoveProposal::for_member(&gid, &record, bob.public_key())
            .sign(&bob, &mut rng)
            .unwrap();
        let mut tampered = signed.encoded().to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(SignedRemoveProposal::decode(&tampered).is_err());
        assert!(SignedRemoveProposal::decode(&[0x80]).is_err());
        assert_eq!(signed.proposal().target_slot, 1);
    }
}
