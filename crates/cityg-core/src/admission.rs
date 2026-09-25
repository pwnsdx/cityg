//! Admission of joining devices, verifiable by every member (audit H-01, P-4).
//!
//! ```text
//! Invite       := ["city-g/invite/v1", gid, invite_pk, expires_at_ms,
//!                  inviter_device_pk]
//! SignedInvite := [Invite..., signature]        ctx "city-g/invite/v1",
//!                                               signed by the inviter (an admin)
//! invite_id    := H_L("invite-id", [invite_pk])
//!
//! Admission    := ["city-g/admission/v1", gid, joiner_leaf_id,
//!                  authorizer_kind, authorizer_pk, invite]
//! SignedAdmission := [Admission..., signature]  ctx "city-g/admission/v1",
//!                                               signed by authorizer_pk
//!   authorizer_kind 0: authorizer_pk is an admin device key, invite = null
//!   authorizer_kind 1: authorizer_pk is the invite key, invite = SignedInvite
//! admission_hash := H(SignedAdmission)
//! ```
//!
//! An admin either signs an admission for a known joiner device, or signs an
//! invite whose key pair derives from a 32-byte seed shared out of band (an
//! invite link); the joiner then signs its own admission with the invite key.
//! Members check admissions against the admin set of the roster the join
//! commit applies to, so a server cannot add a member on its own; the roster
//! commits to each member's `admission_hash`. Invite expiry needs a clock and
//! is enforced by the delivery service.

use ciborium::value::Value;
use cityg_pqc::SignatureContext;
use rand_core::CryptoRngCore;

use crate::cbor::{bytes, expect_bytes, expect_bytes32, expect_uint, text, uint};
use crate::error::{CoreError, CoreResult};
use crate::hash::{Digest, h, h_l};
use crate::identity::{DeviceIdentity, check_device_key};
use crate::roster::Roster;
use crate::signed::{open_signed, sign_fields};

/// Label of an invite.
pub const INVITE_LABEL: &str = "city-g/invite/v1";
/// Label of an admission.
pub const ADMISSION_LABEL: &str = "city-g/admission/v1";
/// Upper bound on an encoded signed invite.
pub const MAX_INVITE_BYTES: usize = 16 * 1024;
/// Upper bound on an encoded signed admission.
pub const MAX_ADMISSION_BYTES: usize = 32 * 1024;

/// `invite_id := H_L("invite-id", [invite_pk])`.
pub fn invite_id(invite_pk: &[u8]) -> CoreResult<Digest> {
    h_l("invite-id", vec![bytes(invite_pk)])
}

/// Invitation delegating admission to the holder of an invite key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invite {
    pub gid: Digest,
    pub invite_pk: Vec<u8>,
    pub expires_at_ms: u64,
    pub inviter_device_pk: Vec<u8>,
}

impl Invite {
    /// New invite for the key pair derived from `invite_seed`.
    #[must_use]
    pub fn from_seed(
        gid: &Digest,
        invite_seed: &[u8; 32],
        expires_at_ms: u64,
        inviter_device_pk: &[u8],
    ) -> Self {
        Self {
            gid: *gid,
            invite_pk: DeviceIdentity::from_seed(invite_seed).public_key().to_vec(),
            expires_at_ms,
            inviter_device_pk: inviter_device_pk.to_vec(),
        }
    }

    /// Sign the invite with the inviter identity.
    pub fn sign(
        self,
        inviter: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<SignedInvite> {
        if inviter.public_key() != self.inviter_device_pk {
            return Err(CoreError::Invalid(
                "inviter key does not match the identity",
            ));
        }
        let encoded = sign_fields(
            vec![
                text(INVITE_LABEL),
                bytes(&self.gid),
                bytes(&self.invite_pk),
                uint(self.expires_at_ms),
                bytes(&self.inviter_device_pk),
            ],
            inviter,
            SignatureContext::INVITE,
            rng,
        )?;
        SignedInvite::decode(&encoded)
    }
}

/// An invite whose signature verifies under its inviter key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedInvite {
    invite: Invite,
    encoded: Vec<u8>,
}

impl SignedInvite {
    /// Decode a signed invite and verify its signature.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let opened = open_signed(encoded, INVITE_LABEL, 5, MAX_INVITE_BYTES, "invite")?;
        let mut fields = opened.fields.iter().skip(1).cloned();
        let mut next = || fields.next().ok_or(CoreError::Malformed("invite"));
        let gid = expect_bytes32(next()?, "invite gid")?;
        let invite_pk = expect_bytes(next()?, "invite key")?;
        check_device_key(&invite_pk, "invite key")?;
        let expires_at_ms = expect_uint(&next()?, "invite expiry")?;
        let inviter_device_pk = expect_bytes(next()?, "inviter key")?;
        check_device_key(&inviter_device_pk, "inviter key")?;
        opened.verify(&inviter_device_pk, SignatureContext::INVITE, "invite")?;
        Ok(Self {
            invite: Invite {
                gid,
                invite_pk,
                expires_at_ms,
                inviter_device_pk,
            },
            encoded: encoded.to_vec(),
        })
    }

    /// The invite content.
    #[must_use]
    pub fn invite(&self) -> &Invite {
        &self.invite
    }

    /// Deterministic encoding (signature included).
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// `invite_id` of the invite key.
    pub fn id(&self) -> CoreResult<Digest> {
        invite_id(&self.invite.invite_pk)
    }

    /// Check that the invite is for `gid` and that its inviter is an admin
    /// of `roster`.
    pub fn authorize(&self, gid: &Digest, roster: &Roster) -> CoreResult<()> {
        if &self.invite.gid != gid {
            return Err(CoreError::Invalid("invite for another group"));
        }
        if !roster.is_admin(&self.invite.inviter_device_pk) {
            return Err(CoreError::Unauthorized("inviter is not an admin"));
        }
        Ok(())
    }
}

/// Who authorized an admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Authorizer {
    /// An admin signed the admission directly.
    Admin { device_pk: Vec<u8> },
    /// The joiner signed with the key of an admin-signed invite.
    Invite(SignedInvite),
}

/// A signed admission of `joiner_leaf_id` into `gid`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedAdmission {
    pub gid: Digest,
    pub joiner_leaf_id: Digest,
    pub authorizer: Authorizer,
    encoded: Vec<u8>,
}

impl SignedAdmission {
    /// Admission signed directly by an admin.
    pub fn by_admin(
        gid: &Digest,
        joiner_leaf_id: &Digest,
        admin: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let encoded = sign_fields(
            vec![
                text(ADMISSION_LABEL),
                bytes(gid),
                bytes(joiner_leaf_id),
                uint(0),
                bytes(admin.public_key()),
                Value::Null,
            ],
            admin,
            SignatureContext::ADMISSION,
            rng,
        )?;
        Self::decode(&encoded)
    }

    /// Admission signed by the joiner with the invite key derived from
    /// `invite_seed`.
    pub fn with_invite(
        joiner_leaf_id: &Digest,
        invite: &SignedInvite,
        invite_seed: &[u8; 32],
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let invite_key = DeviceIdentity::from_seed(invite_seed);
        if invite_key.public_key() != invite.invite().invite_pk {
            return Err(CoreError::Invalid("invite seed does not match the invite"));
        }
        let encoded = sign_fields(
            vec![
                text(ADMISSION_LABEL),
                bytes(&invite.invite().gid),
                bytes(joiner_leaf_id),
                uint(1),
                bytes(invite_key.public_key()),
                bytes(invite.encoded()),
            ],
            &invite_key,
            SignatureContext::ADMISSION,
            rng,
        )?;
        Self::decode(&encoded)
    }

    /// Decode a signed admission and verify every signature it carries.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let opened = open_signed(
            encoded,
            ADMISSION_LABEL,
            6,
            MAX_ADMISSION_BYTES,
            "admission",
        )?;
        let mut fields = opened.fields.iter().skip(1).cloned();
        let mut next = || fields.next().ok_or(CoreError::Malformed("admission"));
        let gid = expect_bytes32(next()?, "admission gid")?;
        let joiner_leaf_id = expect_bytes32(next()?, "admission joiner")?;
        let kind = expect_uint(&next()?, "admission authorizer kind")?;
        let authorizer_pk = expect_bytes(next()?, "admission authorizer")?;
        check_device_key(&authorizer_pk, "admission authorizer")?;
        let invite = next()?;
        let authorizer = match (kind, invite) {
            (0, Value::Null) => Authorizer::Admin {
                device_pk: authorizer_pk.clone(),
            },
            (1, Value::Bytes(invite)) => {
                let invite = SignedInvite::decode(&invite)?;
                if invite.invite().invite_pk != authorizer_pk || invite.invite().gid != gid {
                    return Err(CoreError::Invalid("admission does not match its invite"));
                }
                Authorizer::Invite(invite)
            }
            _ => return Err(CoreError::Malformed("admission authorizer")),
        };
        opened.verify(&authorizer_pk, SignatureContext::ADMISSION, "admission")?;
        Ok(Self {
            gid,
            joiner_leaf_id,
            authorizer,
            encoded: encoded.to_vec(),
        })
    }

    /// Deterministic encoding (signatures included).
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// `admission_hash := H(SignedAdmission)`.
    #[must_use]
    pub fn hash(&self) -> Digest {
        h(&self.encoded)
    }

    /// Expiry of the invite the admission relies on, if any.
    #[must_use]
    pub fn expires_at_ms(&self) -> Option<u64> {
        match &self.authorizer {
            Authorizer::Admin { .. } => None,
            Authorizer::Invite(invite) => Some(invite.invite().expires_at_ms),
        }
    }

    /// Check the admission of `joiner_leaf_id` into `gid` against the admin
    /// set of `roster`.
    pub fn authorize(
        &self,
        gid: &Digest,
        joiner_leaf_id: &Digest,
        roster: &Roster,
    ) -> CoreResult<()> {
        if &self.gid != gid {
            return Err(CoreError::Invalid("admission for another group"));
        }
        if &self.joiner_leaf_id != joiner_leaf_id {
            return Err(CoreError::Invalid("admission for another device"));
        }
        match &self.authorizer {
            Authorizer::Admin { device_pk } if roster.is_admin(device_pk) => Ok(()),
            Authorizer::Admin { .. } => Err(CoreError::Unauthorized("admitter is not an admin")),
            Authorizer::Invite(invite) => invite.authorize(gid, roster),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::identity::leaf_id;
    use crate::roster::MemberRecord;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn setup() -> (Digest, DeviceIdentity, DeviceIdentity, Roster) {
        let alice = DeviceIdentity::from_seed(&[1; 32]);
        let bob = DeviceIdentity::from_seed(&[2; 32]);
        let gid = [7; 32];
        let mut roster = Roster::genesis(&gid, alice.public_key()).unwrap();
        roster
            .add_member(MemberRecord {
                leaf_id: leaf_id(&gid, bob.public_key()).unwrap(),
                device_pk: bob.public_key().to_vec(),
                slot: 1,
                generation: 1,
                admission_hash: [0; 32],
            })
            .unwrap();
        (gid, alice, bob, roster)
    }

    #[test]
    fn admin_admissions_are_checked_against_the_admin_set() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let (gid, alice, bob, roster) = setup();
        let joiner = [5; 32];
        let admission = SignedAdmission::by_admin(&gid, &joiner, &alice, &mut rng).unwrap();
        admission.authorize(&gid, &joiner, &roster).unwrap();
        assert_eq!(admission.expires_at_ms(), None);
        assert_eq!(
            SignedAdmission::decode(admission.encoded()).unwrap(),
            admission
        );
        assert_ne!(admission.hash(), [0; 32]);
        assert!(admission.authorize(&gid, &[6; 32], &roster).is_err());
        assert!(admission.authorize(&[8; 32], &joiner, &roster).is_err());

        let by_member = SignedAdmission::by_admin(&gid, &joiner, &bob, &mut rng).unwrap();
        assert!(matches!(
            by_member.authorize(&gid, &joiner, &roster),
            Err(CoreError::Unauthorized(_))
        ));
    }

    #[test]
    fn invite_admissions_chain_to_an_admin() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let (gid, alice, bob, roster) = setup();
        let seed = [42; 32];
        let invite = Invite::from_seed(&gid, &seed, 1_000, alice.public_key())
            .sign(&alice, &mut rng)
            .unwrap();
        assert_eq!(
            invite.id().unwrap(),
            invite_id(&invite.invite().invite_pk).unwrap()
        );
        assert_eq!(SignedInvite::decode(invite.encoded()).unwrap(), invite);
        let joiner = [5; 32];
        let admission = SignedAdmission::with_invite(&joiner, &invite, &seed, &mut rng).unwrap();
        admission.authorize(&gid, &joiner, &roster).unwrap();
        assert_eq!(admission.expires_at_ms(), Some(1_000));
        assert!(SignedAdmission::with_invite(&joiner, &invite, &[1; 32], &mut rng).is_err());

        // An invite signed by a non-admin does not authorize anything.
        let rogue = Invite::from_seed(&gid, &seed, 1_000, bob.public_key())
            .sign(&bob, &mut rng)
            .unwrap();
        let rogue_admission =
            SignedAdmission::with_invite(&joiner, &rogue, &seed, &mut rng).unwrap();
        assert!(rogue_admission.authorize(&gid, &joiner, &roster).is_err());
        assert!(
            Invite::from_seed(&gid, &seed, 1, alice.public_key())
                .sign(&bob, &mut rng)
                .is_err()
        );
        let other_group = Invite::from_seed(&[9; 32], &seed, 1, alice.public_key())
            .sign(&alice, &mut rng)
            .unwrap();
        assert!(other_group.authorize(&gid, &roster).is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let (gid, alice, _, _) = setup();
        let admission = SignedAdmission::by_admin(&gid, &[5; 32], &alice, &mut rng).unwrap();
        let mut tampered = admission.encoded().to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(SignedAdmission::decode(&tampered).is_err());
        let invite = Invite::from_seed(&gid, &[1; 32], 5, alice.public_key())
            .sign(&alice, &mut rng)
            .unwrap();
        let mut tampered = invite.encoded().to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(SignedInvite::decode(&tampered).is_err());
        assert!(SignedAdmission::decode(&[0x80]).is_err());
    }
}
