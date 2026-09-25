//! Admission of joining devices, verifiable by every member (audit H-01, P-4).
//!
//! ```text
//! Invite       := ["city-g/invite/v2", gid, invite_pk, expires_at_ms, max_uses,
//!                  inviter_device_pk]
//! SignedInvite := [Invite..., signature]       ctx "city-g/invite/v2",
//!                                              signed by the inviter (an admin)
//! invite_id    := H_L("invite-id", [invite_pk])
//!
//! Admission    := ["city-g/admission/v2", gid, device_id, not_after_epoch,
//!                  authorizer_kind, authorizer_pk, invite]
//! SignedAdmission := [Admission..., signature] ctx "city-g/admission/v2",
//!                                              signed by authorizer_pk
//!   authorizer_kind 0: authorizer_pk is an admin device key, invite = null
//!   authorizer_kind 1: authorizer_pk is the invite key, invite = SignedInvite
//! admission_hash := H(SignedAdmission)
//!
//! InviteRevocation := ["city-g/invite-revocation/v1", gid, invite_id, revoker_device_pk]
//!                     ctx "city-g/invite-revocation/v1", signed by an admin
//! ```
//!
//! An admin either signs an admission for a known device, or signs an invite
//! whose key pair derives from a 32-byte seed shared out of band (an invite
//! link); the joiner then signs its own admission with the invite key.
//! Members check an admission against the admins of the epoch the join
//! enters, so a delivery service cannot add a member on its own, and the tree
//! records each member's `admission_hash`.
//!
//! An admission is good for one occupancy: it names a last epoch
//! (`not_after_epoch`, at most `MAX_ADMISSION_EPOCHS` after the join epoch),
//! and the admission of an occupancy that ended by a removal is retired
//! until then. Invite expiry (a time), use count and revocation need a clock
//! or a global count and are enforced by the delivery service.

use ciborium::value::Value;
use cityg_pqc::SignatureContext;
use rand_core::CryptoRngCore;

use crate::cbor::{bytes, expect_bytes, expect_bytes32, expect_uint, text, uint};
use crate::error::{CoreError, CoreResult};
use crate::hash::{Digest, h, h_l};
use crate::identity::{DeviceIdentity, check_device_key};
use crate::registry::{MAX_ADMISSION_EPOCHS, Membership};
use crate::signed::{open_signed, sign_fields};

/// Label of an invite.
pub const INVITE_LABEL: &str = "city-g/invite/v2";
/// Label of an admission.
pub const ADMISSION_LABEL: &str = "city-g/admission/v2";
/// Label of an invite revocation.
pub const INVITE_REVOCATION_LABEL: &str = "city-g/invite-revocation/v1";
/// Upper bound on an encoded signed invite.
pub const MAX_INVITE_BYTES: usize = 8 * 1024;
/// Upper bound on an encoded signed admission.
pub const MAX_ADMISSION_BYTES: usize = 16 * 1024;
/// Upper bound on an encoded signed invite revocation.
pub const MAX_INVITE_REVOCATION_BYTES: usize = 8 * 1024;

/// `invite_id := H_L("invite-id", [invite_pk])`.
pub fn invite_id(invite_pk: &[u8]) -> CoreResult<Digest> {
    h_l("invite-id", vec![bytes(invite_pk)])
}

fn field<'a>(
    fields: &mut impl Iterator<Item = &'a Value>,
    what: &'static str,
) -> CoreResult<Value> {
    fields.next().cloned().ok_or(CoreError::Malformed(what))
}

/// Invitation delegating admission to the holder of an invite key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invite {
    pub gid: Digest,
    pub invite_pk: Vec<u8>,
    pub expires_at_ms: u64,
    /// Number of joins the delivery service lets the invite admit.
    pub max_uses: u64,
    pub inviter_device_pk: Vec<u8>,
}

impl Invite {
    /// New invite for the key pair derived from `invite_seed`.
    #[must_use]
    pub fn from_seed(
        gid: &Digest,
        invite_seed: &[u8; 32],
        expires_at_ms: u64,
        max_uses: u64,
        inviter_device_pk: &[u8],
    ) -> Self {
        Self {
            gid: *gid,
            invite_pk: DeviceIdentity::from_seed(invite_seed).public_key().to_vec(),
            expires_at_ms,
            max_uses,
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
                uint(self.max_uses),
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
        let opened = open_signed(encoded, INVITE_LABEL, 6, MAX_INVITE_BYTES, "invite")?;
        let mut fields = opened.fields.iter().skip(1);
        let gid = expect_bytes32(field(&mut fields, "invite")?, "invite gid")?;
        let invite_pk = expect_bytes(field(&mut fields, "invite")?, "invite key")?;
        check_device_key(&invite_pk, "invite key")?;
        let expires_at_ms = expect_uint(&field(&mut fields, "invite")?, "invite expiry")?;
        let max_uses = expect_uint(&field(&mut fields, "invite")?, "invite uses")?;
        if max_uses == 0 {
            return Err(CoreError::Invalid("invite without uses"));
        }
        let inviter_device_pk = expect_bytes(field(&mut fields, "invite")?, "inviter key")?;
        check_device_key(&inviter_device_pk, "inviter key")?;
        opened.verify(&inviter_device_pk, SignatureContext::INVITE, "invite")?;
        Ok(Self {
            invite: Invite {
                gid,
                invite_pk,
                expires_at_ms,
                max_uses,
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

    /// Check that the invite is for `gid` and that its inviter is an admin.
    pub fn authorize(&self, gid: &Digest, membership: &Membership<'_>) -> CoreResult<()> {
        if &self.invite.gid != gid {
            return Err(CoreError::Invalid("invite for another group"));
        }
        if !membership.is_admin_key(&self.invite.inviter_device_pk) {
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

/// A signed admission of the device `device_id` into `gid`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedAdmission {
    pub gid: Digest,
    pub device_id: Digest,
    /// Last epoch a join may use the admission in.
    pub not_after_epoch: u64,
    pub authorizer: Authorizer,
    encoded: Vec<u8>,
}

impl SignedAdmission {
    /// Admission signed directly by an admin.
    pub fn by_admin(
        gid: &Digest,
        device_id: &Digest,
        not_after_epoch: u64,
        admin: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let encoded = sign_fields(
            vec![
                text(ADMISSION_LABEL),
                bytes(gid),
                bytes(device_id),
                uint(not_after_epoch),
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
        device_id: &Digest,
        not_after_epoch: u64,
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
                bytes(device_id),
                uint(not_after_epoch),
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
            7,
            MAX_ADMISSION_BYTES,
            "admission",
        )?;
        let mut fields = opened.fields.iter().skip(1);
        let gid = expect_bytes32(field(&mut fields, "admission")?, "admission gid")?;
        let device_id = expect_bytes32(field(&mut fields, "admission")?, "admission device")?;
        let not_after_epoch =
            expect_uint(&field(&mut fields, "admission")?, "admission last epoch")?;
        let kind = expect_uint(
            &field(&mut fields, "admission")?,
            "admission authorizer kind",
        )?;
        let authorizer_pk = expect_bytes(field(&mut fields, "admission")?, "admission authorizer")?;
        check_device_key(&authorizer_pk, "admission authorizer")?;
        let authorizer = match (kind, field(&mut fields, "admission")?) {
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
            device_id,
            not_after_epoch,
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

    /// The invite the admission relies on, if any.
    #[must_use]
    pub fn invite(&self) -> Option<&SignedInvite> {
        match &self.authorizer {
            Authorizer::Admin { .. } => None,
            Authorizer::Invite(invite) => Some(invite),
        }
    }

    /// Check the admission of `device_id` into `gid` for a join entering the
    /// epoch `epoch`: the epoch is within the admission's validity, the
    /// admission was not retired and its last epoch is above the retired
    /// floor, and its authorizer is an admin of `membership`.
    pub fn authorize(
        &self,
        gid: &Digest,
        device_id: &Digest,
        epoch: u64,
        membership: &Membership<'_>,
    ) -> CoreResult<()> {
        if &self.gid != gid {
            return Err(CoreError::Invalid("admission for another group"));
        }
        if &self.device_id != device_id {
            return Err(CoreError::Invalid("admission for another device"));
        }
        if epoch > self.not_after_epoch
            || self.not_after_epoch > epoch.saturating_add(MAX_ADMISSION_EPOCHS)
        {
            return Err(CoreError::Invalid("admission outside its validity"));
        }
        if membership.registry.is_retired(&self.hash())
            || self.not_after_epoch <= membership.registry.retired_floor()
        {
            return Err(CoreError::Unauthorized("admission of a removed member"));
        }
        match &self.authorizer {
            Authorizer::Admin { device_pk } if membership.is_admin_key(device_pk) => Ok(()),
            Authorizer::Admin { .. } => Err(CoreError::Unauthorized("admitter is not an admin")),
            Authorizer::Invite(invite) => invite.authorize(gid, membership),
        }
    }
}

/// An admin's revocation of an invite (enforced by the delivery service).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedInviteRevocation {
    pub gid: Digest,
    pub invite_id: Digest,
    pub revoker_device_pk: Vec<u8>,
    encoded: Vec<u8>,
}

impl SignedInviteRevocation {
    /// Revocation of `invite_id`, signed by `admin`.
    pub fn sign(
        gid: &Digest,
        invite_id: &Digest,
        admin: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let encoded = sign_fields(
            vec![
                text(INVITE_REVOCATION_LABEL),
                bytes(gid),
                bytes(invite_id),
                bytes(admin.public_key()),
            ],
            admin,
            SignatureContext::INVITE_REVOCATION,
            rng,
        )?;
        Self::decode(&encoded)
    }

    /// Decode a revocation and verify its signature.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let opened = open_signed(
            encoded,
            INVITE_REVOCATION_LABEL,
            4,
            MAX_INVITE_REVOCATION_BYTES,
            "invite revocation",
        )?;
        let mut fields = opened.fields.iter().skip(1);
        let gid = expect_bytes32(field(&mut fields, "invite revocation")?, "revocation gid")?;
        let invite_id = expect_bytes32(
            field(&mut fields, "invite revocation")?,
            "revocation invite",
        )?;
        let revoker_device_pk =
            expect_bytes(field(&mut fields, "invite revocation")?, "revocation key")?;
        check_device_key(&revoker_device_pk, "revocation key")?;
        opened.verify(
            &revoker_device_pk,
            SignatureContext::INVITE_REVOCATION,
            "invite revocation",
        )?;
        Ok(Self {
            gid,
            invite_id,
            revoker_device_pk,
            encoded: encoded.to_vec(),
        })
    }

    /// Deterministic encoding (signature included).
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Check that the revocation is for `gid` and signed by an admin.
    pub fn authorize(&self, gid: &Digest, membership: &Membership<'_>) -> CoreResult<()> {
        if &self.gid != gid {
            return Err(CoreError::Invalid("invite revocation for another group"));
        }
        if !membership.is_admin_key(&self.revoker_device_pk) {
            return Err(CoreError::Unauthorized("revoker is not an admin"));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::identity::device_id;
    use crate::kem::KemSecret;
    use crate::registry::{MAX_RETIRED, Registry};
    use crate::tree::{LeafNode, PublicTree};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn setup(rng: &mut ChaCha20Rng) -> (Digest, DeviceIdentity, DeviceIdentity, PublicTree) {
        let alice = DeviceIdentity::from_seed(&[1; 32]);
        let bob = DeviceIdentity::from_seed(&[2; 32]);
        let gid = [7; 32];
        let mut tree = PublicTree::new(4).unwrap();
        for (leaf, identity) in [&alice, &bob].into_iter().enumerate() {
            tree.add_leaf(
                leaf as u32,
                LeafNode {
                    device_pk: identity.public_key().to_vec(),
                    since: 0,
                    encryption_key: KemSecret::generate(rng).public_key(),
                    admission_hash: [0; 32],
                },
            )
            .unwrap();
        }
        (gid, alice, bob, tree)
    }

    #[test]
    fn admin_admissions_are_checked_against_the_admins() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let (gid, alice, bob, tree) = setup(&mut rng);
        let registry = Registry::genesis(4).unwrap();
        let membership = Membership::new(&tree, &registry);
        let joiner = device_id(&gid, DeviceIdentity::from_seed(&[5; 32]).public_key()).unwrap();
        let admission = SignedAdmission::by_admin(&gid, &joiner, 10, &alice, &mut rng).unwrap();
        admission.authorize(&gid, &joiner, 3, &membership).unwrap();
        admission.authorize(&gid, &joiner, 10, &membership).unwrap();
        assert!(admission.invite().is_none());
        assert_eq!(
            SignedAdmission::decode(admission.encoded()).unwrap(),
            admission
        );
        assert_ne!(admission.hash(), [0; 32]);
        assert!(admission.authorize(&gid, &[6; 32], 3, &membership).is_err());
        assert!(
            admission
                .authorize(&[8; 32], &joiner, 3, &membership)
                .is_err()
        );
        // Outside its validity window.
        assert_eq!(
            admission.authorize(&gid, &joiner, 11, &membership),
            Err(CoreError::Invalid("admission outside its validity"))
        );
        let far = SignedAdmission::by_admin(&gid, &joiner, 5000, &alice, &mut rng).unwrap();
        assert!(far.authorize(&gid, &joiner, 3, &membership).is_err());
        far.authorize(&gid, &joiner, 5000 - MAX_ADMISSION_EPOCHS, &membership)
            .unwrap();

        let by_member = SignedAdmission::by_admin(&gid, &joiner, 10, &bob, &mut rng).unwrap();
        assert!(matches!(
            by_member.authorize(&gid, &joiner, 3, &membership),
            Err(CoreError::Unauthorized(_))
        ));

        // A retired admission cannot be used again.
        let mut retired = registry.clone();
        retired.retire(&admission.hash(), 2, 4);
        let membership = Membership::new(&tree, &retired);
        assert_eq!(
            admission.authorize(&gid, &joiner, 5, &membership),
            Err(CoreError::Unauthorized("admission of a removed member"))
        );

        // Not even once the list overflows: dropping its entry raised the
        // retired floor above its last epoch.
        for index in 0..MAX_RETIRED {
            let mut hash = [0xaa; 32];
            hash[..8].copy_from_slice(&(index as u64).to_be_bytes());
            retired.retire(&hash, 3, 4);
        }
        assert!(!retired.is_retired(&admission.hash()));
        let membership = Membership::new(&tree, &retired);
        assert_eq!(
            admission.authorize(&gid, &joiner, 5, &membership),
            Err(CoreError::Unauthorized("admission of a removed member"))
        );
        let not_after = retired.admission_not_after(5, 1024);
        assert_eq!(not_after, 2 + MAX_ADMISSION_EPOCHS + 1);
        SignedAdmission::by_admin(&gid, &joiner, not_after, &alice, &mut rng)
            .unwrap()
            .authorize(&gid, &joiner, 5, &membership)
            .unwrap();
    }

    #[test]
    fn invite_admissions_chain_to_an_admin() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let (gid, alice, bob, tree) = setup(&mut rng);
        let registry = Registry::genesis(4).unwrap();
        let membership = Membership::new(&tree, &registry);
        let seed = [42; 32];
        let invite = Invite::from_seed(&gid, &seed, 1_000, 3, alice.public_key())
            .sign(&alice, &mut rng)
            .unwrap();
        assert_eq!(
            invite.id().unwrap(),
            invite_id(&invite.invite().invite_pk).unwrap()
        );
        assert_eq!(invite.invite().max_uses, 3);
        assert_eq!(SignedInvite::decode(invite.encoded()).unwrap(), invite);
        let joiner = [5; 32];
        let admission =
            SignedAdmission::with_invite(&joiner, 20, &invite, &seed, &mut rng).unwrap();
        admission.authorize(&gid, &joiner, 1, &membership).unwrap();
        assert_eq!(admission.invite(), Some(&invite));
        assert!(SignedAdmission::with_invite(&joiner, 20, &invite, &[1; 32], &mut rng).is_err());

        // An invite signed by a non-admin does not authorize anything.
        let rogue = Invite::from_seed(&gid, &seed, 1_000, 1, bob.public_key())
            .sign(&bob, &mut rng)
            .unwrap();
        let rogue_admission =
            SignedAdmission::with_invite(&joiner, 20, &rogue, &seed, &mut rng).unwrap();
        assert!(
            rogue_admission
                .authorize(&gid, &joiner, 1, &membership)
                .is_err()
        );
        assert!(
            Invite::from_seed(&gid, &seed, 1, 1, alice.public_key())
                .sign(&bob, &mut rng)
                .is_err()
        );
        let other_group = Invite::from_seed(&[9; 32], &seed, 1, 1, alice.public_key())
            .sign(&alice, &mut rng)
            .unwrap();
        assert!(other_group.authorize(&gid, &membership).is_err());
        assert_eq!(
            Invite::from_seed(&gid, &seed, 1, 0, alice.public_key()).sign(&alice, &mut rng),
            Err(CoreError::Invalid("invite without uses"))
        );
    }

    #[test]
    fn revocations_are_signed_by_admins() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let (gid, alice, bob, tree) = setup(&mut rng);
        let registry = Registry::genesis(4).unwrap();
        let membership = Membership::new(&tree, &registry);
        let revocation = SignedInviteRevocation::sign(&gid, &[3; 32], &alice, &mut rng).unwrap();
        revocation.authorize(&gid, &membership).unwrap();
        assert_eq!(
            SignedInviteRevocation::decode(revocation.encoded()).unwrap(),
            revocation
        );
        assert!(revocation.authorize(&[1; 32], &membership).is_err());
        let by_member = SignedInviteRevocation::sign(&gid, &[3; 32], &bob, &mut rng).unwrap();
        assert_eq!(
            by_member.authorize(&gid, &membership),
            Err(CoreError::Unauthorized("revoker is not an admin"))
        );
        let mut tampered = revocation.encoded().to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(SignedInviteRevocation::decode(&tampered).is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let alice = DeviceIdentity::from_seed(&[1; 32]);
        let gid = [7; 32];
        let admission = SignedAdmission::by_admin(&gid, &[5; 32], 9, &alice, &mut rng).unwrap();
        let mut tampered = admission.encoded().to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(SignedAdmission::decode(&tampered).is_err());
        let invite = Invite::from_seed(&gid, &[1; 32], 5, 1, alice.public_key())
            .sign(&alice, &mut rng)
            .unwrap();
        let mut tampered = invite.encoded().to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(SignedInvite::decode(&tampered).is_err());
        assert!(SignedAdmission::decode(&[0x80]).is_err());
    }
}
