//! Signed objects of profile v0.4-draft (docs/specs-v0.4-draft.md section 6).
//!
//! ```text
//! Invite         := ["city-g/invite/v4", gid, invite_pk, expires_at_ms, max_uses,
//!                    inviter, inviter_pk]                         ctx INVITE, by the inviter
//! Admission      := ["city-g/admission/v4", gid, device_id, not_after_epoch, kind,
//!                    admin or null, authorizer_pk, invite or null] ctx ADMISSION
//!   kind 0: signed by admin `admin`, whose key is authorizer_pk
//!   kind 1: signed by the invite key authorizer_pk of the enclosed invite
//! JoinRequest    := ["city-g/join-request/v4", gid, device_pk, encryption_key,
//!                    init_key, not_after_epoch, admission or null] ctx JOIN_REQUEST, by the device
//! RemoveProposal := ["city-g/remove/v4", gid, target, proposer]   ctx REMOVE_PROPOSAL
//! Eviction       := ["city-g/eviction/v4", gid, target, policy_hash]   (unsigned)
//! GroupPolicy    := ["city-g/group-policy/v4", gid, admission, max_idle_epochs or null,
//!                    admin]                                       ctx GROUP_POLICY
//!   admission 0: closed (a join needs an admission), 1: open (any device)
//! UpdateRequest  := ["city-g/update/v4", gid, member, replaces, encryption_key]  ctx UPDATE_REQUEST
//! CatchUpRequest := ["city-g/catch-up/v4", gid, member, prev_interim, init_key]  ctx CATCH_UP
//! ReEntryRequest := ["city-g/re-entry/v4", gid, member, replaces, encryption_key,
//!                    init_key]                                    ctx RE_ENTRY
//! Checkpoint     := ["city-g/checkpoint/v4", gid, epoch, interim, tree_hash,
//!                    registry_hash, height, district_bits, external_pk_hash,
//!                    time_ms, admin]                              ctx CHECKPOINT
//! ```
//!
//! A group is *closed* unless the policy in force opens it. In a closed
//! group every join carries an admission signed by an admin or an invite;
//! in an open group a join may carry none: the device's own signature of
//! its request is enough, and the device is visible as a member like any
//! other.
//!
//! Members, admins and inviters are named by occupancy. `replaces` is
//! `H_L("kem-pk", [key])` of the leaf key an update or a re-entry replaces:
//! a request applies once, and cannot be replayed once the key changed.
//! `prev_interim` binds a catch-up request to the window that serves it.
//!
//! Decoding parses and checks lengths; signatures are checked by `verify`
//! methods, so that a party can place an entry without checking it (E-12).

use std::collections::BTreeMap;

use ciborium::value::Value;
use cityg_core::cbor::{bytes, decode, encode, expect_list, text, uint};
use cityg_core::error::{CoreError, CoreResult};
use cityg_core::hash::{Digest, h};
use cityg_core::identity::{DeviceIdentity, check_device_key};
use cityg_core::kem::validate_public_key;
use cityg_pqc::SignatureContext;
use rand_core::CryptoRngCore;

use crate::codec::{Signed, open_signed, open_unsigned, sign_fields};
use crate::crypto::{h_l, kem_pk_hash};
use crate::tree::Occupancy;

/// An admission names a last epoch at most this many epochs after the join.
pub const MAX_ADMISSION_EPOCHS: u64 = 1 << 16;
/// Upper bound on an encoded invite.
pub const MAX_INVITE_BYTES: usize = 12 * 1024;
/// Upper bound on an encoded admission.
pub const MAX_ADMISSION_BYTES: usize = 24 * 1024;
/// Upper bound on any other encoded request.
pub const MAX_REQUEST_BYTES: usize = 48 * 1024;

pub const INVITE_LABEL: &str = "city-g/invite/v4";
pub const ADMISSION_LABEL: &str = "city-g/admission/v4";
pub const JOIN_REQUEST_LABEL: &str = "city-g/join-request/v4";
pub const REMOVE_LABEL: &str = "city-g/remove/v4";
pub const EVICTION_LABEL: &str = "city-g/eviction/v4";
pub const POLICY_LABEL: &str = "city-g/group-policy/v4";
pub const UPDATE_LABEL: &str = "city-g/update/v4";
pub const CATCH_UP_LABEL: &str = "city-g/catch-up/v4";
pub const RE_ENTRY_LABEL: &str = "city-g/re-entry/v4";
pub const CHECKPOINT_LABEL: &str = "city-g/checkpoint/v4";

/// `gid := H_L("group-id", [creator_device_pk, nonce])`.
pub fn group_id(creator_pk: &[u8], nonce: &[u8; 32]) -> CoreResult<Digest> {
    h_l("group-id", vec![bytes(creator_pk), bytes(nonce)])
}

/// `device_id := H_L("device-id", [gid, device_pk])`.
pub fn device_id(gid: &Digest, device_pk: &[u8]) -> CoreResult<Digest> {
    h_l("device-id", vec![bytes(gid), bytes(device_pk)])
}

fn check_gid(found: &Digest, gid: &Digest, what: &'static str) -> CoreResult<()> {
    if found == gid {
        Ok(())
    } else {
        Err(CoreError::Invalid(what))
    }
}

/// An invite: an admin delegates admissions to the holder of an invite key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invite {
    pub gid: Digest,
    pub invite_pk: Vec<u8>,
    pub expires_at_ms: u64,
    pub max_uses: u64,
    pub inviter: Occupancy,
    pub inviter_pk: Vec<u8>,
    signed: Signed,
}

impl Invite {
    /// Sign an invite for the key derived from `invite_seed`.
    pub fn sign(
        gid: &Digest,
        invite_seed: &[u8; 32],
        expires_at_ms: u64,
        max_uses: u64,
        inviter: Occupancy,
        identity: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let invite_pk = DeviceIdentity::from_seed(invite_seed).public_key().to_vec();
        let signed = sign_fields(
            vec![
                text(INVITE_LABEL),
                bytes(gid),
                bytes(&invite_pk),
                uint(expires_at_ms),
                uint(max_uses),
                inviter.value(),
                bytes(identity.public_key()),
            ],
            identity,
            SignatureContext::INVITE,
            rng,
        )?;
        Self::decode(&signed.encoded)
    }

    /// Parse an invite.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let (mut fields, signed) =
            open_signed(encoded, INVITE_LABEL, 7, MAX_INVITE_BYTES, "invite")?;
        let invite = Self {
            gid: fields.digest()?,
            invite_pk: fields.bytes()?,
            expires_at_ms: fields.uint()?,
            max_uses: fields.uint()?,
            inviter: fields.occupancy()?,
            inviter_pk: fields.bytes()?,
            signed,
        };
        check_device_key(&invite.invite_pk, "invite key")?;
        check_device_key(&invite.inviter_pk, "inviter key")?;
        Ok(invite)
    }

    /// Encoded signed invite.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.signed.encoded
    }

    /// `invite_id := H_L("invite-id", [invite_pk])`.
    pub fn id(&self) -> CoreResult<Digest> {
        h_l("invite-id", vec![bytes(&self.invite_pk)])
    }

    /// Check the inviter's signature and that the inviter is an admin.
    pub fn verify(&self, gid: &Digest, admins: &BTreeMap<Occupancy, Vec<u8>>) -> CoreResult<()> {
        check_gid(&self.gid, gid, "invite group")?;
        if admins.get(&self.inviter) != Some(&self.inviter_pk) {
            return Err(CoreError::Unauthorized("inviter is not an admin"));
        }
        self.signed
            .verify(&self.inviter_pk, SignatureContext::INVITE, "invite")
    }
}

/// Who signed an admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Authorizer {
    /// An admin, by occupancy.
    Admin(Occupancy),
    /// The holder of an invite key.
    Invite(Box<Invite>),
}

/// Permission for one device to join once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admission {
    pub gid: Digest,
    pub device_id: Digest,
    pub not_after_epoch: u64,
    pub authorizer: Authorizer,
    pub authorizer_pk: Vec<u8>,
    signed: Signed,
}

impl Admission {
    fn sign_with(
        gid: &Digest,
        device_id: &Digest,
        not_after_epoch: u64,
        authorizer: &Authorizer,
        identity: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let (kind, admin, invite) = match authorizer {
            Authorizer::Admin(admin) => (0, admin.value(), Value::Null),
            Authorizer::Invite(invite) => (1, Value::Null, bytes(invite.encoded())),
        };
        let signed = sign_fields(
            vec![
                text(ADMISSION_LABEL),
                bytes(gid),
                bytes(device_id),
                uint(not_after_epoch),
                uint(kind),
                admin,
                bytes(identity.public_key()),
                invite,
            ],
            identity,
            SignatureContext::ADMISSION,
            rng,
        )?;
        Self::decode(&signed.encoded)
    }

    /// An admission signed by admin `admin`.
    pub fn by_admin(
        gid: &Digest,
        device_id: &Digest,
        not_after_epoch: u64,
        admin: Occupancy,
        identity: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        Self::sign_with(
            gid,
            device_id,
            not_after_epoch,
            &Authorizer::Admin(admin),
            identity,
            rng,
        )
    }

    /// An admission signed with the key of `invite`, derived from
    /// `invite_seed`.
    pub fn with_invite(
        invite: &Invite,
        invite_seed: &[u8; 32],
        device_id: &Digest,
        not_after_epoch: u64,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let key = DeviceIdentity::from_seed(invite_seed);
        if key.public_key() != invite.invite_pk {
            return Err(CoreError::Invalid("invite seed does not match the invite"));
        }
        Self::sign_with(
            &invite.gid,
            device_id,
            not_after_epoch,
            &Authorizer::Invite(Box::new(invite.clone())),
            &key,
            rng,
        )
    }

    /// Parse an admission.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let (mut fields, signed) = open_signed(
            encoded,
            ADMISSION_LABEL,
            8,
            MAX_ADMISSION_BYTES,
            "admission",
        )?;
        let gid = fields.digest()?;
        let device_id = fields.digest()?;
        let not_after_epoch = fields.uint()?;
        let kind = fields.uint()?;
        let admin = fields.optional_occupancy()?;
        let authorizer_pk = fields.bytes()?;
        let invite = fields.optional_bytes()?;
        check_device_key(&authorizer_pk, "admission authorizer key")?;
        let authorizer = match (kind, admin, invite) {
            (0, Some(admin), None) => Authorizer::Admin(admin),
            (1, None, Some(invite)) => {
                let invite = Invite::decode(&invite)?;
                if invite.invite_pk != authorizer_pk || invite.gid != gid {
                    return Err(CoreError::Invalid("admission invite"));
                }
                Authorizer::Invite(Box::new(invite))
            }
            _ => return Err(CoreError::Malformed("admission kind")),
        };
        Ok(Self {
            gid,
            device_id,
            not_after_epoch,
            authorizer,
            authorizer_pk,
            signed,
        })
    }

    /// Encoded signed admission.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.signed.encoded
    }

    /// `admission_hash := H(SignedAdmission)`.
    #[must_use]
    pub fn hash(&self) -> Digest {
        h(&self.signed.encoded)
    }

    /// The admin key a joiner anchors its entry on: the admin's, or the
    /// inviter's.
    #[must_use]
    pub fn anchor_key(&self) -> &[u8] {
        match &self.authorizer {
            Authorizer::Admin(_) => &self.authorizer_pk,
            Authorizer::Invite(invite) => &invite.inviter_pk,
        }
    }

    /// Check the admission for `device_id` joining at `epoch` under the
    /// admins `admins` of the previous epoch.
    pub fn verify(
        &self,
        gid: &Digest,
        device_id: &Digest,
        epoch: u64,
        admins: &BTreeMap<Occupancy, Vec<u8>>,
    ) -> CoreResult<()> {
        check_gid(&self.gid, gid, "admission group")?;
        if &self.device_id != device_id {
            return Err(CoreError::Invalid("admission device"));
        }
        if epoch > self.not_after_epoch
            || self.not_after_epoch > epoch.saturating_add(MAX_ADMISSION_EPOCHS)
        {
            return Err(CoreError::Invalid("admission expired or too long"));
        }
        match &self.authorizer {
            Authorizer::Admin(admin) => {
                if admins.get(admin) != Some(&self.authorizer_pk) {
                    return Err(CoreError::Unauthorized("admission signer is not an admin"));
                }
            }
            Authorizer::Invite(invite) => invite.verify(gid, admins)?,
        }
        self.signed.verify(
            &self.authorizer_pk,
            SignatureContext::ADMISSION,
            "admission",
        )
    }
}

/// A device's request to join.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinRequest {
    pub gid: Digest,
    pub device_pk: Vec<u8>,
    pub encryption_key: Vec<u8>,
    pub init_key: Vec<u8>,
    /// Last epoch the request may enter.
    pub not_after_epoch: u64,
    /// The admission; `None` for a join into an open group.
    pub admission: Option<Admission>,
    signed: Signed,
}

impl JoinRequest {
    /// Sign a join request, with an admission, or without one for an open
    /// group.
    pub fn sign(
        gid: &Digest,
        identity: &DeviceIdentity,
        encryption_key: &[u8],
        init_key: &[u8],
        not_after_epoch: u64,
        admission: Option<&Admission>,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let signed = sign_fields(
            vec![
                text(JOIN_REQUEST_LABEL),
                bytes(gid),
                bytes(identity.public_key()),
                bytes(encryption_key),
                bytes(init_key),
                uint(not_after_epoch),
                admission.map_or(Value::Null, |admission| bytes(admission.encoded())),
            ],
            identity,
            SignatureContext::JOIN_REQUEST,
            rng,
        )?;
        Self::decode(&signed.encoded)
    }

    /// Parse a join request.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let (mut fields, signed) = open_signed(
            encoded,
            JOIN_REQUEST_LABEL,
            7,
            MAX_REQUEST_BYTES,
            "join request",
        )?;
        let request = Self {
            gid: fields.digest()?,
            device_pk: fields.bytes()?,
            encryption_key: fields.bytes()?,
            init_key: fields.bytes()?,
            not_after_epoch: fields.uint()?,
            admission: fields
                .optional_bytes()?
                .map(|admission| Admission::decode(&admission))
                .transpose()?,
            signed,
        };
        check_device_key(&request.device_pk, "join request device key")?;
        validate_public_key(&request.encryption_key)?;
        validate_public_key(&request.init_key)?;
        if request.encryption_key == request.init_key {
            return Err(CoreError::Invalid("init key equals the leaf key"));
        }
        Ok(request)
    }

    /// Encoded signed request.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.signed.encoded
    }

    /// `H(encoded)`, which a change and a welcome name.
    #[must_use]
    pub fn reference(&self) -> Digest {
        h(&self.signed.encoded)
    }

    /// What the admission map records for this join, so that it applies
    /// once: the admission's hash, or the request's own for an open join.
    #[must_use]
    pub fn token(&self) -> Digest {
        self.admission
            .as_ref()
            .map_or_else(|| self.reference(), Admission::hash)
    }

    /// `device_id` of the joining device.
    pub fn device_id(&self) -> CoreResult<Digest> {
        device_id(&self.gid, &self.device_pk)
    }

    /// Check the device's signature and, for a join at `epoch`, the request's
    /// validity and its admission under the admins of the previous epoch. A
    /// join without admission is valid only if the group is `open`.
    pub fn verify(
        &self,
        gid: &Digest,
        epoch: u64,
        admins: &BTreeMap<Occupancy, Vec<u8>>,
        open: bool,
    ) -> CoreResult<()> {
        check_gid(&self.gid, gid, "join request group")?;
        if epoch > self.not_after_epoch
            || self.not_after_epoch > epoch.saturating_add(MAX_ADMISSION_EPOCHS)
        {
            return Err(CoreError::Invalid("join request expired or too long"));
        }
        self.signed.verify(
            &self.device_pk,
            SignatureContext::JOIN_REQUEST,
            "join request",
        )?;
        match &self.admission {
            Some(admission) => admission.verify(gid, &self.device_id()?, epoch, admins),
            None if open => Ok(()),
            None => Err(CoreError::Unauthorized(
                "join without admission in a closed group",
            )),
        }
    }
}

/// A proposal to remove a member, by an admin or by the member itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoveProposal {
    pub gid: Digest,
    pub target: Occupancy,
    pub proposer: Occupancy,
    signed: Signed,
}

impl RemoveProposal {
    /// Sign a removal proposal.
    pub fn sign(
        gid: &Digest,
        target: Occupancy,
        proposer: Occupancy,
        identity: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let signed = sign_fields(
            vec![
                text(REMOVE_LABEL),
                bytes(gid),
                target.value(),
                proposer.value(),
            ],
            identity,
            SignatureContext::REMOVE_PROPOSAL,
            rng,
        )?;
        Self::decode(&signed.encoded)
    }

    /// Parse a removal proposal.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let (mut fields, signed) = open_signed(
            encoded,
            REMOVE_LABEL,
            4,
            MAX_REQUEST_BYTES,
            "remove proposal",
        )?;
        Ok(Self {
            gid: fields.digest()?,
            target: fields.occupancy()?,
            proposer: fields.occupancy()?,
            signed,
        })
    }

    /// Encoded signed proposal.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.signed.encoded
    }

    /// Check that the proposer may remove the target and signed with
    /// `proposer_pk` (the admin key, or the target's own device key).
    pub fn verify(
        &self,
        gid: &Digest,
        admins: &BTreeMap<Occupancy, Vec<u8>>,
        target_pk: &[u8],
    ) -> CoreResult<()> {
        check_gid(&self.gid, gid, "remove proposal group")?;
        let key = if self.proposer == self.target {
            target_pk
        } else {
            admins
                .get(&self.proposer)
                .ok_or(CoreError::Unauthorized("proposer is not an admin"))?
        };
        self.signed
            .verify(key, SignatureContext::REMOVE_PROPOSAL, "remove proposal")
    }
}

/// An eviction by the delivery service under the group policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Eviction {
    pub gid: Digest,
    pub target: Occupancy,
    pub policy_hash: Digest,
    encoded: Vec<u8>,
}

impl Eviction {
    /// A new eviction.
    pub fn new(gid: &Digest, target: Occupancy, policy_hash: &Digest) -> CoreResult<Self> {
        let encoded = encode(&cityg_core::cbor::array(vec![
            text(EVICTION_LABEL),
            bytes(gid),
            target.value(),
            bytes(policy_hash),
        ]))?;
        Self::decode(&encoded)
    }

    /// Parse an eviction.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let mut fields = open_unsigned(encoded, EVICTION_LABEL, 4, MAX_REQUEST_BYTES, "eviction")?;
        Ok(Self {
            gid: fields.digest()?,
            target: fields.occupancy()?,
            policy_hash: fields.digest()?,
            encoded: encoded.to_vec(),
        })
    }

    /// Encoding.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Check the eviction of a member whose leaf key last changed at epoch
    /// `updated`, in a window creating epoch `epoch`.
    pub fn verify(
        &self,
        gid: &Digest,
        policy: &GroupPolicy,
        updated: u64,
        epoch: u64,
    ) -> CoreResult<()> {
        check_gid(&self.gid, gid, "eviction group")?;
        if policy.hash() != self.policy_hash {
            return Err(CoreError::Invalid("eviction policy"));
        }
        let max_idle = policy
            .max_idle_epochs
            .ok_or(CoreError::Invalid("the policy evicts nobody"))?;
        if epoch.saturating_sub(updated) <= max_idle {
            return Err(CoreError::Invalid("member not idle long enough"));
        }
        Ok(())
    }
}

/// The policy of a group, which an admin signs: whether the group is open
/// (a join needs no admission) and, if set, how long a member's leaf key
/// may stay unchanged before the delivery service may evict it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupPolicy {
    pub gid: Digest,
    pub open: bool,
    pub max_idle_epochs: Option<u64>,
    pub admin: Occupancy,
    signed: Signed,
}

impl GroupPolicy {
    /// Sign a policy.
    pub fn sign(
        gid: &Digest,
        open: bool,
        max_idle_epochs: Option<u64>,
        admin: Occupancy,
        identity: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let signed = sign_fields(
            vec![
                text(POLICY_LABEL),
                bytes(gid),
                uint(u64::from(open)),
                max_idle_epochs.map_or(Value::Null, uint),
                admin.value(),
            ],
            identity,
            SignatureContext::GROUP_POLICY,
            rng,
        )?;
        Self::decode(&signed.encoded)
    }

    /// Parse a policy.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let (mut fields, signed) =
            open_signed(encoded, POLICY_LABEL, 5, MAX_REQUEST_BYTES, "group policy")?;
        let gid = fields.digest()?;
        let open = match fields.uint()? {
            0 => false,
            1 => true,
            _ => return Err(CoreError::Malformed("group policy admission")),
        };
        let max_idle_epochs = fields
            .optional()?
            .map(|value| cityg_core::cbor::expect_uint(&value, "group policy"))
            .transpose()?;
        Ok(Self {
            gid,
            open,
            max_idle_epochs,
            admin: fields.occupancy()?,
            signed,
        })
    }

    /// Encoded signed policy.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.signed.encoded
    }

    /// `H(SignedGroupPolicy)`.
    #[must_use]
    pub fn hash(&self) -> Digest {
        h(&self.signed.encoded)
    }

    /// Check the signature under `admin_pk` (the creator's key at genesis).
    pub fn verify_signature(&self, gid: &Digest, admin_pk: &[u8]) -> CoreResult<()> {
        check_gid(&self.gid, gid, "group policy group")?;
        self.signed
            .verify(admin_pk, SignatureContext::GROUP_POLICY, "group policy")
    }

    /// Check that an admin of the previous epoch signed the policy.
    pub fn verify(&self, gid: &Digest, admins: &BTreeMap<Occupancy, Vec<u8>>) -> CoreResult<()> {
        let key = admins
            .get(&self.admin)
            .ok_or(CoreError::Unauthorized("policy signer is not an admin"))?;
        self.verify_signature(gid, key)
    }
}

/// A member's new leaf key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateRequest {
    pub gid: Digest,
    pub member: Occupancy,
    pub replaces: Digest,
    pub encryption_key: Vec<u8>,
    signed: Signed,
}

impl UpdateRequest {
    /// Sign an update replacing the leaf key `current_key`.
    pub fn sign(
        gid: &Digest,
        member: Occupancy,
        current_key: &[u8],
        encryption_key: &[u8],
        identity: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let signed = sign_fields(
            vec![
                text(UPDATE_LABEL),
                bytes(gid),
                member.value(),
                bytes(&kem_pk_hash(current_key)?),
                bytes(encryption_key),
            ],
            identity,
            SignatureContext::UPDATE_REQUEST,
            rng,
        )?;
        Self::decode(&signed.encoded)
    }

    /// Parse an update.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let (mut fields, signed) = open_signed(
            encoded,
            UPDATE_LABEL,
            5,
            MAX_REQUEST_BYTES,
            "update request",
        )?;
        let request = Self {
            gid: fields.digest()?,
            member: fields.occupancy()?,
            replaces: fields.digest()?,
            encryption_key: fields.bytes()?,
            signed,
        };
        validate_public_key(&request.encryption_key)?;
        Ok(request)
    }

    /// Encoded signed request.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.signed.encoded
    }

    /// Check the member's signature with its device key `device_pk`.
    pub fn verify(&self, gid: &Digest, device_pk: &[u8]) -> CoreResult<()> {
        check_gid(&self.gid, gid, "update request group")?;
        self.signed.verify(
            device_pk,
            SignatureContext::UPDATE_REQUEST,
            "update request",
        )
    }
}

/// A returning member's request for a welcome into the next window (a jump).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatchUpRequest {
    pub gid: Digest,
    pub member: Occupancy,
    pub prev_interim: Digest,
    pub init_key: Vec<u8>,
    signed: Signed,
}

impl CatchUpRequest {
    /// Sign a catch-up request for the window that follows the epoch whose
    /// interim transcript hash is `prev_interim`.
    pub fn sign(
        gid: &Digest,
        member: Occupancy,
        prev_interim: &Digest,
        init_key: &[u8],
        identity: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let signed = sign_fields(
            vec![
                text(CATCH_UP_LABEL),
                bytes(gid),
                member.value(),
                bytes(prev_interim),
                bytes(init_key),
            ],
            identity,
            SignatureContext::CATCH_UP,
            rng,
        )?;
        Self::decode(&signed.encoded)
    }

    /// Parse a catch-up request.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let (mut fields, signed) = open_signed(
            encoded,
            CATCH_UP_LABEL,
            5,
            MAX_REQUEST_BYTES,
            "catch-up request",
        )?;
        let request = Self {
            gid: fields.digest()?,
            member: fields.occupancy()?,
            prev_interim: fields.digest()?,
            init_key: fields.bytes()?,
            signed,
        };
        validate_public_key(&request.init_key)?;
        Ok(request)
    }

    /// Encoded signed request.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.signed.encoded
    }

    /// `H(encoded)`, which its welcome names.
    #[must_use]
    pub fn reference(&self) -> Digest {
        h(&self.signed.encoded)
    }

    /// Check the member's signature and that the request is for the window
    /// that follows `prev_interim`.
    pub fn verify(&self, gid: &Digest, prev_interim: &Digest, device_pk: &[u8]) -> CoreResult<()> {
        check_gid(&self.gid, gid, "catch-up request group")?;
        if &self.prev_interim != prev_interim {
            return Err(CoreError::Invalid("catch-up request for another window"));
        }
        self.signed
            .verify(device_pk, SignatureContext::CATCH_UP, "catch-up request")
    }
}

/// A returning member's new leaf key and one-time init key: it re-enters
/// its own leaf, and seals the window itself when nobody is online.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReEntryRequest {
    pub gid: Digest,
    pub member: Occupancy,
    pub replaces: Digest,
    pub encryption_key: Vec<u8>,
    pub init_key: Vec<u8>,
    signed: Signed,
}

impl ReEntryRequest {
    /// Sign a re-entry replacing the leaf key `current_key`.
    pub fn sign(
        gid: &Digest,
        member: Occupancy,
        current_key: &[u8],
        encryption_key: &[u8],
        init_key: &[u8],
        identity: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let signed = sign_fields(
            vec![
                text(RE_ENTRY_LABEL),
                bytes(gid),
                member.value(),
                bytes(&kem_pk_hash(current_key)?),
                bytes(encryption_key),
                bytes(init_key),
            ],
            identity,
            SignatureContext::RE_ENTRY,
            rng,
        )?;
        Self::decode(&signed.encoded)
    }

    /// Parse a re-entry request.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let (mut fields, signed) = open_signed(
            encoded,
            RE_ENTRY_LABEL,
            6,
            MAX_REQUEST_BYTES,
            "re-entry request",
        )?;
        let request = Self {
            gid: fields.digest()?,
            member: fields.occupancy()?,
            replaces: fields.digest()?,
            encryption_key: fields.bytes()?,
            init_key: fields.bytes()?,
            signed,
        };
        validate_public_key(&request.encryption_key)?;
        validate_public_key(&request.init_key)?;
        if request.encryption_key == request.init_key {
            return Err(CoreError::Invalid("init key equals the leaf key"));
        }
        Ok(request)
    }

    /// Encoded signed request.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.signed.encoded
    }

    /// `H(encoded)`, which a change and a welcome name.
    #[must_use]
    pub fn reference(&self) -> Digest {
        h(&self.signed.encoded)
    }

    /// Check the member's signature with its device key `device_pk`.
    pub fn verify(&self, gid: &Digest, device_pk: &[u8]) -> CoreResult<()> {
        check_gid(&self.gid, gid, "re-entry request group")?;
        self.signed
            .verify(device_pk, SignatureContext::RE_ENTRY, "re-entry request")
    }
}

/// What an admin states of an epoch in a checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointContent {
    pub epoch: u64,
    pub interim: Digest,
    pub tree_hash: Digest,
    pub registry_hash: Digest,
    pub height: u8,
    pub district_bits: u8,
    pub external_pk_hash: Digest,
    pub time_ms: u64,
}

/// An admin's signed statement of an epoch, which joiners anchor on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub gid: Digest,
    pub content: CheckpointContent,
    pub admin: Occupancy,
    signed: Signed,
}

impl Checkpoint {
    /// Sign a checkpoint.
    pub fn sign(
        gid: &Digest,
        content: &CheckpointContent,
        admin: Occupancy,
        identity: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let signed = sign_fields(
            vec![
                text(CHECKPOINT_LABEL),
                bytes(gid),
                uint(content.epoch),
                bytes(&content.interim),
                bytes(&content.tree_hash),
                bytes(&content.registry_hash),
                uint(u64::from(content.height)),
                uint(u64::from(content.district_bits)),
                bytes(&content.external_pk_hash),
                uint(content.time_ms),
                admin.value(),
            ],
            identity,
            SignatureContext::CHECKPOINT,
            rng,
        )?;
        Self::decode(&signed.encoded)
    }

    /// Parse a checkpoint.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let (mut fields, signed) = open_signed(
            encoded,
            CHECKPOINT_LABEL,
            11,
            MAX_REQUEST_BYTES,
            "checkpoint",
        )?;
        let gid = fields.digest()?;
        let content = CheckpointContent {
            epoch: fields.uint()?,
            interim: fields.digest()?,
            tree_hash: fields.digest()?,
            registry_hash: fields.digest()?,
            height: fields.u8()?,
            district_bits: fields.u8()?,
            external_pk_hash: fields.digest()?,
            time_ms: fields.uint()?,
        };
        Ok(Self {
            gid,
            content,
            admin: fields.occupancy()?,
            signed,
        })
    }

    /// Encoded signed checkpoint.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.signed.encoded
    }

    /// Check the signature under the admin key `admin_pk`.
    pub fn verify(&self, gid: &Digest, admin_pk: &[u8]) -> CoreResult<()> {
        check_gid(&self.gid, gid, "checkpoint group")?;
        self.signed
            .verify(admin_pk, SignatureContext::CHECKPOINT, "checkpoint")
    }
}

/// Kind of a change in a district commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ChangeKind {
    Removal = 0,
    Eviction = 1,
    Join = 2,
    Update = 3,
    ReEntry = 4,
}

impl ChangeKind {
    /// Wire value.
    #[must_use]
    pub const fn code(self) -> u64 {
        self as u64
    }

    /// From the wire value.
    pub fn from_code(code: u64) -> CoreResult<Self> {
        Ok(match code {
            0 => Self::Removal,
            1 => Self::Eviction,
            2 => Self::Join,
            3 => Self::Update,
            4 => Self::ReEntry,
            _ => return Err(CoreError::Malformed("change kind")),
        })
    }
}

/// An entry of a window: what a district commit's change refers to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Join(JoinRequest),
    Removal(RemoveProposal),
    Eviction(Eviction),
    Update(UpdateRequest),
    ReEntry(ReEntryRequest),
}

impl Request {
    /// Parse a request of any kind.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let items = expect_list(decode(encoded, MAX_REQUEST_BYTES, "request")?, "request")?;
        let label = match items.first() {
            Some(Value::Text(label)) => label.as_str(),
            _ => return Err(CoreError::Malformed("request")),
        };
        Ok(match label {
            JOIN_REQUEST_LABEL => Self::Join(JoinRequest::decode(encoded)?),
            REMOVE_LABEL => Self::Removal(RemoveProposal::decode(encoded)?),
            EVICTION_LABEL => Self::Eviction(Eviction::decode(encoded)?),
            UPDATE_LABEL => Self::Update(UpdateRequest::decode(encoded)?),
            RE_ENTRY_LABEL => Self::ReEntry(ReEntryRequest::decode(encoded)?),
            _ => return Err(CoreError::Malformed("request label")),
        })
    }

    /// Kind of change it makes.
    #[must_use]
    pub const fn kind(&self) -> ChangeKind {
        match self {
            Self::Join(_) => ChangeKind::Join,
            Self::Removal(_) => ChangeKind::Removal,
            Self::Eviction(_) => ChangeKind::Eviction,
            Self::Update(_) => ChangeKind::Update,
            Self::ReEntry(_) => ChangeKind::ReEntry,
        }
    }

    /// Encoding.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        match self {
            Self::Join(request) => request.encoded(),
            Self::Removal(request) => request.encoded(),
            Self::Eviction(request) => request.encoded(),
            Self::Update(request) => request.encoded(),
            Self::ReEntry(request) => request.encoded(),
        }
    }

    /// `H(encoded)`, which a district commit's change names.
    #[must_use]
    pub fn reference(&self) -> Digest {
        h(self.encoded())
    }

    /// The group it is for.
    #[must_use]
    pub const fn gid(&self) -> &Digest {
        match self {
            Self::Join(request) => &request.gid,
            Self::Removal(request) => &request.gid,
            Self::Eviction(request) => &request.gid,
            Self::Update(request) => &request.gid,
            Self::ReEntry(request) => &request.gid,
        }
    }

    /// The existing member it concerns, if any (not for a join).
    #[must_use]
    pub const fn subject(&self) -> Option<Occupancy> {
        match self {
            Self::Join(_) => None,
            Self::Removal(request) => Some(request.target),
            Self::Eviction(request) => Some(request.target),
            Self::Update(request) => Some(request.member),
            Self::ReEntry(request) => Some(request.member),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use cityg_core::kem::KemSecret;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    struct Setup {
        gid: Digest,
        admin: Occupancy,
        admin_id: DeviceIdentity,
        admins: BTreeMap<Occupancy, Vec<u8>>,
    }

    fn setup() -> Setup {
        let admin_id = DeviceIdentity::from_seed(&[1; 32]);
        let gid = group_id(admin_id.public_key(), &[2; 32]).unwrap();
        let admin = Occupancy { leaf: 0, since: 0 };
        let admins = BTreeMap::from([(admin, admin_id.public_key().to_vec())]);
        Setup {
            gid,
            admin,
            admin_id,
            admins,
        }
    }

    #[test]
    fn join_requests_check_their_admission() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let s = setup();
        let device = DeviceIdentity::from_seed(&[3; 32]);
        let id = device_id(&s.gid, device.public_key()).unwrap();
        let leaf = KemSecret::generate(&mut rng).public_key();
        let init = KemSecret::generate(&mut rng).public_key();
        let admission =
            Admission::by_admin(&s.gid, &id, 10, s.admin, &s.admin_id, &mut rng).unwrap();
        let request = JoinRequest::sign(
            &s.gid,
            &device,
            &leaf,
            &init,
            10,
            Some(&admission),
            &mut rng,
        )
        .unwrap();
        let decoded = JoinRequest::decode(request.encoded()).unwrap();
        decoded.verify(&s.gid, 3, &s.admins, false).unwrap();
        assert!(
            decoded.verify(&s.gid, 11, &s.admins, false).is_err(),
            "expired"
        );
        assert!(
            decoded.verify(&s.gid, 3, &BTreeMap::new(), false).is_err(),
            "no admin"
        );
        assert_eq!(decoded.token(), admission.hash());
        assert!(matches!(
            Request::decode(request.encoded()).unwrap(),
            Request::Join(_)
        ));
        // An admission for another device does not pass.
        let other = DeviceIdentity::from_seed(&[4; 32]);
        let stolen =
            JoinRequest::sign(&s.gid, &other, &leaf, &init, 10, Some(&admission), &mut rng)
                .unwrap();
        assert!(stolen.verify(&s.gid, 3, &s.admins, false).is_err());
        assert_eq!(admission.anchor_key(), s.admin_id.public_key());
        // Without admission: only in an open group, and only while valid.
        let open = JoinRequest::sign(&s.gid, &other, &leaf, &init, 10, None, &mut rng).unwrap();
        let open = JoinRequest::decode(open.encoded()).unwrap();
        open.verify(&s.gid, 3, &s.admins, true).unwrap();
        assert_eq!(
            open.verify(&s.gid, 3, &s.admins, false).unwrap_err(),
            CoreError::Unauthorized("join without admission in a closed group")
        );
        assert!(open.verify(&s.gid, 11, &s.admins, true).is_err(), "expired");
        assert_eq!(open.token(), open.reference());
        let late = 3 + MAX_ADMISSION_EPOCHS + 1;
        let late = JoinRequest::sign(&s.gid, &other, &leaf, &init, late, None, &mut rng).unwrap();
        assert!(late.verify(&s.gid, 3, &s.admins, true).is_err(), "too long");
    }

    #[test]
    fn invites_delegate_admission() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let s = setup();
        let seed = [9u8; 32];
        let invite = Invite::sign(&s.gid, &seed, 1_000, 5, s.admin, &s.admin_id, &mut rng).unwrap();
        let device = DeviceIdentity::from_seed(&[5; 32]);
        let id = device_id(&s.gid, device.public_key()).unwrap();
        let admission = Admission::with_invite(&invite, &seed, &id, 20, &mut rng).unwrap();
        let decoded = Admission::decode(admission.encoded()).unwrap();
        decoded.verify(&s.gid, &id, 5, &s.admins).unwrap();
        assert_eq!(decoded.anchor_key(), s.admin_id.public_key());
        assert!(Admission::with_invite(&invite, &[8; 32], &id, 20, &mut rng).is_err());
        let former = BTreeMap::from([(
            Occupancy { leaf: 3, since: 1 },
            s.admin_id.public_key().to_vec(),
        )]);
        assert!(decoded.verify(&s.gid, &id, 5, &former).is_err());
    }

    #[test]
    fn requests_of_members_bind_their_signer_and_target() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let s = setup();
        let member = Occupancy { leaf: 1, since: 1 };
        let member_id = DeviceIdentity::from_seed(&[6; 32]);
        let old = KemSecret::generate(&mut rng).public_key();
        let new = KemSecret::generate(&mut rng).public_key();
        let init = KemSecret::generate(&mut rng).public_key();

        let by_admin =
            RemoveProposal::sign(&s.gid, member, s.admin, &s.admin_id, &mut rng).unwrap();
        by_admin
            .verify(&s.gid, &s.admins, member_id.public_key())
            .unwrap();
        let by_self = RemoveProposal::sign(&s.gid, member, member, &member_id, &mut rng).unwrap();
        by_self
            .verify(&s.gid, &s.admins, member_id.public_key())
            .unwrap();
        let by_other = RemoveProposal::sign(
            &s.gid,
            member,
            Occupancy { leaf: 2, since: 1 },
            &member_id,
            &mut rng,
        )
        .unwrap();
        assert!(
            by_other
                .verify(&s.gid, &s.admins, member_id.public_key())
                .is_err()
        );

        let update = UpdateRequest::sign(&s.gid, member, &old, &new, &member_id, &mut rng).unwrap();
        update.verify(&s.gid, member_id.public_key()).unwrap();
        assert_eq!(update.replaces, kem_pk_hash(&old).unwrap());
        assert!(update.verify(&s.gid, s.admin_id.public_key()).is_err());

        let re_entry =
            ReEntryRequest::sign(&s.gid, member, &old, &new, &init, &member_id, &mut rng).unwrap();
        re_entry.verify(&s.gid, member_id.public_key()).unwrap();
        assert_eq!(
            Request::decode(re_entry.encoded()).unwrap().subject(),
            Some(member)
        );

        let catch_up =
            CatchUpRequest::sign(&s.gid, member, &[7; 32], &init, &member_id, &mut rng).unwrap();
        catch_up
            .verify(&s.gid, &[7; 32], member_id.public_key())
            .unwrap();
        assert!(
            catch_up
                .verify(&s.gid, &[8; 32], member_id.public_key())
                .is_err()
        );

        let policy =
            GroupPolicy::sign(&s.gid, false, Some(100), s.admin, &s.admin_id, &mut rng).unwrap();
        let decoded = GroupPolicy::decode(policy.encoded()).unwrap();
        decoded.verify(&s.gid, &s.admins).unwrap();
        assert!(!decoded.open && decoded.max_idle_epochs == Some(100));
        assert!(decoded.verify(&s.gid, &BTreeMap::new()).is_err());
        let eviction = Eviction::new(&s.gid, member, &policy.hash()).unwrap();
        eviction.verify(&s.gid, &policy, 5, 106).unwrap();
        assert!(eviction.verify(&s.gid, &policy, 5, 105).is_err());
        let open = GroupPolicy::sign(&s.gid, true, None, s.admin, &s.admin_id, &mut rng).unwrap();
        assert!(GroupPolicy::decode(open.encoded()).unwrap().open);
        let under_open = Eviction::new(&s.gid, member, &open.hash()).unwrap();
        assert!(
            under_open.verify(&s.gid, &open, 5, 1_000).is_err(),
            "this policy evicts nobody"
        );
        assert_eq!(
            Request::decode(eviction.encoded()).unwrap().kind(),
            ChangeKind::Eviction
        );

        let content = CheckpointContent {
            epoch: 4,
            interim: [1; 32],
            tree_hash: [2; 32],
            registry_hash: [3; 32],
            height: 5,
            district_bits: 2,
            external_pk_hash: [4; 32],
            time_ms: 99,
        };
        let checkpoint =
            Checkpoint::sign(&s.gid, &content, s.admin, &s.admin_id, &mut rng).unwrap();
        let decoded = Checkpoint::decode(checkpoint.encoded()).unwrap();
        decoded.verify(&s.gid, s.admin_id.public_key()).unwrap();
        assert_eq!(decoded.content, content);
        assert!(checkpoint.verify(&s.gid, member_id.public_key()).is_err());
    }
}
