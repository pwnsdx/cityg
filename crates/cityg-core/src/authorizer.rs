//! The authorized mode (docs/specs-v0.5-draft.md section 4.9): the
//! group's authorizer, which holds the place of MLS's authentication
//! service, signs batches of the joins it authorizes and a checkpoint of
//! each epoch, and may remove members.
//!
//! ```text
//! AuthorizationBatch   := ["city-g/authorization-batch/v5", gid, epoch, root, count, signature]
//!   root               := MTH("authorized", [H(JoinRequest_1), ..., H(JoinRequest_count)])
//! Authorization        := [batch, index, path]                path: MTH inclusion proof
//! AuthorizerCheckpoint := ["city-g/authorizer-checkpoint/v5", gid, epoch, H(GroupContext_n),
//!                          confirmation_tag_n, kem_pk_hash(external_pk_n), signature]
//! authorizer_pk_hash   := H_L("authorizer", [authorizer_pk])
//! ```
//!
//! Both are signed with the authorizer's ML-DSA-65 key under their labels.
//! A join in an authorized group carries no admission: the DS attaches its
//! authorization, the batch of the window and the proof of the request's
//! hash in it. One signature covers every join of a window.
//!
//! The authorizer follows the group's public state, checks each window as
//! the DS does and signs the checkpoint of the epoch it creates. A joiner
//! that trusts it enters with that checkpoint instead of a chain of seals
//! ([`CheckpointedEpoch`]); a member may require it before it accepts a
//! window.

use std::sync::Arc;

use cityg_pqc::SignatureContext;
use rand_core::CryptoRngCore;

use crate::cbor::{bytes, text, uint};
use crate::codec::{Signed, open_signed, sign_fields};
use crate::commit::{CityTask, DistrictCommit, Seal, SealHeader};
use crate::crypto::{Digest, h_l, kem_pk_hash};
use crate::error::{CoreError, CoreResult};
use crate::identity::DeviceIdentity;
use crate::merkle;
use crate::objects::{JoinRequest, RemoveProposal, Urgency};
use crate::registry::RegistryHeader;
use crate::schedule::{GroupContext, interim_transcript_hash};
use crate::tree::{Divisions, Occupancy, Shape};
use crate::window::{EpochHeader, PublicState, Requests, check_window};

/// Label of authorization batches.
pub const BATCH_LABEL: &str = "city-g/authorization-batch/v5";

/// Label of authorizer checkpoints.
pub const CHECKPOINT_LABEL: &str = "city-g/authorizer-checkpoint/v5";

/// Label of the Merkle tree of a batch.
const AUTHORIZED_LABEL: &str = "authorized";

/// Largest encoded batch.
const MAX_BATCH_BYTES: usize = 8 * 1024;

/// `H_L("authorizer", [authorizer_pk])`, which the registry of an
/// authorized group holds.
pub fn authorizer_pk_hash(authorizer_pk: &[u8]) -> CoreResult<Digest> {
    h_l("authorizer", vec![bytes(authorizer_pk)])
}

/// The joins an authorizer authorizes for one window: the root of their
/// requests' hashes, signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationBatch {
    pub gid: Digest,
    /// The window it authorizes joins for, the one that creates `epoch`.
    pub epoch: u64,
    pub root: Digest,
    pub count: u64,
    signed: Signed,
}

impl AuthorizationBatch {
    fn sign(
        gid: &Digest,
        epoch: u64,
        requests: &[Digest],
        identity: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let count = u64::try_from(requests.len()).map_err(|_| CoreError::TooLarge("batch"))?;
        let signed = sign_fields(
            vec![
                text(BATCH_LABEL),
                bytes(gid),
                uint(epoch),
                bytes(&merkle::root(AUTHORIZED_LABEL, requests)?),
                uint(count),
            ],
            identity,
            SignatureContext::AUTHORIZATION_BATCH,
            rng,
        )?;
        Self::decode(&signed.encoded)
    }

    /// Parse a batch.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let (mut fields, signed) = open_signed(
            encoded,
            BATCH_LABEL,
            5,
            MAX_BATCH_BYTES,
            "authorization batch",
        )?;
        Ok(Self {
            gid: fields.digest()?,
            epoch: fields.uint()?,
            root: fields.digest()?,
            count: fields.uint()?,
            signed,
        })
    }

    /// Encoded signed batch.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.signed.encoded
    }

    /// Check the authorizer's signature.
    pub fn verify(&self, gid: &Digest, authorizer_pk: &[u8]) -> CoreResult<()> {
        if self.gid != *gid {
            return Err(CoreError::Invalid("authorization batch for another group"));
        }
        self.signed.verify(
            authorizer_pk,
            SignatureContext::AUTHORIZATION_BATCH,
            "authorization batch",
        )
    }
}

/// The authorization of one join: its window's batch, which the DS sends
/// once per window, and the proof of the request's hash in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorization {
    pub batch: Arc<AuthorizationBatch>,
    pub index: u64,
    pub path: Vec<Digest>,
}

impl Authorization {
    /// Check that the authorizer, whose key is `authorizer_pk`, authorized
    /// the request whose hash is `request` for the window that creates
    /// `epoch`.
    pub fn verify(
        &self,
        gid: &Digest,
        epoch: u64,
        request: &Digest,
        authorizer_pk: &[u8],
    ) -> CoreResult<()> {
        self.batch.verify(gid, authorizer_pk)?;
        self.check_proof(epoch, request)
    }

    /// Check the window and the proof alone, for a batch whose signature
    /// is already checked.
    pub fn check_proof(&self, epoch: u64, request: &Digest) -> CoreResult<()> {
        if self.batch.epoch != epoch {
            return Err(CoreError::Invalid("authorization for another window"));
        }
        merkle::verify_inclusion(
            AUTHORIZED_LABEL,
            &self.batch.root,
            self.batch.count,
            self.index,
            request,
            &self.path,
        )
        .map_err(|_| CoreError::Unauthorized("join not in the authorizer's batch"))
    }

    /// Size in bytes of the proof as a deployment would send it, the batch
    /// aside.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        9 + 33 * self.path.len()
    }
}

/// The authorizer's checkpoint of an epoch: it checked the window that
/// created it, and signs its group context, its confirmation tag and its
/// external key, which the seal carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizerCheckpoint {
    pub gid: Digest,
    pub epoch: u64,
    /// `H(GroupContext_n)`.
    pub context_hash: Digest,
    /// `confirmation_tag_n`.
    pub tag: Digest,
    /// `kem_pk_hash(external_pk_n)`.
    pub external_pk_hash: Digest,
    signed: Signed,
}

impl AuthorizerCheckpoint {
    fn sign(
        gid: &Digest,
        seal: &Seal,
        identity: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let signed = sign_fields(
            vec![
                text(CHECKPOINT_LABEL),
                bytes(gid),
                uint(seal.header.epoch),
                bytes(&GroupContext::of_seal(&seal.header)?.hash()?),
                bytes(&seal.tag),
                bytes(&kem_pk_hash(&seal.external_pk)?),
            ],
            identity,
            SignatureContext::AUTHORIZER_CHECKPOINT,
            rng,
        )?;
        Self::decode(&signed.encoded)
    }

    /// Parse a checkpoint.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let (mut fields, signed) = open_signed(
            encoded,
            CHECKPOINT_LABEL,
            6,
            MAX_BATCH_BYTES,
            "authorizer checkpoint",
        )?;
        Ok(Self {
            gid: fields.digest()?,
            epoch: fields.uint()?,
            context_hash: fields.digest()?,
            tag: fields.digest()?,
            external_pk_hash: fields.digest()?,
            signed,
        })
    }

    /// Encoded signed checkpoint.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.signed.encoded
    }

    /// Check the authorizer's signature.
    pub fn verify(&self, gid: &Digest, authorizer_pk: &[u8]) -> CoreResult<()> {
        if self.gid != *gid {
            return Err(CoreError::Invalid(
                "authorizer checkpoint for another group",
            ));
        }
        self.signed.verify(
            authorizer_pk,
            SignatureContext::AUTHORIZER_CHECKPOINT,
            "authorizer checkpoint",
        )
    }

    /// Check that the checkpoint is that of the epoch whose group context
    /// is `context`, with the tag and the external key a member computed
    /// or a seal carries.
    pub fn check_epoch(
        &self,
        context: &GroupContext,
        tag: &Digest,
        external_pk: &[u8],
    ) -> CoreResult<()> {
        if self.epoch != context.epoch
            || self.context_hash != context.hash()?
            || self.tag != *tag
            || self.external_pk_hash != kem_pk_hash(external_pk)?
        {
            return Err(CoreError::Invalid("authorizer checkpoint of another epoch"));
        }
        Ok(())
    }
}

/// An epoch as a joiner that trusts the authorizer receives it, instead of
/// a chain of seals: the authorizer's checkpoint, and the seal header, the
/// registry header and the external key that the checkpoint binds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointedEpoch {
    pub checkpoint: AuthorizerCheckpoint,
    pub seal: SealHeader,
    pub registry: RegistryHeader,
    pub external_pk: Vec<u8>,
}

impl CheckpointedEpoch {
    /// The header of the epoch, for a joiner that trusts the authorizer
    /// whose key is `authorizer_pk`, which the epoch's registry must name,
    /// and the epoch's group context, whose confirmed transcript hash the
    /// joiner checks its welcome's tag against.
    pub fn header(
        &self,
        gid: &Digest,
        authorizer_pk: &[u8],
    ) -> CoreResult<(EpochHeader, GroupContext)> {
        self.checkpoint.verify(gid, authorizer_pk)?;
        let context = GroupContext::of_seal(&self.seal)?;
        self.checkpoint
            .check_epoch(&context, &self.checkpoint.tag, &self.external_pk)?;
        if context.gid != *gid
            || self.registry.hash()? != context.registry_hash
            || self.registry.authorizer != Some(authorizer_pk_hash(authorizer_pk)?)
        {
            return Err(CoreError::Invalid("authorizer checkpoint"));
        }
        let shape = Shape::new(
            context.height,
            Divisions::new(
                context.district_bits,
                context.island_bits,
                context.subcity_bits,
            )?,
        )?;
        let header = EpochHeader {
            gid: *gid,
            epoch: context.epoch,
            shape,
            tree_hash: context.tree_hash,
            registry: self.registry.clone(),
            interim: interim_transcript_hash(
                &context.confirmed_transcript_hash,
                &self.checkpoint.tag,
            )?,
            external_pk: self.external_pk.clone(),
        };
        Ok((header, context))
    }

    /// Size in bytes as a deployment would send it.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.checkpoint.encoded().len()
            + self.seal.encode().map_or(0, |seal| seal.len())
            + self.registry.encoded_len()
            + self.external_pk.len()
            + 3
    }
}

/// What the authorizer checks a window with: its district commits, its
/// city tasks, its seal and its requests, as the DS keeps them.
#[derive(Clone, Copy, Debug)]
pub struct SealedWindow<'a> {
    pub commits: &'a [DistrictCommit],
    pub city_tasks: &'a [CityTask],
    pub seal: &'a Seal,
    pub requests: &'a Requests,
}

/// A group's authorizer: its key, what it signs, and the public state it
/// follows to check windows.
pub struct Authorizer {
    gid: Digest,
    identity: DeviceIdentity,
    state: Option<PublicState>,
}

impl core::fmt::Debug for Authorizer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Authorizer").finish_non_exhaustive()
    }
}

impl Authorizer {
    /// The authorizer of group `gid`, with its key.
    #[must_use]
    pub const fn new(gid: Digest, identity: DeviceIdentity) -> Self {
        Self {
            gid,
            identity,
            state: None,
        }
    }

    /// Follow the group from a public state it trusts, such as the state
    /// in force when an admin named it.
    pub fn follow_from(&mut self, state: PublicState) -> CoreResult<()> {
        if state.gid != self.gid {
            return Err(CoreError::Invalid("state of another group"));
        }
        self.state = Some(state);
        Ok(())
    }

    /// The epoch of the state it follows.
    #[must_use]
    pub fn epoch(&self) -> Option<u64> {
        self.state.as_ref().map(|state| state.epoch)
    }

    /// Check the next window as the DS does, every entry included (its
    /// joins carry authorizations under the key in force), apply it, and
    /// sign the checkpoint of the epoch it creates, if the new registry
    /// still names this authorizer. It signs one checkpoint per epoch: the
    /// state it follows moves past it.
    pub fn checkpoint(
        &mut self,
        window: &SealedWindow<'_>,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<AuthorizerCheckpoint> {
        let state = self
            .state
            .as_ref()
            .ok_or(CoreError::Invalid("the authorizer follows no state"))?;
        let outcome = check_window(
            state,
            window.commits,
            window.city_tasks,
            window.seal,
            window.requests,
            true,
        )?;
        let mut next = state.clone();
        next.apply(&outcome)?;
        if next.registry.header()?.authorizer != Some(authorizer_pk_hash(self.public_key())?) {
            return Err(CoreError::Unauthorized(
                "the group names another authorizer",
            ));
        }
        let checkpoint = AuthorizerCheckpoint::sign(&self.gid, window.seal, &self.identity, rng)?;
        self.state = Some(next);
        Ok(checkpoint)
    }

    /// Its public key, which an admin names in the group policy.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        self.identity.public_key()
    }

    /// Authorize `requests` for the window that creates `epoch`: sign the
    /// root of their hashes, and attach to each its authorization. Whom to
    /// authorize is the authorizer's decision; it checks here that each
    /// request is a device's, for this group, and may still enter.
    pub fn authorize(
        &self,
        epoch: u64,
        requests: Vec<JoinRequest>,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Vec<JoinRequest>> {
        for request in &requests {
            request.check_signed(&self.gid, epoch)?;
            if request.admission.is_some() {
                return Err(CoreError::Invalid("an admission in an authorized group"));
            }
        }
        let hashes: Vec<Digest> = requests.iter().map(JoinRequest::reference).collect();
        let batch = Arc::new(AuthorizationBatch::sign(
            &self.gid,
            epoch,
            &hashes,
            &self.identity,
            rng,
        )?);
        requests
            .into_iter()
            .enumerate()
            .map(|(index, mut request)| {
                request.authorization = Some(Box::new(Authorization {
                    batch: Arc::clone(&batch),
                    index: u64::try_from(index).map_err(|_| CoreError::TooLarge("batch"))?,
                    path: merkle::inclusion_proof(AUTHORIZED_LABEL, &hashes, index)?,
                }));
                Ok(request)
            })
            .collect()
    }

    /// Propose the removal of `target`, which is urgent (section 2.9).
    pub fn remove_proposal(
        &self,
        target: Occupancy,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<RemoveProposal> {
        RemoveProposal::sign(
            &self.gid,
            target,
            None,
            Urgency::Urgent,
            &self.identity,
            rng,
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::card::{CardKey, LeafKeys};
    use crate::kem::KemSecret;
    use crate::objects::{AdmissionMode, Admitters, GroupPolicy, PolicyTerms};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn join(gid: &Digest, seed: u8, rng: &mut ChaCha20Rng) -> JoinRequest {
        let device = DeviceIdentity::from_seed(&[seed; 32]);
        let leaf = KemSecret::generate(rng).public_key();
        let card = CardKey::generate(rng).card();
        JoinRequest::sign(
            gid,
            &device,
            LeafKeys {
                encryption_key: &leaf,
                card: &card,
            },
            &KemSecret::generate(rng).public_key(),
            20,
            None,
            rng,
        )
        .unwrap()
    }

    #[test]
    fn a_batch_authorizes_its_joins_for_one_window() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let gid = [3; 32];
        let authorizer = Authorizer::new(gid, DeviceIdentity::from_seed(&[1; 32]));
        let key = authorizer.public_key().to_vec();
        let hash = authorizer_pk_hash(&key).unwrap();
        let admins = BTreeMap::new();
        let admitters =
            Admitters::new(&admins, AdmissionMode::Authorized, Some(&hash), Some(&key)).unwrap();
        let joins: Vec<JoinRequest> = (10..15).map(|seed| join(&gid, seed, &mut rng)).collect();
        let authorized = authorizer.authorize(7, joins.clone(), &mut rng).unwrap();
        for request in &authorized {
            request.verify(&gid, 7, &admitters).unwrap();
            // For its window only.
            assert!(request.verify(&gid, 8, &admitters).is_err());
        }
        // One signature for the batch; the proofs are short.
        let batch = &authorized[0].authorization.as_ref().unwrap().batch;
        assert_eq!(batch.count, 5);
        assert_eq!(
            *batch,
            AuthorizationBatch::decode(batch.encoded()).unwrap().into()
        );
        assert!(authorized[0].authorization.as_ref().unwrap().encoded_len() <= 9 + 33 * 3);
        // Without its authorization, or with another's, a join is refused.
        assert_eq!(
            joins[0].verify(&gid, 7, &admitters).unwrap_err(),
            CoreError::Unauthorized("join without authorization")
        );
        let mut swapped = joins[0].clone();
        swapped.authorization = authorized[1].authorization.clone();
        assert!(swapped.verify(&gid, 7, &admitters).is_err());
        // Another authorizer's batch does not pass.
        let other = Authorizer::new(gid, DeviceIdentity::from_seed(&[2; 32]));
        let forged = other.authorize(7, joins[..1].to_vec(), &mut rng).unwrap();
        assert!(forged[0].verify(&gid, 7, &admitters).is_err());
        // Admitters need the key the registry names.
        assert!(
            Admitters::new(
                &admins,
                AdmissionMode::Authorized,
                Some(&hash),
                Some(other.public_key())
            )
            .is_err()
        );
        assert!(Admitters::new(&admins, AdmissionMode::Authorized, Some(&hash), None).is_err());
        // An open group's admitters do not take an authorization for a join.
        let open = Admitters::new(&admins, AdmissionMode::Open, None, None).unwrap();
        assert!(open.authorizer_pk.is_none());
    }

    #[test]
    fn the_authorizer_removes_urgently_and_only_in_its_group() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let gid = [4; 32];
        let authorizer = Authorizer::new(gid, DeviceIdentity::from_seed(&[1; 32]));
        let key = authorizer.public_key().to_vec();
        let hash = authorizer_pk_hash(&key).unwrap();
        let admins = BTreeMap::new();
        let admitters =
            Admitters::new(&admins, AdmissionMode::Authorized, Some(&hash), Some(&key)).unwrap();
        let target = Occupancy { leaf: 3, since: 1 };
        let target_pk = DeviceIdentity::from_seed(&[5; 32]).public_key().to_vec();
        let removal = authorizer.remove_proposal(target, &mut rng).unwrap();
        assert_eq!((removal.proposer, removal.urgency), (None, Urgency::Urgent));
        let decoded = RemoveProposal::decode(removal.encoded()).unwrap();
        decoded.verify(&gid, &admitters, &target_pk).unwrap();
        // Not in a group without an authorizer, and never ordinary.
        let closed = Admitters::new(&admins, AdmissionMode::Closed, None, None).unwrap();
        assert!(decoded.verify(&gid, &closed, &target_pk).is_err());
        let ordinary = RemoveProposal::sign(
            &gid,
            target,
            None,
            Urgency::Ordinary,
            &DeviceIdentity::from_seed(&[1; 32]),
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            ordinary.verify(&gid, &admitters, &target_pk).unwrap_err(),
            CoreError::Invalid("an authorizer's removal is urgent")
        );
    }

    #[test]
    fn a_policy_names_an_authorizer_with_the_authorized_mode_only() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let gid = [5; 32];
        let admin = DeviceIdentity::from_seed(&[1; 32]);
        let at = Occupancy { leaf: 0, since: 0 };
        let key = DeviceIdentity::from_seed(&[2; 32]).public_key().to_vec();
        let policy = GroupPolicy::sign(
            &gid,
            &PolicyTerms::authorized(key.clone()),
            at,
            &admin,
            &mut rng,
        )
        .unwrap();
        let decoded = GroupPolicy::decode(policy.encoded()).unwrap();
        assert_eq!(decoded.admission(), AdmissionMode::Authorized);
        assert_eq!(decoded.authorizer_pk(), Some(key.as_slice()));
        assert_eq!(
            decoded.authorizer().unwrap(),
            Some(authorizer_pk_hash(&key).unwrap())
        );
        for terms in [
            PolicyTerms {
                authorizer_pk: None,
                ..PolicyTerms::authorized(key.clone())
            },
            PolicyTerms {
                authorizer_pk: Some(key.clone()),
                ..PolicyTerms::open()
            },
            PolicyTerms::authorized(vec![1; 32]),
        ] {
            assert!(GroupPolicy::sign(&gid, &terms, at, &admin, &mut rng).is_err());
        }
    }
}
