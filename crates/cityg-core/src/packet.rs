//! What members, joiners and returning members download
//! (docs/specs.md section 13).
//!
//! * A [`Packet`] per member and window (E-13): the seal header, the
//!   confirmation tag, the registry roots, and the steps of the member's
//!   path. For a window sealed by an entrant it adds the seal signature and
//!   the evidence that the entrant may seal (E-7). An island follower's
//!   packet has the steps of its path up to its island root and the top of
//!   its path: a relay element, a flat element or a refresh (E-15).
//! * A [`SealLink`] per window for those who check the chain of seals from
//!   a checkpoint or from their last epoch (E-10): the seal proof and the
//!   evidence that its signer was a member of the previous epoch, or an
//!   admitted entrant.
//! * An [`Entry`] for a joiner, a member re-entering its leaf, or a member
//!   jumping to the present (E-8): the links, the welcome, the steps of its
//!   whole path and a proof of its leaf.

use std::collections::BTreeMap;

use crate::commit::{SealHeader, SealKind, SealProof};
use crate::crypto::{Digest, KEM_WRAP_BYTES, kem_pk_hash};
use crate::error::{CoreError, CoreResult};
use crate::objects::{AdmissionMode, Checkpoint, GroupPolicy, JoinRequest, ReEntryRequest};
use crate::registry::RegistryHeader;
use crate::rekey::Step;
use crate::schedule::{confirmed_transcript_hash, interim_transcript_hash};
use crate::smm::SmmProof;
use crate::top::Top;
use crate::tree::{Divisions, LeafProof, Occupancy, ParentNode, Shape};
use crate::welcome::Welcome;
use crate::window::EpochHeader;

/// The registry header after a window, as sent to members: the admins only
/// when they changed, and the group policy object when the window set it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryUpdate {
    pub admins: Option<BTreeMap<Occupancy, Vec<u8>>>,
    pub devices_root: Digest,
    pub admissions_root: Digest,
    pub keys_root: Digest,
    pub policy: Option<Digest>,
    pub admission: AdmissionMode,
    pub authorizer: Option<Digest>,
    /// The policy the window set, if it changed.
    pub policy_object: Option<GroupPolicy>,
}

/// Check a change of the registry's policy, from `before` to `after`: a
/// policy the window sets must come with its object, signed by an admin of
/// the previous epoch, and the admission mode and the authorizer change only
/// by a new policy. A member checks this itself, so that no sealer can open
/// a closed group behind the admins' backs.
pub fn check_policy_change(
    gid: &Digest,
    before: &RegistryHeader,
    after: &RegistryHeader,
    object: Option<&GroupPolicy>,
) -> CoreResult<()> {
    if after.policy == before.policy && object.is_none() {
        return if after.admission == before.admission && after.authorizer == before.authorizer {
            Ok(())
        } else {
            Err(CoreError::Invalid(
                "admission mode changed without a policy",
            ))
        };
    }
    let object = object.ok_or(CoreError::Invalid("new policy without its object"))?;
    if Some(object.hash()) != after.policy
        || object.admission() != after.admission
        || object.authorizer()? != after.authorizer
    {
        return Err(CoreError::Invalid("policy object"));
    }
    object.verify(gid, &before.admins)
}

impl RegistryUpdate {
    /// The update from `before` to `after`; `policy` is the policy the window
    /// set, if any.
    #[must_use]
    pub fn between(
        before: &RegistryHeader,
        after: &RegistryHeader,
        policy: Option<&GroupPolicy>,
    ) -> Self {
        Self {
            admins: (before.admins != after.admins).then(|| after.admins.clone()),
            devices_root: after.devices_root,
            admissions_root: after.admissions_root,
            keys_root: after.keys_root,
            policy: after.policy,
            admission: after.admission,
            authorizer: after.authorizer,
            policy_object: (before.policy != after.policy)
                .then(|| policy.cloned())
                .flatten(),
        }
    }

    /// The header after the window, once a change of policy is checked.
    pub fn apply(&self, gid: &Digest, before: &RegistryHeader) -> CoreResult<RegistryHeader> {
        let after = RegistryHeader {
            admins: self.admins.clone().unwrap_or_else(|| before.admins.clone()),
            devices_root: self.devices_root,
            admissions_root: self.admissions_root,
            keys_root: self.keys_root,
            policy: self.policy,
            admission: self.admission,
            authorizer: self.authorizer,
        };
        check_policy_change(gid, before, &after, self.policy_object.as_ref())?;
        Ok(after)
    }

    fn encoded_len(&self) -> usize {
        let admins: usize = self
            .admins
            .as_ref()
            .map_or(1, |admins| admins.values().map(|key| key.len() + 16).sum());
        let policy = self
            .policy_object
            .as_ref()
            .map_or(1, |policy| policy.encoded().len());
        admins + 3 * 33 + 36 + 34 + policy
    }
}

/// Evidence that the entrant of a window may seal it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntrantEvidence {
    /// A joiner: its request, and proofs that its device is not a member
    /// and its admission (or, in an open or authorized group, its request)
    /// unused, against the previous registry; in an authorized group, the
    /// authorizer's key, which the registry's hash of it checks.
    Join {
        request: Box<JoinRequest>,
        device: SmmProof,
        admission: SmmProof,
        authorizer_pk: Option<Vec<u8>>,
    },
    /// A returning member: its request, and its leaf in the previous tree.
    ReEntry {
        request: Box<ReEntryRequest>,
        leaf: LeafProof,
    },
}

impl EntrantEvidence {
    /// Check the evidence and the seal signature against the header of the
    /// previous epoch.
    pub fn verify(&self, previous: &EpochHeader, proof: &SealProof) -> CoreResult<()> {
        let header = &proof.header;
        let init = header
            .entrant
            .as_ref()
            .ok_or(CoreError::Invalid("entrant evidence for a member seal"))?;
        match self {
            Self::Join {
                request,
                device,
                admission,
                authorizer_pk,
            } => {
                if request.reference() != init.request || header.sealer.since != header.epoch {
                    return Err(CoreError::Invalid("entrant request"));
                }
                request.verify(
                    &previous.gid,
                    header.epoch,
                    &previous.registry.admitters(authorizer_pk.as_deref())?,
                )?;
                previous
                    .registry
                    .check_new_device(&request.device_id()?, device)?;
                previous
                    .registry
                    .check_unused_admission(&request.token(), admission)?;
                proof.verify_signature(&request.device_pk)
            }
            Self::ReEntry { request, leaf } => {
                if request.reference() != init.request
                    || request.member != header.sealer
                    || leaf.occupancy() != Some(request.member)
                {
                    return Err(CoreError::Invalid("entrant request"));
                }
                leaf.verify(&previous.tree_hash)?;
                let node = leaf
                    .leaf
                    .as_ref()
                    .ok_or(CoreError::Invalid("entrant leaf"))?;
                if request.replaces != kem_pk_hash(&node.encryption_key)? {
                    return Err(CoreError::Invalid("re-entry replaces another key"));
                }
                request.verify(&previous.gid, &node.device_pk)?;
                proof.verify_signature(&node.device_pk)
            }
        }
    }

    fn encoded_len(&self) -> usize {
        match self {
            Self::Join {
                request,
                device,
                admission,
                authorizer_pk,
            } => {
                let authorization = request.authorization.as_ref().map_or(0, |authorization| {
                    authorization.encoded_len() + authorization.batch.encoded().len()
                });
                request.encoded().len()
                    + authorization
                    + device.encoded_len()
                    + admission.encoded_len()
                    + authorizer_pk.as_ref().map_or(1, |key| key.len() + 3)
            }
            Self::ReEntry { request, leaf } => {
                request.encoded().len() + leaf.encoded_len().unwrap_or_default()
            }
        }
    }
}

/// Who signed a seal, as a verifier of the chain of seals checks it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealerEvidence {
    /// A member of the previous epoch: its leaf in the previous tree.
    Member(LeafProof),
    /// The window's entrant.
    Entrant(Box<EntrantEvidence>),
}

/// One window of a chain of seals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealLink {
    pub proof: SealProof,
    pub sealer: SealerEvidence,
    /// The registry header after the window.
    pub registry: RegistryHeader,
    /// The group policy the window set, if it changed.
    pub policy: Option<GroupPolicy>,
}

impl SealLink {
    /// Size in bytes as a deployment would send it: like a packet, a chain
    /// of links carries the admins only when they change, which this
    /// estimate assumes.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let proof = self.proof.encode().map_or(0, |encoded| encoded.len());
        let sealer = match &self.sealer {
            SealerEvidence::Member(leaf) => leaf.encoded_len().unwrap_or_default(),
            SealerEvidence::Entrant(evidence) => evidence.encoded_len(),
        };
        let policy = self
            .policy
            .as_ref()
            .map_or(0, |policy| policy.encoded().len());
        proof
            + sealer
            + RegistryUpdate::between(&self.registry, &self.registry, None).encoded_len()
            + policy
    }
}

fn check_successor(previous: &EpochHeader, header: &SealHeader) -> CoreResult<Shape> {
    if header.gid != previous.gid
        || header.prev_interim != previous.interim
        || header.district_bits != previous.shape.district_bits
        || header.island_bits != previous.shape.island_bits
        || header.subcity_bits != previous.shape.subcity_bits
    {
        return Err(CoreError::Invalid("seal does not follow the epoch"));
    }
    if header.epoch != previous.epoch + 1 {
        return Err(CoreError::EpochMismatch {
            expected: previous.epoch + 1,
            got: header.epoch,
        });
    }
    previous.shape.grown(header.height)
}

impl EpochHeader {
    /// The header of an epoch an admin checkpointed, for a joiner that
    /// trusts the admin key `admin_pk` (from its invite or admission, or
    /// from the public link of an open group).
    /// `registry` and `external_pk` come from the delivery service and are
    /// checked against the checkpoint, whose signer must be an admin of that
    /// registry.
    pub fn from_checkpoint(
        gid: &Digest,
        checkpoint: &Checkpoint,
        admin_pk: &[u8],
        registry: RegistryHeader,
        external_pk: Vec<u8>,
    ) -> CoreResult<Self> {
        checkpoint.verify(gid, admin_pk)?;
        let content = &checkpoint.content;
        if registry.hash()? != content.registry_hash
            || kem_pk_hash(&external_pk)? != content.external_pk_hash
            || registry.admin_key(checkpoint.admin) != Some(admin_pk)
        {
            return Err(CoreError::Invalid("checkpoint registry or external key"));
        }
        Ok(Self {
            gid: *gid,
            epoch: content.epoch,
            shape: Shape::new(
                content.height,
                Divisions::new(
                    content.district_bits,
                    content.island_bits,
                    content.subcity_bits,
                )?,
            )?,
            tree_hash: content.tree_hash,
            registry,
            interim: content.interim,
            external_pk,
        })
    }

    /// The header of the next epoch, after checking the window's seal: its
    /// signer was a member of this epoch, or an admitted entrant.
    pub fn follow(&self, link: &SealLink) -> CoreResult<Self> {
        let header = &link.proof.header;
        let shape = check_successor(self, header)?;
        match (&link.sealer, header.kind) {
            (SealerEvidence::Member(leaf), SealKind::Member) => {
                leaf.verify(&self.tree_hash)?;
                if leaf.occupancy() != Some(header.sealer) {
                    return Err(CoreError::Invalid("sealer leaf"));
                }
                let node = leaf
                    .leaf
                    .as_ref()
                    .ok_or(CoreError::Invalid("sealer leaf"))?;
                link.proof.verify_signature(&node.device_pk)?;
            }
            (SealerEvidence::Entrant(evidence), SealKind::Entrant) => {
                evidence.verify(self, &link.proof)?;
            }
            _ => return Err(CoreError::Invalid("sealer evidence")),
        }
        if link.registry.hash()? != header.registry_hash {
            return Err(CoreError::Invalid("registry header"));
        }
        check_policy_change(
            &self.gid,
            &self.registry,
            &link.registry,
            link.policy.as_ref(),
        )?;
        let confirmed = confirmed_transcript_hash(&self.interim, &header.hash()?)?;
        Ok(Self {
            gid: self.gid,
            epoch: header.epoch,
            shape,
            tree_hash: header.tree_hash,
            registry: link.registry.clone(),
            interim: interim_transcript_hash(&confirmed, &link.proof.tag)?,
            external_pk: link.proof.external_pk.clone(),
        })
    }
}

/// The seal signature and entrant evidence of a window sealed by an entrant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntrantProof {
    pub signature: Vec<u8>,
    pub evidence: EntrantEvidence,
}

/// What a member downloads for one window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub header: SealHeader,
    pub tag: Digest,
    pub entrant: Option<EntrantProof>,
    pub registry: RegistryUpdate,
    /// `H_L("kem-pk", [key])` of the member's leaf key after the window.
    pub leaf_key: Digest,
    /// Steps of the member's path, by level: the nodes the window re-keyed
    /// (for an island follower, up to its island root).
    pub path: BTreeMap<u8, Step>,
    /// For an island follower, how it gets the window's root secret.
    pub top: Option<Top>,
}

impl Packet {
    /// Size in bytes as a deployment would send it.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let header = self.header.encode().map_or(0, |encoded| encoded.len());
        let entrant = self.entrant.as_ref().map_or(1, |entrant| {
            entrant.signature.len() + entrant.evidence.encoded_len()
        });
        let path: usize = self
            .path
            .values()
            .map(|step| match step {
                Step::Chain => 3,
                Step::Wrap(_) => 3 + KEM_WRAP_BYTES,
            })
            .sum();
        let top = self.top.as_ref().map_or(1, |top| 2 + top.encoded_len());
        header + 34 + entrant + self.registry.encoded_len() + 34 + path + top
    }
}

/// How each node of a member's path last got its secret: `(epoch, step)`.
pub type EntrySteps = BTreeMap<u8, (u64, Step)>;

/// What a joiner, a member re-entering its leaf or a member jumping to the
/// present downloads to enter an epoch: its whole path, or its island path
/// and a top (docs/specs-v0.5-draft.md section 3.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Seals from the verifier's anchor to the epoch it enters.
    pub links: Vec<SealLink>,
    pub welcome: Welcome,
    /// The steps of its path, up to the root, or up to its island root for
    /// an entry by island.
    pub steps: EntrySteps,
    /// Its leaf in the tree of the epoch it enters.
    pub leaf: LeafProof,
    /// The parents on its path in that tree, by level from 1, as far as
    /// `steps` go.
    pub nodes: Vec<Option<ParentNode>>,
    /// For an entry by island: the root's node and the top of its island.
    pub top: Option<EntryTop>,
}

/// The top of an entry by island: the root's node, which the leaf proof
/// covers, and the relay element or the flat element of the entrant's
/// island, which gives the root secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryTop {
    pub root: ParentNode,
    pub top: Top,
}

impl Entry {
    /// Size in bytes as a deployment would send it.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let links: usize = self.links.iter().map(SealLink::encoded_len).sum();
        let steps: usize = self
            .steps
            .values()
            .map(|(_, step)| match step {
                Step::Chain => 12,
                Step::Wrap(_) => 12 + KEM_WRAP_BYTES,
            })
            .sum();
        let nodes: usize = self
            .nodes
            .iter()
            .map(|node| {
                node.as_ref()
                    .map_or(1, |node| node.encryption_key.len() + 16)
            })
            .sum();
        let top = self.top.as_ref().map_or(1, |top| {
            top.root.encryption_key.len() + 16 + top.top.encoded_len()
        });
        links
            + self.welcome.encode().map_or(0, |encoded| encoded.len())
            + steps
            + self.leaf.encoded_len().unwrap_or_default()
            + nodes
            + top
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;
    use crate::objects::PolicyTerms;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn the_admission_mode_changes_only_with_an_admin_policy() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let gid = [3; 32];
        let admin = Occupancy { leaf: 0, since: 0 };
        let admin_id = DeviceIdentity::from_seed(&[1; 32]);
        let other = Occupancy { leaf: 1, since: 1 };
        let other_id = DeviceIdentity::from_seed(&[2; 32]);
        let before = RegistryHeader {
            admins: BTreeMap::from([(admin, admin_id.public_key().to_vec())]),
            devices_root: [0; 32],
            admissions_root: [0; 32],
            keys_root: [0; 32],
            policy: None,
            admission: AdmissionMode::Closed,
            authorizer: None,
        };
        let with = |policy: Option<Digest>, admission: AdmissionMode| RegistryHeader {
            policy,
            admission,
            ..before.clone()
        };
        check_policy_change(&gid, &before, &before, None).unwrap();
        assert!(
            check_policy_change(&gid, &before, &with(None, AdmissionMode::Open), None).is_err()
        );
        // A new policy comes with its object, which matches the hash and the
        // mode and is signed by an admin.
        let open =
            GroupPolicy::sign(&gid, &PolicyTerms::open(), admin, &admin_id, &mut rng).unwrap();
        let hash = Some(open.hash());
        let opened = with(hash, AdmissionMode::Open);
        assert!(check_policy_change(&gid, &before, &opened, None).is_err());
        assert!(
            check_policy_change(
                &gid,
                &before,
                &with(hash, AdmissionMode::Closed),
                Some(&open)
            )
            .is_err()
        );
        check_policy_change(&gid, &before, &opened, Some(&open)).unwrap();
        let posing =
            GroupPolicy::sign(&gid, &PolicyTerms::open(), other, &other_id, &mut rng).unwrap();
        assert!(
            check_policy_change(
                &gid,
                &before,
                &with(Some(posing.hash()), AdmissionMode::Open),
                Some(&posing)
            )
            .is_err()
        );
        // The policy in force, with or without its object.
        check_policy_change(&gid, &opened, &opened, Some(&open)).unwrap();
        check_policy_change(&gid, &opened, &opened, None).unwrap();
        assert!(
            check_policy_change(&gid, &opened, &with(hash, AdmissionMode::Closed), None).is_err()
        );
    }
}
