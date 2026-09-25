//! Light members: group state without the public tree.
//!
//! A full member keeps the whole public tree, about 4 KB per member (a
//! device key and a leaf key per leaf, a key per parent node), so tens of
//! megabytes for the largest groups. A [`LightSession`] keeps instead:
//!
//! * the GroupContext and transcript of the current epoch, and the registry
//!   (capacity, admins, retired admissions: small, and checked against
//!   `registry_hash` at every commit);
//! * the occupied leaves and the epoch each occupancy began (a few bytes per
//!   member), which is all the commit transition needs to place entering
//!   members and to derive the per-sender message chains;
//! * its own record, its private path keys and the epoch secrets, like a
//!   full member;
//! * the device keys of the members it verified, kept current through the
//!   commits it processes.
//!
//! # What a light member checks
//!
//! For every commit it receives a [`LightCommit`]: Merkle proofs
//! ([`LeafProof`]), against the tree hash of the epoch the commit starts
//! from, of the records the commit's authorization refers to (its author,
//! the removal targets and admin proposers, the authorizers of admissions).
//! The delivery service computes them when it accepts the commit. With them
//! the light member runs the same transition as a full member
//! ([`crate::state::stage_on`] on a [`PartialTree`]): signatures, removal
//! authorizations, admin changes, admissions and retired admissions, entry
//! leaves, the new registry and its hash. It then opens its path secret
//! (the update path names the node each secret is encrypted to), checks the
//! derived public keys against the published ones and the confirmation tag
//! under the new epoch's secrets.
//!
//! It cannot recompute the new tree hash, nor check that a joining device or
//! a rotated key is not already used elsewhere in the tree: for these it
//! relies on the delivery service, which verifies every commit on the full
//! tree, and on the committer, whose tree hash the confirmation tag binds.
//! A malicious delivery service colluding with a member can therefore show
//! light members a tree that full members reject; it still cannot forge a
//! commit (signatures, confirmation tag) nor authorize an admission.
//!
//! Light members do not author commits: to commit, a light member fetches
//! the snapshot of its epoch and becomes a full member
//! ([`LightSession::upgrade`]); a full member becomes light with
//! [`crate::session::GroupSession::to_light`].

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::admission::{Authorizer, SignedAdmission};
use crate::cbor::{
    array, bytes, decode, encode, expect_array, expect_bytes, expect_bytes32, expect_label,
    expect_list, expect_u32, expect_uint, text, uint,
};
use crate::commit::{Commit, CommitContent, CommitKind, max_commit_bytes};
use crate::cover::{CoverFailureReason, CoverFailureReport};
use crate::error::{CoreError, CoreResult};
use crate::group_info::SignedGroupInfo;
use crate::hash::{Digest, digest_eq};
use crate::identity::DeviceIdentity;
use crate::join::{JoinSecrets, Welcome};
use crate::kem::{KEM_CIPHERTEXT_BYTES, validate_public_key};
use crate::key_schedule::{
    EpochSecrets, GroupContext, RetainedEpochSecrets, confirmed_transcript_hash,
    interim_transcript_hash,
};
use crate::message::{Envelope, EpochMessages, ReceivedMessage};
use crate::proposal::{RemoveProposal, SignedRemoveProposal};
use crate::registry::Registry;
use crate::session::{
    CommitSummary, GroupSession, GroupSnapshot, PreviousEpoch, ProcessedCommit, open_envelope,
    previous_from_value, previous_to_value, private_from_values, private_to_values, retire_epoch,
    verify_snapshot,
};
use crate::state::{PartialTree, PublicGroupState, StagedChanges, proposed_changes, stage_on};
use crate::tree::{
    LeafNode, LeafProof, MemberRef, PathContext, PathSecrets, PrivatePath, WRAPPED_SECRET_BYTES,
    ancestor, common_ancestor_level, decrypt_path_entry, is_ancestor_or_self, leaf_node, level,
    next,
};

/// Label of a [`LightCommit`].
pub const LIGHT_COMMIT_LABEL: &str = "city-g/light-commit/v1";
/// Label of a [`LightJoin`].
pub const LIGHT_JOIN_LABEL: &str = "city-g/light-join/v1";
/// Label of an exported light session.
const LIGHT_SESSION_LABEL: &str = "city-g/light-session/v1";
/// Largest encoded [`LightCommit`]: one proof per record a commit of the
/// largest size can refer to.
pub const MAX_LIGHT_COMMIT_BYTES: usize = 8 << 20;
/// Largest encoded [`LightJoin`].
pub const MAX_LIGHT_JOIN_BYTES: usize = 1 << 20;
/// Device keys of other members a light session keeps at most.
pub const MAX_KNOWN_KEYS: usize = 1024;

/// Merkle proofs, against the tree hash of the epoch a commit starts from,
/// of the member records the commit's authorization refers to:
///
/// ```text
/// LightCommit := ["city-g/light-commit/v1", [LeafProof, ...]]   ; increasing leaves
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LightCommit {
    pub proofs: Vec<LeafProof>,
}

impl LightCommit {
    /// The proofs a light member needs for `content`, a commit on `prev`
    /// (the delivery service computes them when it accepts the commit): the
    /// author of a member commit or resync, the target of each removal and
    /// the admin that proposed it, and the authorizer of each admission.
    pub fn for_commit(prev: &PublicGroupState, content: &CommitContent) -> CoreResult<Self> {
        let tree = &prev.tree;
        let mut leaves = BTreeSet::new();
        if matches!(content.kind, CommitKind::Member | CommitKind::Resync) {
            leaves.insert(content.author_leaf);
        }
        for removal in &content.removals {
            let proposal = removal.proposal();
            leaves.insert(proposal.target_leaf);
            leaves.extend(tree.find_device(&proposal.proposer_device_pk));
        }
        let admissions = content
            .admission
            .iter()
            .chain(content.joins.iter().map(|request| &request.admission));
        for admission in admissions {
            leaves.extend(tree.find_device(authorizer_key(admission)));
        }
        leaves.retain(|leaf| *leaf < tree.width());
        Ok(Self {
            proofs: tree.leaf_proofs(leaves)?,
        })
    }

    /// Deterministic CBOR encoding.
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        encode(&array(vec![
            text(LIGHT_COMMIT_LABEL),
            array(self.proofs.iter().map(LeafProof::to_value).collect()),
        ]))
    }

    /// Decode an encoded bundle (structure only).
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let mut items = expect_array(
            decode(encoded, MAX_LIGHT_COMMIT_BYTES, "light commit")?,
            2,
            "light commit",
        )?
        .into_iter();
        expect_label(
            &next(&mut items, "light commit")?,
            LIGHT_COMMIT_LABEL,
            "light commit",
        )?;
        let proofs = expect_list(next(&mut items, "light commit")?, "light commit proofs")?
            .into_iter()
            .map(LeafProof::from_value)
            .collect::<CoreResult<Vec<_>>>()?;
        if proofs.windows(2).any(|pair| pair[0].leaf >= pair[1].leaf) {
            return Err(CoreError::Malformed("light commit proofs"));
        }
        Ok(Self { proofs })
    }
}

fn authorizer_key(admission: &SignedAdmission) -> &[u8] {
    match &admission.authorizer {
        Authorizer::Admin { device_pk } => device_pk,
        Authorizer::Invite(invite) => &invite.invite().inviter_device_pk,
    }
}

/// What a light joiner needs besides its welcome, the commit and its
/// GroupInfo, for the epoch the commit created:
///
/// ```text
/// LightJoin := ["city-g/light-join/v1", registry, [[leaf, since], ...], LeafProof]
/// ```
///
/// The registry is checked against the commit's `registry_hash` and the
/// joiner's proof against its `tree_hash`. The occupancy list is not
/// authenticated: a wrong list makes the joiner's view diverge, which the
/// next commit it processes detects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LightJoin {
    pub registry: Registry,
    pub members: Vec<MemberRef>,
    pub joiner_proof: LeafProof,
}

impl LightJoin {
    /// The light-join data of `state` for the member in `joiner_leaf`.
    pub fn for_state(state: &PublicGroupState, joiner_leaf: u32) -> CoreResult<Self> {
        Ok(Self {
            registry: state.registry.clone(),
            members: state.tree.member_refs().collect(),
            joiner_proof: state.tree.leaf_proof(joiner_leaf)?,
        })
    }

    /// Deterministic CBOR encoding.
    pub fn encode(&self) -> CoreResult<Vec<u8>> {
        encode(&array(vec![
            text(LIGHT_JOIN_LABEL),
            bytes(&self.registry.to_cbor()?),
            array(
                self.members
                    .iter()
                    .map(|member| member.to_value())
                    .collect(),
            ),
            self.joiner_proof.to_value(),
        ]))
    }

    /// Decode an encoded light join.
    pub fn decode(encoded: &[u8]) -> CoreResult<Self> {
        let mut items = expect_array(
            decode(encoded, MAX_LIGHT_JOIN_BYTES, "light join")?,
            4,
            "light join",
        )?
        .into_iter();
        expect_label(
            &next(&mut items, "light join")?,
            LIGHT_JOIN_LABEL,
            "light join",
        )?;
        let registry = Registry::from_cbor(&expect_bytes(
            next(&mut items, "light join")?,
            "light join registry",
        )?)?;
        let members = expect_list(next(&mut items, "light join")?, "light join members")?
            .into_iter()
            .map(MemberRef::from_value)
            .collect::<CoreResult<Vec<_>>>()?;
        let joiner_proof = LeafProof::from_value(next(&mut items, "light join")?)?;
        Ok(Self {
            registry,
            members,
            joiner_proof,
        })
    }
}

/// One device's state in one group, without the public tree.
#[derive(Clone)]
pub struct LightSession {
    group_context: GroupContext,
    interim_transcript_hash: Digest,
    registry: Registry,
    /// Occupied leaves and the epoch their occupancy began.
    occupied: BTreeMap<u32, u64>,
    me: MemberRef,
    /// This member's record.
    record: LeafNode,
    private: PrivatePath,
    secrets: RetainedEpochSecrets,
    messages: EpochMessages,
    previous: VecDeque<PreviousEpoch>,
    blocked: BTreeSet<MemberRef>,
    last_own_update_epoch: u64,
    /// Device keys of members, verified against a tree hash and kept
    /// current through the commits processed since.
    known_keys: BTreeMap<MemberRef, Vec<u8>>,
}

impl core::fmt::Debug for LightSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LightSession")
            .field("epoch", &self.group_context.epoch)
            .field("leaf", &self.me.leaf)
            .field("members", &self.occupied.len())
            .finish_non_exhaustive()
    }
}

/// Everything [`GroupSession::to_light`] hands over.
pub(crate) struct LightParts {
    pub(crate) group_context: GroupContext,
    pub(crate) interim_transcript_hash: Digest,
    pub(crate) registry: Registry,
    pub(crate) occupied: BTreeMap<u32, u64>,
    pub(crate) me: MemberRef,
    pub(crate) record: LeafNode,
    pub(crate) private: PrivatePath,
    pub(crate) secrets: RetainedEpochSecrets,
    pub(crate) messages: EpochMessages,
    pub(crate) previous: VecDeque<PreviousEpoch>,
    pub(crate) blocked: BTreeSet<MemberRef>,
    pub(crate) last_own_update_epoch: u64,
}

/// Check the shape of an update path a light member cannot validate against
/// the tree: one entry per level of a tree of `width` leaves, on the
/// author's direct path, with well-formed keys and ciphertexts.
fn check_path_shape(content: &CommitContent, width: u32) -> CoreResult<()> {
    let path = &content.update_path;
    validate_public_key(&path.leaf_public_key)?;
    if path.nodes.len() != width.trailing_zeros() as usize {
        return Err(CoreError::Invalid("update path length"));
    }
    for (index, entry) in path.nodes.iter().enumerate() {
        let at_level = u32::try_from(index + 1).map_err(|_| CoreError::Invalid("update path"))?;
        if entry.node != ancestor(content.author_leaf, at_level) {
            return Err(CoreError::Invalid("update path node"));
        }
        validate_public_key(&entry.public_key)?;
        for target in &entry.targets {
            if target.kem_ciphertext.len() != KEM_CIPHERTEXT_BYTES
                || target.wrapped_secret.len() != WRAPPED_SECRET_BYTES
            {
                return Err(CoreError::Malformed("update path ciphertext"));
            }
        }
    }
    Ok(())
}

/// Check the GroupInfo published with a commit against the epoch a light
/// member derived, signed by `signer_pk` (the author's key in the new
/// epoch).
fn check_group_info(
    group_info: &[u8],
    context: &GroupContext,
    commit: &Commit,
    secrets: &EpochSecrets,
    signer_pk: &[u8],
) -> CoreResult<()> {
    let signed = SignedGroupInfo::decode_unverified(group_info)?;
    let info = signed.info();
    if &info.group_context != context
        || info.confirmation_tag != commit.confirmation_tag
        || info.signer_leaf != commit.content.author_leaf
        || info.external_public_key != secrets.external_key()?.public_key()
    {
        return Err(CoreError::Invalid("group info does not match the commit"));
    }
    signed.verify_signer_key(signer_pk)
}

impl LightSession {
    pub(crate) fn from_parts(parts: LightParts) -> Self {
        Self {
            group_context: parts.group_context,
            interim_transcript_hash: parts.interim_transcript_hash,
            registry: parts.registry,
            occupied: parts.occupied,
            me: parts.me,
            record: parts.record,
            private: parts.private,
            secrets: parts.secrets,
            messages: parts.messages,
            previous: parts.previous,
            blocked: parts.blocked,
            last_own_update_epoch: parts.last_own_update_epoch,
            known_keys: BTreeMap::new(),
        }
    }

    /// Enter a group through the welcome of a commit that included this
    /// device's join request, without the public tree: `commit` and
    /// `group_info` are the commit and its GroupInfo, `join` the light-join
    /// data of the epoch it created. The caller erases `secrets` afterwards.
    pub fn join_with_welcome(
        identity: &DeviceIdentity,
        secrets: &JoinSecrets,
        commit: &[u8],
        group_info: &[u8],
        welcome: &[u8],
        join: &LightJoin,
    ) -> CoreResult<Self> {
        let welcome = Welcome::decode(welcome)?;
        let (commit, anchor_tbs) =
            Commit::decode(commit, max_commit_bytes(join.registry.capacity()))?;
        let content = &commit.content;
        if welcome.gid != content.gid || welcome.epoch != content.epoch {
            return Err(CoreError::Invalid("welcome for another epoch"));
        }
        let requested = content
            .joins
            .iter()
            .find(|request| request.reference().ok() == Some(welcome.request_ref))
            .ok_or(CoreError::Invalid(
                "the commit does not include the request",
            ))?;
        if requested.device_pk != identity.public_key()
            || requested.encryption_key != secrets.encryption_key.public_key()
            || requested.init_key != secrets.init_key.public_key()
        {
            return Err(CoreError::Invalid("welcome for another request"));
        }
        let joiner = welcome.open(&secrets.init_key)?;
        let epoch_secrets = EpochSecrets::from_joiner_secret(&joiner)?;
        let confirmed = confirmed_transcript_hash(
            &content.prev_interim_transcript_hash,
            &anchor_tbs,
            &commit.signature,
            commit.rotation_signature.as_deref(),
        )?;
        let tag = epoch_secrets.confirmation_tag(&confirmed)?;
        if !digest_eq(&tag, &commit.confirmation_tag) {
            return Err(CoreError::Invalid("confirmation tag"));
        }
        let context = GroupContext {
            gid: content.gid,
            epoch: content.epoch,
            tree_hash: content.tree_hash,
            registry_hash: content.registry_hash,
            confirmed_transcript_hash: confirmed,
        };
        let signer_pk = content
            .new_device_pk
            .as_deref()
            .unwrap_or(&content.author_device_pk);
        check_group_info(group_info, &context, &commit, &epoch_secrets, signer_pk)?;
        if !digest_eq(&join.registry.registry_hash()?, &content.registry_hash) {
            return Err(CoreError::Invalid("light join registry"));
        }

        // This device's leaf, proven against the tree hash the commit
        // states.
        join.joiner_proof.verify(&content.tree_hash)?;
        let leaf = join.joiner_proof.leaf;
        let record = LeafNode {
            device_pk: identity.public_key().to_vec(),
            since: content.epoch,
            encryption_key: requested.encryption_key.clone(),
            admission_hash: requested.admission.hash(),
        };
        if join.joiner_proof.node.as_ref() != Some(&record) {
            return Err(CoreError::Invalid(
                "welcomed leaf does not match the request",
            ));
        }
        let me = MemberRef {
            leaf,
            since: content.epoch,
        };
        let mut occupied = BTreeMap::new();
        for member in &join.members {
            if member.since > content.epoch || occupied.insert(member.leaf, member.since).is_some()
            {
                return Err(CoreError::Invalid("light join members"));
            }
        }
        let tree = PartialTree {
            capacity: join.registry.capacity(),
            occupied,
            records: BTreeMap::new(),
        };
        if tree.occupied.get(&leaf) != Some(&content.epoch)
            || !tree.occupied.contains_key(&content.author_leaf)
            || !join
                .registry
                .admins()
                .all(|admin| tree.occupied.contains_key(&admin))
            || tree.width() > tree.capacity
        {
            return Err(CoreError::Invalid("light join members"));
        }
        check_path_shape(content, tree.width())?;

        let mut private = PrivatePath {
            leaf: Some(secrets.encryption_key.clone()),
            nodes: BTreeMap::new(),
        };
        let path_secrets = open_path(content, &private, me)?;
        private.nodes.extend(path_secrets.node_keys);

        let messages = EpochMessages::new(
            &content.gid,
            content.epoch,
            epoch_secrets.msg_secret(),
            tree.member_refs(),
            me,
        )?;
        let mut known_keys = BTreeMap::new();
        let author_since = tree
            .occupied
            .get(&content.author_leaf)
            .copied()
            .ok_or(CoreError::Invalid("light join members"))?;
        known_keys.insert(
            MemberRef {
                leaf: content.author_leaf,
                since: author_since,
            },
            signer_pk.to_vec(),
        );
        Ok(Self {
            interim_transcript_hash: interim_transcript_hash(&confirmed, &commit.confirmation_tag)?,
            group_context: context,
            registry: join.registry.clone(),
            occupied: tree.occupied,
            me,
            record,
            private,
            secrets: epoch_secrets.retained(),
            messages,
            previous: VecDeque::new(),
            blocked: BTreeSet::new(),
            last_own_update_epoch: content.epoch,
            known_keys,
        })
    }

    /// Process a commit authored by another party, with the proofs the
    /// delivery service computed for it. `group_info` is the GroupInfo
    /// published with it, checked when present.
    pub fn process_commit(
        &mut self,
        commit: &[u8],
        group_info: Option<&[u8]>,
        light: &LightCommit,
    ) -> CoreResult<ProcessedCommit> {
        let (commit, anchor_tbs) =
            Commit::decode(commit, max_commit_bytes(self.registry.capacity()))?;
        let content = &commit.content;
        let gid = self.group_context.gid;
        if content.gid != gid {
            return Err(CoreError::Invalid("commit for another group"));
        }
        let expected = self.group_context.epoch + 1;
        if content.epoch != expected {
            return Err(CoreError::EpochMismatch {
                expected,
                got: content.epoch,
            });
        }
        if !digest_eq(
            &content.prev_interim_transcript_hash,
            &self.interim_transcript_hash,
        ) {
            return Err(CoreError::TranscriptMismatch);
        }
        if content.author_leaf == self.me.leaf && content.kind != CommitKind::ExternalJoin {
            return Err(CoreError::Invalid("own commit without its pending state"));
        }

        // The records of the epoch the commit starts from that its
        // authorization refers to, proven against the current tree hash.
        let mut tree = self.partial_tree();
        for proof in &light.proofs {
            proof.verify(&self.group_context.tree_hash)?;
            let Some(node) = &proof.node else { continue };
            if self.occupied.get(&proof.leaf) != Some(&node.since)
                || (proof.leaf == self.me.leaf && node != &self.record)
            {
                return Err(CoreError::Invalid("light proof of an unknown occupancy"));
            }
            tree.records.insert(proof.leaf, node.clone());
        }
        let old_author_key = tree
            .records
            .get(&content.author_leaf)
            .map(|author| author.device_pk.clone());
        let old_author_since = self.occupied.get(&content.author_leaf).copied();

        let staged = stage_on(
            &gid,
            self.group_context.epoch,
            &tree,
            &self.registry,
            &proposed_changes(content),
        )?;
        let width = staged.tree.width();
        if width > staged.tree.capacity {
            return Err(CoreError::Invalid("the group is full"));
        }
        check_path_shape(content, width)?;
        if !digest_eq(&staged.registry.registry_hash()?, &content.registry_hash) {
            return Err(CoreError::Invalid("commit registry hash"));
        }
        let author = MemberRef {
            leaf: staged.author_leaf,
            since: staged
                .tree
                .occupied
                .get(&staged.author_leaf)
                .copied()
                .ok_or(CoreError::Invalid("commit author is not a member"))?,
        };
        let summary = CommitSummary::from_staged(content, &staged, author);
        if staged.removed.iter().any(|member| member.member == self.me) {
            return Ok(ProcessedCommit::Removed(summary));
        }

        let path_secrets = open_path(content, &self.private, self.me)?;
        let init = if content.kind.is_external() {
            let kem_output = content
                .external_init
                .as_deref()
                .ok_or(CoreError::Malformed("commit external init"))?;
            self.secrets.external_init_secret(kem_output)?
        } else {
            Zeroizing::new(*self.secrets.init_secret())
        };
        let confirmed = confirmed_transcript_hash(
            &self.interim_transcript_hash,
            &anchor_tbs,
            &commit.signature,
            commit.rotation_signature.as_deref(),
        )?;
        let context = GroupContext {
            gid,
            epoch: content.epoch,
            tree_hash: content.tree_hash,
            registry_hash: content.registry_hash,
            confirmed_transcript_hash: confirmed,
        };
        let secrets = EpochSecrets::derive(&init, &path_secrets.commit_secret, &context)?;
        let tag = secrets.confirmation_tag(&confirmed)?;
        if !digest_eq(&tag, &commit.confirmation_tag) {
            return Err(CoreError::Invalid("confirmation tag"));
        }
        let signer_pk = content
            .new_device_pk
            .as_deref()
            .unwrap_or(&content.author_device_pk);
        if let Some(group_info) = group_info {
            check_group_info(group_info, &context, &commit, &secrets, signer_pk)?;
        }

        // Private keys: nodes a removal blanked, nodes above the new root and
        // the author's path are dropped; the author's path from the common
        // ancestor up is re-keyed from the path secret.
        let root_level = width.trailing_zeros();
        let mut private = self.private.clone();
        private.nodes.retain(|node, _| {
            level(*node) <= root_level
                && !staged
                    .removed
                    .iter()
                    .any(|removed| is_ancestor_or_self(*node, leaf_node(removed.member.leaf)))
                && !content
                    .update_path
                    .nodes
                    .iter()
                    .any(|entry| entry.node == *node)
        });
        private.nodes.extend(path_secrets.node_keys);

        let rotated = content
            .new_device_pk
            .as_ref()
            .and(old_author_key.as_deref())
            .map(|old_key| (author, old_key));
        let previous = retire_epoch(&self.previous, &self.messages, rotated);
        let messages = EpochMessages::new(
            &gid,
            content.epoch,
            secrets.msg_secret(),
            staged.tree.member_refs(),
            self.me,
        )?;
        let known_keys = self.next_known_keys(&staged, content.kind, old_author_since);
        let mut blocked = self.blocked.clone();
        blocked.retain(|member| staged.tree.occupied.get(&member.leaf) == Some(&member.since));

        self.interim_transcript_hash =
            interim_transcript_hash(&confirmed, &commit.confirmation_tag)?;
        self.group_context = context;
        self.registry = staged.registry;
        self.occupied = staged.tree.occupied;
        self.private = private;
        self.secrets = secrets.retained();
        self.messages = messages;
        self.previous = previous;
        self.blocked = blocked;
        self.known_keys = known_keys;
        Ok(ProcessedCommit::Advanced(summary))
    }

    /// Device keys to keep after a commit: those of occupancies that remain,
    /// updated with every record the commit's transition knew (proven
    /// records, entries, the rotated author key).
    fn next_known_keys(
        &self,
        staged: &StagedChanges<PartialTree>,
        kind: CommitKind,
        old_author_since: Option<u64>,
    ) -> BTreeMap<MemberRef, Vec<u8>> {
        let mut known: BTreeMap<MemberRef, Vec<u8>> = self
            .known_keys
            .iter()
            .filter(|(member, _)| {
                staged.tree.occupied.get(&member.leaf) == Some(&member.since)
                    && !(kind == CommitKind::Resync
                        && member.leaf == staged.author_leaf
                        && Some(member.since) == old_author_since)
            })
            .map(|(member, key)| (*member, key.clone()))
            .collect();
        for (leaf, record) in &staged.tree.records {
            if *leaf != self.me.leaf {
                known.insert(
                    MemberRef {
                        leaf: *leaf,
                        since: record.since,
                    },
                    record.device_pk.clone(),
                );
            }
        }
        while known.len() > MAX_KNOWN_KEYS {
            known.pop_first();
        }
        known
    }

    fn partial_tree(&self) -> PartialTree {
        PartialTree {
            capacity: self.registry.capacity(),
            occupied: self.occupied.clone(),
            records: BTreeMap::from([(self.me.leaf, self.record.clone())]),
        }
    }

    /// Record the device keys of members from proofs against the current
    /// tree hash (for instance of message senders). Returns how many
    /// current occupancies the proofs showed.
    pub fn learn_members(&mut self, proofs: &[LeafProof]) -> CoreResult<usize> {
        let mut learnt = 0;
        for proof in proofs {
            proof.verify(&self.group_context.tree_hash)?;
            if let Some((member, record)) = proof.member()
                && self.occupied.get(&member.leaf) == Some(&member.since)
                && member != self.me
            {
                self.known_keys.insert(member, record.device_pk.clone());
                learnt += 1;
            }
        }
        while self.known_keys.len() > MAX_KNOWN_KEYS {
            self.known_keys.pop_first();
        }
        Ok(learnt)
    }

    /// The sender of `envelope` when it is a current member whose device
    /// key this session does not know yet: prove its leaf with
    /// [`LightSession::learn_members`] before decrypting.
    pub fn unknown_sender(&self, envelope: &[u8]) -> CoreResult<Option<MemberRef>> {
        let sender = Envelope::decode(envelope)?.header.sender;
        Ok(
            (self.is_member(sender) && sender != self.me && !self.known_keys.contains_key(&sender))
                .then_some(sender),
        )
    }

    /// Encrypt and sign an application message.
    pub fn encrypt(
        &mut self,
        identity: &DeviceIdentity,
        content_type: u64,
        authenticated_data: &[u8],
        plaintext: &[u8],
        signed_timestamp_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Vec<u8>> {
        self.check_identity(identity)?;
        self.messages.encrypt(
            identity,
            content_type,
            authenticated_data,
            plaintext,
            signed_timestamp_ms,
            rng,
        )
    }

    /// Decrypt and authenticate an envelope of the current epoch or of a
    /// previous epoch whose keys are still held. The sender must be a
    /// current member without a recorded removal whose device key this
    /// session knows.
    pub fn decrypt(&mut self, envelope: &[u8]) -> CoreResult<ReceivedMessage> {
        let envelope = Envelope::decode(envelope)?;
        let sender = envelope.header.sender;
        if !self.is_member(sender) {
            return Err(CoreError::Unauthorized("sender is not a member"));
        }
        if self.blocked.contains(&sender) {
            return Err(CoreError::Unauthorized("sender has a pending removal"));
        }
        let current_key = self
            .known_keys
            .get(&sender)
            .cloned()
            .ok_or(CoreError::Unauthorized("sender key not proven"))?;
        open_envelope(
            &mut self.messages,
            &mut self.previous,
            &envelope,
            &current_key,
        )
    }

    /// Record a removal proposal read from the delivery-service log: messages
    /// from its target are rejected from now on. The delivery service
    /// authorized the proposal; a light member checks its signature and its
    /// target. Returns the blocked member, or `None` if it does not apply.
    pub fn add_pending_removal(&mut self, proposal: &SignedRemoveProposal) -> Option<MemberRef> {
        let target = MemberRef {
            leaf: proposal.proposal().target_leaf,
            since: proposal.proposal().target_since,
        };
        (proposal.proposal().gid == self.group_context.gid && self.is_member(target)).then(|| {
            self.blocked.insert(target);
            target
        })
    }

    /// Sign this member's own leave proposal.
    pub fn propose_leave(
        &self,
        identity: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<SignedRemoveProposal> {
        self.check_identity(identity)?;
        RemoveProposal {
            gid: self.group_context.gid,
            target_leaf: self.me.leaf,
            target_since: self.me.since,
            proposer_device_pk: identity.public_key().to_vec(),
        }
        .sign(identity, rng)
    }

    /// Sign a report that the commit of `epoch` could not be processed.
    pub fn report_cover_failure(
        &self,
        identity: &DeviceIdentity,
        epoch: u64,
        reason: CoverFailureReason,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<CoverFailureReport> {
        self.check_identity(identity)?;
        CoverFailureReport::sign(&self.group_context.gid, epoch, reason, identity, rng)
    }

    /// Become a full member again with the snapshot of the current epoch
    /// (to author a commit): the snapshot must describe exactly this
    /// session's epoch, members and keys.
    pub fn upgrade(self, snapshot: &GroupSnapshot) -> CoreResult<GroupSession> {
        let (state, _) = verify_snapshot(snapshot)?;
        if state.group_context()? != self.group_context
            || !digest_eq(
                &state.interim_transcript_hash,
                &self.interim_transcript_hash,
            )
            || state.registry != self.registry
        {
            return Err(CoreError::Invalid("snapshot of another epoch"));
        }
        if !state
            .tree
            .member_refs()
            .eq(self.occupied.iter().map(|(leaf, since)| MemberRef {
                leaf: *leaf,
                since: *since,
            }))
            || state.tree.leaf(self.me.leaf) != Some(&self.record)
        {
            return Err(CoreError::Invalid("snapshot members disagree"));
        }
        let consistent = self.private.nodes.iter().all(|(node, key)| {
            state
                .tree
                .node_public_key(*node)
                .is_none_or(|public_key| public_key == key.public_key())
        }) && self
            .private
            .leaf
            .as_ref()
            .is_none_or(|key| key.public_key() == self.record.encryption_key);
        if !consistent {
            return Err(CoreError::Invalid("private keys disagree with the tree"));
        }
        GroupSession::from_light(
            state,
            self.me,
            self.private,
            self.secrets,
            self.messages,
            self.previous,
            self.blocked,
            self.last_own_update_epoch,
        )
    }

    fn check_identity(&self, identity: &DeviceIdentity) -> CoreResult<()> {
        if identity.public_key() != self.record.device_pk {
            return Err(CoreError::Invalid("identity does not own this session"));
        }
        Ok(())
    }

    fn is_member(&self, member: MemberRef) -> bool {
        self.occupied.get(&member.leaf) == Some(&member.since)
    }

    /// Group identifier.
    #[must_use]
    pub fn gid(&self) -> &Digest {
        &self.group_context.gid
    }

    /// Current epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.group_context.epoch
    }

    /// GroupContext of the current epoch.
    #[must_use]
    pub fn group_context(&self) -> &GroupContext {
        &self.group_context
    }

    /// Current registry.
    #[must_use]
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Occupancies of the current members, by leaf.
    pub fn members(&self) -> impl Iterator<Item = MemberRef> + '_ {
        self.occupied.iter().map(|(leaf, since)| MemberRef {
            leaf: *leaf,
            since: *since,
        })
    }

    /// Number of members.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.occupied.len()
    }

    /// Device key of `member`, when this session verified it.
    #[must_use]
    pub fn known_key(&self, member: MemberRef) -> Option<&[u8]> {
        if member == self.me {
            return Some(&self.record.device_pk);
        }
        self.known_keys.get(&member).map(Vec::as_slice)
    }

    /// This member's occupancy.
    #[must_use]
    pub fn me(&self) -> MemberRef {
        self.me
    }

    /// The member whose verified device key is `device_pk`.
    #[must_use]
    pub fn member_with_key(&self, device_pk: &[u8]) -> Option<MemberRef> {
        if device_pk == self.record.device_pk {
            return Some(self.me);
        }
        self.known_keys
            .iter()
            .find(|(_, key)| key.as_slice() == device_pk)
            .map(|(member, _)| *member)
    }

    /// Whether this member is an admin.
    #[must_use]
    pub fn is_admin(&self) -> bool {
        self.registry.is_admin(self.me.leaf)
    }

    /// Epochs since this member last re-keyed its own leaf.
    #[must_use]
    pub fn epochs_since_own_update(&self) -> u64 {
        self.group_context
            .epoch
            .saturating_sub(self.last_own_update_epoch)
    }

    /// Next generation this member will send in the current epoch.
    #[must_use]
    pub fn next_own_generation(&self) -> u32 {
        self.messages.next_own_generation()
    }

    /// Fingerprint of the transcript (equal for full and light members of
    /// the same epoch).
    #[must_use]
    pub fn transcript_fingerprint(&self) -> Digest {
        self.interim_transcript_hash
    }

    /// Erase the keys of every previous epoch up to `epoch`.
    pub fn expire_epochs_through(&mut self, epoch: u64) {
        self.previous
            .retain(|previous| previous.messages.epoch() > epoch);
    }

    /// Erase the keys of every previous epoch.
    pub fn expire_previous_epochs(&mut self) {
        self.previous.clear();
    }

    /// Previous epochs whose keys are still held, newest first.
    pub fn previous_epochs(&self) -> impl Iterator<Item = u64> + '_ {
        self.previous
            .iter()
            .map(|previous| previous.messages.epoch())
    }

    /// Export the session, secrets included, for encrypted persistence.
    pub fn export(&self) -> CoreResult<Zeroizing<Vec<u8>>> {
        let (private_leaf, private_nodes) = private_to_values(&self.private);
        let context = &self.group_context;
        Ok(Zeroizing::new(encode(&array(vec![
            text(LIGHT_SESSION_LABEL),
            bytes(&context.gid),
            uint(context.epoch),
            bytes(&context.tree_hash),
            bytes(&context.confirmed_transcript_hash),
            bytes(&self.interim_transcript_hash),
            bytes(&self.registry.to_cbor()?),
            array(
                self.occupied
                    .iter()
                    .map(|(leaf, since)| array(vec![uint(u64::from(*leaf)), uint(*since)]))
                    .collect(),
            ),
            self.me.to_value(),
            self.record.to_value(),
            private_leaf,
            private_nodes,
            bytes(self.secrets.init_secret()),
            bytes(self.secrets.external_secret()),
            self.messages.to_value(),
            previous_to_value(&self.previous),
            array(
                self.blocked
                    .iter()
                    .map(|member| member.to_value())
                    .collect(),
            ),
            uint(self.last_own_update_epoch),
            array(
                self.known_keys
                    .iter()
                    .map(|(member, key)| array(vec![member.to_value(), bytes(key)]))
                    .collect(),
            ),
        ]))?))
    }

    /// Restore an exported light session.
    pub fn import(encoded: &[u8]) -> CoreResult<Self> {
        let mut items = expect_array(
            decode(encoded, 64 << 20, "light session")?,
            19,
            "light session",
        )?
        .into_iter();
        let mut item = || next(&mut items, "light session");
        expect_label(&item()?, LIGHT_SESSION_LABEL, "light session")?;
        let gid = expect_bytes32(item()?, "light session gid")?;
        let epoch = expect_uint(&item()?, "light session epoch")?;
        let tree_hash = expect_bytes32(item()?, "light session tree hash")?;
        let confirmed_transcript_hash = expect_bytes32(item()?, "light session transcript")?;
        let interim_transcript_hash = expect_bytes32(item()?, "light session transcript")?;
        let registry = Registry::from_cbor(&expect_bytes(item()?, "light session registry")?)?;
        let mut occupied = BTreeMap::new();
        for entry in expect_list(item()?, "light session members")? {
            let mut fields = expect_array(entry, 2, "light session member")?.into_iter();
            let leaf = expect_u32(&next(&mut fields, "light session member")?, "member leaf")?;
            let since = expect_uint(&next(&mut fields, "light session member")?, "member since")?;
            if occupied.insert(leaf, since).is_some() {
                return Err(CoreError::Malformed("light session members"));
            }
        }
        let me = MemberRef::from_value(item()?)?;
        let record = LeafNode::from_value(item()?)?;
        let private = private_from_values(item()?, item()?)?;
        let init_secret = expect_bytes32(item()?, "light session init secret")?;
        let external_secret = expect_bytes32(item()?, "light session external secret")?;
        let messages = EpochMessages::from_value(item()?)?;
        let previous = previous_from_value(item()?)?;
        let blocked = expect_list(item()?, "light session blocked")?
            .into_iter()
            .map(MemberRef::from_value)
            .collect::<CoreResult<BTreeSet<_>>>()?;
        let last_own_update_epoch = expect_uint(&item()?, "light session update")?;
        let mut known_keys = BTreeMap::new();
        for entry in expect_list(item()?, "light session keys")? {
            let mut pair = expect_array(entry, 2, "light session key")?.into_iter();
            let member = MemberRef::from_value(next(&mut pair, "light session key")?)?;
            let key = expect_bytes(next(&mut pair, "light session key")?, "light session key")?;
            known_keys.insert(member, key);
        }
        if occupied.get(&me.leaf) != Some(&me.since)
            || record.since != me.since
            || messages.epoch() != epoch
            || known_keys.len() > MAX_KNOWN_KEYS
        {
            return Err(CoreError::Malformed("light session"));
        }
        Ok(Self {
            group_context: GroupContext {
                gid,
                epoch,
                tree_hash,
                registry_hash: registry.registry_hash()?,
                confirmed_transcript_hash,
            },
            interim_transcript_hash,
            registry,
            occupied,
            me,
            record,
            private,
            secrets: RetainedEpochSecrets::from_parts(init_secret, external_secret),
            messages,
            previous,
            blocked,
            last_own_update_epoch,
            known_keys,
        })
    }
}

/// Open the path secret of the commit's update path meant for `me` and
/// derive the keys of the author's path above it, without the tree: the
/// entry is the one of the common ancestor of the author and `me`, and the
/// target the node of `me`'s direct path whose private key `private` holds.
fn open_path(
    content: &CommitContent,
    private: &PrivatePath,
    me: MemberRef,
) -> CoreResult<PathSecrets> {
    if content.author_leaf == me.leaf {
        return Err(CoreError::Invalid("own update path"));
    }
    let index = common_ancestor_level(content.author_leaf, me.leaf) as usize - 1;
    let entry = content
        .update_path
        .nodes
        .get(index)
        .ok_or(CoreError::Invalid("member not covered by the update path"))?;
    let (target, key) = entry
        .targets
        .iter()
        .find_map(|target| {
            private
                .key_for(me.leaf, target.target)
                .map(|key| (target, key))
        })
        .ok_or(CoreError::Decrypt("no path secret for this member"))?;
    let context = PathContext {
        gid: content.gid,
        epoch: content.epoch,
        author_leaf: content.author_leaf,
    };
    decrypt_path_entry(&context, &content.update_path, index, target, key)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests;
