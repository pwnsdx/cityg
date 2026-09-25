//! Public group state and the commit transition.
//!
//! The delivery service and every member run the same deterministic
//! transition on the public part of the state, so they agree on the tree,
//! the registry and the transcript of every epoch. Members additionally run
//! the secret part (path decryption and key schedule) in `session`.
//!
//! Order of a commit's effects on the state of epoch `n - 1`, for epoch `n`:
//! 1. retired admissions that expired before `n` are dropped;
//! 2. removals, each authorized against epoch `n - 1` and never targeting
//!    the author: the removed leaves and their direct paths are blanked, the
//!    removed members lose their admin rights and their admissions are
//!    retired;
//! 3. admin changes (member commits, by an admin of epoch `n - 1`);
//! 4. entries, each into the lowest blank leaf (the tree doubles when it is
//!    full, up to its capacity), with `since = n`: first the author of an
//!    external join, then every join request in order; the admission of each
//!    is checked against the admins and retired admissions at that point. A
//!    resynchronising author re-enters its own leaf instead;
//! 5. the rotation of the author's device key (member commits);
//! 6. promotion of the author if no admin remains;
//! 7. truncation of the tree to its canonical width;
//! 8. the author's update path, validated against the tree of steps 1-7.

use std::collections::BTreeMap;

use crate::admission::SignedAdmission;
use crate::cbor::{
    array, bytes, decode, encode, expect_array, expect_bytes, expect_bytes32, expect_uint, uint,
};
use crate::commit::{AdminChange, Commit, CommitContent, CommitKind, max_commit_bytes};
use crate::error::{CoreError, CoreResult};
use crate::hash::{Digest, ZERO32, digest_eq};
use crate::identity::{device_id, group_id};
use crate::join::SignedJoinRequest;
use crate::key_schedule::{GroupContext, confirmed_transcript_hash, interim_transcript_hash};
use crate::proposal::SignedRemoveProposal;
use crate::registry::{Membership, Registry};
use crate::tree::{
    LeafNode, MAX_CAPACITY, MemberRef, PathContext, PublicTree, canonical_width, entry_leaf_of,
    next, validate_update_path,
};

/// Public state of a group at one epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicGroupState {
    pub gid: Digest,
    pub epoch: u64,
    pub tree: PublicTree,
    pub registry: Registry,
    pub confirmed_transcript_hash: Digest,
    pub interim_transcript_hash: Digest,
}

impl PublicGroupState {
    /// `GroupContext` of the epoch.
    pub fn group_context(&self) -> CoreResult<GroupContext> {
        Ok(GroupContext {
            gid: self.gid,
            epoch: self.epoch,
            tree_hash: self.tree.tree_hash()?,
            registry_hash: self.registry.registry_hash()?,
            confirmed_transcript_hash: self.confirmed_transcript_hash,
        })
    }

    /// The membership of the epoch.
    #[must_use]
    pub fn membership(&self) -> Membership<'_> {
        Membership::new(&self.tree, &self.registry)
    }

    /// Largest number of leaves of the group.
    #[must_use]
    pub fn capacity(&self) -> u32 {
        self.registry.capacity()
    }

    /// Deterministic CBOR encoding (snapshots).
    pub fn to_cbor(&self) -> CoreResult<Vec<u8>> {
        encode(&array(vec![
            bytes(&self.gid),
            uint(self.epoch),
            bytes(&self.tree.to_cbor()?),
            bytes(&self.registry.to_cbor()?),
            bytes(&self.confirmed_transcript_hash),
            bytes(&self.interim_transcript_hash),
        ]))
    }

    /// Decode a snapshot and check that its tree and registry agree.
    pub fn from_cbor(encoded: &[u8]) -> CoreResult<Self> {
        let mut items =
            expect_array(decode(encoded, 80 << 20, "group state")?, 6, "group state")?.into_iter();
        let gid = expect_bytes32(next(&mut items, "group state")?, "group state gid")?;
        let epoch = expect_uint(&next(&mut items, "group state")?, "group state epoch")?;
        let tree = PublicTree::from_cbor(&expect_bytes(
            next(&mut items, "group state")?,
            "group state tree",
        )?)?;
        let registry = Registry::from_cbor(&expect_bytes(
            next(&mut items, "group state")?,
            "group state registry",
        )?)?;
        let confirmed_transcript_hash =
            expect_bytes32(next(&mut items, "group state")?, "group state transcript")?;
        let interim_transcript_hash =
            expect_bytes32(next(&mut items, "group state")?, "group state transcript")?;
        let state = Self {
            gid,
            epoch,
            tree,
            registry,
            confirmed_transcript_hash,
            interim_transcript_hash,
        };
        state.check_consistency()?;
        Ok(state)
    }

    /// The tree is well formed, has the registry's capacity, every admin
    /// leaf holds a member and at least one admin exists.
    pub fn check_consistency(&self) -> CoreResult<()> {
        check_tree_and_registry(&self.tree, &self.registry)
    }
}

/// Invariants shared by every epoch: see [`PublicGroupState::check_consistency`].
pub fn check_tree_and_registry(tree: &PublicTree, registry: &Registry) -> CoreResult<()> {
    tree.check_well_formed()?;
    if tree.capacity() != registry.capacity() {
        return Err(CoreError::Invalid("tree and registry disagree"));
    }
    if !registry.has_admin() || registry.admins().any(|leaf| tree.leaf(leaf).is_none()) {
        return Err(CoreError::Invalid("tree and registry disagree"));
    }
    Ok(())
}

/// A member whose occupancy a commit ends or starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberChange {
    pub member: MemberRef,
    pub device_pk: Vec<u8>,
}

/// What the commit transition needs from a tree. The full [`PublicTree`]
/// implements it, and so does the [`PartialTree`] of a light member, so
/// both run the same transition rules.
pub trait StageTree: Clone {
    /// Membership of this tree with `registry`.
    fn membership<'a>(&'a self, registry: &'a Registry) -> Membership<'a>;
    /// Record of the member in `leaf`, if known.
    fn record(&self, leaf: u32) -> Option<&LeafNode>;
    /// Whether `leaf` is occupied since epoch `since`.
    fn has_member(&self, leaf: u32, since: u64) -> bool;
    /// Leaf of a known member whose device key is `device_pk`.
    fn find_device(&self, device_pk: &[u8]) -> Option<u32>;
    /// Leaf the next entering member takes.
    fn entry_leaf(&self) -> Option<u32>;
    /// Place a member in the blank `leaf`.
    fn add_leaf(&mut self, leaf: u32, member: LeafNode) -> CoreResult<()>;
    /// Start a new occupancy of the occupied `leaf`.
    fn replace_leaf(&mut self, leaf: u32, member: LeafNode) -> CoreResult<()>;
    /// End the occupancy of `leaf`.
    fn remove_leaf(&mut self, leaf: u32) -> CoreResult<()>;
    /// Rotate the device key of the member in `leaf`.
    fn set_device_key(&mut self, leaf: u32, device_pk: &[u8]) -> CoreResult<()>;
    /// Shrink to the canonical width.
    fn truncate(&mut self);
}

impl StageTree for PublicTree {
    fn membership<'a>(&'a self, registry: &'a Registry) -> Membership<'a> {
        Membership::new(self, registry)
    }

    fn record(&self, leaf: u32) -> Option<&LeafNode> {
        self.leaf(leaf)
    }

    fn has_member(&self, leaf: u32, since: u64) -> bool {
        self.member(leaf, since).is_some()
    }

    fn find_device(&self, device_pk: &[u8]) -> Option<u32> {
        PublicTree::find_device(self, device_pk)
    }

    fn entry_leaf(&self) -> Option<u32> {
        PublicTree::entry_leaf(self)
    }

    fn add_leaf(&mut self, leaf: u32, member: LeafNode) -> CoreResult<()> {
        PublicTree::add_leaf(self, leaf, member)
    }

    fn replace_leaf(&mut self, leaf: u32, member: LeafNode) -> CoreResult<()> {
        PublicTree::replace_leaf(self, leaf, member)
    }

    fn remove_leaf(&mut self, leaf: u32) -> CoreResult<()> {
        PublicTree::remove_leaf(self, leaf).map(|_| ())
    }

    fn set_device_key(&mut self, leaf: u32, device_pk: &[u8]) -> CoreResult<()> {
        PublicTree::set_device_key(self, leaf, device_pk)
    }

    fn truncate(&mut self) {
        PublicTree::truncate(self);
    }
}

/// The tree as a light member sees it: which leaves are occupied since
/// when, and the records it verified (with Merkle proofs) or learnt from the
/// commits it processed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialTree {
    pub capacity: u32,
    /// Occupied leaves and the epoch their occupancy began.
    pub occupied: BTreeMap<u32, u64>,
    /// Known member records, by leaf.
    pub records: BTreeMap<u32, LeafNode>,
}

impl PartialTree {
    /// Canonical width of the tree: the smallest power of two covering the
    /// rightmost occupied leaf.
    #[must_use]
    pub fn width(&self) -> u32 {
        canonical_width(self.occupied.keys().copied())
    }

    /// Occupancies of the members, by leaf.
    pub fn member_refs(&self) -> impl Iterator<Item = MemberRef> + '_ {
        self.occupied.iter().map(|(leaf, since)| MemberRef {
            leaf: *leaf,
            since: *since,
        })
    }
}

impl StageTree for PartialTree {
    fn membership<'a>(&'a self, registry: &'a Registry) -> Membership<'a> {
        Membership::proven(&self.records, registry)
    }

    fn record(&self, leaf: u32) -> Option<&LeafNode> {
        self.records.get(&leaf)
    }

    fn has_member(&self, leaf: u32, since: u64) -> bool {
        self.occupied.get(&leaf) == Some(&since)
    }

    fn find_device(&self, device_pk: &[u8]) -> Option<u32> {
        self.records
            .iter()
            .find(|(_, member)| member.device_pk == device_pk)
            .map(|(leaf, _)| *leaf)
    }

    fn entry_leaf(&self) -> Option<u32> {
        entry_leaf_of(self.occupied.keys().copied(), self.capacity)
    }

    fn add_leaf(&mut self, leaf: u32, member: LeafNode) -> CoreResult<()> {
        if leaf >= self.capacity {
            return Err(CoreError::Invalid("the group is full"));
        }
        if self.occupied.contains_key(&leaf) {
            return Err(CoreError::Invalid("leaf already occupied"));
        }
        self.occupied.insert(leaf, member.since);
        self.records.insert(leaf, member);
        Ok(())
    }

    fn replace_leaf(&mut self, leaf: u32, member: LeafNode) -> CoreResult<()> {
        if !self.occupied.contains_key(&leaf) {
            return Err(CoreError::Invalid("leaf is blank"));
        }
        self.occupied.insert(leaf, member.since);
        self.records.insert(leaf, member);
        Ok(())
    }

    fn remove_leaf(&mut self, leaf: u32) -> CoreResult<()> {
        self.occupied
            .remove(&leaf)
            .ok_or(CoreError::Invalid("leaf is blank"))?;
        self.records.remove(&leaf);
        Ok(())
    }

    fn set_device_key(&mut self, leaf: u32, device_pk: &[u8]) -> CoreResult<()> {
        let member = self
            .records
            .get_mut(&leaf)
            .ok_or(CoreError::Invalid("leaf record unknown"))?;
        member.device_pk = device_pk.to_vec();
        Ok(())
    }

    fn truncate(&mut self) {}
}

/// Membership changes of a commit, before its update path is applied.
#[derive(Clone, Debug)]
pub struct StagedChanges<T = PublicTree> {
    /// Tree the author's update path is generated against.
    pub tree: T,
    /// Registry of the new epoch.
    pub registry: Registry,
    /// Leaf of the commit author in the new epoch.
    pub author_leaf: u32,
    /// Occupancies ended by the commit.
    pub removed: Vec<MemberChange>,
    /// Occupancy started by the author (genesis, external join, resync).
    pub author_entry: Option<MemberChange>,
    /// Occupancies started by the join requests, in order.
    pub joined: Vec<MemberChange>,
    /// Leaf promoted to admin because no admin remained.
    pub promoted_admin: Option<u32>,
}

/// The inputs of a commit that determine its membership changes.
#[derive(Clone, Copy, Debug)]
pub struct ProposedChanges<'a> {
    pub kind: CommitKind,
    pub author_leaf: u32,
    pub author_device_pk: &'a [u8],
    pub removals: &'a [SignedRemoveProposal],
    pub joins: &'a [SignedJoinRequest],
    pub admin_changes: &'a [AdminChange],
    /// Admission of the author of an external join.
    pub admission: Option<&'a SignedAdmission>,
    /// New device key of the author (member commits).
    pub new_device_pk: Option<&'a [u8]>,
    /// Leaf key of the author's update path (placed in an entered leaf).
    pub leaf_public_key: &'a [u8],
}

/// Leaf the author of an external join on `prev` enters, after `removals`.
pub fn plan_entry_leaf(
    prev: &PublicGroupState,
    removals: &[SignedRemoveProposal],
) -> CoreResult<u32> {
    let mut tree = prev.tree.clone();
    for removal in removals {
        removal.authorize(&prev.gid, &prev.membership())?;
        tree.remove_leaf(removal.proposal().target_leaf)?;
    }
    tree.entry_leaf()
        .ok_or(CoreError::Invalid("the group is full"))
}

/// Apply the membership changes of a non-genesis commit for epoch
/// `prev.epoch + 1` to `prev`.
pub fn stage_changes(
    prev: &PublicGroupState,
    changes: &ProposedChanges<'_>,
) -> CoreResult<StagedChanges> {
    stage_on(&prev.gid, prev.epoch, &prev.tree, &prev.registry, changes)
}

/// Apply the membership changes of a non-genesis commit for epoch
/// `epoch + 1` of group `gid` to `prev_tree` and `prev_registry` (the
/// transition every party runs, on a full or a partial tree).
pub fn stage_on<T: StageTree>(
    gid: &Digest,
    epoch: u64,
    prev_tree: &T,
    prev_registry: &Registry,
    changes: &ProposedChanges<'_>,
) -> CoreResult<StagedChanges<T>> {
    let gid = *gid;
    let prev_membership = prev_tree.membership(prev_registry);
    let epoch = epoch + 1;
    let author_leaf = changes.author_leaf;
    let author = prev_tree.record(author_leaf);
    match changes.kind {
        CommitKind::Member | CommitKind::Resync => {
            let author = author.ok_or(CoreError::Unauthorized("commit author is not a member"))?;
            if author.device_pk != changes.author_device_pk {
                return Err(CoreError::Unauthorized(
                    "commit author key does not match its leaf",
                ));
            }
        }
        CommitKind::ExternalJoin => {
            if prev_tree.find_device(changes.author_device_pk).is_some() {
                return Err(CoreError::Invalid("joiner is already a member"));
            }
        }
        CommitKind::Genesis => return Err(CoreError::Invalid("genesis after epoch 0")),
    }
    let own_leaf = changes.kind != CommitKind::ExternalJoin;

    let mut tree = prev_tree.clone();
    let mut registry = prev_registry.clone();
    registry.prune(epoch);

    let mut removed = Vec::with_capacity(changes.removals.len());
    for removal in changes.removals {
        let target = removal.authorize(&gid, &prev_membership)?;
        let leaf = removal.proposal().target_leaf;
        if own_leaf && leaf == author_leaf {
            // The author of a commit never ends its own occupancy (C-03).
            return Err(CoreError::Unauthorized("commit author removes itself"));
        }
        removed.push(MemberChange {
            member: MemberRef {
                leaf,
                since: target.since,
            },
            device_pk: target.device_pk.clone(),
        });
        registry.retire(&target.admission_hash, target.since, epoch);
        registry.forget_leaf(leaf);
        tree.remove_leaf(leaf)?;
    }

    if !changes.admin_changes.is_empty() {
        if !prev_registry.is_admin(author_leaf) {
            return Err(CoreError::Unauthorized("admin change by a non-admin"));
        }
        for change in changes.admin_changes {
            let (leaf, since) = change.target();
            if !tree.has_member(leaf, since) {
                return Err(CoreError::Invalid("admin change target is not a member"));
            }
            match change {
                AdminChange::Grant { .. } => registry.grant_admin(leaf)?,
                AdminChange::Revoke { .. } => registry.revoke_admin(leaf)?,
            }
        }
    }

    let author_entry = match changes.kind {
        CommitKind::ExternalJoin => {
            let admission = changes
                .admission
                .ok_or(CoreError::Malformed("commit fields for its kind"))?;
            let device = device_id(&gid, changes.author_device_pk)?;
            admission.authorize(&gid, &device, epoch, &tree.membership(&registry))?;
            let leaf = tree
                .entry_leaf()
                .ok_or(CoreError::Invalid("the group is full"))?;
            if leaf != author_leaf {
                return Err(CoreError::Invalid("join leaf is not the entry leaf"));
            }
            tree.add_leaf(
                leaf,
                LeafNode {
                    device_pk: changes.author_device_pk.to_vec(),
                    since: epoch,
                    encryption_key: changes.leaf_public_key.to_vec(),
                    admission_hash: admission.hash(),
                },
            )?;
            Some(MemberChange {
                member: MemberRef { leaf, since: epoch },
                device_pk: changes.author_device_pk.to_vec(),
            })
        }
        CommitKind::Resync => {
            let current = tree
                .record(author_leaf)
                .cloned()
                .ok_or(CoreError::Unauthorized("commit author is not a member"))?;
            tree.replace_leaf(
                author_leaf,
                LeafNode {
                    since: epoch,
                    encryption_key: changes.leaf_public_key.to_vec(),
                    ..current
                },
            )?;
            Some(MemberChange {
                member: MemberRef {
                    leaf: author_leaf,
                    since: epoch,
                },
                device_pk: changes.author_device_pk.to_vec(),
            })
        }
        _ => None,
    };

    let mut joined = Vec::with_capacity(changes.joins.len());
    for request in changes.joins {
        request.authorize(&gid, epoch, &tree.membership(&registry))?;
        let leaf = tree
            .entry_leaf()
            .ok_or(CoreError::Invalid("the group is full"))?;
        tree.add_leaf(
            leaf,
            LeafNode {
                device_pk: request.device_pk.clone(),
                since: epoch,
                encryption_key: request.encryption_key.clone(),
                admission_hash: request.admission.hash(),
            },
        )?;
        joined.push(MemberChange {
            member: MemberRef { leaf, since: epoch },
            device_pk: request.device_pk.clone(),
        });
    }

    if let Some(new_device_pk) = changes.new_device_pk {
        if changes.kind != CommitKind::Member {
            return Err(CoreError::Malformed("commit fields for its kind"));
        }
        if tree.find_device(new_device_pk).is_some() {
            return Err(CoreError::Invalid("new device key is already in the group"));
        }
        tree.set_device_key(author_leaf, new_device_pk)?;
    }

    let promoted_admin = if registry.has_admin() {
        None
    } else {
        registry.grant_admin(author_leaf)?;
        Some(author_leaf)
    };
    tree.truncate();
    Ok(StagedChanges {
        tree,
        registry,
        author_leaf,
        removed,
        author_entry,
        joined,
        promoted_admin,
    })
}

/// Initial membership of a new group.
pub fn stage_genesis(
    capacity: u32,
    creator_device_pk: &[u8],
    leaf_public_key: &[u8],
) -> CoreResult<StagedChanges> {
    let mut tree = PublicTree::new(capacity)?;
    let registry = Registry::genesis(capacity)?;
    tree.add_leaf(
        0,
        LeafNode {
            device_pk: creator_device_pk.to_vec(),
            since: 0,
            encryption_key: leaf_public_key.to_vec(),
            admission_hash: ZERO32,
        },
    )?;
    Ok(StagedChanges {
        tree,
        registry,
        author_leaf: 0,
        removed: Vec::new(),
        author_entry: Some(MemberChange {
            member: MemberRef { leaf: 0, since: 0 },
            device_pk: creator_device_pk.to_vec(),
        }),
        joined: Vec::new(),
        promoted_admin: None,
    })
}

/// A verified commit and the public state it produces.
#[derive(Clone, Debug)]
pub struct CommitTransition {
    pub commit: Commit,
    pub anchor_tbs: Vec<u8>,
    pub staged: StagedChanges,
    pub path_context: PathContext,
    pub next: PublicGroupState,
    pub group_context: GroupContext,
}

impl CommitTransition {
    /// Occupancy of the commit's author in the new epoch.
    #[must_use]
    pub fn author(&self) -> MemberRef {
        let leaf = self.staged.author_leaf;
        MemberRef {
            leaf,
            since: self.next.tree.leaf(leaf).map_or(0, |member| member.since),
        }
    }
}

fn finish(
    commit: Commit,
    anchor_tbs: Vec<u8>,
    staged: StagedChanges,
    prev_interim: &Digest,
) -> CoreResult<CommitTransition> {
    let content = &commit.content;
    validate_update_path(&staged.tree, staged.author_leaf, &content.update_path)?;
    let mut tree = staged.tree.clone();
    tree.apply_update_path(staged.author_leaf, &content.update_path)?;
    if !digest_eq(&tree.tree_hash()?, &content.tree_hash) {
        return Err(CoreError::Invalid("commit tree hash"));
    }
    if !digest_eq(&staged.registry.registry_hash()?, &content.registry_hash) {
        return Err(CoreError::Invalid("commit registry hash"));
    }
    let confirmed = confirmed_transcript_hash(
        prev_interim,
        &anchor_tbs,
        &commit.signature,
        commit.rotation_signature.as_deref(),
    )?;
    let interim = interim_transcript_hash(&confirmed, &commit.confirmation_tag)?;
    let next = PublicGroupState {
        gid: content.gid,
        epoch: content.epoch,
        tree,
        registry: staged.registry.clone(),
        confirmed_transcript_hash: confirmed,
        interim_transcript_hash: interim,
    };
    let group_context = GroupContext {
        gid: content.gid,
        epoch: content.epoch,
        tree_hash: content.tree_hash,
        registry_hash: content.registry_hash,
        confirmed_transcript_hash: confirmed,
    };
    let path_context = PathContext {
        gid: content.gid,
        epoch: content.epoch,
        author_leaf: staged.author_leaf,
    };
    Ok(CommitTransition {
        commit,
        anchor_tbs,
        staged,
        path_context,
        next,
        group_context,
    })
}

/// Verify the genesis commit of a group.
pub fn verify_genesis(encoded: &[u8]) -> CoreResult<CommitTransition> {
    let (commit, anchor_tbs) = Commit::decode(encoded, max_commit_bytes(MAX_CAPACITY))?;
    let content = &commit.content;
    if content.kind != CommitKind::Genesis {
        return Err(CoreError::Invalid("first commit is not a genesis"));
    }
    if content.epoch != 0 {
        return Err(CoreError::EpochMismatch {
            expected: 0,
            got: content.epoch,
        });
    }
    if content.prev_interim_transcript_hash != ZERO32 {
        return Err(CoreError::TranscriptMismatch);
    }
    let nonce = content
        .group_nonce
        .ok_or(CoreError::Malformed("commit fields for its kind"))?;
    if content.gid != group_id(&content.author_device_pk, &nonce)? {
        return Err(CoreError::Invalid("gid does not bind the creator"));
    }
    let capacity = content
        .capacity
        .ok_or(CoreError::Malformed("commit fields for its kind"))?;
    let staged = stage_genesis(
        capacity,
        &content.author_device_pk,
        &content.update_path.leaf_public_key,
    )?;
    finish(commit, anchor_tbs, staged, &ZERO32)
}

/// Verify a commit on top of `prev`.
pub fn verify_commit(prev: &PublicGroupState, encoded: &[u8]) -> CoreResult<CommitTransition> {
    let (commit, anchor_tbs) = Commit::decode(encoded, max_commit_bytes(prev.capacity()))?;
    let content = &commit.content;
    if content.gid != prev.gid {
        return Err(CoreError::Invalid("commit for another group"));
    }
    let expected = prev.epoch + 1;
    if content.epoch != expected {
        return Err(CoreError::EpochMismatch {
            expected,
            got: content.epoch,
        });
    }
    if !digest_eq(
        &content.prev_interim_transcript_hash,
        &prev.interim_transcript_hash,
    ) {
        return Err(CoreError::TranscriptMismatch);
    }
    let staged = stage_changes(prev, &proposed_changes(content))?;
    finish(commit, anchor_tbs, staged, &prev.interim_transcript_hash)
}

/// The [`ProposedChanges`] a commit content states.
#[must_use]
pub fn proposed_changes(content: &CommitContent) -> ProposedChanges<'_> {
    ProposedChanges {
        kind: content.kind,
        author_leaf: content.author_leaf,
        author_device_pk: &content.author_device_pk,
        removals: &content.removals,
        joins: &content.joins,
        admin_changes: &content.admin_changes,
        admission: content.admission.as_ref(),
        new_device_pk: content.new_device_pk.as_deref(),
        leaf_public_key: &content.update_path.leaf_public_key,
    }
}
