//! Public group state and the commit transition.
//!
//! The delivery service and every member run the same deterministic
//! transition on the public part of the state, so they agree on the tree,
//! the roster and the transcript of every epoch. Members additionally run
//! the secret part (path decryption and key schedule) in `session`.
//!
//! Order of a commit's effects on the state of epoch `n - 1`:
//! 1. removals (each authorized against roster `n - 1`, never targeting the
//!    author), which blank the removed leaves and their direct paths;
//! 2. admin changes (member commits, author admin in roster `n - 1`);
//! 3. the join of an external joiner in the lowest free slot (admission
//!    checked against the admins that remain after step 1), or the renewal of
//!    a resynchronising member's own slot;
//! 4. promotion of the lowest-slot member if no admin remains;
//! 5. the author's update path, validated against the tree of steps 1-3.

use crate::cbor::{
    array, bytes, decode, encode, expect_array, expect_bytes, expect_bytes32, expect_uint, uint,
};
use crate::commit::{AdminChange, Commit, CommitContent, CommitKind, JoinRecord, max_commit_bytes};
use crate::error::{CoreError, CoreResult};
use crate::hash::{Digest, ZERO32, digest_eq};
use crate::identity::{group_id, leaf_id};
use crate::key_schedule::{GroupContext, confirmed_transcript_hash, interim_transcript_hash};
use crate::proposal::SignedRemoveProposal;
use crate::roster::{MemberRecord, Roster};
use crate::tree::{LeafNode, MAX_N_MAX, PathContext, PublicTree, next, validate_update_path};

/// Public state of a group at one epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicGroupState {
    pub gid: Digest,
    pub epoch: u64,
    pub tree: PublicTree,
    pub roster: Roster,
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
            roster_hash: self.roster.roster_hash()?,
            confirmed_transcript_hash: self.confirmed_transcript_hash,
        })
    }

    /// Number of leaf slots of the group.
    #[must_use]
    pub fn n_max(&self) -> u32 {
        self.tree.n_max()
    }

    /// Deterministic CBOR encoding (snapshots).
    pub fn to_cbor(&self) -> CoreResult<Vec<u8>> {
        encode(&array(vec![
            bytes(&self.gid),
            uint(self.epoch),
            bytes(&self.tree.to_cbor()?),
            bytes(&self.roster.to_cbor()?),
            bytes(&self.confirmed_transcript_hash),
            bytes(&self.interim_transcript_hash),
        ]))
    }

    /// Decode a snapshot and check that its tree and roster agree.
    pub fn from_cbor(encoded: &[u8]) -> CoreResult<Self> {
        let mut items =
            expect_array(decode(encoded, 64 << 20, "group state")?, 6, "group state")?.into_iter();
        let gid = expect_bytes32(next(&mut items, "group state")?, "group state gid")?;
        let epoch = expect_uint(&next(&mut items, "group state")?, "group state epoch")?;
        let tree = PublicTree::from_cbor(&expect_bytes(
            next(&mut items, "group state")?,
            "group state tree",
        )?)?;
        let roster = Roster::from_cbor(
            &expect_bytes(next(&mut items, "group state")?, "group state roster")?,
            &gid,
        )?;
        let confirmed_transcript_hash =
            expect_bytes32(next(&mut items, "group state")?, "group state transcript")?;
        let interim_transcript_hash =
            expect_bytes32(next(&mut items, "group state")?, "group state transcript")?;
        let state = Self {
            gid,
            epoch,
            tree,
            roster,
            confirmed_transcript_hash,
            interim_transcript_hash,
        };
        state.check_consistency()?;
        Ok(state)
    }

    /// Every roster member occupies its tree leaf and vice versa.
    pub fn check_consistency(&self) -> CoreResult<()> {
        for slot in 0..self.tree.n_max() {
            match (self.tree.leaf(slot), self.roster.member_in_slot(slot)) {
                (None, None) => {}
                (Some(leaf), Some(member))
                    if leaf.leaf_id == member.leaf_id && leaf.generation == member.generation => {}
                _ => return Err(CoreError::Invalid("tree and roster disagree")),
            }
        }
        if self
            .roster
            .members()
            .any(|member| member.slot >= self.tree.n_max())
        {
            return Err(CoreError::Invalid("tree and roster disagree"));
        }
        Ok(())
    }
}

/// Membership changes of a commit, before its update path is applied.
#[derive(Clone, Debug)]
pub struct StagedChanges {
    /// Tree the author's update path is generated against.
    pub tree: PublicTree,
    /// Roster of the new epoch.
    pub roster: Roster,
    /// Slot of the commit author in the new epoch.
    pub author_slot: u32,
    /// Occupancies ended by the commit.
    pub removed: Vec<MemberRecord>,
    /// Occupancy started (join, resync or genesis) by the commit.
    pub entered: Option<MemberRecord>,
    /// Device key promoted to admin because no admin remained.
    pub promoted_admin: Option<Vec<u8>>,
}

/// The inputs of a commit that determine its membership changes.
#[derive(Clone, Copy, Debug)]
pub struct ProposedChanges<'a> {
    pub kind: CommitKind,
    pub author_device_pk: &'a [u8],
    pub removals: &'a [SignedRemoveProposal],
    pub admin_changes: &'a [AdminChange],
    pub join: Option<&'a JoinRecord>,
    /// Leaf key of the author's update path (placed in the joined slot).
    pub leaf_public_key: &'a [u8],
}

/// Slot and generation an external joiner enters after `removals`.
pub fn plan_join_slot(
    prev: &PublicGroupState,
    removals: &[SignedRemoveProposal],
) -> CoreResult<(u32, u64)> {
    let mut tree = prev.tree.clone();
    for removal in removals {
        let target = removal.authorize(&prev.gid, &prev.roster)?;
        tree.remove_leaf(target.slot)?;
    }
    let slot = tree
        .first_free_slot()
        .ok_or(CoreError::Invalid("the group is full"))?;
    Ok((slot, prev.roster.next_generation(slot)))
}

/// Apply the membership changes of a non-genesis commit to `prev`.
pub fn stage_changes(
    prev: &PublicGroupState,
    changes: &ProposedChanges<'_>,
) -> CoreResult<StagedChanges> {
    let gid = prev.gid;
    let author_leaf_id = leaf_id(&gid, changes.author_device_pk)?;
    let existing = prev.roster.member_by_leaf(&author_leaf_id).cloned();
    if let Some(existing) = &existing
        && existing.device_pk != changes.author_device_pk
    {
        return Err(CoreError::Invalid(
            "author key does not match its roster record",
        ));
    }
    match (changes.kind, &existing) {
        (CommitKind::Member | CommitKind::Resync, None) => {
            return Err(CoreError::Unauthorized("commit author is not a member"));
        }
        (CommitKind::ExternalJoin, Some(_)) => {
            return Err(CoreError::Invalid("joiner is already a member"));
        }
        (CommitKind::Genesis, _) => return Err(CoreError::Invalid("genesis after epoch 0")),
        _ => {}
    }

    let mut tree = prev.tree.clone();
    let mut roster = prev.roster.clone();
    let mut removed = Vec::with_capacity(changes.removals.len());
    for removal in changes.removals {
        let target = removal.authorize(&gid, &prev.roster)?.clone();
        if target.leaf_id == author_leaf_id {
            // The author of a commit never ends its own occupancy (C-03).
            return Err(CoreError::Unauthorized("commit author removes itself"));
        }
        roster.remove_member(target.slot, target.generation)?;
        tree.remove_leaf(target.slot)?;
        removed.push(target);
    }

    if !changes.admin_changes.is_empty() {
        if !prev.roster.is_admin(changes.author_device_pk) {
            return Err(CoreError::Unauthorized("admin change by a non-admin"));
        }
        for change in changes.admin_changes {
            match change {
                AdminChange::Grant(device_pk) => roster.grant_admin(device_pk)?,
                AdminChange::Revoke(device_pk) => roster.revoke_admin(device_pk)?,
            }
        }
    }

    let (author_slot, entered) = match (changes.kind, existing) {
        (CommitKind::Member, Some(member)) => {
            if changes.join.is_some() {
                return Err(CoreError::Malformed("commit fields for its kind"));
            }
            (member.slot, None)
        }
        (CommitKind::ExternalJoin, None) => {
            let join = changes
                .join
                .ok_or(CoreError::Malformed("commit fields for its kind"))?;
            let admission = join
                .admission
                .as_ref()
                .ok_or(CoreError::Malformed("commit fields for its kind"))?;
            if tree.first_free_slot() != Some(join.slot) {
                return Err(CoreError::Invalid("join slot is not the lowest free slot"));
            }
            if join.generation != roster.next_generation(join.slot) {
                return Err(CoreError::Invalid("join slot generation"));
            }
            admission.authorize(&gid, &author_leaf_id, &roster)?;
            let record = MemberRecord {
                leaf_id: author_leaf_id,
                device_pk: changes.author_device_pk.to_vec(),
                slot: join.slot,
                generation: join.generation,
                admission_hash: admission.hash(),
            };
            roster.add_member(record.clone())?;
            tree.add_leaf(
                join.slot,
                LeafNode {
                    leaf_id: author_leaf_id,
                    generation: join.generation,
                    public_key: changes.leaf_public_key.to_vec(),
                },
            )?;
            (join.slot, Some(record))
        }
        (CommitKind::Resync, Some(member)) => {
            let join = changes
                .join
                .ok_or(CoreError::Malformed("commit fields for its kind"))?;
            if join.admission.is_some() || join.slot != member.slot {
                return Err(CoreError::Invalid(
                    "resync must renew the author's own slot",
                ));
            }
            if join.generation != roster.next_generation(member.slot) {
                return Err(CoreError::Invalid("join slot generation"));
            }
            let record = roster.renew_generation(member.slot)?.clone();
            tree.remove_leaf(member.slot)?;
            tree.add_leaf(
                member.slot,
                LeafNode {
                    leaf_id: author_leaf_id,
                    generation: record.generation,
                    public_key: changes.leaf_public_key.to_vec(),
                },
            )?;
            (member.slot, Some(record))
        }
        _ => return Err(CoreError::Invalid("commit kind")),
    };
    let promoted_admin = roster.promote_if_adminless();
    Ok(StagedChanges {
        tree,
        roster,
        author_slot,
        removed,
        entered,
        promoted_admin,
    })
}

/// Initial membership of a new group.
pub fn stage_genesis(
    gid: &Digest,
    n_max: u32,
    creator_device_pk: &[u8],
    leaf_public_key: &[u8],
) -> CoreResult<StagedChanges> {
    if n_max > MAX_N_MAX {
        return Err(CoreError::Invalid("n_max"));
    }
    let mut tree = PublicTree::new(n_max)?;
    let roster = Roster::genesis(gid, creator_device_pk)?;
    let creator = roster
        .member_in_slot(0)
        .cloned()
        .ok_or(CoreError::Invalid("genesis roster"))?;
    tree.add_leaf(
        0,
        LeafNode {
            leaf_id: creator.leaf_id,
            generation: creator.generation,
            public_key: leaf_public_key.to_vec(),
        },
    )?;
    Ok(StagedChanges {
        tree,
        roster,
        author_slot: 0,
        removed: Vec::new(),
        entered: Some(creator),
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

fn finish(
    commit: Commit,
    anchor_tbs: Vec<u8>,
    staged: StagedChanges,
    prev_interim: &Digest,
) -> CoreResult<CommitTransition> {
    let content = &commit.content;
    validate_update_path(&staged.tree, staged.author_slot, &content.update_path)?;
    let mut tree = staged.tree.clone();
    tree.apply_update_path(staged.author_slot, &content.update_path)?;
    if !digest_eq(&tree.tree_hash()?, &content.tree_hash) {
        return Err(CoreError::Invalid("commit tree hash"));
    }
    if !digest_eq(&staged.roster.roster_hash()?, &content.roster_hash) {
        return Err(CoreError::Invalid("commit roster hash"));
    }
    let confirmed = confirmed_transcript_hash(prev_interim, &anchor_tbs, &commit.signature)?;
    let interim = interim_transcript_hash(&confirmed, &commit.confirmation_tag)?;
    let next = PublicGroupState {
        gid: content.gid,
        epoch: content.epoch,
        tree,
        roster: staged.roster.clone(),
        confirmed_transcript_hash: confirmed,
        interim_transcript_hash: interim,
    };
    let group_context = GroupContext {
        gid: content.gid,
        epoch: content.epoch,
        tree_hash: content.tree_hash,
        roster_hash: content.roster_hash,
        confirmed_transcript_hash: confirmed,
    };
    let path_context = PathContext {
        gid: content.gid,
        epoch: content.epoch,
        author_slot: staged.author_slot,
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

fn check_author(content: &CommitContent) -> CoreResult<()> {
    if content.author_leaf_id != leaf_id(&content.gid, &content.author_device_pk)? {
        return Err(CoreError::Invalid("commit author leaf id"));
    }
    Ok(())
}

/// Verify the genesis commit of a group.
pub fn verify_genesis(encoded: &[u8]) -> CoreResult<CommitTransition> {
    let (commit, anchor_tbs) = Commit::decode(encoded, max_commit_bytes(MAX_N_MAX))?;
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
    check_author(content)?;
    let nonce = content
        .group_nonce
        .ok_or(CoreError::Malformed("commit fields for its kind"))?;
    if content.gid != group_id(&content.author_device_pk, &nonce)? {
        return Err(CoreError::Invalid("gid does not bind the creator"));
    }
    let n_max = content
        .n_max
        .ok_or(CoreError::Malformed("commit fields for its kind"))?;
    let staged = stage_genesis(
        &content.gid,
        n_max,
        &content.author_device_pk,
        &content.update_path.leaf_public_key,
    )?;
    finish(commit, anchor_tbs, staged, &ZERO32)
}

/// Verify a commit on top of `prev`.
pub fn verify_commit(prev: &PublicGroupState, encoded: &[u8]) -> CoreResult<CommitTransition> {
    let (commit, anchor_tbs) = Commit::decode(encoded, max_commit_bytes(prev.n_max()))?;
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
    check_author(content)?;
    let staged = stage_changes(
        prev,
        &ProposedChanges {
            kind: content.kind,
            author_device_pk: &content.author_device_pk,
            removals: &content.removals,
            admin_changes: &content.admin_changes,
            join: content.join.as_ref(),
            leaf_public_key: &content.update_path.leaf_public_key,
        },
    )?;
    finish(commit, anchor_tbs, staged, &prev.interim_transcript_hash)
}
