//! Member state machine.
//!
//! A [`GroupSession`] holds everything one device knows about one group at
//! its current epoch: the public state, its private tree keys, the secrets
//! it keeps for the epoch and the message ratchets. It performs no I/O: the
//! application publishes the commits it builds, feeds it the commits and
//! envelopes the delivery service relays, in log order, and persists
//! [`GroupSession::export`] under its own at-rest protection.
//!
//! Commits built by this member become effective only once the delivery
//! service accepted them: [`GroupSession::commit`] returns a
//! [`PendingCommit`] that [`GroupSession::apply_own_commit`] installs after
//! acceptance, and that is dropped if another commit won the epoch.

use std::collections::{BTreeMap, BTreeSet};

use ciborium::value::Value;
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::admission::{Invite, SignedAdmission, SignedInvite};
use crate::cbor::{
    array, bytes, decode, encode, expect_array, expect_bytes, expect_bytes32, expect_label,
    expect_list, expect_u32, expect_uint, text, uint,
};
use crate::commit::{AdminChange, Commit, CommitContent, CommitKind, JoinRecord};
use crate::cover::{CoverFailureReason, CoverFailureReport};
use crate::error::{CoreError, CoreResult};
use crate::group_info::{GroupInfo, SignedGroupInfo};
use crate::hash::{Digest, ZERO32, digest_eq};
use crate::identity::{DeviceIdentity, group_id, leaf_id};
use crate::kem::KemSecret;
use crate::key_schedule::{
    EpochSecrets, GroupContext, RetainedEpochSecrets, commit_secret, confirmed_transcript_hash,
    external_init,
};
use crate::message::{Envelope, EpochMessages, ReceivedMessage};
use crate::proposal::{RemoveProposal, SignedRemoveProposal};
use crate::roster::{MemberRecord, Roster};
use crate::state::{
    CommitTransition, ProposedChanges, PublicGroupState, plan_join_slot, stage_changes,
    stage_genesis, verify_commit, verify_genesis,
};
use crate::tree::{
    PrivatePath, PublicTree, decrypt_update_path, generate_update_path_from_leaf_secret,
    leaf_key_from_secret, new_leaf_secret, next,
};

/// Label of an exported session.
const SESSION_LABEL: &str = "city-g/session/v2";

/// A commit ready to be published: the commit and the GroupInfo of the
/// epoch it creates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedCommit {
    pub epoch: u64,
    pub commit: Vec<u8>,
    pub group_info: Vec<u8>,
}

/// State of the epoch a commit built by this member creates.
#[derive(Debug)]
pub struct PendingCommit {
    base_epoch: Option<u64>,
    session: Box<GroupSession>,
}

impl PendingCommit {
    /// Epoch the commit creates.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.session.epoch()
    }

    /// Group of the commit.
    #[must_use]
    pub fn gid(&self) -> &Digest {
        self.session.gid()
    }

    /// Session of a group this device creates, joins or resynchronises
    /// (external commits and genesis only; member commits go through
    /// [`GroupSession::apply_own_commit`]).
    pub fn into_session(self) -> CoreResult<GroupSession> {
        if self.base_epoch.is_some() {
            return Err(CoreError::Invalid(
                "member commits are applied to their session",
            ));
        }
        Ok(*self.session)
    }
}

/// What a joiner fetches from the delivery service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupSnapshot {
    pub group_info: Vec<u8>,
    pub tree: Vec<u8>,
    pub roster: Vec<u8>,
}

/// Verify a snapshot: the GroupInfo signer is a member of the roster, and
/// tree and roster match the GroupContext it signed.
pub fn verify_snapshot(snapshot: &GroupSnapshot) -> CoreResult<(PublicGroupState, GroupInfo)> {
    let signed = SignedGroupInfo::decode_unverified(&snapshot.group_info)?;
    let info = signed.info().clone();
    let context = &info.group_context;
    let tree = PublicTree::from_cbor(&snapshot.tree)?;
    let roster = Roster::from_cbor(&snapshot.roster, &context.gid)?;
    signed.verify(&tree, &roster)?;
    let state = PublicGroupState {
        gid: context.gid,
        epoch: context.epoch,
        tree,
        roster,
        confirmed_transcript_hash: context.confirmed_transcript_hash,
        interim_transcript_hash: info.interim_transcript_hash()?,
    };
    state.check_consistency()?;
    Ok((state, info))
}

/// Summary of an accepted commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitSummary {
    pub epoch: u64,
    pub kind: CommitKind,
    pub author_leaf_id: Digest,
    pub author_device_pk: Vec<u8>,
    pub removed: Vec<MemberRecord>,
    pub entered: Option<MemberRecord>,
    pub admin_changes: Vec<AdminChange>,
    pub promoted_admin: Option<Vec<u8>>,
}

impl CommitSummary {
    fn from_transition(transition: &CommitTransition) -> Self {
        let content = &transition.commit.content;
        Self {
            epoch: content.epoch,
            kind: content.kind,
            author_leaf_id: content.author_leaf_id,
            author_device_pk: content.author_device_pk.clone(),
            removed: transition.staged.removed.clone(),
            entered: transition.staged.entered.clone(),
            admin_changes: content.admin_changes.clone(),
            promoted_admin: transition.staged.promoted_admin.clone(),
        }
    }
}

/// Outcome of processing another member's commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessedCommit {
    /// The session moved to the new epoch.
    Advanced(CommitSummary),
    /// The commit removed this member; the session must be discarded.
    Removed(CommitSummary),
}

#[derive(Clone, Debug)]
struct PreviousEpoch {
    roster: Roster,
    messages: EpochMessages,
}

struct Plan<'a> {
    kind: CommitKind,
    prev: Option<&'a PublicGroupState>,
    prev_init_secret: Zeroizing<[u8; 32]>,
    external_init: Option<Vec<u8>>,
    removals: Vec<SignedRemoveProposal>,
    admin_changes: Vec<AdminChange>,
    join: Option<JoinRecord>,
    genesis: Option<(Digest, u32)>,
}

/// One device's state in one group.
#[derive(Clone)]
pub struct GroupSession {
    state: PublicGroupState,
    group_context: GroupContext,
    my_leaf_id: Digest,
    my_slot: u32,
    private: PrivatePath,
    secrets: RetainedEpochSecrets,
    messages: EpochMessages,
    previous: Option<PreviousEpoch>,
    blocked: BTreeSet<Digest>,
    last_own_update_epoch: u64,
}

impl core::fmt::Debug for GroupSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GroupSession")
            .field("epoch", &self.state.epoch)
            .field("slot", &self.my_slot)
            .field("members", &self.state.roster.len())
            .finish_non_exhaustive()
    }
}

fn build(
    identity: &DeviceIdentity,
    plan: Plan<'_>,
    rng: &mut impl CryptoRngCore,
) -> CoreResult<(PendingCommit, PublishedCommit)> {
    let author_device_pk = identity.public_key();
    let leaf_secret = new_leaf_secret(rng);
    let leaf_public_key = leaf_key_from_secret(&leaf_secret)?.public_key();
    let (gid, epoch, staged, prev_interim) = match (plan.genesis, plan.prev) {
        (Some((nonce, n_max)), None) => {
            let gid = group_id(author_device_pk, &nonce)?;
            let staged = stage_genesis(&gid, n_max, author_device_pk, &leaf_public_key)?;
            (gid, 0, staged, ZERO32)
        }
        (None, Some(prev)) => {
            let staged = stage_changes(
                prev,
                &ProposedChanges {
                    kind: plan.kind,
                    author_device_pk,
                    removals: &plan.removals,
                    admin_changes: &plan.admin_changes,
                    join: plan.join.as_ref(),
                    leaf_public_key: &leaf_public_key,
                },
            )?;
            (
                prev.gid,
                prev.epoch + 1,
                staged,
                prev.interim_transcript_hash,
            )
        }
        _ => return Err(CoreError::Invalid("commit plan")),
    };
    let path_context = crate::tree::PathContext {
        gid,
        epoch,
        author_slot: staged.author_slot,
    };
    let (update_path, path_secrets) =
        generate_update_path_from_leaf_secret(&staged.tree, &path_context, &leaf_secret, rng)?;
    let mut tree = staged.tree.clone();
    tree.apply_update_path(staged.author_slot, &update_path)?;
    let content = CommitContent {
        gid,
        epoch,
        kind: plan.kind,
        prev_interim_transcript_hash: prev_interim,
        author_leaf_id: leaf_id(&gid, author_device_pk)?,
        author_device_pk: author_device_pk.to_vec(),
        roster_hash: staged.roster.roster_hash()?,
        tree_hash: tree.tree_hash()?,
        update_path,
        removals: plan.removals,
        admin_changes: plan.admin_changes,
        join: plan.join,
        external_init: plan.external_init,
        group_nonce: plan.genesis.map(|(nonce, _)| nonce),
        n_max: plan.genesis.map(|(_, n_max)| n_max),
    };
    let anchor_tbs = content.tbs()?;
    let signature = content.sign(identity, rng)?;
    let confirmed = confirmed_transcript_hash(&prev_interim, &anchor_tbs, &signature)?;
    let context = GroupContext {
        gid,
        epoch,
        tree_hash: content.tree_hash,
        roster_hash: content.roster_hash,
        confirmed_transcript_hash: confirmed,
    };
    let commit_secret = commit_secret(&path_secrets.root_secret)?;
    let secrets = EpochSecrets::derive(&plan.prev_init_secret, &commit_secret, &context)?;
    let confirmation_tag = secrets.confirmation_tag(&confirmed)?;
    let encoded = Commit {
        content,
        signature,
        confirmation_tag,
    }
    .encode()?;

    // Run the transition every other party runs on the published bytes, so
    // the local state is exactly the one they compute.
    let transition = match plan.prev {
        None => verify_genesis(&encoded)?,
        Some(prev) => verify_commit(prev, &encoded)?,
    };
    if transition.group_context != context {
        return Err(CoreError::Invalid(
            "commit does not reproduce its own context",
        ));
    }
    let private = PrivatePath {
        leaf: path_secrets.leaf_key,
        nodes: path_secrets.node_keys,
    };
    let my_leaf_id = identity.leaf_id(&gid)?;
    let group_info = GroupInfo {
        group_context: context,
        confirmation_tag,
        external_public_key: secrets.external_key()?.public_key(),
        signer_leaf_id: my_leaf_id,
    }
    .sign(identity, rng)?;
    let mut session = GroupSession::activate(transition.next, &secrets, private, &my_leaf_id)?;
    session.last_own_update_epoch = epoch;
    Ok((
        PendingCommit {
            base_epoch: plan
                .prev
                .filter(|_| plan.kind == CommitKind::Member)
                .map(|prev| prev.epoch),
            session: Box::new(session),
        },
        PublishedCommit {
            epoch,
            commit: encoded,
            group_info: group_info.encoded().to_vec(),
        },
    ))
}

impl GroupSession {
    fn activate(
        state: PublicGroupState,
        secrets: &EpochSecrets,
        mut private: PrivatePath,
        my_leaf_id: &Digest,
    ) -> CoreResult<Self> {
        let my_slot = state
            .roster
            .member_by_leaf(my_leaf_id)
            .map(|member| member.slot)
            .ok_or(CoreError::Invalid("this device is not a member"))?;
        private.retain_live(&state.tree);
        let messages = EpochMessages::new(
            &state.gid,
            state.epoch,
            secrets.msg_secret(),
            &state.roster,
            my_leaf_id,
        )?;
        Ok(Self {
            group_context: state.group_context()?,
            state,
            my_leaf_id: *my_leaf_id,
            my_slot,
            private,
            secrets: secrets.retained(),
            messages,
            previous: None,
            blocked: BTreeSet::new(),
            last_own_update_epoch: 0,
        })
    }

    /// Create a group of `n_max` slots with this device as its first member
    /// and admin. The session is usable once the delivery service accepted
    /// the genesis commit ([`PendingCommit::into_session`]).
    pub fn create(
        identity: &DeviceIdentity,
        n_max: u32,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<(PendingCommit, PublishedCommit)> {
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        build(
            identity,
            Plan {
                kind: CommitKind::Genesis,
                prev: None,
                prev_init_secret: Zeroizing::new(ZERO32),
                external_init: None,
                removals: Vec::new(),
                admin_changes: Vec::new(),
                join: None,
                genesis: Some((nonce, n_max)),
            },
            rng,
        )
    }

    /// Join a group through an external commit. `pending_removals` are the
    /// removal proposals the delivery service holds; the commit includes all
    /// of them.
    pub fn join(
        identity: &DeviceIdentity,
        snapshot: &GroupSnapshot,
        pending_removals: &[SignedRemoveProposal],
        admission: SignedAdmission,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<(PendingCommit, PublishedCommit)> {
        let (prev, info) = verify_snapshot(snapshot)?;
        let removals = sorted_removals(pending_removals);
        let (slot, generation) = plan_join_slot(&prev, &removals)?;
        let (kem_output, init) = external_init(&info.external_public_key, rng)?;
        build(
            identity,
            Plan {
                kind: CommitKind::ExternalJoin,
                prev: Some(&prev),
                prev_init_secret: init,
                external_init: Some(kem_output),
                removals,
                admin_changes: Vec::new(),
                join: Some(JoinRecord {
                    slot,
                    generation,
                    admission: Some(admission),
                }),
                genesis: None,
            },
            rng,
        )
    }

    /// Re-enter a group this device is a member of after losing its state or
    /// failing to process a commit (external commit renewing its own slot).
    pub fn resync(
        identity: &DeviceIdentity,
        snapshot: &GroupSnapshot,
        pending_removals: &[SignedRemoveProposal],
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<(PendingCommit, PublishedCommit)> {
        let (prev, info) = verify_snapshot(snapshot)?;
        let me = prev
            .roster
            .member_by_device(identity.public_key())
            .cloned()
            .ok_or(CoreError::Unauthorized("resync by a non-member"))?;
        let removals = sorted_removals(pending_removals);
        let (kem_output, init) = external_init(&info.external_public_key, rng)?;
        build(
            identity,
            Plan {
                kind: CommitKind::Resync,
                prev: Some(&prev),
                prev_init_secret: init,
                external_init: Some(kem_output),
                removals,
                admin_changes: Vec::new(),
                join: Some(JoinRecord {
                    slot: me.slot,
                    generation: prev.roster.next_generation(me.slot),
                    admission: None,
                }),
                genesis: None,
            },
            rng,
        )
    }

    /// Build a member commit: re-key this member's path, commit `removals`
    /// (all pending proposals plus any this member adds) and `admin_changes`.
    pub fn commit(
        &self,
        identity: &DeviceIdentity,
        removals: &[SignedRemoveProposal],
        admin_changes: &[AdminChange],
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<(PendingCommit, PublishedCommit)> {
        self.check_identity(identity)?;
        build(
            identity,
            Plan {
                kind: CommitKind::Member,
                prev: Some(&self.state),
                prev_init_secret: Zeroizing::new(*self.secrets.init_secret()),
                external_init: None,
                removals: sorted_removals(removals),
                admin_changes: admin_changes.to_vec(),
                join: None,
                genesis: None,
            },
            rng,
        )
    }

    /// Install a commit built by this member once the delivery service
    /// accepted it. The keys of the epoch it replaces stay available for late
    /// messages until [`GroupSession::expire_previous_epoch`].
    pub fn apply_own_commit(&mut self, pending: PendingCommit) -> CoreResult<()> {
        if pending.base_epoch != Some(self.state.epoch) || pending.gid() != self.gid() {
            return Err(CoreError::Invalid(
                "pending commit does not extend this epoch",
            ));
        }
        let mut next = *pending.session;
        next.previous = Some(PreviousEpoch {
            roster: self.state.roster.clone(),
            messages: self.messages.clone(),
        });
        *self = next;
        Ok(())
    }

    /// Process a commit authored by another party. `group_info` is the
    /// GroupInfo published with it, checked when present.
    pub fn process_commit(
        &mut self,
        commit: &[u8],
        group_info: Option<&[u8]>,
    ) -> CoreResult<ProcessedCommit> {
        let transition = verify_commit(&self.state, commit)?;
        let summary = CommitSummary::from_transition(&transition);
        let content = &transition.commit.content;
        if content.author_leaf_id == self.my_leaf_id {
            return Err(CoreError::Invalid("own commit without its pending state"));
        }
        if transition
            .staged
            .removed
            .iter()
            .any(|member| member.leaf_id == self.my_leaf_id)
        {
            return Ok(ProcessedCommit::Removed(summary));
        }
        let path_secrets = decrypt_update_path(
            &transition.staged.tree,
            &transition.path_context,
            &content.update_path,
            self.my_slot,
            &self.private,
        )?;
        let init = if content.kind.is_external() {
            let kem_output = content
                .external_init
                .as_deref()
                .ok_or(CoreError::Malformed("commit external init"))?;
            self.secrets.external_init_secret(kem_output)?
        } else {
            Zeroizing::new(*self.secrets.init_secret())
        };
        let commit_secret = commit_secret(&path_secrets.root_secret)?;
        let secrets = EpochSecrets::derive(&init, &commit_secret, &transition.group_context)?;
        let tag = secrets.confirmation_tag(&transition.group_context.confirmed_transcript_hash)?;
        if !digest_eq(&tag, &transition.commit.confirmation_tag) {
            return Err(CoreError::Invalid("confirmation tag"));
        }
        if let Some(group_info) = group_info {
            check_group_info(group_info, &transition, &secrets)?;
        }
        let mut private = self.private.clone();
        for node in transition
            .next
            .tree
            .direct_path(transition.path_context.author_slot)?
        {
            private.nodes.remove(&node);
        }
        private.nodes.extend(path_secrets.node_keys);
        let mut next = Self::activate(transition.next, &secrets, private, &self.my_leaf_id)?;
        next.last_own_update_epoch = self.last_own_update_epoch;
        next.previous = Some(PreviousEpoch {
            roster: self.state.roster.clone(),
            messages: self.messages.clone(),
        });
        *self = next;
        Ok(ProcessedCommit::Advanced(summary))
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

    /// Decrypt and authenticate an envelope of the current or previous epoch.
    pub fn decrypt(&mut self, envelope: &[u8]) -> CoreResult<ReceivedMessage> {
        let envelope = Envelope::decode(envelope)?;
        if digest_eq(&envelope.header.epoch_ref, self.messages.epoch_ref()) {
            return self
                .messages
                .decrypt(&envelope, &self.state.roster, &self.blocked);
        }
        match &mut self.previous {
            Some(previous)
                if digest_eq(&envelope.header.epoch_ref, previous.messages.epoch_ref()) =>
            {
                // Late messages are only accepted from senders the last
                // commit did not remove.
                if self
                    .state
                    .roster
                    .member_by_leaf(&envelope.header.sender_leaf_id)
                    .is_none()
                {
                    return Err(CoreError::Unauthorized("sender is not a member"));
                }
                previous
                    .messages
                    .decrypt(&envelope, &previous.roster, &self.blocked)
            }
            _ => Err(CoreError::Invalid("message for an epoch without keys")),
        }
    }

    /// Erase the keys of the previous epoch (end of the grace window).
    pub fn expire_previous_epoch(&mut self) {
        self.previous = None;
    }

    /// Whether keys of the previous epoch are still held.
    #[must_use]
    pub fn has_previous_epoch(&self) -> bool {
        self.previous.is_some()
    }

    /// Record the removal proposals the delivery service holds: messages
    /// from their targets are rejected from now on (P-3.c). Proposals that
    /// do not apply to the current roster are ignored. Returns the blocked
    /// leaves.
    pub fn set_pending_removals(&mut self, proposals: &[SignedRemoveProposal]) -> Vec<Digest> {
        self.blocked = proposals
            .iter()
            .filter_map(|proposal| {
                proposal
                    .authorize(&self.state.gid, &self.state.roster)
                    .ok()
                    .map(|target| target.leaf_id)
            })
            .collect();
        self.blocked.iter().copied().collect()
    }

    /// Sign a proposal removing the member in `slot` (an admin removal, or
    /// this member's own leave when `slot` is its slot).
    pub fn propose_removal(
        &self,
        identity: &DeviceIdentity,
        slot: u32,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<SignedRemoveProposal> {
        self.check_identity(identity)?;
        let target = self
            .state
            .roster
            .member_in_slot(slot)
            .ok_or(CoreError::Invalid("no member in slot"))?;
        let proposal = RemoveProposal::for_member(&self.state.gid, target, identity.public_key())
            .sign(identity, rng)?;
        proposal.authorize(&self.state.gid, &self.state.roster)?;
        Ok(proposal)
    }

    /// Sign this member's own leave proposal.
    pub fn propose_leave(
        &self,
        identity: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<SignedRemoveProposal> {
        self.propose_removal(identity, self.my_slot, rng)
    }

    /// Sign an invite whose key derives from `invite_seed` (admins only).
    pub fn create_invite(
        &self,
        identity: &DeviceIdentity,
        invite_seed: &[u8; 32],
        expires_at_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<SignedInvite> {
        self.check_admin(identity)?;
        Invite::from_seed(
            &self.state.gid,
            invite_seed,
            expires_at_ms,
            identity.public_key(),
        )
        .sign(identity, rng)
    }

    /// Sign an admission for the device `joiner_device_pk` (admins only).
    pub fn admit(
        &self,
        identity: &DeviceIdentity,
        joiner_device_pk: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<SignedAdmission> {
        self.check_admin(identity)?;
        SignedAdmission::by_admin(
            &self.state.gid,
            &leaf_id(&self.state.gid, joiner_device_pk)?,
            identity,
            rng,
        )
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
        CoverFailureReport::sign(&self.state.gid, epoch, reason, identity, rng)
    }

    fn check_identity(&self, identity: &DeviceIdentity) -> CoreResult<()> {
        if identity.leaf_id(&self.state.gid)? != self.my_leaf_id {
            return Err(CoreError::Invalid("identity does not own this session"));
        }
        Ok(())
    }

    fn check_admin(&self, identity: &DeviceIdentity) -> CoreResult<()> {
        self.check_identity(identity)?;
        if !self.state.roster.is_admin(identity.public_key()) {
            return Err(CoreError::Unauthorized("not an admin"));
        }
        Ok(())
    }

    /// Group identifier.
    #[must_use]
    pub fn gid(&self) -> &Digest {
        &self.state.gid
    }

    /// Current epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.state.epoch
    }

    /// Current roster.
    #[must_use]
    pub fn roster(&self) -> &Roster {
        &self.state.roster
    }

    /// Current public state.
    #[must_use]
    pub fn public_state(&self) -> &PublicGroupState {
        &self.state
    }

    /// GroupContext of the current epoch.
    #[must_use]
    pub fn group_context(&self) -> &GroupContext {
        &self.group_context
    }

    /// This member's slot.
    #[must_use]
    pub fn my_slot(&self) -> u32 {
        self.my_slot
    }

    /// This member's leaf identifier.
    #[must_use]
    pub fn my_leaf_id(&self) -> &Digest {
        &self.my_leaf_id
    }

    /// Epochs since this member last re-keyed its own leaf (the application
    /// publishes an empty commit when this exceeds its FS/PCS window).
    #[must_use]
    pub fn epochs_since_own_update(&self) -> u64 {
        self.state.epoch.saturating_sub(self.last_own_update_epoch)
    }

    /// Next generation this member will send in the current epoch.
    #[must_use]
    pub fn next_own_generation(&self) -> u32 {
        self.messages.next_own_generation()
    }

    /// Public key of the epoch's external ML-KEM key (as in the GroupInfo).
    pub fn external_public_key(&self) -> CoreResult<Vec<u8>> {
        Ok(self.secrets.external_key()?.public_key())
    }

    /// Fingerprint of the transcript, for out-of-band comparison between
    /// members (equal fingerprints mean equal histories).
    #[must_use]
    pub fn transcript_fingerprint(&self) -> Digest {
        self.state.interim_transcript_hash
    }

    /// Export the session, secrets included, for encrypted persistence.
    pub fn export(&self) -> CoreResult<Zeroizing<Vec<u8>>> {
        let private_nodes = self
            .private
            .nodes
            .iter()
            .map(|(node, key)| array(vec![uint(u64::from(*node)), bytes(key.seed())]))
            .collect();
        let previous = match &self.previous {
            None => Value::Null,
            Some(previous) => array(vec![
                bytes(&previous.roster.to_cbor()?),
                previous.messages.to_value(),
            ]),
        };
        Ok(Zeroizing::new(encode(&array(vec![
            text(SESSION_LABEL),
            bytes(&self.state.to_cbor()?),
            bytes(&self.my_leaf_id),
            self.private
                .leaf
                .as_ref()
                .map_or(Value::Null, |leaf| bytes(leaf.seed())),
            array(private_nodes),
            bytes(self.secrets.init_secret()),
            bytes(self.secrets.external_secret()),
            self.messages.to_value(),
            previous,
            array(self.blocked.iter().map(|leaf| bytes(leaf)).collect()),
            uint(self.last_own_update_epoch),
        ]))?))
    }

    /// Restore an exported session.
    pub fn import(encoded: &[u8]) -> CoreResult<Self> {
        let mut items =
            expect_array(decode(encoded, 256 << 20, "session")?, 11, "session")?.into_iter();
        expect_label(&next(&mut items, "session")?, SESSION_LABEL, "session")?;
        let state = PublicGroupState::from_cbor(&expect_bytes(
            next(&mut items, "session")?,
            "session state",
        )?)?;
        let my_leaf_id = expect_bytes32(next(&mut items, "session")?, "session leaf")?;
        let leaf = match next(&mut items, "session")? {
            Value::Null => None,
            value => Some(KemSecret::from_seed(
                expect_bytes(value, "session leaf key")?
                    .try_into()
                    .map_err(|_| CoreError::Malformed("session leaf key"))?,
            )),
        };
        let mut nodes = BTreeMap::new();
        for entry in expect_list(next(&mut items, "session")?, "session nodes")? {
            let mut fields = expect_array(entry, 2, "session node")?.into_iter();
            let node = expect_u32(&next(&mut fields, "session node")?, "session node")?;
            let seed: [u8; 64] = expect_bytes(next(&mut fields, "session node")?, "node key")?
                .try_into()
                .map_err(|_| CoreError::Malformed("session node key"))?;
            nodes.insert(node, KemSecret::from_seed(seed));
        }
        let init_secret = expect_bytes32(next(&mut items, "session")?, "session init secret")?;
        let external_secret =
            expect_bytes32(next(&mut items, "session")?, "session external secret")?;
        let messages = EpochMessages::from_value(next(&mut items, "session")?)?;
        let previous = match next(&mut items, "session")? {
            Value::Null => None,
            value => {
                let mut fields = expect_array(value, 2, "session previous")?.into_iter();
                let roster = Roster::from_cbor(
                    &expect_bytes(next(&mut fields, "session previous")?, "previous roster")?,
                    &state.gid,
                )?;
                let messages = EpochMessages::from_value(next(&mut fields, "session previous")?)?;
                Some(PreviousEpoch { roster, messages })
            }
        };
        let blocked = expect_list(next(&mut items, "session")?, "session blocked")?
            .into_iter()
            .map(|leaf| expect_bytes32(leaf, "session blocked leaf"))
            .collect::<CoreResult<BTreeSet<_>>>()?;
        let last_own_update_epoch = expect_uint(&next(&mut items, "session")?, "session update")?;
        let my_slot = state
            .roster
            .member_by_leaf(&my_leaf_id)
            .map(|member| member.slot)
            .ok_or(CoreError::Malformed("session member"))?;
        if messages.epoch() != state.epoch {
            return Err(CoreError::Malformed("session message epoch"));
        }
        Ok(Self {
            group_context: state.group_context()?,
            state,
            my_leaf_id,
            my_slot,
            private: PrivatePath { leaf, nodes },
            secrets: RetainedEpochSecrets::from_parts(init_secret, external_secret),
            messages,
            previous,
            blocked,
            last_own_update_epoch,
        })
    }
}

fn sorted_removals(removals: &[SignedRemoveProposal]) -> Vec<SignedRemoveProposal> {
    let mut by_slot: BTreeMap<u32, SignedRemoveProposal> = BTreeMap::new();
    for removal in removals {
        by_slot
            .entry(removal.proposal().target_slot)
            .or_insert_with(|| removal.clone());
    }
    by_slot.into_values().collect()
}

fn check_group_info(
    group_info: &[u8],
    transition: &CommitTransition,
    secrets: &EpochSecrets,
) -> CoreResult<()> {
    let signed = SignedGroupInfo::decode_unverified(group_info)?;
    let info = signed.info();
    if info.group_context != transition.group_context
        || info.confirmation_tag != transition.commit.confirmation_tag
        || info.signer_leaf_id != transition.commit.content.author_leaf_id
        || info.external_public_key != secrets.external_key()?.public_key()
    {
        return Err(CoreError::Invalid("group info does not match the commit"));
    }
    signed.verify(&transition.next.tree, &transition.next.roster)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests;
