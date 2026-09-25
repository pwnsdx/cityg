//! Delivery-service state machine for one group.
//!
//! The delivery service orders commits and relays messages; it holds no
//! group secret. [`GroupLedger`] runs the public commit transition on every
//! commit it accepts (so it can never be tricked into relaying a commit that
//! members would reject), enforces the rules that need a global order, a
//! count or a clock, and stores the public data joiners need:
//!
//! * the first valid commit for epoch `n + 1` wins; later ones are rejected
//!   with an epoch mismatch and their authors rebuild on the new epoch;
//! * removal proposals and join requests are recorded concurrently, each
//!   authorized against the current epoch. A commit must include every
//!   *overdue* proposal, one recorded before the current epoch started (the
//!   oldest [`MAX_REMOVALS_PER_COMMIT`] removals and [`MAX_JOINS_PER_COMMIT`]
//!   join requests when more are waiting); proposals recorded since may wait
//!   for the next commit, so a commit never fails because a proposal arrived
//!   while it was being built. After each commit, the proposals it did not
//!   include are checked again and those that no longer apply are dropped;
//! * the GroupInfo published with a commit must be signed by its author and
//!   describe the epoch the ledger computed, and the commit comes with one
//!   welcome per join request it includes, kept for the joiner;
//! * for light members, it computes the Merkle proofs of each accepted
//!   commit ([`crate::light::LightCommit`], against the tree the commit
//!   starts from, which only it still has afterwards) and the light-join data
//!   of the current epoch;
//! * invites expire by the ledger clock, admit at most `max_uses` joins and
//!   can be revoked by an admin;
//! * a message is accepted for the current epoch, or for one of the
//!   [`MAX_GRACE_EPOCHS`] previous ones during [`GRACE_WINDOW_MS`] after it
//!   ended, only from a member of that epoch that is still a member without
//!   a recorded removal, and at most once per `(epoch, sender, generation)`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use ciborium::value::Value;

use crate::admission::{SignedAdmission, SignedInvite, SignedInviteRevocation};
use crate::cbor::{
    array, bytes, decode, encode, expect_array, expect_bytes, expect_bytes32, expect_label,
    expect_list, expect_uint, text, uint,
};
use crate::commit::{CommitKind, MAX_JOINS_PER_COMMIT, MAX_REMOVALS_PER_COMMIT};
use crate::cover::CoverFailureReport;
use crate::error::{CoreError, CoreResult};
use crate::group_info::SignedGroupInfo;
use crate::hash::{Digest, digest_eq};
use crate::join::{SignedJoinRequest, Welcome};
use crate::light::{LightCommit, LightJoin};
use crate::message::{Envelope, GRACE_WINDOW_MS, MAX_GRACE_EPOCHS, ReplayWindow, epoch_ref};
use crate::proposal::{SignedRemoveProposal, proposal_ref};
use crate::session::GroupSnapshot;
use crate::state::{
    CommitTransition, MemberChange, PublicGroupState, verify_commit, verify_genesis,
};
use crate::tree::{MemberRef, next};

const LEDGER_LABEL: &str = "city-g/ledger/v3";
/// Invites a group stores at once.
pub const MAX_INVITES: usize = 256;
/// Cover-failure reports a group keeps.
pub const MAX_COVER_FAILURES: usize = 256;
/// Welcomes a group keeps for joiners that have not fetched them yet.
pub const MAX_WELCOMES: usize = 4096;
/// Revoked invite identifiers a group remembers.
pub const MAX_REVOKED_INVITES: usize = 1024;

/// Public summary of an accepted commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedCommit {
    pub epoch: u64,
    pub kind: CommitKind,
    pub author: MemberRef,
    pub removed: Vec<MemberChange>,
    pub author_entry: Option<MemberChange>,
    pub joined: Vec<MemberChange>,
    /// Pending join requests the commit made obsolete, by reference.
    pub dropped_requests: Vec<Digest>,
    /// The encoded [`LightCommit`] of the commit (empty for a genesis).
    pub light: Vec<u8>,
}

impl AcceptedCommit {
    fn from_transition(transition: &CommitTransition) -> Self {
        Self {
            epoch: transition.commit.content.epoch,
            kind: transition.commit.content.kind,
            author: transition.author(),
            removed: transition.staged.removed.clone(),
            author_entry: transition.staged.author_entry.clone(),
            joined: transition.staged.joined.clone(),
            dropped_requests: Vec::new(),
            light: Vec::new(),
        }
    }
}

/// An accepted message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedMessage {
    pub epoch: u64,
    pub sender: MemberRef,
    pub generation: u32,
}

/// Outcome of recording a proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalStatus {
    Recorded,
    AlreadyRecorded,
}

/// Where a join request stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JoinStatus {
    /// Recorded, waiting for a commit.
    Pending,
    /// Included in the commit of `epoch`; `welcome` carries its secret.
    Committed { epoch: u64, welcome: Vec<u8> },
    /// Unknown: never recorded, dropped, or its welcome expired.
    Unknown,
}

/// A recorded removal proposal or join request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Proposal {
    Remove(SignedRemoveProposal),
    Join(Box<SignedJoinRequest>),
}

impl Proposal {
    /// Deterministic encoding of the signed proposal.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        match self {
            Self::Remove(proposal) => proposal.encoded(),
            Self::Join(request) => request.encoded(),
        }
    }
}

/// A proposal waiting for a commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingProposal {
    pub proposal: Proposal,
    pub reference: Digest,
    /// Epoch during which it was recorded: it is overdue once a later epoch
    /// is current.
    pub recorded_epoch: u64,
}

#[derive(Clone, Debug)]
struct PreviousEpoch {
    epoch: u64,
    members: BTreeSet<MemberRef>,
    ended_at_ms: u64,
    windows: BTreeMap<MemberRef, ReplayWindow>,
}

#[derive(Clone, Debug)]
struct StoredInvite {
    invite: SignedInvite,
    uses: u64,
}

#[derive(Clone, Debug)]
struct StoredWelcome {
    epoch: u64,
    welcome: Vec<u8>,
    /// Device key of the joiner (to find its leaf for a light join).
    device_pk: Vec<u8>,
}

/// Delivery-service state of one group.
#[derive(Clone, Debug)]
pub struct GroupLedger {
    state: PublicGroupState,
    group_info: Vec<u8>,
    epoch_started_at_ms: u64,
    previous: VecDeque<PreviousEpoch>,
    windows: BTreeMap<MemberRef, ReplayWindow>,
    pending: Vec<PendingProposal>,
    invites: BTreeMap<Digest, StoredInvite>,
    revoked_invites: VecDeque<Digest>,
    cover_failures: Vec<CoverFailureReport>,
    welcomes: BTreeMap<Digest, StoredWelcome>,
    welcome_order: VecDeque<Digest>,
}

fn check_group_info(group_info: &[u8], transition: &CommitTransition) -> CoreResult<()> {
    let signed = SignedGroupInfo::decode_unverified(group_info)?;
    let info = signed.info();
    if info.group_context != transition.group_context
        || info.confirmation_tag != transition.commit.confirmation_tag
        || info.signer_leaf != transition.commit.content.author_leaf
    {
        return Err(CoreError::Invalid("group info does not match the commit"));
    }
    signed.verify(&transition.next.tree, &transition.next.registry)
}

impl GroupLedger {
    /// Create the ledger of a group from its genesis commit and GroupInfo.
    pub fn create(
        commit: &[u8],
        group_info: &[u8],
        now_ms: u64,
    ) -> CoreResult<(Self, AcceptedCommit)> {
        let transition = verify_genesis(commit)?;
        check_group_info(group_info, &transition)?;
        let accepted = AcceptedCommit::from_transition(&transition);
        Ok((
            Self {
                state: transition.next,
                group_info: group_info.to_vec(),
                epoch_started_at_ms: now_ms,
                previous: VecDeque::new(),
                windows: BTreeMap::new(),
                pending: Vec::new(),
                invites: BTreeMap::new(),
                revoked_invites: VecDeque::new(),
                cover_failures: Vec::new(),
                welcomes: BTreeMap::new(),
                welcome_order: VecDeque::new(),
            },
            accepted,
        ))
    }

    /// Check the invite an admission relies on: known, not revoked, not
    /// expired, and with a use left when `count_use` is set.
    fn check_invite_use(
        &self,
        admission: &SignedAdmission,
        now_ms: u64,
        count_use: bool,
    ) -> CoreResult<Option<Digest>> {
        let Some(invite) = admission.invite() else {
            return Ok(None);
        };
        let id = invite.id()?;
        if self.revoked_invites.contains(&id) {
            return Err(CoreError::Unauthorized("invite revoked"));
        }
        if invite.invite().expires_at_ms < now_ms {
            return Err(CoreError::Invalid("invite expired"));
        }
        if count_use {
            let uses = self.invites.get(&id).map_or(0, |stored| stored.uses);
            if uses >= invite.invite().max_uses {
                return Err(CoreError::Unauthorized("invite has no use left"));
            }
        }
        Ok(Some(id))
    }

    fn count_invite_use(&mut self, id: Option<Digest>, admission: &SignedAdmission) {
        let (Some(id), Some(invite)) = (id, admission.invite()) else {
            return;
        };
        self.invites
            .entry(id)
            .or_insert_with(|| StoredInvite {
                invite: invite.clone(),
                uses: 0,
            })
            .uses += 1;
    }

    /// Accept the commit of the next epoch, with its GroupInfo and one
    /// welcome per join request it includes.
    pub fn apply_commit(
        &mut self,
        commit: &[u8],
        group_info: &[u8],
        welcomes: &[Vec<u8>],
        now_ms: u64,
    ) -> CoreResult<AcceptedCommit> {
        let transition = verify_commit(&self.state, commit)?;
        let content = &transition.commit.content;
        let included: BTreeSet<Digest> = content
            .removals
            .iter()
            .map(SignedRemoveProposal::reference)
            .chain(content.joins.iter().map(SignedJoinRequest::reference))
            .collect::<CoreResult<_>>()?;
        let epoch = self.state.epoch;
        let overdue = |join: bool, limit: usize| -> Vec<Digest> {
            self.pending
                .iter()
                .filter(|pending| {
                    pending.recorded_epoch < epoch
                        && matches!(pending.proposal, Proposal::Join(_)) == join
                })
                .map(|pending| pending.reference)
                .take(limit)
                .collect()
        };
        let required = [
            overdue(false, MAX_REMOVALS_PER_COMMIT),
            overdue(true, MAX_JOINS_PER_COMMIT),
        ];
        if required
            .iter()
            .flatten()
            .any(|reference| !included.contains(reference))
        {
            return Err(CoreError::Invalid("overdue proposals must be committed"));
        }
        // A joiner whose request is recorded may author the external commit
        // itself: its admission already used the invite when the request
        // was recorded.
        let author_recorded = |admission: &SignedAdmission| {
            self.pending_joins().any(|request| {
                request.device_pk == content.author_device_pk
                    && request.admission.hash() == admission.hash()
            })
        };
        let mut invite_uses = Vec::new();
        for (admission, recorded) in content
            .admission
            .iter()
            .map(|admission| (admission, author_recorded(admission)))
            .chain(content.joins.iter().map(|request| {
                let recorded = request
                    .reference()
                    .is_ok_and(|reference| self.is_pending(&reference));
                (&request.admission, recorded)
            }))
        {
            let id = self.check_invite_use(admission, now_ms, !recorded)?;
            if !recorded {
                invite_uses.push((id, admission.clone()));
            }
        }
        check_group_info(group_info, &transition)?;
        if welcomes.len() != content.joins.len() {
            return Err(CoreError::Invalid("one welcome per join request"));
        }
        let mut stored = Vec::with_capacity(welcomes.len());
        for (encoded, request) in welcomes.iter().zip(&content.joins) {
            let welcome = Welcome::decode(encoded)?;
            let reference = request.reference()?;
            if welcome.gid != content.gid
                || welcome.epoch != content.epoch
                || welcome.request_ref != reference
                || welcome.encode()? != *encoded
            {
                return Err(CoreError::Invalid("welcome does not match its request"));
            }
            stored.push((reference, encoded.clone(), request.device_pk.clone()));
        }

        let mut accepted = AcceptedCommit::from_transition(&transition);
        accepted.light = LightCommit::for_commit(&self.state, content)?.encode()?;
        for (id, admission) in invite_uses {
            self.count_invite_use(id, &admission);
        }
        let previous_state = std::mem::replace(&mut self.state, transition.next);
        self.previous.push_front(PreviousEpoch {
            epoch: previous_state.epoch,
            members: previous_state.tree.member_refs().collect(),
            ended_at_ms: now_ms,
            windows: std::mem::take(&mut self.windows),
        });
        self.previous.truncate(MAX_GRACE_EPOCHS);
        self.group_info = group_info.to_vec();
        self.epoch_started_at_ms = now_ms;
        for (reference, welcome, device_pk) in stored {
            self.store_welcome(
                reference,
                StoredWelcome {
                    epoch: self.state.epoch,
                    welcome,
                    device_pk,
                },
            );
        }
        let next_epoch = self.state.epoch + 1;
        let (gid, membership) = (self.state.gid, self.state.membership());
        let mut dropped = Vec::new();
        self.pending.retain(|pending| {
            if included.contains(&pending.reference) {
                return false;
            }
            let valid = match &pending.proposal {
                Proposal::Remove(proposal) => proposal.authorize(&gid, &membership).is_ok(),
                Proposal::Join(request) => request.authorize(&gid, next_epoch, &membership).is_ok(),
            };
            if !valid && matches!(pending.proposal, Proposal::Join(_)) {
                dropped.push(pending.reference);
            }
            valid
        });
        accepted.dropped_requests = dropped;
        let membership = self.state.membership();
        self.invites.retain(|_, stored| {
            stored.invite.authorize(&gid, &membership).is_ok()
                && stored.invite.invite().expires_at_ms >= now_ms
        });
        Ok(accepted)
    }

    fn store_welcome(&mut self, reference: Digest, stored: StoredWelcome) {
        if self.welcomes.insert(reference, stored).is_none() {
            self.welcome_order.push_back(reference);
        }
        while self.welcome_order.len() > MAX_WELCOMES {
            if let Some(oldest) = self.welcome_order.pop_front() {
                self.welcomes.remove(&oldest);
            }
        }
    }

    fn is_pending(&self, reference: &Digest) -> bool {
        self.pending
            .iter()
            .any(|pending| &pending.reference == reference)
    }

    /// Record a removal proposal authorized against the current epoch.
    pub fn submit_remove_proposal(&mut self, encoded: &[u8]) -> CoreResult<ProposalStatus> {
        let proposal = SignedRemoveProposal::decode(encoded)?;
        let target = proposal.authorize(&self.state.gid, &self.state.membership())?;
        let target = MemberRef {
            leaf: proposal.proposal().target_leaf,
            since: target.since,
        };
        if self
            .pending_removal_targets()
            .any(|pending| pending == target)
        {
            return Ok(ProposalStatus::AlreadyRecorded);
        }
        self.pending.push(PendingProposal {
            reference: proposal.reference()?,
            proposal: Proposal::Remove(proposal),
            recorded_epoch: self.state.epoch,
        });
        Ok(ProposalStatus::Recorded)
    }

    /// Record a join request that can enter the next epoch. Returns its
    /// reference and whether it was new.
    pub fn submit_join_request(
        &mut self,
        encoded: &[u8],
        now_ms: u64,
    ) -> CoreResult<(Digest, ProposalStatus)> {
        let request = SignedJoinRequest::decode(encoded)?;
        let reference = request.reference()?;
        if self.is_pending(&reference) {
            return Ok((reference, ProposalStatus::AlreadyRecorded));
        }
        if self
            .pending_joins()
            .any(|pending| pending.device_pk == request.device_pk)
        {
            return Err(CoreError::Invalid("a request of this device is pending"));
        }
        request.authorize(
            &self.state.gid,
            self.state.epoch + 1,
            &self.state.membership(),
        )?;
        let members = self.state.tree.member_count() + self.pending_joins().count();
        if members >= self.state.capacity() as usize {
            return Err(CoreError::TooLarge("the group is full"));
        }
        let id = self.check_invite_use(&request.admission, now_ms, true)?;
        self.count_invite_use(id, &request.admission);
        self.pending.push(PendingProposal {
            reference,
            proposal: Proposal::Join(Box::new(request)),
            recorded_epoch: self.state.epoch,
        });
        Ok((reference, ProposalStatus::Recorded))
    }

    /// Recorded proposals, in recording order.
    #[must_use]
    pub fn pending(&self) -> &[PendingProposal] {
        &self.pending
    }

    /// Recorded removal proposals, in recording order.
    pub fn pending_removals(&self) -> impl Iterator<Item = &SignedRemoveProposal> {
        self.pending
            .iter()
            .filter_map(|pending| match &pending.proposal {
                Proposal::Remove(proposal) => Some(proposal),
                Proposal::Join(_) => None,
            })
    }

    /// Recorded join requests, in recording order.
    pub fn pending_joins(&self) -> impl Iterator<Item = &SignedJoinRequest> {
        self.pending
            .iter()
            .filter_map(|pending| match &pending.proposal {
                Proposal::Join(request) => Some(request.as_ref()),
                Proposal::Remove(_) => None,
            })
    }

    fn pending_removal_targets(&self) -> impl Iterator<Item = MemberRef> + '_ {
        self.pending_removals().map(|proposal| MemberRef {
            leaf: proposal.proposal().target_leaf,
            since: proposal.proposal().target_since,
        })
    }

    /// Where the join request `reference` stands.
    #[must_use]
    pub fn join_status(&self, reference: &Digest) -> JoinStatus {
        if let Some(stored) = self.welcomes.get(reference) {
            return JoinStatus::Committed {
                epoch: stored.epoch,
                welcome: stored.welcome.clone(),
            };
        }
        if self.is_pending(reference) {
            JoinStatus::Pending
        } else {
            JoinStatus::Unknown
        }
    }

    /// The encoded [`LightJoin`] of the join request `reference`, when the
    /// commit that included it created the current epoch (a light joiner of
    /// an older epoch resyncs instead).
    pub fn light_join(&self, reference: &Digest) -> CoreResult<Option<Vec<u8>>> {
        let Some(stored) = self.welcomes.get(reference) else {
            return Ok(None);
        };
        if stored.epoch != self.state.epoch {
            return Ok(None);
        }
        let Some(leaf) = self.state.tree.find_device(&stored.device_pk) else {
            return Ok(None);
        };
        if self.state.tree.member(leaf, stored.epoch).is_none() {
            return Ok(None);
        }
        Ok(Some(LightJoin::for_state(&self.state, leaf)?.encode()?))
    }

    /// Store an admin-signed invite.
    pub fn publish_invite(&mut self, encoded: &[u8], now_ms: u64) -> CoreResult<Digest> {
        let invite = SignedInvite::decode(encoded)?;
        invite.authorize(&self.state.gid, &self.state.membership())?;
        if invite.invite().expires_at_ms < now_ms {
            return Err(CoreError::Invalid("invite expired"));
        }
        let id = invite.id()?;
        if self.revoked_invites.contains(&id) {
            return Err(CoreError::Unauthorized("invite revoked"));
        }
        if !self.invites.contains_key(&id) {
            self.invites
                .retain(|_, stored| stored.invite.invite().expires_at_ms >= now_ms);
            if self.invites.len() >= MAX_INVITES {
                return Err(CoreError::TooLarge("invites"));
            }
            self.invites.insert(id, StoredInvite { invite, uses: 0 });
        }
        Ok(id)
    }

    /// Revoke an invite on an admin's signed request: the invite can no
    /// longer be fetched or used, and the pending join requests that rely
    /// on it are dropped. Returns the dropped requests.
    pub fn revoke_invite(&mut self, encoded: &[u8]) -> CoreResult<Vec<Digest>> {
        let revocation = SignedInviteRevocation::decode(encoded)?;
        revocation.authorize(&self.state.gid, &self.state.membership())?;
        let id = revocation.invite_id;
        self.invites.remove(&id);
        if !self.revoked_invites.contains(&id) {
            self.revoked_invites.push_back(id);
            while self.revoked_invites.len() > MAX_REVOKED_INVITES {
                self.revoked_invites.pop_front();
            }
        }
        let mut dropped = Vec::new();
        self.pending.retain(|pending| match &pending.proposal {
            Proposal::Join(request)
                if request
                    .admission
                    .invite()
                    .and_then(|invite| invite.id().ok())
                    == Some(id) =>
            {
                dropped.push(pending.reference);
                false
            }
            _ => true,
        });
        Ok(dropped)
    }

    /// Invite `id`, while it is valid.
    #[must_use]
    pub fn invite(&self, id: &Digest, now_ms: u64) -> Option<&SignedInvite> {
        self.invites
            .get(id)
            .map(|stored| &stored.invite)
            .filter(|invite| invite.invite().expires_at_ms >= now_ms)
    }

    /// Joins invite `id` admitted or has requests for.
    #[must_use]
    pub fn invite_uses(&self, id: &Digest) -> u64 {
        self.invites.get(id).map_or(0, |stored| stored.uses)
    }

    /// Accept an envelope for relay.
    pub fn accept_message(&mut self, encoded: &[u8], now_ms: u64) -> CoreResult<AcceptedMessage> {
        let envelope = Envelope::decode(encoded)?;
        let header = &envelope.header;
        let sender = header.sender;
        let gid = self.state.gid;
        // A sender must be a member of the current epoch, even for a late
        // message of a previous one: a member removed by a later commit
        // cannot keep posting during the grace window.
        if self.state.tree.member_by_ref(sender).is_none() {
            return Err(CoreError::Unauthorized("sender is not a member"));
        }
        if self
            .pending_removal_targets()
            .any(|target| target == sender)
        {
            return Err(CoreError::Unauthorized("sender has a pending removal"));
        }
        let (epoch, windows) = if digest_eq(&header.epoch_ref, &epoch_ref(&gid, self.state.epoch)?)
        {
            (self.state.epoch, &mut self.windows)
        } else {
            let mut found = None;
            for previous in &mut self.previous {
                if digest_eq(&header.epoch_ref, &epoch_ref(&gid, previous.epoch)?) {
                    found = Some(previous);
                    break;
                }
            }
            match found {
                Some(previous)
                    if now_ms <= previous.ended_at_ms.saturating_add(GRACE_WINDOW_MS) =>
                {
                    if !previous.members.contains(&sender) {
                        return Err(CoreError::Unauthorized(
                            "sender is not a member of the epoch",
                        ));
                    }
                    (previous.epoch, &mut previous.windows)
                }
                _ => return Err(CoreError::Invalid("message for an inactive epoch")),
            }
        };
        windows
            .entry(sender)
            .or_default()
            .accept(header.generation)?;
        Ok(AcceptedMessage {
            epoch,
            sender,
            generation: header.generation,
        })
    }

    /// Record a cover-failure report of a current member about the current
    /// epoch.
    pub fn submit_cover_failure(&mut self, encoded: &[u8]) -> CoreResult<()> {
        let report = CoverFailureReport::decode(encoded)?;
        report.verify(&self.state.gid, &self.state.tree)?;
        if report.epoch != self.state.epoch {
            return Err(CoreError::EpochMismatch {
                expected: self.state.epoch,
                got: report.epoch,
            });
        }
        if self.cover_failures.len() >= MAX_COVER_FAILURES {
            self.cover_failures.remove(0);
        }
        self.cover_failures.push(report);
        Ok(())
    }

    /// Recorded cover-failure reports, oldest first.
    #[must_use]
    pub fn cover_failures(&self) -> &[CoverFailureReport] {
        &self.cover_failures
    }

    /// What a joiner or resyncing member needs: GroupInfo, tree, registry.
    pub fn snapshot(&self) -> CoreResult<GroupSnapshot> {
        Ok(GroupSnapshot {
            group_info: self.group_info.clone(),
            tree: self.state.tree.to_cbor()?,
            registry: self.state.registry.to_cbor()?,
        })
    }

    /// Public state of the current epoch.
    #[must_use]
    pub fn state(&self) -> &PublicGroupState {
        &self.state
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

    /// GroupInfo of the current epoch.
    #[must_use]
    pub fn group_info(&self) -> &[u8] {
        &self.group_info
    }

    /// When the current epoch started, by the ledger clock.
    #[must_use]
    pub fn epoch_started_at_ms(&self) -> u64 {
        self.epoch_started_at_ms
    }

    /// Snapshot of the whole ledger (persistence).
    pub fn to_cbor(&self) -> CoreResult<Vec<u8>> {
        let windows = |windows: &BTreeMap<MemberRef, ReplayWindow>| {
            array(
                windows
                    .iter()
                    .map(|(member, window)| array(vec![member.to_value(), window.to_value()]))
                    .collect(),
            )
        };
        encode(&array(vec![
            text(LEDGER_LABEL),
            bytes(&self.state.to_cbor()?),
            bytes(&self.group_info),
            uint(self.epoch_started_at_ms),
            array(
                self.previous
                    .iter()
                    .map(|previous| {
                        array(vec![
                            uint(previous.epoch),
                            array(previous.members.iter().map(|m| m.to_value()).collect()),
                            uint(previous.ended_at_ms),
                            windows(&previous.windows),
                        ])
                    })
                    .collect(),
            ),
            windows(&self.windows),
            array(
                self.pending
                    .iter()
                    .map(|pending| {
                        array(vec![
                            uint(u64::from(matches!(pending.proposal, Proposal::Join(_)))),
                            bytes(pending.proposal.encoded()),
                            uint(pending.recorded_epoch),
                        ])
                    })
                    .collect(),
            ),
            array(
                self.invites
                    .values()
                    .map(|stored| array(vec![bytes(stored.invite.encoded()), uint(stored.uses)]))
                    .collect(),
            ),
            array(self.revoked_invites.iter().map(|id| bytes(id)).collect()),
            array(
                self.cover_failures
                    .iter()
                    .map(|report| bytes(report.encoded()))
                    .collect(),
            ),
            array(
                self.welcome_order
                    .iter()
                    .filter_map(|reference| {
                        self.welcomes.get(reference).map(|stored| {
                            array(vec![
                                bytes(reference),
                                uint(stored.epoch),
                                bytes(&stored.welcome),
                                bytes(&stored.device_pk),
                            ])
                        })
                    })
                    .collect(),
            ),
        ]))
    }

    /// Restore a snapshot, re-checking every signed object it holds.
    pub fn from_cbor(encoded: &[u8]) -> CoreResult<Self> {
        let mut items =
            expect_array(decode(encoded, 256 << 20, "ledger")?, 11, "ledger")?.into_iter();
        expect_label(&next(&mut items, "ledger")?, LEDGER_LABEL, "ledger")?;
        let state = PublicGroupState::from_cbor(&expect_bytes(
            next(&mut items, "ledger")?,
            "ledger state",
        )?)?;
        let group_info = expect_bytes(next(&mut items, "ledger")?, "ledger group info")?;
        let signed = SignedGroupInfo::decode_unverified(&group_info)?;
        if signed.info().group_context != state.group_context()? {
            return Err(CoreError::Invalid("ledger group info"));
        }
        signed.verify(&state.tree, &state.registry)?;
        let epoch_started_at_ms = expect_uint(&next(&mut items, "ledger")?, "ledger epoch start")?;
        let read_windows = |value: Value| -> CoreResult<BTreeMap<MemberRef, ReplayWindow>> {
            expect_list(value, "ledger windows")?
                .into_iter()
                .map(|entry| {
                    let mut fields = expect_array(entry, 2, "ledger window")?.into_iter();
                    Ok((
                        MemberRef::from_value(next(&mut fields, "ledger window")?)?,
                        ReplayWindow::from_value(next(&mut fields, "ledger window")?)?,
                    ))
                })
                .collect()
        };
        let mut previous = VecDeque::new();
        for entry in expect_list(next(&mut items, "ledger")?, "ledger previous")? {
            let mut fields = expect_array(entry, 4, "ledger previous")?.into_iter();
            previous.push_back(PreviousEpoch {
                epoch: expect_uint(&next(&mut fields, "ledger previous")?, "previous epoch")?,
                members: expect_list(next(&mut fields, "ledger previous")?, "previous members")?
                    .into_iter()
                    .map(MemberRef::from_value)
                    .collect::<CoreResult<_>>()?,
                ended_at_ms: expect_uint(&next(&mut fields, "ledger previous")?, "ended at")?,
                windows: read_windows(next(&mut fields, "ledger previous")?)?,
            });
        }
        if previous.len() > MAX_GRACE_EPOCHS {
            return Err(CoreError::Malformed("ledger previous"));
        }
        let windows = read_windows(next(&mut items, "ledger")?)?;
        let mut pending = Vec::new();
        for entry in expect_list(next(&mut items, "ledger")?, "ledger pending")? {
            let mut fields = expect_array(entry, 3, "ledger pending")?.into_iter();
            let kind = expect_uint(&next(&mut fields, "ledger pending")?, "pending kind")?;
            let encoded = expect_bytes(next(&mut fields, "ledger pending")?, "pending proposal")?;
            let recorded_epoch =
                expect_uint(&next(&mut fields, "ledger pending")?, "pending epoch")?;
            let proposal = match kind {
                0 => Proposal::Remove(SignedRemoveProposal::decode(&encoded)?),
                1 => Proposal::Join(Box::new(SignedJoinRequest::decode(&encoded)?)),
                _ => return Err(CoreError::Malformed("pending kind")),
            };
            pending.push(PendingProposal {
                proposal,
                reference: proposal_ref(&encoded)?,
                recorded_epoch,
            });
        }
        let mut invites = BTreeMap::new();
        for entry in expect_list(next(&mut items, "ledger")?, "ledger invites")? {
            let mut fields = expect_array(entry, 2, "ledger invite")?.into_iter();
            let invite = SignedInvite::decode(&expect_bytes(
                next(&mut fields, "ledger invite")?,
                "invite",
            )?)?;
            let uses = expect_uint(&next(&mut fields, "ledger invite")?, "invite uses")?;
            invites.insert(invite.id()?, StoredInvite { invite, uses });
        }
        let revoked_invites = expect_list(next(&mut items, "ledger")?, "ledger revoked")?
            .into_iter()
            .map(|id| expect_bytes32(id, "revoked invite"))
            .collect::<CoreResult<VecDeque<_>>>()?;
        let cover_failures = expect_list(next(&mut items, "ledger")?, "ledger reports")?
            .into_iter()
            .map(|report| CoverFailureReport::decode(&expect_bytes(report, "ledger report")?))
            .collect::<CoreResult<Vec<_>>>()?;
        let mut welcomes = BTreeMap::new();
        let mut welcome_order = VecDeque::new();
        for entry in expect_list(next(&mut items, "ledger")?, "ledger welcomes")? {
            let mut fields = expect_array(entry, 4, "ledger welcome")?.into_iter();
            let reference = expect_bytes32(next(&mut fields, "ledger welcome")?, "welcome ref")?;
            let epoch = expect_uint(&next(&mut fields, "ledger welcome")?, "welcome epoch")?;
            let welcome = expect_bytes(next(&mut fields, "ledger welcome")?, "welcome")?;
            let device_pk = expect_bytes(next(&mut fields, "ledger welcome")?, "welcome device")?;
            Welcome::decode(&welcome)?;
            welcomes.insert(
                reference,
                StoredWelcome {
                    epoch,
                    welcome,
                    device_pk,
                },
            );
            welcome_order.push_back(reference);
        }
        Ok(Self {
            state,
            group_info,
            epoch_started_at_ms,
            previous,
            windows,
            pending,
            invites,
            revoked_invites,
            cover_failures,
            welcomes,
            welcome_order,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests;
