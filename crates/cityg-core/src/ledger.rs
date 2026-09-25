//! Delivery-service state machine for one group.
//!
//! The delivery service orders commits and relays messages; it holds no
//! group secret. [`GroupLedger`] runs the public commit transition on every
//! commit it accepts (so it can never be tricked into relaying a commit that
//! members would reject), enforces the rules that need a global order or a
//! clock, and stores the public data joiners need:
//!
//! * the first valid commit for epoch `n + 1` wins; later ones are rejected
//!   with an epoch mismatch and their authors rebuild on the new epoch;
//! * a commit must include every recorded removal proposal (P-3.c);
//! * the GroupInfo published with a commit must be signed by its author and
//!   describe the epoch the ledger computed;
//! * invite expiry is checked against the ledger clock;
//! * a message is accepted for the current epoch, or for the previous one
//!   during [`GRACE_WINDOW_MS`], only from a member of that epoch without a
//!   recorded removal, and at most once per `(epoch, sender, generation)`.

use std::collections::BTreeMap;

use ciborium::value::Value;

use crate::admission::SignedInvite;
use crate::cbor::{
    array, bytes, decode, encode, expect_array, expect_bytes, expect_bytes32, expect_label,
    expect_list, expect_uint, text, uint,
};
use crate::commit::CommitKind;
use crate::cover::CoverFailureReport;
use crate::error::{CoreError, CoreResult};
use crate::group_info::SignedGroupInfo;
use crate::hash::{Digest, digest_eq};
use crate::message::{Envelope, GRACE_WINDOW_MS, ReplayWindow, epoch_ref};
use crate::proposal::SignedRemoveProposal;
use crate::roster::{MemberRecord, Roster};
use crate::session::GroupSnapshot;
use crate::state::{CommitTransition, PublicGroupState, verify_commit, verify_genesis};
use crate::tree::next;

/// Label of a ledger snapshot.
const LEDGER_LABEL: &str = "city-g/ledger/v1";
/// Most invites a group keeps.
pub const MAX_INVITES: usize = 256;
/// Most cover-failure reports a group keeps.
pub const MAX_COVER_FAILURES: usize = 256;

/// Summary of an accepted commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedCommit {
    pub epoch: u64,
    pub kind: CommitKind,
    pub author_leaf_id: Digest,
    pub removed: Vec<MemberRecord>,
    pub entered: Option<MemberRecord>,
}

impl AcceptedCommit {
    fn from_transition(transition: &CommitTransition) -> Self {
        let content = &transition.commit.content;
        Self {
            epoch: content.epoch,
            kind: content.kind,
            author_leaf_id: content.author_leaf_id,
            removed: transition.staged.removed.clone(),
            entered: transition.staged.entered.clone(),
        }
    }
}

/// Metadata of an accepted message envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedMessage {
    pub epoch: u64,
    pub sender_leaf_id: Digest,
    pub generation: u32,
}

/// Whether a removal proposal was new.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalStatus {
    Recorded,
    AlreadyRecorded,
}

#[derive(Clone, Debug)]
struct PreviousEpoch {
    epoch: u64,
    roster: Roster,
    ended_at_ms: u64,
    windows: BTreeMap<Digest, ReplayWindow>,
}

/// Public state of one group as held by the delivery service.
#[derive(Clone, Debug)]
pub struct GroupLedger {
    state: PublicGroupState,
    group_info: Vec<u8>,
    epoch_started_at_ms: u64,
    previous: Option<PreviousEpoch>,
    windows: BTreeMap<Digest, ReplayWindow>,
    pending: BTreeMap<u32, SignedRemoveProposal>,
    invites: BTreeMap<Digest, SignedInvite>,
    cover_failures: Vec<CoverFailureReport>,
}

fn check_group_info(group_info: &[u8], transition: &CommitTransition) -> CoreResult<()> {
    let signed = SignedGroupInfo::decode_unverified(group_info)?;
    let info = signed.info();
    if info.group_context != transition.group_context
        || info.confirmation_tag != transition.commit.confirmation_tag
        || info.signer_leaf_id != transition.commit.content.author_leaf_id
    {
        return Err(CoreError::Invalid("group info does not match the commit"));
    }
    signed.verify(&transition.next.tree, &transition.next.roster)
}

impl GroupLedger {
    /// Start a ledger from a genesis commit and its GroupInfo.
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
                previous: None,
                windows: BTreeMap::new(),
                pending: BTreeMap::new(),
                invites: BTreeMap::new(),
                cover_failures: Vec::new(),
            },
            accepted,
        ))
    }

    /// Accept the next commit.
    pub fn apply_commit(
        &mut self,
        commit: &[u8],
        group_info: &[u8],
        now_ms: u64,
    ) -> CoreResult<AcceptedCommit> {
        let transition = verify_commit(&self.state, commit)?;
        let content = &transition.commit.content;
        for (slot, proposal) in &self.pending {
            let committed = transition.staged.removed.iter().any(|member| {
                member.slot == *slot && member.generation == proposal.proposal().target_generation
            });
            if !committed {
                return Err(CoreError::Invalid(
                    "pending removal proposals must be committed",
                ));
            }
        }
        if let Some(admission) = content
            .join
            .as_ref()
            .and_then(|join| join.admission.as_ref())
            && admission
                .expires_at_ms()
                .is_some_and(|expires_at_ms| now_ms > expires_at_ms)
        {
            return Err(CoreError::Invalid("invite expired"));
        }
        check_group_info(group_info, &transition)?;
        let accepted = AcceptedCommit::from_transition(&transition);
        let previous_state = std::mem::replace(&mut self.state, transition.next);
        self.previous = Some(PreviousEpoch {
            epoch: previous_state.epoch,
            roster: previous_state.roster,
            ended_at_ms: now_ms,
            windows: std::mem::take(&mut self.windows),
        });
        self.group_info = group_info.to_vec();
        self.epoch_started_at_ms = now_ms;
        self.pending.clear();
        let (gid, roster) = (self.state.gid, &self.state.roster);
        self.invites.retain(|_, invite| {
            invite.authorize(&gid, roster).is_ok() && invite.invite().expires_at_ms >= now_ms
        });
        Ok(accepted)
    }

    /// Record a removal proposal after checking it against the roster.
    pub fn submit_remove_proposal(&mut self, encoded: &[u8]) -> CoreResult<ProposalStatus> {
        let proposal = SignedRemoveProposal::decode(encoded)?;
        let target = proposal.authorize(&self.state.gid, &self.state.roster)?;
        let slot = target.slot;
        if self.pending.contains_key(&slot) {
            return Ok(ProposalStatus::AlreadyRecorded);
        }
        self.pending.insert(slot, proposal);
        Ok(ProposalStatus::Recorded)
    }

    /// Recorded removal proposals, by target slot.
    pub fn pending_removals(&self) -> impl Iterator<Item = &SignedRemoveProposal> {
        self.pending.values()
    }

    /// Whether every member has a recorded removal: nobody can commit any
    /// more, and the group only comes back through a joiner's commit.
    #[must_use]
    pub fn is_vacant(&self) -> bool {
        self.state
            .roster
            .members()
            .all(|member| self.pending.contains_key(&member.slot))
    }

    /// Store an invite signed by a current admin.
    pub fn publish_invite(&mut self, encoded: &[u8], now_ms: u64) -> CoreResult<Digest> {
        let invite = SignedInvite::decode(encoded)?;
        invite.authorize(&self.state.gid, &self.state.roster)?;
        if invite.invite().expires_at_ms < now_ms {
            return Err(CoreError::Invalid("invite expired"));
        }
        let id = invite.id()?;
        if !self.invites.contains_key(&id) {
            self.invites
                .retain(|_, stored| stored.invite().expires_at_ms >= now_ms);
            if self.invites.len() >= MAX_INVITES {
                return Err(CoreError::TooLarge("invites"));
            }
            self.invites.insert(id, invite);
        }
        Ok(id)
    }

    /// Invite with identifier `id`, if stored and not expired.
    #[must_use]
    pub fn invite(&self, id: &Digest, now_ms: u64) -> Option<&SignedInvite> {
        self.invites
            .get(id)
            .filter(|invite| invite.invite().expires_at_ms >= now_ms)
    }

    /// Accept an envelope for relay.
    pub fn accept_message(&mut self, encoded: &[u8], now_ms: u64) -> CoreResult<AcceptedMessage> {
        let envelope = Envelope::decode(encoded)?;
        let header = &envelope.header;
        let sender = header.sender_leaf_id;
        let gid = self.state.gid;
        // A sender must be a member of the current epoch, even for a late
        // message of the previous epoch: a member removed by the last commit
        // cannot keep posting during the grace window.
        if self.state.roster.member_by_leaf(&sender).is_none() {
            return Err(CoreError::Unauthorized("sender is not a member"));
        }
        if self
            .pending
            .values()
            .any(|proposal| proposal.proposal().target_leaf_id == sender)
        {
            return Err(CoreError::Unauthorized("sender has a pending removal"));
        }
        let (epoch, roster, windows) =
            if digest_eq(&header.epoch_ref, &epoch_ref(&gid, self.state.epoch)?) {
                (self.state.epoch, &self.state.roster, &mut self.windows)
            } else {
                match &mut self.previous {
                    Some(previous)
                        if digest_eq(&header.epoch_ref, &epoch_ref(&gid, previous.epoch)?)
                            && now_ms <= previous.ended_at_ms.saturating_add(GRACE_WINDOW_MS) =>
                    {
                        (previous.epoch, &previous.roster, &mut previous.windows)
                    }
                    _ => return Err(CoreError::Invalid("message for an inactive epoch")),
                }
            };
        if roster.member_by_leaf(&sender).is_none() {
            return Err(CoreError::Unauthorized(
                "sender is not a member of the epoch",
            ));
        }
        windows
            .entry(sender)
            .or_default()
            .accept(header.generation)?;
        Ok(AcceptedMessage {
            epoch,
            sender_leaf_id: sender,
            generation: header.generation,
        })
    }

    /// Record a cover-failure report from a member of the current epoch.
    pub fn submit_cover_failure(&mut self, encoded: &[u8]) -> CoreResult<()> {
        let report = CoverFailureReport::decode(encoded)?;
        report.verify(&self.state.gid, &self.state.roster)?;
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

    /// What a joiner (or a resynchronising member) fetches.
    pub fn snapshot(&self) -> CoreResult<GroupSnapshot> {
        Ok(GroupSnapshot {
            group_info: self.group_info.clone(),
            tree: self.state.tree.to_cbor()?,
            roster: self.state.roster.to_cbor()?,
        })
    }

    /// Current public state.
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

    /// Current roster.
    #[must_use]
    pub fn roster(&self) -> &Roster {
        &self.state.roster
    }

    /// GroupInfo of the current epoch.
    #[must_use]
    pub fn group_info(&self) -> &[u8] {
        &self.group_info
    }

    /// When the current epoch started (ledger clock).
    #[must_use]
    pub fn epoch_started_at_ms(&self) -> u64 {
        self.epoch_started_at_ms
    }

    /// Deterministic snapshot of the ledger.
    pub fn to_cbor(&self) -> CoreResult<Vec<u8>> {
        let windows = |windows: &BTreeMap<Digest, ReplayWindow>| {
            array(
                windows
                    .iter()
                    .map(|(leaf, window)| array(vec![bytes(leaf), window.to_value()]))
                    .collect(),
            )
        };
        let previous = match &self.previous {
            None => Value::Null,
            Some(previous) => array(vec![
                uint(previous.epoch),
                bytes(&previous.roster.to_cbor()?),
                uint(previous.ended_at_ms),
                windows(&previous.windows),
            ]),
        };
        encode(&array(vec![
            text(LEDGER_LABEL),
            bytes(&self.state.to_cbor()?),
            bytes(&self.group_info),
            uint(self.epoch_started_at_ms),
            previous,
            windows(&self.windows),
            array(
                self.pending
                    .values()
                    .map(|proposal| bytes(proposal.encoded()))
                    .collect(),
            ),
            array(
                self.invites
                    .values()
                    .map(|invite| bytes(invite.encoded()))
                    .collect(),
            ),
            array(
                self.cover_failures
                    .iter()
                    .map(|report| bytes(report.encoded()))
                    .collect(),
            ),
        ]))
    }

    /// Restore a snapshot, re-checking every signed object it holds.
    pub fn from_cbor(encoded: &[u8]) -> CoreResult<Self> {
        let mut items =
            expect_array(decode(encoded, 256 << 20, "ledger")?, 9, "ledger")?.into_iter();
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
        signed.verify(&state.tree, &state.roster)?;
        let epoch_started_at_ms = expect_uint(&next(&mut items, "ledger")?, "ledger epoch start")?;
        let read_windows = |value: Value| -> CoreResult<BTreeMap<Digest, ReplayWindow>> {
            expect_list(value, "ledger windows")?
                .into_iter()
                .map(|entry| {
                    let mut fields = expect_array(entry, 2, "ledger window")?.into_iter();
                    Ok((
                        expect_bytes32(next(&mut fields, "ledger window")?, "window leaf")?,
                        ReplayWindow::from_value(next(&mut fields, "ledger window")?)?,
                    ))
                })
                .collect()
        };
        let previous = match next(&mut items, "ledger")? {
            Value::Null => None,
            value => {
                let mut fields = expect_array(value, 4, "ledger previous")?.into_iter();
                Some(PreviousEpoch {
                    epoch: expect_uint(&next(&mut fields, "ledger previous")?, "previous epoch")?,
                    roster: Roster::from_cbor(
                        &expect_bytes(next(&mut fields, "ledger previous")?, "previous roster")?,
                        &state.gid,
                    )?,
                    ended_at_ms: expect_uint(&next(&mut fields, "ledger previous")?, "ended at")?,
                    windows: read_windows(next(&mut fields, "ledger previous")?)?,
                })
            }
        };
        let windows = read_windows(next(&mut items, "ledger")?)?;
        let mut pending = BTreeMap::new();
        for entry in expect_list(next(&mut items, "ledger")?, "ledger pending")? {
            let proposal = SignedRemoveProposal::decode(&expect_bytes(entry, "ledger pending")?)?;
            let slot = proposal.authorize(&state.gid, &state.roster)?.slot;
            pending.insert(slot, proposal);
        }
        let mut invites = BTreeMap::new();
        for entry in expect_list(next(&mut items, "ledger")?, "ledger invites")? {
            let invite = SignedInvite::decode(&expect_bytes(entry, "ledger invite")?)?;
            invites.insert(invite.id()?, invite);
        }
        let cover_failures = expect_list(next(&mut items, "ledger")?, "ledger reports")?
            .into_iter()
            .map(|entry| CoverFailureReport::decode(&expect_bytes(entry, "ledger report")?))
            .collect::<CoreResult<Vec<_>>>()?;
        Ok(Self {
            state,
            group_info,
            epoch_started_at_ms,
            previous,
            windows,
            pending,
            invites,
            cover_failures,
        })
    }
}
