//! A room: one group as served by the v0.2 delivery service.
//!
//! A room wraps the group's [`GroupLedger`] with the ordered log members
//! fetch (commits and message envelopes, numbered by `seq`), the alias
//! bindings of members and retention. Every public mutation returns the
//! [`RoomRecord`] to journal; [`Room::apply_record`] replays records.

use std::collections::{BTreeMap, VecDeque};

use ciborium::value::Value;
use cityg_core::binding::AliasBinding;
use cityg_core::cbor::{
    array, bytes, decode, encode, expect_array, expect_bytes, expect_bytes32, expect_label,
    expect_list, expect_uint, text, uint,
};
use cityg_core::hash::Digest;
use cityg_core::ledger::{GroupLedger, ProposalStatus};
use cityg_core::message::Envelope;
use cityg_core::session::GroupSnapshot;
use cityg_core::{CoreError, CoreResult};

use super::record::RoomRecord;

const ROOM_SNAPSHOT_LABEL: &str = "city-g/room/v1";

/// Deployment limits and retention of rooms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoomConfig {
    /// Largest `n_max` a new group may declare.
    pub max_n_max: u32,
    /// How long message envelopes stay in the log.
    pub message_retention_ms: u64,
    /// How long commits stay in the log (the latest commit always stays).
    pub commit_retention_ms: u64,
    /// Most entries kept in the log; the oldest messages go first.
    pub max_log_entries: usize,
}

impl Default for RoomConfig {
    fn default() -> Self {
        Self {
            max_n_max: 256,
            message_retention_ms: 7 * 24 * 3_600_000,
            commit_retention_ms: 30 * 24 * 3_600_000,
            max_log_entries: 50_000,
        }
    }
}

/// Why a room refused a request.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RoomError {
    /// A protocol object failed verification or a protocol rule.
    #[error("{0}")]
    Protocol(#[from] CoreError),
    /// The requester is not allowed to perform the request.
    #[error("forbidden: {0}")]
    Forbidden(&'static str),
    /// The request exceeds a deployment limit.
    #[error("limit: {0}")]
    Limit(&'static str),
    /// The requested object does not exist.
    #[error("not found: {0}")]
    NotFound(&'static str),
}

/// Body of a log entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogBody {
    Commit {
        commit: Vec<u8>,
        group_info: Vec<u8>,
    },
    Message {
        sender_leaf_id: Digest,
        envelope: Vec<u8>,
    },
    /// A recorded removal proposal: receivers reject the target's messages
    /// from this point of the log on.
    Proposal { proposal: Vec<u8> },
}

/// One entry of the ordered room log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    pub seq: u64,
    pub epoch: u64,
    pub accepted_at_ms: u64,
    pub body: LogBody,
}

impl LogEntry {
    fn is_commit(&self) -> bool {
        matches!(self.body, LogBody::Commit { .. })
    }

    fn to_value(&self) -> Value {
        let body = match &self.body {
            LogBody::Commit { commit, group_info } => {
                array(vec![uint(0), bytes(commit), bytes(group_info)])
            }
            LogBody::Message {
                sender_leaf_id,
                envelope,
            } => array(vec![uint(1), bytes(sender_leaf_id), bytes(envelope)]),
            LogBody::Proposal { proposal } => array(vec![uint(2), bytes(proposal)]),
        };
        array(vec![
            uint(self.seq),
            uint(self.epoch),
            uint(self.accepted_at_ms),
            body,
        ])
    }

    fn from_value(value: Value) -> CoreResult<Self> {
        let mut items = expect_array(value, 4, "log entry")?.into_iter();
        let mut next = || items.next().ok_or(CoreError::Malformed("log entry"));
        let seq = expect_uint(&next()?, "log seq")?;
        let epoch = expect_uint(&next()?, "log epoch")?;
        let accepted_at_ms = expect_uint(&next()?, "log time")?;
        let mut fields = expect_list(next()?, "log body")?.into_iter();
        let mut field = || fields.next().ok_or(CoreError::Malformed("log body"));
        let body = match expect_uint(&field()?, "log body tag")? {
            0 => LogBody::Commit {
                commit: expect_bytes(field()?, "log commit")?,
                group_info: expect_bytes(field()?, "log group info")?,
            },
            1 => LogBody::Message {
                sender_leaf_id: expect_bytes32(field()?, "log sender")?,
                envelope: expect_bytes(field()?, "log envelope")?,
            },
            2 => LogBody::Proposal {
                proposal: expect_bytes(field()?, "log proposal")?,
            },
            _ => return Err(CoreError::Malformed("log body tag")),
        };
        if fields.next().is_some() {
            return Err(CoreError::Malformed("log body"));
        }
        Ok(Self {
            seq,
            epoch,
            accepted_at_ms,
            body,
        })
    }
}

/// Public state a joiner or resyncing member fetches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomInfo {
    pub epoch: u64,
    pub snapshot: GroupSnapshot,
    pub pending_removals: Vec<Vec<u8>>,
    pub head_seq: u64,
    pub vacant: bool,
}

/// A page of the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogPage {
    pub entries: Vec<LogEntry>,
    pub head_seq: u64,
    pub first_seq: u64,
}

/// One group served by the delivery service.
#[derive(Clone, Debug)]
pub struct Room {
    ledger: GroupLedger,
    log: VecDeque<LogEntry>,
    next_seq: u64,
    aliases: BTreeMap<Digest, AliasBinding>,
    config: RoomConfig,
}

impl Room {
    /// Create a room from a genesis commit.
    pub fn create(
        commit: &[u8],
        group_info: &[u8],
        now_ms: u64,
        config: RoomConfig,
    ) -> Result<(Self, RoomRecord), RoomError> {
        let (ledger, _) = GroupLedger::create(commit, group_info, now_ms)?;
        if ledger.state().n_max() > config.max_n_max {
            return Err(RoomError::Limit("n_max above the deployment limit"));
        }
        let mut room = Self {
            ledger,
            log: VecDeque::new(),
            next_seq: 1,
            aliases: BTreeMap::new(),
            config,
        };
        room.push(
            0,
            now_ms,
            LogBody::Commit {
                commit: commit.to_vec(),
                group_info: group_info.to_vec(),
            },
        );
        Ok((
            room,
            RoomRecord::Genesis {
                commit: commit.to_vec(),
                group_info: group_info.to_vec(),
                at_ms: now_ms,
            },
        ))
    }

    fn push(&mut self, epoch: u64, accepted_at_ms: u64, body: LogBody) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.log.push_back(LogEntry {
            seq,
            epoch,
            accepted_at_ms,
            body,
        });
        self.enforce_log_cap();
        seq
    }

    fn enforce_log_cap(&mut self) {
        while self.log.len() > self.config.max_log_entries {
            // Drop the oldest message; if only commits remain, the oldest
            // commit that is not the latest.
            let position = self
                .log
                .iter()
                .position(|entry| !entry.is_commit())
                .or_else(|| (self.log.len() > 1).then_some(0));
            match position {
                Some(position) => {
                    self.log.remove(position);
                }
                None => break,
            }
        }
    }

    /// Accept the next commit.
    pub fn publish_commit(
        &mut self,
        commit: &[u8],
        group_info: &[u8],
        now_ms: u64,
    ) -> Result<(LogEntry, RoomRecord), RoomError> {
        let accepted = self.ledger.apply_commit(commit, group_info, now_ms)?;
        for member in &accepted.removed {
            self.aliases.remove(&member.leaf_id);
        }
        let seq = self.push(
            accepted.epoch,
            now_ms,
            LogBody::Commit {
                commit: commit.to_vec(),
                group_info: group_info.to_vec(),
            },
        );
        let entry = self.entry(seq).ok_or(RoomError::NotFound("log entry"))?;
        Ok((
            entry,
            RoomRecord::Commit {
                commit: commit.to_vec(),
                group_info: group_info.to_vec(),
                at_ms: now_ms,
            },
        ))
    }

    fn entry(&self, seq: u64) -> Option<LogEntry> {
        self.log
            .iter()
            .rev()
            .find(|entry| entry.seq == seq)
            .cloned()
    }

    /// Relay an envelope sent by the member `sender` (the leaf the request
    /// authenticated as).
    pub fn send(
        &mut self,
        envelope: &[u8],
        sender: &Digest,
        now_ms: u64,
    ) -> Result<(LogEntry, RoomRecord), RoomError> {
        let decoded = Envelope::decode(envelope)?;
        if &decoded.header.sender_leaf_id != sender {
            return Err(RoomError::Forbidden(
                "envelope sender is not the session member",
            ));
        }
        let entry = self.apply_message(envelope, now_ms)?;
        Ok((
            entry,
            RoomRecord::Message {
                envelope: envelope.to_vec(),
                at_ms: now_ms,
            },
        ))
    }

    fn apply_message(&mut self, envelope: &[u8], now_ms: u64) -> Result<LogEntry, RoomError> {
        let accepted = self.ledger.accept_message(envelope, now_ms)?;
        let seq = self.push(
            accepted.epoch,
            now_ms,
            LogBody::Message {
                sender_leaf_id: accepted.sender_leaf_id,
                envelope: envelope.to_vec(),
            },
        );
        self.entry(seq).ok_or(RoomError::NotFound("log entry"))
    }

    /// Record a removal proposal. Returns its status, whether the room is
    /// now vacant, and the record to journal when it was new.
    pub fn submit_remove_proposal(
        &mut self,
        proposal: &[u8],
        now_ms: u64,
    ) -> Result<(ProposalStatus, bool, Option<RoomRecord>), RoomError> {
        let status = self.ledger.submit_remove_proposal(proposal)?;
        let record = (status == ProposalStatus::Recorded).then(|| {
            self.push(
                self.ledger.epoch(),
                now_ms,
                LogBody::Proposal {
                    proposal: proposal.to_vec(),
                },
            );
            RoomRecord::RemoveProposal {
                proposal: proposal.to_vec(),
                at_ms: now_ms,
            }
        });
        Ok((status, self.ledger.is_vacant(), record))
    }

    /// Store an admin-signed invite.
    pub fn publish_invite(
        &mut self,
        invite: &[u8],
        now_ms: u64,
    ) -> Result<(Digest, RoomRecord), RoomError> {
        let id = self.ledger.publish_invite(invite, now_ms)?;
        Ok((
            id,
            RoomRecord::Invite {
                invite: invite.to_vec(),
                at_ms: now_ms,
            },
        ))
    }

    /// Invite `id`, if stored and not expired.
    #[must_use]
    pub fn invite(&self, id: &Digest, now_ms: u64) -> Option<Vec<u8>> {
        self.ledger
            .invite(id, now_ms)
            .map(|invite| invite.encoded().to_vec())
    }

    /// Store a member's alias binding (replacing its previous one).
    pub fn bind_alias(&mut self, binding: &[u8]) -> Result<RoomRecord, RoomError> {
        self.apply_alias(binding)?;
        Ok(RoomRecord::Alias {
            binding: binding.to_vec(),
        })
    }

    fn apply_alias(&mut self, binding: &[u8]) -> Result<(), RoomError> {
        let binding = AliasBinding::decode(binding)?;
        if &binding.gid != self.ledger.gid() {
            return Err(RoomError::Protocol(CoreError::Invalid(
                "alias binding for another group",
            )));
        }
        let leaf = binding.leaf_id()?;
        if self.ledger.roster().member_by_leaf(&leaf).is_none() {
            return Err(RoomError::Forbidden("alias binding of a non-member"));
        }
        self.aliases.insert(leaf, binding);
        Ok(())
    }

    /// Alias bindings of current members.
    #[must_use]
    pub fn aliases(&self) -> Vec<Vec<u8>> {
        self.aliases
            .iter()
            .filter(|(leaf, _)| self.ledger.roster().member_by_leaf(leaf).is_some())
            .map(|(_, binding)| binding.encoded().to_vec())
            .collect()
    }

    /// Record a cover-failure report.
    pub fn submit_cover_failure(&mut self, report: &[u8]) -> Result<RoomRecord, RoomError> {
        self.ledger.submit_cover_failure(report)?;
        Ok(RoomRecord::CoverFailure {
            report: report.to_vec(),
        })
    }

    /// Recorded cover-failure reports.
    #[must_use]
    pub fn cover_failures(&self) -> Vec<Vec<u8>> {
        self.ledger
            .cover_failures()
            .iter()
            .map(|report| report.encoded().to_vec())
            .collect()
    }

    /// Public state for joiners.
    pub fn info(&self) -> Result<RoomInfo, RoomError> {
        Ok(RoomInfo {
            epoch: self.ledger.epoch(),
            snapshot: self.ledger.snapshot()?,
            pending_removals: self
                .ledger
                .pending_removals()
                .map(|proposal| proposal.encoded().to_vec())
                .collect(),
            head_seq: self.head_seq(),
            vacant: self.ledger.is_vacant(),
        })
    }

    /// Up to `limit` log entries after `after_seq`.
    #[must_use]
    pub fn log_after(&self, after_seq: u64, limit: usize) -> LogPage {
        LogPage {
            entries: self
                .log
                .iter()
                .filter(|entry| entry.seq > after_seq)
                .take(limit)
                .cloned()
                .collect(),
            head_seq: self.head_seq(),
            first_seq: self.log.front().map_or(self.next_seq, |entry| entry.seq),
        }
    }

    /// Sequence number of the last log entry.
    #[must_use]
    pub fn head_seq(&self) -> u64 {
        self.next_seq - 1
    }

    /// Drop expired messages and commits (the latest commit stays).
    pub fn prune(&mut self, now_ms: u64) -> usize {
        let before = self.log.len();
        let latest_commit = self
            .log
            .iter()
            .rev()
            .find(|entry| entry.is_commit())
            .map(|entry| entry.seq);
        let config = self.config;
        self.log.retain(|entry| {
            let age = now_ms.saturating_sub(entry.accepted_at_ms);
            if entry.is_commit() {
                Some(entry.seq) == latest_commit || age <= config.commit_retention_ms
            } else {
                age <= config.message_retention_ms
            }
        });
        before - self.log.len()
    }

    /// The group ledger.
    #[must_use]
    pub fn ledger(&self) -> &GroupLedger {
        &self.ledger
    }

    /// Group identifier.
    #[must_use]
    pub fn gid(&self) -> &Digest {
        self.ledger.gid()
    }

    /// Whether `leaf` is a current member.
    #[must_use]
    pub fn is_member(&self, leaf: &Digest) -> bool {
        self.ledger.roster().member_by_leaf(leaf).is_some()
    }

    /// Re-apply a journaled record (replay after a restart).
    pub fn apply_record(&mut self, record: &RoomRecord) -> Result<(), RoomError> {
        match record {
            RoomRecord::Genesis { .. } => {
                return Err(RoomError::Protocol(CoreError::Invalid(
                    "genesis record inside a room journal",
                )));
            }
            RoomRecord::Commit {
                commit,
                group_info,
                at_ms,
            } => {
                self.publish_commit(commit, group_info, *at_ms)?;
            }
            RoomRecord::Message { envelope, at_ms } => {
                self.apply_message(envelope, *at_ms)?;
            }
            RoomRecord::RemoveProposal { proposal, at_ms } => {
                self.submit_remove_proposal(proposal, *at_ms)?;
            }
            RoomRecord::Invite { invite, at_ms } => {
                self.publish_invite(invite, *at_ms)?;
            }
            RoomRecord::Alias { binding } => self.apply_alias(binding)?,
            RoomRecord::CoverFailure { report } => {
                self.submit_cover_failure(report)?;
            }
        }
        Ok(())
    }

    /// Rebuild a room from its journal (first record: genesis).
    pub fn replay(records: &[RoomRecord], config: RoomConfig) -> Result<Self, RoomError> {
        let (first, rest) = records
            .split_first()
            .ok_or(RoomError::NotFound("room journal"))?;
        let RoomRecord::Genesis {
            commit,
            group_info,
            at_ms,
        } = first
        else {
            return Err(RoomError::Protocol(CoreError::Invalid(
                "room journal does not start with a genesis",
            )));
        };
        let (mut room, _) = Self::create(commit, group_info, *at_ms, config)?;
        for record in rest {
            room.apply_record(record)?;
        }
        Ok(room)
    }

    /// Deterministic snapshot of the room.
    pub fn to_snapshot(&self) -> CoreResult<Vec<u8>> {
        encode(&array(vec![
            text(ROOM_SNAPSHOT_LABEL),
            bytes(&self.ledger.to_cbor()?),
            uint(self.next_seq),
            array(self.log.iter().map(LogEntry::to_value).collect()),
            array(
                self.aliases
                    .values()
                    .map(|binding| bytes(binding.encoded()))
                    .collect(),
            ),
        ]))
    }

    /// Restore a room from [`Room::to_snapshot`].
    pub fn from_snapshot(encoded: &[u8], config: RoomConfig) -> Result<Self, RoomError> {
        let mut items = expect_array(
            decode(encoded, 1 << 30, "room snapshot")?,
            5,
            "room snapshot",
        )?
        .into_iter();
        let mut next = || items.next().ok_or(CoreError::Malformed("room snapshot"));
        expect_label(&next()?, ROOM_SNAPSHOT_LABEL, "room snapshot")?;
        let ledger = GroupLedger::from_cbor(&expect_bytes(next()?, "room ledger")?)?;
        let next_seq = expect_uint(&next()?, "room next seq")?;
        let log = expect_list(next()?, "room log")?
            .into_iter()
            .map(LogEntry::from_value)
            .collect::<CoreResult<VecDeque<_>>>()?;
        if log
            .iter()
            .zip(log.iter().skip(1))
            .any(|(a, b)| a.seq >= b.seq)
            || log.back().is_some_and(|entry| entry.seq >= next_seq)
        {
            return Err(RoomError::Protocol(CoreError::Malformed("room log order")));
        }
        let mut aliases = BTreeMap::new();
        for binding in expect_list(next()?, "room aliases")? {
            let binding = AliasBinding::decode(&expect_bytes(binding, "room alias")?)?;
            aliases.insert(binding.leaf_id()?, binding);
        }
        Ok(Self {
            ledger,
            log,
            next_seq,
            aliases,
            config,
        })
    }
}
