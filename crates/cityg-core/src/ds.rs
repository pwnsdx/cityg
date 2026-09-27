//! An in-memory delivery service (docs/specs.md section 14, with sections 2
//! and 3 of docs/specs-v0.5-draft.md).
//!
//! It never draws a group secret and never signs a group object. It records
//! requests after checking them, closes windows (E-1) at the cadence of
//! their removals (E-16), places joins (E-11), assigns the roles of a
//! window among its joiners and online members or, with nobody online, to
//! an entrant (E-3, E-7, E-17): its district commits, its city tasks and
//! its seal; checks what the roles send back, assigns the relays and flat
//! elements of each window's islands (E-15), serves one packet per member,
//! whole or by island (E-13, E-15), or by repair (E-17), the chains of seals
//! and the entries of joiners and returning members, whole or by island
//! (E-8, E-10, E-17), keeps the latest wrap of
//! every node, enforces recorded removals at delivery, evicts under an
//! admin-signed policy, and keeps the records auditors sample (E-12).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::audit::{AuditRecord, records};
use crate::card::Card;
use crate::commit::{Change, CityTask, DistrictCommit, Seal, SealKind};
use crate::crypto::{Digest, Wrap, ZERO32, kem_pk_hash};
use crate::dispute::{Dispute, DisputeStatement, DisputeVerifier};
use crate::error::{CoreError, CoreResult};
use crate::member::{CatchUps, PendingRemoval};
use crate::objects::{
    Authorizer, CatchUpRequest, ChangeKind, Checkpoint, Eviction, GroupPolicy, JoinRequest,
    ReEntryRequest, RemoveProposal, RepairRequest, Request, UpdateRequest, Urgency,
};
use crate::packet::{
    EntrantEvidence, EntrantProof, Entry, EntrySteps, EntryTop, Packet, RegistryUpdate, SealLink,
    SealerEvidence,
};
use crate::registry::RegistryHeader;
use crate::rekey::{Step, WindowIndex};
use crate::roles::{WelcomeKind, WelcomeTask, WindowTask, WindowWork};
use crate::schedule::{confirmed_transcript_hash, interim_transcript_hash};
use crate::top::{RelayElement, Repair, Top, TopTask};
use crate::tree::{
    CityPart, LeafNode, LeafProof, MAX_HEIGHT, NodeId, Occupancy, ParentNode, Shape, leaf_key_hash,
};
use crate::welcome::Welcome;
use crate::window::{
    PublicState, Requests, SealerInfo, WindowShape, check_city_task, check_committer,
    check_district_commit, check_entry, check_sealer, check_window, district_leaves,
    joiner_request, needed_height,
};

/// Timing of windows (E-16).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DsConfig {
    /// Longest wait of a request (`WINDOW_ORDINARY`): joins, updates,
    /// ordinary removals and evictions wait at most this long.
    pub window_ordinary_ms: u64,
    /// Window length when an urgent removal is pending (`WINDOW_URGENT`).
    pub window_urgent_ms: u64,
    /// Give a window's tasks to its joiners first (docs/specs-v0.5-draft.md
    /// section 3.4); otherwise to members only, as in v0.4.
    pub joiner_tasks: bool,
    /// Give no role to a performer once this many members asked for
    /// repairs of nodes it drew (docs/specs-v0.5-draft.md section 3.8); 0
    /// never excludes.
    pub repair_threshold: usize,
}

impl Default for DsConfig {
    fn default() -> Self {
        Self {
            window_ordinary_ms: 60_000,
            window_urgent_ms: 5_000,
            joiner_tasks: true,
            repair_threshold: 2,
        }
    }
}

/// Which top an island packet carries (E-15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TopChoice {
    /// The relay element of the member's island, else its flat element,
    /// else a refresh.
    Best,
    /// The flat element, else a refresh: for a member whose relay element
    /// did not open or led to a wrong tag.
    AvoidRelay,
    /// A refresh: for a relay, or a member that wants its whole path back.
    Refresh,
}

#[derive(Clone, Debug)]
struct Queued<T> {
    item: T,
    recorded_ms: u64,
}

#[derive(Clone, Debug, Default)]
struct Queue {
    joins: Vec<Queued<JoinRequest>>,
    removals: Vec<Queued<RemoveProposal>>,
    evictions: Vec<Queued<Eviction>>,
    updates: Vec<Queued<UpdateRequest>>,
    re_entries: Vec<Queued<ReEntryRequest>>,
    catch_ups: Vec<Queued<CatchUpRequest>>,
    policy: Option<Queued<GroupPolicy>>,
}

impl Queue {
    fn oldest(&self) -> Option<u64> {
        let times = self
            .joins
            .iter()
            .map(|q| q.recorded_ms)
            .chain(self.removals.iter().map(|q| q.recorded_ms))
            .chain(self.evictions.iter().map(|q| q.recorded_ms))
            .chain(self.updates.iter().map(|q| q.recorded_ms))
            .chain(self.re_entries.iter().map(|q| q.recorded_ms))
            .chain(self.catch_ups.iter().map(|q| q.recorded_ms))
            .chain(self.policy.iter().map(|q| q.recorded_ms));
        times.min()
    }

    /// When the oldest urgent removal was recorded. Evictions are ordinary.
    fn oldest_urgent(&self) -> Option<u64> {
        self.removals
            .iter()
            .filter(|q| q.item.urgency == Urgency::Urgent)
            .map(|q| q.recorded_ms)
            .min()
    }

    /// Every target of a recorded removal or eviction, with its urgency and
    /// when it was recorded: for an urgent one, when its first urgent
    /// removal was, which starts the urgent clock; otherwise, its first
    /// record.
    fn removal_targets(&self) -> BTreeMap<Occupancy, (u64, Urgency)> {
        let mut first: BTreeMap<Occupancy, (u64, Option<u64>)> = BTreeMap::new();
        for (target, at, urgency) in self
            .removals
            .iter()
            .map(|q| (q.item.target, q.recorded_ms, q.item.urgency))
            .chain(
                self.evictions
                    .iter()
                    .map(|q| (q.item.target, q.recorded_ms, Urgency::Ordinary)),
            )
        {
            let urgent = (urgency == Urgency::Urgent).then_some(at);
            first
                .entry(target)
                .and_modify(|(any, urgent_at)| {
                    *any = (*any).min(at);
                    *urgent_at = match (*urgent_at, urgent) {
                        (Some(a), Some(b)) => Some(a.min(b)),
                        (a, b) => a.or(b),
                    };
                })
                .or_insert((at, urgent));
        }
        first
            .into_iter()
            .map(|(target, (any, urgent_at))| {
                let entry = urgent_at.map_or((any, Urgency::Ordinary), |at| (at, Urgency::Urgent));
                (target, entry)
            })
            .collect()
    }
}

/// The latest re-key of a node: its epoch and its wraps, by target.
#[derive(Clone, Debug)]
struct Latest {
    epoch: u64,
    wraps: HashMap<NodeId, Wrap>,
}

#[derive(Clone, Debug)]
struct EntryData {
    steps: EntrySteps,
    leaf: LeafProof,
    nodes: Vec<Option<ParentNode>>,
}

/// A sealed window, as the delivery service keeps it.
#[derive(Clone, Debug)]
pub struct StoredWindow {
    pub task: WindowTask,
    pub seal: Seal,
    pub commits: Vec<DistrictCommit>,
    pub city_tasks: Vec<CityTask>,
    pub requests: Requests,
    pub catch_ups: CatchUps,
    index: WindowIndex,
    sealer: SealerEvidence,
    registry_before: RegistryHeader,
    registry: RegistryHeader,
    policy: Option<GroupPolicy>,
    leaves: BTreeMap<u32, Option<LeafNode>>,
    entries: HashMap<Digest, EntryData>,
    welcomes: HashMap<Digest, Welcome>,
    audits: Vec<AuditRecord>,
    committer_leaves: HashMap<Occupancy, LeafProof>,
    shape: Shape,
    top: TopTask,
    relays: BTreeMap<u32, RelayElement>,
    flats: BTreeMap<u32, Wrap>,
    /// Repairs of members a faulty task cut off, by leaf.
    repairs: BTreeMap<u32, Repair>,
    /// The member asked for each leaf's repair, and how many were asked.
    repair_makers: BTreeMap<u32, (Occupancy, usize)>,
    /// Disputes that convicted a performer of the window.
    disputes: Vec<Dispute>,
}

impl StoredWindow {
    /// Audit records of the window's entries.
    #[must_use]
    pub fn audits(&self) -> &[AuditRecord] {
        &self.audits
    }

    /// Leaf of a committer of the window, in the tree after it.
    #[must_use]
    pub fn committer_leaf(&self, committer: Occupancy) -> Option<&LeafProof> {
        self.committer_leaves.get(&committer)
    }

    /// Total size of the window's district commits.
    #[must_use]
    pub fn district_bytes(&self) -> usize {
        self.commits
            .iter()
            .map(|commit| commit.encoded().len())
            .sum()
    }

    /// Size of the seal.
    #[must_use]
    pub fn seal_bytes(&self) -> usize {
        self.seal.encode().map_or(0, |encoded| encoded.len())
    }

    /// Who gives the window's islands their top (E-15).
    #[must_use]
    pub const fn top_task(&self) -> &TopTask {
        &self.top
    }

    /// The disputes that convicted a performer of the window: evidence that
    /// anyone can check (docs/specs-v0.5-draft.md section 3.8).
    #[must_use]
    pub fn disputes(&self) -> &[Dispute] {
        &self.disputes
    }

    /// Islands whose relay element or flat element was delivered.
    #[must_use]
    pub fn topped_islands(&self) -> BTreeSet<u32> {
        self.relays
            .keys()
            .chain(self.flats.keys())
            .copied()
            .collect()
    }
}

struct OpenWindow {
    task: WindowTask,
    window: WindowShape,
    sealer: SealerInfo,
    requests: Requests,
    catch_ups: CatchUps,
    commits: BTreeMap<u32, DistrictCommit>,
    city_tasks: BTreeMap<CityPart, CityTask>,
}

/// The delivery service of one group.
pub struct DeliveryService {
    config: DsConfig,
    genesis: Seal,
    genesis_registry: RegistryHeader,
    genesis_leaf: LeafNode,
    state: PublicState,
    windows: Vec<StoredWindow>,
    latest: HashMap<NodeId, Latest>,
    queue: Queue,
    open: Option<OpenWindow>,
    online: BTreeSet<Occupancy>,
    checkpoints: Vec<Checkpoint>,
    invite_uses: HashMap<Digest, u64>,
    /// The members that asked for repairs of nodes each performer drew.
    blamed: BTreeMap<Occupancy, BTreeSet<Occupancy>>,
    /// Performers that a dispute convicted.
    convicted: BTreeSet<Occupancy>,
    /// The proof system that checks disputes, if the service has one.
    verifier: Option<Box<dyn DisputeVerifier>>,
}

impl core::fmt::Debug for DeliveryService {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeliveryService")
            .field("epoch", &self.state.epoch)
            .field("members", &self.state.tree.member_count())
            .finish_non_exhaustive()
    }
}

impl DeliveryService {
    /// A delivery service for the group a genesis seal creates.
    pub fn new(genesis: Seal, config: DsConfig) -> CoreResult<Self> {
        let state = PublicState::from_genesis(&genesis)?;
        let genesis_registry = state.registry.header()?;
        let genesis_leaf = state
            .tree
            .leaf(0)
            .ok_or(CoreError::Invalid("genesis without its creator"))?
            .clone();
        let mut latest = HashMap::new();
        latest.insert(
            NodeId { level: 1, index: 0 },
            Latest {
                epoch: 0,
                wraps: HashMap::new(),
            },
        );
        Ok(Self {
            config,
            genesis,
            genesis_registry,
            genesis_leaf,
            state,
            windows: Vec::new(),
            latest,
            queue: Queue::default(),
            open: None,
            online: BTreeSet::new(),
            checkpoints: Vec::new(),
            invite_uses: HashMap::new(),
            blamed: BTreeMap::new(),
            convicted: BTreeSet::new(),
            verifier: None,
        })
    }

    /// The current public state (what committers and sealers are shown).
    #[must_use]
    pub const fn state(&self) -> &PublicState {
        &self.state
    }

    /// The current epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.state.epoch
    }

    /// Timing configuration.
    #[must_use]
    pub const fn config(&self) -> &DsConfig {
        &self.config
    }

    /// Change the timing and assignment rules; windows opened afterwards
    /// follow them.
    pub fn set_config(&mut self, config: DsConfig) {
        self.config = config;
    }

    /// Mark a member online (a volunteer for roles) or offline.
    pub fn set_online(&mut self, member: Occupancy, online: bool) {
        if online {
            self.online.insert(member);
        } else {
            self.online.remove(&member);
        }
    }

    fn next_epoch(&self) -> u64 {
        self.state.epoch + 1
    }

    fn check_invite(&self, join: &JoinRequest, now_ms: u64) -> CoreResult<()> {
        if let Some(Authorizer::Invite(invite)) = join.admission.as_ref().map(|a| &a.authorizer) {
            if now_ms > invite.expires_at_ms {
                return Err(CoreError::Invalid("invite expired"));
            }
            let id = invite.id()?;
            let used = self.invite_uses.get(&id).copied().unwrap_or(0);
            let queued = self
                .queue
                .joins
                .iter()
                .filter(|q| match q.item.admission.as_ref().map(|a| &a.authorizer) {
                    Some(Authorizer::Invite(other)) => other.invite_pk == invite.invite_pk,
                    _ => false,
                })
                .count() as u64;
            if used + queued >= invite.max_uses {
                return Err(CoreError::Invalid("invite used up"));
            }
        }
        Ok(())
    }

    /// Record a join request after checking it.
    pub fn submit_join(&mut self, request: JoinRequest, now_ms: u64) -> CoreResult<Digest> {
        check_entry(
            &self.state,
            self.next_epoch(),
            0,
            &Request::Join(request.clone()),
            true,
        )?;
        let device = request.device_id()?;
        let token = request.token();
        if self.queue.joins.iter().any(|q| {
            q.item.device_id().is_ok_and(|other| other == device) || q.item.token() == token
        }) {
            return Err(CoreError::Invalid("join already queued"));
        }
        self.check_free_keys(&request.encryption_key, &request.card, None)?;
        self.check_invite(&request, now_ms)?;
        let reference = request.reference();
        self.queue.joins.push(Queued {
            item: request,
            recorded_ms: now_ms,
        });
        Ok(reference)
    }

    /// Check that a request's leaf key and card are in no leaf and in no
    /// other queued request (docs/specs-v0.5-draft.md section 4.2): a window
    /// that sets a key twice would be refused. The queued request of
    /// `member`, which this one replaces, does not count.
    fn check_free_keys(
        &self,
        encryption_key: &[u8],
        card: &Card,
        member: Option<Occupancy>,
    ) -> CoreResult<()> {
        let keys = [leaf_key_hash(encryption_key)?, card.hash()?];
        let mut queued = Vec::new();
        for q in &self.queue.joins {
            queued.push((None, &q.item.encryption_key, &q.item.card));
        }
        for q in &self.queue.updates {
            queued.push((Some(q.item.member), &q.item.encryption_key, &q.item.card));
        }
        for q in &self.queue.re_entries {
            queued.push((Some(q.item.member), &q.item.encryption_key, &q.item.card));
        }
        for (owner, other_key, other_card) in queued {
            if member.is_some() && owner == member {
                continue;
            }
            let other = [leaf_key_hash(other_key)?, other_card.hash()?];
            if keys.iter().any(|key| other.contains(key)) {
                return Err(CoreError::Invalid("a leaf key or card already queued"));
            }
        }
        if keys
            .iter()
            .any(|key| self.state.registry.key(key).is_some())
        {
            return Err(CoreError::Invalid("a leaf key or card already in use"));
        }
        Ok(())
    }

    fn check_subject(&self, subject: Occupancy) -> CoreResult<()> {
        if self.state.tree.is_member(subject) {
            Ok(())
        } else {
            Err(CoreError::Invalid("not a member"))
        }
    }

    /// Record a removal after checking it. From now on the removed member's
    /// messages and commits are refused.
    pub fn submit_removal(&mut self, proposal: RemoveProposal, now_ms: u64) -> CoreResult<()> {
        self.check_subject(proposal.target)?;
        check_entry(
            &self.state,
            self.next_epoch(),
            proposal.target.leaf,
            &Request::Removal(proposal.clone()),
            true,
        )?;
        // One per target; an urgent removal replaces an ordinary one, and
        // its time starts the urgent clock.
        match self
            .queue
            .removals
            .iter_mut()
            .find(|q| q.item.target == proposal.target)
        {
            None => self.queue.removals.push(Queued {
                item: proposal,
                recorded_ms: now_ms,
            }),
            Some(queued)
                if queued.item.urgency == Urgency::Ordinary
                    && proposal.urgency == Urgency::Urgent =>
            {
                *queued = Queued {
                    item: proposal,
                    recorded_ms: now_ms,
                };
            }
            Some(_) => {}
        }
        Ok(())
    }

    /// Record a leaf key update after checking it.
    pub fn submit_update(&mut self, request: UpdateRequest, now_ms: u64) -> CoreResult<()> {
        self.check_subject(request.member)?;
        check_entry(
            &self.state,
            self.next_epoch(),
            request.member.leaf,
            &Request::Update(request.clone()),
            true,
        )?;
        self.check_free_keys(&request.encryption_key, &request.card, Some(request.member))?;
        self.queue
            .updates
            .retain(|q| q.item.member != request.member);
        self.queue.updates.push(Queued {
            item: request,
            recorded_ms: now_ms,
        });
        Ok(())
    }

    /// Record a re-entry after checking it.
    pub fn submit_re_entry(&mut self, request: ReEntryRequest, now_ms: u64) -> CoreResult<Digest> {
        self.check_subject(request.member)?;
        check_entry(
            &self.state,
            self.next_epoch(),
            request.member.leaf,
            &Request::ReEntry(request.clone()),
            true,
        )?;
        self.check_free_keys(&request.encryption_key, &request.card, Some(request.member))?;
        self.queue
            .re_entries
            .retain(|q| q.item.member != request.member);
        let reference = request.reference();
        self.queue.re_entries.push(Queued {
            item: request,
            recorded_ms: now_ms,
        });
        Ok(reference)
    }

    /// Record a catch-up request after checking it.
    pub fn submit_catch_up(&mut self, request: CatchUpRequest, now_ms: u64) -> CoreResult<Digest> {
        let device_pk = self
            .state
            .device_pk(request.member)
            .ok_or(CoreError::Invalid("not a member"))?;
        request.verify(&self.state.gid, &self.state.interim, device_pk)?;
        let reference = request.reference();
        self.queue
            .catch_ups
            .retain(|q| q.item.member != request.member);
        self.queue.catch_ups.push(Queued {
            item: request,
            recorded_ms: now_ms,
        });
        Ok(reference)
    }

    /// Record a group policy after checking it.
    pub fn submit_policy(&mut self, policy: GroupPolicy, now_ms: u64) -> CoreResult<()> {
        policy.verify(&self.state.gid, self.state.registry.admins())?;
        if self.state.registry.policy() == Some(&policy.hash()) {
            return Err(CoreError::Invalid("policy already in force"));
        }
        self.queue.policy = Some(Queued {
            item: policy,
            recorded_ms: now_ms,
        });
        Ok(())
    }

    /// Queue the eviction of every member whose leaf key has not changed for
    /// longer than the policy in force allows. Returns how many were queued.
    pub fn evict_idle(&mut self, now_ms: u64) -> CoreResult<usize> {
        let Some(policy) = self.state.policy.clone() else {
            return Ok(0);
        };
        let Some(max_idle) = policy.max_idle_epochs else {
            return Ok(0);
        };
        let epoch = self.next_epoch();
        let queued: BTreeSet<Occupancy> = self.queue.removal_targets().into_keys().collect();
        let idle: Vec<Occupancy> = self
            .state
            .tree
            .leaves()
            .filter(|(_, leaf)| epoch.saturating_sub(leaf.updated) > max_idle)
            .map(|(index, leaf)| leaf.occupancy(index))
            .filter(|occupancy| !queued.contains(occupancy))
            .collect();
        for target in &idle {
            let eviction = Eviction::new(&self.state.gid, *target, &policy.hash())?;
            self.queue.evictions.push(Queued {
                item: eviction,
                recorded_ms: now_ms,
            });
        }
        Ok(idle.len())
    }

    /// Recorded removals and evictions not applied yet.
    #[must_use]
    pub fn pending_removals(&self) -> Vec<PendingRemoval> {
        self.queue
            .removal_targets()
            .into_iter()
            .map(|(target, (recorded_ms, urgency))| PendingRemoval {
                target,
                recorded_ms,
                urgency,
            })
            .collect()
    }

    /// Whether the service accepts messages and commits from `member`:
    /// not once a removal of it is recorded (E-7).
    #[must_use]
    pub fn accepts_from(&self, member: Occupancy) -> bool {
        self.state.tree.is_member(member) && !self.queue.removal_targets().contains_key(&member)
    }

    /// Whether a window should be closed at `now_ms`: its oldest request
    /// has waited `WINDOW_ORDINARY`, or its oldest urgent removal
    /// `WINDOW_URGENT` (E-16).
    #[must_use]
    pub fn due(&self, now_ms: u64) -> bool {
        if self.open.is_some() {
            return false;
        }
        let by_age = self
            .queue
            .oldest()
            .is_some_and(|oldest| now_ms.saturating_sub(oldest) >= self.config.window_ordinary_ms);
        let by_urgency = self
            .queue
            .oldest_urgent()
            .is_some_and(|oldest| now_ms.saturating_sub(oldest) >= self.config.window_urgent_ms);
        by_age || by_urgency
    }

    /// Whether a queued entry is still valid for the window creating
    /// `epoch`: what may have changed since it was checked (expiry, admins,
    /// the policy, the member's key) is checked again; signatures are not.
    fn still_valid(&self, request: &Request, epoch: u64) -> bool {
        let admins = self.state.registry.admins();
        match request {
            Request::Join(join) => {
                let authorized = match &join.admission {
                    None => self.state.registry.is_open(),
                    Some(admission) => {
                        epoch <= admission.not_after_epoch
                            && match &admission.authorizer {
                                Authorizer::Admin(admin) => {
                                    admins.get(admin) == Some(&admission.authorizer_pk)
                                }
                                Authorizer::Invite(invite) => {
                                    admins.get(&invite.inviter) == Some(&invite.inviter_pk)
                                }
                            }
                    }
                };
                authorized
                    && epoch <= join.not_after_epoch
                    && join
                        .device_id()
                        .is_ok_and(|id| self.state.registry.device(&id).is_none())
                    && self.state.registry.admission(&join.token()).is_none()
            }
            Request::Removal(proposal) => {
                self.state.tree.is_member(proposal.target)
                    && (proposal.proposer == proposal.target
                        || admins.contains_key(&proposal.proposer))
            }
            Request::Eviction(eviction) => {
                let policy = self.state.policy.as_ref();
                self.state.registry.policy() == Some(&eviction.policy_hash)
                    && self
                        .state
                        .tree
                        .member(eviction.target)
                        .zip(policy)
                        .is_some_and(|(leaf, policy)| {
                            policy.max_idle_epochs.is_some_and(|max_idle| {
                                epoch.saturating_sub(leaf.updated) > max_idle
                            })
                        })
            }
            Request::Update(_) | Request::ReEntry(_) => true,
        }
    }

    /// Leaves for `count` joins: the leaves the window empties first, then
    /// the lowest free leaves (E-11).
    fn place(&self, count: usize, emptied: &[u32]) -> Vec<u32> {
        let mut slots: Vec<u32> = emptied.iter().copied().take(count).collect();
        let emptied: BTreeSet<u32> = emptied.iter().copied().collect();
        let mut occupied = self.state.tree.leaves().map(|(index, _)| index).peekable();
        let mut candidate: u64 = 0;
        let limit = 1u64 << MAX_HEIGHT;
        while slots.len() < count && candidate < limit {
            while occupied
                .peek()
                .is_some_and(|index| u64::from(*index) < candidate)
            {
                occupied.next();
            }
            let Ok(leaf) = u32::try_from(candidate) else {
                break;
            };
            candidate += 1;
            if occupied.peek() == Some(&leaf) || emptied.contains(&leaf) {
                continue;
            }
            slots.push(leaf);
        }
        slots
    }

    /// Close a window: choose its changes, place its joins, and assign its
    /// roles: online members if any, else an entrant (a joiner or a
    /// re-entering member). Returns `None` when there is nothing to do or
    /// nobody to seal; recorded removals then stay enforced at delivery.
    pub fn open_window(&mut self, now_ms: u64) -> CoreResult<Option<WindowTask>> {
        if self.open.is_some() {
            return Err(CoreError::Invalid("a window is already open"));
        }
        let epoch = self.next_epoch();
        let tree = &self.state.tree;
        let mut requests = Requests::new();
        let mut changes: Vec<Change> = Vec::new();
        let mut subjects: BTreeSet<Occupancy> = BTreeSet::new();
        for (target, request) in self
            .queue
            .removals
            .iter()
            .map(|q| (q.item.target, Request::Removal(q.item.clone())))
            .chain(
                self.queue
                    .evictions
                    .iter()
                    .map(|q| (q.item.target, Request::Eviction(q.item.clone()))),
            )
        {
            if !self.still_valid(&request, epoch) || !subjects.insert(target) {
                continue;
            }
            changes.push(Change {
                leaf: target.leaf,
                kind: request.kind(),
                request: request.reference(),
            });
            requests.insert(request);
        }
        let mut emptied: Vec<u32> = subjects.iter().map(|target| target.leaf).collect();
        emptied.sort_unstable();
        for (member, request) in self
            .queue
            .updates
            .iter()
            .map(|q| (q.item.member, Request::Update(q.item.clone())))
            .chain(
                self.queue
                    .re_entries
                    .iter()
                    .map(|q| (q.item.member, Request::ReEntry(q.item.clone()))),
            )
        {
            if !tree.is_member(member) || !subjects.insert(member) {
                continue;
            }
            let current = tree
                .leaf(member.leaf)
                .map(|leaf| kem_pk_hash(&leaf.encryption_key))
                .transpose()?;
            let replaces = match &request {
                Request::Update(update) => update.replaces,
                Request::ReEntry(re_entry) => re_entry.replaces,
                _ => continue,
            };
            if current != Some(replaces) {
                continue;
            }
            changes.push(Change {
                leaf: member.leaf,
                kind: request.kind(),
                request: request.reference(),
            });
            requests.insert(request);
        }
        let joins: Vec<JoinRequest> = self
            .queue
            .joins
            .iter()
            .map(|q| q.item.clone())
            .filter(|join| self.still_valid(&Request::Join(join.clone()), epoch))
            .collect();
        let slots = self.place(joins.len(), &emptied);
        for (join, leaf) in joins.into_iter().zip(slots) {
            let request = Request::Join(join);
            changes.push(Change {
                leaf,
                kind: ChangeKind::Join,
                request: request.reference(),
            });
            requests.insert(request);
        }
        changes.sort();
        let catch_ups: Vec<CatchUpRequest> = self
            .queue
            .catch_ups
            .iter()
            .map(|q| q.item.clone())
            .filter(|request| {
                request.prev_interim == self.state.interim
                    && tree.is_member(request.member)
                    && !subjects.contains(&request.member)
            })
            .collect();
        if self
            .queue
            .policy
            .as_ref()
            .is_some_and(|q| !self.state.registry.is_admin(q.item.admin))
        {
            self.queue.policy = None;
        }
        let policy = self.queue.policy.as_ref().map(|q| q.item.clone());
        if changes.is_empty() && catch_ups.is_empty() && policy.is_none() {
            return Ok(None);
        }
        let height = needed_height(tree.height(), changes.iter().map(|c| c.leaf).max());
        let shape = tree.shape().grown(height)?;
        let window = WindowShape::new(tree, epoch, shape, changes.iter().copied())?;
        let volunteers: Vec<Occupancy> = self
            .online
            .iter()
            .copied()
            .filter(|member| {
                tree.is_member(*member)
                    && !window.affected.contains(member)
                    && !self.is_excluded(*member)
            })
            .collect();
        let (committers, city, sealer, entrant) = if volunteers.is_empty() {
            let entrant = changes
                .iter()
                .find(|change| matches!(change.kind, ChangeKind::Join | ChangeKind::ReEntry));
            let Some(entrant) = entrant else {
                return Ok(None);
            };
            let occupancy = match requests.get(&entrant.request) {
                Some(Request::ReEntry(re_entry)) => re_entry.member,
                _ => Occupancy {
                    leaf: entrant.leaf,
                    since: epoch,
                },
            };
            let committers = window
                .districts
                .iter()
                .map(|district| (*district, occupancy))
                .collect();
            let city = window.parts.iter().map(|part| (*part, occupancy)).collect();
            (committers, city, occupancy, Some(entrant.request))
        } else {
            // Joiners first (docs/specs-v0.5-draft.md section 3.4): the
            // window's joins, as the occupancies they take. Each district
            // goes to a joiner that takes a leaf of it, else to a joiner with
            // no task, else to a volunteer of the district, else to
            // volunteers in turn.
            let joiners: Vec<Occupancy> = if self.config.joiner_tasks {
                changes
                    .iter()
                    .filter(|change| change.kind == ChangeKind::Join)
                    .map(|change| Occupancy {
                        leaf: change.leaf,
                        since: epoch,
                    })
                    .collect()
            } else {
                Vec::new()
            };
            let mut busy: BTreeSet<Occupancy> = BTreeSet::new();
            let mut committers = BTreeMap::new();
            for joiner in &joiners {
                let district = shape.district_of(joiner.leaf);
                if window.districts.contains(&district) && !committers.contains_key(&district) {
                    committers.insert(district, *joiner);
                    busy.insert(*joiner);
                }
            }
            let mut by_district: BTreeMap<u32, Occupancy> = BTreeMap::new();
            for volunteer in &volunteers {
                by_district
                    .entry(shape.district_of(volunteer.leaf))
                    .or_insert(*volunteer);
            }
            let mut next = 0usize;
            for district in &window.districts {
                if committers.contains_key(district) {
                    continue;
                }
                let committer = joiners
                    .iter()
                    .copied()
                    .find(|joiner| !busy.contains(joiner))
                    .or_else(|| by_district.get(district).copied())
                    .unwrap_or_else(|| {
                        let chosen = volunteers[next % volunteers.len()];
                        next += 1;
                        chosen
                    });
                busy.insert(committer);
                committers.insert(*district, committer);
            }
            let sealer = volunteers
                .iter()
                .copied()
                .find(|volunteer| !busy.contains(volunteer))
                .unwrap_or(volunteers[0]);
            // City tasks: joiners with no task, then volunteers with no
            // task, then volunteers in turn.
            busy.insert(sealer);
            let mut city = BTreeMap::new();
            for part in &window.parts {
                let performer = joiners
                    .iter()
                    .chain(&volunteers)
                    .copied()
                    .find(|performer| !busy.contains(performer))
                    .unwrap_or_else(|| {
                        let chosen = volunteers[next % volunteers.len()];
                        next += 1;
                        chosen
                    });
                busy.insert(performer);
                city.insert(*part, performer);
            }
            (committers, city, sealer, None)
        };
        // Welcomers (v0.4 §11): the committer of the district when it is a
        // member, members in turn when it is a joiner, which cannot welcome
        // (docs/specs-v0.5-draft.md section 3.4), the sealer for a catch-up
        // outside the window's districts, and the entrant in its window.
        let mut turn = 0usize;
        let mut welcomer_of = |leaf: u32| -> Occupancy {
            if entrant.is_some() {
                return sealer;
            }
            match committers.get(&shape.district_of(leaf)) {
                Some(committer) if committer.since < epoch => *committer,
                Some(_) => {
                    let chosen = volunteers[turn % volunteers.len()];
                    turn += 1;
                    chosen
                }
                None => sealer,
            }
        };
        let mut welcomes = Vec::new();
        for change in &changes {
            let kind = match change.kind {
                ChangeKind::Join => WelcomeKind::Join,
                ChangeKind::ReEntry => WelcomeKind::ReEntry,
                _ => continue,
            };
            if Some(change.request) == entrant {
                continue;
            }
            let welcomer = welcomer_of(change.leaf);
            welcomes.push(WelcomeTask {
                kind,
                request: change.request,
                welcomer,
            });
        }
        let mut catch_up_map = CatchUps::new();
        for request in catch_ups {
            let welcomer = welcomer_of(request.member.leaf);
            welcomes.push(WelcomeTask {
                kind: WelcomeKind::CatchUp,
                request: request.reference(),
                welcomer,
            });
            catch_up_map.insert(request.reference(), request);
        }
        let task = WindowTask {
            gid: self.state.gid,
            epoch,
            height,
            changes,
            committers,
            city,
            sealer,
            entrant,
            policy: policy.as_ref().map(|policy| policy.encoded().to_vec()),
            welcomes,
            time_ms: now_ms.max(self.state.time_ms),
        };
        let kind = if entrant.is_some() {
            SealKind::Entrant
        } else {
            SealKind::Member
        };
        let sealer_info = check_sealer(
            &self.state,
            &window,
            kind,
            sealer,
            entrant.as_ref(),
            &requests,
        )?;
        self.open = Some(OpenWindow {
            task: task.clone(),
            window,
            sealer: sealer_info,
            requests,
            catch_ups: catch_up_map,
            commits: BTreeMap::new(),
            city_tasks: BTreeMap::new(),
        });
        Ok(Some(task))
    }

    /// The open window's task, requests and catch-up requests.
    #[must_use]
    pub fn open_window_data(&self) -> Option<(&WindowTask, &Requests, &CatchUps)> {
        self.open
            .as_ref()
            .map(|open| (&open.task, &open.requests, &open.catch_ups))
    }

    /// District commits received for the open window, in district order.
    #[must_use]
    pub fn open_commits(&self) -> Vec<DistrictCommit> {
        self.open
            .as_ref()
            .map(|open| open.commits.values().cloned().collect())
            .unwrap_or_default()
    }

    /// City tasks received for the open window, sub-cities first.
    #[must_use]
    pub fn open_city_tasks(&self) -> Vec<CityTask> {
        self.open
            .as_ref()
            .map(|open| open.city_tasks.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Give district `district` of the open window to another committer
    /// (a committer that failed); a commit already received is dropped.
    pub fn reassign(&mut self, district: u32, committer: Occupancy) -> CoreResult<WindowTask> {
        if !self.may_perform(committer) {
            return Err(CoreError::Invalid("committer"));
        }
        let open = self
            .open
            .as_mut()
            .ok_or(CoreError::Invalid("no open window"))?;
        let old = open
            .task
            .committers
            .insert(district, committer)
            .ok_or(CoreError::Invalid("district not in the window"))?;
        let shape = open.window.shape;
        let member = committer.since < open.task.epoch;
        let sealer = open.task.sealer;
        for welcome in &mut open.task.welcomes {
            let leaf = match welcome.kind {
                WelcomeKind::CatchUp => open
                    .catch_ups
                    .get(&welcome.request)
                    .map(|request| request.member.leaf),
                WelcomeKind::Join | WelcomeKind::ReEntry => open
                    .task
                    .changes
                    .iter()
                    .find(|change| change.request == welcome.request)
                    .map(|change| change.leaf),
            };
            if leaf.is_none_or(|leaf| shape.district_of(leaf) != district) {
                continue;
            }
            // A member committer welcomes its district; a joiner cannot, so
            // the old committer's welcomes go to the sealer.
            if member {
                welcome.welcomer = committer;
            } else if welcome.welcomer == old {
                welcome.welcomer = sealer;
            }
        }
        open.commits.remove(&district);
        // The city tasks built on the dropped commit are dropped too: its
        // sub-city's and the top's.
        if shape.has_city() {
            open.city_tasks
                .remove(&CityPart::SubCity(shape.subcity_of(district)));
            open.city_tasks.remove(&CityPart::Top);
        }
        Ok(open.task.clone())
    }

    /// Give part `part` of the city of the open window to another performer
    /// (a performer that failed, docs/specs-v0.5-draft.md section 3.4); a
    /// task already received is dropped, with the top's built on it.
    pub fn reassign_city(
        &mut self,
        part: CityPart,
        performer: Occupancy,
    ) -> CoreResult<WindowTask> {
        if !self.may_perform(performer) {
            return Err(CoreError::Invalid("performer"));
        }
        let open = self
            .open
            .as_mut()
            .ok_or(CoreError::Invalid("no open window"))?;
        let slot = open
            .task
            .city
            .get_mut(&part)
            .ok_or(CoreError::Invalid("part not in the window"))?;
        *slot = performer;
        open.city_tasks.remove(&part);
        open.city_tasks.remove(&CityPart::Top);
        Ok(open.task.clone())
    }

    /// Whether `performer` may take over a task of the open window, a member
    /// window: a member the service accepts from and the window leaves
    /// alone, or a joiner of the window (docs/specs-v0.5-draft.md section
    /// 3.3).
    fn may_perform(&self, performer: Occupancy) -> bool {
        self.open.as_ref().is_some_and(|open| {
            open.task.entrant.is_none()
                && !open.window.affected.contains(&performer)
                && !self.is_excluded(performer)
                && self.accepts_performer(open, performer)
        })
    }

    /// Whether the service takes a task of the open window from
    /// `performer`: a member it accepts from, or a joiner of the window.
    fn accepts_performer(&self, open: &OpenWindow, performer: Occupancy) -> bool {
        self.accepts_from(performer)
            || joiner_request(&open.window, performer, &open.requests).is_some()
    }

    /// Drop the open window; its requests stay queued.
    pub fn abort_window(&mut self) {
        self.open = None;
    }

    /// Check and keep a district commit of the open window.
    pub fn submit_district_commit(&mut self, commit: DistrictCommit) -> CoreResult<()> {
        let open = self
            .open
            .as_ref()
            .ok_or(CoreError::Invalid("no open window"))?;
        if open.task.committers.get(&commit.district) != Some(&commit.committer) {
            return Err(CoreError::Unauthorized("not the district's committer"));
        }
        // The tasks above build on the first commit received: a second one
        // must be the same.
        if let Some(kept) = open.commits.get(&commit.district) {
            return if kept.hash() == commit.hash() {
                Ok(())
            } else {
                Err(CoreError::Invalid("district already committed"))
            };
        }
        if !open.sealer.entrant && !self.accepts_performer(open, commit.committer) {
            return Err(CoreError::Unauthorized("committer removed"));
        }
        let committer_pk = check_committer(
            &self.state,
            &open.window,
            commit.committer,
            &open.sealer,
            &open.requests,
        )?;
        let leaves = district_leaves(
            &self.state,
            &open.window,
            commit.district,
            &open.requests,
            false,
        )?;
        check_district_commit(&self.state, &open.window, &commit, &leaves, &committer_pk)?;
        if let Some(open) = self.open.as_mut() {
            open.commits.insert(commit.district, commit);
        }
        Ok(())
    }

    /// Check and keep a city task of the open window (docs/specs-v0.5-draft.md
    /// section 3.2), once what it builds on is in: the commits of the
    /// sub-city's districts, or every sub-city task for the top.
    pub fn submit_city_task(&mut self, city_task: CityTask) -> CoreResult<()> {
        let open = self
            .open
            .as_ref()
            .ok_or(CoreError::Invalid("no open window"))?;
        if open.task.city.get(&city_task.part) != Some(&city_task.performer) {
            return Err(CoreError::Unauthorized("not the city task's performer"));
        }
        if !open.sealer.entrant && !self.accepts_performer(open, city_task.performer) {
            return Err(CoreError::Unauthorized("performer removed"));
        }
        if let Some(kept) = open.city_tasks.get(&city_task.part) {
            return if kept.hash() == city_task.hash() {
                Ok(())
            } else {
                Err(CoreError::Invalid("city part already performed"))
            };
        }
        let shape = open.window.shape;
        let ready = match city_task.part {
            CityPart::SubCity(subcity) => open
                .window
                .districts
                .iter()
                .filter(|district| shape.subcity_of(**district) == subcity)
                .all(|district| open.commits.contains_key(district)),
            CityPart::Top => open
                .window
                .parts
                .iter()
                .filter(|part| **part != CityPart::Top)
                .all(|part| open.city_tasks.contains_key(part)),
        };
        if !ready {
            return Err(CoreError::Invalid("city task before what it builds on"));
        }
        let performer_pk = check_committer(
            &self.state,
            &open.window,
            city_task.performer,
            &open.sealer,
            &open.requests,
        )?;
        let commits: Vec<DistrictCommit> = open.commits.values().cloned().collect();
        let tasks: Vec<CityTask> = open.city_tasks.values().cloned().collect();
        let work = WindowWork {
            commits: &commits,
            city_tasks: &tasks,
            requests: &open.requests,
        };
        let (below, before) = work.base(&self.state, &open.window, city_task.part)?;
        check_city_task(
            &self.state,
            &open.window,
            &city_task,
            &below,
            &before,
            &performer_pk,
        )?;
        if let Some(open) = self.open.as_mut() {
            open.city_tasks.insert(city_task.part, city_task);
        }
        Ok(())
    }

    /// Check the seal of the open window, apply the window, and keep what
    /// members, joiners and auditors will ask for. Returns the new epoch.
    pub fn submit_seal(&mut self, seal: Seal) -> CoreResult<u64> {
        let open = self
            .open
            .as_ref()
            .ok_or(CoreError::Invalid("no open window"))?;
        if seal.header.sealer != open.task.sealer
            || open.commits.len() != open.task.committers.len()
            || open.city_tasks.len() != open.task.city.len()
        {
            return Err(CoreError::Invalid("seal before its district commits"));
        }
        if !open.sealer.entrant && !self.accepts_from(seal.header.sealer) {
            return Err(CoreError::Unauthorized("sealer removed"));
        }
        let commits: Vec<DistrictCommit> = open.commits.values().cloned().collect();
        let city_tasks: Vec<CityTask> = open.city_tasks.values().cloned().collect();
        let outcome = check_window(
            &self.state,
            &commits,
            &city_tasks,
            &seal,
            &open.requests,
            false,
        )?;
        if outcome.policy.as_ref().map(|p| p.encoded().to_vec()) != open.task.policy {
            return Err(CoreError::Invalid("seal policy"));
        }
        let Some(open) = self.open.take() else {
            return Err(CoreError::Invalid("no open window"));
        };
        // What refers to the state before the window.
        let audits = records(&self.state, &open.window, &commits, &open.requests)?;
        let sealer = if open.sealer.entrant {
            let reference = seal
                .header
                .entrant
                .as_ref()
                .map(|entrant| entrant.request)
                .ok_or(CoreError::Invalid("entrant seal"))?;
            SealerEvidence::Entrant(Box::new(match open.requests.get(&reference) {
                Some(Request::Join(join)) => EntrantEvidence::Join {
                    request: Box::new(join.clone()),
                    device: self.state.registry.device_proof(&join.device_id()?)?,
                    admission: self.state.registry.admission_proof(&join.token())?,
                },
                Some(Request::ReEntry(re_entry)) => EntrantEvidence::ReEntry {
                    request: Box::new(re_entry.clone()),
                    leaf: self.state.tree.leaf_proof(re_entry.member.leaf)?,
                },
                _ => return Err(CoreError::Invalid("entrant request")),
            }))
        } else {
            SealerEvidence::Member(self.state.tree.leaf_proof(seal.header.sealer.leaf)?)
        };
        let registry_before = self.state.registry.header()?;
        self.state.apply(&outcome)?;
        let registry = self.state.registry.header()?;
        let epoch = outcome.epoch;
        let shape = self.state.tree.shape();
        let mut index = WindowIndex::default();
        let mut all_updates = Vec::new();
        let mut all_wraps: Vec<&Wrap> = Vec::new();
        for commit in &commits {
            index.add(&commit.updates, &commit.wraps);
            all_updates.extend(commit.updates.iter().cloned());
            all_wraps.extend(commit.wraps.iter());
        }
        for city_task in &city_tasks {
            index.add(&city_task.updates, &city_task.wraps);
            all_updates.extend(city_task.updates.iter().cloned());
            all_wraps.extend(city_task.wraps.iter());
        }
        for update in &all_updates {
            if update.public_key.is_some() {
                self.latest.insert(
                    update.node,
                    Latest {
                        epoch,
                        wraps: HashMap::new(),
                    },
                );
            } else {
                self.latest.remove(&update.node);
            }
        }
        for wrapped in all_wraps {
            if let Some(latest) = self.latest.get_mut(&wrapped.node) {
                latest.wraps.insert(wrapped.target, wrapped.clone());
            }
        }
        let mut entries = HashMap::new();
        for welcome in &open.task.welcomes {
            let leaf = match welcome.kind {
                WelcomeKind::CatchUp => open
                    .catch_ups
                    .get(&welcome.request)
                    .map(|request| request.member.leaf),
                _ => open
                    .task
                    .changes
                    .iter()
                    .find(|change| change.request == welcome.request)
                    .map(|change| change.leaf),
            }
            .ok_or(CoreError::Invalid("welcome task"))?;
            entries.insert(welcome.request, self.entry_data(leaf)?);
        }
        let mut committer_leaves = HashMap::new();
        for committer in open
            .task
            .committers
            .values()
            .chain(open.task.city.values())
            .chain(core::iter::once(&open.task.sealer))
        {
            if self.state.tree.is_member(*committer) {
                committer_leaves.insert(*committer, self.state.tree.leaf_proof(committer.leaf)?);
            }
        }
        self.remove_applied(&open);
        let top = if index.is_empty() {
            // Nothing re-keyed: the root did not change.
            TopTask {
                epoch,
                ..TopTask::default()
            }
        } else {
            self.assign_top(epoch)
        };
        for change in &open.task.changes {
            if let Some(Request::Join(join)) = open.requests.get(&change.request)
                && let Some(Authorizer::Invite(invite)) = join
                    .admission
                    .as_ref()
                    .map(|admission| &admission.authorizer)
            {
                *self.invite_uses.entry(invite.id()?).or_insert(0) += 1;
            }
        }
        self.windows.push(StoredWindow {
            task: open.task,
            seal,
            commits,
            city_tasks,
            requests: open.requests,
            catch_ups: open.catch_ups,
            index,
            sealer,
            registry_before,
            registry,
            policy: outcome.policy.clone(),
            leaves: outcome.tree.leaves.clone(),
            entries,
            welcomes: HashMap::new(),
            audits,
            committer_leaves,
            shape,
            top,
            relays: BTreeMap::new(),
            flats: BTreeMap::new(),
            repairs: BTreeMap::new(),
            repair_makers: BTreeMap::new(),
            disputes: Vec::new(),
        });
        Ok(epoch)
    }

    /// The relays and flat elements of the window that created `epoch`,
    /// from the state after it (E-15). Each island that holds members gets
    /// a relay: an online member of the island that was a member of the
    /// previous epoch and has no removal recorded, taken in turn from one
    /// window to the next. The flat elements of the other islands are
    /// spread over the relays; with no relay, members refresh.
    fn assign_top(&self, epoch: u64) -> TopTask {
        let shape = self.state.tree.shape();
        let mut task = TopTask {
            epoch,
            ..TopTask::default()
        };
        if !shape.has_islands() {
            return task;
        }
        let removing = self.queue.removal_targets();
        let mut candidates: BTreeMap<u32, Vec<Occupancy>> = BTreeMap::new();
        for (leaf, node) in self.state.tree.leaves() {
            let member = node.occupancy(leaf);
            let island = candidates.entry(shape.island_of(leaf)).or_default();
            if member.since < epoch
                && self.online.contains(&member)
                && !removing.contains_key(&member)
                && !self.is_excluded(member)
            {
                island.push(member);
            }
        }
        let mut bare = Vec::new();
        for (island, members) in &candidates {
            if members.is_empty() {
                bare.push(*island);
                continue;
            }
            let turn = usize::try_from(epoch).unwrap_or(0) % members.len();
            task.relays.insert(*island, members[turn]);
        }
        let relays: Vec<Occupancy> = task.relays.values().copied().collect();
        if !relays.is_empty() {
            for (turn, island) in bare.into_iter().enumerate() {
                task.flats
                    .entry(relays[turn % relays.len()])
                    .or_default()
                    .push(island);
            }
        }
        task
    }

    /// Keep the relay element of a sealed window from `relay`, the
    /// authenticated sender, which the window must have made the relay of
    /// its island. Relay elements are not signed and the service cannot
    /// check them: a wrong one makes the island's members fall back to a
    /// flat element or a refresh.
    pub fn submit_relay(&mut self, relay: Occupancy, element: RelayElement) -> CoreResult<()> {
        let gid = self.state.gid;
        let stored = self.stored_mut(element.epoch)?;
        if element.gid != gid || element.sealed.len() != crate::crypto::SEALED_SECRET_BYTES {
            return Err(CoreError::Invalid("relay element"));
        }
        if stored.top.relays.get(&element.island) != Some(&relay) {
            return Err(CoreError::Unauthorized("not the relay of this island"));
        }
        stored.relays.insert(element.island, element);
        Ok(())
    }

    /// Take a member's request for a repair of the latest window
    /// (docs/specs-v0.5-draft.md section 3.7) and name the member the service
    /// asks for it, if one is online. The request must be signed by a member
    /// the service accepts from, for the window's seal, and name a node of
    /// its path that the window re-keyed. The service cannot check the fault
    /// itself: it counts the member against the performer whose taint the
    /// node bears, once per member, and excludes the performer from roles
    /// once `repair_threshold` members did (section 3.8). The maker is an
    /// online member outside the node's subtree, neither the member nor that
    /// performer nor excluded, taken in turn; asking again for the same
    /// window, after a repair that did not open or a maker that did not
    /// answer, asks the next one and drops the repair kept.
    pub fn request_repair(&mut self, request: &RepairRequest) -> CoreResult<Option<Occupancy>> {
        // The fields the signature covers, whatever the caller changed.
        let request = &RepairRequest::decode(request.encoded())?;
        let epoch = self.state.epoch;
        let seal_hash = self.window(epoch)?.seal.header.hash()?;
        if request.epoch != epoch || request.seal_hash != seal_hash {
            return Err(CoreError::Invalid("repair request for another window"));
        }
        let member = request.member;
        if !self.accepts_from(member) {
            return Err(CoreError::Unauthorized("repair request"));
        }
        let leaf = self
            .state
            .tree
            .member(member)
            .ok_or(CoreError::Unauthorized("repair request"))?;
        request.verify(&self.state.gid, &leaf.device_pk)?;
        if request.level > self.state.tree.height() {
            return Err(CoreError::Invalid("repair request level"));
        }
        let node = NodeId::of_leaf(member.leaf, request.level);
        if self.latest.get(&node).map(|latest| latest.epoch) != Some(epoch) {
            return Err(CoreError::Invalid(
                "repair request for a node the window did not re-key",
            ));
        }
        let performer = self
            .state
            .tree
            .parent(node)
            .ok_or(CoreError::Invalid("repair request for a blank node"))?
            .taint;
        self.blamed.entry(performer).or_default().insert(member);
        let makers: Vec<Occupancy> = self
            .online
            .iter()
            .copied()
            .filter(|maker| {
                *maker != member
                    && *maker != performer
                    && self.accepts_from(*maker)
                    && !self.is_excluded(*maker)
                    && NodeId::of_leaf(maker.leaf, node.level) != node
            })
            .collect();
        let stored = self.stored_mut(epoch)?;
        stored.repairs.remove(&member.leaf);
        if makers.is_empty() {
            stored.repair_makers.remove(&member.leaf);
            return Ok(None);
        }
        let asked = stored
            .repair_makers
            .get(&member.leaf)
            .map_or(0, |(_, asked)| *asked);
        let turn = usize::try_from(epoch).unwrap_or(0).wrapping_add(asked);
        let maker = makers[turn % makers.len()];
        stored.repair_makers.insert(member.leaf, (maker, asked + 1));
        Ok(Some(maker))
    }

    /// How many members asked for repairs of nodes that `performer` drew.
    #[must_use]
    pub fn blame(&self, performer: Occupancy) -> usize {
        self.blamed.get(&performer).map_or(0, BTreeSet::len)
    }

    /// Whether the service gives `member` no role: a dispute convicted it,
    /// or `repair_threshold` members asked for repairs of nodes it drew
    /// (docs/specs-v0.5-draft.md section 3.8). The exclusion binds no member,
    /// and re-keys nothing.
    #[must_use]
    pub fn is_excluded(&self, member: Occupancy) -> bool {
        self.convicted.contains(&member)
            || (self.config.repair_threshold > 0
                && self.blame(member) >= self.config.repair_threshold)
    }

    /// Whether a dispute convicted `performer`.
    #[must_use]
    pub fn is_convicted(&self, performer: Occupancy) -> bool {
        self.convicted.contains(&performer)
    }

    /// Lift the exclusion of `member`: forget the requests counted against
    /// it and its conviction. The disputes stay with their windows.
    pub fn pardon(&mut self, member: Occupancy) {
        self.blamed.remove(&member);
        self.convicted.remove(&member);
    }

    /// Give the service the proof system that checks disputes
    /// (docs/specs-v0.5-draft.md section 3.8); without one, it refuses them.
    pub fn set_dispute_verifier(&mut self, verifier: Box<dyn DisputeVerifier>) {
        self.verifier = Some(verifier);
    }

    /// The task of the latest window that holds the wrap of `node` to
    /// `target`, and the wrap's index in it: what a dispute names.
    pub fn wrap_origin(&self, node: NodeId, target: NodeId) -> CoreResult<(Digest, u32)> {
        let stored = self.window(self.state.epoch)?;
        let tasks = stored
            .commits
            .iter()
            .map(|commit| (commit.hash(), &commit.wraps))
            .chain(
                stored
                    .city_tasks
                    .iter()
                    .map(|task| (task.hash(), &task.wraps)),
            );
        for (hash, wraps) in tasks {
            if let Some(index) = wraps
                .iter()
                .position(|wrapped| wrapped.node == node && wrapped.target == target)
            {
                let index = u32::try_from(index).map_err(|_| CoreError::Invalid("wrap index"))?;
                return Ok((hash, index));
            }
        }
        Err(CoreError::Invalid("no such wrap in the latest window"))
    }

    /// Judge a dispute of a wrap of the latest window, and return the
    /// performer it convicts (docs/specs-v0.5-draft.md section 3.8). The
    /// dispute must be signed by a member the service accepts from, for the
    /// window's seal, and name a wrap of a task the seal lists, addressed to
    /// the member's leaf or to a node of its path. The service builds the
    /// statement from its own copy of the task and of the tree, and its
    /// verifier checks it. A conviction excludes the performer from every
    /// role at once; the dispute stays with its window as evidence.
    pub fn submit_dispute(&mut self, dispute: &Dispute) -> CoreResult<Occupancy> {
        // The fields the signature covers, whatever the caller changed.
        let dispute = Dispute::decode(dispute.encoded())?;
        let claim = &dispute.content;
        let verifier = self
            .verifier
            .as_ref()
            .ok_or(CoreError::Invalid("no dispute verifier"))?;
        let epoch = self.state.epoch;
        let stored = self.window(epoch)?;
        if claim.epoch != epoch || claim.seal_hash != stored.seal.header.hash()? {
            return Err(CoreError::Invalid("dispute of another window"));
        }
        let member = claim.member;
        if !self.accepts_from(member) {
            return Err(CoreError::Unauthorized("dispute"));
        }
        let leaf = self
            .state
            .tree
            .member(member)
            .ok_or(CoreError::Unauthorized("dispute"))?;
        dispute.verify(&self.state.gid, &leaf.device_pk)?;
        let (performer, wraps) = stored
            .commits
            .iter()
            .find(|commit| commit.hash() == claim.task)
            .map(|commit| (commit.committer, &commit.wraps))
            .or_else(|| {
                stored
                    .city_tasks
                    .iter()
                    .find(|task| task.hash() == claim.task)
                    .map(|task| (task.performer, &task.wraps))
            })
            .ok_or(CoreError::Invalid(
                "dispute of a task the seal does not list",
            ))?;
        let wrapped = usize::try_from(claim.wrap_index)
            .ok()
            .and_then(|index| wraps.get(index))
            .ok_or(CoreError::Invalid(
                "dispute of a wrap the task does not hold",
            ))?;
        if wrapped.target != NodeId::of_leaf(member.leaf, wrapped.target.level) {
            return Err(CoreError::Invalid(
                "dispute of a wrap off the member's path",
            ));
        }
        // `pk_t`, the key the wrap is addressed to, and `pk_v`, the published
        // key of the wrapped node, from the tree of the epoch.
        let pk_t = if wrapped.target.level == 0 {
            &leaf.encryption_key
        } else {
            &self
                .state
                .tree
                .parent(wrapped.target)
                .ok_or(CoreError::Invalid("dispute of a wrap to a blank node"))?
                .encryption_key
        };
        let pk_v = &self
            .state
            .tree
            .parent(wrapped.node)
            .ok_or(CoreError::Invalid("dispute of a wrap of a blank node"))?
            .encryption_key;
        let statement =
            DisputeStatement::new(&self.state.gid, epoch, wrapped, pk_t, pk_v, claim.kind)?;
        if !verifier.verify(&statement, &claim.proof) {
            return Err(CoreError::Invalid("dispute not proven"));
        }
        self.convicted.insert(performer);
        self.stored_mut(epoch)?.disputes.push(dispute);
        Ok(performer)
    }

    /// The leaf of `member` and the parents of its path in the current tree,
    /// which a member that cannot follow the latest window checks against
    /// the window's tree hash before it asks for a repair.
    pub fn path_proof(
        &self,
        member: Occupancy,
    ) -> CoreResult<(LeafProof, Vec<Option<ParentNode>>)> {
        if !self.state.tree.is_member(member) {
            return Err(CoreError::Invalid("path of a non-member"));
        }
        Ok((
            self.state.tree.leaf_proof(member.leaf)?,
            self.state.tree.path_nodes(member.leaf),
        ))
    }

    /// Keep a repair for the member at `repair.leaf`, made by `maker`, the
    /// member the service asked for it (docs/specs-v0.5-draft.md section
    /// 3.7). The service checks its addresses, not its content: unsigned,
    /// like a flat element, a repair that does not lead to the tag only makes
    /// the member ask again.
    pub fn submit_repair(&mut self, maker: Occupancy, repair: Repair) -> CoreResult<()> {
        if !self.accepts_from(maker) {
            return Err(CoreError::Unauthorized("repair maker"));
        }
        let gid = self.state.gid;
        let stored = self.stored_mut(repair.epoch)?;
        if stored
            .repair_makers
            .get(&repair.leaf)
            .map(|(asked, _)| *asked)
            != Some(maker)
        {
            return Err(CoreError::Unauthorized("repair nobody asked for"));
        }
        if repair.gid != gid
            || repair.wrap.node != stored.shape.root()
            || repair.wrap.target != NodeId::leaf(repair.leaf)
            || repair.wrap.sealed.len() != crate::crypto::SEALED_SECRET_BYTES
        {
            return Err(CoreError::Invalid("repair"));
        }
        stored.repairs.insert(repair.leaf, repair);
        Ok(())
    }

    /// The packet of window `epoch` for `member` by repair: its header and
    /// tag, no path, and the repair of its leaf.
    pub fn repair_packet(&self, epoch: u64, member: Occupancy) -> CoreResult<Packet> {
        let mut packet = self.packet(epoch, member)?;
        let repair = self
            .window(epoch)?
            .repairs
            .get(&member.leaf)
            .cloned()
            .ok_or(CoreError::Invalid("no repair for this leaf"))?;
        packet.path.clear();
        packet.top = Some(Top::Repair(repair));
        Ok(packet)
    }

    /// Keep the flat elements of a sealed window from `member`, the
    /// authenticated sender, which the window must have asked for them. The
    /// service checks their addresses and sizes, not their content.
    pub fn submit_flats(
        &mut self,
        member: Occupancy,
        epoch: u64,
        flats: Vec<Wrap>,
    ) -> CoreResult<()> {
        let stored = self.stored_mut(epoch)?;
        let shape = stored.shape;
        let asked = stored.top.flats.get(&member).cloned().unwrap_or_default();
        for flat in &flats {
            let island = flat.target.index;
            if !asked.contains(&island) {
                return Err(CoreError::Unauthorized("flat element nobody asked for"));
            }
            if flat.node != shape.root()
                || flat.target != shape.island_root(island)
                || flat.kem_ciphertext.len() != crate::kem::KEM_CIPHERTEXT_BYTES
                || flat.sealed.len() != crate::crypto::SEALED_SECRET_BYTES
            {
                return Err(CoreError::Invalid("flat element"));
            }
        }
        for flat in flats {
            stored.flats.insert(flat.target.index, flat);
        }
        Ok(())
    }

    fn stored_mut(&mut self, epoch: u64) -> CoreResult<&mut StoredWindow> {
        let index = usize::try_from(epoch)
            .ok()
            .and_then(|epoch| epoch.checked_sub(1))
            .ok_or(CoreError::Invalid("no window created epoch 0"))?;
        self.windows
            .get_mut(index)
            .ok_or(CoreError::Invalid("unknown epoch"))
    }

    /// The last step of each level `from..=height` of the path of `leaf`,
    /// as of `epoch`: from the latest re-key of every node for the current
    /// epoch, else from the windows up to `epoch`.
    fn steps_as_of(&self, epoch: u64, leaf: u32, from: u8, height: u8) -> CoreResult<EntrySteps> {
        let mut steps = EntrySteps::new();
        for level in from..=height {
            let node = NodeId::of_leaf(leaf, level);
            let child = node.child_toward(leaf);
            let step = if epoch == self.state.epoch {
                self.latest.get(&node).map(|latest| {
                    let step = latest
                        .wraps
                        .get(&child)
                        .map_or(Step::Chain, |wrapped| Step::Wrap(wrapped.clone()));
                    (latest.epoch, step)
                })
            } else {
                self.windows
                    .iter()
                    .take(usize::try_from(epoch).unwrap_or(0))
                    .rev()
                    .find_map(|stored| {
                        stored.index.keyed(node).map(|live| {
                            live.then(|| {
                                let step = stored
                                    .index
                                    .wrap(node, child)
                                    .map_or(Step::Chain, |wrapped| Step::Wrap(wrapped.clone()));
                                (stored.seal.header.epoch, step)
                            })
                        })
                    })
                    .flatten()
            };
            steps.insert(
                level,
                step.ok_or(CoreError::Invalid("blank ancestor of a member"))?,
            );
        }
        Ok(steps)
    }

    /// The packet of an island follower `member` for the window that
    /// created `epoch` (E-15): the steps of its path up to its island root,
    /// and a top as `choice` asks. A tree without islands, or a window that
    /// re-keyed nothing, gives the packet of [`Self::packet`].
    pub fn island_packet(
        &self,
        epoch: u64,
        member: Occupancy,
        choice: TopChoice,
    ) -> CoreResult<Packet> {
        let mut packet = self.packet(epoch, member)?;
        let stored = self.window(epoch)?;
        let shape = stored.shape;
        if !shape.has_islands() || stored.index.is_empty() {
            return Ok(packet);
        }
        let level = shape.island_level();
        packet.path.retain(|stepped, _| *stepped <= level);
        let island = shape.island_of(member.leaf);
        let relay = stored
            .relays
            .get(&island)
            .filter(|_| choice == TopChoice::Best);
        let flat = stored
            .flats
            .get(&island)
            .filter(|_| choice != TopChoice::Refresh);
        packet.top = Some(match (relay, flat) {
            (Some(relay), _) => Top::Relay(relay.clone()),
            (None, Some(flat)) => Top::Flat(flat.clone()),
            (None, None) => {
                Top::Refresh(self.steps_as_of(epoch, member.leaf, level + 1, shape.height)?)
            }
        });
        Ok(packet)
    }

    /// The last step of every level of `member`'s path above its island
    /// root, as of the current epoch: what an island follower refreshes
    /// its path from before sealing a window without a city (E-15).
    pub fn refresh_steps(&self, member: Occupancy) -> CoreResult<EntrySteps> {
        if !self.accepts_from(member) {
            return Err(CoreError::Unauthorized("not a member, or removal recorded"));
        }
        let shape = self.state.tree.shape();
        if !shape.has_islands() {
            return Ok(EntrySteps::new());
        }
        self.steps_as_of(
            self.state.epoch,
            member.leaf,
            shape.island_level() + 1,
            shape.height,
        )
    }

    fn entry_data(&self, leaf: u32) -> CoreResult<EntryData> {
        let mut steps = EntrySteps::new();
        for level in 1..=self.state.tree.height() {
            let node = NodeId::of_leaf(leaf, level);
            let latest = self
                .latest
                .get(&node)
                .ok_or(CoreError::Invalid("blank ancestor of a member"))?;
            let step = latest
                .wraps
                .get(&node.child_toward(leaf))
                .map_or(Step::Chain, |wrapped| Step::Wrap(wrapped.clone()));
            steps.insert(level, (latest.epoch, step));
        }
        Ok(EntryData {
            steps,
            leaf: self.state.tree.leaf_proof(leaf)?,
            nodes: self.state.tree.path_nodes(leaf),
        })
    }

    fn remove_applied(&mut self, open: &OpenWindow) {
        let applied: BTreeSet<Digest> = open.task.changes.iter().map(|c| c.request).collect();
        let tree = &self.state.tree;
        let next = self.state.epoch + 1;
        let joins = core::mem::take(&mut self.queue.joins);
        self.queue.joins = joins
            .into_iter()
            .filter(|q| {
                !applied.contains(&q.item.reference())
                    && self.still_valid(&Request::Join(q.item.clone()), next)
            })
            .collect();
        self.queue
            .removals
            .retain(|q| tree.is_member(q.item.target));
        self.queue
            .evictions
            .retain(|q| tree.is_member(q.item.target));
        self.queue.updates.retain(|q| {
            !applied.contains(&Request::Update(q.item.clone()).reference())
                && tree.is_member(q.item.member)
        });
        self.queue
            .re_entries
            .retain(|q| !applied.contains(&q.item.reference()) && tree.is_member(q.item.member));
        let interim = self.state.interim;
        self.queue.catch_ups.retain(|q| {
            !open.catch_ups.contains_key(&q.item.reference()) && q.item.prev_interim == interim
        });
        if open.task.policy.is_some() {
            self.queue.policy = None;
        }
    }

    /// Keep a welcome of a sealed window from `welcomer`, the authenticated
    /// sender, which the window must have assigned it. Welcomes are not
    /// signed: without this check any member could replace a joiner's
    /// welcome with one it cannot open.
    pub fn submit_welcome(&mut self, welcomer: Occupancy, welcome: Welcome) -> CoreResult<()> {
        let stored = self
            .windows
            .iter_mut()
            .find(|stored| stored.seal.header.epoch == welcome.epoch)
            .ok_or(CoreError::Invalid("welcome for an unknown window"))?;
        if !stored.entries.contains_key(&welcome.request) || welcome.gid != self.state.gid {
            return Err(CoreError::Invalid("welcome nobody asked for"));
        }
        let task = stored
            .task
            .welcomes
            .iter()
            .find(|task| task.request == welcome.request && task.welcomer == welcomer)
            .ok_or(CoreError::Unauthorized("not the welcomer of this request"))?;
        // A catch-up's welcome is sealed to the member's leaf key too; a
        // join's or a re-entry's is not.
        if welcome.leaf_ciphertext.is_some() != (task.kind == WelcomeKind::CatchUp) {
            return Err(CoreError::Invalid("welcome of another kind"));
        }
        stored.welcomes.insert(welcome.request, welcome);
        Ok(())
    }

    /// The sealed window that created `epoch`.
    pub fn window(&self, epoch: u64) -> CoreResult<&StoredWindow> {
        let index = usize::try_from(epoch)
            .ok()
            .and_then(|epoch| epoch.checked_sub(1))
            .ok_or(CoreError::Invalid("no window created epoch 0"))?;
        self.windows
            .get(index)
            .ok_or(CoreError::Invalid("unknown epoch"))
    }

    fn leaf_at(&self, epoch: u64, leaf: u32) -> Option<LeafNode> {
        for stored in self
            .windows
            .iter()
            .take(usize::try_from(epoch).unwrap_or(0))
            .rev()
        {
            if let Some(change) = stored.leaves.get(&leaf) {
                return change.clone();
            }
        }
        (leaf == 0).then(|| self.genesis_leaf.clone())
    }

    /// The packet of `member` for the window that created `epoch`. Refused
    /// to a member whose removal is recorded, and to non-members.
    pub fn packet(&self, epoch: u64, member: Occupancy) -> CoreResult<Packet> {
        if self.queue.removal_targets().contains_key(&member) {
            return Err(CoreError::Unauthorized("removal recorded"));
        }
        let stored = self.window(epoch)?;
        let leaf = self
            .leaf_at(epoch, member.leaf)
            .filter(|leaf| leaf.since == member.since)
            .ok_or(CoreError::Unauthorized("not a member at that epoch"))?;
        let header = &stored.seal.header;
        let entrant = match (&stored.sealer, header.kind) {
            (SealerEvidence::Entrant(evidence), SealKind::Entrant) => Some(EntrantProof {
                signature: stored.seal.signature.clone(),
                evidence: evidence.as_ref().clone(),
            }),
            _ => None,
        };
        Ok(Packet {
            header: header.clone(),
            tag: stored.seal.tag,
            entrant,
            registry: RegistryUpdate::between(
                &stored.registry_before,
                &stored.registry,
                stored.policy.as_ref(),
            ),
            leaf_key: kem_pk_hash(&leaf.encryption_key)?,
            path: stored.index.steps(member.leaf, header.height)?,
            top: None,
        })
    }

    /// The link of the window that created `epoch`.
    pub fn link(&self, epoch: u64) -> CoreResult<SealLink> {
        let stored = self.window(epoch)?;
        Ok(SealLink {
            proof: stored.seal.proof(),
            sealer: stored.sealer.clone(),
            registry: stored.registry.clone(),
            policy: stored.policy.clone(),
        })
    }

    /// Links of the windows after epoch `after`, up to epoch `upto`.
    pub fn links(&self, after: u64, upto: u64) -> CoreResult<Vec<SealLink>> {
        (after + 1..=upto).map(|epoch| self.link(epoch)).collect()
    }

    /// What the holder of `request` needs to enter the epoch that welcomes
    /// it, checking the seals from epoch `anchor`.
    pub fn entry(&self, request: &Digest, anchor: u64) -> CoreResult<Entry> {
        let stored = self
            .windows
            .iter()
            .find(|stored| stored.entries.contains_key(request))
            .ok_or(CoreError::Invalid("no window welcomes this request"))?;
        let data = stored
            .entries
            .get(request)
            .ok_or(CoreError::Invalid("no window welcomes this request"))?;
        let welcome = stored
            .welcomes
            .get(request)
            .ok_or(CoreError::Invalid("welcome not sealed yet"))?
            .clone();
        Ok(Entry {
            links: self.links(anchor, stored.seal.header.epoch)?,
            welcome,
            steps: data.steps.clone(),
            leaf: data.leaf.clone(),
            nodes: data.nodes.clone(),
            top: None,
        })
    }

    /// The entry of `request` by island (docs/specs-v0.5-draft.md section
    /// 3.6): the steps and parents of its path up to its island root, the
    /// root's node, and the relay element of its island, else its flat
    /// element (as `choice` allows, like an island packet); with neither,
    /// or no islands, the whole path.
    pub fn island_entry(
        &self,
        request: &Digest,
        anchor: u64,
        choice: TopChoice,
    ) -> CoreResult<Entry> {
        let mut entry = self.entry(request, anchor)?;
        let stored = self.window(entry.welcome.epoch)?;
        let shape = stored.shape;
        if !shape.has_islands() {
            return Ok(entry);
        }
        let island = shape.island_of(entry.leaf.index);
        let relay = stored
            .relays
            .get(&island)
            .filter(|_| choice == TopChoice::Best)
            .map(|relay| Top::Relay(relay.clone()));
        let flat = stored
            .flats
            .get(&island)
            .filter(|_| choice != TopChoice::Refresh)
            .map(|flat| Top::Flat(flat.clone()));
        let Some(top) = relay.or(flat) else {
            return Ok(entry);
        };
        let root = entry
            .nodes
            .last()
            .cloned()
            .flatten()
            .ok_or(CoreError::Invalid("blank root"))?;
        let level = shape.island_level();
        entry.steps.retain(|stepped, _| *stepped <= level);
        entry.nodes.truncate(usize::from(level));
        entry.top = Some(EntryTop { root, top });
        Ok(entry)
    }

    /// Keep an admin's checkpoint after checking it against the epoch it
    /// names.
    pub fn submit_checkpoint(&mut self, checkpoint: Checkpoint) -> CoreResult<()> {
        let admin_pk = self
            .state
            .registry
            .admins()
            .get(&checkpoint.admin)
            .ok_or(CoreError::Unauthorized("checkpoint signer is not an admin"))?;
        checkpoint.verify(&self.state.gid, admin_pk)?;
        let content = &checkpoint.content;
        let (registry, external_pk) = self.anchor_material(content.epoch)?;
        let (interim, tree_hash, height) = if content.epoch == self.state.epoch {
            (
                self.state.interim,
                self.state.tree.tree_hash()?,
                self.state.tree.height(),
            )
        } else {
            let header = &self.window(content.epoch)?.seal.header;
            (
                self.interim_of(content.epoch)?,
                header.tree_hash,
                header.height,
            )
        };
        if content.interim != interim
            || content.tree_hash != tree_hash
            || content.height != height
            || content.district_bits != self.state.tree.district_bits()
            || content.island_bits != self.state.tree.island_bits()
            || content.subcity_bits != self.state.tree.subcity_bits()
            || content.registry_hash != registry.hash()?
            || content.external_pk_hash != kem_pk_hash(&external_pk)?
        {
            return Err(CoreError::Invalid("checkpoint of another state"));
        }
        self.checkpoints.push(checkpoint);
        Ok(())
    }

    fn interim_of(&self, epoch: u64) -> CoreResult<Digest> {
        let genesis_confirmed = confirmed_transcript_hash(&ZERO32, &self.genesis.header.hash()?)?;
        let mut interim = interim_transcript_hash(&genesis_confirmed, &self.genesis.tag)?;
        for stored in self
            .windows
            .iter()
            .take(usize::try_from(epoch).unwrap_or(0))
        {
            let confirmed = confirmed_transcript_hash(&interim, &stored.seal.header.hash()?)?;
            interim = interim_transcript_hash(&confirmed, &stored.seal.tag)?;
        }
        Ok(interim)
    }

    /// The latest checkpoint.
    #[must_use]
    pub fn latest_checkpoint(&self) -> Option<&Checkpoint> {
        self.checkpoints.last()
    }

    /// The registry header and external key of `epoch`, which a joiner
    /// checks against a checkpoint.
    pub fn anchor_material(&self, epoch: u64) -> CoreResult<(RegistryHeader, Vec<u8>)> {
        if epoch == 0 {
            return Ok((
                self.genesis_registry.clone(),
                self.genesis.external_pk.clone(),
            ));
        }
        let stored = self.window(epoch)?;
        Ok((stored.registry.clone(), stored.seal.external_pk.clone()))
    }
}
