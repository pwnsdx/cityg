//! An in-memory delivery service (docs/specs-v0.4-draft.md section 14).
//!
//! It never draws a group secret and never signs a group object. It records
//! requests after checking them, closes windows (E-1), places joins (E-11),
//! assigns the roles of a window among online members or, with nobody
//! online, to an entrant (E-3, E-7), checks what the roles send back,
//! serves one packet per member (E-13), the chains of seals and the entries
//! of joiners and returning members (E-8, E-10), keeps the latest wrap of
//! every node, enforces recorded removals at delivery, evicts under an
//! admin-signed policy, and keeps the records auditors sample (E-12).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use cityg_core::error::{CoreError, CoreResult};
use cityg_core::hash::Digest;

use crate::audit::{AuditRecord, records};
use crate::commit::{Change, DistrictCommit, Seal, SealKind};
use crate::crypto::{Wrap, kem_pk_hash};
use crate::member::{CatchUps, PendingRemoval};
use crate::objects::{
    Authorizer, CatchUpRequest, ChangeKind, Checkpoint, Eviction, EvictionPolicy, JoinRequest,
    ReEntryRequest, RemoveProposal, Request, UpdateRequest,
};
use crate::packet::{
    EntrantEvidence, EntrantProof, Entry, EntrySteps, Packet, RegistryUpdate, SealLink,
    SealerEvidence,
};
use crate::registry::RegistryHeader;
use crate::rekey::{Step, WindowIndex};
use crate::roles::{WelcomeKind, WelcomeTask, WindowTask};
use crate::tree::{LeafNode, LeafProof, MAX_HEIGHT, NodeId, Occupancy, ParentNode};
use crate::welcome::Welcome;
use crate::window::{
    PublicState, Requests, SealerInfo, WindowShape, check_committer, check_district_commit,
    check_entry, check_sealer, check_window, district_leaves, needed_height,
};

/// Timing of windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DsConfig {
    /// Longest window (`WINDOW_MAX`).
    pub window_max_ms: u64,
    /// Window length when a removal is pending (`WINDOW_REMOVAL`).
    pub window_removal_ms: u64,
}

impl Default for DsConfig {
    fn default() -> Self {
        Self {
            window_max_ms: 60_000,
            window_removal_ms: 5_000,
        }
    }
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
    policy: Option<Queued<EvictionPolicy>>,
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

    fn oldest_removal(&self) -> Option<u64> {
        self.removals
            .iter()
            .map(|q| q.recorded_ms)
            .chain(self.evictions.iter().map(|q| q.recorded_ms))
            .min()
    }

    fn removal_targets(&self) -> BTreeMap<Occupancy, u64> {
        let mut targets = BTreeMap::new();
        for (target, at) in self
            .removals
            .iter()
            .map(|q| (q.item.target, q.recorded_ms))
            .chain(
                self.evictions
                    .iter()
                    .map(|q| (q.item.target, q.recorded_ms)),
            )
        {
            targets
                .entry(target)
                .and_modify(|first: &mut u64| *first = (*first).min(at))
                .or_insert(at);
        }
        targets
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
    pub requests: Requests,
    pub catch_ups: CatchUps,
    index: WindowIndex,
    sealer: SealerEvidence,
    registry_before: RegistryHeader,
    registry: RegistryHeader,
    leaves: BTreeMap<u32, Option<LeafNode>>,
    entries: HashMap<Digest, EntryData>,
    welcomes: HashMap<Digest, Welcome>,
    audits: Vec<AuditRecord>,
    committer_leaves: HashMap<Occupancy, LeafProof>,
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
}

struct OpenWindow {
    task: WindowTask,
    window: WindowShape,
    sealer: SealerInfo,
    requests: Requests,
    catch_ups: CatchUps,
    commits: BTreeMap<u32, DistrictCommit>,
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
        if let Authorizer::Invite(invite) = &join.admission.authorizer {
            if now_ms > invite.expires_at_ms {
                return Err(CoreError::Invalid("invite expired"));
            }
            let id = invite.id()?;
            let used = self.invite_uses.get(&id).copied().unwrap_or(0);
            let queued = self
                .queue
                .joins
                .iter()
                .filter(|q| match &q.item.admission.authorizer {
                    Authorizer::Invite(other) => other.invite_pk == invite.invite_pk,
                    Authorizer::Admin(_) => false,
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
        let admission = request.admission.hash();
        if self.queue.joins.iter().any(|q| {
            q.item.device_id().is_ok_and(|other| other == device)
                || q.item.admission.hash() == admission
        }) {
            return Err(CoreError::Invalid("join already queued"));
        }
        self.check_invite(&request, now_ms)?;
        let reference = request.reference();
        self.queue.joins.push(Queued {
            item: request,
            recorded_ms: now_ms,
        });
        Ok(reference)
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
        if !self
            .queue
            .removals
            .iter()
            .any(|q| q.item.target == proposal.target)
        {
            self.queue.removals.push(Queued {
                item: proposal,
                recorded_ms: now_ms,
            });
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
        self.queue.catch_ups.push(Queued {
            item: request,
            recorded_ms: now_ms,
        });
        Ok(reference)
    }

    /// Record an eviction policy after checking it.
    pub fn submit_policy(&mut self, policy: EvictionPolicy, now_ms: u64) -> CoreResult<()> {
        policy.verify(&self.state.gid, self.state.registry.admins())?;
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
        let epoch = self.next_epoch();
        let queued: BTreeSet<Occupancy> = self.queue.removal_targets().into_keys().collect();
        let idle: Vec<Occupancy> = self
            .state
            .tree
            .leaves()
            .filter(|(_, leaf)| epoch.saturating_sub(leaf.updated) > policy.max_idle_epochs)
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
            .map(|(target, recorded_ms)| PendingRemoval {
                target,
                recorded_ms,
            })
            .collect()
    }

    /// Whether the service accepts messages and commits from `member`:
    /// not once a removal of it is recorded (E-7).
    #[must_use]
    pub fn accepts_from(&self, member: Occupancy) -> bool {
        self.state.tree.is_member(member) && !self.queue.removal_targets().contains_key(&member)
    }

    /// Whether a window should be closed at `now_ms`.
    #[must_use]
    pub fn due(&self, now_ms: u64) -> bool {
        if self.open.is_some() {
            return false;
        }
        let by_age = self
            .queue
            .oldest()
            .is_some_and(|oldest| now_ms.saturating_sub(oldest) >= self.config.window_max_ms);
        let by_removal = self
            .queue
            .oldest_removal()
            .is_some_and(|oldest| now_ms.saturating_sub(oldest) >= self.config.window_removal_ms);
        by_age || by_removal
    }

    /// Whether a queued entry is still valid for the window creating
    /// `epoch`: what may have changed since it was checked (expiry, admins,
    /// the policy, the member's key) is checked again; signatures are not.
    fn still_valid(&self, request: &Request, epoch: u64) -> bool {
        let admins = self.state.registry.admins();
        match request {
            Request::Join(join) => {
                let admission = &join.admission;
                let authorized = match &admission.authorizer {
                    Authorizer::Admin(admin) => admins.get(admin) == Some(&admission.authorizer_pk),
                    Authorizer::Invite(invite) => {
                        admins.get(&invite.inviter) == Some(&invite.inviter_pk)
                    }
                };
                authorized
                    && epoch <= admission.not_after_epoch
                    && join
                        .device_id()
                        .is_ok_and(|id| self.state.registry.device(&id).is_none())
                    && self.state.registry.admission(&admission.hash()).is_none()
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
                            epoch.saturating_sub(leaf.updated) > policy.max_idle_epochs
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
            requests.insert(request.reference(), request);
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
            requests.insert(request.reference(), request);
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
            requests.insert(request.reference(), request);
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
            .filter(|member| tree.is_member(*member) && !window.affected.contains(member))
            .collect();
        let (committers, sealer, entrant) = if volunteers.is_empty() {
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
            (committers, occupancy, Some(entrant.request))
        } else {
            let mut by_district: BTreeMap<u32, Occupancy> = BTreeMap::new();
            for volunteer in &volunteers {
                by_district
                    .entry(shape.district_of(volunteer.leaf))
                    .or_insert(*volunteer);
            }
            let mut next = 0usize;
            let mut committers = BTreeMap::new();
            for district in &window.districts {
                let committer = by_district.get(district).copied().unwrap_or_else(|| {
                    let chosen = volunteers[next % volunteers.len()];
                    next += 1;
                    chosen
                });
                committers.insert(*district, committer);
            }
            let busy: BTreeSet<Occupancy> = committers.values().copied().collect();
            let sealer = volunteers
                .iter()
                .copied()
                .find(|volunteer| !busy.contains(volunteer))
                .unwrap_or(volunteers[0]);
            (committers, sealer, None)
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
            let welcomer = committers
                .get(&shape.district_of(change.leaf))
                .copied()
                .unwrap_or(sealer);
            welcomes.push(WelcomeTask {
                kind,
                request: change.request,
                welcomer,
            });
        }
        let mut catch_up_map = CatchUps::new();
        for request in catch_ups {
            let welcomer = committers
                .get(&shape.district_of(request.member.leaf))
                .copied()
                .unwrap_or(sealer);
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

    /// Give district `district` of the open window to another committer
    /// (a committer that failed); a commit already received is dropped.
    pub fn reassign(&mut self, district: u32, committer: Occupancy) -> CoreResult<WindowTask> {
        let open = self
            .open
            .as_mut()
            .ok_or(CoreError::Invalid("no open window"))?;
        if open.task.entrant.is_some()
            || !self.state.tree.is_member(committer)
            || open.window.affected.contains(&committer)
        {
            return Err(CoreError::Invalid("committer"));
        }
        let old = open
            .task
            .committers
            .insert(district, committer)
            .ok_or(CoreError::Invalid("district not in the window"))?;
        for welcome in &mut open.task.welcomes {
            if welcome.welcomer == old
                && open.task.changes.iter().any(|c| {
                    c.request == welcome.request
                        && self.state.tree.shape().district_of(c.leaf) == district
                })
            {
                welcome.welcomer = committer;
            }
        }
        open.commits.remove(&district);
        Ok(open.task.clone())
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
        if !open.sealer.entrant && !self.accepts_from(commit.committer) {
            return Err(CoreError::Unauthorized("committer removed"));
        }
        let committer_pk =
            check_committer(&self.state, &open.window, commit.committer, &open.sealer)?;
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

    /// Check the seal of the open window, apply the window, and keep what
    /// members, joiners and auditors will ask for. Returns the new epoch.
    pub fn submit_seal(&mut self, seal: Seal) -> CoreResult<u64> {
        let open = self
            .open
            .as_ref()
            .ok_or(CoreError::Invalid("no open window"))?;
        if seal.header.sealer != open.task.sealer
            || open.commits.len() != open.task.committers.len()
        {
            return Err(CoreError::Invalid("seal before its district commits"));
        }
        if !open.sealer.entrant && !self.accepts_from(seal.header.sealer) {
            return Err(CoreError::Unauthorized("sealer removed"));
        }
        let commits: Vec<DistrictCommit> = open.commits.values().cloned().collect();
        let outcome = check_window(&self.state, &commits, &seal, &open.requests, false)?;
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
                    request: join.clone(),
                    device: self.state.registry.device_proof(&join.device_id()?)?,
                    admission: self
                        .state
                        .registry
                        .admission_proof(&join.admission.hash())?,
                },
                Some(Request::ReEntry(re_entry)) => EntrantEvidence::ReEntry {
                    request: re_entry.clone(),
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
        let mut index = WindowIndex::default();
        let mut all_updates = Vec::new();
        let mut all_wraps: Vec<&Wrap> = Vec::new();
        for commit in &commits {
            index.add(&commit.updates, &commit.wraps);
            all_updates.extend(commit.updates.iter().cloned());
            all_wraps.extend(commit.wraps.iter());
        }
        index.add(&seal.body.city_updates, &seal.body.city_wraps);
        all_updates.extend(seal.body.city_updates.iter().cloned());
        all_wraps.extend(seal.body.city_wraps.iter());
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
            .chain(core::iter::once(&open.task.sealer))
        {
            if self.state.tree.is_member(*committer) {
                committer_leaves.insert(*committer, self.state.tree.leaf_proof(committer.leaf)?);
            }
        }
        self.remove_applied(&open);
        for change in &open.task.changes {
            if let Some(Request::Join(join)) = open.requests.get(&change.request)
                && let Authorizer::Invite(invite) = &join.admission.authorizer
            {
                *self.invite_uses.entry(invite.id()?).or_insert(0) += 1;
            }
        }
        self.windows.push(StoredWindow {
            task: open.task,
            seal,
            commits,
            requests: open.requests,
            catch_ups: open.catch_ups,
            index,
            sealer,
            registry_before,
            registry,
            leaves: outcome.tree.leaves.clone(),
            entries,
            welcomes: HashMap::new(),
            audits,
            committer_leaves,
        });
        Ok(epoch)
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

    /// Keep a welcome of a sealed window.
    pub fn submit_welcome(&mut self, welcome: Welcome) -> CoreResult<()> {
        let stored = self
            .windows
            .iter_mut()
            .find(|stored| stored.seal.header.epoch == welcome.epoch)
            .ok_or(CoreError::Invalid("welcome for an unknown window"))?;
        if !stored.entries.contains_key(&welcome.request) || welcome.gid != self.state.gid {
            return Err(CoreError::Invalid("welcome nobody asked for"));
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
            registry: RegistryUpdate::between(&stored.registry_before, &stored.registry),
            leaf_key: kem_pk_hash(&leaf.encryption_key)?,
            path: stored.index.steps(member.leaf, header.height)?,
        })
    }

    /// The link of the window that created `epoch`.
    pub fn link(&self, epoch: u64) -> CoreResult<SealLink> {
        let stored = self.window(epoch)?;
        Ok(SealLink {
            proof: stored.seal.proof(),
            sealer: stored.sealer.clone(),
            registry: stored.registry.clone(),
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
        })
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
            || content.registry_hash != registry.hash()?
            || content.external_pk_hash != kem_pk_hash(&external_pk)?
        {
            return Err(CoreError::Invalid("checkpoint of another state"));
        }
        self.checkpoints.push(checkpoint);
        Ok(())
    }

    fn interim_of(&self, epoch: u64) -> CoreResult<Digest> {
        let genesis_confirmed = crate::schedule::confirmed_transcript_hash(
            &cityg_core::hash::ZERO32,
            &self.genesis.header.hash()?,
        )?;
        let mut interim =
            crate::schedule::interim_transcript_hash(&genesis_confirmed, &self.genesis.tag)?;
        for stored in self
            .windows
            .iter()
            .take(usize::try_from(epoch).unwrap_or(0))
        {
            let confirmed =
                crate::schedule::confirmed_transcript_hash(&interim, &stored.seal.header.hash()?)?;
            interim = crate::schedule::interim_transcript_hash(&confirmed, &stored.seal.tag)?;
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
