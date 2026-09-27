//! What a window asks of its committers, the performers of its city tasks
//! and its sealer (docs/specs.md sections 12.4, 12.5 and 12.7;
//! docs/specs-v0.5-draft.md sections 3.2 to 3.5), shared by members and
//! entrants.

use std::collections::BTreeMap;

use rand_core::CryptoRngCore;

use crate::commit::{
    Change, CityTask, CityTaskContent, DistrictCommit, DistrictCommitContent, EntrantInit, Seal,
    SealBody, SealHeader, SealKind,
};
use crate::crypto::{Digest, commit_secret};
use crate::error::{CoreError, CoreResult};
use crate::identity::DeviceIdentity;
use crate::membership::{self, MembershipLog};
use crate::message::MessageLog;
use crate::objects::GroupPolicy;
use crate::rekey::{self, KeySource, NewRoots, Rekeyed, generate, plan_district, plan_part};
use crate::schedule::{
    EpochSecrets, GroupContext, confirmed_transcript_hash, interim_transcript_hash,
};
use crate::tree::{CityPart, Occupancy, Overlay, TreeDelta};
use crate::window::{
    EpochHeader, PublicState, Requests, SealerInfo, WindowShape, district_leaves, district_roots,
    keyed_parents, part_below, prev_district_hash, prev_part_hash, registry_delta, subcity_roots,
};

/// Whom a welcome is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WelcomeKind {
    Join,
    ReEntry,
    CatchUp,
}

/// A welcome the window owes, and who seals it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WelcomeTask {
    pub kind: WelcomeKind,
    pub request: Digest,
    pub welcomer: Occupancy,
}

/// A window as the delivery service plans it: its changes, its height, and
/// its roles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowTask {
    pub gid: Digest,
    pub epoch: u64,
    pub height: u8,
    /// Every change of the window, sorted by `(leaf, kind)`.
    pub changes: Vec<Change>,
    /// Committer of each district of the window.
    pub committers: BTreeMap<u32, Occupancy>,
    /// Performer of each city task of the window (docs/specs-v0.5-draft.md
    /// section 3.2).
    pub city: BTreeMap<CityPart, Occupancy>,
    pub sealer: Occupancy,
    /// The entrant's request, when an entrant seals the window.
    pub entrant: Option<Digest>,
    /// A group policy the window sets.
    pub policy: Option<Vec<u8>>,
    pub welcomes: Vec<WelcomeTask>,
    pub time_ms: u64,
}

impl WindowTask {
    /// The window's structure over `state`, checked against the roles.
    pub fn window(&self, state: &PublicState) -> CoreResult<WindowShape> {
        if self.gid != state.gid || self.epoch != state.epoch + 1 {
            return Err(CoreError::Invalid("window task for another epoch"));
        }
        let shape = state.tree.shape().grown(self.height)?;
        let window =
            WindowShape::new(&state.tree, self.epoch, shape, self.changes.iter().copied())?;
        if window.districts != self.committers.keys().copied().collect()
            || window.parts != self.city.keys().copied().collect()
        {
            return Err(CoreError::Invalid("window task districts"));
        }
        Ok(window)
    }

    /// The group policy the window sets.
    pub fn policy(&self) -> CoreResult<Option<GroupPolicy>> {
        self.policy.as_deref().map(GroupPolicy::decode).transpose()
    }
}

/// Commit district `district`: check its entries, plan, draw and wrap the
/// new secrets, and sign. The caller erases the returned secrets once it no
/// longer needs them.
#[allow(clippy::too_many_arguments)]
pub fn build_district(
    state: &PublicState,
    window: &WindowShape,
    district: u32,
    requests: &Requests,
    committer: Occupancy,
    identity: &DeviceIdentity,
    hedge: &[u8; 32],
    rng: &mut impl CryptoRngCore,
) -> CoreResult<(DistrictCommit, Rekeyed)> {
    let leaves = district_leaves(state, window, district, requests, true)?;
    let plan = plan_district(
        &state.tree,
        window.shape,
        district,
        &leaves,
        &window.forced(district),
    )?;
    let keys = KeySource {
        tree: &state.tree,
        shape: window.shape,
        leaves: &leaves,
        below: None,
    };
    let rekeyed = generate(&plan, &keys, &state.gid, window.epoch, hedge, rng)?;
    let delta = TreeDelta {
        leaves: leaves.clone(),
        parents: keyed_parents(&rekeyed.updates, committer),
    };
    let district_hash = Overlay::new(&state.tree, window.shape, &delta)?.district_hash(district)?;
    let commit = DistrictCommit::sign(
        DistrictCommitContent {
            gid: state.gid,
            epoch: window.epoch,
            district,
            height: window.shape.height,
            prev_district_hash: prev_district_hash(state, window.shape, district)?,
            committer,
            changes: window.district_changes(district).to_vec(),
            updates: rekeyed.updates.clone(),
            wraps: rekeyed.wraps.clone(),
            district_hash,
        },
        identity,
        rng,
    )?;
    Ok((commit, rekeyed))
}

/// What a window's performers have submitted, as the delivery service shows
/// it: its district commits, its city tasks, and the requests of its
/// changes.
#[derive(Clone, Copy, Debug)]
pub struct WindowWork<'a> {
    pub commits: &'a [DistrictCommit],
    pub city_tasks: &'a [CityTask],
    pub requests: &'a Requests,
}

impl WindowWork<'_> {
    /// What the task of `part` builds on: the new roots of the tier below,
    /// and the delta of the district commits and, for the top, of the
    /// sub-city tasks. Nothing is checked but their structure: the task binds
    /// them through its hashes, and the DS and the sealer check them
    /// (docs/specs-v0.5-draft.md section 3.2).
    pub fn base(
        &self,
        state: &PublicState,
        window: &WindowShape,
        part: CityPart,
    ) -> CoreResult<(NewRoots, TreeDelta)> {
        let mut delta = TreeDelta::default();
        for commit in self.commits {
            delta.leaves.extend(district_leaves(
                state,
                window,
                commit.district,
                self.requests,
                false,
            )?);
            delta
                .parents
                .extend(keyed_parents(&commit.updates, commit.committer));
        }
        let lower: Vec<CityTask> = self
            .city_tasks
            .iter()
            .filter(|task| task.part < part)
            .cloned()
            .collect();
        for task in &lower {
            delta
                .parents
                .extend(keyed_parents(&task.updates, task.performer));
        }
        let districts = district_roots(window.shape, self.commits)?;
        let subcities = subcity_roots(window.shape, &lower)?;
        Ok((
            part_below(window.shape, part, &districts, &subcities),
            delta,
        ))
    }
}

/// What a city task builds on: its part, the new roots of the tier below
/// (`None` for a root that became blank), and the window's delta before it
/// (its district commits and, for the top, its sub-city tasks).
pub struct CityTaskInput<'a> {
    pub state: &'a PublicState,
    pub window: &'a WindowShape,
    pub part: CityPart,
    pub below: &'a NewRoots,
    pub before: &'a TreeDelta,
    pub performer: Occupancy,
}

/// Perform a city task (docs/specs-v0.5-draft.md section 3.2): plan the
/// part, draw and wrap its new secrets, and sign. The caller erases the
/// returned secrets once it no longer needs them.
pub fn build_city_task(
    input: &CityTaskInput<'_>,
    identity: &DeviceIdentity,
    hedge: &[u8; 32],
    rng: &mut impl CryptoRngCore,
) -> CoreResult<(CityTask, Rekeyed)> {
    let state = input.state;
    let shape = input.window.shape;
    let live = input
        .below
        .iter()
        .map(|(index, key)| (*index, key.is_some()))
        .collect();
    let plan = plan_part(
        &state.tree,
        shape,
        input.part,
        &live,
        &input.window.part_forced(input.part),
    )?;
    let leaves = rekey::LeafChanges::new();
    let keys = KeySource {
        tree: &state.tree,
        shape,
        leaves: &leaves,
        below: Some((shape.part_base(input.part), input.below)),
    };
    let rekeyed = generate(&plan, &keys, &state.gid, input.window.epoch, hedge, rng)?;
    let mut after = input.before.clone();
    after
        .parents
        .extend(keyed_parents(&rekeyed.updates, input.performer));
    let part_hash =
        Overlay::new(&state.tree, shape, &after)?.node_hash(shape.part_root(input.part))?;
    let task = CityTask::sign(
        CityTaskContent {
            gid: state.gid,
            epoch: input.window.epoch,
            part: input.part,
            height: shape.height,
            prev_part_hash: prev_part_hash(state, shape, input.part)?,
            performer: input.performer,
            updates: rekeyed.updates.clone(),
            wraps: rekeyed.wraps.clone(),
            part_hash,
        },
        identity,
        rng,
    )?;
    Ok((task, rekeyed))
}

/// Everything a sealer has gathered before signing.
pub struct SealDraft<'a> {
    pub state: &'a PublicState,
    pub window: &'a WindowShape,
    pub commits: &'a [DistrictCommit],
    pub requests: &'a Requests,
    pub sealer: &'a SealerInfo,
    pub entrant: Option<EntrantInit>,
    /// The districts' delta and the city's parents.
    pub delta: TreeDelta,
    pub city_tasks: &'a [CityTask],
    pub policy: Option<GroupPolicy>,
    pub time_ms: u64,
    /// The log of the previous epoch's messages, which the DS gave the
    /// sealer (docs/specs-v0.5-draft.md section 4.8).
    pub message_log: MessageLog,
    /// `init_secret` of the previous epoch, or the external init secret.
    pub init_prev: &'a [u8; 32],
    /// The window's new root secret.
    pub root_secret: &'a [u8; 32],
}

/// A signed seal, the secrets of the epoch it creates, and its header.
pub struct Sealed {
    pub seal: Seal,
    pub secrets: EpochSecrets,
    pub header: EpochHeader,
}

/// Compute the new hashes, the key schedule and the confirmation tag, and
/// sign the seal.
pub fn finish_seal(
    draft: SealDraft<'_>,
    identity: &DeviceIdentity,
    rng: &mut impl CryptoRngCore,
) -> CoreResult<Sealed> {
    let state = draft.state;
    let window = draft.window;
    let shape = window.shape;
    let tree_hash = Overlay::new(&state.tree, shape, &draft.delta)?.tree_hash()?;
    let delta = registry_delta(
        state,
        window,
        draft.requests,
        draft.policy.as_ref(),
        draft.sealer.occupancy,
        &draft.sealer.device_pk,
    )?;
    let registry = state.registry.header_with(&delta)?;
    let registry_hash = registry.hash()?;
    let body = SealBody {
        districts: draft
            .commits
            .iter()
            .map(|commit| (commit.district, commit.hash()))
            .collect(),
        city: draft
            .city_tasks
            .iter()
            .map(|task| (task.part, task.hash()))
            .collect(),
        policy: draft
            .policy
            .as_ref()
            .map(|policy| policy.encoded().to_vec()),
        genesis: None,
    };
    let kind = if draft.entrant.is_some() {
        SealKind::Entrant
    } else {
        SealKind::Member
    };
    let header = SealHeader {
        gid: state.gid,
        epoch: window.epoch,
        prev_interim: state.interim,
        kind,
        sealer: draft.sealer.occupancy,
        height: shape.height,
        district_bits: shape.district_bits,
        island_bits: shape.island_bits,
        subcity_bits: shape.subcity_bits,
        tree_hash,
        registry_hash,
        body_hash: body.hash()?,
        time_ms: draft.time_ms,
        message_log: draft.message_log,
        membership_log: MembershipLog::of(&membership::records(state, window, draft.requests)?)?,
        entrant: draft.entrant,
    };
    let confirmed = confirmed_transcript_hash(&state.interim, &header.hash()?)?;
    let context = GroupContext {
        gid: state.gid,
        epoch: window.epoch,
        tree_hash,
        registry_hash,
        height: shape.height,
        district_bits: shape.district_bits,
        island_bits: shape.island_bits,
        subcity_bits: shape.subcity_bits,
        confirmed_transcript_hash: confirmed,
    };
    let commit = commit_secret(draft.root_secret)?;
    let secrets = EpochSecrets::derive(draft.init_prev, &commit, &context)?;
    let tag = secrets.confirmation_tag(&confirmed)?;
    let external_pk = secrets.external_key()?.public_key();
    let seal = Seal::sign(header, body, tag, external_pk.clone(), identity, rng)?;
    Ok(Sealed {
        seal,
        secrets,
        header: EpochHeader {
            gid: state.gid,
            epoch: window.epoch,
            shape,
            tree_hash,
            registry,
            interim: interim_transcript_hash(&confirmed, &tag)?,
            external_pk,
        },
    })
}

/// The delta of a window whose district commits were checked, with the
/// parents of its city tasks, each tainted by its performer.
#[must_use]
pub fn with_city(mut delta: TreeDelta, city_tasks: &[CityTask]) -> TreeDelta {
    for task in city_tasks {
        delta
            .parents
            .extend(keyed_parents(&task.updates, task.performer));
    }
    delta
}
