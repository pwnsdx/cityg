//! What a window asks of its committers and its sealer
//! (docs/specs-v0.4-draft.md section 12.4), shared by members and entrants.

use std::collections::BTreeMap;

use rand_core::CryptoRngCore;

use crate::commit::{
    Change, DistrictCommit, DistrictCommitContent, EntrantInit, Seal, SealBody, SealHeader,
    SealKind,
};
use crate::crypto::{Digest, commit_secret};
use crate::error::{CoreError, CoreResult};
use crate::identity::DeviceIdentity;
use crate::objects::GroupPolicy;
use crate::rekey::{self, KeySource, Rekeyed, generate, plan_city, plan_district};
use crate::schedule::{
    EpochSecrets, GroupContext, confirmed_transcript_hash, interim_transcript_hash,
};
use crate::tree::{Occupancy, Overlay, TreeDelta};
use crate::window::{
    EpochHeader, PublicState, Requests, SealerInfo, WindowShape, district_leaves, keyed_parents,
    prev_district_hash, registry_delta,
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
        if window.districts != self.committers.keys().copied().collect() {
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
        roots: None,
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

/// Re-key the city above the districts of the window, whose new roots are
/// `roots`.
pub fn build_city(
    state: &PublicState,
    window: &WindowShape,
    roots: &BTreeMap<u32, Option<Vec<u8>>>,
    hedge: &[u8; 32],
    rng: &mut impl CryptoRngCore,
) -> CoreResult<Rekeyed> {
    let live = roots.iter().map(|(d, key)| (*d, key.is_some())).collect();
    let plan = plan_city(&state.tree, window.shape, &live, &window.city_forced)?;
    let leaves = rekey::LeafChanges::new();
    let keys = KeySource {
        tree: &state.tree,
        shape: window.shape,
        leaves: &leaves,
        roots: Some(roots),
    };
    generate(&plan, &keys, &state.gid, window.epoch, hedge, rng)
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
    pub city: &'a Rekeyed,
    pub policy: Option<GroupPolicy>,
    pub time_ms: u64,
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
        city_updates: draft.city.updates.clone(),
        city_wraps: draft.city.wraps.clone(),
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
        tree_hash,
        registry_hash,
        body_hash: body.hash()?,
        time_ms: draft.time_ms,
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

/// The district delta and city parents of a window whose district commits
/// were checked, with the city re-key `city` by `sealer`.
#[must_use]
pub fn with_city(mut delta: TreeDelta, city: &Rekeyed, sealer: Occupancy) -> TreeDelta {
    delta.parents.extend(keyed_parents(&city.updates, sealer));
    delta
}
