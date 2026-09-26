//! Members, joiners and returning members (docs/specs-v0.4-draft.md
//! sections 12 to 14).
//!
//! A [`Member`] keeps its leaf key, the secrets of its path, the secrets of
//! its epoch and the epoch's header: O(log N) state, whatever the size of
//! the group. It follows the group window by window from [`Packet`]s,
//! checking the confirmation tag (and, for windows an entrant sealed, the
//! entrant's signature and admission). Any member may commit a district or
//! seal a window from the public state the delivery service shows it, once
//! it has checked that state against its header.
//!
//! A [`Joiner`] enters from a checkpoint; a [`Returning`] member either
//! jumps to the present with a welcome or re-enters its leaf. Both check
//! the chain of seals from their anchor, and both can seal a window
//! themselves when no member is online (E-7).

use std::collections::{BTreeMap, HashMap};

use cityg_core::error::{CoreError, CoreResult};
use cityg_core::hash::{Digest, ZERO32};
use cityg_core::identity::DeviceIdentity;
use cityg_core::kem::KemSecret;
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::commit::{
    DistrictCommit, EntrantInit, Genesis, Seal, SealBody, SealHeader, SealKind, SealProof,
};
use crate::crypto::{Secret, commit_secret, fresh_secret, kem_pk_hash, node_key};
use crate::objects::{
    Admission, CatchUpRequest, Checkpoint, CheckpointContent, GroupPolicy, Invite, JoinRequest,
    ReEntryRequest, RemoveProposal, Request, UpdateRequest, group_id,
};
use crate::packet::{Entry, Packet, SealLink};
use crate::rekey::{MemberPath, WindowIndex};
use crate::roles::{
    SealDraft, WelcomeKind, WindowTask, build_city, build_district, finish_seal, with_city,
};
use crate::schedule::{
    EpochSecrets, GroupContext, confirmed_transcript_hash, external_init, interim_transcript_hash,
};
use crate::tree::{Occupancy, Shape};
use crate::welcome::Welcome;
use crate::window::{
    EpochHeader, PublicState, Requests, check_districts, check_sealer, district_roots, genesis_tree,
};

/// A removal the delivery service recorded and has not applied yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingRemoval {
    pub target: Occupancy,
    pub recorded_ms: u64,
}

/// Catch-up requests of a window, by reference.
pub type CatchUps = HashMap<Digest, CatchUpRequest>;

/// A member of the group.
pub struct Member {
    identity: DeviceIdentity,
    occupancy: Occupancy,
    path: MemberPath,
    header: EpochHeader,
    previous: Option<EpochHeader>,
    seal_hash: Digest,
    secrets: EpochSecrets,
    pending_leaf: Option<KemSecret>,
}

impl core::fmt::Debug for Member {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Member")
            .field("occupancy", &self.occupancy)
            .field("epoch", &self.header.epoch)
            .finish_non_exhaustive()
    }
}

impl Member {
    /// Create a group: the creator at leaf 0, admin, in a tree of two leaves
    /// with districts of `2^district_bits` leaves. An `open` group admits any
    /// device without admission (its creator signs that policy at genesis);
    /// otherwise every join needs an admission. Returns the creator and the
    /// genesis seal.
    pub fn create(
        identity: DeviceIdentity,
        nonce: [u8; 32],
        district_bits: u8,
        open: bool,
        time_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<(Self, Seal)> {
        let gid = group_id(identity.public_key(), &nonce)?;
        let creator = Occupancy { leaf: 0, since: 0 };
        let policy = if open {
            Some(GroupPolicy::sign(
                &gid, true, None, creator, &identity, rng,
            )?)
        } else {
            None
        };
        let leaf_key = KemSecret::generate(rng);
        let root_secret = fresh_secret(&ZERO32, rng)?;
        let root_pk = node_key(&root_secret)?.public_key();
        let (tree, registry) = genesis_tree(
            &gid,
            district_bits,
            identity.public_key(),
            &leaf_key.public_key(),
            &root_pk,
            policy.as_ref(),
        )?;
        let body = SealBody {
            policy: policy.as_ref().map(|policy| policy.encoded().to_vec()),
            genesis: Some(Genesis {
                nonce,
                creator_pk: identity.public_key().to_vec(),
                encryption_key: leaf_key.public_key(),
                root_pk,
            }),
            ..SealBody::default()
        };
        let tree_hash = tree.tree_hash()?;
        let registry_header = registry.header()?;
        let header = SealHeader {
            gid,
            epoch: 0,
            prev_interim: ZERO32,
            kind: SealKind::Genesis,
            sealer: creator,
            height: 1,
            district_bits,
            tree_hash,
            registry_hash: registry_header.hash()?,
            body_hash: body.hash()?,
            time_ms,
            entrant: None,
        };
        let seal_hash = header.hash()?;
        let confirmed = confirmed_transcript_hash(&ZERO32, &seal_hash)?;
        let context = GroupContext {
            gid,
            epoch: 0,
            tree_hash,
            registry_hash: header.registry_hash,
            height: 1,
            district_bits,
            confirmed_transcript_hash: confirmed,
        };
        let commit = commit_secret(&root_secret)?;
        let secrets = EpochSecrets::derive(&ZERO32, &commit, &context)?;
        let tag = secrets.confirmation_tag(&confirmed)?;
        let external_pk = secrets.external_key()?.public_key();
        let seal = Seal::sign(header, body, tag, external_pk.clone(), &identity, rng)?;
        let mut path = MemberPath::new(0, leaf_key);
        path.set_secrets(BTreeMap::from([(1, root_secret)]));
        let member = Self {
            identity,
            occupancy: creator,
            path,
            header: EpochHeader {
                gid,
                epoch: 0,
                shape: Shape::new(1, district_bits)?,
                tree_hash,
                registry: registry_header,
                interim: interim_transcript_hash(&confirmed, &tag)?,
                external_pk,
            },
            previous: None,
            seal_hash,
            secrets,
            pending_leaf: None,
        };
        Ok((member, seal))
    }

    /// The member's occupancy.
    #[must_use]
    pub const fn occupancy(&self) -> Occupancy {
        self.occupancy
    }

    /// The group.
    #[must_use]
    pub const fn gid(&self) -> &Digest {
        &self.header.gid
    }

    /// The current epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.header.epoch
    }

    /// The header of the current epoch.
    #[must_use]
    pub const fn header(&self) -> &EpochHeader {
        &self.header
    }

    /// The header of the previous epoch (what auditors check entries of the
    /// last window against).
    #[must_use]
    pub const fn previous_header(&self) -> Option<&EpochHeader> {
        self.previous.as_ref()
    }

    /// The member's device identity.
    #[must_use]
    pub const fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    /// Whether the member is an admin.
    #[must_use]
    pub fn is_admin(&self) -> bool {
        self.header.registry.admins.contains_key(&self.occupancy)
    }

    /// `msg_secret` of the current epoch.
    #[must_use]
    pub const fn msg_secret(&self) -> &[u8; 32] {
        self.secrets.msg_secret()
    }

    /// The member's leaf key.
    #[must_use]
    pub fn leaf_public_key(&self) -> &[u8] {
        self.path.leaf_public_key()
    }

    /// The devices the window that created the current epoch let in, with
    /// their occupancies, checked against the seal the member accepted: in
    /// an open group, every join is visible to whoever looks.
    pub fn window_joins(
        &self,
        seal: &Seal,
        commits: &[DistrictCommit],
        requests: &Requests,
    ) -> CoreResult<Vec<(Occupancy, Vec<u8>)>> {
        if seal.header.hash()? != self.seal_hash {
            return Err(CoreError::Invalid("seal of another epoch"));
        }
        crate::window::joins_of(seal, commits, requests)
    }

    /// Follow one window.
    pub fn process(&mut self, packet: &Packet) -> CoreResult<()> {
        let header = &packet.header;
        if header.gid != self.header.gid
            || header.prev_interim != self.header.interim
            || header.district_bits != self.header.shape.district_bits
        {
            return Err(CoreError::Invalid("packet for another epoch"));
        }
        if header.epoch != self.header.epoch + 1 {
            return Err(CoreError::EpochMismatch {
                expected: self.header.epoch + 1,
                got: header.epoch,
            });
        }
        let shape = self.header.shape.grown(header.height)?;
        let registry = packet
            .registry
            .apply(&self.header.gid, &self.header.registry)?;
        if registry.hash()? != header.registry_hash {
            return Err(CoreError::Invalid("registry header"));
        }
        let init_prev: Secret = match (header.kind, &header.entrant, &packet.entrant) {
            (SealKind::Member, None, None) => Zeroizing::new(*self.secrets.init_secret()),
            (SealKind::Entrant, Some(init), Some(_)) => {
                self.secrets.external_init_secret(&init.kem_output)?
            }
            _ => return Err(CoreError::Invalid("packet seal kind")),
        };
        let mut path = self.path.clone();
        let mut leaf_changed = false;
        if packet.leaf_key != kem_pk_hash(path.leaf_public_key())? {
            let pending = self
                .pending_leaf
                .as_ref()
                .ok_or(CoreError::Invalid("packet names another leaf key"))?;
            if packet.leaf_key != kem_pk_hash(&pending.public_key())? {
                return Err(CoreError::Invalid("packet names another leaf key"));
            }
            path.set_leaf_key(pending.clone());
            leaf_changed = true;
        }
        let secrets = path.advance(shape.height, &packet.path, &self.header.gid, header.epoch)?;
        let root = secrets
            .get(&shape.height)
            .ok_or(CoreError::Invalid("unknown root secret"))?;
        let seal_hash = header.hash()?;
        let confirmed = confirmed_transcript_hash(&self.header.interim, &seal_hash)?;
        let context = GroupContext {
            gid: self.header.gid,
            epoch: header.epoch,
            tree_hash: header.tree_hash,
            registry_hash: header.registry_hash,
            height: shape.height,
            district_bits: shape.district_bits,
            confirmed_transcript_hash: confirmed,
        };
        let commit = commit_secret(root)?;
        let epoch_secrets = EpochSecrets::derive(&init_prev, &commit, &context)?;
        if epoch_secrets.confirmation_tag(&confirmed)? != packet.tag {
            return Err(CoreError::Invalid("confirmation tag"));
        }
        let external_pk = epoch_secrets.external_key()?.public_key();
        if let Some(entrant) = &packet.entrant {
            // The external key is public: the tag alone does not show that the
            // window comes from an admitted entrant (E-7).
            let proof = SealProof {
                header: header.clone(),
                tag: packet.tag,
                external_pk: external_pk.clone(),
                signature: entrant.signature.clone(),
            };
            entrant.evidence.verify(&self.header, &proof)?;
        }
        path.set_secrets(secrets);
        if leaf_changed {
            self.pending_leaf = None;
        }
        let next = EpochHeader {
            gid: self.header.gid,
            epoch: header.epoch,
            shape,
            tree_hash: header.tree_hash,
            registry,
            interim: interim_transcript_hash(&confirmed, &packet.tag)?,
            external_pk,
        };
        self.previous = Some(core::mem::replace(&mut self.header, next));
        self.path = path;
        self.secrets = epoch_secrets;
        self.seal_hash = seal_hash;
        Ok(())
    }

    /// Request a new leaf key (post-compromise security): the next window
    /// re-keys the member's path and every node it taints.
    pub fn update_request(&mut self, rng: &mut impl CryptoRngCore) -> CoreResult<UpdateRequest> {
        let key = KemSecret::generate(rng);
        let request = UpdateRequest::sign(
            &self.header.gid,
            self.occupancy,
            self.path.leaf_public_key(),
            &key.public_key(),
            &self.identity,
            rng,
        )?;
        self.pending_leaf = Some(key);
        Ok(request)
    }

    /// Propose the removal of `target` (as an admin, or of oneself).
    pub fn remove_proposal(
        &self,
        target: Occupancy,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<RemoveProposal> {
        RemoveProposal::sign(
            &self.header.gid,
            target,
            self.occupancy,
            &self.identity,
            rng,
        )
    }

    fn require_admin(&self) -> CoreResult<()> {
        if self.is_admin() {
            Ok(())
        } else {
            Err(CoreError::Unauthorized("not an admin"))
        }
    }

    /// Admit the device `device_pk` (as an admin).
    pub fn admit(
        &self,
        device_pk: &[u8],
        not_after_epoch: u64,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Admission> {
        self.require_admin()?;
        let device = crate::objects::device_id(&self.header.gid, device_pk)?;
        Admission::by_admin(
            &self.header.gid,
            &device,
            not_after_epoch,
            self.occupancy,
            &self.identity,
            rng,
        )
    }

    /// Sign an invite for the key derived from `seed` (as an admin).
    pub fn invite(
        &self,
        seed: &[u8; 32],
        expires_at_ms: u64,
        max_uses: u64,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Invite> {
        self.require_admin()?;
        Invite::sign(
            &self.header.gid,
            seed,
            expires_at_ms,
            max_uses,
            self.occupancy,
            &self.identity,
            rng,
        )
    }

    /// Sign a group policy (as an admin): whether the group is open, and
    /// after how many epochs without a key update a member may be evicted.
    pub fn group_policy(
        &self,
        open: bool,
        max_idle_epochs: Option<u64>,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<GroupPolicy> {
        self.require_admin()?;
        GroupPolicy::sign(
            &self.header.gid,
            open,
            max_idle_epochs,
            self.occupancy,
            &self.identity,
            rng,
        )
    }

    /// Sign a checkpoint of the current epoch (as an admin).
    pub fn checkpoint(&self, time_ms: u64, rng: &mut impl CryptoRngCore) -> CoreResult<Checkpoint> {
        self.require_admin()?;
        let header = &self.header;
        Checkpoint::sign(
            &header.gid,
            &CheckpointContent {
                epoch: header.epoch,
                interim: header.interim,
                tree_hash: header.tree_hash,
                registry_hash: header.registry_hash()?,
                height: header.shape.height,
                district_bits: header.shape.district_bits,
                external_pk_hash: kem_pk_hash(&header.external_pk)?,
                time_ms,
            },
            self.occupancy,
            &self.identity,
            rng,
        )
    }

    /// Commit district `district` of the window `task` (E-3): check the
    /// state against the member's header, check the district's entries,
    /// re-key, sign, and erase what was drawn.
    pub fn commit_district(
        &self,
        state: &PublicState,
        task: &WindowTask,
        district: u32,
        requests: &Requests,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<DistrictCommit> {
        state.check_against(&self.header)?;
        if task.committers.get(&district) != Some(&self.occupancy) || task.entrant.is_some() {
            return Err(CoreError::Unauthorized("not the district's committer"));
        }
        let window = task.window(state)?;
        if window.affected.contains(&self.occupancy) {
            return Err(CoreError::Unauthorized("committer changed by its window"));
        }
        let (commit, drawn) = build_district(
            state,
            &window,
            district,
            requests,
            self.occupancy,
            &self.identity,
            self.secrets.init_secret(),
            rng,
        )?;
        drop(drawn);
        Ok(commit)
    }

    /// Seal the window `task` (E-1): check every district commit (signature,
    /// structure, taints), re-key the city, and sign the seal.
    pub fn seal(
        &self,
        state: &PublicState,
        task: &WindowTask,
        commits: &[DistrictCommit],
        requests: &Requests,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Seal> {
        state.check_against(&self.header)?;
        if task.sealer != self.occupancy || task.entrant.is_some() {
            return Err(CoreError::Unauthorized("not the window's sealer"));
        }
        let window = task.window(state)?;
        let sealer = check_sealer(
            state,
            &window,
            SealKind::Member,
            self.occupancy,
            None,
            requests,
        )?;
        let delta = check_districts(state, &window, commits, requests, &sealer, false)?;
        let roots = district_roots(window.shape, commits)?;
        let city = build_city(state, &window, &roots, self.secrets.init_secret(), rng)?;
        let root = window.shape.root();
        let root_secret = if let Some(secret) = city.secret(root) {
            secret.clone()
        } else if let ([commit], false) = (commits, window.shape.has_city()) {
            let mut index = WindowIndex::default();
            index.add(&commit.updates, &commit.wraps);
            let steps = index.steps(self.occupancy.leaf, window.shape.height)?;
            let secrets =
                self.path
                    .advance(window.shape.height, &steps, &state.gid, window.epoch)?;
            secrets
                .get(&window.shape.height)
                .ok_or(CoreError::Invalid("unknown root secret"))?
                .clone()
        } else if commits.is_empty() && window.shape == self.header.shape {
            self.path
                .secret(window.shape.height)
                .ok_or(CoreError::Invalid("unknown root secret"))?
                .clone()
        } else {
            return Err(CoreError::Invalid("window without a new root"));
        };
        let sealed = finish_seal(
            SealDraft {
                state,
                window: &window,
                commits,
                requests,
                sealer: &sealer,
                entrant: None,
                delta: with_city(delta, &city, self.occupancy),
                city: &city,
                policy: task.policy()?,
                time_ms: task.time_ms,
                init_prev: self.secrets.init_secret(),
                root_secret: &root_secret,
            },
            &self.identity,
            rng,
        )?;
        drop(city);
        Ok(sealed.seal)
    }

    /// Seal the welcomes the window owes and assigned to this member (E-6),
    /// once the member follows the window. A join or a re-entry is welcomed
    /// only if it is in a district commit of this member that the seal
    /// lists; a catch-up only if its member is still in the group and signed
    /// it for this window.
    #[allow(clippy::too_many_arguments)]
    pub fn welcomes(
        &self,
        state: &PublicState,
        seal: &Seal,
        commits: &[DistrictCommit],
        task: &WindowTask,
        requests: &Requests,
        catch_ups: &CatchUps,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Vec<Welcome>> {
        if seal.header.hash()? != self.seal_hash || seal.body.hash()? != seal.header.body_hash {
            return Err(CoreError::Invalid("seal of another epoch"));
        }
        state.check_against(&self.header)?;
        let mut welcomes = Vec::new();
        for welcome in task
            .welcomes
            .iter()
            .filter(|w| w.welcomer == self.occupancy)
        {
            let init_key = match welcome.kind {
                WelcomeKind::CatchUp => {
                    let request = catch_ups
                        .get(&welcome.request)
                        .filter(|request| request.reference() == welcome.request)
                        .ok_or(CoreError::Invalid("missing catch-up request"))?;
                    let device_pk = state
                        .device_pk(request.member)
                        .ok_or(CoreError::Invalid("catch-up of a non-member"))?;
                    request.verify(&self.header.gid, &seal.header.prev_interim, device_pk)?;
                    request.init_key.as_slice()
                }
                WelcomeKind::Join | WelcomeKind::ReEntry => {
                    let listed = commits.iter().any(|commit| {
                        commit.committer == self.occupancy
                            && commit.changes.iter().any(|c| c.request == welcome.request)
                            && seal
                                .body
                                .districts
                                .contains(&(commit.district, commit.hash()))
                    });
                    if !listed {
                        return Err(CoreError::Invalid("welcome for an entry not committed"));
                    }
                    match (welcome.kind, requests.get(&welcome.request)) {
                        (WelcomeKind::Join, Some(Request::Join(join))) => join.init_key.as_slice(),
                        (WelcomeKind::ReEntry, Some(Request::ReEntry(re_entry))) => {
                            re_entry.init_key.as_slice()
                        }
                        _ => return Err(CoreError::Invalid("missing request to welcome")),
                    }
                }
            };
            welcomes.push(Welcome::seal(
                &self.header.gid,
                self.header.epoch,
                &welcome.request,
                init_key,
                self.secrets.joiner_secret(),
                rng,
            )?);
        }
        Ok(welcomes)
    }

    /// Whether the member may send in its epoch: not while a removal older
    /// than `window_removal_ms` waits (E-7).
    #[must_use]
    pub fn may_send(
        &self,
        pending: &[PendingRemoval],
        now_ms: u64,
        window_removal_ms: u64,
    ) -> bool {
        !pending
            .iter()
            .any(|removal| now_ms.saturating_sub(removal.recorded_ms) > window_removal_ms)
    }

    /// Ask to jump to the present (E-8): a welcome into the window that
    /// follows the epoch whose interim transcript hash is `current_interim`.
    pub fn catch_up(
        self,
        current_interim: &Digest,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<(Returning, CatchUpRequest)> {
        let init_key = KemSecret::generate(rng);
        let request = CatchUpRequest::sign(
            &self.header.gid,
            self.occupancy,
            current_interim,
            &init_key.public_key(),
            &self.identity,
            rng,
        )?;
        let returning = Returning {
            leaf_key: self.path_leaf_key(),
            identity: self.identity,
            occupancy: self.occupancy,
            init_key,
            request: request.reference(),
            anchor: self.header,
            re_entry: false,
        };
        Ok((returning, request))
    }

    /// Ask to re-enter the member's leaf with a new leaf key (E-8), to be
    /// welcomed by a member or to seal the window itself.
    pub fn re_enter(self, rng: &mut impl CryptoRngCore) -> CoreResult<(Returning, ReEntryRequest)> {
        let leaf_key = KemSecret::generate(rng);
        let init_key = KemSecret::generate(rng);
        let request = ReEntryRequest::sign(
            &self.header.gid,
            self.occupancy,
            self.path.leaf_public_key(),
            &leaf_key.public_key(),
            &init_key.public_key(),
            &self.identity,
            rng,
        )?;
        let returning = Returning {
            identity: self.identity,
            occupancy: self.occupancy,
            leaf_key,
            init_key,
            request: request.reference(),
            anchor: self.header,
            re_entry: true,
        };
        Ok((returning, request))
    }

    fn path_leaf_key(&self) -> KemSecret {
        self.path.leaf_key().clone()
    }
}

/// What an entrant produced when it sealed a window.
pub struct EntrantSealed {
    pub commits: Vec<DistrictCommit>,
    pub seal: Seal,
    pub welcomes: Vec<Welcome>,
    pub member: Member,
}

impl core::fmt::Debug for EntrantSealed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EntrantSealed")
            .field("commits", &self.commits.len())
            .field("welcomes", &self.welcomes.len())
            .finish_non_exhaustive()
    }
}

/// A device that asked to join.
pub struct Joiner {
    identity: DeviceIdentity,
    leaf_key: KemSecret,
    init_key: KemSecret,
    request: JoinRequest,
    anchor: EpochHeader,
}

impl core::fmt::Debug for Joiner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Joiner")
            .field("anchor_epoch", &self.anchor.epoch)
            .finish_non_exhaustive()
    }
}

impl Joiner {
    /// A joiner anchored on `anchor` (a checkpointed epoch, E-10), with an
    /// admission, or without one for an open group. Its request may enter
    /// until epoch `not_after_epoch`.
    pub fn new(
        identity: DeviceIdentity,
        admission: Option<&Admission>,
        not_after_epoch: u64,
        anchor: EpochHeader,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<Self> {
        let leaf_key = KemSecret::generate(rng);
        let init_key = KemSecret::generate(rng);
        let request = JoinRequest::sign(
            &anchor.gid,
            &identity,
            &leaf_key.public_key(),
            &init_key.public_key(),
            not_after_epoch,
            admission,
            rng,
        )?;
        Ok(Self {
            identity,
            leaf_key,
            init_key,
            request,
            anchor,
        })
    }

    /// The join request.
    #[must_use]
    pub const fn request(&self) -> &JoinRequest {
        &self.request
    }

    /// The epoch the joiner has checked up to.
    #[must_use]
    pub const fn anchor(&self) -> &EpochHeader {
        &self.anchor
    }

    /// Check the chain of seals from the anchor forward.
    pub fn follow(&mut self, links: &[SealLink]) -> CoreResult<()> {
        self.anchor = follow_all(&self.anchor, links)?;
        Ok(())
    }

    /// Enter the epoch a member sealed, with its welcome.
    pub fn enter(self, entry: &Entry) -> CoreResult<Member> {
        let last = entry
            .links
            .last()
            .ok_or(CoreError::Invalid("entry without a seal"))?;
        let occupancy = Occupancy {
            leaf: entry.leaf.index,
            since: last.proof.header.epoch,
        };
        let expected = self.leaf_key.public_key();
        let admission_hash = self.request.token();
        enter_with(
            EnterInput {
                identity: self.identity,
                occupancy,
                leaf_key: self.leaf_key,
                init_key: &self.init_key,
                request: self.request.reference(),
                anchor: &self.anchor,
                entry,
            },
            |leaf| leaf.encryption_key == expected && leaf.admission_hash == admission_hash,
        )
    }

    /// Seal the window as its entrant (nobody online): commit every district,
    /// seal with an external init, and welcome the others.
    pub fn seal_window(
        self,
        state: &PublicState,
        task: &WindowTask,
        requests: &Requests,
        catch_ups: &CatchUps,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<EntrantSealed> {
        let reference = self.request.reference();
        let leaf = task
            .changes
            .iter()
            .find(|change| change.request == reference)
            .ok_or(CoreError::Invalid("join not in the window"))?
            .leaf;
        seal_as_entrant(
            EntrantInput {
                identity: self.identity,
                occupancy: Occupancy {
                    leaf,
                    since: task.epoch,
                },
                leaf_key: self.leaf_key,
                request: reference,
                anchor: &self.anchor,
            },
            state,
            task,
            requests,
            catch_ups,
            rng,
        )
    }
}

/// A member coming back after an absence (E-8).
pub struct Returning {
    identity: DeviceIdentity,
    occupancy: Occupancy,
    leaf_key: KemSecret,
    init_key: KemSecret,
    request: Digest,
    anchor: EpochHeader,
    re_entry: bool,
}

impl core::fmt::Debug for Returning {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Returning")
            .field("occupancy", &self.occupancy)
            .field("anchor_epoch", &self.anchor.epoch)
            .field("re_entry", &self.re_entry)
            .finish_non_exhaustive()
    }
}

impl Returning {
    /// The member's occupancy.
    #[must_use]
    pub const fn occupancy(&self) -> Occupancy {
        self.occupancy
    }

    /// The epoch the member has checked up to.
    #[must_use]
    pub const fn anchor(&self) -> &EpochHeader {
        &self.anchor
    }

    /// Check the chain of seals from the anchor forward.
    pub fn follow(&mut self, links: &[SealLink]) -> CoreResult<()> {
        self.anchor = follow_all(&self.anchor, links)?;
        Ok(())
    }

    /// Enter the present with a welcome: a jump (the leaf key is unchanged)
    /// or a re-entry a member sealed (the new leaf key).
    pub fn enter(self, entry: &Entry) -> CoreResult<Member> {
        let expected = self.leaf_key.public_key();
        let re_entry = self.re_entry;
        let entry_epoch = entry
            .links
            .last()
            .ok_or(CoreError::Invalid("entry without a seal"))?
            .proof
            .header
            .epoch;
        enter_with(
            EnterInput {
                identity: self.identity,
                occupancy: self.occupancy,
                leaf_key: self.leaf_key,
                init_key: &self.init_key,
                request: self.request,
                anchor: &self.anchor,
                entry,
            },
            |leaf| leaf.encryption_key == expected && (!re_entry || leaf.updated == entry_epoch),
        )
    }

    /// Seal the window as its entrant (a re-entry with nobody online).
    pub fn seal_window(
        self,
        state: &PublicState,
        task: &WindowTask,
        requests: &Requests,
        catch_ups: &CatchUps,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<EntrantSealed> {
        if !self.re_entry {
            return Err(CoreError::Invalid("a jump does not seal"));
        }
        seal_as_entrant(
            EntrantInput {
                identity: self.identity,
                occupancy: self.occupancy,
                leaf_key: self.leaf_key,
                request: self.request,
                anchor: &self.anchor,
            },
            state,
            task,
            requests,
            catch_ups,
            rng,
        )
    }
}

fn follow_all(anchor: &EpochHeader, links: &[SealLink]) -> CoreResult<EpochHeader> {
    let mut header = anchor.clone();
    for link in links {
        header = header.follow(link)?;
    }
    Ok(header)
}

struct EnterInput<'a> {
    identity: DeviceIdentity,
    occupancy: Occupancy,
    leaf_key: KemSecret,
    init_key: &'a KemSecret,
    request: Digest,
    anchor: &'a EpochHeader,
    entry: &'a Entry,
}

fn enter_with(
    input: EnterInput<'_>,
    expected_leaf: impl Fn(&crate::tree::LeafNode) -> bool,
) -> CoreResult<Member> {
    let entry = input.entry;
    let (last, before) = entry
        .links
        .split_last()
        .ok_or(CoreError::Invalid("entry without a seal"))?;
    let previous = follow_all(input.anchor, before)?;
    let header = previous.follow(last)?;
    entry.leaf.verify(&header.tree_hash)?;
    let leaf = entry
        .leaf
        .leaf
        .as_ref()
        .ok_or(CoreError::Invalid("entry leaf"))?;
    if entry.leaf.occupancy() != Some(input.occupancy)
        || leaf.device_pk != input.identity.public_key()
        || !expected_leaf(leaf)
    {
        return Err(CoreError::Invalid("entry leaf"));
    }
    entry.leaf.check_path(&entry.nodes)?;
    let mut path = MemberPath::new(input.occupancy.leaf, input.leaf_key);
    let secrets = path.recover(header.shape.height, &entry.steps, &header.gid)?;
    MemberPath::check_keys(&secrets, &entry.nodes)?;
    let welcome = &entry.welcome;
    if welcome.gid != header.gid
        || welcome.epoch != header.epoch
        || welcome.request != input.request
    {
        return Err(CoreError::Invalid("welcome for another entry"));
    }
    let joiner = welcome.open(input.init_key)?;
    let secrets_of_epoch = EpochSecrets::from_joiner_secret(&joiner)?;
    let seal_hash = last.proof.header.hash()?;
    let confirmed = confirmed_transcript_hash(&previous.interim, &seal_hash)?;
    if secrets_of_epoch.confirmation_tag(&confirmed)? != last.proof.tag
        || secrets_of_epoch.external_key()?.public_key() != last.proof.external_pk
    {
        return Err(CoreError::Invalid("welcome does not match the seal"));
    }
    path.set_secrets(secrets);
    Ok(Member {
        identity: input.identity,
        occupancy: input.occupancy,
        path,
        header,
        previous: Some(previous),
        seal_hash,
        secrets: secrets_of_epoch,
        pending_leaf: None,
    })
}

struct EntrantInput<'a> {
    identity: DeviceIdentity,
    occupancy: Occupancy,
    leaf_key: KemSecret,
    request: Digest,
    anchor: &'a EpochHeader,
}

fn seal_as_entrant(
    input: EntrantInput<'_>,
    state: &PublicState,
    task: &WindowTask,
    requests: &Requests,
    catch_ups: &CatchUps,
    rng: &mut impl CryptoRngCore,
) -> CoreResult<EntrantSealed> {
    state.check_against(input.anchor)?;
    if task.entrant != Some(input.request)
        || task.sealer != input.occupancy
        || task
            .committers
            .values()
            .any(|committer| *committer != input.occupancy)
        || task.welcomes.iter().any(|w| w.welcomer != input.occupancy)
    {
        return Err(CoreError::Invalid("entrant task"));
    }
    let window = task.window(state)?;
    let sealer = check_sealer(
        state,
        &window,
        SealKind::Entrant,
        input.occupancy,
        Some(&input.request),
        requests,
    )?;
    let (kem_output, init_prev) = external_init(&state.external_pk, rng)?;
    let mut commits = Vec::with_capacity(window.districts.len());
    let mut path: BTreeMap<u8, Secret> = BTreeMap::new();
    for district in &window.districts {
        let (commit, drawn) = build_district(
            state,
            &window,
            *district,
            requests,
            input.occupancy,
            &input.identity,
            &init_prev,
            rng,
        )?;
        path.extend(drawn.path_secrets(input.occupancy.leaf));
        commits.push(commit);
    }
    let delta = check_districts(state, &window, &commits, requests, &sealer, false)?;
    let roots = district_roots(window.shape, &commits)?;
    let city = build_city(state, &window, &roots, &init_prev, rng)?;
    path.extend(city.path_secrets(input.occupancy.leaf));
    let root_secret = path
        .get(&window.shape.height)
        .ok_or(CoreError::Invalid("entrant without the root"))?
        .clone();
    let sealed = finish_seal(
        SealDraft {
            state,
            window: &window,
            commits: &commits,
            requests,
            sealer: &sealer,
            entrant: Some(EntrantInit {
                kem_output,
                request: input.request,
            }),
            delta: with_city(delta, &city, input.occupancy),
            city: &city,
            policy: task.policy()?,
            time_ms: task.time_ms,
            init_prev: &init_prev,
            root_secret: &root_secret,
        },
        &input.identity,
        rng,
    )?;
    drop(city);
    let mut welcomes = Vec::new();
    for welcome in &task.welcomes {
        if welcome.request == input.request {
            continue;
        }
        let init_key = match (welcome.kind, requests.get(&welcome.request)) {
            (WelcomeKind::Join, Some(Request::Join(join))) => join.init_key.as_slice(),
            (WelcomeKind::ReEntry, Some(Request::ReEntry(re_entry))) => {
                re_entry.init_key.as_slice()
            }
            (WelcomeKind::CatchUp, _) => {
                let request = catch_ups
                    .get(&welcome.request)
                    .filter(|request| request.reference() == welcome.request)
                    .ok_or(CoreError::Invalid("missing catch-up request"))?;
                if window.removed.contains(&request.member) {
                    return Err(CoreError::Invalid("catch-up of a removed member"));
                }
                let device_pk = state
                    .device_pk(request.member)
                    .ok_or(CoreError::Invalid("catch-up of a non-member"))?;
                request.verify(&state.gid, &state.interim, device_pk)?;
                request.init_key.as_slice()
            }
            _ => return Err(CoreError::Invalid("missing request to welcome")),
        };
        if matches!(welcome.kind, WelcomeKind::Join | WelcomeKind::ReEntry)
            && !window
                .all_changes()
                .any(|change| change.request == welcome.request)
        {
            return Err(CoreError::Invalid("welcome for an entry not in the window"));
        }
        welcomes.push(Welcome::seal(
            &state.gid,
            window.epoch,
            &welcome.request,
            init_key,
            sealed.secrets.joiner_secret(),
            rng,
        )?);
    }
    let mut member_path = MemberPath::new(input.occupancy.leaf, input.leaf_key);
    member_path.set_secrets(path);
    let seal_hash = sealed.seal.header.hash()?;
    let member = Member {
        identity: input.identity,
        occupancy: input.occupancy,
        path: member_path,
        header: sealed.header,
        previous: Some(input.anchor.clone()),
        seal_hash,
        secrets: sealed.secrets,
        pending_leaf: None,
    };
    Ok(EntrantSealed {
        commits,
        seal: sealed.seal,
        welcomes,
        member,
    })
}
