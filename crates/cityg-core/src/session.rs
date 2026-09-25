//! Member state machine.
//!
//! A [`GroupSession`] holds everything one device knows about one group at
//! its current epoch: the public state, its private tree keys, the secrets
//! it keeps for the epoch and the message ratchets of the current epoch and
//! of up to [`MAX_GRACE_EPOCHS`] previous ones. It performs no I/O: the
//! application publishes the commits it builds, feeds it the commits and
//! envelopes the delivery service relays, in log order, and persists
//! [`GroupSession::export`] under its own at-rest protection.
//!
//! Commits built by this member become effective only once the delivery
//! service accepted them: [`GroupSession::commit`] returns a
//! [`PendingCommit`] that [`GroupSession::apply_own_commit`] installs after
//! acceptance, and that is dropped if another commit won the epoch.
//!
//! A device enters a group in one of three ways: it creates it
//! ([`GroupSession::create`]); it publishes a join request
//! ([`GroupSession::request_join`]) that some commit includes, and opens its
//! welcome ([`GroupSession::join_with_welcome`]); or it authors an external
//! commit ([`GroupSession::join_external`]), which may bring the other
//! pending join requests along.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use ciborium::value::Value;
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::admission::{Invite, SignedAdmission, SignedInvite, SignedInviteRevocation};
use crate::cbor::{
    array, bytes, decode, encode, expect_array, expect_bytes, expect_bytes32, expect_label,
    expect_list, expect_u32, expect_uint, text, uint,
};
use crate::commit::{AdminChange, Commit, CommitContent, CommitKind, max_commit_bytes};
use crate::cover::{CoverFailureReason, CoverFailureReport};
use crate::error::{CoreError, CoreResult};
use crate::group_info::{GroupInfo, SignedGroupInfo};
use crate::hash::{Digest, ZERO32, digest_eq};
use crate::identity::{DeviceIdentity, device_id, group_id};
use crate::join::{JoinSecrets, SignedJoinRequest, Welcome};
use crate::kem::{KEM_SEED_BYTES, KemSecret};
use crate::key_schedule::{
    EpochSecrets, GroupContext, RetainedEpochSecrets, confirmed_transcript_hash, external_init,
    joiner_secret,
};
use crate::light::LightSession;
use crate::message::{Envelope, EpochMessages, MAX_GRACE_EPOCHS, ReceivedMessage};
use crate::proposal::{RemoveProposal, SignedRemoveProposal};
use crate::registry::Registry;
use crate::state::{
    CommitTransition, MemberChange, ProposedChanges, PublicGroupState, StagedChanges,
    plan_entry_leaf, stage_changes, stage_genesis, verify_commit, verify_genesis,
};
use crate::tree::{
    MemberRef, PathContext, PrivatePath, PublicTree, decrypt_update_path,
    generate_update_path_from_leaf_secret, leaf_key_from_secret, new_leaf_secret, next,
};

/// Label of an exported session.
const SESSION_LABEL: &str = "city-g/session/v3";

/// A commit ready to be published: the commit, the GroupInfo of the epoch
/// it creates and one welcome per join request it includes, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedCommit {
    pub epoch: u64,
    pub commit: Vec<u8>,
    pub group_info: Vec<u8>,
    pub welcomes: Vec<Vec<u8>>,
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

/// What the delivery service gives a joiner or a resyncing member: the
/// GroupInfo, tree and registry of one epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupSnapshot {
    pub group_info: Vec<u8>,
    pub tree: Vec<u8>,
    pub registry: Vec<u8>,
}

/// Verify a snapshot: tree and registry match the GroupContext the
/// GroupInfo states, and the GroupInfo signer is a member.
pub fn verify_snapshot(snapshot: &GroupSnapshot) -> CoreResult<(PublicGroupState, GroupInfo)> {
    let signed = SignedGroupInfo::decode_unverified(&snapshot.group_info)?;
    let info = signed.info().clone();
    let context = &info.group_context;
    let tree = PublicTree::from_cbor(&snapshot.tree)?;
    let registry = Registry::from_cbor(&snapshot.registry)?;
    signed.verify(&tree, &registry)?;
    let state = PublicGroupState {
        gid: context.gid,
        epoch: context.epoch,
        tree,
        registry,
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
    /// Occupancy of the author in the new epoch.
    pub author: MemberRef,
    /// Device key that signed the commit.
    pub author_device_pk: Vec<u8>,
    pub removed: Vec<MemberChange>,
    /// Occupancy started by the author (external join, resync).
    pub author_entry: Option<MemberChange>,
    /// Occupancies started by join requests, in order.
    pub joined: Vec<MemberChange>,
    pub admin_changes: Vec<AdminChange>,
    pub promoted_admin: Option<u32>,
    /// New device key of the author, when the commit rotated it.
    pub rotated_device_pk: Option<Vec<u8>>,
}

impl CommitSummary {
    fn from_transition(transition: &CommitTransition) -> Self {
        Self::from_staged(
            &transition.commit.content,
            &transition.staged,
            transition.author(),
        )
    }

    /// Summary of `content` once staged as `staged`; `author` is the
    /// author's occupancy in the new epoch.
    pub(crate) fn from_staged<T>(
        content: &CommitContent,
        staged: &StagedChanges<T>,
        author: MemberRef,
    ) -> Self {
        Self {
            epoch: content.epoch,
            kind: content.kind,
            author,
            author_device_pk: content.author_device_pk.clone(),
            removed: staged.removed.clone(),
            author_entry: staged.author_entry.clone(),
            joined: staged.joined.clone(),
            admin_changes: content.admin_changes.clone(),
            promoted_admin: staged.promoted_admin,
            rotated_device_pk: content.new_device_pk.clone(),
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

/// What a member commit does besides re-keying the author's path.
#[derive(Clone, Copy, Debug, Default)]
pub struct CommitOptions<'a> {
    /// Removal proposals to commit (recorded ones and any this member adds).
    pub removals: &'a [SignedRemoveProposal],
    /// Join requests to commit, in order.
    pub joins: &'a [SignedJoinRequest],
    /// Admin changes (admins only).
    pub admin_changes: &'a [AdminChange],
    /// New device key of this member: the commit rotates it.
    pub new_identity: Option<&'a DeviceIdentity>,
}

/// Keys of an epoch that ended, kept for late messages.
#[derive(Clone, Debug)]
pub(crate) struct PreviousEpoch {
    pub(crate) messages: EpochMessages,
    /// Device keys members of that epoch held then and rotated since.
    pub(crate) rotated_keys: BTreeMap<MemberRef, Vec<u8>>,
}

/// The previous epochs to keep once `current` ends: `current` in front, at
/// most [`MAX_GRACE_EPOCHS`]. `rotated` names the member whose device key
/// the next epoch changes, with its old key.
pub(crate) fn retire_epoch(
    previous: &VecDeque<PreviousEpoch>,
    current: &EpochMessages,
    rotated: Option<(MemberRef, &[u8])>,
) -> VecDeque<PreviousEpoch> {
    let mut previous = previous.clone();
    previous.push_front(PreviousEpoch {
        messages: current.clone(),
        rotated_keys: BTreeMap::new(),
    });
    previous.truncate(MAX_GRACE_EPOCHS);
    if let Some((member, old_key)) = rotated {
        for epoch in &mut previous {
            if epoch.messages.has_sender(member) {
                epoch
                    .rotated_keys
                    .entry(member)
                    .or_insert_with(|| old_key.to_vec());
            }
        }
    }
    previous
}

/// Open `envelope` with the keys of the current epoch or of a previous one;
/// `current_key` is the sender's device key now (the key it held in a
/// previous epoch if it rotated since is recorded there).
pub(crate) fn open_envelope(
    messages: &mut EpochMessages,
    previous: &mut VecDeque<PreviousEpoch>,
    envelope: &Envelope,
    current_key: &[u8],
) -> CoreResult<ReceivedMessage> {
    if digest_eq(&envelope.header.epoch_ref, messages.epoch_ref()) {
        return messages.decrypt(envelope, current_key);
    }
    let previous = previous
        .iter_mut()
        .find(|previous| digest_eq(&envelope.header.epoch_ref, previous.messages.epoch_ref()))
        .ok_or(CoreError::Invalid("message for an epoch without keys"))?;
    let key = previous
        .rotated_keys
        .get(&envelope.header.sender)
        .map_or(current_key, Vec::as_slice)
        .to_vec();
    previous.messages.decrypt(envelope, &key)
}

/// Encoding of the previous epochs of a session.
pub(crate) fn previous_to_value(previous: &VecDeque<PreviousEpoch>) -> Value {
    array(
        previous
            .iter()
            .map(|previous| {
                array(vec![
                    previous.messages.to_value(),
                    array(
                        previous
                            .rotated_keys
                            .iter()
                            .map(|(member, key)| array(vec![member.to_value(), bytes(key)]))
                            .collect(),
                    ),
                ])
            })
            .collect(),
    )
}

/// Decode [`previous_to_value`].
pub(crate) fn previous_from_value(value: Value) -> CoreResult<VecDeque<PreviousEpoch>> {
    let mut previous = VecDeque::new();
    for entry in expect_list(value, "session previous")? {
        let mut fields = expect_array(entry, 2, "session previous")?.into_iter();
        let messages = EpochMessages::from_value(next(&mut fields, "session previous")?)?;
        let mut rotated_keys = BTreeMap::new();
        for rotated in expect_list(next(&mut fields, "session previous")?, "rotated keys")? {
            let mut pair = expect_array(rotated, 2, "rotated key")?.into_iter();
            let member = MemberRef::from_value(next(&mut pair, "rotated key")?)?;
            let key = expect_bytes(next(&mut pair, "rotated key")?, "rotated key")?;
            rotated_keys.insert(member, key);
        }
        previous.push_back(PreviousEpoch {
            messages,
            rotated_keys,
        });
    }
    if previous.len() > MAX_GRACE_EPOCHS {
        return Err(CoreError::Malformed("session previous epochs"));
    }
    Ok(previous)
}

/// Encoding of a member's private keys: `[leaf seed or null, [[node, seed], ...]]`.
pub(crate) fn private_to_values(private: &PrivatePath) -> (Value, Value) {
    (
        private
            .leaf
            .as_ref()
            .map_or(Value::Null, |leaf| bytes(leaf.seed())),
        array(
            private
                .nodes
                .iter()
                .map(|(node, key)| array(vec![uint(u64::from(*node)), bytes(key.seed())]))
                .collect(),
        ),
    )
}

/// Decode [`private_to_values`].
pub(crate) fn private_from_values(leaf: Value, nodes: Value) -> CoreResult<PrivatePath> {
    let seed = |value: Value, what: &'static str| -> CoreResult<KemSecret> {
        let seed: [u8; KEM_SEED_BYTES] = expect_bytes(value, what)?
            .try_into()
            .map_err(|_| CoreError::Malformed(what))?;
        Ok(KemSecret::from_seed(seed))
    };
    let leaf = match leaf {
        Value::Null => None,
        value => Some(seed(value, "session leaf key")?),
    };
    let mut keys = BTreeMap::new();
    for entry in expect_list(nodes, "session nodes")? {
        let mut fields = expect_array(entry, 2, "session node")?.into_iter();
        let node = expect_u32(&next(&mut fields, "session node")?, "session node")?;
        keys.insert(node, seed(next(&mut fields, "session node")?, "node key")?);
    }
    Ok(PrivatePath { leaf, nodes: keys })
}

struct Plan<'a> {
    kind: CommitKind,
    prev: Option<&'a PublicGroupState>,
    prev_init_secret: Zeroizing<[u8; 32]>,
    external_init: Option<Vec<u8>>,
    author_leaf: u32,
    removals: Vec<SignedRemoveProposal>,
    joins: Vec<SignedJoinRequest>,
    admin_changes: Vec<AdminChange>,
    admission: Option<SignedAdmission>,
    new_identity: Option<&'a DeviceIdentity>,
    genesis: Option<(Digest, u32)>,
}

/// One device's state in one group.
#[derive(Clone)]
pub struct GroupSession {
    state: PublicGroupState,
    group_context: GroupContext,
    me: MemberRef,
    private: PrivatePath,
    secrets: RetainedEpochSecrets,
    messages: EpochMessages,
    previous: VecDeque<PreviousEpoch>,
    blocked: BTreeSet<MemberRef>,
    last_own_update_epoch: u64,
}

impl core::fmt::Debug for GroupSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GroupSession")
            .field("epoch", &self.state.epoch)
            .field("leaf", &self.me.leaf)
            .field("members", &self.state.tree.member_count())
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
        (Some((nonce, capacity)), None) => {
            let gid = group_id(author_device_pk, &nonce)?;
            let staged = stage_genesis(capacity, author_device_pk, &leaf_public_key)?;
            (gid, 0, staged, ZERO32)
        }
        (None, Some(prev)) => {
            let staged = stage_changes(
                prev,
                &ProposedChanges {
                    kind: plan.kind,
                    author_leaf: plan.author_leaf,
                    author_device_pk,
                    removals: &plan.removals,
                    joins: &plan.joins,
                    admin_changes: &plan.admin_changes,
                    admission: plan.admission.as_ref(),
                    new_device_pk: plan.new_identity.map(DeviceIdentity::public_key),
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
    let path_context = PathContext {
        gid,
        epoch,
        author_leaf: staged.author_leaf,
    };
    let (update_path, path_secrets) =
        generate_update_path_from_leaf_secret(&staged.tree, &path_context, &leaf_secret, rng)?;
    let mut tree = staged.tree.clone();
    tree.apply_update_path(staged.author_leaf, &update_path)?;
    let content = CommitContent {
        gid,
        epoch,
        kind: plan.kind,
        prev_interim_transcript_hash: prev_interim,
        author_leaf: staged.author_leaf,
        author_device_pk: author_device_pk.to_vec(),
        tree_hash: tree.tree_hash()?,
        registry_hash: staged.registry.registry_hash()?,
        update_path,
        removals: plan.removals,
        joins: plan.joins,
        admin_changes: plan.admin_changes,
        admission: plan.admission,
        external_init: plan.external_init,
        group_nonce: plan.genesis.map(|(nonce, _)| nonce),
        capacity: plan.genesis.map(|(_, capacity)| capacity),
        new_device_pk: plan
            .new_identity
            .map(|identity| identity.public_key().to_vec()),
    };
    let anchor_tbs = content.tbs()?;
    let signature = content.sign(identity, rng)?;
    let rotation_signature = plan
        .new_identity
        .map(|new_identity| content.sign_rotation(new_identity, rng))
        .transpose()?;
    let confirmed = confirmed_transcript_hash(
        &prev_interim,
        &anchor_tbs,
        &signature,
        rotation_signature.as_deref(),
    )?;
    let context = GroupContext {
        gid,
        epoch,
        tree_hash: content.tree_hash,
        registry_hash: content.registry_hash,
        confirmed_transcript_hash: confirmed,
    };
    let joiner = joiner_secret(
        &plan.prev_init_secret,
        &path_secrets.commit_secret,
        &context,
    )?;
    let secrets = EpochSecrets::from_joiner_secret(&joiner)?;
    let confirmation_tag = secrets.confirmation_tag(&confirmed)?;
    let welcomes = content
        .joins
        .iter()
        .map(|request| Welcome::seal(epoch, request, &joiner, rng)?.encode())
        .collect::<CoreResult<Vec<_>>>()?;
    let encoded = Commit {
        content,
        signature,
        rotation_signature,
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
    let signer = plan.new_identity.unwrap_or(identity);
    let group_info = GroupInfo {
        group_context: context,
        confirmation_tag,
        external_public_key: secrets.external_key()?.public_key(),
        signer_leaf: staged.author_leaf,
    }
    .sign(signer, rng)?;
    let me = transition.author();
    let mut session = GroupSession::activate(transition.next, &secrets, private, me)?;
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
            welcomes,
        },
    ))
}

impl GroupSession {
    fn activate(
        state: PublicGroupState,
        secrets: &EpochSecrets,
        mut private: PrivatePath,
        me: MemberRef,
    ) -> CoreResult<Self> {
        if state.tree.member_by_ref(me).is_none() {
            return Err(CoreError::Invalid("this device is not a member"));
        }
        private.retain_live(&state.tree);
        let messages = EpochMessages::new(
            &state.gid,
            state.epoch,
            secrets.msg_secret(),
            state.tree.member_refs(),
            me,
        )?;
        Ok(Self {
            group_context: state.group_context()?,
            state,
            me,
            private,
            secrets: secrets.retained(),
            messages,
            previous: VecDeque::new(),
            blocked: BTreeSet::new(),
            last_own_update_epoch: 0,
        })
    }

    /// Create a group of at most `capacity` members with this device as its
    /// first member and admin. The session is usable once the delivery
    /// service accepted the genesis commit ([`PendingCommit::into_session`]).
    pub fn create(
        identity: &DeviceIdentity,
        capacity: u32,
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
                author_leaf: 0,
                removals: Vec::new(),
                joins: Vec::new(),
                admin_changes: Vec::new(),
                admission: None,
                new_identity: None,
                genesis: Some((nonce, capacity)),
            },
            rng,
        )
    }

    /// Sign a join request of `identity` with `admission`. The joiner keeps
    /// the returned secrets until its welcome arrives.
    pub fn request_join(
        identity: &DeviceIdentity,
        admission: &SignedAdmission,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<(SignedJoinRequest, JoinSecrets)> {
        let secrets = JoinSecrets::generate(rng);
        let request = SignedJoinRequest::create(identity, &secrets, admission, rng)?;
        Ok((request, secrets))
    }

    /// Enter a group through the welcome of a commit that included this
    /// device's join request. `snapshot` describes the epoch the commit
    /// created, `commit` is that commit (its update path carries the path
    /// secrets this device decrypts with its leaf key), and `welcome` the
    /// joiner secret encrypted to its init key. The caller erases `secrets`
    /// afterwards.
    pub fn join_with_welcome(
        identity: &DeviceIdentity,
        secrets: &JoinSecrets,
        snapshot: &GroupSnapshot,
        commit: &[u8],
        welcome: &[u8],
    ) -> CoreResult<Self> {
        let (state, info) = verify_snapshot(snapshot)?;
        let welcome = Welcome::decode(welcome)?;
        if welcome.gid != state.gid || welcome.epoch != state.epoch {
            return Err(CoreError::Invalid("welcome for another epoch"));
        }
        let (commit, anchor_tbs) = Commit::decode(commit, max_commit_bytes(state.capacity()))?;
        let content = &commit.content;
        let confirmed = confirmed_transcript_hash(
            &content.prev_interim_transcript_hash,
            &anchor_tbs,
            &commit.signature,
            commit.rotation_signature.as_deref(),
        )?;
        if content.gid != state.gid
            || content.epoch != state.epoch
            || !digest_eq(&confirmed, &state.confirmed_transcript_hash)
            || !digest_eq(&commit.confirmation_tag, &info.confirmation_tag)
        {
            return Err(CoreError::Invalid(
                "commit does not create the snapshot epoch",
            ));
        }
        let requested = content
            .joins
            .iter()
            .find(|request| request.reference().ok() == Some(welcome.request_ref))
            .ok_or(CoreError::Invalid(
                "the commit does not include the request",
            ))?;
        if requested.device_pk != identity.public_key()
            || requested.encryption_key != secrets.encryption_key.public_key()
            || requested.init_key != secrets.init_key.public_key()
        {
            return Err(CoreError::Invalid("welcome for another request"));
        }
        let joiner = welcome.open(&secrets.init_key)?;
        let epoch_secrets = EpochSecrets::from_joiner_secret(&joiner)?;
        let tag = epoch_secrets.confirmation_tag(&state.confirmed_transcript_hash)?;
        if !digest_eq(&tag, &info.confirmation_tag) {
            return Err(CoreError::Invalid("confirmation tag"));
        }
        if info.external_public_key != epoch_secrets.external_key()?.public_key() {
            return Err(CoreError::Invalid("group info does not match the epoch"));
        }
        let leaf = state
            .tree
            .find_device(identity.public_key())
            .ok_or(CoreError::Invalid("this device is not a member"))?;
        let me = MemberRef {
            leaf,
            since: state.epoch,
        };
        if state
            .tree
            .member_by_ref(me)
            .map(|member| &member.encryption_key)
            != Some(&requested.encryption_key)
        {
            return Err(CoreError::Invalid(
                "welcomed leaf does not match the request",
            ));
        }
        let mut private = PrivatePath {
            leaf: Some(secrets.encryption_key.clone()),
            nodes: BTreeMap::new(),
        };
        let path_context = PathContext {
            gid: state.gid,
            epoch: state.epoch,
            author_leaf: content.author_leaf,
        };
        let path_secrets = decrypt_update_path(
            &state.tree,
            &path_context,
            &content.update_path,
            leaf,
            &private,
        )?;
        private.nodes.extend(path_secrets.node_keys);
        let epoch = state.epoch;
        let mut session = Self::activate(state, &epoch_secrets, private, me)?;
        session.last_own_update_epoch = epoch;
        Ok(session)
    }

    /// Join a group through an external commit, with `admission`. The
    /// commit includes `removals` (the recorded removal proposals) and
    /// `joins` (other pending join requests), whose authors receive a
    /// welcome.
    pub fn join_external(
        identity: &DeviceIdentity,
        snapshot: &GroupSnapshot,
        admission: SignedAdmission,
        removals: &[SignedRemoveProposal],
        joins: &[SignedJoinRequest],
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<(PendingCommit, PublishedCommit)> {
        let (prev, info) = verify_snapshot(snapshot)?;
        let removals = sorted_removals(removals);
        let author_leaf = plan_entry_leaf(&prev, &removals)?;
        let (kem_output, init) = external_init(&info.external_public_key, rng)?;
        build(
            identity,
            Plan {
                kind: CommitKind::ExternalJoin,
                prev: Some(&prev),
                prev_init_secret: init,
                external_init: Some(kem_output),
                author_leaf,
                removals,
                joins: joins.to_vec(),
                admin_changes: Vec::new(),
                admission: Some(admission),
                new_identity: None,
                genesis: None,
            },
            rng,
        )
    }

    /// Re-enter a group this device is a member of after losing its state or
    /// failing to process a commit (external commit starting a new occupancy
    /// of its own leaf). Like any commit it includes the recorded removals
    /// and pending join requests.
    pub fn resync(
        identity: &DeviceIdentity,
        snapshot: &GroupSnapshot,
        removals: &[SignedRemoveProposal],
        joins: &[SignedJoinRequest],
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<(PendingCommit, PublishedCommit)> {
        let (prev, info) = verify_snapshot(snapshot)?;
        let author_leaf = prev
            .tree
            .find_device(identity.public_key())
            .ok_or(CoreError::Unauthorized("resync by a non-member"))?;
        let (kem_output, init) = external_init(&info.external_public_key, rng)?;
        build(
            identity,
            Plan {
                kind: CommitKind::Resync,
                prev: Some(&prev),
                prev_init_secret: init,
                external_init: Some(kem_output),
                author_leaf,
                removals: sorted_removals(removals),
                joins: joins.to_vec(),
                admin_changes: Vec::new(),
                admission: None,
                new_identity: None,
                genesis: None,
            },
            rng,
        )
    }

    /// Build a member commit: re-key this member's path and apply `options`.
    /// When `options.new_identity` is set, the commit rotates this member's
    /// device key: once it is accepted, the application signs with the new
    /// identity.
    pub fn commit(
        &self,
        identity: &DeviceIdentity,
        options: CommitOptions<'_>,
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
                author_leaf: self.me.leaf,
                removals: sorted_removals(options.removals),
                joins: options.joins.to_vec(),
                admin_changes: options.admin_changes.to_vec(),
                admission: None,
                new_identity: options.new_identity,
                genesis: None,
            },
            rng,
        )
    }

    /// Install a commit built by this member once the delivery service
    /// accepted it. The keys of the epoch it replaces stay available for late
    /// messages until they expire.
    pub fn apply_own_commit(&mut self, pending: PendingCommit) -> CoreResult<()> {
        if pending.base_epoch != Some(self.state.epoch) || pending.gid() != self.gid() {
            return Err(CoreError::Invalid(
                "pending commit does not extend this epoch",
            ));
        }
        let mut next = *pending.session;
        let rotated = (next.state.tree.leaf(self.me.leaf).map(|m| &m.device_pk)
            != self.state.tree.leaf(self.me.leaf).map(|m| &m.device_pk))
        .then_some(self.me);
        next.previous = self.retire_current_epoch(rotated);
        next.blocked = self.blocked.clone();
        next.blocked
            .retain(|member| next.state.tree.member_by_ref(*member).is_some());
        *self = next;
        Ok(())
    }

    /// Keys of the current and previous epochs to keep once the next epoch
    /// is active; `rotated` names the member whose device key the new epoch
    /// changes.
    fn retire_current_epoch(&self, rotated: Option<MemberRef>) -> VecDeque<PreviousEpoch> {
        let rotated = rotated.and_then(|member| {
            self.state
                .tree
                .member_by_ref(member)
                .map(|old| (member, old.device_pk.as_slice()))
        });
        retire_epoch(&self.previous, &self.messages, rotated)
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
        if content.author_leaf == self.me.leaf && content.kind != CommitKind::ExternalJoin {
            return Err(CoreError::Invalid("own commit without its pending state"));
        }
        if transition
            .staged
            .removed
            .iter()
            .any(|member| member.member == self.me)
        {
            return Ok(ProcessedCommit::Removed(summary));
        }
        let path_secrets = decrypt_update_path(
            &transition.staged.tree,
            &transition.path_context,
            &content.update_path,
            self.me.leaf,
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
        let secrets = EpochSecrets::derive(
            &init,
            &path_secrets.commit_secret,
            &transition.group_context,
        )?;
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
            .direct_path(transition.path_context.author_leaf)?
        {
            private.nodes.remove(&node);
        }
        private.nodes.extend(path_secrets.node_keys);
        let rotated = content.new_device_pk.as_ref().map(|_| summary.author);
        let mut next = Self::activate(transition.next, &secrets, private, self.me)?;
        next.last_own_update_epoch = self.last_own_update_epoch;
        next.previous = self.retire_current_epoch(rotated);
        next.blocked = self.blocked.clone();
        next.blocked
            .retain(|member| next.state.tree.member_by_ref(*member).is_some());
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

    /// Decrypt and authenticate an envelope of the current epoch or of a
    /// previous epoch whose keys are still held. The sender must be a
    /// member of the current epoch (the same occupancy) without a recorded
    /// removal.
    pub fn decrypt(&mut self, envelope: &[u8]) -> CoreResult<ReceivedMessage> {
        let envelope = Envelope::decode(envelope)?;
        let sender = envelope.header.sender;
        let current_key = self
            .state
            .tree
            .member_by_ref(sender)
            .map(|member| member.device_pk.clone())
            .ok_or(CoreError::Unauthorized("sender is not a member"))?;
        if self.blocked.contains(&sender) {
            return Err(CoreError::Unauthorized("sender has a pending removal"));
        }
        open_envelope(
            &mut self.messages,
            &mut self.previous,
            &envelope,
            &current_key,
        )
    }

    /// Erase the keys of every previous epoch up to `epoch` (end of their
    /// grace window).
    pub fn expire_epochs_through(&mut self, epoch: u64) {
        self.previous
            .retain(|previous| previous.messages.epoch() > epoch);
    }

    /// Erase the keys of every previous epoch.
    pub fn expire_previous_epochs(&mut self) {
        self.previous.clear();
    }

    /// Previous epochs whose keys are still held, newest first.
    pub fn previous_epochs(&self) -> impl Iterator<Item = u64> + '_ {
        self.previous
            .iter()
            .map(|previous| previous.messages.epoch())
    }

    /// Record the removal proposals the delivery service holds: messages
    /// from their targets are rejected from now on (P-3.c). Proposals that
    /// do not apply to the current epoch are ignored. Returns the blocked
    /// members.
    pub fn set_pending_removals(&mut self, proposals: &[SignedRemoveProposal]) -> Vec<MemberRef> {
        self.blocked = proposals
            .iter()
            .filter_map(|proposal| self.removal_target(proposal))
            .collect();
        self.blocked.iter().copied().collect()
    }

    /// Record one removal proposal read from the delivery-service log;
    /// messages from its target are rejected from now on. Returns the
    /// blocked member, or `None` if the proposal does not apply.
    pub fn add_pending_removal(&mut self, proposal: &SignedRemoveProposal) -> Option<MemberRef> {
        let target = self.removal_target(proposal)?;
        self.blocked.insert(target);
        Some(target)
    }

    fn removal_target(&self, proposal: &SignedRemoveProposal) -> Option<MemberRef> {
        let target = proposal
            .authorize(&self.state.gid, &self.state.membership())
            .ok()?;
        Some(MemberRef {
            leaf: proposal.proposal().target_leaf,
            since: target.since,
        })
    }

    /// Sign a proposal removing the member in `leaf` (an admin removal, or
    /// this member's own leave when `leaf` is its leaf).
    pub fn propose_removal(
        &self,
        identity: &DeviceIdentity,
        leaf: u32,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<SignedRemoveProposal> {
        self.check_identity(identity)?;
        let target = self
            .state
            .tree
            .leaf(leaf)
            .ok_or(CoreError::Invalid("no member in leaf"))?;
        let proposal = RemoveProposal {
            gid: self.state.gid,
            target_leaf: leaf,
            target_since: target.since,
            proposer_device_pk: identity.public_key().to_vec(),
        }
        .sign(identity, rng)?;
        proposal.authorize(&self.state.gid, &self.state.membership())?;
        Ok(proposal)
    }

    /// Sign this member's own leave proposal.
    pub fn propose_leave(
        &self,
        identity: &DeviceIdentity,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<SignedRemoveProposal> {
        self.propose_removal(identity, self.me.leaf, rng)
    }

    /// Sign an invite whose key derives from `invite_seed` (admins only).
    pub fn create_invite(
        &self,
        identity: &DeviceIdentity,
        invite_seed: &[u8; 32],
        expires_at_ms: u64,
        max_uses: u64,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<SignedInvite> {
        self.check_admin(identity)?;
        Invite::from_seed(
            &self.state.gid,
            invite_seed,
            expires_at_ms,
            max_uses,
            identity.public_key(),
        )
        .sign(identity, rng)
    }

    /// Sign the revocation of an invite (admins only).
    pub fn revoke_invite(
        &self,
        identity: &DeviceIdentity,
        invite_id: &Digest,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<SignedInviteRevocation> {
        self.check_admin(identity)?;
        SignedInviteRevocation::sign(&self.state.gid, invite_id, identity, rng)
    }

    /// Sign an admission for the device `joiner_device_pk`, valid until
    /// epoch `not_after_epoch` (admins only).
    pub fn admit(
        &self,
        identity: &DeviceIdentity,
        joiner_device_pk: &[u8],
        not_after_epoch: u64,
        rng: &mut impl CryptoRngCore,
    ) -> CoreResult<SignedAdmission> {
        self.check_admin(identity)?;
        SignedAdmission::by_admin(
            &self.state.gid,
            &device_id(&self.state.gid, joiner_device_pk)?,
            not_after_epoch,
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
        if self
            .state
            .tree
            .leaf(self.me.leaf)
            .map(|member| member.device_pk.as_slice())
            != Some(identity.public_key())
        {
            return Err(CoreError::Invalid("identity does not own this session"));
        }
        Ok(())
    }

    fn check_admin(&self, identity: &DeviceIdentity) -> CoreResult<()> {
        self.check_identity(identity)?;
        if !self.state.registry.is_admin(self.me.leaf) {
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

    /// Current tree (the members).
    #[must_use]
    pub fn tree(&self) -> &PublicTree {
        &self.state.tree
    }

    /// Current registry (capacity, admins, retired admissions).
    #[must_use]
    pub fn registry(&self) -> &Registry {
        &self.state.registry
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

    /// This member's occupancy.
    #[must_use]
    pub fn me(&self) -> MemberRef {
        self.me
    }

    /// This member's leaf.
    #[must_use]
    pub fn my_leaf(&self) -> u32 {
        self.me.leaf
    }

    /// Whether this member is an admin.
    #[must_use]
    pub fn is_admin(&self) -> bool {
        self.state.registry.is_admin(self.me.leaf)
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

    /// Public key of the epoch's external X-Wing key (as in the GroupInfo).
    pub fn external_public_key(&self) -> CoreResult<Vec<u8>> {
        Ok(self.secrets.external_key()?.public_key())
    }

    /// Fingerprint of the transcript, for out-of-band comparison between
    /// members (equal fingerprints mean equal histories).
    #[must_use]
    pub fn transcript_fingerprint(&self) -> Digest {
        self.state.interim_transcript_hash
    }

    /// The light session of this member: the same epoch, keys and message
    /// state, without the public tree (see [`crate::light`]).
    pub fn to_light(&self) -> CoreResult<LightSession> {
        let record = self
            .state
            .tree
            .member_by_ref(self.me)
            .cloned()
            .ok_or(CoreError::Invalid("this device is not a member"))?;
        Ok(LightSession::from_parts(crate::light::LightParts {
            group_context: self.group_context.clone(),
            interim_transcript_hash: self.state.interim_transcript_hash,
            registry: self.state.registry.clone(),
            occupied: self
                .state
                .tree
                .member_refs()
                .map(|member| (member.leaf, member.since))
                .collect(),
            me: self.me,
            record,
            private: self.private.clone(),
            secrets: self.secrets.clone(),
            messages: self.messages.clone(),
            previous: self.previous.clone(),
            blocked: self.blocked.clone(),
            last_own_update_epoch: self.last_own_update_epoch,
        }))
    }

    /// Rebuild a full session from a light one and the public state of its
    /// epoch ([`LightSession::upgrade`] checked they agree).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_light(
        state: PublicGroupState,
        me: MemberRef,
        mut private: PrivatePath,
        secrets: RetainedEpochSecrets,
        messages: EpochMessages,
        previous: VecDeque<PreviousEpoch>,
        blocked: BTreeSet<MemberRef>,
        last_own_update_epoch: u64,
    ) -> CoreResult<Self> {
        if state.tree.member_by_ref(me).is_none() || messages.epoch() != state.epoch {
            return Err(CoreError::Invalid("this device is not a member"));
        }
        private.retain_live(&state.tree);
        Ok(Self {
            group_context: state.group_context()?,
            state,
            me,
            private,
            secrets,
            messages,
            previous,
            blocked,
            last_own_update_epoch,
        })
    }

    /// Export the session, secrets included, for encrypted persistence.
    pub fn export(&self) -> CoreResult<Zeroizing<Vec<u8>>> {
        let (private_leaf, private_nodes) = private_to_values(&self.private);
        Ok(Zeroizing::new(encode(&array(vec![
            text(SESSION_LABEL),
            bytes(&self.state.to_cbor()?),
            self.me.to_value(),
            private_leaf,
            private_nodes,
            bytes(self.secrets.init_secret()),
            bytes(self.secrets.external_secret()),
            self.messages.to_value(),
            previous_to_value(&self.previous),
            array(
                self.blocked
                    .iter()
                    .map(|member| member.to_value())
                    .collect(),
            ),
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
        let me = MemberRef::from_value(next(&mut items, "session")?)?;
        let private =
            private_from_values(next(&mut items, "session")?, next(&mut items, "session")?)?;
        let init_secret = expect_bytes32(next(&mut items, "session")?, "session init secret")?;
        let external_secret =
            expect_bytes32(next(&mut items, "session")?, "session external secret")?;
        let messages = EpochMessages::from_value(next(&mut items, "session")?)?;
        let previous = previous_from_value(next(&mut items, "session")?)?;
        let blocked = expect_list(next(&mut items, "session")?, "session blocked")?
            .into_iter()
            .map(MemberRef::from_value)
            .collect::<CoreResult<BTreeSet<_>>>()?;
        let last_own_update_epoch = expect_uint(&next(&mut items, "session")?, "session update")?;
        if state.tree.member_by_ref(me).is_none() {
            return Err(CoreError::Malformed("session member"));
        }
        if messages.epoch() != state.epoch {
            return Err(CoreError::Malformed("session message epoch"));
        }
        Ok(Self {
            group_context: state.group_context()?,
            state,
            me,
            private,
            secrets: RetainedEpochSecrets::from_parts(init_secret, external_secret),
            messages,
            previous,
            blocked,
            last_own_update_epoch,
        })
    }
}

/// One proposal per target leaf, by increasing leaf (the order a commit
/// lists them in).
#[must_use]
pub fn sorted_removals(removals: &[SignedRemoveProposal]) -> Vec<SignedRemoveProposal> {
    let mut by_leaf: BTreeMap<u32, SignedRemoveProposal> = BTreeMap::new();
    for removal in removals {
        by_leaf
            .entry(removal.proposal().target_leaf)
            .or_insert_with(|| removal.clone());
    }
    by_leaf.into_values().collect()
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
        || info.signer_leaf != transition.commit.content.author_leaf
        || info.external_public_key != secrets.external_key()?.public_key()
    {
        return Err(CoreError::Invalid("group info does not match the commit"));
    }
    signed.verify(&transition.next.tree, &transition.next.registry)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod tests;
