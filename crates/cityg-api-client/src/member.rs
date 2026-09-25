//! Member driver: one device's participation in one group.
//!
//! [`Member`] combines a [`GroupSession`] with the delivery-service client:
//! it creates and joins groups, follows the log in order (commits, messages
//! and recorded proposals), publishes commits with retries when another
//! commit wins the epoch, resyncs when the local state can no longer follow,
//! and manages the member's session token.
//!
//! Joins are batched: a joiner records a join request, then waits a short,
//! jittered while for a commit to include it (any member commits the
//! recorded requests with [`Member::commit_pending`]). If none does, it
//! authors an external commit itself, which also brings the other pending
//! requests in. Either way the group moves by one commit per batch, not one
//! per joiner.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cityg_core::CoreError;
use cityg_core::admission::{SignedAdmission, SignedInvite, invite_id};
use cityg_core::binding::{AliasBinding, SessionAuth};
use cityg_core::cbor::{
    array, bytes, decode, encode, expect_array, expect_bytes, expect_label, text, uint,
};
use cityg_core::commit::{AdminChange, MAX_JOINS_PER_COMMIT, MAX_REMOVALS_PER_COMMIT};
use cityg_core::cover::CoverFailureReason;
use cityg_core::hash::Digest;
use cityg_core::identity::DeviceIdentity;
use cityg_core::join::SignedJoinRequest;
use cityg_core::message::{Envelope, ReceivedMessage};
use cityg_core::proposal::SignedRemoveProposal;
use cityg_core::registry::Registry;
use cityg_core::session::{
    CommitOptions, CommitSummary, GroupSession, GroupSnapshot, PendingCommit, ProcessedCommit,
    PublishedCommit,
};
use cityg_core::tree::{MemberRef, PublicTree};
use cityg_proto::{ErrorCode, MAX_LOG_PAGE, pb};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use super::client::{ClientError, DsClient};
use super::invite::InviteLink;
use super::light::LightMember;

/// Content type of UTF-8 chat text.
pub const CONTENT_TYPE_TEXT: u64 = 1;
/// Validity, in epochs, of the admissions this driver signs.
pub const ADMISSION_VALIDITY_EPOCHS: u64 = 1024;
/// How many times a commit is rebuilt after losing the epoch.
pub(crate) const COMMIT_ATTEMPTS: usize = 8;
/// Tokens are renewed this long before they expire.
const TOKEN_MARGIN_MS: u64 = 60_000;
/// How long a joiner waits for a commit to include its request before it
/// commits its own entry, at most (jittered).
const JOIN_WAIT_MS: u64 = 2_000;
/// Interval between two polls of a join request.
const JOIN_POLL_MS: u64 = 150;
const MEMBER_LABEL: &str = "city-g/member/v2";

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// What a sync observed.
#[derive(Clone, Debug, Default)]
pub struct SyncReport {
    /// Decrypted messages from other members, in log order.
    pub messages: Vec<ReceivedMessage>,
    /// Commits processed (other members' and this member's own).
    pub commits: Vec<CommitSummary>,
    /// Removal proposals recorded since the last sync.
    pub proposals: Vec<SignedRemoveProposal>,
    /// Join requests recorded since the last sync.
    pub join_requests: Vec<SignedJoinRequest>,
    /// Envelopes that were rejected (replay, removed sender, bad signature).
    pub rejected: usize,
    /// This member was removed from the group; the member must be dropped.
    pub removed: bool,
    /// The member had to resync (re-enter its leaf) to follow the group.
    pub resynced: bool,
}

/// A message this member sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SentMessage {
    pub seq: u64,
    pub epoch: u64,
    pub signed_timestamp_ms: u64,
}

struct Unconfirmed {
    pending: PendingCommit,
    commit: Vec<u8>,
    new_identity: Option<DeviceIdentity>,
}

/// Receives the exported member state (secrets included) whenever it must
/// be made durable: after a message is encrypted and before it is sent, and
/// after every processed or published commit. Persisting it in that order
/// guarantees a restarted device never reuses a message generation.
pub type StateSink = std::sync::Arc<dyn Fn(&[u8]) -> Result<(), String> + Send + Sync>;

/// One device's membership in one group.
pub struct Member {
    client: DsClient,
    identity: DeviceIdentity,
    session: GroupSession,
    log_seq: u64,
    token: Option<([u8; 32], u64)>,
    pending_removals: BTreeMap<u32, SignedRemoveProposal>,
    pending_joins: BTreeMap<Digest, SignedJoinRequest>,
    unconfirmed: Option<Unconfirmed>,
    sink: Option<StateSink>,
}

impl core::fmt::Debug for Member {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Member")
            .field("gid", &hex::encode(self.session.gid()))
            .field("epoch", &self.session.epoch())
            .field("log_seq", &self.log_seq)
            .finish_non_exhaustive()
    }
}

pub(crate) fn snapshot_of(info: &pb::GroupInfoResponse) -> GroupSnapshot {
    GroupSnapshot {
        group_info: info.group_info.clone(),
        tree: info.tree.clone(),
        registry: info.registry.clone(),
    }
}

/// The recorded proposals of `info` a commit includes: the oldest removals
/// and join requests, up to the per-commit bounds.
pub(crate) fn pending_of(
    info: &pb::GroupInfoResponse,
) -> Result<(Vec<SignedRemoveProposal>, Vec<SignedJoinRequest>), ClientError> {
    let removals = info
        .pending_removals
        .iter()
        .take(MAX_REMOVALS_PER_COMMIT)
        .map(|proposal| SignedRemoveProposal::decode(proposal).map_err(ClientError::from))
        .collect::<Result<Vec<_>, _>>()?;
    let joins = info
        .pending_joins
        .iter()
        .take(MAX_JOINS_PER_COMMIT)
        .map(|request| SignedJoinRequest::decode(request).map_err(ClientError::from))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((removals, joins))
}

fn check_owner(session: &GroupSession, identity: &DeviceIdentity) -> Result<(), ClientError> {
    if session
        .tree()
        .leaf(session.my_leaf())
        .map(|member| member.device_pk.as_slice())
        != Some(identity.public_key())
    {
        return Err(ClientError::State("the session belongs to another device"));
    }
    Ok(())
}

/// A cached session token and its expiry.
pub(crate) type CachedToken = Option<([u8; 32], u64)>;

/// A valid session token of `identity` in `gid`, opening a new session when
/// the cached one is missing or about to expire.
pub(crate) async fn session_token(
    client: &DsClient,
    identity: &DeviceIdentity,
    gid: &Digest,
    cached: &mut CachedToken,
) -> Result<[u8; 32], ClientError> {
    let now = now_ms();
    if let Some((token, expires_at_ms)) = *cached
        && expires_at_ms > now.saturating_add(TOKEN_MARGIN_MS)
    {
        return Ok(token);
    }
    let auth = SessionAuth::sign(gid, now, identity, &mut OsRng)?;
    let response = client.open_session(gid, auth.encoded()).await?;
    let token: [u8; 32] = response
        .token
        .try_into()
        .map_err(|_| ClientError::Decode("token must be 32 bytes".into()))?;
    *cached = Some((token, response.expires_at_ms));
    Ok(token)
}

/// One page of the log after `after`, renewing the token once if refused.
pub(crate) async fn fetch_page(
    client: &DsClient,
    identity: &DeviceIdentity,
    gid: &Digest,
    cached: &mut CachedToken,
    after: u64,
    light: bool,
) -> Result<pb::FetchLogResponse, ClientError> {
    let token = session_token(client, identity, gid, cached).await?;
    match client
        .fetch_log(gid, after, MAX_LOG_PAGE, light, &token)
        .await
    {
        Err(error) if error.api_code() == Some(ErrorCode::Unauthorized) => {
            *cached = None;
            let token = session_token(client, identity, gid, cached).await?;
            client
                .fetch_log(gid, after, MAX_LOG_PAGE, light, &token)
                .await
        }
        other => other,
    }
}

/// Log position of the commit of `epoch` (the log start if gone).
pub(crate) async fn commit_seq(
    client: &DsClient,
    identity: &DeviceIdentity,
    gid: &Digest,
    cached: &mut CachedToken,
    epoch: u64,
) -> Result<u64, ClientError> {
    let mut after = 0;
    loop {
        let page = fetch_page(client, identity, gid, cached, after, false).await?;
        let count = page.entries.len();
        for entry in page.entries {
            after = entry.seq;
            if entry.epoch == epoch && matches!(entry.body, Some(pb::log_entry::Body::Commit(_))) {
                return Ok(entry.seq);
            }
        }
        if count < MAX_LOG_PAGE as usize {
            return Ok(after);
        }
    }
}

/// How a joiner entered the group.
enum Entered {
    Full(Member),
    Light(LightMember),
}

/// An admission for `identity` through the invite of `link`.
pub(crate) async fn admission_for_invite(
    client: &DsClient,
    identity: &DeviceIdentity,
    link: &InviteLink,
) -> Result<SignedAdmission, ClientError> {
    let invite_key = DeviceIdentity::from_seed(&link.invite_seed);
    let id = invite_id(invite_key.public_key())?;
    let response = client.get_invite(&link.gid, &id).await?;
    let invite = SignedInvite::decode(&response.invite)?;
    if invite.invite().gid != link.gid {
        return Err(ClientError::InvalidInvite("invite for another group"));
    }
    let info = client.group_info(&link.gid).await?;
    let registry = Registry::from_cbor(&info.registry)?;
    Ok(SignedAdmission::with_invite(
        &identity.device_id(&link.gid)?,
        registry.admission_not_after(info.epoch, ADMISSION_VALIDITY_EPOCHS),
        &invite,
        &link.invite_seed,
        &mut OsRng,
    )?)
}

impl Member {
    fn assemble(
        client: DsClient,
        identity: DeviceIdentity,
        session: GroupSession,
        log_seq: u64,
    ) -> Self {
        Self {
            client,
            identity,
            session,
            log_seq,
            token: None,
            pending_removals: BTreeMap::new(),
            pending_joins: BTreeMap::new(),
            unconfirmed: None,
            sink: None,
        }
    }

    /// Wrap a group session obtained out of band (a tool or a test);
    /// `log_seq` is the last room log position it reflects. The session must
    /// belong to `identity`.
    pub fn from_session(
        client: DsClient,
        identity: DeviceIdentity,
        session: GroupSession,
        log_seq: u64,
    ) -> Result<Self, ClientError> {
        check_owner(&session, &identity)?;
        Ok(Self::assemble(client, identity, session, log_seq))
    }

    /// Install the sink that persists the member state.
    pub fn set_state_sink(&mut self, sink: StateSink) {
        self.sink = Some(sink);
    }

    /// Persist the current state through the sink, if any.
    pub fn save(&self) -> Result<(), ClientError> {
        if let Some(sink) = &self.sink {
            let exported = self.export()?;
            sink(&exported)
                .map_err(|_| ClientError::State("failed to persist the member state"))?;
        }
        Ok(())
    }

    /// Create a group of at most `capacity` members; this device is its
    /// first admin.
    pub async fn create(
        client: DsClient,
        identity: DeviceIdentity,
        capacity: u32,
    ) -> Result<Self, ClientError> {
        let (pending, published) = GroupSession::create(&identity, capacity, &mut OsRng)?;
        let gid = *pending.gid();
        let response = client
            .create_group(&gid, &published.commit, &published.group_info)
            .await?;
        Ok(Self::assemble(
            client,
            identity,
            pending.into_session()?,
            response.seq,
        ))
    }

    /// Join through an invite link.
    pub async fn join_with_invite(
        client: DsClient,
        identity: DeviceIdentity,
        link: &InviteLink,
    ) -> Result<Self, ClientError> {
        let admission = admission_for_invite(&client, &identity, link).await?;
        Self::join_with_admission(client, identity, &link.gid, admission).await
    }

    /// Join with an admission (signed by an admin or with an invite key):
    /// record a join request, wait for a commit to include it, and commit
    /// the entry externally when none does.
    pub async fn join_with_admission(
        client: DsClient,
        identity: DeviceIdentity,
        gid: &Digest,
        admission: SignedAdmission,
    ) -> Result<Self, ClientError> {
        match Self::join_group(client, identity, gid, admission, false).await? {
            Entered::Full(member) => Ok(member),
            Entered::Light(member) => member.upgrade().await,
        }
    }

    /// [`LightMember::join_with_admission`]: like a full join, but the
    /// joiner enters with its welcome without the public tree when it can.
    pub(crate) async fn join_light(
        client: DsClient,
        identity: DeviceIdentity,
        gid: &Digest,
        admission: SignedAdmission,
    ) -> Result<LightMember, ClientError> {
        match Self::join_group(client, identity, gid, admission, true).await? {
            Entered::Full(member) => member.into_light(),
            Entered::Light(member) => Ok(member),
        }
    }

    async fn join_group(
        client: DsClient,
        identity: DeviceIdentity,
        gid: &Digest,
        admission: SignedAdmission,
        light: bool,
    ) -> Result<Entered, ClientError> {
        let (request, secrets) = GroupSession::request_join(&identity, &admission, &mut OsRng)?;
        let submitted = client.submit_join_request(gid, request.encoded()).await?;
        let reference: Digest = submitted
            .request_ref
            .try_into()
            .map_err(|_| ClientError::Decode("request ref must be 32 bytes".into()))?;
        let wait_ms = JOIN_WAIT_MS / 2 + OsRng.next_u64() % (JOIN_WAIT_MS / 2);
        let mut last_error = ClientError::State("join did not run");
        for attempt in 0..COMMIT_ATTEMPTS {
            // First look whether a commit brought the request in.
            let deadline = now_ms().saturating_add(if attempt == 0 { wait_ms } else { 0 });
            loop {
                let status = client.join_status(gid, &reference, light).await?;
                match status.status.as_str() {
                    "committed" => {
                        if light
                            && let Some(member) = LightMember::enter_with_welcome(
                                client.clone(),
                                identity.clone(),
                                &secrets,
                                &status,
                            )
                            .await?
                        {
                            return Ok(Entered::Light(member));
                        }
                        return Self::enter_with_welcome(client, identity, gid, &secrets, &status)
                            .await
                            .map(Entered::Full);
                    }
                    "pending" => {}
                    _ => {
                        // Dropped (revoked invite, expired admission) or
                        // committed by the joiner's own lost commit.
                        let info = client.group_info(gid).await?;
                        let tree = PublicTree::from_cbor(&info.tree)?;
                        if tree.find_device(identity.public_key()).is_some() {
                            return Self::resync_from_scratch(client, identity, gid)
                                .await
                                .map(Entered::Full);
                        }
                        return Err(ClientError::State("the join request was dropped"));
                    }
                }
                if now_ms() >= deadline {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(JOIN_POLL_MS)).await;
            }
            // Nobody committed it: commit this device's entry, bringing the
            // other recorded proposals along.
            let info = client.group_info(gid).await?;
            if PublicTree::from_cbor(&info.tree)?
                .find_device(identity.public_key())
                .is_some()
            {
                // A commit brought the request in since the status check:
                // the next attempt reads its welcome.
                continue;
            }
            let (removals, joins) = pending_of(&info)?;
            let others: Vec<SignedJoinRequest> = joins
                .into_iter()
                .filter(|pending| pending.device_pk != identity.public_key())
                .take(MAX_JOINS_PER_COMMIT)
                .collect();
            let (pending, published) = GroupSession::join_external(
                &identity,
                &snapshot_of(&info),
                admission.clone(),
                &removals,
                &others,
                &mut OsRng,
            )?;
            if pending.gid() != gid {
                return Err(ClientError::State("group info of another group"));
            }
            match client
                .publish_commit(
                    gid,
                    &published.commit,
                    &published.group_info,
                    &published.welcomes,
                )
                .await
            {
                Ok(response) => {
                    return Ok(Entered::Full(Self::assemble(
                        client,
                        identity,
                        pending.into_session()?,
                        response.seq,
                    )));
                }
                Err(error) if error.is_conflict() => last_error = error,
                Err(error) => return Err(error),
            }
        }
        Err(last_error)
    }

    /// Open the welcome of a committed join request; when the group already
    /// moved past the commit's epoch, re-enter the leaf with a resync.
    async fn enter_with_welcome(
        client: DsClient,
        identity: DeviceIdentity,
        gid: &Digest,
        secrets: &cityg_core::join::JoinSecrets,
        status: &pb::JoinStatusResponse,
    ) -> Result<Self, ClientError> {
        let info = client.group_info(gid).await?;
        if let Some(commit) = &status.commit
            && info.epoch == status.epoch
        {
            let session = GroupSession::join_with_welcome(
                &identity,
                secrets,
                &snapshot_of(&info),
                &commit.commit,
                &status.welcome,
            )?;
            // Start from the commit: the joiner reads what follows it.
            let mut member = Self::assemble(client, identity, session, 0);
            member.log_seq = commit_seq(
                &member.client,
                &member.identity,
                gid,
                &mut member.token,
                status.epoch,
            )
            .await?;
            return Ok(member);
        }
        Self::resync_from_scratch(client, identity, gid).await
    }

    /// Become a light member ([`LightMember`]): the same state without the
    /// public tree.
    pub fn into_light(self) -> Result<LightMember, ClientError> {
        let session = self.session.to_light()?;
        Ok(LightMember::assemble(
            self.client,
            self.identity,
            session,
            self.log_seq,
            self.token,
            self.sink,
        ))
    }

    /// Re-enter a group this device is a member of, from scratch (lost state).
    pub async fn resync_from_scratch(
        client: DsClient,
        identity: DeviceIdentity,
        gid: &Digest,
    ) -> Result<Self, ClientError> {
        let (session, seq) = resync_session(&client, &identity, gid).await?;
        Ok(Self::assemble(client, identity, session, seq))
    }

    /// Restore a member from [`Member::export`].
    pub fn restore(
        client: DsClient,
        identity: DeviceIdentity,
        exported: &[u8],
    ) -> Result<Self, ClientError> {
        let mut items =
            expect_array(decode(exported, 512 << 20, "member")?, 3, "member")?.into_iter();
        let mut next = || items.next().ok_or(CoreError::Malformed("member"));
        expect_label(&next()?, MEMBER_LABEL, "member")?;
        let session =
            GroupSession::import(&Zeroizing::new(expect_bytes(next()?, "member session")?))?;
        check_owner(&session, &identity)
            .map_err(|_| ClientError::State("exported member belongs to another device"))?;
        let log_seq = cityg_core::cbor::expect_uint(&next()?, "member log position")?;
        Ok(Self::assemble(client, identity, session, log_seq))
    }

    /// Export the member (session secrets included) for encrypted storage.
    pub fn export(&self) -> Result<Zeroizing<Vec<u8>>, ClientError> {
        let session = self.session.export()?;
        Ok(Zeroizing::new(encode(&array(vec![
            text(MEMBER_LABEL),
            bytes(&session),
            uint(self.log_seq),
        ]))?))
    }

    /// The group session.
    #[must_use]
    pub fn session(&self) -> &GroupSession {
        &self.session
    }

    /// The device identity (the current one, after a key rotation).
    #[must_use]
    pub fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    /// The delivery-service client.
    #[must_use]
    pub fn client(&self) -> &DsClient {
        &self.client
    }

    /// Group identifier.
    #[must_use]
    pub fn gid(&self) -> Digest {
        *self.session.gid()
    }

    /// Position of the last processed log entry.
    #[must_use]
    pub fn log_seq(&self) -> u64 {
        self.log_seq
    }

    /// Removal proposals recorded since the last commit.
    #[must_use]
    pub fn pending_removals(&self) -> Vec<SignedRemoveProposal> {
        self.pending_removals.values().cloned().collect()
    }

    /// Join requests read from the log that no commit included yet.
    pub fn pending_joins(&self) -> Vec<SignedJoinRequest> {
        self.pending_joins.values().cloned().collect()
    }

    /// Keep the recorded proposals a commit left pending: removals whose
    /// target still holds its leaf and join requests that can still enter.
    fn prune_pending(&mut self) {
        let gid = self.gid();
        let state = self.session.public_state();
        let membership = state.membership();
        let next_epoch = state.epoch.saturating_add(1);
        self.pending_removals
            .retain(|_, proposal| proposal.authorize(&gid, &membership).is_ok());
        self.pending_joins
            .retain(|_, request| request.authorize(&gid, next_epoch, &membership).is_ok());
    }

    /// A valid session token, opening a new session when needed.
    pub async fn token(&mut self) -> Result<[u8; 32], ClientError> {
        let gid = self.gid();
        session_token(&self.client, &self.identity, &gid, &mut self.token).await
    }

    /// WebSocket URL of the log-head notifications of the group.
    pub async fn websocket_url(&mut self) -> Result<String, ClientError> {
        let token = self.token().await?;
        Ok(self.client.websocket_url(&self.gid(), &token))
    }

    async fn fetch_page_after(&mut self, after: u64) -> Result<pb::FetchLogResponse, ClientError> {
        let gid = self.gid();
        fetch_page(
            &self.client,
            &self.identity,
            &gid,
            &mut self.token,
            after,
            false,
        )
        .await
    }

    /// Follow the log: process commits, decrypt messages, record proposals.
    pub async fn sync(&mut self) -> Result<SyncReport, ClientError> {
        let start = self.log_seq;
        let result = self.sync_inner().await;
        if self.log_seq != start {
            self.save()?;
        }
        result
    }

    async fn sync_inner(&mut self) -> Result<SyncReport, ClientError> {
        let mut report = SyncReport::default();
        loop {
            let page = match self.fetch_page_after(self.log_seq).await {
                Ok(page) => page,
                // A removed member's token is refused: it learns its
                // removal from the public state.
                Err(error) if error.api_code() == Some(ErrorCode::Forbidden) => {
                    let info = self.client.group_info(&self.gid()).await?;
                    let tree = PublicTree::from_cbor(&info.tree)?;
                    if tree.find_device(self.identity.public_key()).is_none() {
                        report.removed = true;
                        return Ok(report);
                    }
                    return Err(error);
                }
                Err(error) => return Err(error),
            };
            let count = page.entries.len();
            for entry in page.entries {
                self.process_entry(entry, &mut report).await?;
                if report.removed || report.resynced {
                    return Ok(report);
                }
            }
            if count < MAX_LOG_PAGE as usize {
                return Ok(report);
            }
        }
    }

    async fn process_entry(
        &mut self,
        entry: pb::LogEntry,
        report: &mut SyncReport,
    ) -> Result<(), ClientError> {
        let seq = entry.seq;
        match entry.body {
            Some(pb::log_entry::Body::Commit(commit)) => {
                if entry.epoch <= self.session.epoch() {
                    self.log_seq = seq;
                    return Ok(());
                }
                if entry.epoch > self.session.epoch() + 1 {
                    // A commit we need is gone from the log.
                    return self.resync(report, None).await;
                }
                // An own commit whose acknowledgement was lost is installed
                // from its pending state; any other commit supersedes it.
                if let Some(unconfirmed) = self.unconfirmed.take()
                    && unconfirmed.commit == commit.commit
                {
                    self.install_own(unconfirmed.pending, unconfirmed.new_identity)?;
                    self.log_seq = seq;
                    return Ok(());
                }
                match self
                    .session
                    .process_commit(&commit.commit, Some(&commit.group_info))
                {
                    Ok(ProcessedCommit::Advanced(summary)) => {
                        self.prune_pending();
                        report.commits.push(summary);
                        self.log_seq = seq;
                    }
                    Ok(ProcessedCommit::Removed(summary)) => {
                        report.commits.push(summary);
                        report.removed = true;
                        self.log_seq = seq;
                    }
                    Err(error) => {
                        let reason = match &error {
                            CoreError::Decrypt(_) => CoverFailureReason::NotCovered,
                            CoreError::Invalid("update path public key mismatch") => {
                                CoverFailureReason::PathKeyMismatch
                            }
                            CoreError::Invalid("confirmation tag") => {
                                CoverFailureReason::ConfirmationTagMismatch
                            }
                            _ => CoverFailureReason::StateLost,
                        };
                        return self.resync(report, Some((entry.epoch, reason))).await;
                    }
                }
            }
            Some(pb::log_entry::Body::Envelope(envelope)) => {
                self.log_seq = seq;
                let own = Envelope::decode(&envelope)
                    .map(|decoded| decoded.header.sender == self.session.me())
                    .unwrap_or(false);
                if !own {
                    match self.session.decrypt(&envelope) {
                        Ok(message) => report.messages.push(message),
                        Err(_) => report.rejected += 1,
                    }
                }
            }
            Some(pb::log_entry::Body::Proposal(proposal)) => {
                self.log_seq = seq;
                let proposal = SignedRemoveProposal::decode(&proposal)?;
                if self.session.add_pending_removal(&proposal).is_some() {
                    self.pending_removals
                        .insert(proposal.proposal().target_leaf, proposal.clone());
                    report.proposals.push(proposal);
                }
            }
            Some(pb::log_entry::Body::JoinRequest(request)) => {
                self.log_seq = seq;
                let request = SignedJoinRequest::decode(&request)?;
                let state = self.session.public_state();
                if request
                    .authorize(
                        &state.gid,
                        state.epoch.saturating_add(1),
                        &state.membership(),
                    )
                    .is_ok()
                {
                    self.pending_joins
                        .insert(request.reference()?, request.clone());
                    report.join_requests.push(request);
                }
            }
            None => self.log_seq = seq,
        }
        Ok(())
    }

    fn install_own(
        &mut self,
        pending: PendingCommit,
        new_identity: Option<DeviceIdentity>,
    ) -> Result<(), ClientError> {
        self.session.apply_own_commit(pending)?;
        self.prune_pending();
        if let Some(new_identity) = new_identity {
            // The old key no longer names a member: its tokens are dead.
            self.identity = new_identity;
            self.token = None;
        }
        Ok(())
    }

    async fn resync(
        &mut self,
        report: &mut SyncReport,
        failure: Option<(u64, CoverFailureReason)>,
    ) -> Result<(), ClientError> {
        let gid = self.gid();
        if let Some((epoch, reason)) = failure
            && let Ok(failure) =
                self.session
                    .report_cover_failure(&self.identity, epoch, reason, &mut OsRng)
        {
            // Best effort: the report is evidence, the resync is the fix.
            let _ = self.client.cover_failure(&gid, failure.encoded()).await;
        }
        let (session, seq) = resync_session(&self.client, &self.identity, &gid).await?;
        self.session = session;
        self.log_seq = seq;
        self.pending_removals.clear();
        self.pending_joins.clear();
        self.unconfirmed = None;
        report.resynced = true;
        self.save()
    }

    /// Publish a commit built on the latest state with every recorded
    /// proposal, plus `extra_removals`, `admin_changes` and an optional
    /// rotation of the device key, rebuilding it when another commit wins
    /// the epoch.
    async fn commit_with(
        &mut self,
        extra_removals: &[SignedRemoveProposal],
        admin_changes: &[AdminChange],
        new_identity: Option<&DeviceIdentity>,
    ) -> Result<SyncReport, ClientError> {
        let gid = self.gid();
        let mut last_error = ClientError::State("commit did not run");
        let mut report = SyncReport::default();
        for _ in 0..COMMIT_ATTEMPTS {
            let synced = self.sync().await?;
            merge_reports(&mut report, synced);
            if report.removed {
                return Err(ClientError::State("this member was removed"));
            }
            let info = self.client.group_info(&gid).await?;
            if info.epoch != self.session.epoch() {
                continue;
            }
            let (mut removals, joins) = pending_of(&info)?;
            for extra in extra_removals {
                if !removals
                    .iter()
                    .any(|pending| pending.proposal().target_leaf == extra.proposal().target_leaf)
                {
                    removals.push(extra.clone());
                }
            }
            let (pending, published) = self.session.commit(
                &self.identity,
                CommitOptions {
                    removals: &removals,
                    joins: &joins,
                    admin_changes,
                    new_identity,
                },
                &mut OsRng,
            )?;
            match self
                .publish(&gid, pending, &published, new_identity.cloned())
                .await
            {
                Ok(()) => return Ok(report),
                Err(error) if error.is_conflict() => last_error = error,
                Err(error) => return Err(error),
            }
        }
        Err(last_error)
    }

    async fn publish(
        &mut self,
        gid: &Digest,
        pending: PendingCommit,
        published: &PublishedCommit,
        new_identity: Option<DeviceIdentity>,
    ) -> Result<(), ClientError> {
        match self
            .client
            .publish_commit(
                gid,
                &published.commit,
                &published.group_info,
                &published.welcomes,
            )
            .await
        {
            Ok(_) => {
                self.install_own(pending, new_identity)?;
                self.save()
            }
            Err(ClientError::Transport(message)) => {
                // Accepted or not: the next sync tells.
                self.unconfirmed = Some(Unconfirmed {
                    pending,
                    commit: published.commit.clone(),
                    new_identity,
                });
                Err(ClientError::Transport(message))
            }
            Err(error) => Err(error),
        }
    }

    /// Re-key this member's leaf and path (forward secrecy and PCS). The
    /// commit also carries every recorded proposal.
    pub async fn self_update(&mut self) -> Result<SyncReport, ClientError> {
        self.commit_with(&[], &[], None).await
    }

    /// Rotate this member's device key: the commit is signed by the current
    /// key and by `new_identity`, and this member signs with the new key
    /// from then on. It keeps its leaf, admission and admin rights.
    pub async fn rotate_device_key(
        &mut self,
        new_identity: DeviceIdentity,
    ) -> Result<SyncReport, ClientError> {
        self.commit_with(&[], &[], Some(&new_identity)).await
    }

    /// Commit the recorded proposals (removals and join requests), if any
    /// and if none removes this member. Returns whether a commit was
    /// published.
    pub async fn commit_pending(&mut self) -> Result<bool, ClientError> {
        let info = self.client.group_info(&self.gid()).await?;
        let me = self.session.me();
        let (removals, joins) = pending_of(&info)?;
        if (removals.is_empty() && joins.is_empty())
            || removals.iter().any(|proposal| {
                proposal.proposal().target_leaf == me.leaf
                    && proposal.proposal().target_since == me.since
            })
        {
            return Ok(false);
        }
        self.commit_with(&[], &[], None).await?;
        Ok(true)
    }

    /// Remove the member in `leaf` (admins).
    pub async fn remove_member(&mut self, leaf: u32) -> Result<SyncReport, ClientError> {
        let proposal = self
            .session
            .propose_removal(&self.identity, leaf, &mut OsRng)?;
        self.commit_with(&[proposal], &[], None).await
    }

    /// Grant or revoke the admin rights of the member in `leaf` (admins).
    pub async fn set_admin(&mut self, leaf: u32, grant: bool) -> Result<SyncReport, ClientError> {
        let since = self
            .session
            .tree()
            .leaf(leaf)
            .map(|member| member.since)
            .ok_or(ClientError::State("no member in that leaf"))?;
        let change = if grant {
            AdminChange::Grant { leaf, since }
        } else {
            AdminChange::Revoke { leaf, since }
        };
        self.commit_with(&[], &[change], None).await
    }

    /// Leave the group: record this member's leave proposal. Another member
    /// (or the next joiner) commits it; this member must stop using the
    /// group.
    pub async fn leave(&mut self) -> Result<(), ClientError> {
        let proposal = self.session.propose_leave(&self.identity, &mut OsRng)?;
        self.client
            .submit_remove_proposal(&self.gid(), proposal.encoded())
            .await?;
        Ok(())
    }

    /// Encrypt and send a text message.
    pub async fn send_text(&mut self, text: &str) -> Result<SentMessage, ClientError> {
        self.send(CONTENT_TYPE_TEXT, b"", text.as_bytes()).await
    }

    /// Encrypt and send a message.
    pub async fn send(
        &mut self,
        content_type: u64,
        authenticated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<SentMessage, ClientError> {
        let gid = self.gid();
        let mut refreshed = false;
        loop {
            let timestamp = now_ms();
            let envelope = self.session.encrypt(
                &self.identity,
                content_type,
                authenticated_data,
                plaintext,
                timestamp,
                &mut OsRng,
            )?;
            // The generation is spent: make that durable before the
            // ciphertext leaves the device.
            self.save()?;
            let token = self.token().await?;
            match self.client.send(&gid, &envelope, &token).await {
                Ok(response) => {
                    return Ok(SentMessage {
                        seq: response.seq,
                        epoch: response.epoch,
                        signed_timestamp_ms: timestamp,
                    });
                }
                Err(error)
                    if !refreshed
                        && matches!(
                            error.api_code(),
                            Some(ErrorCode::Unauthorized | ErrorCode::Unprocessable)
                        ) =>
                {
                    // Expired token, or an epoch the service no longer
                    // accepts: renew and catch up, then encrypt again.
                    refreshed = true;
                    self.token = None;
                    let report = self.sync().await?;
                    if report.removed {
                        return Err(ClientError::State("this member was removed"));
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Create an invite link valid for `ttl_ms` and `max_uses` joins
    /// (admins).
    pub async fn create_invite_link(
        &mut self,
        server_url: &str,
        ttl_ms: u64,
        max_uses: u64,
    ) -> Result<InviteLink, ClientError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(seed.as_mut());
        let invite = self.session.create_invite(
            &self.identity,
            &seed,
            now_ms().saturating_add(ttl_ms),
            max_uses,
            &mut OsRng,
        )?;
        self.client
            .publish_invite(&self.gid(), invite.encoded())
            .await?;
        Ok(InviteLink {
            server_url: server_url.to_string(),
            gid: self.gid(),
            invite_seed: seed,
        })
    }

    /// Revoke the invite of `link` (admins). Returns how many pending join
    /// requests relied on it.
    pub async fn revoke_invite(&mut self, link: &InviteLink) -> Result<usize, ClientError> {
        let id = invite_id(DeviceIdentity::from_seed(&link.invite_seed).public_key())?;
        let revocation = self
            .session
            .revoke_invite(&self.identity, &id, &mut OsRng)?;
        let response = self
            .client
            .revoke_invite(&self.gid(), revocation.encoded())
            .await?;
        Ok(response.dropped.len())
    }

    /// Admit a device directly (admins), for about
    /// [`ADMISSION_VALIDITY_EPOCHS`] epochs; the joiner then requests its
    /// join.
    pub fn admit(&self, joiner_device_pk: &[u8]) -> Result<SignedAdmission, ClientError> {
        Ok(self.session.admit(
            &self.identity,
            joiner_device_pk,
            self.session
                .registry()
                .admission_not_after(self.session.epoch(), ADMISSION_VALIDITY_EPOCHS),
            &mut OsRng,
        )?)
    }

    /// Publish this member's display name.
    pub async fn bind_alias(&mut self, alias: &str) -> Result<(), ClientError> {
        let binding = AliasBinding::sign(&self.gid(), alias, &self.identity, &mut OsRng)?;
        self.client
            .bind_alias(&self.gid(), binding.encoded())
            .await?;
        Ok(())
    }

    /// Display names of current members, by occupancy (verified bindings
    /// whose key is the member's current device key).
    pub async fn aliases(&mut self) -> Result<BTreeMap<MemberRef, String>, ClientError> {
        let token = self.token().await?;
        let response = self.client.aliases(&self.gid(), &token).await?;
        let mut aliases = BTreeMap::new();
        for binding in response.bindings {
            let Ok(binding) = AliasBinding::decode(&binding) else {
                continue;
            };
            if binding.gid != self.gid() {
                continue;
            }
            let tree = self.session.tree();
            if let Some(leaf) = tree.find_device(&binding.device_pk)
                && let Some(member) = tree.leaf(leaf)
            {
                aliases.insert(
                    MemberRef {
                        leaf,
                        since: member.since,
                    },
                    binding.alias,
                );
            }
        }
        Ok(aliases)
    }

    /// Erase the keys of the previous epochs (end of the grace window).
    pub fn expire_previous_epochs(&mut self) -> Result<(), ClientError> {
        self.session.expire_previous_epochs();
        self.save()
    }
}

fn merge_reports(into: &mut SyncReport, from: SyncReport) {
    into.messages.extend(from.messages);
    into.commits.extend(from.commits);
    into.proposals.extend(from.proposals);
    into.join_requests.extend(from.join_requests);
    into.rejected += from.rejected;
    into.removed |= from.removed;
    into.resynced |= from.resynced;
}

pub(crate) async fn resync_session(
    client: &DsClient,
    identity: &DeviceIdentity,
    gid: &Digest,
) -> Result<(GroupSession, u64), ClientError> {
    let mut last_error = ClientError::State("resync did not run");
    for _ in 0..COMMIT_ATTEMPTS {
        let info = client.group_info(gid).await?;
        let (removals, joins) = pending_of(&info)?;
        let (pending, published) =
            GroupSession::resync(identity, &snapshot_of(&info), &removals, &joins, &mut OsRng)?;
        match client
            .publish_commit(
                gid,
                &published.commit,
                &published.group_info,
                &published.welcomes,
            )
            .await
        {
            Ok(response) => return Ok((pending.into_session()?, response.seq)),
            Err(error) if error.is_conflict() => last_error = error,
            Err(error) => return Err(error),
        }
    }
    Err(last_error)
}
