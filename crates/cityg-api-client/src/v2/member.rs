//! Member driver: one device's participation in one group.
//!
//! [`Member`] combines a [`GroupSession`] with the delivery-service client:
//! it creates and joins groups, follows the log in order (commits, messages
//! and removal proposals), publishes commits with retries when another
//! commit wins the epoch, resyncs when the local state can no longer follow,
//! and manages the member's session token.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use cityg_core::CoreError;
use cityg_core::admission::{SignedAdmission, SignedInvite, invite_id};
use cityg_core::binding::{AliasBinding, SessionAuth};
use cityg_core::cbor::{
    array, bytes, decode, encode, expect_array, expect_bytes, expect_label, text, uint,
};
use cityg_core::commit::AdminChange;
use cityg_core::cover::CoverFailureReason;
use cityg_core::hash::Digest;
use cityg_core::identity::DeviceIdentity;
use cityg_core::message::{Envelope, ReceivedMessage};
use cityg_core::proposal::SignedRemoveProposal;
use cityg_core::session::{
    CommitSummary, GroupSession, GroupSnapshot, PendingCommit, ProcessedCommit, PublishedCommit,
};
use cityg_proto::{ErrorCode, MAX_LOG_PAGE, pb};
use rand_core::OsRng;
use zeroize::Zeroizing;

use super::client::{ClientError, DsClient};
use super::invite::InviteLink;

/// Content type of UTF-8 chat text.
pub const CONTENT_TYPE_TEXT: u64 = 1;
/// How many times a commit is rebuilt after losing the epoch.
const COMMIT_ATTEMPTS: usize = 8;
/// Tokens are renewed this long before they expire.
const TOKEN_MARGIN_MS: u64 = 60_000;
const MEMBER_LABEL: &str = "city-g/member/v1";

fn now_ms() -> u64 {
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
    /// Envelopes that were rejected (replay, removed sender, bad signature).
    pub rejected: usize,
    /// This member was removed from the group; the member must be dropped.
    pub removed: bool,
    /// The member had to resync (re-enter its slot) to follow the group.
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

fn snapshot_of(info: &pb::GroupInfoResponse) -> GroupSnapshot {
    GroupSnapshot {
        group_info: info.group_info.clone(),
        tree: info.tree.clone(),
        roster: info.roster.clone(),
    }
}

fn pending_of(info: &pb::GroupInfoResponse) -> Result<Vec<SignedRemoveProposal>, ClientError> {
    info.pending_removals
        .iter()
        .map(|proposal| SignedRemoveProposal::decode(proposal).map_err(ClientError::from))
        .collect()
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
        if session.my_leaf_id() != &identity.leaf_id(session.gid())? {
            return Err(ClientError::State("the session belongs to another device"));
        }
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
            sink(&exported).map_err(|_| ClientError::State("failed to persist the member state"))?;
        }
        Ok(())
    }

    /// Create a group of `n_max` slots; this device is its first admin.
    pub async fn create(
        client: DsClient,
        identity: DeviceIdentity,
        n_max: u32,
    ) -> Result<Self, ClientError> {
        let (pending, published) = GroupSession::create(&identity, n_max, &mut OsRng)?;
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
        let invite_key = DeviceIdentity::from_seed(&link.invite_seed);
        let id = invite_id(invite_key.public_key())?;
        let response = client.get_invite(&link.gid, &id).await?;
        let invite = SignedInvite::decode(&response.invite)?;
        if invite.invite().gid != link.gid {
            return Err(ClientError::InvalidInvite("invite for another group"));
        }
        let admission = SignedAdmission::with_invite(
            &identity.leaf_id(&link.gid)?,
            &invite,
            &link.invite_seed,
            &mut OsRng,
        )?;
        Self::join_with_admission(client, identity, &link.gid, admission).await
    }

    /// Join with an admission (signed by an admin or with an invite key).
    pub async fn join_with_admission(
        client: DsClient,
        identity: DeviceIdentity,
        gid: &Digest,
        admission: SignedAdmission,
    ) -> Result<Self, ClientError> {
        let mut last_error = ClientError::State("join did not run");
        for _ in 0..COMMIT_ATTEMPTS {
            let info = client.group_info(gid).await?;
            let (pending, published) = GroupSession::join(
                &identity,
                &snapshot_of(&info),
                &pending_of(&info)?,
                admission.clone(),
                &mut OsRng,
            )?;
            if pending.gid() != gid {
                return Err(ClientError::State("group info of another group"));
            }
            match client
                .publish_commit(gid, &published.commit, &published.group_info)
                .await
            {
                Ok(response) => {
                    return Ok(Self::assemble(
                        client,
                        identity,
                        pending.into_session()?,
                        response.seq,
                    ));
                }
                Err(error) if error.is_conflict() => last_error = error,
                Err(error) => return Err(error),
            }
        }
        Err(last_error)
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
        if session.my_leaf_id() != &identity.leaf_id(session.gid())? {
            return Err(ClientError::State(
                "exported member belongs to another device",
            ));
        }
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

    /// The device identity.
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

    /// A valid session token, opening a new session when needed.
    pub async fn token(&mut self) -> Result<[u8; 32], ClientError> {
        let now = now_ms();
        if let Some((token, expires_at_ms)) = self.token
            && expires_at_ms > now.saturating_add(TOKEN_MARGIN_MS)
        {
            return Ok(token);
        }
        let gid = self.gid();
        let auth = SessionAuth::sign(&gid, now, &self.identity, &mut OsRng)?;
        let response = self.client.open_session(&gid, auth.encoded()).await?;
        let token: [u8; 32] = response
            .token
            .try_into()
            .map_err(|_| ClientError::Decode("token must be 32 bytes".into()))?;
        self.token = Some((token, response.expires_at_ms));
        Ok(token)
    }

    /// WebSocket URL of the log-head notifications of the group.
    pub async fn websocket_url(&mut self) -> Result<String, ClientError> {
        let token = self.token().await?;
        Ok(self.client.websocket_url(&self.gid(), &token))
    }

    async fn fetch_page(&mut self) -> Result<pb::FetchLogResponse, ClientError> {
        let gid = self.gid();
        let token = self.token().await?;
        match self
            .client
            .fetch_log(&gid, self.log_seq, MAX_LOG_PAGE, &token)
            .await
        {
            Err(error) if error.api_code() == Some(ErrorCode::Unauthorized) => {
                self.token = None;
                let token = self.token().await?;
                self.client
                    .fetch_log(&gid, self.log_seq, MAX_LOG_PAGE, &token)
                    .await
            }
            other => other,
        }
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
            let page = match self.fetch_page().await {
                Ok(page) => page,
                // A removed member's token is refused: it learns its
                // removal from the public state.
                Err(error) if error.api_code() == Some(ErrorCode::Forbidden) => {
                    let info = self.client.group_info(&self.gid()).await?;
                    let roster = cityg_core::roster::Roster::from_cbor(&info.roster, &self.gid())?;
                    if roster.member_by_leaf(self.session.my_leaf_id()).is_none() {
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
                    self.session.apply_own_commit(unconfirmed.pending)?;
                    self.pending_removals.clear();
                    self.log_seq = seq;
                    return Ok(());
                }
                match self
                    .session
                    .process_commit(&commit.commit, Some(&commit.group_info))
                {
                    Ok(ProcessedCommit::Advanced(summary)) => {
                        self.pending_removals.clear();
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
                            CoreError::Decrypt(_) => Some(CoverFailureReason::NotCovered),
                            CoreError::Invalid("update path public key mismatch") => {
                                Some(CoverFailureReason::PathKeyMismatch)
                            }
                            CoreError::Invalid("confirmation tag") => {
                                Some(CoverFailureReason::ConfirmationTagMismatch)
                            }
                            _ => Some(CoverFailureReason::StateLost),
                        };
                        return self
                            .resync(report, reason.map(|reason| (entry.epoch, reason)))
                            .await;
                    }
                }
            }
            Some(pb::log_entry::Body::Envelope(envelope)) => {
                self.log_seq = seq;
                let own = Envelope::decode(&envelope)
                    .map(|decoded| &decoded.header.sender_leaf_id == self.session.my_leaf_id())
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
                        .insert(proposal.proposal().target_slot, proposal.clone());
                    report.proposals.push(proposal);
                }
            }
            None => self.log_seq = seq,
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
        self.unconfirmed = None;
        report.resynced = true;
        self.save()
    }

    /// Publish a commit built by `build` on the latest state, rebuilding it
    /// when another commit wins the epoch.
    async fn commit_with(
        &mut self,
        extra_removals: &[SignedRemoveProposal],
        admin_changes: &[AdminChange],
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
            let mut removals = pending_of(&info)?;
            for extra in extra_removals {
                if !removals
                    .iter()
                    .any(|pending| pending.proposal().target_slot == extra.proposal().target_slot)
                {
                    removals.push(extra.clone());
                }
            }
            if info.epoch != self.session.epoch() {
                continue;
            }
            let (pending, published) =
                self.session
                    .commit(&self.identity, &removals, admin_changes, &mut OsRng)?;
            match self.publish(&gid, pending, &published).await {
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
    ) -> Result<(), ClientError> {
        match self
            .client
            .publish_commit(gid, &published.commit, &published.group_info)
            .await
        {
            Ok(_) => {
                self.session.apply_own_commit(pending)?;
                self.pending_removals.clear();
                self.save()
            }
            Err(ClientError::Transport(message)) => {
                // Accepted or not: the next sync tells.
                self.unconfirmed = Some(Unconfirmed {
                    pending,
                    commit: published.commit.clone(),
                });
                Err(ClientError::Transport(message))
            }
            Err(error) => Err(error),
        }
    }

    /// Re-key this member's leaf and path (forward secrecy and PCS).
    pub async fn self_update(&mut self) -> Result<SyncReport, ClientError> {
        self.commit_with(&[], &[]).await
    }

    /// Commit the recorded removal proposals, if any and if none targets
    /// this member. Returns whether a commit was published.
    pub async fn commit_pending_removals(&mut self) -> Result<bool, ClientError> {
        let info = self.client.group_info(&self.gid()).await?;
        let pending = pending_of(&info)?;
        if pending.is_empty()
            || pending
                .iter()
                .any(|proposal| &proposal.proposal().target_leaf_id == self.session.my_leaf_id())
        {
            return Ok(false);
        }
        self.commit_with(&[], &[]).await?;
        Ok(true)
    }

    /// Remove the member in `slot` (admins).
    pub async fn remove_member(&mut self, slot: u32) -> Result<SyncReport, ClientError> {
        let proposal = self
            .session
            .propose_removal(&self.identity, slot, &mut OsRng)?;
        self.commit_with(&[proposal], &[]).await
    }

    /// Grant or revoke admin rights (admins).
    pub async fn set_admin(
        &mut self,
        device_pk: &[u8],
        grant: bool,
    ) -> Result<SyncReport, ClientError> {
        let change = if grant {
            AdminChange::Grant(device_pk.to_vec())
        } else {
            AdminChange::Revoke(device_pk.to_vec())
        };
        self.commit_with(&[], &[change]).await
    }

    /// Leave the group: record this member's leave proposal. Another member
    /// commits it; this member must stop using the group. Returns whether
    /// the group is now vacant (no member left to commit).
    pub async fn leave(&mut self) -> Result<bool, ClientError> {
        let proposal = self.session.propose_leave(&self.identity, &mut OsRng)?;
        let response = self
            .client
            .submit_remove_proposal(&self.gid(), proposal.encoded())
            .await?;
        Ok(response.vacant)
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

    /// Create an invite link valid for `ttl_ms` (admins).
    pub async fn create_invite_link(
        &mut self,
        server_url: &str,
        ttl_ms: u64,
    ) -> Result<InviteLink, ClientError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        rand_core::RngCore::fill_bytes(&mut OsRng, seed.as_mut());
        let invite = self.session.create_invite(
            &self.identity,
            &seed,
            now_ms().saturating_add(ttl_ms),
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

    /// Admit a device directly (admins); the joiner publishes the join.
    pub fn admit(&self, joiner_device_pk: &[u8]) -> Result<SignedAdmission, ClientError> {
        Ok(self
            .session
            .admit(&self.identity, joiner_device_pk, &mut OsRng)?)
    }

    /// Publish this member's display name.
    pub async fn bind_alias(&mut self, alias: &str) -> Result<(), ClientError> {
        let binding = AliasBinding::sign(&self.gid(), alias, &self.identity, &mut OsRng)?;
        self.client
            .bind_alias(&self.gid(), binding.encoded())
            .await?;
        Ok(())
    }

    /// Display names of current members, by leaf (verified bindings only).
    pub async fn aliases(&mut self) -> Result<BTreeMap<Digest, String>, ClientError> {
        let token = self.token().await?;
        let response = self.client.aliases(&self.gid(), &token).await?;
        let mut aliases = BTreeMap::new();
        for binding in response.bindings {
            let Ok(binding) = AliasBinding::decode(&binding) else {
                continue;
            };
            let Ok(leaf) = binding.leaf_id() else {
                continue;
            };
            let current = self
                .session
                .roster()
                .member_by_leaf(&leaf)
                .is_some_and(|member| member.device_pk == binding.device_pk);
            if binding.gid == self.gid() && current {
                aliases.insert(leaf, binding.alias);
            }
        }
        Ok(aliases)
    }

    /// Erase the keys of the previous epoch (end of the grace window).
    pub fn expire_previous_epoch(&mut self) -> Result<(), ClientError> {
        self.session.expire_previous_epoch();
        self.save()
    }
}

fn merge_reports(into: &mut SyncReport, from: SyncReport) {
    into.messages.extend(from.messages);
    into.commits.extend(from.commits);
    into.proposals.extend(from.proposals);
    into.rejected += from.rejected;
    into.removed |= from.removed;
    into.resynced |= from.resynced;
}

async fn resync_session(
    client: &DsClient,
    identity: &DeviceIdentity,
    gid: &Digest,
) -> Result<(GroupSession, u64), ClientError> {
    let mut last_error = ClientError::State("resync did not run");
    for _ in 0..COMMIT_ATTEMPTS {
        let info = client.group_info(gid).await?;
        let (pending, published) = GroupSession::resync(
            identity,
            &snapshot_of(&info),
            &pending_of(&info)?,
            &mut OsRng,
        )?;
        match client
            .publish_commit(gid, &published.commit, &published.group_info)
            .await
        {
            Ok(response) => return Ok((pending.into_session()?, response.seq)),
            Err(error) if error.is_conflict() => last_error = error,
            Err(error) => return Err(error),
        }
    }
    Err(last_error)
}
