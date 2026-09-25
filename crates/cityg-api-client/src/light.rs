//! Light member driver: a [`LightSession`] with the delivery-service client.
//!
//! A light member keeps no public tree (see [`cityg_core::light`]). It
//! follows the log like a full member, with the Merkle proofs the delivery
//! service attaches to each commit, and proves the leaves of message senders
//! it does not know yet with [`DsClient::leaf_proofs`] (messages from them
//! wait until the end of the sync, when the proofs are against the current
//! tree). To commit, it becomes a full member for the time of the commit:
//! [`LightMember::upgrade`], then [`Member::into_light`].
//!
//! A light member that falls too far behind (a commit it needs left the log)
//! or cannot process a commit re-enters with a resync, which needs the
//! snapshot, and turns light again.

use std::collections::{BTreeMap, BTreeSet};

use cityg_core::CoreError;
use cityg_core::admission::SignedAdmission;
use cityg_core::binding::AliasBinding;
use cityg_core::cbor::{
    array, bytes, decode, encode, expect_array, expect_bytes, expect_label, expect_list,
    expect_uint, text, uint,
};
use cityg_core::cover::CoverFailureReason;
use cityg_core::hash::Digest;
use cityg_core::identity::DeviceIdentity;
use cityg_core::join::{JoinSecrets, SignedJoinRequest};
use cityg_core::light::{LightCommit, LightJoin, LightSession};
use cityg_core::proposal::SignedRemoveProposal;
use cityg_core::session::ProcessedCommit;
use cityg_core::tree::{LeafProof, MemberRef};
use cityg_proto::{ErrorCode, MAX_LOG_PAGE, pb};
use rand_core::OsRng;
use zeroize::Zeroizing;

use super::client::{ClientError, DsClient};
use super::invite::InviteLink;
use super::member::{
    COMMIT_ATTEMPTS, CONTENT_TYPE_TEXT, CachedToken, Member, SentMessage, StateSink, SyncReport,
    admission_for_invite, commit_seq, fetch_page, now_ms, session_token, snapshot_of,
};

const LIGHT_MEMBER_LABEL: &str = "city-g/light-member/v1";
/// Envelopes kept at most while their senders' keys are being proven.
const MAX_DEFERRED: usize = 1024;
/// Leaves proven per request.
const PROOFS_PER_REQUEST: usize = 64;

/// One device's light membership in one group.
pub struct LightMember {
    client: DsClient,
    identity: DeviceIdentity,
    session: LightSession,
    log_seq: u64,
    token: CachedToken,
    /// Envelopes whose sender's device key is not proven yet.
    deferred: Vec<Vec<u8>>,
    sink: Option<StateSink>,
}

impl core::fmt::Debug for LightMember {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LightMember")
            .field("gid", &hex::encode(self.session.gid()))
            .field("epoch", &self.session.epoch())
            .field("log_seq", &self.log_seq)
            .finish_non_exhaustive()
    }
}

impl LightMember {
    pub(crate) fn assemble(
        client: DsClient,
        identity: DeviceIdentity,
        session: LightSession,
        log_seq: u64,
        token: CachedToken,
        sink: Option<StateSink>,
    ) -> Self {
        Self {
            client,
            identity,
            session,
            log_seq,
            token,
            deferred: Vec::new(),
            sink,
        }
    }

    /// Join through an invite link as a light member.
    pub async fn join_with_invite(
        client: DsClient,
        identity: DeviceIdentity,
        link: &InviteLink,
    ) -> Result<Self, ClientError> {
        let admission = admission_for_invite(&client, &identity, link).await?;
        Self::join_with_admission(client, identity, &link.gid, admission).await
    }

    /// Join with an admission as a light member: when a commit includes the
    /// request while it is still the latest one, the joiner enters with its
    /// welcome and the light-join data, without the public tree; otherwise
    /// it enters like a full member and turns light.
    pub async fn join_with_admission(
        client: DsClient,
        identity: DeviceIdentity,
        gid: &Digest,
        admission: SignedAdmission,
    ) -> Result<Self, ClientError> {
        Member::join_light(client, identity, gid, admission).await
    }

    /// Enter with the welcome of a committed request, if the delivery service
    /// gave the light-join data (the commit's epoch is still the current one).
    pub(crate) async fn enter_with_welcome(
        client: DsClient,
        identity: DeviceIdentity,
        secrets: &JoinSecrets,
        status: &pb::JoinStatusResponse,
    ) -> Result<Option<Self>, ClientError> {
        let Some(commit) = &status.commit else {
            return Ok(None);
        };
        if status.light_join.is_empty() {
            return Ok(None);
        }
        let join = LightJoin::decode(&status.light_join)?;
        let session = LightSession::join_with_welcome(
            &identity,
            secrets,
            &commit.commit,
            &commit.group_info,
            &status.welcome,
            &join,
        )?;
        let mut token = None;
        let gid = *session.gid();
        let log_seq = commit_seq(&client, &identity, &gid, &mut token, status.epoch).await?;
        Ok(Some(Self::assemble(
            client, identity, session, log_seq, token, None,
        )))
    }

    /// Become a full member with the snapshot of the current epoch (to
    /// commit): catch up, fetch the snapshot, check it against the light
    /// state.
    pub async fn upgrade(mut self) -> Result<Member, ClientError> {
        let gid = self.gid();
        for _ in 0..COMMIT_ATTEMPTS {
            if self.sync().await?.removed {
                return Err(ClientError::State("this member was removed"));
            }
            let info = self.client.group_info(&gid).await?;
            if info.epoch != self.session.epoch() {
                continue;
            }
            let session = self.session.clone().upgrade(&snapshot_of(&info))?;
            let mut member =
                Member::from_session(self.client, self.identity, session, self.log_seq)?;
            if let Some(sink) = self.sink {
                member.set_state_sink(sink);
            }
            return Ok(member);
        }
        Err(ClientError::State(
            "the group kept moving during the upgrade",
        ))
    }

    /// Install the sink that persists the member state.
    pub fn set_state_sink(&mut self, sink: StateSink) {
        self.sink = Some(sink);
    }

    /// Persist the member state through the sink, if any.
    pub fn save(&self) -> Result<(), ClientError> {
        if let Some(sink) = &self.sink {
            let exported = self.export()?;
            sink(&exported)
                .map_err(|_| ClientError::State("failed to persist the member state"))?;
        }
        Ok(())
    }

    /// Export the member (session secrets included) for encrypted storage.
    pub fn export(&self) -> Result<Zeroizing<Vec<u8>>, ClientError> {
        let session = self.session.export()?;
        Ok(Zeroizing::new(encode(&array(vec![
            text(LIGHT_MEMBER_LABEL),
            bytes(&session),
            uint(self.log_seq),
            array(
                self.deferred
                    .iter()
                    .map(|envelope| bytes(envelope))
                    .collect(),
            ),
        ]))?))
    }

    /// Restore a member from [`LightMember::export`].
    pub fn restore(
        client: DsClient,
        identity: DeviceIdentity,
        exported: &[u8],
    ) -> Result<Self, ClientError> {
        let mut items = expect_array(
            decode(exported, 128 << 20, "light member")?,
            4,
            "light member",
        )?
        .into_iter();
        let mut next = || items.next().ok_or(CoreError::Malformed("light member"));
        expect_label(&next()?, LIGHT_MEMBER_LABEL, "light member")?;
        let session = LightSession::import(&Zeroizing::new(expect_bytes(
            next()?,
            "light member session",
        )?))?;
        if session.known_key(session.me()) != Some(identity.public_key()) {
            return Err(ClientError::State(
                "exported member belongs to another device",
            ));
        }
        let log_seq = expect_uint(&next()?, "light member log position")?;
        let deferred = expect_list(next()?, "light member deferred")?
            .into_iter()
            .map(|envelope| expect_bytes(envelope, "light member envelope"))
            .collect::<Result<Vec<_>, _>>()?;
        let mut member = Self::assemble(client, identity, session, log_seq, None, None);
        member.deferred = deferred;
        Ok(member)
    }

    /// The light session.
    #[must_use]
    pub fn session(&self) -> &LightSession {
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

    /// Envelopes waiting for their sender's key to be proven.
    #[must_use]
    pub fn deferred_messages(&self) -> usize {
        self.deferred.len()
    }

    /// A valid session token, opening a new session when needed.
    pub async fn token(&mut self) -> Result<[u8; 32], ClientError> {
        let gid = self.gid();
        session_token(&self.client, &self.identity, &gid, &mut self.token).await
    }

    /// Follow the log: process commits with their proofs, decrypt messages
    /// (proving unknown senders at the end), record proposals.
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
        let gid = self.gid();
        loop {
            let page = match fetch_page(
                &self.client,
                &self.identity,
                &gid,
                &mut self.token,
                self.log_seq,
                true,
            )
            .await
            {
                Ok(page) => page,
                // A removed member's token is refused: it learns its
                // removal from its leaf.
                Err(error) if error.api_code() == Some(ErrorCode::Forbidden) => {
                    if !self.still_in_leaf().await? {
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
                break;
            }
        }
        self.open_deferred(&mut report).await?;
        Ok(report)
    }

    /// Whether the delivery service still shows this device in its leaf (an
    /// unverified hint, used once its token was refused).
    async fn still_in_leaf(&self) -> Result<bool, ClientError> {
        let me = self.session.me();
        let response = self.client.leaf_proofs(&self.gid(), &[me.leaf]).await?;
        Ok(response
            .proofs
            .first()
            .map(|proof| LeafProof::decode(proof))
            .transpose()?
            .and_then(|proof| proof.node)
            .is_some_and(|node| {
                node.since == me.since && node.device_pk == self.identity.public_key()
            }))
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
                let processed = LightCommit::decode(&commit.light).and_then(|proofs| {
                    self.session
                        .process_commit(&commit.commit, Some(&commit.group_info), &proofs)
                });
                match processed {
                    Ok(ProcessedCommit::Advanced(summary)) => {
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
                let sender = cityg_core::message::Envelope::decode(&envelope)
                    .map(|decoded| decoded.header.sender)
                    .ok();
                if sender == Some(self.session.me()) {
                    return Ok(());
                }
                if self
                    .session
                    .unknown_sender(&envelope)
                    .ok()
                    .flatten()
                    .is_some()
                {
                    if self.deferred.len() < MAX_DEFERRED {
                        self.deferred.push(envelope);
                    } else {
                        report.rejected += 1;
                    }
                    return Ok(());
                }
                match self.session.decrypt(&envelope) {
                    Ok(message) => report.messages.push(message),
                    Err(_) => report.rejected += 1,
                }
            }
            Some(pb::log_entry::Body::Proposal(proposal)) => {
                self.log_seq = seq;
                let proposal = SignedRemoveProposal::decode(&proposal)?;
                if self.session.add_pending_removal(&proposal).is_some() {
                    report.proposals.push(proposal);
                }
            }
            Some(pb::log_entry::Body::JoinRequest(request)) => {
                self.log_seq = seq;
                report
                    .join_requests
                    .push(SignedJoinRequest::decode(&request)?);
            }
            None => self.log_seq = seq,
        }
        Ok(())
    }

    /// Prove the senders of the deferred envelopes against the current tree
    /// and open them. When the group moved on meanwhile, they wait for the
    /// next sync.
    async fn open_deferred(&mut self, report: &mut SyncReport) -> Result<(), ClientError> {
        if self.deferred.is_empty() {
            return Ok(());
        }
        let gid = self.gid();
        let unknown: BTreeSet<u32> = self
            .deferred
            .iter()
            .filter_map(|envelope| self.session.unknown_sender(envelope).ok().flatten())
            .map(|sender| sender.leaf)
            .collect();
        let unknown: Vec<u32> = unknown.into_iter().collect();
        for leaves in unknown.chunks(PROOFS_PER_REQUEST) {
            let response = self.client.leaf_proofs(&gid, leaves).await?;
            if response.epoch != self.session.epoch() {
                return Ok(());
            }
            let proofs = response
                .proofs
                .iter()
                .map(|proof| LeafProof::decode(proof))
                .collect::<Result<Vec<_>, _>>()?;
            self.session.learn_members(&proofs)?;
        }
        for envelope in std::mem::take(&mut self.deferred) {
            match self.session.decrypt(&envelope) {
                Ok(message) => report.messages.push(message),
                Err(_) => report.rejected += 1,
            }
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
        let member =
            Member::resync_from_scratch(self.client.clone(), self.identity.clone(), &gid).await?;
        let light = member.into_light()?;
        self.session = light.session;
        self.log_seq = light.log_seq;
        self.deferred.clear();
        report.resynced = true;
        self.save()
    }

    /// Leave the group: record this member's leave proposal.
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

    /// Publish this member's display name.
    pub async fn bind_alias(&mut self, alias: &str) -> Result<(), ClientError> {
        let binding = AliasBinding::sign(&self.gid(), alias, &self.identity, &mut OsRng)?;
        self.client
            .bind_alias(&self.gid(), binding.encoded())
            .await?;
        Ok(())
    }

    /// Display names of the members whose device keys this member verified,
    /// by occupancy.
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
            if let Some(member) = self.session.member_with_key(&binding.device_pk) {
                aliases.insert(member, binding.alias);
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
