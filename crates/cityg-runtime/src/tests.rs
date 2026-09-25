#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cityg_core::admission::{SignedAdmission, SignedInvite, invite_id};
use cityg_core::binding::{AliasBinding, SessionAuth};
use cityg_core::identity::DeviceIdentity;
use cityg_core::join::SignedJoinRequest;
use cityg_core::proposal::SignedRemoveProposal;
use cityg_core::session::{CommitOptions, GroupSession, GroupSnapshot, PublishedCommit};
use cityg_proto::pb;
use cityg_server::{MemoryRoomStore, Room, RoomStore, restore_room};
use prost::Message;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use super::*;

struct Host {
    config: ServiceConfig,
    room: Option<Room>,
    store: MemoryRoomStore,
    sessions: SessionRegistry,
    rng: ChaCha20Rng,
    now: u64,
}

impl Host {
    fn new() -> Self {
        Self {
            config: ServiceConfig {
                compact_every: 4,
                ..ServiceConfig::default()
            },
            room: None,
            store: MemoryRoomStore::new(),
            sessions: SessionRegistry::new(),
            rng: ChaCha20Rng::seed_from_u64(99),
            now: 10_000,
        }
    }

    fn call(
        &mut self,
        route: Route,
        body: &impl Message,
        token: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>, ApiError> {
        let body = body.encode_to_vec();
        let handled = match (route, self.room.as_mut()) {
            (Route::CreateGroup, None) => {
                let (room, handled) = create_room(&body, &self.config, self.now)?;
                self.room = Some(room);
                handled
            }
            (_, Some(room)) => handle_room_request(
                route,
                &body,
                room,
                &mut self.sessions,
                token,
                &self.config,
                self.now,
                &mut self.rng,
            )?,
            (_, None) => return Err(ApiError::new(ErrorCode::NotFound, "no room")),
        };
        if let (Some(record), Some(room)) = (&handled.record, &self.room) {
            persist_record(&mut self.store, room, record, self.config.compact_every)?;
        }
        Ok(handled.body)
    }
}

struct Client {
    identity: DeviceIdentity,
    session: Option<GroupSession>,
    token: Option<[u8; 32]>,
    seq: u64,
    rng: ChaCha20Rng,
}

impl Client {
    fn new(seed: u8) -> Self {
        Self {
            identity: DeviceIdentity::from_seed(&[seed; 32]),
            session: None,
            token: None,
            seq: 0,
            rng: ChaCha20Rng::seed_from_u64(u64::from(seed)),
        }
    }

    fn gid(&self) -> Vec<u8> {
        self.session.as_ref().unwrap().gid().to_vec()
    }

    fn open_session(&mut self, host: &mut Host) {
        let auth = SessionAuth::sign(
            self.session.as_ref().unwrap().gid(),
            host.now,
            &self.identity,
            &mut self.rng,
        )
        .unwrap();
        let response = host
            .call(
                Route::OpenSession,
                &pb::OpenSessionRequest {
                    gid: self.gid(),
                    auth: auth.encoded().to_vec(),
                },
                None,
            )
            .unwrap();
        let response = pb::OpenSessionResponse::decode(response.as_slice()).unwrap();
        self.token = Some(response.token.try_into().unwrap());
    }

    fn sync(&mut self, host: &mut Host) -> Vec<Vec<u8>> {
        let response = host
            .call(
                Route::FetchLog,
                &pb::FetchLogRequest {
                    gid: self.gid(),
                    after_seq: self.seq,
                    limit: 0,
                    light: false,
                },
                self.token.as_ref(),
            )
            .unwrap();
        let page = pb::FetchLogResponse::decode(response.as_slice()).unwrap();
        let mut plaintexts = Vec::new();
        for entry in page.entries {
            self.seq = entry.seq;
            let session = self.session.as_mut().unwrap();
            match entry.body.unwrap() {
                pb::log_entry::Body::Commit(commit) => {
                    if entry.epoch == session.epoch() + 1 {
                        session
                            .process_commit(&commit.commit, Some(&commit.group_info))
                            .unwrap();
                    }
                }
                pb::log_entry::Body::Envelope(envelope) => {
                    if let Ok(message) = session.decrypt(&envelope) {
                        plaintexts.push(message.plaintext);
                    }
                }
                pb::log_entry::Body::Proposal(proposal) => {
                    session.add_pending_removal(&SignedRemoveProposal::decode(&proposal).unwrap());
                }
                pb::log_entry::Body::JoinRequest(request) => {
                    SignedJoinRequest::decode(&request).unwrap();
                }
            }
        }
        plaintexts
    }

    fn send(&mut self, host: &mut Host, text: &[u8]) -> Result<Vec<u8>, ApiError> {
        let envelope = self
            .session
            .as_mut()
            .unwrap()
            .encrypt(&self.identity, 1, b"", text, host.now, &mut self.rng)
            .unwrap();
        host.call(
            Route::SendMessage,
            &pb::SendMessageRequest {
                gid: self.gid(),
                envelope,
            },
            self.token.as_ref(),
        )
    }

    fn info(&self, host: &mut Host) -> pb::GroupInfoResponse {
        info(host, self.gid())
    }

    /// Commit every recorded proposal and publish the commit.
    fn commit(&mut self, host: &mut Host) -> Result<PublishedCommit, ApiError> {
        let info = self.info(host);
        let removals: Vec<SignedRemoveProposal> = info
            .pending_removals
            .iter()
            .map(|bytes| SignedRemoveProposal::decode(bytes).unwrap())
            .collect();
        let joins: Vec<SignedJoinRequest> = info
            .pending_joins
            .iter()
            .map(|bytes| SignedJoinRequest::decode(bytes).unwrap())
            .collect();
        let (pending, published) = self
            .session
            .as_ref()
            .unwrap()
            .commit(
                &self.identity,
                CommitOptions {
                    removals: &removals,
                    joins: &joins,
                    ..CommitOptions::default()
                },
                &mut self.rng,
            )
            .unwrap();
        publish(host, self.gid(), &published)?;
        self.session
            .as_mut()
            .unwrap()
            .apply_own_commit(pending)
            .unwrap();
        Ok(published)
    }
}

fn info(host: &mut Host, gid: Vec<u8>) -> pb::GroupInfoResponse {
    let response = host
        .call(Route::GroupInfo, &pb::GroupInfoRequest { gid }, None)
        .unwrap();
    pb::GroupInfoResponse::decode(response.as_slice()).unwrap()
}

fn publish(host: &mut Host, gid: Vec<u8>, published: &PublishedCommit) -> Result<(), ApiError> {
    host.call(
        Route::PublishCommit,
        &pb::PublishCommitRequest {
            gid,
            commit: published.commit.clone(),
            group_info: published.group_info.clone(),
            welcomes: published.welcomes.clone(),
        },
        None,
    )
    .map(|_| ())
}

fn snapshot(info: &pb::GroupInfoResponse) -> GroupSnapshot {
    GroupSnapshot {
        group_info: info.group_info.clone(),
        tree: info.tree.clone(),
        registry: info.registry.clone(),
    }
}

#[test]
fn a_group_lives_through_the_service() {
    let mut host = Host::new();
    let mut alice = Client::new(1);
    let (pending, genesis) = GroupSession::create(&alice.identity, 8, &mut alice.rng).unwrap();
    let gid = pending.gid().to_vec();
    // The request gid must be the genesis gid.
    assert_eq!(
        host.call(
            Route::CreateGroup,
            &pb::CreateGroupRequest {
                gid: vec![0; 32],
                commit: genesis.commit.clone(),
                group_info: genesis.group_info.clone(),
            },
            None,
        )
        .unwrap_err()
        .code,
        ErrorCode::BadRequest
    );
    let created = host
        .call(
            Route::CreateGroup,
            &pb::CreateGroupRequest {
                gid: gid.clone(),
                commit: genesis.commit.clone(),
                group_info: genesis.group_info.clone(),
            },
            None,
        )
        .unwrap();
    assert_eq!(
        pb::CreateGroupResponse::decode(created.as_slice())
            .unwrap()
            .seq,
        1
    );
    alice.session = Some(pending.into_session().unwrap());
    alice.seq = 1;
    assert_eq!(
        host.call(
            Route::CreateGroup,
            &pb::CreateGroupRequest {
                gid: gid.clone(),
                commit: genesis.commit,
                group_info: genesis.group_info,
            },
            None,
        )
        .unwrap_err()
        .code,
        ErrorCode::Conflict
    );

    // Alice publishes an invite; Bob fetches it by the id of its seed.
    let invite_seed = [5; 32];
    let invite = alice
        .session
        .as_ref()
        .unwrap()
        .create_invite(
            &alice.identity,
            &invite_seed,
            host.now + 60_000,
            2,
            &mut alice.rng,
        )
        .unwrap();
    host.call(
        Route::PublishInvite,
        &pb::PublishInviteRequest {
            gid: gid.clone(),
            invite: invite.encoded().to_vec(),
        },
        None,
    )
    .unwrap();
    let mut bob = Client::new(2);
    let id = invite_id(DeviceIdentity::from_seed(&invite_seed).public_key()).unwrap();
    let fetched = host
        .call(
            Route::GetInvite,
            &pb::GetInviteRequest {
                gid: gid.clone(),
                invite_id: id.to_vec(),
            },
            None,
        )
        .unwrap();
    let fetched = SignedInvite::decode(
        &pb::GetInviteResponse::decode(fetched.as_slice())
            .unwrap()
            .invite,
    )
    .unwrap();
    assert_eq!(
        host.call(
            Route::GetInvite,
            &pb::GetInviteRequest {
                gid: gid.clone(),
                invite_id: vec![0; 32],
            },
            None,
        )
        .unwrap_err()
        .code,
        ErrorCode::NotFound
    );
    let admission = SignedAdmission::with_invite(
        &bob.identity
            .device_id(&gid.clone().try_into().unwrap())
            .unwrap(),
        100,
        &fetched,
        &invite_seed,
        &mut bob.rng,
    )
    .unwrap();
    let info = alice.info(&mut host);
    let (pending, join) = GroupSession::join_external(
        &bob.identity,
        &snapshot(&info),
        admission,
        &[],
        &[],
        &mut bob.rng,
    )
    .unwrap();
    let published = host
        .call(
            Route::PublishCommit,
            &pb::PublishCommitRequest {
                gid: gid.clone(),
                commit: join.commit.clone(),
                group_info: join.group_info.clone(),
                welcomes: Vec::new(),
            },
            None,
        )
        .unwrap();
    let published = pb::PublishCommitResponse::decode(published.as_slice()).unwrap();
    assert_eq!((published.epoch, published.seq), (1, 2));
    bob.session = Some(pending.into_session().unwrap());
    bob.seq = 2;
    // Replaying the same commit is a stale epoch.
    assert_eq!(
        host.call(
            Route::PublishCommit,
            &pb::PublishCommitRequest {
                gid: gid.clone(),
                commit: join.commit,
                group_info: join.group_info,
                welcomes: Vec::new(),
            },
            None,
        )
        .unwrap_err()
        .code,
        ErrorCode::Conflict
    );

    // Traffic needs a session token of a current member.
    assert_eq!(
        alice.send(&mut host, b"no token").unwrap_err().code,
        ErrorCode::Unauthorized
    );
    alice.open_session(&mut host);
    bob.open_session(&mut host);
    assert!(alice.sync(&mut host).is_empty());
    alice.send(&mut host, b"hello bob").unwrap();
    assert_eq!(bob.sync(&mut host), vec![b"hello bob".to_vec()]);

    // Aliases.
    let binding = AliasBinding::sign(
        bob.session.as_ref().unwrap().gid(),
        "bob",
        &bob.identity,
        &mut bob.rng,
    )
    .unwrap();
    host.call(
        Route::BindAlias,
        &pb::BindAliasRequest {
            gid: gid.clone(),
            binding: binding.encoded().to_vec(),
        },
        None,
    )
    .unwrap();
    let aliases = host
        .call(
            Route::Aliases,
            &pb::AliasesRequest { gid: gid.clone() },
            alice.token.as_ref(),
        )
        .unwrap();
    assert_eq!(
        pb::AliasesResponse::decode(aliases.as_slice())
            .unwrap()
            .bindings,
        vec![binding.encoded().to_vec()]
    );

    // Carol asks to join with the same invite; Alice commits her request
    // together with the next commit, and Carol opens her welcome.
    let mut carol = Client::new(3);
    let admission = SignedAdmission::with_invite(
        &carol
            .identity
            .device_id(&gid.clone().try_into().unwrap())
            .unwrap(),
        100,
        &fetched,
        &invite_seed,
        &mut carol.rng,
    )
    .unwrap();
    let (request, secrets) =
        GroupSession::request_join(&carol.identity, &admission, &mut carol.rng).unwrap();
    let response = host
        .call(
            Route::SubmitJoinRequest,
            &pb::SubmitJoinRequestRequest {
                gid: gid.clone(),
                request: request.encoded().to_vec(),
            },
            None,
        )
        .unwrap();
    let response = pb::SubmitJoinRequestResponse::decode(response.as_slice()).unwrap();
    assert_eq!(response.status, "recorded");
    let join_status = |host: &mut Host| {
        let response = host
            .call(
                Route::JoinStatus,
                &pb::JoinStatusRequest {
                    gid: gid.clone(),
                    request_ref: response.request_ref.clone(),
                    light: true,
                },
                None,
            )
            .unwrap();
        pb::JoinStatusResponse::decode(response.as_slice()).unwrap()
    };
    assert_eq!(join_status(&mut host).status, "pending");
    // The invite had two uses: a third joiner is refused.
    let dave = DeviceIdentity::from_seed(&[4; 32]);
    let spent = SignedAdmission::with_invite(
        &dave.device_id(&gid.clone().try_into().unwrap()).unwrap(),
        100,
        &fetched,
        &invite_seed,
        &mut carol.rng,
    )
    .unwrap();
    let (spent, _) = GroupSession::request_join(&dave, &spent, &mut carol.rng).unwrap();
    assert_eq!(
        host.call(
            Route::SubmitJoinRequest,
            &pb::SubmitJoinRequestRequest {
                gid: gid.clone(),
                request: spent.encoded().to_vec(),
            },
            None,
        )
        .unwrap_err()
        .code,
        ErrorCode::Forbidden
    );
    alice.commit(&mut host).unwrap();
    let status = join_status(&mut host);
    assert_eq!(status.status, "committed");
    assert_eq!(status.epoch, status.current_epoch);
    // A light joiner gets its leaf proof, the registry and the occupancies.
    let light_join = cityg_core::light::LightJoin::decode(&status.light_join).unwrap();
    let commit = status.commit.unwrap();
    assert!(light_join.joiner_proof.node.is_some());
    assert_eq!(light_join.members.len(), 3);
    carol.session = Some(
        GroupSession::join_with_welcome(
            &carol.identity,
            &secrets,
            &snapshot(&alice.info(&mut host)),
            &commit.commit,
            &status.welcome,
        )
        .unwrap(),
    );
    carol.seq = host.room.as_ref().unwrap().head_seq();
    bob.sync(&mut host);
    carol.open_session(&mut host);
    alice.send(&mut host, b"hello carol").unwrap();
    assert_eq!(carol.sync(&mut host), vec![b"hello carol".to_vec()]);
    assert_eq!(
        host.call(
            Route::JoinStatus,
            &pb::JoinStatusRequest {
                gid: gid.clone(),
                request_ref: vec![1; 3],
                light: false,
            },
            None,
        )
        .unwrap_err()
        .code,
        ErrorCode::BadRequest
    );

    // Alice revokes the invite.
    let revocation = alice
        .session
        .as_ref()
        .unwrap()
        .revoke_invite(&alice.identity, &id, &mut alice.rng)
        .unwrap();
    let revoked = host
        .call(
            Route::RevokeInvite,
            &pb::RevokeInviteRequest {
                gid: gid.clone(),
                revocation: revocation.encoded().to_vec(),
            },
            None,
        )
        .unwrap();
    assert!(
        pb::RevokeInviteResponse::decode(revoked.as_slice())
            .unwrap()
            .dropped
            .is_empty()
    );

    // Bob leaves; Alice commits the recorded proposal.
    let leave = bob
        .session
        .as_ref()
        .unwrap()
        .propose_leave(&bob.identity, &mut bob.rng)
        .unwrap();
    let response = host
        .call(
            Route::SubmitRemoveProposal,
            &pb::SubmitRemoveProposalRequest {
                gid: gid.clone(),
                proposal: leave.encoded().to_vec(),
            },
            None,
        )
        .unwrap();
    let response = pb::SubmitRemoveProposalResponse::decode(response.as_slice()).unwrap();
    assert_eq!(response.status, "recorded");
    assert_eq!(
        bob.send(&mut host, b"leaving").unwrap_err().code,
        ErrorCode::Forbidden
    );
    assert_eq!(alice.info(&mut host).pending_removals.len(), 1);
    // Recorded during this epoch, the proposal may wait one commit; after
    // that, a commit without it conflicts.
    let empty = |alice: &mut Client| {
        let (pending, published) = alice
            .session
            .as_ref()
            .unwrap()
            .commit(&alice.identity, CommitOptions::default(), &mut alice.rng)
            .unwrap();
        (pending, published)
    };
    let (pending, first) = empty(&mut alice);
    publish(&mut host, gid.clone(), &first).unwrap();
    alice
        .session
        .as_mut()
        .unwrap()
        .apply_own_commit(pending)
        .unwrap();
    let (_, second) = empty(&mut alice);
    assert_eq!(
        publish(&mut host, gid.clone(), &second).unwrap_err().code,
        ErrorCode::Conflict
    );
    alice.commit(&mut host).unwrap();
    // Bob's token died with his membership.
    let error = host
        .call(
            Route::FetchLog,
            &pb::FetchLogRequest {
                gid: gid.clone(),
                after_seq: 0,
                limit: 10,
                light: true,
            },
            bob.token.as_ref(),
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Forbidden);

    // Cover-failure reports are recorded and listed for members.
    let report = alice
        .session
        .as_ref()
        .unwrap()
        .report_cover_failure(
            &alice.identity,
            alice.session.as_ref().unwrap().epoch(),
            cityg_core::cover::CoverFailureReason::StateLost,
            &mut alice.rng,
        )
        .unwrap();
    host.call(
        Route::CoverFailure,
        &pb::CoverFailureRequest {
            gid: gid.clone(),
            report: report.encoded().to_vec(),
        },
        None,
    )
    .unwrap();
    let reports = host
        .call(
            Route::CoverFailures,
            &pb::CoverFailuresRequest { gid: gid.clone() },
            alice.token.as_ref(),
        )
        .unwrap();
    assert_eq!(
        pb::CoverFailuresResponse::decode(reports.as_slice())
            .unwrap()
            .reports
            .len(),
        1
    );

    // The durable state rebuilds the same room.
    let gid32: [u8; 32] = gid.clone().try_into().unwrap();
    let stored = host.store.load(&gid32).unwrap().unwrap();
    assert!(stored.snapshot.is_some(), "compaction happened");
    let restored = restore_room(&stored, host.config.room).unwrap();
    assert_eq!(
        restored.to_snapshot().unwrap(),
        host.room.as_ref().unwrap().to_snapshot().unwrap()
    );
}

#[test]
fn sessions_are_checked() {
    let mut host = Host::new();
    let mut alice = Client::new(3);
    let (pending, genesis) = GroupSession::create(&alice.identity, 4, &mut alice.rng).unwrap();
    let gid = pending.gid().to_vec();
    host.call(
        Route::CreateGroup,
        &pb::CreateGroupRequest {
            gid: gid.clone(),
            commit: genesis.commit,
            group_info: genesis.group_info,
        },
        None,
    )
    .unwrap();
    alice.session = Some(pending.into_session().unwrap());
    let gid32: [u8; 32] = gid.clone().try_into().unwrap();

    // Stale, foreign and non-member session requests are refused.
    let stale = SessionAuth::sign(
        &gid32,
        host.now + 3_600_000,
        &alice.identity,
        &mut alice.rng,
    )
    .unwrap();
    let foreign = SessionAuth::sign(&[9; 32], host.now, &alice.identity, &mut alice.rng).unwrap();
    let stranger = DeviceIdentity::from_seed(&[4; 32]);
    let outsider = SessionAuth::sign(&gid32, host.now, &stranger, &mut alice.rng).unwrap();
    for (auth, code) in [
        (stale, ErrorCode::Unprocessable),
        (foreign, ErrorCode::Unprocessable),
        (outsider, ErrorCode::Forbidden),
    ] {
        let error = host
            .call(
                Route::OpenSession,
                &pb::OpenSessionRequest {
                    gid: gid.clone(),
                    auth: auth.encoded().to_vec(),
                },
                None,
            )
            .unwrap_err();
        assert_eq!(error.code, code);
    }

    alice.open_session(&mut host);
    assert_eq!(host.sessions.len(), 1);
    assert!(!host.sessions.is_empty());
    let unknown = [7u8; 32];
    assert_eq!(
        host.call(
            Route::Aliases,
            &pb::AliasesRequest { gid: gid.clone() },
            Some(&unknown),
        )
        .unwrap_err()
        .code,
        ErrorCode::Unauthorized
    );
    // Tokens expire.
    host.now += host.config.session_ttl_ms + 1;
    assert_eq!(
        host.call(
            Route::Aliases,
            &pb::AliasesRequest { gid: gid.clone() },
            alice.token.as_ref(),
        )
        .unwrap_err()
        .code,
        ErrorCode::Unauthorized
    );
    host.sessions.prune(host.now);
    assert!(host.sessions.is_empty());
    // Malformed bodies are bad requests.
    let room = host.room.as_mut().unwrap();
    let error = handle_room_request(
        Route::PublishCommit,
        &[0xff, 0xff],
        room,
        &mut host.sessions,
        None,
        &host.config,
        host.now,
        &mut host.rng,
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::BadRequest);
}

#[test]
fn leaf_proofs_are_served_against_the_current_tree() {
    let mut host = Host::new();
    let mut alice = Client::new(5);
    let (pending, genesis) = GroupSession::create(&alice.identity, 4, &mut alice.rng).unwrap();
    let gid = pending.gid().to_vec();
    host.call(
        Route::CreateGroup,
        &pb::CreateGroupRequest {
            gid: gid.clone(),
            commit: genesis.commit,
            group_info: genesis.group_info,
        },
        None,
    )
    .unwrap();
    let session = pending.into_session().unwrap();
    let proofs = |host: &mut Host, leaves: Vec<u32>| {
        host.call(
            Route::LeafProofs,
            &pb::LeafProofsRequest {
                gid: gid.clone(),
                leaves,
            },
            None,
        )
    };
    let response =
        pb::LeafProofsResponse::decode(proofs(&mut host, vec![0]).unwrap().as_slice()).unwrap();
    assert_eq!(response.epoch, 0);
    let proof = cityg_core::tree::LeafProof::decode(&response.proofs[0]).unwrap();
    proof.verify(&session.group_context().tree_hash).unwrap();
    assert_eq!(
        proof.node.map(|node| node.device_pk),
        Some(alice.identity.public_key().to_vec())
    );
    assert_eq!(
        proofs(&mut host, vec![1]).unwrap_err().code,
        ErrorCode::Unprocessable
    );
    assert_eq!(
        proofs(&mut host, vec![0; 65]).unwrap_err().code,
        ErrorCode::PayloadTooLarge
    );
}

#[test]
fn errors_map_to_codes() {
    use cityg_core::CoreError;
    use cityg_server::RoomError;
    let cases = [
        (CoreError::Malformed("x"), ErrorCode::BadRequest),
        (CoreError::NonDeterministic("x"), ErrorCode::BadRequest),
        (
            CoreError::EpochMismatch {
                expected: 1,
                got: 2,
            },
            ErrorCode::Conflict,
        ),
        (CoreError::TranscriptMismatch, ErrorCode::Conflict),
        (CoreError::Replay, ErrorCode::Conflict),
        (
            CoreError::Invalid("overdue proposals must be committed"),
            ErrorCode::Conflict,
        ),
        (
            CoreError::Invalid("a request of this device is pending"),
            ErrorCode::Conflict,
        ),
        (CoreError::Unauthorized("x"), ErrorCode::Forbidden),
        (CoreError::TooLarge("x"), ErrorCode::PayloadTooLarge),
        (CoreError::BadSignature("x"), ErrorCode::Unprocessable),
        (CoreError::Invalid("x"), ErrorCode::Unprocessable),
        (CoreError::Decrypt("x"), ErrorCode::Unprocessable),
        (CoreError::Crypto("x"), ErrorCode::Unprocessable),
    ];
    for (error, code) in cases {
        assert_eq!(core_error(error).code, code);
    }
    assert_eq!(
        room_error(RoomError::Forbidden("x")).code,
        ErrorCode::Forbidden
    );
    assert_eq!(
        room_error(RoomError::Limit("x")).code,
        ErrorCode::PayloadTooLarge
    );
    assert_eq!(
        room_error(RoomError::NotFound("x")).code,
        ErrorCode::NotFound
    );
}

#[test]
fn service_limits_follow_the_configuration() {
    let mut config = cityg_config::CityGConfig::default();
    config.server.max_group_size = 32;
    config.server.message_retention_secs = 60;
    config.server.commit_retention_secs = 120;
    config.server.max_log_entries = 10;
    config.server.session_ttl_secs = 5;
    config.server.auth_skew_secs = 7;
    config.server.compact_every = 3;
    let service = ServiceConfig::from_config(&config);
    assert_eq!(service.room.max_capacity, 32);
    assert_eq!(service.room.message_retention_ms, 60_000);
    assert_eq!(service.room.commit_retention_ms, 120_000);
    assert_eq!(service.room.max_log_entries, 10);
    assert_eq!(service.session_ttl_ms, 5_000);
    assert_eq!(service.auth_skew_ms, 7_000);
    assert_eq!(service.compact_every, 3);
    // The defaults of both crates agree.
    assert_eq!(
        ServiceConfig::from_config(&cityg_config::CityGConfig::default()),
        ServiceConfig::default()
    );
}

#[test]
fn native_stores_live_in_memory_or_in_the_state_directory() {
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let alice = DeviceIdentity::from_seed(&[9; 32]);
    let (pending, genesis) = GroupSession::create(&alice, 4, &mut rng).unwrap();
    let gid = *pending.gid();
    let create = pb::CreateGroupRequest {
        gid: gid.to_vec(),
        commit: genesis.commit,
        group_info: genesis.group_info,
    }
    .encode_to_vec();
    let config = ServiceConfig::default();

    let dir = std::env::temp_dir().join(format!("cityg-runtime-store-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    for state_path in [None, Some(dir.join("rooms"))] {
        let mut store = NativeRoomStore::for_state_path(state_path.as_deref()).unwrap();
        let (room, handled) = create_room(&create, &config, 10).unwrap();
        persist_record(
            &mut store,
            &room,
            handled.record.as_ref().unwrap(),
            config.compact_every,
        )
        .unwrap();
        assert_eq!(store.list().unwrap(), vec![gid]);
        let stored = store.load(&gid).unwrap().unwrap();
        let restored = restore_room(&stored, config.room).unwrap();
        assert_eq!(restored.head_seq(), room.head_seq());
    }
    assert!(dir.join("rooms").is_dir());
    let _ = std::fs::remove_dir_all(&dir);
}
