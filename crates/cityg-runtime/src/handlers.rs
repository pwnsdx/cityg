//! Protobuf request handlers over [`Room`].

use cityg_core::CoreError;
use cityg_proto::pb;
use cityg_proto::{ApiError, DEFAULT_LOG_PAGE, ErrorCode, MAX_LOG_PAGE, Route};
use cityg_server::{LogBody, LogEntry, Room, RoomConfig, RoomError, RoomRecord, RoomStore};
use prost::Message;
use rand_core::CryptoRngCore;

use super::sessions::SessionRegistry;

/// Deployment settings of the v2 service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceConfig {
    pub room: RoomConfig,
    /// Lifetime of a session token.
    pub session_ttl_ms: u64,
    /// Accepted clock difference for a SessionAuth.
    pub auth_skew_ms: u64,
    /// Journal length that triggers a compaction.
    pub compact_every: usize,
}

impl ServiceConfig {
    /// The limits of the `[server]` section of `config`.
    #[must_use]
    pub fn from_config(config: &cityg_config::CityGConfig) -> Self {
        let server = &config.server;
        Self {
            room: RoomConfig {
                max_n_max: server.max_group_size,
                message_retention_ms: server.message_retention_secs.saturating_mul(1000),
                commit_retention_ms: server.commit_retention_secs.saturating_mul(1000),
                max_log_entries: server.max_log_entries,
            },
            session_ttl_ms: server.session_ttl_secs.saturating_mul(1000),
            auth_skew_ms: server.auth_skew_secs.saturating_mul(1000),
            compact_every: server.compact_every,
        }
    }
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            room: RoomConfig::default(),
            session_ttl_ms: 3_600_000,
            auth_skew_ms: 300_000,
            compact_every: 256,
        }
    }
}

/// Result of a handled request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handled {
    /// Protobuf response body.
    pub body: Vec<u8>,
    /// Record to journal before replying.
    pub record: Option<RoomRecord>,
    /// New log head, when the request appended to the log.
    pub new_head: Option<u64>,
}

impl Handled {
    fn reply(message: &impl Message) -> Self {
        Self {
            body: message.encode_to_vec(),
            record: None,
            new_head: None,
        }
    }
}

/// API error of a protocol error.
#[must_use]
pub fn core_error(error: CoreError) -> ApiError {
    let code = match &error {
        CoreError::Malformed(_) | CoreError::NonDeterministic(_) => ErrorCode::BadRequest,
        CoreError::EpochMismatch { .. } | CoreError::TranscriptMismatch | CoreError::Replay => {
            ErrorCode::Conflict
        }
        CoreError::Invalid("pending removal proposals must be committed") => ErrorCode::Conflict,
        CoreError::Unauthorized(_) => ErrorCode::Forbidden,
        CoreError::TooLarge(_) => ErrorCode::PayloadTooLarge,
        CoreError::BadSignature(_)
        | CoreError::Invalid(_)
        | CoreError::Decrypt(_)
        | CoreError::Crypto(_) => ErrorCode::Unprocessable,
    };
    ApiError::new(code, error.to_string())
}

/// API error of a room error.
#[must_use]
pub fn room_error(error: RoomError) -> ApiError {
    match error {
        RoomError::Protocol(error) => core_error(error),
        RoomError::Forbidden(message) => ApiError::new(ErrorCode::Forbidden, message),
        RoomError::Limit(message) => ApiError::new(ErrorCode::PayloadTooLarge, message),
        RoomError::NotFound(message) => ApiError::new(ErrorCode::NotFound, message),
    }
}

fn decode<M: Message + Default>(body: &[u8]) -> Result<M, ApiError> {
    M::decode(body).map_err(|_| ApiError::new(ErrorCode::BadRequest, "malformed request"))
}

fn digest(bytes: &[u8], what: &'static str) -> Result<[u8; 32], ApiError> {
    bytes
        .try_into()
        .map_err(|_| ApiError::new(ErrorCode::BadRequest, what))
}

fn log_entry(entry: LogEntry) -> pb::LogEntry {
    pb::LogEntry {
        seq: entry.seq,
        epoch: entry.epoch,
        accepted_at_ms: entry.accepted_at_ms,
        body: Some(match entry.body {
            LogBody::Commit { commit, group_info } => {
                pb::log_entry::Body::Commit(pb::CommitEntry { commit, group_info })
            }
            LogBody::Message { envelope, .. } => pb::log_entry::Body::Envelope(envelope),
            LogBody::Proposal { proposal } => pb::log_entry::Body::Proposal(proposal),
        }),
    }
}

/// Handle `CreateGroup`: build the room of a genesis commit.
pub fn create_room(
    body: &[u8],
    config: &ServiceConfig,
    now_ms: u64,
) -> Result<(Room, Handled), ApiError> {
    let request: pb::CreateGroupRequest = decode(body)?;
    let gid = digest(&request.gid, "gid must be 32 bytes")?;
    let (room, record) = Room::create(&request.commit, &request.group_info, now_ms, config.room)
        .map_err(room_error)?;
    if room.gid() != &gid {
        return Err(ApiError::new(
            ErrorCode::BadRequest,
            "request gid differs from the genesis gid",
        ));
    }
    let head = room.head_seq();
    Ok((
        room,
        Handled {
            body: pb::CreateGroupResponse {
                epoch: 0,
                seq: head,
            }
            .encode_to_vec(),
            record: Some(record),
            new_head: Some(head),
        },
    ))
}

/// Handle a request on an existing room.
#[allow(clippy::too_many_arguments)]
pub fn handle_room_request(
    route: Route,
    body: &[u8],
    room: &mut Room,
    sessions: &mut SessionRegistry,
    bearer: Option<&[u8; 32]>,
    config: &ServiceConfig,
    now_ms: u64,
    rng: &mut impl CryptoRngCore,
) -> Result<Handled, ApiError> {
    let member = if route.requires_token() {
        Some(sessions.check(bearer, room, now_ms)?)
    } else {
        None
    };
    match route {
        Route::CreateGroup => Err(ApiError::new(ErrorCode::Conflict, "group already exists")),
        Route::GroupInfo => {
            let info = room.info().map_err(room_error)?;
            Ok(Handled::reply(&pb::GroupInfoResponse {
                epoch: info.epoch,
                group_info: info.snapshot.group_info,
                tree: info.snapshot.tree,
                roster: info.snapshot.roster,
                pending_removals: info.pending_removals,
                head_seq: info.head_seq,
                vacant: info.vacant,
            }))
        }
        Route::PublishCommit => {
            let request: pb::PublishCommitRequest = decode(body)?;
            let (entry, record) = room
                .publish_commit(&request.commit, &request.group_info, now_ms)
                .map_err(room_error)?;
            room.prune(now_ms);
            Ok(Handled {
                body: pb::PublishCommitResponse {
                    epoch: entry.epoch,
                    seq: entry.seq,
                }
                .encode_to_vec(),
                record: Some(record),
                new_head: Some(entry.seq),
            })
        }
        Route::FetchLog => {
            let request: pb::FetchLogRequest = decode(body)?;
            let limit = match request.limit {
                0 => DEFAULT_LOG_PAGE,
                limit => limit.min(MAX_LOG_PAGE),
            };
            let page = room.log_after(request.after_seq, limit as usize);
            Ok(Handled::reply(&pb::FetchLogResponse {
                entries: page.entries.into_iter().map(log_entry).collect(),
                head_seq: page.head_seq,
                first_seq: page.first_seq,
            }))
        }
        Route::SubmitRemoveProposal => {
            let request: pb::SubmitRemoveProposalRequest = decode(body)?;
            let (status, vacant, record) = room
                .submit_remove_proposal(&request.proposal, now_ms)
                .map_err(room_error)?;
            let new_head = record.as_ref().map(|_| room.head_seq());
            let status = match status {
                cityg_core::ledger::ProposalStatus::Recorded => "recorded",
                cityg_core::ledger::ProposalStatus::AlreadyRecorded => "already_recorded",
            };
            Ok(Handled {
                body: pb::SubmitRemoveProposalResponse {
                    status: status.to_string(),
                    vacant,
                }
                .encode_to_vec(),
                record,
                new_head,
            })
        }
        Route::PublishInvite => {
            let request: pb::PublishInviteRequest = decode(body)?;
            let (id, record) = room
                .publish_invite(&request.invite, now_ms)
                .map_err(room_error)?;
            Ok(Handled {
                body: pb::PublishInviteResponse {
                    invite_id: id.to_vec(),
                }
                .encode_to_vec(),
                record: Some(record),
                new_head: None,
            })
        }
        Route::GetInvite => {
            let request: pb::GetInviteRequest = decode(body)?;
            let id = digest(&request.invite_id, "invite id must be 32 bytes")?;
            let invite = room
                .invite(&id, now_ms)
                .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "invite not found"))?;
            Ok(Handled::reply(&pb::GetInviteResponse { invite }))
        }
        Route::SendMessage => {
            let request: pb::SendMessageRequest = decode(body)?;
            let sender =
                member.ok_or_else(|| ApiError::new(ErrorCode::Unauthorized, "missing token"))?;
            let (entry, record) = room
                .send(&request.envelope, &sender, now_ms)
                .map_err(room_error)?;
            if entry.seq % 64 == 0 {
                room.prune(now_ms);
            }
            Ok(Handled {
                body: pb::SendMessageResponse {
                    epoch: entry.epoch,
                    seq: entry.seq,
                }
                .encode_to_vec(),
                record: Some(record),
                new_head: Some(entry.seq),
            })
        }
        Route::CoverFailure => {
            let request: pb::CoverFailureRequest = decode(body)?;
            let record = room
                .submit_cover_failure(&request.report)
                .map_err(room_error)?;
            Ok(Handled {
                body: pb::CoverFailureResponse {
                    recorded: room.cover_failures().len() as u64,
                }
                .encode_to_vec(),
                record: Some(record),
                new_head: None,
            })
        }
        Route::CoverFailures => Ok(Handled::reply(&pb::CoverFailuresResponse {
            reports: room.cover_failures(),
        })),
        Route::OpenSession => {
            let request: pb::OpenSessionRequest = decode(body)?;
            let (token, expires_at_ms) = sessions.open(
                room,
                &request.auth,
                now_ms,
                config.session_ttl_ms,
                config.auth_skew_ms,
                rng,
            )?;
            Ok(Handled::reply(&pb::OpenSessionResponse {
                token: token.to_vec(),
                expires_at_ms,
            }))
        }
        Route::BindAlias => {
            let request: pb::BindAliasRequest = decode(body)?;
            let record = room.bind_alias(&request.binding).map_err(room_error)?;
            Ok(Handled {
                body: pb::BindAliasResponse {
                    count: room.aliases().len() as u64,
                }
                .encode_to_vec(),
                record: Some(record),
                new_head: None,
            })
        }
        Route::Aliases => Ok(Handled::reply(&pb::AliasesResponse {
            bindings: room.aliases(),
        })),
    }
}

/// Journal `record` of `room`, compacting the journal when it grew past
/// `compact_every` records.
pub fn persist_record<S: RoomStore>(
    store: &mut S,
    room: &Room,
    record: &RoomRecord,
    compact_every: usize,
) -> Result<(), ApiError> {
    let internal = |message: String| ApiError::new(ErrorCode::Internal, message);
    let encoded = record
        .encode()
        .map_err(|error| internal(error.to_string()))?;
    let length = store
        .append(room.gid(), &encoded)
        .map_err(|error| internal(error.to_string()))?;
    if length >= compact_every.max(1) {
        let snapshot = room
            .to_snapshot()
            .map_err(|error| internal(error.to_string()))?;
        store
            .compact(room.gid(), &snapshot)
            .map_err(|error| internal(error.to_string()))?;
    }
    Ok(())
}

/// Room store of a native deployment: in memory, or on disk when the
/// deployment has a state path.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Debug)]
pub enum NativeRoomStore {
    Memory(cityg_server::MemoryRoomStore),
    File(cityg_server::FileRoomStore),
}

#[cfg(not(target_arch = "wasm32"))]
impl NativeRoomStore {
    /// Store in the directory `state_path` (created when missing), or in
    /// memory when there is no state path.
    pub fn for_state_path(state_path: Option<&std::path::Path>) -> std::io::Result<Self> {
        match state_path {
            None => Ok(Self::Memory(cityg_server::MemoryRoomStore::new())),
            Some(path) => cityg_server::FileRoomStore::new(path.to_path_buf())
                .map(Self::File)
                .map_err(|error| std::io::Error::other(error.to_string())),
        }
    }
}

/// Error of [`NativeRoomStore`].
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct NativeRoomStoreError(String);

#[cfg(not(target_arch = "wasm32"))]
impl RoomStore for NativeRoomStore {
    type Error = NativeRoomStoreError;

    fn load(
        &self,
        gid: &cityg_core::hash::Digest,
    ) -> Result<Option<cityg_server::StoredRoom>, Self::Error> {
        match self {
            Self::Memory(store) => store.load(gid).map_err(|error| match error {}),
            Self::File(store) => store
                .load(gid)
                .map_err(|error| NativeRoomStoreError(error.to_string())),
        }
    }

    fn append(
        &mut self,
        gid: &cityg_core::hash::Digest,
        record: &[u8],
    ) -> Result<usize, Self::Error> {
        match self {
            Self::Memory(store) => store.append(gid, record).map_err(|error| match error {}),
            Self::File(store) => store
                .append(gid, record)
                .map_err(|error| NativeRoomStoreError(error.to_string())),
        }
    }

    fn compact(
        &mut self,
        gid: &cityg_core::hash::Digest,
        snapshot: &[u8],
    ) -> Result<(), Self::Error> {
        match self {
            Self::Memory(store) => store.compact(gid, snapshot).map_err(|error| match error {}),
            Self::File(store) => store
                .compact(gid, snapshot)
                .map_err(|error| NativeRoomStoreError(error.to_string())),
        }
    }

    fn list(&self) -> Result<Vec<cityg_core::hash::Digest>, Self::Error> {
        match self {
            Self::Memory(store) => store.list().map_err(|error| match error {}),
            Self::File(store) => store
                .list()
                .map_err(|error| NativeRoomStoreError(error.to_string())),
        }
    }
}
