//! HTTP client of the v0.3 delivery-service API.

use std::time::Duration;

use cityg_core::CoreError;
use cityg_proto::pb;
use cityg_proto::{ApiError, ErrorCode, Route, bearer_value};
use prost::Message;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};

/// Error of a client operation.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The delivery service refused the request.
    #[error("{0}")]
    Api(#[from] ApiError),
    /// The request did not reach the service or its reply was lost.
    #[error("transport error: {0}")]
    Transport(String),
    /// The reply could not be decoded.
    #[error("decode error: {0}")]
    Decode(String),
    /// A protocol object failed verification or a protocol rule.
    #[error("protocol error: {0}")]
    Protocol(#[from] CoreError),
    /// An invite link could not be parsed.
    #[error("invalid invite link: {0}")]
    InvalidInvite(&'static str),
    /// The local state does not allow the operation.
    #[error("{0}")]
    State(&'static str),
}

impl ClientError {
    /// Code of an API error.
    #[must_use]
    pub fn api_code(&self) -> Option<ErrorCode> {
        match self {
            ClientError::Api(error) => Some(error.code),
            _ => None,
        }
    }

    /// Whether the service reported a conflict (stale epoch, uncommitted
    /// removals, replay): the caller syncs and retries.
    #[must_use]
    pub fn is_conflict(&self) -> bool {
        self.api_code() == Some(ErrorCode::Conflict)
    }
}

/// HTTP client of one delivery service.
#[derive(Clone, Debug)]
pub struct DsClient {
    http: reqwest::Client,
    base_url: String,
}

fn gid_bytes(gid: &[u8; 32]) -> Vec<u8> {
    gid.to_vec()
}

impl DsClient {
    /// Client of the service at `base_url` with a 30 s request timeout.
    pub fn new(base_url: impl Into<String>) -> Result<Self, ClientError> {
        Self::with_timeout(base_url, Duration::from_secs(30))
    }

    /// Client with a custom request timeout.
    pub fn with_timeout(
        base_url: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, ClientError> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        Ok(Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_owned(),
        })
    }

    /// Base URL of the service.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// WebSocket URL of the log-head notifications of `gid`.
    #[must_use]
    pub fn websocket_url(&self, gid: &[u8; 32], token: &[u8; 32]) -> String {
        let base = if let Some(rest) = self.base_url.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = self.base_url.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            self.base_url.clone()
        };
        format!(
            "{base}/v3/ws?gid={}&token={}",
            hex::encode(gid),
            hex::encode(token)
        )
    }

    async fn call<Req: Message, Resp: Message + Default>(
        &self,
        route: Route,
        request: &Req,
        token: Option<&[u8; 32]>,
    ) -> Result<Resp, ClientError> {
        let mut builder = self
            .http
            .post(format!("{}{}", self.base_url, route.path()))
            .header(CONTENT_TYPE, "application/x-protobuf")
            .body(request.encode_to_vec());
        if let Some(token) = token {
            builder = builder.header(AUTHORIZATION, bearer_value(token));
        }
        let response = builder
            .send()
            .await
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        if !(200..300).contains(&status) {
            return Err(ClientError::Api(ApiError::from_body(status, &body)));
        }
        Resp::decode(body.as_ref()).map_err(|error| ClientError::Decode(error.to_string()))
    }

    /// Publish the genesis commit of a new group.
    pub async fn create_group(
        &self,
        gid: &[u8; 32],
        commit: &[u8],
        group_info: &[u8],
    ) -> Result<pb::CreateGroupResponse, ClientError> {
        self.call(
            Route::CreateGroup,
            &pb::CreateGroupRequest {
                gid: gid_bytes(gid),
                commit: commit.to_vec(),
                group_info: group_info.to_vec(),
            },
            None,
        )
        .await
    }

    /// Public state of a group.
    pub async fn group_info(&self, gid: &[u8; 32]) -> Result<pb::GroupInfoResponse, ClientError> {
        self.call(
            Route::GroupInfo,
            &pb::GroupInfoRequest {
                gid: gid_bytes(gid),
            },
            None,
        )
        .await
    }

    /// Publish a commit, the GroupInfo of the epoch it creates and one
    /// welcome per join request it includes.
    pub async fn publish_commit(
        &self,
        gid: &[u8; 32],
        commit: &[u8],
        group_info: &[u8],
        welcomes: &[Vec<u8>],
    ) -> Result<pb::PublishCommitResponse, ClientError> {
        self.call(
            Route::PublishCommit,
            &pb::PublishCommitRequest {
                gid: gid_bytes(gid),
                commit: commit.to_vec(),
                group_info: group_info.to_vec(),
                welcomes: welcomes.to_vec(),
            },
            None,
        )
        .await
    }

    /// Log entries after `after_seq`; commits carry their light-member
    /// proofs when `light` is set.
    pub async fn fetch_log(
        &self,
        gid: &[u8; 32],
        after_seq: u64,
        limit: u32,
        light: bool,
        token: &[u8; 32],
    ) -> Result<pb::FetchLogResponse, ClientError> {
        self.call(
            Route::FetchLog,
            &pb::FetchLogRequest {
                gid: gid_bytes(gid),
                after_seq,
                limit,
                light,
            },
            Some(token),
        )
        .await
    }

    /// Merkle proofs of `leaves` against the current tree hash.
    pub async fn leaf_proofs(
        &self,
        gid: &[u8; 32],
        leaves: &[u32],
    ) -> Result<pb::LeafProofsResponse, ClientError> {
        self.call(
            Route::LeafProofs,
            &pb::LeafProofsRequest {
                gid: gid_bytes(gid),
                leaves: leaves.to_vec(),
            },
            None,
        )
        .await
    }

    /// Record a signed removal proposal.
    pub async fn submit_remove_proposal(
        &self,
        gid: &[u8; 32],
        proposal: &[u8],
    ) -> Result<pb::SubmitRemoveProposalResponse, ClientError> {
        self.call(
            Route::SubmitRemoveProposal,
            &pb::SubmitRemoveProposalRequest {
                gid: gid_bytes(gid),
                proposal: proposal.to_vec(),
            },
            None,
        )
        .await
    }

    /// Record a signed join request.
    pub async fn submit_join_request(
        &self,
        gid: &[u8; 32],
        request: &[u8],
    ) -> Result<pb::SubmitJoinRequestResponse, ClientError> {
        self.call(
            Route::SubmitJoinRequest,
            &pb::SubmitJoinRequestRequest {
                gid: gid_bytes(gid),
                request: request.to_vec(),
            },
            None,
        )
        .await
    }

    /// Where a join request stands; with `light`, the light-join data of
    /// the commit's epoch while it is current.
    pub async fn join_status(
        &self,
        gid: &[u8; 32],
        request_ref: &[u8; 32],
        light: bool,
    ) -> Result<pb::JoinStatusResponse, ClientError> {
        self.call(
            Route::JoinStatus,
            &pb::JoinStatusRequest {
                gid: gid_bytes(gid),
                request_ref: request_ref.to_vec(),
                light,
            },
            None,
        )
        .await
    }

    /// Revoke an invite with an admin-signed revocation.
    pub async fn revoke_invite(
        &self,
        gid: &[u8; 32],
        revocation: &[u8],
    ) -> Result<pb::RevokeInviteResponse, ClientError> {
        self.call(
            Route::RevokeInvite,
            &pb::RevokeInviteRequest {
                gid: gid_bytes(gid),
                revocation: revocation.to_vec(),
            },
            None,
        )
        .await
    }

    /// Store an admin-signed invite; returns its identifier.
    pub async fn publish_invite(
        &self,
        gid: &[u8; 32],
        invite: &[u8],
    ) -> Result<pb::PublishInviteResponse, ClientError> {
        self.call(
            Route::PublishInvite,
            &pb::PublishInviteRequest {
                gid: gid_bytes(gid),
                invite: invite.to_vec(),
            },
            None,
        )
        .await
    }

    /// Fetch an invite by identifier.
    pub async fn get_invite(
        &self,
        gid: &[u8; 32],
        invite_id: &[u8; 32],
    ) -> Result<pb::GetInviteResponse, ClientError> {
        self.call(
            Route::GetInvite,
            &pb::GetInviteRequest {
                gid: gid_bytes(gid),
                invite_id: invite_id.to_vec(),
            },
            None,
        )
        .await
    }

    /// Relay a message envelope.
    pub async fn send(
        &self,
        gid: &[u8; 32],
        envelope: &[u8],
        token: &[u8; 32],
    ) -> Result<pb::SendMessageResponse, ClientError> {
        self.call(
            Route::SendMessage,
            &pb::SendMessageRequest {
                gid: gid_bytes(gid),
                envelope: envelope.to_vec(),
            },
            Some(token),
        )
        .await
    }

    /// Record a cover-failure report.
    pub async fn cover_failure(
        &self,
        gid: &[u8; 32],
        report: &[u8],
    ) -> Result<pb::CoverFailureResponse, ClientError> {
        self.call(
            Route::CoverFailure,
            &pb::CoverFailureRequest {
                gid: gid_bytes(gid),
                report: report.to_vec(),
            },
            None,
        )
        .await
    }

    /// Recorded cover-failure reports.
    pub async fn cover_failures(
        &self,
        gid: &[u8; 32],
        token: &[u8; 32],
    ) -> Result<pb::CoverFailuresResponse, ClientError> {
        self.call(
            Route::CoverFailures,
            &pb::CoverFailuresRequest {
                gid: gid_bytes(gid),
            },
            Some(token),
        )
        .await
    }

    /// Exchange a signed SessionAuth for a bearer token.
    pub async fn open_session(
        &self,
        gid: &[u8; 32],
        auth: &[u8],
    ) -> Result<pb::OpenSessionResponse, ClientError> {
        self.call(
            Route::OpenSession,
            &pb::OpenSessionRequest {
                gid: gid_bytes(gid),
                auth: auth.to_vec(),
            },
            None,
        )
        .await
    }

    /// Store a signed alias binding.
    pub async fn bind_alias(
        &self,
        gid: &[u8; 32],
        binding: &[u8],
    ) -> Result<pb::BindAliasResponse, ClientError> {
        self.call(
            Route::BindAlias,
            &pb::BindAliasRequest {
                gid: gid_bytes(gid),
                binding: binding.to_vec(),
            },
            None,
        )
        .await
    }

    /// Alias bindings of current members.
    pub async fn aliases(
        &self,
        gid: &[u8; 32],
        token: &[u8; 32],
    ) -> Result<pb::AliasesResponse, ClientError> {
        self.call(
            Route::Aliases,
            &pb::AliasesRequest {
                gid: gid_bytes(gid),
            },
            Some(token),
        )
        .await
    }
}
