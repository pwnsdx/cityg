#![forbid(unsafe_code)]
//! Protobuf wire schema of the City-G v0.3 delivery-service API.
//!
//! The schema lives in `proto/cityg_v3.proto`. This crate adds the route
//! table shared by the native server, the Cloudflare Worker and the clients,
//! and the error codes of the API.

/// Generated protobuf messages (`package cityg.v3`).
#[allow(clippy::all, clippy::pedantic, missing_docs)]
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/cityg.v3.rs"));
}

use prost::Message;

/// Profile served by this API.
pub const API_PROFILE_VERSION: &str = "v0.3";
/// Largest request body the API accepts (a commit of the largest tree).
pub const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;
/// Default and largest number of log entries per page.
pub const DEFAULT_LOG_PAGE: u32 = 256;
/// Largest number of log entries per page.
pub const MAX_LOG_PAGE: u32 = 1024;
/// Header carrying the bearer token of a member session.
pub const AUTHORIZATION_HEADER: &str = "authorization";
/// Prefix of the bearer token in the authorization header.
pub const BEARER_PREFIX: &str = "Bearer ";

/// Routes of the v3 API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Route {
    CreateGroup,
    GroupInfo,
    PublishCommit,
    FetchLog,
    SubmitRemoveProposal,
    SubmitJoinRequest,
    JoinStatus,
    PublishInvite,
    GetInvite,
    RevokeInvite,
    SendMessage,
    CoverFailure,
    CoverFailures,
    OpenSession,
    BindAlias,
    Aliases,
    LeafProofs,
}

impl Route {
    /// Every route, in a stable order.
    pub const ALL: [Route; 17] = [
        Route::CreateGroup,
        Route::GroupInfo,
        Route::PublishCommit,
        Route::FetchLog,
        Route::SubmitRemoveProposal,
        Route::SubmitJoinRequest,
        Route::JoinStatus,
        Route::PublishInvite,
        Route::GetInvite,
        Route::RevokeInvite,
        Route::SendMessage,
        Route::CoverFailure,
        Route::CoverFailures,
        Route::OpenSession,
        Route::BindAlias,
        Route::Aliases,
        Route::LeafProofs,
    ];

    /// HTTP path of the route.
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Route::CreateGroup => "/v3/groups/create",
            Route::GroupInfo => "/v3/groups/info",
            Route::PublishCommit => "/v3/groups/commit",
            Route::FetchLog => "/v3/groups/log",
            Route::SubmitRemoveProposal => "/v3/groups/remove_proposal",
            Route::SubmitJoinRequest => "/v3/groups/join_request",
            Route::JoinStatus => "/v3/groups/join_status",
            Route::PublishInvite => "/v3/groups/invite",
            Route::GetInvite => "/v3/groups/invite/get",
            Route::RevokeInvite => "/v3/groups/invite/revoke",
            Route::SendMessage => "/v3/groups/send",
            Route::CoverFailure => "/v3/groups/cover_failure",
            Route::CoverFailures => "/v3/groups/cover_failures",
            Route::OpenSession => "/v3/groups/session",
            Route::BindAlias => "/v3/groups/alias",
            Route::Aliases => "/v3/groups/aliases",
            Route::LeafProofs => "/v3/groups/leaf_proofs",
        }
    }

    /// Route of an HTTP path.
    #[must_use]
    pub fn from_path(path: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|route| route.path() == path)
    }

    /// Whether the route needs a member session token. Routes carrying a
    /// signed protocol object authenticate through that object instead.
    #[must_use]
    pub const fn requires_token(self) -> bool {
        matches!(
            self,
            Route::FetchLog | Route::SendMessage | Route::Aliases | Route::CoverFailures
        )
    }
}

/// First field of every request.
#[derive(Clone, PartialEq, Message)]
struct GidOnly {
    #[prost(bytes = "vec", tag = "1")]
    gid: Vec<u8>,
}

/// Read the group identifier of any request body.
pub fn request_gid(body: &[u8]) -> Result<[u8; 32], ApiError> {
    let decoded = GidOnly::decode(body)
        .map_err(|_| ApiError::new(ErrorCode::BadRequest, "malformed request"))?;
    decoded
        .gid
        .try_into()
        .map_err(|_| ApiError::new(ErrorCode::BadRequest, "gid must be 32 bytes"))
}

/// Error codes of the API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    /// The request does not build on the current state (stale epoch,
    /// existing group, pending removals not committed).
    Conflict,
    /// The requested log position is no longer retained.
    Gone,
    PayloadTooLarge,
    /// A protocol object failed verification.
    Unprocessable,
    TooManyRequests,
    Internal,
}

impl ErrorCode {
    /// HTTP status of the code.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            ErrorCode::BadRequest => 400,
            ErrorCode::Unauthorized => 401,
            ErrorCode::Forbidden => 403,
            ErrorCode::NotFound => 404,
            ErrorCode::Conflict => 409,
            ErrorCode::Gone => 410,
            ErrorCode::PayloadTooLarge => 413,
            ErrorCode::Unprocessable => 422,
            ErrorCode::TooManyRequests => 429,
            ErrorCode::Internal => 500,
        }
    }

    /// Stable machine-readable name of the code.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::Unauthorized => "unauthorized",
            ErrorCode::Forbidden => "forbidden",
            ErrorCode::NotFound => "not_found",
            ErrorCode::Conflict => "conflict",
            ErrorCode::Gone => "gone",
            ErrorCode::PayloadTooLarge => "payload_too_large",
            ErrorCode::Unprocessable => "unprocessable",
            ErrorCode::TooManyRequests => "too_many_requests",
            ErrorCode::Internal => "internal",
        }
    }

    /// Code of an HTTP status (unknown statuses map to `Internal`).
    #[must_use]
    pub const fn from_status(status: u16) -> Self {
        match status {
            400 => ErrorCode::BadRequest,
            401 => ErrorCode::Unauthorized,
            403 => ErrorCode::Forbidden,
            404 => ErrorCode::NotFound,
            409 => ErrorCode::Conflict,
            410 => ErrorCode::Gone,
            413 => ErrorCode::PayloadTooLarge,
            422 => ErrorCode::Unprocessable,
            429 => ErrorCode::TooManyRequests,
            _ => ErrorCode::Internal,
        }
    }
}

/// An API error: a code and a human-readable message.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{}: {message}", code.name())]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
}

impl ApiError {
    /// New error.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Protobuf body of the error.
    #[must_use]
    pub fn to_body(&self) -> Vec<u8> {
        pb::ErrorResponse {
            code: self.code.name().to_string(),
            message: self.message.clone(),
        }
        .encode_to_vec()
    }

    /// Decode an error body received with `status`.
    #[must_use]
    pub fn from_body(status: u16, body: &[u8]) -> Self {
        match pb::ErrorResponse::decode(body) {
            Ok(error) => Self::new(ErrorCode::from_status(status), error.message),
            Err(_) => Self::new(ErrorCode::from_status(status), format!("HTTP {status}")),
        }
    }
}

/// Extract the token of an `Authorization: Bearer <hex>` header value.
#[must_use]
pub fn parse_bearer(value: &str) -> Option<[u8; 32]> {
    let hex = value.strip_prefix(BEARER_PREFIX)?.trim();
    if hex.len() != 64 {
        return None;
    }
    let mut token = [0u8; 32];
    for (index, byte) in token.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(2 * index..2 * index + 2)?, 16).ok()?;
    }
    Some(token)
}

/// `Authorization` header value for `token`.
#[must_use]
pub fn bearer_value(token: &[u8; 32]) -> String {
    let mut value = String::with_capacity(BEARER_PREFIX.len() + 64);
    value.push_str(BEARER_PREFIX);
    for byte in token {
        value.push_str(&format!("{byte:02x}"));
    }
    value
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn routes_round_trip_through_paths() {
        for route in Route::ALL {
            assert_eq!(Route::from_path(route.path()), Some(route));
        }
        assert_eq!(Route::from_path("/v1/members"), None);
        assert_eq!(Route::from_path("/v2/groups/info"), None);
        assert!(!Route::JoinStatus.requires_token());
        assert!(Route::SendMessage.requires_token());
        assert!(!Route::PublishCommit.requires_token());
    }

    #[test]
    fn gid_is_read_from_any_request() {
        let body = pb::SendMessageRequest {
            gid: vec![7; 32],
            envelope: vec![1, 2, 3],
        }
        .encode_to_vec();
        assert_eq!(request_gid(&body).unwrap(), [7; 32]);
        let short = pb::GroupInfoRequest { gid: vec![1; 5] }.encode_to_vec();
        assert_eq!(request_gid(&short).unwrap_err().code, ErrorCode::BadRequest);
        assert!(request_gid(&[0xff, 0xff]).is_err());
    }

    #[test]
    fn errors_and_tokens_encode() {
        for status in [400, 401, 403, 404, 409, 410, 413, 422, 429, 500] {
            let code = ErrorCode::from_status(status);
            assert_eq!(code.status(), status);
            let error = ApiError::new(code, "boom");
            assert_eq!(ApiError::from_body(status, &error.to_body()), error);
            assert!(error.to_string().contains(code.name()));
        }
        assert_eq!(ErrorCode::from_status(418), ErrorCode::Internal);
        assert_eq!(ApiError::from_body(404, &[0xff]).code, ErrorCode::NotFound);
        let token = [0xab; 32];
        assert_eq!(parse_bearer(&bearer_value(&token)), Some(token));
        assert_eq!(parse_bearer("Bearer xyz"), None);
        assert_eq!(parse_bearer("Basic abc"), None);
        assert_eq!(parse_bearer(&format!("Bearer {}", "zz".repeat(32))), None);
    }
}
