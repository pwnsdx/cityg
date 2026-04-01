use axum::{
    http::{HeaderValue, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};
use cityg_api_schema::{
    BundleCborRequestDecodeError, ExpelMemberTicketRequestValidationError,
    FetchMessagesRequestValidationError, GetBundleRequestValidationError,
    JoinTicketRequestPreparationError, MembersRequestValidationError,
    MergeTicketRequestValidationError, PreparedIdentityBindingError, RoomAdminProofValidationError,
    RoomAdminRequestValidationError, SearchMembersRequestValidationError,
    SendMessageRequestValidationError,
};
use cityg_client::CityGError as ClientError;
use cityg_runtime::{
    BarrierPaginationError, RoomBarrierEnvelopeError, RoomBarrierHelperPreparationError,
    RoomFullVerificationWitnessPreparationError, RoomTicketPreparationError,
    classify_refresh_pivot_conflict,
};
use msphf_orchestrator::{AcceptanceError, mhw::FreezeError};
use serde::Serialize;
use serde_json::to_vec as to_json_vec;
use thiserror::Error;
use tracing::{error, info, warn};

#[derive(Debug, Error)]
pub(crate) enum ApiError {
    #[error("failed to decode protobuf payload: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("server error: {message}")]
    Server {
        message: String,
        freeze: Option<FreezeError>,
        error_label: Option<&'static str>,
        failed_index: Option<u32>,
    },
    #[error("resource not found")]
    NotFound,
    #[error("rate limited")]
    RateLimited,
    #[error("unauthorized: {0}")]
    Unauthorized(&'static str),
}

impl ApiError {
    pub(crate) fn server_message(message: impl Into<String>) -> Self {
        Self::server_with_context(message.into(), None, None, None)
    }

    pub(crate) fn conflict(message: impl Into<String>) -> Self {
        ApiError::Conflict(message.into())
    }

    pub(crate) fn server_with_freeze(message: impl Into<String>, freeze: FreezeError) -> Self {
        Self::server_with_context(message.into(), Some(freeze), None, None)
    }

    pub(crate) fn server_message_with_context(
        message: impl Into<String>,
        error_label: Option<&'static str>,
        failed_index: Option<u32>,
    ) -> Self {
        Self::server_with_context(message.into(), None, error_label, failed_index)
    }

    pub(crate) fn server_with_freeze_context(
        message: impl Into<String>,
        freeze: FreezeError,
        error_label: Option<&'static str>,
        failed_index: Option<u32>,
    ) -> Self {
        Self::server_with_context(message.into(), Some(freeze), error_label, failed_index)
    }

    pub(crate) fn server_with_context(
        message: String,
        freeze: Option<FreezeError>,
        error_label: Option<&'static str>,
        failed_index: Option<u32>,
    ) -> Self {
        ApiError::Server {
            message,
            freeze,
            error_label,
            failed_index,
        }
    }
}

impl From<ClientError> for ApiError {
    fn from(err: ClientError) -> Self {
        match err {
            ClientError::Acceptance(inner) => match inner {
                AcceptanceError::Freeze(freeze) => ApiError::server_with_freeze(
                    format!("acceptance error: {}", freeze.reason),
                    freeze,
                ),
                other => ApiError::server_message(format!("acceptance error: {other:?}")),
            },
            other => ApiError::server_message(other.to_string()),
        }
    }
}

pub(crate) fn map_barrier_helper_error(err: ClientError) -> ApiError {
    match err {
        ClientError::InvalidInput("group not found") => ApiError::NotFound,
        ClientError::InvalidInput("historical barrier public tree snapshot unavailable") => {
            ApiError::NotFound
        }
        ClientError::InvalidInput(message) => ApiError::InvalidRequest(message),
        other => ApiError::from(other),
    }
}

pub(crate) fn map_room_admin_proof_validation_error(
    err: RoomAdminProofValidationError,
) -> ApiError {
    match err {
        RoomAdminProofValidationError::InvalidPublicKeyLength => {
            ApiError::InvalidRequest("invalid room admin public key length")
        }
        RoomAdminProofValidationError::InvalidSignatureLength => {
            ApiError::InvalidRequest("invalid room admin signature length")
        }
        RoomAdminProofValidationError::MissingRoomId => {
            ApiError::InvalidRequest("room_id must be provided")
        }
        RoomAdminProofValidationError::EncodeProofMessage => {
            ApiError::InvalidRequest("failed to encode room admin proof message")
        }
        RoomAdminProofValidationError::InvalidPublicKey => {
            ApiError::InvalidRequest("invalid room admin public key")
        }
        RoomAdminProofValidationError::InvalidSignature => {
            ApiError::InvalidRequest("invalid room admin signature")
        }
        RoomAdminProofValidationError::VerificationFailed => {
            ApiError::InvalidRequest("room admin proof verification failed")
        }
        RoomAdminProofValidationError::MissingKbroadPublic => {
            ApiError::InvalidRequest("kbroad_public must be provided")
        }
        RoomAdminProofValidationError::EncodePayload => {
            ApiError::InvalidRequest("failed to encode room admin proof payload")
        }
        RoomAdminProofValidationError::ReplayKey(message) => ApiError::server_message(message),
    }
}

pub(crate) fn map_room_admin_request_validation_error(
    err: RoomAdminRequestValidationError,
) -> ApiError {
    match err {
        RoomAdminRequestValidationError::MissingRoomId => {
            ApiError::InvalidRequest("room_id must be provided")
        }
        RoomAdminRequestValidationError::InvalidRoomIdEncoding => {
            ApiError::InvalidRequest("room_id must be 64 hex characters")
        }
        RoomAdminRequestValidationError::InvalidRoomIdLength => {
            ApiError::InvalidRequest("room_id must be 32 bytes")
        }
        RoomAdminRequestValidationError::MissingKbroadPublic => {
            ApiError::InvalidRequest("kbroad_public must be provided")
        }
        RoomAdminRequestValidationError::InvalidKbroadPublicLength => {
            ApiError::InvalidRequest("kbroad_public has unexpected length")
        }
        RoomAdminRequestValidationError::InvalidTargetPopPublicKeyLength => {
            ApiError::InvalidRequest("target_pop_public_key has unexpected length")
        }
        RoomAdminRequestValidationError::MissingAdminProof => {
            ApiError::Unauthorized("room admin proof is required")
        }
    }
}

pub(crate) fn map_expel_member_ticket_request_validation_error(
    err: ExpelMemberTicketRequestValidationError,
) -> ApiError {
    match err {
        ExpelMemberTicketRequestValidationError::MissingRoomId => {
            ApiError::InvalidRequest("room_id must be provided")
        }
        ExpelMemberTicketRequestValidationError::InvalidRoomIdEncoding => {
            ApiError::InvalidRequest("room_id must be 64 hex characters")
        }
        ExpelMemberTicketRequestValidationError::InvalidRoomIdLength => {
            ApiError::InvalidRequest("room_id must be 32 bytes")
        }
        ExpelMemberTicketRequestValidationError::InvalidAuthorLeafId => {
            ApiError::InvalidRequest("author_leaf_id must be 32 bytes")
        }
        ExpelMemberTicketRequestValidationError::InvalidTargetLeafId => {
            ApiError::InvalidRequest("target_leaf_id must be 32 bytes")
        }
        ExpelMemberTicketRequestValidationError::MatchingLeafIds => ApiError::InvalidRequest(
            "author_leaf_id and target_leaf_id must differ; use controlled leave instead",
        ),
        ExpelMemberTicketRequestValidationError::MissingAdminProof => {
            ApiError::Unauthorized("room admin proof is required")
        }
    }
}

pub(crate) fn map_merge_ticket_request_validation_error(
    err: MergeTicketRequestValidationError,
) -> ApiError {
    match err {
        MergeTicketRequestValidationError::MissingRoomId => {
            ApiError::InvalidRequest("room_id must be provided")
        }
        MergeTicketRequestValidationError::InvalidRoomIdEncoding => {
            ApiError::InvalidRequest("room_id must be 64 hex characters")
        }
        MergeTicketRequestValidationError::InvalidRoomIdLength => {
            ApiError::InvalidRequest("room_id must be 32 bytes")
        }
        MergeTicketRequestValidationError::InvalidLeafId => {
            ApiError::InvalidRequest("leaf_id must be 32 bytes")
        }
        MergeTicketRequestValidationError::InvalidIntent => {
            ApiError::InvalidRequest("merge ticket intent is invalid")
        }
    }
}

pub(crate) fn map_fetch_messages_request_validation_error(
    err: FetchMessagesRequestValidationError,
) -> ApiError {
    match err {
        FetchMessagesRequestValidationError::InvalidWeEpochId => {
            ApiError::InvalidRequest("we_epoch_id must be 32 bytes")
        }
        FetchMessagesRequestValidationError::InvalidLeafId => {
            ApiError::InvalidRequest("leaf_id must be 32 bytes")
        }
    }
}

pub(crate) fn map_send_message_request_validation_error(
    err: SendMessageRequestValidationError,
) -> ApiError {
    match err {
        SendMessageRequestValidationError::InvalidWeEpochId => {
            ApiError::InvalidRequest("we_epoch_id must be 32 bytes")
        }
        SendMessageRequestValidationError::MissingCiphertext => {
            ApiError::InvalidRequest("ciphertext must be provided")
        }
        SendMessageRequestValidationError::CiphertextTooLarge => {
            ApiError::InvalidRequest("ciphertext exceeds MAX_PAYLOAD_ENVELOPE_BYTES")
        }
        SendMessageRequestValidationError::InvalidSender => {
            ApiError::InvalidRequest("sender must be 32 bytes")
        }
    }
}

pub(crate) fn map_get_bundle_request_validation_error(
    err: GetBundleRequestValidationError,
) -> ApiError {
    match err {
        GetBundleRequestValidationError::InvalidWeEpochId => {
            ApiError::InvalidRequest("we_epoch_id must be 32 bytes")
        }
    }
}

pub(crate) fn map_bundle_cbor_request_decode_error(err: BundleCborRequestDecodeError) -> ApiError {
    match err {
        BundleCborRequestDecodeError::MissingBundleCbor => {
            ApiError::InvalidRequest("bundle_cbor must be provided")
        }
        BundleCborRequestDecodeError::InvalidBundleEncoding => {
            ApiError::InvalidRequest("invalid bundle encoding")
        }
        BundleCborRequestDecodeError::DecodeFailure(message) => ApiError::server_message(message),
    }
}

pub(crate) fn map_members_request_validation_error(err: MembersRequestValidationError) -> ApiError {
    match err {
        MembersRequestValidationError::MissingGid => {
            ApiError::InvalidRequest("gid must be provided")
        }
        MembersRequestValidationError::InvalidGid => {
            ApiError::InvalidRequest("gid must be 32 bytes")
        }
        MembersRequestValidationError::InvalidParentRoot => {
            ApiError::InvalidRequest("parent_root must be 32 bytes")
        }
    }
}

pub(crate) fn map_search_members_request_validation_error(
    err: SearchMembersRequestValidationError,
) -> ApiError {
    match err {
        SearchMembersRequestValidationError::MissingGid => {
            ApiError::InvalidRequest("gid must be provided")
        }
        SearchMembersRequestValidationError::InvalidGid => {
            ApiError::InvalidRequest("gid must be 32 bytes")
        }
        SearchMembersRequestValidationError::MissingQuery => {
            ApiError::InvalidRequest("query must be provided")
        }
        SearchMembersRequestValidationError::InvalidParentRoot => {
            ApiError::InvalidRequest("parent_root must be 32 bytes")
        }
    }
}

pub(crate) fn map_join_ticket_request_preparation_error(
    err: JoinTicketRequestPreparationError,
) -> ApiError {
    match err {
        JoinTicketRequestPreparationError::MissingRoomId => {
            ApiError::InvalidRequest("room_id must be provided")
        }
        JoinTicketRequestPreparationError::InvalidRoomIdEncoding => {
            ApiError::InvalidRequest("room_id must be 64 hex characters")
        }
        JoinTicketRequestPreparationError::InvalidRoomIdLength => {
            ApiError::InvalidRequest("room_id must be 32 bytes")
        }
        JoinTicketRequestPreparationError::RoomIdMismatch => {
            ApiError::InvalidRequest("request room_id does not match routed room")
        }
        JoinTicketRequestPreparationError::IdentityBinding(
            PreparedIdentityBindingError::Validation(validation),
        ) => ApiError::InvalidRequest(validation.api_message()),
        JoinTicketRequestPreparationError::IdentityBinding(
            PreparedIdentityBindingError::ComputeLeaf(message),
        ) => ApiError::server_message(format!("failed to compute leaf_id: {message}")),
    }
}

#[derive(Serialize)]
struct ErrorResponse<'a> {
    message: &'a str,
    freeze_code: Option<u32>,
    freeze_reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed_index: Option<u32>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message, freeze, error_label, failed_index) = match self {
            ApiError::Decode(err) => (StatusCode::BAD_REQUEST, err.to_string(), None, None, None),
            ApiError::InvalidRequest(msg) => {
                (StatusCode::BAD_REQUEST, msg.to_string(), None, None, None)
            }
            ApiError::Conflict(message) => (StatusCode::CONFLICT, message, None, None, None),
            ApiError::NotFound => (
                StatusCode::NOT_FOUND,
                "resource not found".to_string(),
                None,
                None,
                None,
            ),
            ApiError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate limited".to_string(),
                None,
                None,
                None,
            ),
            ApiError::Unauthorized(msg) => {
                (StatusCode::UNAUTHORIZED, msg.to_string(), None, None, None)
            }
            ApiError::Server {
                message,
                freeze,
                error_label,
                failed_index,
            } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                message,
                freeze,
                error_label,
                failed_index,
            ),
        };
        let freeze_code = freeze.map(|f| f.code);
        let freeze_reason = freeze.map(|f| f.reason);
        if status.is_server_error() {
            error!(
                status = %status,
                message = %message,
                freeze_code = ?freeze_code,
                freeze_reason = ?freeze_reason,
                "request failed"
            );
        } else if status == StatusCode::CONFLICT {
            if let Some(reason) = classify_refresh_pivot_conflict(&message) {
                info!(
                    status = %status,
                    message = %message,
                    conflict_reason = reason,
                    freeze_code = ?freeze_code,
                    freeze_reason = ?freeze_reason,
                    "request conflict"
                );
            } else {
                warn!(
                    status = %status,
                    message = %message,
                    freeze_code = ?freeze_code,
                    freeze_reason = ?freeze_reason,
                    "request failed"
                );
            }
        } else {
            warn!(
                status = %status,
                message = %message,
                freeze_code = ?freeze_code,
                freeze_reason = ?freeze_reason,
                "request failed"
            );
        }
        let body = ErrorResponse {
            message: &message,
            freeze_code,
            freeze_reason,
            error: error_label,
            failed_index,
        };
        let payload = to_json_vec(&body).unwrap_or_else(|e| {
            error!("failed to serialize error body: {}", e);
            r#"{"message":"Internal server error"}"#.as_bytes().to_vec()
        });
        let mut response = (status, payload).into_response();
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        response
    }
}

pub(crate) fn classify_concurrency_pressure(
    message: &str,
    freeze_reason: Option<&'static str>,
) -> Option<&'static str> {
    let lowered = message.to_ascii_lowercase();
    let freeze_lowered = freeze_reason.unwrap_or_default().to_ascii_lowercase();
    if lowered.contains("window full")
        || freeze_lowered.contains("window_full")
        || freeze_lowered.contains("mhw/window")
    {
        return Some("window_full");
    }
    if lowered.contains("mh_heads_invalid") || freeze_lowered.contains("mh_heads_invalid") {
        return Some("mh_heads_invalid");
    }
    if lowered.contains("barrier_version") || lowered.contains("barrier version") {
        return Some("barrier_version");
    }
    if lowered.contains("barrier update required on revocation change") {
        return Some("revocation_change");
    }
    None
}

fn record_concurrency_pressure(endpoint: &'static str, reason: &'static str) {
    metrics::counter!(
        "cityg_concurrency_pressure_total",
        "endpoint" => endpoint,
        "reason" => reason
    )
    .increment(1);
}

pub(crate) fn maybe_record_api_concurrency_error(endpoint: &'static str, err: &ApiError) {
    if let ApiError::Server {
        message, freeze, ..
    } = err
        && let Some(reason) = classify_concurrency_pressure(message, freeze.map(|f| f.reason))
    {
        record_concurrency_pressure(endpoint, reason);
    }
}

pub(crate) fn maybe_record_client_concurrency_error(endpoint: &'static str, err: &ClientError) {
    match err {
        ClientError::InvalidInput(message) => {
            if let Some(reason) = classify_concurrency_pressure(message, None) {
                record_concurrency_pressure(endpoint, reason);
            }
        }
        ClientError::Acceptance(AcceptanceError::Freeze(freeze)) => {
            if let Some(reason) = classify_concurrency_pressure(freeze.reason, Some(freeze.reason))
            {
                record_concurrency_pressure(endpoint, reason);
            }
        }
        ClientError::Acceptance(inner) => {
            let message = format!("{inner:?}");
            if let Some(reason) = classify_concurrency_pressure(&message, None) {
                record_concurrency_pressure(endpoint, reason);
            }
        }
        _ => {}
    }
}

pub(crate) fn map_room_ticket_preparation_error(
    endpoint: &'static str,
    err: RoomTicketPreparationError,
) -> ApiError {
    match err {
        RoomTicketPreparationError::Client(err) => {
            maybe_record_client_concurrency_error(endpoint, &err);
            ApiError::from(err)
        }
        other => ApiError::server_message(other.to_string()),
    }
}

pub(crate) fn map_room_barrier_envelope_error(
    endpoint: &'static str,
    err: RoomBarrierEnvelopeError,
) -> ApiError {
    match err {
        RoomBarrierEnvelopeError::Client(err) => {
            maybe_record_client_concurrency_error(endpoint, &err);
            ApiError::from(err)
        }
        other => ApiError::server_message(other.to_string()),
    }
}

pub(crate) fn map_barrier_pagination_error(err: BarrierPaginationError) -> ApiError {
    match err {
        BarrierPaginationError::MaxEntriesExceedsLimit => {
            ApiError::InvalidRequest("max_entries exceeds MAX_BARRIER_HELPER_PAGE_ENTRIES")
        }
        BarrierPaginationError::PageOffsetOutOfRange => {
            ApiError::InvalidRequest("page_offset out of range")
        }
        BarrierPaginationError::MaxEntriesOutOfRange => {
            ApiError::InvalidRequest("max_entries out of range")
        }
        BarrierPaginationError::TotalEntriesOverflow
        | BarrierPaginationError::NextPageOffsetOverflow => {
            ApiError::server_message(err.to_string())
        }
    }
}

pub(crate) fn map_room_barrier_helper_preparation_error(
    endpoint: &'static str,
    err: RoomBarrierHelperPreparationError,
) -> ApiError {
    match err {
        RoomBarrierHelperPreparationError::Client(err) => map_barrier_helper_error(err),
        RoomBarrierHelperPreparationError::Envelope(err) => {
            map_room_barrier_envelope_error(endpoint, err)
        }
        RoomBarrierHelperPreparationError::Pagination(err) => map_barrier_pagination_error(err),
    }
}

pub(crate) fn map_full_verification_witness_preparation_error(
    endpoint: &'static str,
    err: RoomFullVerificationWitnessPreparationError,
) -> ApiError {
    match err {
        RoomFullVerificationWitnessPreparationError::Client(err) => ApiError::from(err),
        RoomFullVerificationWitnessPreparationError::HelperClient(err) => {
            map_barrier_helper_error(err)
        }
        RoomFullVerificationWitnessPreparationError::Ticket(err) => {
            map_room_ticket_preparation_error(endpoint, err)
        }
        RoomFullVerificationWitnessPreparationError::GroupNotFound => {
            ApiError::InvalidRequest("group not found")
        }
        RoomFullVerificationWitnessPreparationError::CurrentHistoryCommitmentMismatch => {
            ApiError::InvalidRequest(
                "current_history_commitment mismatch with authenticated current state",
            )
        }
        RoomFullVerificationWitnessPreparationError::JoinsPrevBarrierVersionMismatch => {
            ApiError::InvalidRequest(
                "joins_prev_barrier_version mismatch with authenticated current state",
            )
        }
        RoomFullVerificationWitnessPreparationError::GlobalHistoryAttestationMismatch => {
            ApiError::InvalidRequest(
                "current_global_history_attestation mismatch with authenticated current state",
            )
        }
        RoomFullVerificationWitnessPreparationError::DeploymentProfileManifestMismatch => {
            ApiError::InvalidRequest(
                "deployment_profile_manifest mismatch with authenticated current state",
            )
        }
        RoomFullVerificationWitnessPreparationError::MergeTicketArtifactMismatch => {
            ApiError::InvalidRequest(
                "merge_ticket_artifact mismatch with authenticated current state",
            )
        }
        RoomFullVerificationWitnessPreparationError::RevocationRootsHashMismatch => {
            ApiError::InvalidRequest(
                "revocation_roots_hash mismatch with authenticated current state",
            )
        }
        RoomFullVerificationWitnessPreparationError::JoinHelperDataMismatch => {
            ApiError::InvalidRequest("join helper data mismatch with authenticated current state")
        }
        RoomFullVerificationWitnessPreparationError::RevokedHelperDataMismatch => {
            ApiError::InvalidRequest(
                "revoked helper data mismatch with authenticated current state",
            )
        }
        RoomFullVerificationWitnessPreparationError::CoverLeafIndexOutOfRange => {
            ApiError::InvalidRequest("cover_leaf_index out of range")
        }
    }
}
