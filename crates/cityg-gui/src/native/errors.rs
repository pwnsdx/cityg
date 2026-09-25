use cityg_api_client::ClientError;
use cityg_api_client::cityg_proto::ErrorCode;

use super::{CategorizedError, ErrorCategory};

/// Code and message of the first delivery-service error in the chain.
fn api_error(err: &anyhow::Error) -> Option<(ErrorCode, &str)> {
    err.chain()
        .find_map(|cause| match cause.downcast_ref::<ClientError>() {
            Some(ClientError::Api(error)) => Some((error.code, error.message.as_str())),
            _ => None,
        })
}

/// First client-side error in the chain.
fn client_error(err: &anyhow::Error) -> Option<&ClientError> {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<ClientError>())
}

fn flatten_anyhow_chain(err: &anyhow::Error) -> String {
    let mut parts: Vec<String> = Vec::new();
    for cause in err.chain() {
        let text = cause.to_string();
        if parts.last() != Some(&text) {
            parts.push(text);
        }
    }
    parts.join(": ")
}

fn fallback_message(context: &str) -> &'static str {
    match context {
        "join" => "Failed to join room",
        "send" => "Failed to send message",
        "leave" => "Failed to leave room",
        "expel" => "Failed to expel member",
        "fetch" => "Failed to fetch messages",
        "room admin" => "Failed to change room admins",
        _ => "Operation failed",
    }
}

/// Map a delivery-service error code to what the user can do about it.
fn categorize_api_error(
    code: ErrorCode,
    message: &str,
    technical_details: String,
    context: &str,
) -> CategorizedError {
    let message = message.to_lowercase();
    match code {
        ErrorCode::Conflict => CategorizedError::new(
            ErrorCategory::Server,
            "The room moved on",
            technical_details,
            "Another member changed the room at the same time. The client synced; try again.",
            true,
        ),
        ErrorCode::Forbidden if message.contains("admin") || context == "room admin" => {
            CategorizedError::new(
                ErrorCategory::Policy,
                "Room admin rights required",
                technical_details,
                "Only a room admin can do this. Ask an admin of the room to grant you admin rights.",
                false,
            )
        }
        ErrorCode::Forbidden => CategorizedError::new(
            ErrorCategory::Policy,
            "Access denied",
            technical_details,
            "The room refused this device. It may have been removed; join again with a new invite.",
            false,
        ),
        ErrorCode::NotFound => CategorizedError::new(
            ErrorCategory::Server,
            "Room not found",
            technical_details,
            "The room or invite does not exist on this server. Check the server URL or ask for a new invite.",
            false,
        ),
        ErrorCode::Unauthorized => CategorizedError::new(
            ErrorCategory::Policy,
            "Session refused",
            technical_details,
            "The server refused this device's session token. The client opens a new session; try again.",
            true,
        ),
        // A server answers 410 on the paths of a retired API version; lost
        // log entries are detected from the log itself and trigger a resync.
        ErrorCode::Gone => CategorizedError::new(
            ErrorCategory::Server,
            "Incompatible server",
            technical_details,
            "The server no longer serves the City-G v0.3 API this client speaks. Use a client and a server of the same profile version.",
            false,
        ),
        ErrorCode::PayloadTooLarge => CategorizedError::new(
            ErrorCategory::Validation,
            "Too large",
            technical_details,
            "The message or the room is over the server's limits. Send a shorter message.",
            false,
        ),
        ErrorCode::Unprocessable => CategorizedError::new(
            ErrorCategory::Crypto,
            "Verification failed",
            technical_details,
            "The server rejected a protocol object that failed verification. Sync and try again; rejoin if it persists.",
            true,
        ),
        ErrorCode::BadRequest => CategorizedError::new(
            ErrorCategory::Validation,
            "Request rejected",
            technical_details,
            "The server could not read the request. Check that client and server run the same protocol version.",
            false,
        ),
        ErrorCode::TooManyRequests => CategorizedError::new(
            ErrorCategory::Network,
            "Rate limited",
            technical_details,
            "The server is throttling requests. Wait a moment and try again.",
            true,
        ),
        ErrorCode::Internal => CategorizedError::new(
            ErrorCategory::Server,
            "Internal server error",
            technical_details,
            "The server encountered an internal error. Try again in a moment.",
            true,
        ),
    }
}

fn categorize_transport(err_str: &str, technical_details: String) -> CategorizedError {
    if err_str.contains("connection refused") {
        return CategorizedError::new(
            ErrorCategory::Network,
            "Connection refused",
            technical_details,
            "The server actively refused the connection. Verify the server URL and ensure the server is running.",
            true,
        );
    }
    if err_str.contains("timeout") || err_str.contains("timed out") {
        return CategorizedError::new(
            ErrorCategory::Network,
            "Connection timeout",
            technical_details,
            "The server took too long to respond. Check your internet connection or try again later.",
            true,
        );
    }
    CategorizedError::new(
        ErrorCategory::Network,
        "Unable to connect to server",
        technical_details,
        "Check your internet connection and verify the server URL is correct. The server may be temporarily unavailable.",
        true,
    )
}

pub(super) fn categorize_error(err: &anyhow::Error, context: &str) -> CategorizedError {
    let err_str = flatten_anyhow_chain(err).to_lowercase();
    let technical_details = flatten_anyhow_chain(err);

    if let Some((code, message)) = api_error(err) {
        return categorize_api_error(code, message, technical_details, context);
    }

    match client_error(err) {
        Some(ClientError::Transport(_)) => {
            return categorize_transport(&err_str, technical_details);
        }
        Some(ClientError::Decode(_)) => {
            return CategorizedError::new(
                ErrorCategory::Server,
                "Unexpected server reply",
                technical_details,
                "The server's reply could not be read. Check that client and server run the same protocol version.",
                true,
            );
        }
        Some(ClientError::Protocol(_)) => {
            return CategorizedError::new(
                ErrorCategory::Crypto,
                "Verification failed",
                technical_details,
                "A protocol object from the server failed verification. Sync again; rejoin the room if it persists.",
                true,
            );
        }
        Some(ClientError::InvalidInvite(_)) => {
            return CategorizedError::new(
                ErrorCategory::Validation,
                "Invalid invite link",
                technical_details,
                "Paste the complete invite link you received (it starts with cityg-invite:).",
                false,
            );
        }
        Some(ClientError::State(_)) => {
            return CategorizedError::new(
                ErrorCategory::Validation,
                fallback_message(context),
                technical_details,
                "This device's room state does not allow that action right now.",
                false,
            );
        }
        Some(ClientError::Api(_)) | None => {}
    }

    if err_str.contains("connection")
        || err_str.contains("dns")
        || err_str.contains("network")
        || err_str.contains("unreachable")
        || err_str.contains("timeout")
    {
        return categorize_transport(&err_str, technical_details);
    }

    if err_str.contains("must not be empty") {
        return CategorizedError::new(
            ErrorCategory::Validation,
            "Required field missing",
            technical_details,
            "One or more required fields are empty. Fill in all required information and try again.",
            false,
        );
    }

    if err_str.contains("invalid") || err_str.contains("not valid") {
        return CategorizedError::new(
            ErrorCategory::Validation,
            "Invalid input",
            technical_details,
            "Some input data is invalid. Check the format and content of your input fields.",
            false,
        );
    }

    CategorizedError::new(
        ErrorCategory::Server,
        fallback_message(context),
        technical_details,
        "An unexpected error occurred. Please try again or contact support if the issue persists.",
        true,
    )
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use cityg_api_client::cityg_proto::ApiError;

    use super::*;

    fn api(code: ErrorCode, message: &str) -> anyhow::Error {
        anyhow::Error::from(ClientError::Api(ApiError::new(code, message))).context("request")
    }

    #[test]
    fn api_errors_map_to_actionable_categories() {
        let cases = [
            (
                ErrorCode::Conflict,
                "stale epoch",
                "The room moved on",
                true,
            ),
            (
                ErrorCode::Forbidden,
                "not an admin",
                "Room admin rights required",
                false,
            ),
            (ErrorCode::Forbidden, "not a member", "Access denied", false),
            (
                ErrorCode::NotFound,
                "unknown group",
                "Room not found",
                false,
            ),
            (ErrorCode::Unauthorized, "expired", "Session refused", true),
            (ErrorCode::Gone, "retired API", "Incompatible server", false),
            (ErrorCode::PayloadTooLarge, "big", "Too large", false),
            (
                ErrorCode::Unprocessable,
                "bad sig",
                "Verification failed",
                true,
            ),
            (
                ErrorCode::BadRequest,
                "malformed",
                "Request rejected",
                false,
            ),
            (
                ErrorCode::TooManyRequests,
                "slow down",
                "Rate limited",
                true,
            ),
            (ErrorCode::Internal, "boom", "Internal server error", true),
        ];
        for (code, message, expected, retryable) in cases {
            let categorized = categorize_error(&api(code, message), "send");
            assert_eq!(categorized.user_message, expected, "{code:?}");
            assert_eq!(categorized.can_retry, retryable, "{code:?}");
            assert!(categorized.technical_details.contains(message));
        }
        let admin = categorize_error(&api(ErrorCode::Forbidden, "denied"), "room admin");
        assert_eq!(admin.category, ErrorCategory::Policy);
        assert_eq!(admin.user_message, "Room admin rights required");
    }

    #[test]
    fn client_errors_are_categorized() {
        let transport =
            |text: &str| categorize_error(&ClientError::Transport(text.to_string()).into(), "join");
        assert_eq!(
            transport("Connection refused").user_message,
            "Connection refused"
        );
        assert_eq!(
            transport("operation timed out").user_message,
            "Connection timeout"
        );
        assert_eq!(
            transport("dns failure").user_message,
            "Unable to connect to server"
        );

        let decode = categorize_error(&ClientError::Decode("x".into()).into(), "fetch");
        assert_eq!(decode.user_message, "Unexpected server reply");
        let protocol = categorize_error(
            &ClientError::Protocol(cityg_api_client::cityg_core::CoreError::Replay).into(),
            "fetch",
        );
        assert_eq!(protocol.category, ErrorCategory::Crypto);
        let invite = categorize_error(&ClientError::InvalidInvite("prefix").into(), "join");
        assert_eq!(invite.user_message, "Invalid invite link");
        let state = categorize_error(&ClientError::State("not joined").into(), "leave");
        assert_eq!(state.user_message, "Failed to leave room");
        assert!(!state.can_retry);
    }

    #[test]
    fn plain_errors_fall_back_to_heuristics() {
        let network = categorize_error(&anyhow!("network unreachable"), "send");
        assert_eq!(network.category, ErrorCategory::Network);
        let empty = categorize_error(&anyhow!("alias must not be empty"), "join");
        assert_eq!(empty.user_message, "Required field missing");
        let invalid = categorize_error(&anyhow!("invalid server url"), "join");
        assert_eq!(invalid.user_message, "Invalid input");
        for (context, expected) in [
            ("join", "Failed to join room"),
            ("send", "Failed to send message"),
            ("leave", "Failed to leave room"),
            ("expel", "Failed to expel member"),
            ("fetch", "Failed to fetch messages"),
            ("room admin", "Failed to change room admins"),
            ("other", "Operation failed"),
        ] {
            assert_eq!(
                categorize_error(&anyhow!("boom"), context).user_message,
                expected
            );
        }
        let chained = anyhow!("inner").context("outer").context("outer");
        assert_eq!(flatten_anyhow_chain(&chained), "outer: inner");
    }
}
