use super::{ApiClientError, CategorizedError, ErrorCategory};

pub(super) fn describe_http_failure(
    status_text: &str,
    message: &str,
    freeze_code: Option<u32>,
    freeze_reason: Option<&str>,
) -> String {
    let mut detail = format!("server error ({status_text}): {message}");
    if let Some(code) = freeze_code {
        match freeze_reason {
            Some(reason) => detail.push_str(&format!(" [freeze {code} {reason}]")),
            None => detail.push_str(&format!(" [freeze {code}]")),
        }
    }
    detail
}

pub(super) fn http_error_detail_from_anyhow(err: &anyhow::Error) -> Option<String> {
    for cause in err.chain() {
        if let Some(ApiClientError::HttpStatus {
            status,
            message,
            freeze_code,
            freeze_reason,
            ..
        }) = cause.downcast_ref::<ApiClientError>()
        {
            return Some(describe_http_failure(
                status.as_str(),
                message,
                *freeze_code,
                freeze_reason.as_deref(),
            ));
        }
    }
    None
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

fn api_http_status_from_anyhow(err: &anyhow::Error) -> Option<(u16, String)> {
    for cause in err.chain() {
        if let Some(ApiClientError::HttpStatus {
            status, message, ..
        }) = cause.downcast_ref::<ApiClientError>()
        {
            return Some((status.as_u16(), message.to_lowercase()));
        }
    }
    None
}

pub(super) fn is_stale_server_session_error(err: &anyhow::Error) -> bool {
    let Some((status, message)) = api_http_status_from_anyhow(err) else {
        return false;
    };
    if status == 404 {
        return true;
    }
    status >= 500
        && (message.contains("no anchors accepted for group")
            || message.contains("leaf not present in roster")
            || message.contains("unknown membership root")
            || message.contains("resource not found"))
}

pub(super) fn categorize_error(err: &anyhow::Error, context: &str) -> CategorizedError {
    let err_str = err.to_string().to_lowercase();
    let technical_details =
        http_error_detail_from_anyhow(err).unwrap_or_else(|| flatten_anyhow_chain(err));

    if err_str.contains("connection refused") {
        return CategorizedError::new(
            ErrorCategory::Network,
            "Connection refused",
            technical_details.clone(),
            "The server actively refused the connection. Verify the server URL and ensure the server is running.",
            true,
        );
    }

    if err_str.contains("timeout") {
        return CategorizedError::new(
            ErrorCategory::Network,
            "Connection timeout",
            technical_details.clone(),
            "The server took too long to respond. Check your internet connection or try again later.",
            true,
        );
    }

    if err_str.contains("connection")
        || err_str.contains("dns")
        || err_str.contains("network")
        || err_str.contains("unreachable")
    {
        return CategorizedError::new(
            ErrorCategory::Network,
            "Unable to connect to server",
            technical_details.clone(),
            "Check your internet connection and verify the server URL is correct. The server may be temporarily unavailable.",
            true,
        );
    }

    if err_str.contains("404") || err_str.contains("not found") {
        return CategorizedError::new(
            ErrorCategory::Server,
            "Resource not found",
            technical_details.clone(),
            "The requested resource was not found on the server. The room may not exist or the server URL may be incorrect.",
            false,
        );
    }

    if err_str.contains("room admin proof is required")
        || err_str.contains("room admin proof is not authorized")
    {
        return CategorizedError::new(
            ErrorCategory::Policy,
            "Room admin authorization required",
            technical_details.clone(),
            "This action must be performed by the room's admin identity from a client that already owns that room-admin key.",
            false,
        );
    }

    if err_str.contains("admin token is not configured") {
        return CategorizedError::new(
            ErrorCategory::Policy,
            "Admin authentication required",
            technical_details.clone(),
            "This action requires an operator admin token. Configure CITYG_CLIENT_ADMIN_TOKEN only for server/operator endpoints such as window config or debug APIs.",
            true,
        );
    }

    if err_str.contains("message auth token is not configured") {
        return CategorizedError::new(
            ErrorCategory::Policy,
            "Message authentication required",
            technical_details.clone(),
            "Sending messages requires a configured message auth token. Configure CITYG_CLIENT_MESSAGE_AUTH_TOKEN in the client and the matching message token on the server.",
            true,
        );
    }

    if err_str.contains("401") || err_str.contains("unauthorized") {
        return CategorizedError::new(
            ErrorCategory::Policy,
            "Authentication failed",
            technical_details.clone(),
            "Your credentials were rejected. You may need to rejoin the room with valid credentials.",
            true,
        );
    }

    if err_str.contains("403") || err_str.contains("forbidden") {
        return CategorizedError::new(
            ErrorCategory::Policy,
            "Access denied",
            technical_details.clone(),
            "You don't have permission to perform this action. Contact the room administrator.",
            false,
        );
    }

    if err_str.contains("proof")
        || err_str.contains("crypto")
        || err_str.contains("verification")
        || err_str.contains("witness")
        || err_str.contains("signature")
    {
        return CategorizedError::new(
            ErrorCategory::Crypto,
            "Cryptographic operation failed",
            technical_details.clone(),
            "The cryptographic proof generation or verification failed. This may indicate a system issue or invalid cryptographic parameters. Try rejoining the room.",
            true,
        );
    }

    if err_str.contains("rho_replay") {
        return CategorizedError::new(
            ErrorCategory::Policy,
            "Duplicate message detected",
            technical_details.clone(),
            "This message was already sent and the server prevented a duplicate. No action needed.",
            false,
        );
    }

    if err_str.contains("freeze") {
        return CategorizedError::new(
            ErrorCategory::Policy,
            "Room policy violation",
            technical_details.clone(),
            "The room's security policy prevented this action. You may need to rejoin the room or contact the administrator for details.",
            false,
        );
    }

    if err_str.contains("policy") {
        return CategorizedError::new(
            ErrorCategory::Policy,
            "Policy check failed",
            technical_details.clone(),
            "The action was blocked by a policy check. Ensure you're following room rules and try again.",
            false,
        );
    }

    if err_str.contains("must not be empty") {
        return CategorizedError::new(
            ErrorCategory::Validation,
            "Required field missing",
            technical_details.clone(),
            "One or more required fields are empty. Fill in all required information and try again.",
            false,
        );
    }

    if err_str.contains("invalid") || err_str.contains("not valid") {
        return CategorizedError::new(
            ErrorCategory::Validation,
            "Invalid input",
            technical_details.clone(),
            "Some input data is invalid. Check the format and content of your input fields.",
            false,
        );
    }

    if err_str.contains("required") {
        return CategorizedError::new(
            ErrorCategory::Validation,
            "Missing required information",
            technical_details.clone(),
            "Required information is missing. Please provide all necessary details.",
            false,
        );
    }

    if err_str.contains("500") || err_str.contains("internal server error") {
        return CategorizedError::new(
            ErrorCategory::Server,
            "Internal server error",
            technical_details.clone(),
            "The server encountered an internal error. Please try again in a moment. If the problem persists, the server may need attention.",
            true,
        );
    }

    if err_str.contains("502") || err_str.contains("bad gateway") {
        return CategorizedError::new(
            ErrorCategory::Network,
            "Bad gateway",
            technical_details.clone(),
            "The server received an invalid response from an upstream server. Try again in a moment.",
            true,
        );
    }

    if err_str.contains("503") || err_str.contains("service unavailable") {
        return CategorizedError::new(
            ErrorCategory::Server,
            "Service temporarily unavailable",
            technical_details.clone(),
            "The server is temporarily unable to handle your request. Please try again in a few minutes.",
            true,
        );
    }

    if err_str.contains("server error") {
        return CategorizedError::new(
            ErrorCategory::Server,
            "Server error occurred",
            technical_details.clone(),
            "The server encountered an error. Please try again in a moment. If the problem persists, contact support.",
            true,
        );
    }

    let user_msg = match context {
        "join" => "Failed to join room",
        "send" => "Failed to send message",
        "leave" => "Failed to leave room",
        "fetch" => "Failed to fetch messages",
        _ => "Operation failed",
    };

    CategorizedError::new(
        ErrorCategory::Server,
        user_msg,
        technical_details.clone(),
        "An unexpected error occurred. Please try again or contact support if the issue persists.",
        true,
    )
}
