use cityg_api_client::CitygApiClient;

pub(crate) const CLIENT_ADMIN_TOKEN_ENV: &str = "CITYG_CLIENT_ADMIN_TOKEN";
pub(crate) const CLIENT_MESSAGE_TOKEN_ENV: &str = "CITYG_CLIENT_MESSAGE_AUTH_TOKEN";
pub(crate) const MESSAGE_AUTH_HEADER: &str = "x-cityg-message-token";

pub(crate) fn read_nonempty_env(var: &str) -> Option<String> {
    std::env::var(var)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn configured_client_admin_token() -> Option<String> {
    read_nonempty_env(CLIENT_ADMIN_TOKEN_ENV)
}

pub(crate) fn configured_client_message_token() -> Option<String> {
    read_nonempty_env(CLIENT_MESSAGE_TOKEN_ENV)
}

pub(crate) fn new_api_client_with_tokens(
    server_url: &str,
    admin_token: Option<String>,
    message_token: Option<String>,
) -> CitygApiClient {
    let mut client = CitygApiClient::new(server_url);
    if let Some(token) = admin_token {
        client = client.with_admin_token(token);
    }
    if let Some(token) = message_token {
        client = client.with_message_auth_token(token);
    }
    client
}

#[allow(dead_code)]
pub(crate) fn new_api_client(server_url: &str) -> CitygApiClient {
    new_api_client_with_tokens(
        server_url,
        configured_client_admin_token(),
        configured_client_message_token(),
    )
}
