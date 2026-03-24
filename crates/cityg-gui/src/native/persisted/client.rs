use super::*;

fn read_nonempty_env(var: &str) -> Option<String> {
    std::env::var(var)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(in crate::native) fn configured_client_admin_token() -> Option<String> {
    read_nonempty_env(CLIENT_ADMIN_TOKEN_ENV)
}

pub(in crate::native) fn configured_client_message_token() -> Option<String> {
    read_nonempty_env(CLIENT_MESSAGE_TOKEN_ENV)
}

pub(in crate::native) fn new_api_client(server_url: &str) -> CitygApiClient {
    let mut client = CitygApiClient::new(server_url);
    if let Some(token) = configured_client_admin_token() {
        client = client.with_admin_token(token);
    }
    if let Some(token) = configured_client_message_token() {
        client = client.with_message_auth_token(token);
    }
    client
}
