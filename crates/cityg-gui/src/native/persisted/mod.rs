use super::*;

mod session;
mod store;

pub(super) use session::*;
pub(super) use store::*;

/// Version of the persisted session format (profile v0.2).
pub(super) const SESSION_FORMAT_VERSION: u32 = 2;
pub(super) const HISTORY_VERSION: u32 = 1;
/// Chat messages kept on disk per room.
pub(super) const MAX_PERSISTED_MESSAGES: usize = 500;
pub(super) const ALIAS_STORE_VERSION: u32 = 2;
pub(super) const SECURITY_LOG_VERSION: u32 = 1;
pub(super) const MAX_SECURITY_EVENTS: usize = 128;
pub(super) const MAX_ACTIVITY_EVENTS: usize = 256;
pub(super) const ENCRYPTED_SESSION_ENVELOPE_VERSION: u32 = 1;
pub(super) const ENCRYPTED_SESSION_ALG: &str = "chacha20poly1305";
pub(super) const SESSION_PASSPHRASE_ENV: &str = "CITYG_GUI_SESSION_PASSPHRASE";
pub(super) const SESSION_KEY_DERIVE_CONTEXT: &str = "cityg/gui/session-encryption/v1";
pub(super) const SESSION_LOCAL_KEY_FILE: &str = "session-key-v1.bin";

#[derive(Clone, Copy)]
pub(super) enum SessionKeySource {
    EnvPassphrase,
    LocalKeyFile,
}

impl SessionKeySource {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            SessionKeySource::EnvPassphrase => "env-passphrase",
            SessionKeySource::LocalKeyFile => "local-key-file",
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(super) struct LastSessionPointer {
    pub(super) server_url: String,
    pub(super) room_id: String,
}
