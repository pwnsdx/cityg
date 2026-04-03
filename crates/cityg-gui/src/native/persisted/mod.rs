use super::*;

mod barrier;
mod client;
mod session;
mod store;

pub(super) use barrier::*;
pub(super) use client::*;
pub(super) use session::*;
pub(super) use store::*;

pub(super) const ROOM_IDENTITY_VERSION: u32 = 1;
pub(super) const ALIAS_STORE_VERSION: u32 = 2;
pub(super) const SECURITY_LOG_VERSION: u32 = 1;
pub(super) const MAX_SECURITY_EVENTS: usize = 128;
pub(super) const MAX_ACTIVITY_EVENTS: usize = 256;
pub(super) const ENCRYPTED_SESSION_ENVELOPE_VERSION: u32 = 1;
pub(super) const ENCRYPTED_SESSION_ALG: &str = "chacha20poly1305";
pub(super) const SESSION_PASSPHRASE_ENV: &str = "CITYG_GUI_SESSION_PASSPHRASE";
pub(super) use crate::client_env::{CLIENT_ADMIN_TOKEN_ENV, CLIENT_MESSAGE_TOKEN_ENV};
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

pub(super) fn default_epoch_rotation_interval() -> u64 {
    300
}

fn default_barrier_n_max() -> u64 {
    DEFAULT_BARRIER_N_MAX
}

fn default_max_barrier_update_bytes() -> u64 {
    0
}

fn default_barrier_recovery_pending() -> bool {
    false
}

fn default_current_barrier_full_verified() -> bool {
    false
}
