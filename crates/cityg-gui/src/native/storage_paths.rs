#[cfg(test)]
use std::cell::RefCell;
use std::path::PathBuf;
#[cfg(not(test))]
use std::sync::{LazyLock, Mutex};

use super::*;
use dirs::config_dir;

pub(super) fn session_file_path(server_url: &str, room_id: &str) -> Result<PathBuf> {
    let base = session_dir()?;
    let hash = session_key_hash(server_url, room_id)?;
    Ok(base.join(format!("session-{}.json", hash)))
}

pub(super) fn room_identity_file_path(server_url: &str, room_id: &str) -> Result<PathBuf> {
    let base = session_dir()?;
    let hash = session_key_hash(server_url, room_id)?;
    Ok(base.join(format!("room-identity-{}.json", hash)))
}

pub(super) fn roster_file_path(server_url: &str, room_id: &str) -> Result<PathBuf> {
    let base = session_dir()?;
    let hash = session_key_hash(server_url, room_id)?;
    Ok(base.join(format!("roster-{}.json", hash)))
}

pub(super) fn security_log_file_path(server_url: &str, room_id: &str) -> Result<PathBuf> {
    let base = session_dir()?;
    let hash = session_key_hash(server_url, room_id)?;
    Ok(base.join(format!("security-log-{}.json", hash)))
}

pub(super) fn last_session_pointer_path() -> Result<PathBuf> {
    Ok(session_dir()?.join("last-session.json"))
}

pub(super) fn session_dir() -> Result<PathBuf> {
    #[cfg(test)]
    if let Some(path) = CONFIG_DIR_OVERRIDE.with(|override_path| override_path.borrow().clone()) {
        return Ok(path);
    }

    #[cfg(not(test))]
    if let Some(path) = CONFIG_DIR_OVERRIDE
        .lock()
        .map_err(|_| anyhow!("Failed to acquire config dir lock"))?
        .clone()
    {
        return Ok(path);
    }

    if let Ok(override_path) = std::env::var("CITYG_GUI_CONFIG_DIR")
        && !override_path.is_empty()
    {
        let base = PathBuf::from(override_path).join("cityg").join("gui");
        return Ok(base);
    }

    let base = config_dir().ok_or_else(|| anyhow!("cannot determine config directory"))?;
    Ok(base.join("cityg").join("gui"))
}

#[cfg(not(test))]
static CONFIG_DIR_OVERRIDE: LazyLock<Mutex<Option<PathBuf>>> = LazyLock::new(|| Mutex::new(None));

#[cfg(test)]
thread_local! {
    static CONFIG_DIR_OVERRIDE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
pub(super) fn set_config_dir_override_for_tests(path: Option<PathBuf>) -> ConfigDirGuard {
    let previous = CONFIG_DIR_OVERRIDE.with(|override_path| {
        let mut slot = override_path.borrow_mut();
        let previous = slot.clone();
        *slot = path;
        previous
    });
    ConfigDirGuard { previous }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
pub(super) struct ConfigDirGuard {
    previous: Option<PathBuf>,
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
impl Drop for ConfigDirGuard {
    fn drop(&mut self) {
        CONFIG_DIR_OVERRIDE.with(|override_path| {
            *override_path.borrow_mut() = self.previous.clone();
        });
    }
}
